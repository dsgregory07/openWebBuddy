<#
    openWebBuddy.ps1 - Windows launcher for the offline Network Troubleshooting Assistant.

      .\openWebBuddy.ps1            start Ollama + OpenWebUI + the net-diag MCP tool bridge,
                                    then open a browser to the chat UI
      .\openWebBuddy.ps1 stop       stop the MCP bridge and OpenWebUI (Ollama is left running -
                                    it is a shared Windows service)
      .\openWebBuddy.ps1 stop-all   graceful full shutdown - stop the MCP bridge, OpenWebUI,
                                    AND Ollama, so nothing is left consuming resources
      .\openWebBuddy.ps1 status     show what's running (exit 1 if anything is down)
      .\openWebBuddy.ps1 restart    stop then start

    Windows port of the original Linux 'openWebBuddy' bash launcher. Instead of systemd +
    Docker it runs Ollama (native Windows app), OpenWebUI (pip package), and mcpo (pip
    package) as plain background processes, all bound to 127.0.0.1. The Net-Diag tool server
    and prompt suggestions are wired in by bootstrap-openwebui.ps1 through the API.
#>
[CmdletBinding()]
param(
    [ValidateSet('start', 'stop', 'stop-all', 'restart', 'status')]
    [string]$Command = 'start'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$Root = $PSScriptRoot

# Optional machine-local overrides in .env (KEY=VALUE lines), e.g. MCPO_PORT=8100.
$EnvFile = Join-Path $Root '.env'
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

$McpDir      = Join-Path $Root 'net-mcp'
$VenvScripts = Join-Path $McpDir '.venv\Scripts'
$Python      = Join-Path $VenvScripts 'python.exe'
$Mcpo        = Join-Path $VenvScripts 'mcpo.exe'
$OpenWebUI   = Join-Path $VenvScripts 'open-webui.exe'
$Server      = Join-Path $McpDir 'net_mcp_server_win.py'
# net-vuln (nmap security-assessment tools) shares the net-mcp venv - it only needs `mcp`.
$VulnServer  = Join-Path (Join-Path $Root 'net-vuln-mcp') 'net_vuln_server.py'

$LogDir      = Join-Path $Root 'logs'
$DataDir     = Join-Path $Root 'owui-data'

$OllamaExe   = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
$OllamaUrl   = 'http://127.0.0.1:11434'
$Model       = if ($env:MODEL) { $env:MODEL } else { 'llama3.2:1b' }

$OwuiPort    = if ($env:OWUI_PORT) { $env:OWUI_PORT } else { '3000' }
$OwuiUrl     = "http://127.0.0.1:$OwuiPort"
$McpoPort    = if ($env:MCPO_PORT) { $env:MCPO_PORT } else { '8000' }

# ---------------------------------------------------------------------------
# Pretty output
# ---------------------------------------------------------------------------
function Step($m) { Write-Host "==> " -ForegroundColor Blue -NoNewline; Write-Host $m }
function Ok($m)   { Write-Host "  " -NoNewline; Write-Host "OK " -ForegroundColor Green -NoNewline; Write-Host $m }
function Warn($m) { Write-Host "  " -NoNewline; Write-Host "!  " -ForegroundColor Yellow -NoNewline; Write-Host $m }
function Die($m)  { Write-Host "  " -NoNewline; Write-Host "x  " -ForegroundColor Red -NoNewline; Write-Host $m; exit 1 }

# Poll until $Test (a scriptblock returning $true) succeeds, up to $TimeoutSec.
# If $Proc is given and exits first, stop waiting immediately (fail fast on crash).
function Wait-For([scriptblock]$Test, [int]$TimeoutSec, [System.Diagnostics.Process]$Proc = $null) {
    $elapsed = 0
    while ($elapsed -lt $TimeoutSec) {
        try { if (& $Test) { return $true } } catch {}
        if ($Proc -and $Proc.HasExited) { return $false }
        Start-Sleep -Seconds 1
        $elapsed++
    }
    return $false
}

function Test-Http($Url) {
    try {
        Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null
        return $true
    } catch {
        # A 4xx/5xx still means something is listening and answering HTTP.
        return $null -ne $_.Exception.Response
    }
}

function Get-PidFromFile($Path) {
    if (Test-Path $Path) {
        $p = (Get-Content $Path -Raw).Trim()
        if ($p -match '^\d+$') { return [int]$p }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Component: Ollama
# ---------------------------------------------------------------------------
function Start-Ollama {
    Step "Ollama model server"
    if (Test-Http "$OllamaUrl/api/tags") {
        Ok "already running"
    } else {
        if (-not (Test-Path $OllamaExe)) { Die "ollama.exe not found at $OllamaExe (install Ollama for Windows)" }
        Start-Process -FilePath $OllamaExe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
        if (-not (Wait-For { Test-Http "$OllamaUrl/api/tags" } 30)) { Die "ollama did not come up within 30s" }
        Ok "started"
    }
    try {
        $tags = (Invoke-WebRequest -Uri "$OllamaUrl/api/tags" -UseBasicParsing -TimeoutSec 5).Content
        if ($tags -match [regex]::Escape($Model)) { Ok "model $Model available" }
        else { Warn "model $Model not found - pull it with: ollama pull $Model" }
    } catch { Warn "could not query models" }
}

# ---------------------------------------------------------------------------
# Component: MCP tool bridge (one mcpo, config mode -> two OpenAPI tool servers)
#   /net-diag  = OS-command diagnostics (net_mcp_server_win.py)
#   /net-vuln  = nmap security-assessment tools (net_vuln_server.py)
# Both are stdio MCP servers mounted under path prefixes on the same port. The config
# file is generated here (machine-specific absolute paths) into the gitignored logs dir.
# ---------------------------------------------------------------------------
function Write-McpoConfig {
    # A Claude-desktop-style mcpServers map; each entry is one stdio command. The map key
    # becomes the URL path prefix (mcpo mounts it at /<key>). net-vuln reuses net-diag's
    # venv python, so it needs no separate environment.
    $cfg = @{
        mcpServers = @{
            'net-diag' = @{ command = $Python; args = @($Server) }
            'net-vuln' = @{ command = $Python; args = @($VulnServer) }
        }
    }
    $path = Join-Path $LogDir 'mcpo.config.json'
    ($cfg | ConvertTo-Json -Depth 6) | Out-File -FilePath $path -Encoding ascii -Force
    return $path
}

function Get-ToolCount($SubPath) {
    try {
        $spec = (Invoke-WebRequest -Uri "http://127.0.0.1:$McpoPort/$SubPath/openapi.json" -UseBasicParsing -TimeoutSec 5).Content | ConvertFrom-Json
        return ($spec.paths | Get-Member -MemberType NoteProperty).Count
    } catch { return $null }
}

function Start-Mcpo {
    Step "MCP tool bridge (mcpo: net-diag + net-vuln)"
    if (Test-Http "http://127.0.0.1:$McpoPort/net-diag/openapi.json") {
        Ok "already running on :$McpoPort"
        return
    }
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $configFile = Write-McpoConfig
    # 127.0.0.1, not 0.0.0.0: keep the tools off the LAN - anyone who could reach this port
    # could make the machine run pings/port/vuln scans, unauthenticated.
    $mcpoArgs = @(
        '--port', $McpoPort, '--host', '127.0.0.1',
        '--config', $configFile
    )
    $proc = Start-Process -FilePath $Mcpo -ArgumentList $mcpoArgs `
        -RedirectStandardOutput (Join-Path $LogDir 'mcpo.log') `
        -RedirectStandardError  (Join-Path $LogDir 'mcpo.err.log') `
        -WindowStyle Hidden -PassThru
    $proc.Id | Out-File -FilePath (Join-Path $LogDir 'mcpo.pid') -Encoding ascii -Force
    # net-diag is the critical set; its sub-app openapi.json 200s only once the stdio server
    # has connected, so this doubles as a "tools actually loaded" check.
    if (-not (Wait-For { Test-Http "http://127.0.0.1:$McpoPort/net-diag/openapi.json" } 30 $proc)) {
        Die "mcpo did not come up - see $LogDir\mcpo.err.log"
    }
    $diagN = Get-ToolCount 'net-diag'
    $vulnN = Get-ToolCount 'net-vuln'
    if ($null -ne $diagN) { Ok "net-diag: $diagN tools on :$McpoPort/net-diag" } else { Ok "net-diag running on :$McpoPort/net-diag" }
    if ($null -ne $vulnN) { Ok "net-vuln: $vulnN tools on :$McpoPort/net-vuln" } else { Warn "net-vuln did not load - see $LogDir\mcpo.err.log" }
}

# ---------------------------------------------------------------------------
# Component: OpenWebUI (native pip package)
# ---------------------------------------------------------------------------
function Start-Owui {
    Step "OpenWebUI"
    if (Test-Http "$OwuiUrl/health") {
        Ok "already running"
        return
    }
    New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

    # First-boot seeding via simple env vars. The tool server, default model, and prompt
    # suggestions are applied authoritatively by bootstrap-openwebui.ps1 through the API.
    $env:DATA_DIR                        = $DataDir
    $env:OLLAMA_BASE_URL                 = $OllamaUrl
    $env:DEFAULT_MODELS                  = $Model
    $env:ENABLE_FOLLOW_UP_GENERATION     = 'False'
    $env:ENABLE_TAGS_GENERATION          = 'False'
    $env:ENABLE_TITLE_GENERATION         = 'False'
    $env:ENABLE_COMMUNITY_SHARING        = 'False'
    $env:ENABLE_EVALUATION_ARENA_MODELS  = 'False'
    $env:WEBUI_AUTH                       = 'True'
    # Cap the native tool-calling loop (OpenWebUI's default is 256 - a runaway loop on a
    # CPU-bound local model could grind for hours). Override in .env if needed.
    if (-not $env:CHAT_RESPONSE_MAX_TOOL_CALL_ITERATIONS) {
        $env:CHAT_RESPONSE_MAX_TOOL_CALL_ITERATIONS = '12'
    }

    $owuiArgs = @('serve', '--host', '127.0.0.1', '--port', $OwuiPort)
    $proc = Start-Process -FilePath $OpenWebUI -ArgumentList $owuiArgs `
        -RedirectStandardOutput (Join-Path $LogDir 'owui.log') `
        -RedirectStandardError  (Join-Path $LogDir 'owui.err.log') `
        -WindowStyle Hidden -PassThru
    $proc.Id | Out-File -FilePath (Join-Path $LogDir 'owui.pid') -Encoding ascii -Force

    # First boot downloads an embedding model, so allow generous time.
    if (-not (Wait-For { Test-Http "$OwuiUrl/health" } 240 $proc)) {
        Die "OpenWebUI did not become reachable on $OwuiUrl - see $LogDir\owui.err.log (it may have crashed on startup)"
    }
    Ok "reachable at $OwuiUrl"
}

# ---------------------------------------------------------------------------
# Process teardown
# ---------------------------------------------------------------------------
# Stop a process (and its whole tree) as cleanly as possible. Returns $true if it was
# running when we started. Windowed apps (e.g. the Ollama tray) are asked to close first
# and given a grace window; background console services (OpenWebUI, mcpo, ollama serve)
# have no window to receive that, so they go straight to the forced tree-kill.
# taskkill is routed through cmd with its output swallowed so its stderr can never become
# a terminating NativeCommandError under ErrorActionPreference = Stop.
function Stop-Tree([int]$RootPid, [int]$GraceSec = 5) {
    $proc = Get-Process -Id $RootPid -ErrorAction SilentlyContinue
    if (-not $proc) { return $false }
    $askedNicely = $false
    try {
        if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $null = $proc.CloseMainWindow(); $askedNicely = $true }
    } catch {}
    if ($askedNicely) {
        $waited = 0
        while ($waited -lt ($GraceSec * 2)) {
            if (-not (Get-Process -Id $RootPid -ErrorAction SilentlyContinue)) { return $true }
            Start-Sleep -Milliseconds 500
            $waited++
        }
    }
    cmd /c "taskkill /PID $RootPid /T /F >nul 2>nul"
    return $true
}

function Stop-Tracked($Name, $PidFile) {
    Step $Name
    $procId = Get-PidFromFile $PidFile
    $stopped = $false
    if ($procId) { $stopped = Stop-Tree $procId }
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force }
    if ($stopped) { Ok "stopped" } else { Ok "already stopped" }
}

# Full graceful teardown of Ollama (tray app + serve + model-runner children). Ollama
# has no PID file - it is a shared app - so find it by process name.
function Stop-Ollama {
    Step "Ollama model server"
    $procs = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like 'ollama*' })
    if ($procs.Count -eq 0) { Ok "already stopped"; return }
    foreach ($p in $procs) { Stop-Tree $p.Id | Out-Null }
    # Sweep any stragglers the tree-kill missed (separate process groups).
    Start-Sleep -Milliseconds 500
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like 'ollama*' } |
        ForEach-Object { cmd /c "taskkill /PID $($_.Id) /T /F >nul 2>nul" }
    Ok "stopped"
}

function Open-Browser {
    Step "Opening chat"
    Start-Process $OwuiUrl | Out-Null
    Ok "launched browser at $OwuiUrl"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
function Invoke-Start {
    Start-Ollama
    Start-Owui
    Start-Mcpo
    Open-Browser
    Write-Host ""
    Write-Host "openWebBuddy is up." -ForegroundColor Green
    Write-Host "  Chat:   $OwuiUrl"
    Write-Host "  Tools:  http://127.0.0.1:$McpoPort/net-diag  and  /net-vuln (OpenAPI servers)"
    Write-Host "  Stop with: .\openWebBuddy.ps1 stop"
    $dbFile = Join-Path $DataDir 'webui.db'
    if (-not (Test-Path $dbFile)) {
        Write-Host ""
        Write-Host "First run: create the admin account in the browser, then run:" -ForegroundColor Yellow
        Write-Host "  .\bootstrap-openwebui.ps1 <your-admin-email>"
    }
}

function Invoke-Stop {
    Stop-Tracked "net-diag tool bridge (mcpo)" (Join-Path $LogDir 'mcpo.pid')
    Stop-Tracked "OpenWebUI"                    (Join-Path $LogDir 'owui.pid')
    Step "Ollama model server"
    Ok "left running (shared Windows app; use 'stop-all' to stop it too)"
    Write-Host ""
    Write-Host "Stopped OpenWebUI and the tool bridge." -ForegroundColor Green
}

function Invoke-StopAll {
    Stop-Tracked "net-diag tool bridge (mcpo)" (Join-Path $LogDir 'mcpo.pid')
    Stop-Tracked "OpenWebUI"                    (Join-Path $LogDir 'owui.pid')
    Stop-Ollama
    Write-Host ""
    Write-Host "Full stop - OpenWebUI, the tool bridge, and Ollama are all down." -ForegroundColor Green
    Write-Host "Your account, tools, and uploads are safe in owui-data and will be there on restart."
}

function Invoke-Status {
    Step "Status"
    $down = 0
    if (Test-Http "$OllamaUrl/api/tags")                              { Ok "Ollama       running ($OllamaUrl)" }        else { Warn "Ollama       stopped"; $down = 1 }
    if (Test-Http "$OwuiUrl/health")                                   { Ok "OpenWebUI    running ($OwuiUrl)" }           else { Warn "OpenWebUI    stopped"; $down = 1 }
    if (Test-Http "http://127.0.0.1:$McpoPort/net-diag/openapi.json")  { Ok "net-diag MCP running (:$McpoPort/net-diag)" } else { Warn "net-diag MCP stopped"; $down = 1 }
    if (Test-Http "http://127.0.0.1:$McpoPort/net-vuln/openapi.json")  { Ok "net-vuln MCP running (:$McpoPort/net-vuln)" } else { Warn "net-vuln MCP stopped (nmap tools)"; $down = 1 }
    exit $down
}

switch ($Command) {
    'start'    { Invoke-Start }
    'stop'     { Invoke-Stop }
    'stop-all' { Invoke-StopAll }
    'restart'  { Invoke-Stop; Write-Host ""; Invoke-Start }
    'status'   { Invoke-Status }
}
