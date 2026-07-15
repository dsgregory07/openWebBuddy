<#
    setup.ps1 - Windows preflight checker/installer for openWebBuddy (native Windows port).

      .\setup.ps1           check every requirement of .\openWebBuddy.ps1; install what is missing
      .\setup.ps1 -Check    report only, change nothing

    The Windows analog of the Linux 'setup' bash script. Instead of apt/systemd/Docker it
    provisions the pip venv (open-webui + mcp + mcpo + ollama), verifies Ollama and the
    model, checks the Visual C++ runtime that OpenWebUI/PyTorch needs, and - for the
    optional net-vuln security tools - reports on nmap and the Npcap driver. Run from the
    repo root. Auto-installs use winget where possible; nmap/Npcap are reported only,
    because their installer is interactive (see notes it prints).

    If PowerShell blocks it ("running scripts is disabled"), launch with:
      powershell -ExecutionPolicy Bypass -File .\setup.ps1
    Keep this file ASCII-only (Windows PowerShell 5.1 reads UTF-8-without-BOM as CP1252).
#>
[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

# Optional machine-local overrides in .env (KEY=VALUE), e.g. MODEL=..., MCPO_PORT=8100.
$EnvFile = Join-Path $Root '.env'
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

$McpDir       = Join-Path $Root 'net-mcp'
$Venv         = Join-Path $McpDir '.venv'
$VenvScripts  = Join-Path $Venv 'Scripts'
$VenvPython   = Join-Path $VenvScripts 'python.exe'
$Mcpo         = Join-Path $VenvScripts 'mcpo.exe'
$OpenWebUI    = Join-Path $VenvScripts 'open-webui.exe'
$Requirements = Join-Path $McpDir 'requirements.txt'

$Model     = if ($env:MODEL) { $env:MODEL } else { 'qwen2.5:7b-instruct' }
$OllamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
$OllamaUrl = 'http://127.0.0.1:11434'
$PyMin     = [version]'3.10'

# OpenWebUI runs as a pip package on Windows (Docker on Linux), so it is installed on top
# of the shared requirements.txt (mcp + mcpo + ollama).
$ExtraPkgs = @('open-webui')

# ---------------------------------------------------------------------------
# Pretty output (same conventions as openWebBuddy.ps1)
# ---------------------------------------------------------------------------
function Step($m) { Write-Host "==> " -ForegroundColor Blue -NoNewline; Write-Host $m }
function Ok($m)   { Write-Host "  " -NoNewline; Write-Host "OK " -ForegroundColor Green -NoNewline; Write-Host $m }
function Miss($m) { Write-Host "  " -NoNewline; Write-Host "!  " -ForegroundColor Yellow -NoNewline; Write-Host $m; $script:Missing = $true }
function Note($m) { Write-Host "  " -NoNewline; Write-Host "-  " -ForegroundColor Cyan -NoNewline; Write-Host $m }
function Die($m)  { Write-Host "  " -NoNewline; Write-Host "x  " -ForegroundColor Red -NoNewline; Write-Host $m; exit 1 }

$script:Missing = $false
$needVenv = $false; $needModel = $false; $needVcredist = $false
$PyExe = $null; $PyArgs = @()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Find-Nmap {
    $c = Get-Command nmap -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($b in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\Program Files', 'C:\Program Files (x86)')) {
        if ($b) { $p = Join-Path $b 'Nmap\nmap.exe'; if (Test-Path $p) { return $p } }
    }
    return $null
}

# Find a Python >= 3.10 to build the venv. Prefers the py launcher, then python on PATH.
# The probe carries NO double quotes and reports via exit code, not stdout: PS 5.1 strips
# embedded double quotes when handing an argument to a native exe (a "%d.%d" literal would
# reach python as %d.%d and SyntaxError), and each candidate is wrapped in try/catch so a
# not-installed 'py -3.x' (which errors to stderr under ErrorActionPreference=Stop) is just
# skipped rather than aborting the script.
function Find-Python {
    $tries = @()
    if (Have 'py') { foreach ($v in '3.13','3.12','3.11','3.10') { $tries += ,@('py', "-$v") } }
    if (Have 'python') { $tries += ,@('python') }
    foreach ($t in $tries) {
        $exe = $t[0]
        $a = @(); if ($t.Count -gt 1) { $a = @($t[1..($t.Count - 1)]) }
        $good = $false
        try {
            & $exe @a '-c' 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,10) else 1)' 2>$null
            $good = ($LASTEXITCODE -eq 0)
        } catch { $good = $false }
        if ($good) {
            $ver = ''
            try { $ver = ((& $exe @a '-V') -join ' ') -replace '^Python\s+', '' } catch {}
            return @{ Exe = $exe; Args = $a; Ver = $ver }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
function Check-Python {
    Step "Python >= $PyMin with venv support (required by mcp)"
    $p = Find-Python
    if ($p) {
        $script:PyExe = $p.Exe; $script:PyArgs = $p.Args
        $shown = ($p.Exe + ' ' + ($p.Args -join ' ')).Trim()
        Ok "$shown (Python $($p.Ver))"
    } else {
        Miss "no Python >= $PyMin found (install: winget install Python.Python.3.11)"
    }
}

function Check-Venv {
    Step "net-mcp Python environment (open-webui + mcp + mcpo + ollama)"
    $good = (Test-Path $VenvPython) -and (Test-Path $Mcpo) -and (Test-Path $OpenWebUI)
    if ($good) {
        try { & $VenvPython -c 'import mcp, ollama' 2>$null; $good = ($LASTEXITCODE -eq 0) } catch { $good = $false }
    }
    if ($good) { Ok "venv ready at net-mcp\.venv" }
    else { Miss "venv missing or incomplete at net-mcp\.venv"; $script:needVenv = $true }
}

function Check-Ollama {
    Step "Ollama + model $Model"
    if (-not (Test-Path $OllamaExe)) {
        Miss "Ollama not installed (install: winget install Ollama.Ollama)"
        return
    }
    Ok "ollama installed"
    $tags = $null
    try { $tags = (Invoke-WebRequest -Uri "$OllamaUrl/api/tags" -UseBasicParsing -TimeoutSec 5).Content } catch {}
    if (-not $tags) {
        try { $tags = & $OllamaExe list 2>$null | Out-String } catch {}
    }
    if ($tags) {
        if ($tags -match [regex]::Escape($Model)) { Ok "model $Model present" }
        else { Miss "model $Model not pulled (will pull: ollama pull $Model)"; $script:needModel = $true }
    } else {
        Note "Ollama not running - cannot verify model $Model now (setup will pull it if needed)"
        $script:needModel = $true
    }
}

function Check-VcRedist {
    Step "Visual C++ runtime (OpenWebUI/PyTorch needs it or it crashes on boot)"
    $dll = Join-Path $env:WINDIR 'System32\vcruntime140_1.dll'
    if (Test-Path $dll) { Ok "VC++ 2015-2022 runtime present" }
    else { Miss "VC++ 2015-2022 runtime missing (install: winget install Microsoft.VCRedist.2015+.x64)"; $script:needVcredist = $true }
}

function Check-Nmap {
    # net-vuln is OPTIONAL - net-diag works without nmap - so these are notes, not misses.
    Step "nmap + Npcap (optional - only for the net-vuln security tools)"
    $nmap = Find-Nmap
    if ($nmap) {
        $ver = 'unknown'
        try { $v = & $nmap --version 2>$null | Select-Object -First 1; if ($v -match 'Nmap version (\S+)') { $ver = $Matches[1] } } catch {}
        Ok "nmap $ver ($nmap)"
    } else {
        Note "nmap not installed - the 5 net-vuln tools stay disabled until it is."
        Note "  Install from https://nmap.org/download.html (bundles Npcap); leave 'Restrict"
        Note "  Npcap to Administrators only' UNCHECKED. net-diag is unaffected."
        return
    }
    # nmap is present; report the Npcap driver state (raw -sS/-sX need it running).
    $svc = Get-Service npcap -ErrorAction SilentlyContinue
    if (-not $svc) {
        Note "Npcap driver not found - reinstall nmap so it installs Npcap (raw scans need it)."
    } elseif ($svc.Status -ne 'Running') {
        Note "Npcap driver is $($svc.Status) - REBOOT to load it, then -sS/-sX (filtered detection, grinch_scan) work."
    } else {
        $adminOnly = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters' -Name AdminOnly -ErrorAction SilentlyContinue).AdminOnly
        if ($adminOnly -eq 1) { Note "Npcap is admin-only - reinstall with 'Restrict to Administrators only' UNCHECKED for unprivileged raw scans." }
        else { Ok "Npcap driver running (non-admin) - raw scans available" }
    }
}

function Check-ExecPolicy {
    Step "PowerShell execution policy"
    $p = Get-ExecutionPolicy -Scope CurrentUser
    if ($p -in @('Restricted','Undefined','AllSigned')) {
        Note "CurrentUser policy is '$p' - launch scripts with 'powershell -ExecutionPolicy Bypass -File .\openWebBuddy.ps1',"
        Note "  or once run: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned. (openWebBuddy.cmd wraps this for you.)"
    } else {
        Ok "CurrentUser policy is '$p'"
    }
}

# ---------------------------------------------------------------------------
# Install phase
# ---------------------------------------------------------------------------
function Install-Missing {
    if ($needVcredist) {
        Step "Installing the VC++ 2015-2022 runtime (winget)"
        if (Have 'winget') { winget install --id Microsoft.VCRedist.2015+.x64 -e --accept-source-agreements --accept-package-agreements; Ok "requested" }
        else { Die "winget not available - install the VC++ 2015-2022 x64 redistributable manually, then re-run" }
    }

    if ($needVenv) {
        Step "Creating the venv + installing $($ExtraPkgs -join ', '), mcp, mcpo, ollama"
        if (-not $PyExe) {
            $p = Find-Python
            if (-not $p) { Die "no Python >= $PyMin available to build the venv (winget install Python.Python.3.11)" }
            $script:PyExe = $p.Exe; $script:PyArgs = $p.Args
        }
        & $PyExe @PyArgs -m venv $Venv
        if (-not (Test-Path $VenvPython)) { Die "venv creation failed at $Venv" }
        & $VenvPython -m pip install --quiet --upgrade pip
        & $VenvPython -m pip install --quiet @ExtraPkgs
        & $VenvPython -m pip install --quiet -r $Requirements
        if (-not ((Test-Path $Mcpo) -and (Test-Path $OpenWebUI))) { Die "pip install did not produce mcpo/open-webui - see errors above" }
        Ok "venv ready"
    }

    if ($needModel) {
        Step "Pulling model $Model"
        if (-not (Test-Path $OllamaExe)) { Die "Ollama is not installed - install it first (winget install Ollama.Ollama), then re-run" }
        if (-not (Test-Http "$OllamaUrl/api/tags")) {
            Start-Process -FilePath $OllamaExe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
            for ($i = 0; $i -lt 30 -and -not (Test-Http "$OllamaUrl/api/tags"); $i++) { Start-Sleep -Seconds 1 }
        }
        & $OllamaExe pull $Model
        Ok "model ready"
    }
}

function Test-Http($Url) {
    try { Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null; return $true }
    catch { return $null -ne $_.Exception.Response }
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if (-not (Test-Path (Join-Path $Root 'openWebBuddy.ps1'))) {
    Die "openWebBuddy.ps1 not found next to setup.ps1 - run this from the repo root"
}

Check-Python
Check-Venv
Check-Ollama
Check-VcRedist
Check-Nmap
Check-ExecPolicy
Write-Host ""

if (-not $Missing) {
    Write-Host "All required components are present - .\openWebBuddy.ps1 is ready to run." -ForegroundColor Green
    Write-Host "  (nmap/Npcap are optional; see the notes above to enable the net-vuln tools.)"
    exit 0
}

if ($Check) {
    Write-Host "Missing requirements found (see '!' above). Run .\setup.ps1 (no -Check) to install them." -ForegroundColor Yellow
    exit 1
}

Install-Missing
Write-Host ""
Write-Host "Setup complete - run .\openWebBuddy.ps1 to start." -ForegroundColor Green
Write-Host "  First run: create the admin account in the browser, then run:" -ForegroundColor Yellow
Write-Host "    .\bootstrap-openwebui.ps1 <your-admin-email>"
