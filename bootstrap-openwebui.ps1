<#
    bootstrap-openwebui.ps1 - one-time OpenWebUI configuration after first signup.

      .\bootstrap-openwebui.ps1 <admin-email>

    Wiring the Net-Diag tools to the model takes an authenticated API call, and nothing
    can authenticate until the admin account exists. So, once: open the chat, create the
    admin account in the browser, then run this with that account's email. It prompts for
    the password and signs in. Safe to re-run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Email
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

$EnvFile = Join-Path $Root '.env'
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

$OwuiPort = if ($env:OWUI_PORT) { $env:OWUI_PORT } else { '3000' }
$OwuiUrl  = if ($env:OWUI_URL)  { $env:OWUI_URL }  else { "http://127.0.0.1:$OwuiPort" }
$McpoPort = if ($env:MCPO_PORT) { $env:MCPO_PORT } else { '8000' }
$Model    = if ($env:MODEL)     { $env:MODEL }     else { 'llama3.2:1b' }

function Step($m) { Write-Host "==> " -ForegroundColor Blue -NoNewline; Write-Host $m }
function Ok($m)   { Write-Host "  " -NoNewline; Write-Host "OK " -ForegroundColor Green -NoNewline; Write-Host $m }
function Die($m)  { Write-Host "  " -NoNewline; Write-Host "x  " -ForegroundColor Red -NoNewline; Write-Host $m; exit 1 }

Step "OpenWebUI at $OwuiUrl"
try { Invoke-WebRequest -Uri "$OwuiUrl/health" -UseBasicParsing -TimeoutSec 5 | Out-Null; Ok "reachable" }
catch { Die "OpenWebUI is not reachable - start it first (.\openWebBuddy.ps1)" }

Step "Signing in as $Email"
$password = $env:OWUI_PASSWORD
if (-not $password) {
    $secure = Read-Host -AsSecureString "  password for $Email"
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if (-not $password) { Die "no password given" }

try {
    $signin = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/auths/signin" -Method Post `
        -ContentType 'application/json' `
        -Body (@{ email = $Email; password = $password } | ConvertTo-Json)
    $token = $signin.token
} catch { $token = $null }
if (-not $token) { Die "sign-in failed - check the email and password" }
Ok "signed in"

$headers = @{ Authorization = "Bearer $token" }

Step "Registering the Net-Diag tool server"
$toolServer = @{
    TOOL_SERVER_CONNECTIONS = @(
        @{
            url = "http://127.0.0.1:$McpoPort"; path = "openapi.json"; type = "openapi"
            auth_type = "bearer"; headers = $null; key = ""
            config = @{ enable = $true; function_name_filter_list = @(); access_grants = @() }
            spec_type = "url"; spec = ""
            info = @{ id = "Server"; name = "Net-Diag Tools"; description = "Offline network troubleshooting tools (gateway, ping, traceroute, DNS, ARP, port scan, router audit)" }
        }
    )
}
try {
    $resp = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/tool_servers" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body ($toolServer | ConvertTo-Json -Depth 10)
    Ok "tool server 'Server' -> http://127.0.0.1:$McpoPort"
} catch { Die "could not register the tool server: $($_.Exception.Message)" }

Step "Pinning Net-Diag tools to model $Model"
$modelPayload = @{
    id = $Model; base_model_id = $null; name = $Model
    meta = @{
        profile_image_url = "/static/favicon.png"; description = $null
        capabilities = @{ vision = $false; file_upload = $true; web_search = $false; image_generation = $false; code_interpreter = $false; citations = $true }
        suggestion_prompts = $null; tags = @(); toolIds = @("server:Server")
    }
    params = @{ function_calling = "native" }
    access_control = $null; is_active = $true
}
try {
    $resp = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/create" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body ($modelPayload | ConvertTo-Json -Depth 10)
    Ok "model record created with Net-Diag tools pinned"
} catch {
    if ("$($_.Exception.Message)" -match 'taken|already') { Ok "model record already exists - leaving it as is" }
    else { Die "models/create failed: $($_.Exception.Message)" }
}

Step "Setting default model to $Model"
try {
    $cfg = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/export" -Method Get -Headers $headers
    if (-not $cfg.ui) { $cfg | Add-Member -NotePropertyName ui -NotePropertyValue (@{}) -Force }
    $cfg.ui | Add-Member -NotePropertyName default_models -NotePropertyValue $Model -Force
    Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/import" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body (@{ config = $cfg } | ConvertTo-Json -Depth 20) | Out-Null
    Ok "submitted"
} catch { Die "could not set default model: $($_.Exception.Message)" }

Step "Verifying"
$fail = 0
try {
    $m = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model?id=$Model" -Method Get -Headers $headers
    $toolIds = $m.meta.toolIds -join ','
    if ($toolIds -match 'server:Server') { Ok "tools pinned to $Model (toolIds: $toolIds)" }
    else { Write-Host "  x  tool pinning not confirmed (got: '$toolIds')" -ForegroundColor Red; $fail = 1 }
} catch { Write-Host "  x  could not verify tool pinning" -ForegroundColor Red; $fail = 1 }

try {
    $cfg2 = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/export" -Method Get -Headers $headers
    if ($cfg2.ui.default_models -eq $Model) { Ok "default model is $Model" }
    else { Write-Host "  x  default model not confirmed (got: '$($cfg2.ui.default_models)')" -ForegroundColor Red; $fail = 1 }
} catch { Write-Host "  x  could not verify default model" -ForegroundColor Red; $fail = 1 }

Write-Host ""
if ($fail) { Write-Host "Bootstrap incomplete - see errors above." -ForegroundColor Red; exit 1 }
Write-Host "OpenWebUI configured - open $OwuiUrl and start chatting." -ForegroundColor Green
