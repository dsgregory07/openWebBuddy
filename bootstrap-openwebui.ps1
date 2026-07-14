<#
    bootstrap-openwebui.ps1 - one-time OpenWebUI configuration after first signup.

      .\bootstrap-openwebui.ps1 <admin-email>

    Wiring the Net-Diag tools to the model takes an authenticated API call, and nothing
    can authenticate until the admin account exists. So, once: open the chat, create the
    admin account in the browser, then run this with that account's email. It prompts for
    the password and signs in (or reads $env:OWUI_PASSWORD).

    Safe to re-run: if the model record already exists it is UPDATED in place, so re-run
    this after changing MODEL in .env or after pulling a new model. It pins the Net-Diag
    tools, enables native function calling, and sets the agentic system prompt, context
    size, and prompt suggestions on the model.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Email,
    # Optional: configure a specific model instead of the .env MODEL (e.g. to also
    # set up a fallback model record: .\bootstrap-openwebui.ps1 you@mail -Model llama3.2:1b)
    [string]$Model = ''
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
if (-not $Model) {
    $Model = if ($env:MODEL) { $env:MODEL } else { 'llama3.2:1b' }
}

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

Step "Configuring model $Model for agentic troubleshooting"

# Per-model system prompt: makes the model plan, chain tools, and end with a diagnosis.
# Keep this ASCII-only (see WINDOWS.md).
$SystemPrompt = @'
You are an autonomous network troubleshooting agent running locally on this machine. You diagnose problems by calling diagnostic tools; never guess when a tool can check.

Method:
1. Think about which layer most likely explains the symptom: local adapter -> Wi-Fi/link -> gateway/router -> DNS -> WAN/internet -> specific service.
2. Call one tool, read its result, then pick the next tool based on what you learned.
3. For 'internet is down' reports, a good chain is: list_network_interfaces, then check_gateway_reachable, then check_internet, then dns_server_check or traceroute_host depending on what failed.
4. Keep investigating until you can state a diagnosis; most problems need 2-6 tool calls. Never ask the user for permission to run a tool - just run it.
5. If a tool fails or times out, note that and try a different tool instead of repeating the same call.

When you are confident, stop calling tools and answer with exactly three sections:
DIAGNOSIS: one or two sentences naming the failing layer/component.
EVIDENCE: the key tool results that support it.
NEXT STEPS: concrete actions for the user, most likely fix first.
'@

$modelPayload = @{
    id = $Model; base_model_id = $null; name = $Model
    meta = @{
        profile_image_url = "/static/favicon.png"
        description = "Offline network troubleshooter - diagnoses LAN/Wi-Fi/DNS/WAN problems with local tools"
        # builtin_tools=false matters: otherwise OpenWebUI injects its own built-in tools
        # (notes, web search, ...) next to the Net-Diag tools, and small local models
        # wander off calling replace_note_content instead of diagnosing the network.
        capabilities = @{ vision = $false; file_upload = $true; web_search = $false; image_generation = $false; code_interpreter = $false; citations = $true; builtin_tools = $false }
        suggestion_prompts = @(
            @{ title = @("My internet is down", "figure out why"); content = "My internet is down - figure out why and tell me how to fix it." }
            @{ title = @("Is my router OK?", "run a quick audit"); content = "Run a quick audit of my router - is it reachable and are any risky ports open?" }
            @{ title = @("Why is Wi-Fi slow?", "check signal and errors"); content = "My Wi-Fi feels slow - check the signal, link rates, and interface errors." }
            @{ title = @("Is DNS broken?", "test the resolvers"); content = "Websites will not load by name - check whether DNS is the problem." }
        )
        tags = @(); toolIds = @("server:Server")
    }
    params = @{
        function_calling = "native"   # real multi-round tool calls via Ollama /api/chat
        system = $SystemPrompt
        num_ctx = 8192                # room for tool schemas + several tool-result rounds
        temperature = 0.2             # keep tool selection deterministic
    }
    access_grants = @(); is_active = $true
}
$modelBody = $modelPayload | ConvertTo-Json -Depth 10

# Update in place when the record exists so re-runs pick up prompt/param changes.
$exists = $false
try {
    $m = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model?id=$Model" -Method Get -Headers $headers
    if ($m -and $m.id) { $exists = $true }
} catch {}
try {
    if ($exists) {
        Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model/update" -Method Post `
            -Headers $headers -ContentType 'application/json' -Body $modelBody | Out-Null
        Ok "model record updated (tools, native function calling, agentic prompt, num_ctx)"
    } else {
        Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/create" -Method Post `
            -Headers $headers -ContentType 'application/json' -Body $modelBody | Out-Null
        Ok "model record created (tools, native function calling, agentic prompt, num_ctx)"
    }
} catch { Die "model create/update failed: $($_.Exception.Message)" }

Step "Setting default model to $Model"
# Dedicated endpoint (POST /configs/models) - the old whole-config export/import
# round-trip could fail without actually persisting ui.default_models.
try {
    $mcfg = $null
    try { $mcfg = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/models" -Method Get -Headers $headers } catch {}
    # Values must be plain variables: an `if` statement used directly as a hashtable
    # value makes PS 5.1's ConvertTo-Json render an empty array as {} instead of [],
    # which the API rejects with 422.
    $pinned    = $null
    $orderList = @()
    if ($mcfg) {
        $pinned = $mcfg.DEFAULT_PINNED_MODELS
        if ($mcfg.MODEL_ORDER_LIST) { $orderList = @($mcfg.MODEL_ORDER_LIST) }
    }
    $modelsCfg = @{
        DEFAULT_MODELS        = $Model
        DEFAULT_PINNED_MODELS = $pinned
        MODEL_ORDER_LIST      = $orderList
    }
    Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/models" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body ($modelsCfg | ConvertTo-Json -Depth 10) | Out-Null
    Ok "submitted"
} catch { Die "could not set default model: $($_.Exception.Message)" }

Step "Verifying"
$fail = 0
try {
    $m = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model?id=$Model" -Method Get -Headers $headers
    $toolIds = $m.meta.toolIds -join ','
    if ($toolIds -match 'server:Server') { Ok "tools pinned to $Model (toolIds: $toolIds)" }
    else { Write-Host "  x  tool pinning not confirmed (got: '$toolIds')" -ForegroundColor Red; $fail = 1 }
    if ($m.params.system -match 'DIAGNOSIS') { Ok "agentic system prompt set" }
    else { Write-Host "  x  system prompt not confirmed" -ForegroundColor Red; $fail = 1 }
    if ("$($m.params.function_calling)" -eq 'native') { Ok "native function calling enabled" }
    else { Write-Host "  x  function_calling is '$($m.params.function_calling)', expected 'native'" -ForegroundColor Red; $fail = 1 }
} catch { Write-Host "  x  could not verify model config" -ForegroundColor Red; $fail = 1 }

try {
    $cfg2 = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/models" -Method Get -Headers $headers
    if ($cfg2.DEFAULT_MODELS -eq $Model) { Ok "default model is $Model" }
    else { Write-Host "  x  default model not confirmed (got: '$($cfg2.DEFAULT_MODELS)')" -ForegroundColor Red; $fail = 1 }
} catch { Write-Host "  x  could not verify default model" -ForegroundColor Red; $fail = 1 }

Write-Host ""
if ($fail) { Write-Host "Bootstrap incomplete - see errors above." -ForegroundColor Red; exit 1 }
Write-Host "OpenWebUI configured - open $OwuiUrl and start chatting." -ForegroundColor Green
