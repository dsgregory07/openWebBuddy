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
    size, and prompt suggestions on the model. The update API replaces the model's meta
    block wholesale, so this script fetches the existing record first and carries forward
    any Knowledge collections / tags attached via the OpenWebUI UI - otherwise a re-run
    would silently detach them.
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
# num_ctx / temperature come from .env so a bootstrap re-run preserves your tuning instead of
# reverting the model record to hardcoded values (and stays in sync with the OpenWebUI slider).
$NumCtx      = if ($env:NUM_CTX)     { [int]$env:NUM_CTX }        else { 8192 }
$Temperature = if ($env:TEMPERATURE) { [double]$env:TEMPERATURE } else { 0.2 }

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

Step "Checking for an existing model record"
# Fetched now (before building the payload below) so its meta can be carried forward -
# /models/model/update replaces the whole meta block, so anything not explicitly preserved
# here (Knowledge collections, tags attached via the UI) would otherwise be silently wiped
# on every re-run.
$existingMeta = $null
$exists = $false
try {
    $mExisting = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model?id=$Model" -Method Get -Headers $headers
    if ($mExisting -and $mExisting.id) { $exists = $true; $existingMeta = $mExisting.meta }
} catch {}
if ($exists) { Ok "found - will update in place" } else { Ok "not found - will create" }

Step "Registering the net-diag and net-vuln tool servers"
# One mcpo in config mode serves both MCP servers under path prefixes on the same port:
#   /net-diag = OS-command diagnostics, /net-vuln = nmap security-assessment tools.
# Each is its own OpenWebUI tool connection (its own toggleable set). net-diag KEEPS
# info.id "Server" so any existing model pin (toolIds "server:Server") survives the move
# to the /net-diag path. This POST replaces the whole connections list, so both are here.
$toolServer = @{
    TOOL_SERVER_CONNECTIONS = @(
        @{
            url = "http://127.0.0.1:$McpoPort/net-diag"; path = "openapi.json"; type = "openapi"
            auth_type = "bearer"; headers = $null; key = ""
            config = @{ enable = $true; function_name_filter_list = @(); access_grants = @() }
            spec_type = "url"; spec = ""
            info = @{ id = "Server"; name = "Net-Diag Tools"; description = "Offline network troubleshooting tools (gateway, ping, traceroute, DNS, device discovery, port scan, router audit)" }
        }
        @{
            url = "http://127.0.0.1:$McpoPort/net-vuln"; path = "openapi.json"; type = "openapi"
            auth_type = "bearer"; headers = $null; key = ""
            config = @{ enable = $true; function_name_filter_list = @(); access_grants = @() }
            spec_type = "url"; spec = ""
            info = @{ id = "NetVuln"; name = "Net-Vuln Tools"; description = "nmap security-assessment tools (device discovery, port/service/version scan, firewall probe, vulnerability scan). Systems you own or are authorized to test." }
        }
    )
}
try {
    $resp = Invoke-RestMethod -Uri "$OwuiUrl/api/v1/configs/tool_servers" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body ($toolServer | ConvertTo-Json -Depth 10)
    Ok "tool server 'Server'  -> http://127.0.0.1:$McpoPort/net-diag"
    Ok "tool server 'NetVuln' -> http://127.0.0.1:$McpoPort/net-vuln"
} catch { Die "could not register the tool servers: $($_.Exception.Message)" }

Step "Configuring model $Model for agentic troubleshooting"

# Per-model system prompt: makes the model plan, chain tools, and end with a diagnosis.
# Keep this ASCII-only (see WINDOWS.md).
$SystemPrompt = @'
You are an offline assistant running on this Windows machine with two roles: network troubleshooting (diagnose connectivity problems) and security assessment (evaluate what is exposed, on systems the user owns or is authorized to test). You work only by calling tools. Never guess when a tool can check, and never state a finding that no tool actually returned.

TOOL USE
- Call one tool at a time. Read its full output, then choose the next tool based on what it said. Do not fire off speculative calls.
- Call only tools that appear in your tool list. Never invent a tool name; if the check you want has no tool, put it in UNVERIFIED instead of calling something that does not exist.
- Never ask permission to run a tool. Just run it.
- Budget about 15 tool calls per answer (the hard cap is 20); most problems resolve in 2-6. Prefer the composite tools as entry points, because each does several checks in one call:
    check_gateway_reachable  = gateway ping + verdict
    check_internet           = ping 1.1.1.1 + DNS + HTTP fetch + verdict
    router_quick_audit       = gateway ping + management-port scan + risk flags
  These resolve the gateway themselves, so you rarely need get_default_gateway first, and you should not re-ping the gateway with ping_host straight afterwards.
- Do not repeat an identical call. If a tool times out, note it and try a different one.
- A tool that errors (import error, "is not installed", "not found", a non-zero exit code) is a BROKEN TOOL, not a negative result. An unreachable host and an unloadable tool are different things; say which one you got. Do not silently substitute one tool's absence for another tool's answer.

METHOD
Work outward and stop at the first layer that is actually broken:
  adapter/IP -> Wi-Fi link -> gateway/router -> DNS -> WAN/internet -> a specific host/port
- "Internet is down": check_gateway_reachable, then check_internet, then dns_server_check (if DNS failed) or traceroute_host (if the WAN path failed). Call list_network_interfaces first if the adapter itself is suspect: no IP, or a 169.254.x.x address, means DHCP failed and nothing past the adapter is worth testing yet.
- "Wi-Fi is slow": wifi_status, then interface_stats for errors and drops.
- "Cannot reach host/service X": confirm the lower layers are healthy, then http_check or port_scan against X. Reachability is not availability: a host that pings can still have the port closed.
- "What's on my network?" / "what is this device?": dev_disco - leave `host` empty for a full LAN sweep with identity enrichment, or pass an IP to focus on one device.
- Keep going until you can name a failing component. If you still cannot after ~10 calls, report what you have and list the unknowns. Do not loop.

READING RESULTS ON THIS MACHINE
- Ping: Windows counts "Destination host unreachable" replies as RECEIVED. If a ping summary shows loss=0% but also mentions unreachable, that ping FAILED. The tool flags this; do not overrule it.
- net-diag's port_scan and router_quick_audit focus on OPEN ports. When nmap is installed they run it as a connect scan (nmap -sT -Pn, which is Wi-Fi-safe); without nmap they fall back to a built-in TCP connect scan. Either way (both scan the same real top-100 ports under that label now), treat their output as an open-port list: never report a port as "closed" or "filtered" from these two tools - say it was "not open among the ports scanned". For reliable closed-vs-filtered, service versions, or firewall probing, use the net-vuln tools below (scan_ports distinguishes filtered from closed when raw packets are available; on Wi-Fi it too drops to a connect scan and cannot).
- dev_disco identifies devices via three signals of different reliability: an SSDP/UPnP match is a CONFIRMED identity (the device self-reported it); a MAC-vendor match is a hint from the manufacturer prefix only, not proof of what the device is; "identity unknown" means neither channel caught it (common for privacy-randomized MACs on phones/laptops) - it does NOT mean the device is absent. Never upgrade a vendor guess into a confident device claim.
- dns_lookup given an IP tries reverse DNS then NetBIOS. Getting neither back is a normal result on most home LANs (no local PTR zone, and non-Windows devices don't answer NetBIOS) - report it as "no name available", not as a failure.
- wifi_status reports signal as a percentage on Windows, not dBm. Do not invent dBm.
- Several tools end in a VERDICT line. Use it, and do not contradict it without evidence from another tool.

REPORTING
Precision is the whole point. Vague reporting has previously caused a missed open port.
- Give exact values: IP addresses, port numbers, interface names, latency in ms, loss percentages, hop counts, error strings. Never write "some ports were open", "high latency", "a few hops", or "the usual ports".
- Report every result the tool returned, not a summary of the interesting parts. If a scan returns 5 open ports, name all 5 with their numbers. Never sample or summarize a finding.
- Keep these three states distinct and never collapse them:
    (a) the tool ran and found it absent / down / not open
    (b) the tool ran and found it present / up / open
    (c) the tool did not run, timed out, or errored -> UNKNOWN
- State your coverage. If a scan covered a limited range, say so: "scanned the 8 common management ports; others not checked". Never imply coverage you did not achieve.
- Do not infer one result from another. If you did not scan port 8080, you do not know whether port 8080 is open.

SECURITY ASSESSMENT - net-vuln tools (only when the net-vuln category is enabled)
Use these for "is my network/router secure", "what is exposed", "assess my network / this host" - NOT for connectivity troubleshooting (use net-diag for that). If a net-vuln tool is not in your tool list, the category is toggled OFF - do not call it or mention it. These are for systems the user owns or is authorized to test.
- discover_lan: actively enumerate live devices on the LAN via nmap. Works on Wi-Fi and Ethernet (it drops to a connect-based sweep when raw packets are unavailable). For identifying WHAT a device is (not just its IP), prefer net-diag's dev_disco - it adds SSDP/vendor identity that discover_lan does not.
- scan_ports: open / closed / FILTERED states. When raw packets are available it distinguishes "filtered" (firewalled/silently dropped) from "closed" (nothing listening) - report which, do not collapse them; on Wi-Fi it uses a connect scan and cannot show "filtered".
- service_scan: service + version per open port = the attack surface. A version string is NOT itself a vulnerability - never claim a CVE you did not verify.
- grinch_scan: firewall/packet-filter assessment (default target = the gateway). It picks its mode automatically and is Wi-Fi-safe: on a wired link it runs a true Xmas scan (-sX), which reports "open|filtered" (silent) vs "closed" (RST); on Wi-Fi it runs a connect-based probe that separates open vs filtered (silently dropped) vs closed (actively refused). CAVEAT: the Xmas mode cannot characterize Windows hosts (they answer "closed" to every port) - if it says INCONCLUSIVE, relay that.
- penny_special: a VULNERABILITY SCAN of a host - OS fingerprint (wired only), service versions, and nmap's read-only 'default' + 'vuln' NSE scripts, plus curated risky-service flags. A script finding is a LEAD to verify, NOT a confirmed exploitable vuln; report exactly what it flags and never claim an unverified CVE. Absence of a flag is not proof of safety. Defaults to a small port set for speed.
Assessment flow: discover_lan (inventory) -> scan_ports (open/filtered) -> service_scan (versions) -> penny_special (host vulns); use grinch_scan for the router's firewall behavior.
KEEP SCANS LIGHT: nmap scans can be slow. Let the port range default to the light set; only widen (e.g. '1-1024') when the user explicitly asks for thorough, and say it will take longer. Scan one target at a time.
Same precision rules as always: exact ports/services/versions, echo tool results, keep open/closed/filtered/UNKNOWN distinct.

OUTPUT
When you have enough to answer, stop calling tools and use the format that fits the task.

For TROUBLESHOOTING:
DIAGNOSIS: one or two sentences naming the failing layer or component. If everything you checked was healthy, say that plainly instead of manufacturing a fault.
EVIDENCE: one entry per tool that ran, as "tool_name -> result", echoing the result the tool returned rather than paraphrasing it. Include any tool that errored or returned UNKNOWN.
UNVERIFIED: anything you could not confirm, and which tool would confirm it. Write "None" if everything relevant was verified.
NEXT STEPS: concrete actions for the user, most likely fix first.

For SECURITY ASSESSMENT:
SCOPE: what you scanned - the target(s) and the port breadth - so coverage is explicit.
FINDINGS: what is exposed (open ports, services/versions, flagged issues). An nmap script hit is a LEAD to verify, NOT a confirmed vuln, and absence of a flag is not proof of safety. If nothing risky was found, say so plainly instead of inventing a problem.
EVIDENCE: one entry per tool that ran, as "tool_name -> result", echoing the result rather than paraphrasing. Include any tool that errored or returned UNKNOWN.
NEXT STEPS: concrete hardening actions, highest-risk first.
'@

$modelPayload = @{
    id = $Model; base_model_id = $null; name = $Model
    meta = @{
        profile_image_url = "/static/favicon.png"
        description = "Offline network assistant - troubleshoots LAN/Wi-Fi/DNS/WAN and runs security assessments with local tools"
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
        tags = @(); toolIds = @("server:Server", "server:NetVuln")
    }
    params = @{
        function_calling = "native"   # real multi-round tool calls via Ollama /api/chat
        system = $SystemPrompt
        num_ctx = $NumCtx             # from .env NUM_CTX (default 8192); holds tool schemas + tool-result rounds
        temperature = $Temperature    # from .env TEMPERATURE (default 0.2); low = deterministic tool selection
    }
    access_grants = @(); is_active = $true
}
# Carry forward Knowledge/tags from the existing record (see the note at the top of this
# file) - fields this script does not itself manage, so they must be copied in explicitly
# or the wholesale meta replace below would detach them.
if ($existingMeta) {
    if ($existingMeta.knowledge) { $modelPayload.meta.knowledge = @($existingMeta.knowledge) }
    if ($existingMeta.tags -and @($existingMeta.tags).Count -gt 0) { $modelPayload.meta.tags = @($existingMeta.tags) }
}
$modelBody = $modelPayload | ConvertTo-Json -Depth 10

# Update in place when the record exists so re-runs pick up prompt/param changes.
try {
    if ($exists) {
        Invoke-RestMethod -Uri "$OwuiUrl/api/v1/models/model/update" -Method Post `
            -Headers $headers -ContentType 'application/json' -Body $modelBody | Out-Null
        $kept = if ($modelPayload.meta.knowledge) { "$(@($modelPayload.meta.knowledge).Count) Knowledge file(s) kept" } else { "no Knowledge attached" }
        Ok "model record updated (tools, native function calling, agentic prompt, num_ctx, $kept)"
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
    if ($toolIds -match 'server:Server')  { Ok "net-diag tools pinned to $Model (toolIds: $toolIds)" }
    else { Write-Host "  x  net-diag pin not confirmed (got: '$toolIds')" -ForegroundColor Red; $fail = 1 }
    if ($toolIds -match 'server:NetVuln') { Ok "net-vuln tools pinned to $Model" }
    else { Write-Host "  x  net-vuln pin not confirmed (got: '$toolIds')" -ForegroundColor Red; $fail = 1 }
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
