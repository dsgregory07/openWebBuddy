# openWebBuddy on Windows (native)

This is a native-Windows port of openWebBuddy. The original project is Debian-family
Linux only (it uses `apt`, a systemd Ollama service, Docker with `--network host`, and
Linux networking commands). This port keeps the same architecture and the 16 diagnostic
tools, but runs everything natively on Windows with no WSL and no Docker. It also adds a
second, optional tool category - **net-vuln**: 5 nmap-powered security-assessment tools
(see "Security tools (net-vuln)" below).

## What replaces what

| Original (Linux) | Windows port |
|---|---|
| Ollama systemd service | Ollama for Windows (native app, `ollama serve`) |
| OpenWebUI in Docker `--network host` | `open-webui` pip package, bound to `127.0.0.1` |
| `setup` / `openWebBuddy` / `bootstrap-openwebui` (bash) | `openWebBuddy.ps1` / `bootstrap-openwebui.ps1` (PowerShell) |
| `net-mcp/net_mcp_server.py` (`ip`, `ss`, `iw`, `dig`, `traceroute`, `arp-scan`) | `net-mcp/net_mcp_server_win.py` (`route`/`Get-NetRoute`, `netstat`/`Get-NetTCPConnection`, `netsh wlan`, `Resolve-DnsName`, `tracert`, `arp`) |

Ollama and mcpo stay on `127.0.0.1`; OpenWebUI is bound to `127.0.0.1` too (the Linux
version exposes `:3000` on all interfaces — this port keeps it on loopback by default;
set `OWUI_PORT` and edit the host in the launcher if you want LAN access).

## Prerequisites

The fastest path is **`setup.ps1`**, the Windows preflight checker/installer (the analog of
the Linux `setup`). It reports what is present and installs what is missing:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Check   # report only, change nothing
powershell -ExecutionPolicy Bypass -File .\setup.ps1          # create the venv, pull the model, etc.
```

It checks: Python >= 3.10, the `net-mcp\.venv` venv (`open-webui mcp mcpo ollama`), Ollama +
the `.env` model, the Visual C++ runtime OpenWebUI/PyTorch needs, and - for the optional
net-vuln tools - nmap and the Npcap driver. It auto-installs the venv, model, and VC++
runtime via winget/pip; nmap/Npcap it only reports on (their installer is interactive).

What it provisions, for reference:

- Python 3.11 (`winget install Python.Python.3.11`)
- Ollama for Windows (`winget install Ollama.Ollama`) + `ollama pull qwen2.5:7b-instruct`
  (the recommended agentic model; `llama3.2:1b` works as a small fallback but is too weak
  to chain tools reliably)
- A venv at `net-mcp\.venv` with `open-webui mcp mcpo ollama` installed
- The VC++ 2015-2022 x64 runtime (`winget install Microsoft.VCRedist.2015+.x64`)

To recreate just the venv by hand:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" -m venv net-mcp\.venv
net-mcp\.venv\Scripts\python.exe -m pip install open-webui mcp mcpo ollama
```

## Run it

```powershell
# from the repo root
.\openWebBuddy.ps1            # start Ollama + OpenWebUI + net-diag/net-vuln tools, open the browser
.\openWebBuddy.ps1 status     # show what's running
.\openWebBuddy.ps1 stop       # stop OpenWebUI + tool bridge (Ollama is left running)
.\openWebBuddy.ps1 restart
```

If PowerShell blocks the script ("running scripts is disabled"), launch it with:

```powershell
powershell -ExecutionPolicy Bypass -File .\openWebBuddy.ps1
```

### Prefer to double-click?

Double-clicking a `.ps1` only opens it in an editor - Windows will not run it that
way. Double-click **`openWebBuddy.cmd`** instead: it runs the launcher for you with the
right execution policy (pass `start`/`stop`/`status`/`restart` as an argument, or just
double-click for `start`).

### First run only

OpenWebUI starts with no accounts.

1. The browser opens `http://127.0.0.1:3000`; create the admin account.
2. Configure the model (prompts for the password you just set):

```powershell
.\bootstrap-openwebui.ps1 <your-admin-email>
```

Then chat: *"my internet is down"*, *"is my router OK?"*, *"why is wifi slow?"*

Bootstrap is safe to re-run and **updates the model record in place** - re-run it whenever
you change `MODEL` in `.env` or want to pick up a new system prompt. It registers both the
Net-Diag and Net-Vuln tool servers, pins both tool sets to the model, enables native
function calling, disables OpenWebUI's built-in tools (notes, web search, ...) so only
these tools are offered to the model, sets the agentic system prompt, `num_ctx` (8192),
temperature, prompt suggestions, and the workspace default model.

To configure a model other than the `.env` one (e.g. a fallback), pass it explicitly -
note this also makes it the default model, so re-run for the main model last:

```powershell
.\bootstrap-openwebui.ps1 <your-admin-email> -Model llama3.2:1b
.\bootstrap-openwebui.ps1 <your-admin-email>
```

## Agentic troubleshooting - how it works

Ask something like *"my internet is down"* and the model plans and chains tools on its
own (interfaces -> gateway -> WAN/DNS -> traceroute), then answers with
`DIAGNOSIS / EVIDENCE / NEXT STEPS`.

- **Native function calling** is enabled per-model (`params.function_calling = "native"`):
  OpenWebUI forwards the tool schemas to Ollama's `/api/chat` and loops - executing tool
  calls and re-asking the model - until the model stops calling tools.
- The loop is capped at **12 rounds per answer** by the launcher
  (`CHAT_RESPONSE_MAX_TOOL_CALL_ITERATIONS`, override in `.env`; OpenWebUI's own default
  is 256, which could grind for hours on a CPU-bound model if the model loops).
- The agentic behavior lives in the **per-model system prompt** set by
  `bootstrap-openwebui.ps1` - edit the prompt there and re-run it to tune the behavior.
- Tool outputs are deliberately compact (summarized ping/route/ARP/Wi-Fi results instead
  of raw command dumps) so a small local model can actually reason over them.

### Choosing a model

| Model | Size | Tool calling | Notes |
|---|---|---|---|
| `qwen2.5:7b-instruct` (default) | 4.7 GB | excellent | fits an 8 GB GPU fully at q4; the recommended agent |
| `llama3.1:8b` | 4.9 GB | very good | solid alternative if qwen misbehaves |
| `llama3.2:1b` | 1.3 GB | weak | fine for plain chat / smoke tests; unreliable at chaining tools |

Set `MODEL=` in `.env`, `ollama pull` the tag, then re-run `bootstrap-openwebui.ps1`.

**GPU note (GTX 10-series / Pascal):** current Ollama needs NVIDIA driver **570 or
newer** for compute-capability 5.0-6.2 cards; with an older driver (or a "GPU is lost"
state - fixed by a reboot) inference silently falls back to CPU. A 7B q4 model still
works on CPU (measured ~3 tokens/s generation on an i7-4770), but a multi-tool answer
can take several minutes instead of seconds. Update the driver via GeForce Experience
or nvidia.com, then reboot. Check with `nvidia-smi` and `ollama ps` (should say GPU,
not "100% CPU").

## CLI bridge (no OpenWebUI needed)

`net-mcp\ollama_bridge.py` is a terminal chat that drives the same agentic loop directly
against Ollama + the MCP server - useful for testing tools and prompts without the web UI:

```powershell
net-mcp\.venv\Scripts\python.exe net-mcp\ollama_bridge.py                # interactive
net-mcp\.venv\Scripts\python.exe net-mcp\ollama_bridge.py --ask "my internet is down"
```

It picks the Windows server (`net_mcp_server_win.py`) automatically (override with
`--server`), reads the model from `.env`/`MODEL` like the launcher, and prints each tool
call and a preview of its result as the loop runs. Flags: `--model`, `--max-rounds`
(default 12), `--num-ctx` (default 8192), `--temperature` (default 0.2).

## Security tools (net-vuln)

net-vuln is a second, optional tool category that sits alongside net-diag. Where net-diag
answers "is my network working", net-vuln answers "what is exposed / is my network secure",
assessed from this host against your own machine, LAN, and router. Its server is
`net-vuln-mcp/net_vuln_server.py` (it reuses the `net-mcp\.venv` venv - it only needs
`mcp`). One `mcpo` in config mode now serves both categories on the same port under path
prefixes: `http://127.0.0.1:8000/net-diag` and `.../net-vuln`. Each is a separate,
toggleable tool connection in OpenWebUI, and every tool inside it is individually
toggleable.

The 5 tools (all parse nmap XML into compact summaries; all bounded with `-T4` +
`--host-timeout` + a subprocess timeout so a scan cannot hang the tool loop):

- **`discover_lan`** (`nmap -sn`) - active LAN sweep; a real device inventory. For WHAT a
  device is (not just its IP), prefer net-diag's `dev_disco` - it adds SSDP/vendor identity.
- **`scan_ports`** (`nmap -sS`, `-sT` fallback) - open / closed / **filtered** per port.
- **`service_scan`** (`nmap -sV`) - service + version per open port.
- **`grinch_scan`** (`nmap -sX`) - Xmas-scan firewall probe of the router (default target
  the gateway). Cannot characterize Windows hosts (they answer "closed" to every port).
- **`penny_special`** - a custom, read-only NSE banner grab (`net-vuln-mcp/scripts/
  penny_special.nse`, categories `safe`/`discovery`) that flags known-risky services
  (telnet, FTP, SMBv1, obsolete SSH/HTTP, exposed databases, ...).

No intrusive/exploit/dos/brute NSE scripts are ever run, and scans stay on your own
machine / LAN / router.

### Installing nmap (required for net-vuln)

The net-vuln tools shell out to `nmap`, which is **not** installed by the base setup. Until
it is present each net-vuln tool returns a clear "nmap is not installed" message instead of
a result (net-diag is unaffected). To enable them:

1. Install nmap from <https://nmap.org/download.html> (its Windows installer bundles Npcap).
2. During the Npcap step, **leave "Restrict Npcap driver's access to Administrators only"
   UNCHECKED**. That lets the raw-packet scans (`-sS`, `-sX`) run without a UAC prompt each
   session; administrator rights are then needed only once, at install time.
3. **Reboot Windows** so the freshly installed Npcap driver loads - it is set to start at
   boot, and until it is running the raw-packet scans (`-sS` used by `scan_ports` SYN mode,
   and `-sX` used by `grinch_scan`) fail. The connect-based tools work without it. (Advanced:
   instead of rebooting you can load it once as admin with `net start npcap`.)
4. Restart the tool bridge (`.\openWebBuddy.ps1 restart`) so a fresh scan picks up nmap.

If Npcap is missing, the driver has not loaded (no reboot yet), or it was installed
admin-only, `scan_ports` automatically falls back to an unprivileged connect scan (`-sT`,
which cannot report "filtered"), and `grinch_scan` returns a message telling you to reboot or
reinstall Npcap in non-admin mode.

## Notes / differences from the Linux version

- **Wi-Fi signal** is reported by Windows as a quality percentage (via `netsh wlan`),
  not dBm, so `wifi_status` grades it on a percentage scale.
- **`dev_disco`** (net-diag, replaces the old `arp_scan_lan`) is an active device-discovery
  and identity tool, not a passive ARP-cache read. Leave `host` empty to sweep the whole local
  subnet, or pass an IP to identify one device. It layers three signals: an active ping sweep
  (via .NET async `Ping`, so results reflect who is up right now); SSDP/UPnP (pure Python
  `socket`+`urllib`, no nmap needed) for a CONFIRMED name/manufacturer/model from any device
  that self-announces (routers, smart TVs, streaming boxes, speakers, some IoT); and a MAC
  vendor lookup (from nmap's bundled OUI database, if nmap is installed) for everything else -
  a hint from the manufacturer prefix, not a confirmed identity. A device that answers neither
  channel is reported as "identity unknown", not absent (privacy-randomized MACs on phones/
  laptops commonly defeat the vendor lookup).
- **`port_scan` / `router_quick_audit`** (net-diag) run `nmap` as a connect scan (`-sT -Pn`)
  if it is on `PATH`, otherwise fall back to a built-in PowerShell TCP connect scan. Both paths
  are connect-based and Wi-Fi-safe - they never open the adapter for raw packets, so they
  cannot drop a USB Wi-Fi link. `port_scan`'s `"top-100"` now scans the SAME 100 ports (nmap's
  real top-100 by frequency, read from its bundled `nmap-services` data) and returns the same
  output shape whether or not nmap is installed, with service names in both cases. For a real
  security assessment - including "filtered" vs "closed", service versions, and firewall
  probing - use the net-vuln tools above instead.
- **`dns_lookup`** also accepts an IP (instead of a hostname) to resolve it back to a name:
  reverse DNS first, then a NetBIOS name query if there is no PTR record. Neither channel
  succeeding is a normal result on most home LANs (no local PTR zone; non-Windows/non-SMB
  devices don't answer NetBIOS) - it does not mean the device is unreachable.
- **Tool outputs are summarized**, not raw command dumps: `ping`/`tracert`/`arp`/
  `netsh wlan`/`route print`/adapter statistics are parsed into a few compact lines
  (with a raw-output fallback if parsing fails), because a local model reasons far
  better over `Ping x: sent=4 received=0 loss=100%` than over 30 lines of padding.
  The Linux server still returns the raw command output for these.
- OpenWebUI data (accounts, chats, config) lives in `owui-data\` in the repo root; delete
  it to reset. Logs are in `logs\` (`owui.log`, `mcpo.log`, and their `.err.log` files).
- Config overrides go in a `.env` file next to the scripts (e.g. `MCPO_PORT=8100`,
  `OWUI_PORT=3000`, `MODEL=qwen2.5:7b-instruct`,
  `CHAT_RESPONSE_MAX_TOOL_CALL_ITERATIONS=12`).

> All `.ps1` files are ASCII-only on purpose: Windows PowerShell 5.1 reads a UTF-8 file
> without a BOM as Windows-1252, and a stray non-ASCII character (e.g. an em dash) decodes
> to a smart quote that the parser treats as a real quote. Keep them ASCII.
