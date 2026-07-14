# openWebBuddy on Windows (native)

This is a native-Windows port of openWebBuddy. The original project is Debian-family
Linux only (it uses `apt`, a systemd Ollama service, Docker with `--network host`, and
Linux networking commands). This port keeps the same architecture and the same 16
diagnostic tools, but runs everything natively on Windows with no WSL and no Docker.

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

## Prerequisites (already installed by the setup that produced this port)

- Python 3.11 (`winget install Python.Python.3.11`)
- Ollama for Windows (`winget install Ollama.Ollama`) + `ollama pull qwen2.5:7b-instruct`
  (the recommended agentic model; `llama3.2:1b` works as a small fallback but is too weak
  to chain tools reliably)
- A venv at `net-mcp\.venv` with `open-webui mcp mcpo ollama` installed

To recreate the venv from scratch:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe" -m venv net-mcp\.venv
net-mcp\.venv\Scripts\python.exe -m pip install open-webui mcp mcpo ollama
```

## Run it

```powershell
# from the repo root
.\openWebBuddy.ps1            # start Ollama + OpenWebUI + net-diag tools, open the browser
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
you change `MODEL` in `.env` or want to pick up a new system prompt. It registers the
Net-Diag tool server, pins the tools to the model, enables native function calling,
disables OpenWebUI's built-in tools (notes, web search, ...) so only the Net-Diag tools
are offered to the model, sets the agentic system prompt, `num_ctx` (8192), temperature,
prompt suggestions, and the workspace default model.

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

## Notes / differences from the Linux version

- **Wi-Fi signal** is reported by Windows as a quality percentage (via `netsh wlan`),
  not dBm, so `wifi_status` grades it on a percentage scale.
- **`arp_scan_lan`** uses the Windows ARP cache (`arp -a`); there is no `arp-scan`
  equivalent shipped, so it lists hosts this machine has recently contacted rather than
  actively sweeping the subnet.
- **`port_scan` / `router_quick_audit`** use `nmap` if it is on `PATH`, otherwise fall
  back to a built-in PowerShell TCP connect scan (capped at 256 ports for responsiveness).
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
