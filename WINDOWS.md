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
- Ollama for Windows (`winget install Ollama.Ollama`) + `ollama pull llama3.2:1b`
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
2. Pin the tools to the model (prompts for the password you just set):

```powershell
.\bootstrap-openwebui.ps1 <your-admin-email>
```

Then chat: *"my internet is down"*, *"is my router OK?"*, *"why is wifi slow?"*

## Notes / differences from the Linux version

- **Wi-Fi signal** is reported by Windows as a quality percentage (via `netsh wlan`),
  not dBm, so `wifi_status` grades it on a percentage scale.
- **`arp_scan_lan`** uses the Windows ARP cache (`arp -a`); there is no `arp-scan`
  equivalent shipped, so it lists hosts this machine has recently contacted rather than
  actively sweeping the subnet.
- **`port_scan` / `router_quick_audit`** use `nmap` if it is on `PATH`, otherwise fall
  back to a built-in PowerShell TCP connect scan (capped at 256 ports for responsiveness).
- OpenWebUI data (accounts, chats, config) lives in `owui-data\` in the repo root; delete
  it to reset. Logs are in `logs\` (`owui.log`, `mcpo.log`, and their `.err.log` files).
- Config overrides go in a `.env` file next to the scripts (e.g. `MCPO_PORT=8100`,
  `OWUI_PORT=3000`, `MODEL=llama3.2:1b`).

> All `.ps1` files are ASCII-only on purpose: Windows PowerShell 5.1 reads a UTF-8 file
> without a BOM as Windows-1252, and a stray non-ASCII character (e.g. an em dash) decodes
> to a smart quote that the parser treats as a real quote. Keep them ASCII.
