# openWebBuddy

An **offline** LAN/router troubleshooting assistant that runs entirely on your
own hardware. A local Ollama model (`llama3.2:1b`) chats through OpenWebUI and
can call a set of network-diagnostic tools exposed by a small MCP server.
No cloud, no API keys, no data leaving the machine — developed and tested on a
Raspberry Pi 5.

## Quick start

```bash
git clone <this repo> && cd openWebBuddy
./setup                # install anything missing (or ./setup --check to just look)
./openWebBuddy         # start everything and open the chat in a browser
```

First run only — OpenWebUI starts with no accounts:

1. The browser opens `http://localhost:3000`; create the admin account.
2. Generate an API key: **Settings → Account → API keys**.
3. Pin the tools to the model:

```bash
./bootstrap-openwebui <your-api-key>
```

Then just chat: *"my internet is down"*, *"is my router OK?"*, *"why is wifi slow?"*

Day-to-day:

```bash
./openWebBuddy          # start everything
./openWebBuddy stop     # shut everything down
./openWebBuddy status   # show what's running (exit code reflects health)
./openWebBuddy restart  # stop then start
```

## Platform support

**Debian-family Linux only for now** — Raspberry Pi OS, Debian, Ubuntu, PureOS.
`setup` and `openWebBuddy` refuse to run elsewhere: most of the diagnostic
tools shell out to Linux networking commands (`ip`, `ss`, `iw`), so macOS is
explicitly unsupported. A Mac can still *use* the assistant by pointing a
browser at a Linux box running it (`http://<that-box>:3000`).

PureOS note: every apt dependency comes from Debian main; the Ollama binary and
the OpenWebUI container image are pulled from upstream (ollama.com, ghcr.io)
rather than PureOS-vetted repos.

## Architecture

```
  Browser ──▶ OpenWebUI (Docker, :3000)
                 │
                 ├─▶ Ollama (systemd, :11434)              model: llama3.2:1b
                 │     bound to 0.0.0.0 so the container can reach it
                 │
                 └─▶ tool server  http://host.docker.internal:8000
                        └─▶ mcpo ── MCP stdio ──▶ net-mcp/net_mcp_server.py
```

- **Ollama** — local model server (systemd service `ollama`). `setup` installs
  an `OLLAMA_HOST=0.0.0.0` systemd override; without it the OpenWebUI container
  cannot reach the host's Ollama and chats hang.
- **OpenWebUI** — chat UI (Docker container `open-webui`). On first boot,
  `setup` seeds it with the tool-server connection, default model, prompt
  suggestions, and CPU-saving feature toggles.
- **net-diag tool server** (`net-mcp/net_mcp_server.py`) — defines the
  diagnostic tools. `mcpo` wraps it as an OpenAPI tool server; it appears in
  OpenWebUI as **"Net-Diag Tools"**.

## Repo layout

| Path | What it is |
|---|---|
| `openWebBuddy` | launcher — start/stop/status/restart the whole stack |
| `setup` | preflight checker/installer (`--check` = report only) |
| `bootstrap-openwebui` | one-time post-signup config (tool pinning, default model) |
| `net-mcp/net_mcp_server.py` | the MCP diagnostic tools |
| `net-mcp/ollama_bridge.py` | CLI-only chat loop (no web UI) |
| `net-mcp/requirements.txt` | pinned Python deps (`mcp`, `mcpo`, `ollama`) |

## Tools exposed

`get_default_gateway`, `check_gateway_reachable`, `ping_host`,
`traceroute_host`, `dns_lookup`, `list_network_interfaces`, `arp_scan_lan`,
`port_scan`, `router_quick_audit`, `check_internet`, `wifi_status`,
`dns_server_check`, `http_check`, `listening_ports`, `show_routes`,
`interface_stats`.

**To add a tool:** add an `@mcp.tool()` function to
`net-mcp/net_mcp_server.py`, then `./openWebBuddy restart`. It appears
automatically under the Net-Diag Tools server in OpenWebUI.

## The model

Default is `llama3.2:1b` — small enough for snappy CPU-only replies on
Pi-class hardware, and it supports native tool calling. To swap models:

```bash
ollama pull <tag>            # fetch the new model
# edit MODEL="..." in ./openWebBuddy
./bootstrap-openwebui <key>  # re-pin tools + default model
```

Avoid thinking/reasoning models (e.g. `qwen3:4b` "Thinking") on CPU-only
boxes: they generate a long hidden reasoning phase before any visible output
and appear to hang for minutes.

## CLI-only bridge (no OpenWebUI)

`net-mcp/ollama_bridge.py` is a standalone terminal chat loop that connects
the same MCP tools directly to Ollama, for testing without the web UI:

```bash
net-mcp/.venv/bin/python net-mcp/ollama_bridge.py --model llama3.2:1b
```

## Security notes

- **mcpo (`:8000`) and Ollama (`:11434`) listen on all interfaces with no
  auth.** That's fine on a trusted home LAN; on shared networks, firewall
  those ports or bind them to specific interfaces. Anyone who can reach
  `:8000` can make this machine run pings/port scans.
- `setup` installs a sudoers rule (`/etc/sudoers.d/openwebbuddy`) narrowly
  scoped to `systemctl start/stop ollama` and `arp-scan --localnet` — nothing
  else runs privileged.

## Logs

- mcpo / tool server: `logs/mcpo.log`
- OpenWebUI: `docker logs open-webui`
- Ollama: `journalctl -u ollama`
# openWebBuddy
