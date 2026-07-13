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
2. Pin the tools to the model, using that account (it prompts for the password):

```bash
./bootstrap-openwebui <your-admin-email>
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

### Python

The `mcp` package needs **Python ≥ 3.10**, which is newer than the system
`python3` on some of the distros above — Debian 11 and PureOS 10 ship 3.9 and
have nothing newer in apt. `setup` checks for a suitable interpreter and, if the
system has none, fetches a standalone CPython 3.12 with
[uv](https://astral.sh/uv) into your home directory. Nothing system-wide is
touched and `/usr/bin/python3` is left exactly as it was.

Installing the venv with the system 3.9 is what produces pip's rather unhelpful
`No matching distribution found for mcp==...` — every candidate is skipped for
requiring a newer Python.

### Local overrides (`.env`)

An optional, gitignored `.env` next to the scripts is read by `setup`,
`openWebBuddy`, and `bootstrap-openwebui`:

```bash
MCPO_PORT=8100      # default 8000; change it if something else owns that port
```

The port is baked into the OpenWebUI container's tool-server URL, so after
changing it re-run `./setup` — it recreates the container (your accounts and
chats live in a Docker volume and are kept).

## Architecture

```
  Browser ──▶ OpenWebUI (Docker, --network host, :3000)
                 │
                 ├─▶ Ollama (systemd, 127.0.0.1:11434)     model: llama3.2:1b
                 │
                 └─▶ tool server  http://127.0.0.1:8000
                        └─▶ mcpo ── MCP stdio ──▶ net-mcp/net_mcp_server.py
```

- **Ollama** — local model server (systemd service `ollama`), on loopback only.
- **OpenWebUI** — chat UI (Docker container `open-webui`), pinned to a specific
  image tag and run with `--network host`. Sharing the host's network namespace
  is what lets it reach Ollama and the tool bridge over `127.0.0.1`, so neither
  has to be published to the LAN and no `host.docker.internal` alias is needed.
  Linux-only, which this project already is.
- `setup` seeds the tool-server connection, default model, prompt suggestions,
  and CPU-saving toggles via env vars — but OpenWebUI only honours those for
  config keys absent from its database, so `bootstrap-openwebui` re-applies the
  important ones through the API rather than trusting the seed.
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
ollama pull <tag>              # fetch the new model
# edit MODEL="..." in ./openWebBuddy
./bootstrap-openwebui <email>  # re-pin tools + default model
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

- **mcpo (`:8000`, see `MCPO_PORT`) and Ollama (`:11434`) are bound to
  `127.0.0.1`** — neither is reachable from the network. This matters: they have
  no authentication, and anyone who could reach the mcpo port would be able to
  make this machine run pings and port scans on their behalf. Running OpenWebUI
  on the host network is what makes keeping them on loopback possible.
- **The chat UI itself (`:3000`) does listen on all interfaces**, so you can
  reach it from another device on the LAN. It's behind OpenWebUI's own login.
- If you are upgrading from a version that installed an `OLLAMA_HOST=0.0.0.0`
  systemd override, `./setup` removes it.
- `setup` installs a sudoers rule (`/etc/sudoers.d/openwebbuddy`) narrowly
  scoped to `systemctl start/stop ollama` and `arp-scan --localnet` — nothing
  else runs privileged.

## Logs

- mcpo / tool server: `logs/mcpo.log`
- OpenWebUI: `docker logs open-webui`
- Ollama: `journalctl -u ollama`
