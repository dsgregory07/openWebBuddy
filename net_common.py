#!/usr/bin/env python3
"""Shared helpers and tunable config for the Windows MCP servers.

Both net-mcp/net_mcp_server_win.py (net-diag) and net-vuln-mcp/net_vuln_server.py
(net-vuln) import this module, so the command runner, the PowerShell bridge, the
local-network lookups, the argument-escaping helper, and the shared timeout knobs live
in exactly one place instead of being copy-pasted into each server.

Both servers add the repo root (this file's directory) to sys.path and `import net_common`;
they sit one level below the root at net-mcp/ and net-vuln-mcp/, so the same shim works for
both.

Every knob is overridable from the environment. The launcher already loads .env into the
process environment before starting the servers, so timeouts can be tuned without editing
code (e.g. NETDIAG_PING_WAIT_MS=4000 for a slow link). Keep this file ASCII-only.
"""
import os
import subprocess


def env_int(name: str, default: int) -> int:
    """Read an int from the environment, falling back to `default` when unset/empty/invalid."""
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


# --- Shared tunable knobs (env-overridable; defaults preserve prior hardcoded values) ---
CMD_TIMEOUT = env_int("NETDIAG_CMD_TIMEOUT", 15)   # default subprocess timeout (seconds)
PS_TIMEOUT = env_int("NETDIAG_PS_TIMEOUT", 30)     # powershell.exe run timeout (seconds)
PING_WAIT_MS = env_int("NETDIAG_PING_WAIT_MS", 2000)  # per-echo ping timeout (ms)


def ps_quote(value) -> str:
    """Escape a value for safe embedding inside a single-quoted PowerShell literal.

    A single quote is the only metacharacter inside a '...' string in PowerShell; the
    documented escape is to double it (''). Doing this stops a value that contains a quote
    (from an LLM-supplied hostname/interface/DNS-server argument) from breaking out of the
    literal and injecting arbitrary PowerShell.
    """
    return str(value).replace("'", "''")


def run(cmd: list, timeout: int = CMD_TIMEOUT) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0 and not out:
            return f"[exit {proc.returncode}] {err or 'no output'}"
        return out + (f"\n[stderr] {err}" if err else "")
    except FileNotFoundError:
        return f"error: '{cmd[0]}' is not installed"
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {timeout}s"
    except OSError as e:
        return f"error: could not run '{cmd[0]}': {e}"


def run_ps(script: str, timeout: int = PS_TIMEOUT) -> str:
    """Run a PowerShell snippet, forcing UTF-8 output so parsing is stable.

    Default timeout is higher than CMD_TIMEOUT: powershell.exe startup alone can take
    >10s when a local model is saturating the CPU during inference.
    """
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;" + script
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full], timeout=timeout
    )


# ---------------------------------------------------------------------------
# Local network context (gateway + subnet), shared by both servers.
# ---------------------------------------------------------------------------
import re  # noqa: E402  (kept next to the functions that use it)


def default_gateway():
    out = run_ps(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric | Select-Object -First 1;"
        " if ($r) { $r.NextHop }"
    )
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
    return m.group(1) if m else None


def local_ipv4():
    """The IPv4 address of the interface that owns the default route."""
    out = run_ps(
        "$c = Get-NetIPConfiguration -ErrorAction SilentlyContinue |"
        " Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1;"
        " if ($c) { ($c.IPv4Address | Select-Object -First 1).IPAddress }"
    )
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
    return m.group(1) if m else None


def local_subnet_24():
    """Derive the local /24 (e.g. 192.168.1.0/24) from this host's primary IPv4."""
    ip = local_ipv4()
    if not ip:
        return None
    a, b, c, _d = ip.split(".")
    return f"{a}.{b}.{c}.0/24"
