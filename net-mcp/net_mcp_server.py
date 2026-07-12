#!/usr/bin/env python3
"""MCP server exposing local network diagnostic tools for offline router/LAN troubleshooting."""
import re
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("net-diag")

TIMEOUT = 15


def run(cmd: list[str], timeout: int = TIMEOUT) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        if proc.returncode != 0 and not out:
            return f"[exit {proc.returncode}] {err or 'no output'}"
        return out + (f"\n[stderr] {err}" if err else "")
    except FileNotFoundError:
        return f"error: '{cmd[0]}' is not installed"
    except subprocess.TimeoutExpired:
        return f"error: command timed out after {timeout}s"


def default_gateway() -> str | None:
    out = run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else None


@mcp.tool()
def get_default_gateway() -> str:
    """Return this machine's default gateway (router) IP address, as configured in the routing table."""
    gw = default_gateway()
    return gw or "No default gateway found in routing table (not connected to a LAN, or DHCP failed)."


@mcp.tool()
def check_gateway_reachable() -> str:
    """Ping the default gateway (router) to check basic LAN connectivity. Use this first when diagnosing 'no internet' or outage reports."""
    gw = default_gateway()
    if not gw:
        return "No default gateway configured — check that an interface is up and has an IP (see list_network_interfaces)."
    result = run(["ping", "-c", "4", "-W", "2", gw])
    return f"Gateway: {gw}\n{result}"

# NOTE: intended for probing the user's own LAN/router; not restricted to any allowlist since this is a
# single-host offline diagnostic tool, not a multi-tenant service.
@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host (IP or hostname) to check reachability and latency. Use for the router, LAN devices, or any address you have permission to probe."""
    count = max(1, min(count, 10))
    return run(["ping", "-c", str(count), "-W", "2", host], timeout=count * 3 + 10)


@mcp.tool()
def traceroute_host(host: str) -> str:
    """Trace the network path (hop by hop) to a host. Useful to see where connectivity breaks between this machine and the router/internet."""
    if shutil.which("traceroute") is None:
        return "error: traceroute not installed"
    return run(["traceroute", "-w", "2", "-m", "15", host], timeout=45)


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve a hostname to its IP address(es) using the system resolver. Failing DNS while the gateway is pingable usually means WAN/internet, not LAN, is down."""
    if shutil.which("dig"):
        return run(["dig", "+short", hostname])
    if shutil.which("nslookup"):
        return run(["nslookup", hostname])
    return "error: neither dig nor nslookup installed"


@mcp.tool()
def list_network_interfaces() -> str:
    """List local network interfaces, their state (up/down), and assigned IP addresses. Use to check whether the Pi itself has a valid IP/link before blaming the router."""
    return run(["ip", "-brief", "addr", "show"])


@mcp.tool()
def arp_scan_lan() -> str:
    """Scan the local subnet via ARP to discover live devices on the LAN (MAC + IP). Requires being on the LAN; does not need internet. Useful to confirm the router and other devices are actually present on the network during an outage."""
    if shutil.which("arp-scan"):
        result = run(["sudo", "-n", "arp-scan", "--localnet"], timeout=30)
        if "a password is required" not in result and "exit 1" not in result.lower():
            return result
        # NOPASSWD sudo isn't configured for arp-scan specifically — fall back to the
        # unprivileged ARP cache, which only shows already-contacted hosts but needs no sudo.
        fallback = run(["arp", "-a"])
        return f"(arp-scan needs sudo access not currently granted; showing cached ARP table instead)\n{fallback}"
    return run(["arp", "-a"])


@mcp.tool()
def port_scan(host: str, ports: str = "1-1024") -> str:
    """Scan a host's TCP ports to see which services are open (e.g. the router's admin/management interfaces). Use only against your own router/devices for troubleshooting or a basic security check. `ports` is an nmap port spec, e.g. '1-1024', '22,80,443', or 'top-100'."""
    if shutil.which("nmap") is None:
        return "error: nmap not installed"
    if ports == "top-100":
        args = ["nmap", "-F", "-T4", host]
    else:
        args = ["nmap", "-p", ports, "-T4", host]
    return run(args, timeout=60)


@mcp.tool()
def router_quick_audit() -> str:
    """Run a quick composite check against the default gateway: reachability, open management ports (21,22,23,53,80,443,8080,8443), and a note on any risky-looking open services (telnet, unauthenticated admin ports). Good first call for 'is my router OK' questions."""
    gw = default_gateway()
    if not gw:
        return "No default gateway configured — cannot audit router."
    ping_result = run(["ping", "-c", "2", "-W", "2", gw])
    # Keep only the summary line — the per-packet lines are pure token bloat for
    # an LLM that's about to synthesize a written answer, and this Pi's CPU-only
    # inference processes prompt tokens about as slowly as it generates them.
    ping_summary_match = re.search(r"\d+ packets transmitted.*", ping_result)
    ping_summary = ping_summary_match.group(0) if ping_summary_match else ping_result
    if shutil.which("nmap") is None:
        return f"Gateway: {gw}\n{ping_summary}\n(nmap not installed — skipping port audit)"
    scan_result = run(["nmap", "-p", "21,22,23,53,80,443,8080,8443", "-T4", gw], timeout=30)
    port_lines = "\n".join(
        line for line in scan_result.splitlines() if re.match(r"^\d+/tcp\s", line)
    ) or scan_result
    flags = []
    if re.search(r"23/tcp\s+open", scan_result):
        flags.append("Port 23 (telnet) is OPEN — telnet is unencrypted and a common router weakness; disable it if not needed.")
    if re.search(r"21/tcp\s+open", scan_result):
        flags.append("Port 21 (FTP) is OPEN — check if this is required; FTP credentials are sent in plaintext.")
    flag_text = "\n".join(flags) if flags else "No obviously risky ports flagged among the common set checked."
    return f"Gateway: {gw}\nPing: {ping_summary}\n\nOpen ports scanned:\n{port_lines}\n\n{flag_text}"


@mcp.tool()
def check_internet() -> str:
    """Composite WAN/internet check: ping a public IP, resolve a hostname, and fetch a web page. Distinguishes 'LAN up but internet down' from 'DNS broken' from 'all good'. Use after check_gateway_reachable when diagnosing internet problems."""
    results = []
    ip_ping = run(["ping", "-c", "2", "-W", "2", "1.1.1.1"])
    # Parse the loss percentage numerically — a substring test for "0% packet
    # loss" also matches "100% packet loss".
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", ip_ping)
    ip_ok = loss is not None and float(loss.group(1)) == 0
    m = re.search(r"\d+ packets transmitted.*", ip_ping)
    results.append(f"Ping 1.1.1.1 (raw IP): {m.group(0) if m else ip_ping}")
    dns = run(["dig", "+short", "+time=3", "+tries=1", "google.com"])
    dns_ok = bool(re.search(r"^\d+\.\d+\.\d+\.\d+", dns, re.M))
    results.append(f"DNS lookup google.com: {dns.splitlines()[0] if dns_ok else 'FAILED — ' + dns}")
    http = run(["curl", "-sI", "-m", "8", "-o", "/dev/null", "-w", "%{http_code} in %{time_total}s", "http://connectivitycheck.gstatic.com/generate_204"])
    http_ok = http.startswith("204") or http.startswith("200")
    results.append(f"HTTP check: {http}")
    if ip_ok and dns_ok and http_ok:
        verdict = "VERDICT: Internet connectivity looks fully working."
    elif ip_ok and not dns_ok:
        verdict = "VERDICT: Raw internet (IP) works but DNS is broken — check the router's DNS settings or /etc/resolv.conf."
    elif not ip_ok:
        verdict = "VERDICT: No internet at IP level — if the gateway pings OK, the problem is upstream (modem/ISP/WAN)."
    else:
        verdict = "VERDICT: Partial connectivity — DNS resolves but web traffic fails; possible captive portal or firewall."
    return "\n".join(results) + f"\n{verdict}"


@mcp.tool()
def wifi_status() -> str:
    """Show Wi-Fi connection details for this machine: SSID, signal strength (dBm), bitrate, channel/frequency. Weak signal or low bitrate explains slow or flaky connections. Use when the user is on Wi-Fi and reports slowness or drops."""
    out = run(["iw", "dev"])
    ifaces = re.findall(r"Interface (\S+)", out)
    if not ifaces:
        return "No wireless interfaces found (this machine may be on Ethernet only)."
    reports = []
    for iface in ifaces:
        link = run(["iw", "dev", iface, "link"])
        reports.append(f"== {iface} ==\n{link}")
        sig = re.search(r"signal: (-?\d+) dBm", link)
        if sig:
            dbm = int(sig.group(1))
            quality = "excellent" if dbm >= -50 else "good" if dbm >= -60 else "fair" if dbm >= -70 else "weak — expect slowness/drops"
            reports.append(f"Signal assessment: {dbm} dBm ({quality})")
    return "\n".join(reports)


@mcp.tool()
def dns_server_check(hostname: str = "google.com", server: str = "") -> str:
    """Test DNS resolution against a specific DNS server (e.g. the router, 1.1.1.1, or 8.8.8.8). Leave `server` empty to test the system default. Comparing the router's DNS vs a public one isolates whether the router's DNS relay is the problem."""
    if shutil.which("dig") is None:
        return "error: dig not installed"
    cmd = ["dig", "+time=3", "+tries=1", "+stats", hostname]
    if server:
        cmd.insert(1, f"@{server}")
    out = run(cmd)
    keep = [l for l in out.splitlines() if re.match(r"^[^;]", l) or "Query time" in l or "SERVER:" in l or "status:" in l]
    return "\n".join(keep) if keep else out


@mcp.tool()
def http_check(url: str) -> str:
    """Fetch a URL's headers and report HTTP status plus timing breakdown (DNS, connect, total). Use to check whether a specific website/service is reachable and how slow each phase is."""
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return run([
        "curl", "-sI", "-m", "10", "-o", "/dev/null", "-w",
        "HTTP %{http_code}  dns=%{time_namelookup}s  connect=%{time_connect}s  tls=%{time_appconnect}s  total=%{time_total}s  (%{url_effective})",
        url,
    ])


@mcp.tool()
def listening_ports() -> str:
    """List TCP/UDP ports this machine is listening on (local services). Use to check whether an expected local service (SSH, web server, etc.) is actually running and bound."""
    return run(["ss", "-tuln"])


@mcp.tool()
def show_routes() -> str:
    """Show the full IP routing table. Use to spot missing default routes, wrong metrics, or VPN/route conflicts when traffic goes to the wrong place."""
    return run(["ip", "route", "show"])


@mcp.tool()
def interface_stats(interface: str = "") -> str:
    """Show packet/error/drop counters for network interfaces. Rising errors or drops indicate a bad cable, driver issue, or interference. Leave `interface` empty for all interfaces."""
    cmd = ["ip", "-s", "link", "show"]
    if interface:
        cmd += ["dev", interface]
    return run(cmd)


if __name__ == "__main__":
    mcp.run(transport="stdio")
