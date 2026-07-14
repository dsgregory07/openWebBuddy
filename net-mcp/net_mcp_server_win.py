#!/usr/bin/env python3
"""MCP server exposing local network diagnostic tools for offline router/LAN troubleshooting.

Windows port of net_mcp_server.py: same tool names and semantics, but the underlying
commands are the Windows equivalents (ping -n, tracert, netsh wlan, netstat, route,
Resolve-DnsName, arp) instead of the Linux ones (ping -c, traceroute, iw, ss, ip, dig).
"""
import re
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("net-diag")

TIMEOUT = 15


def run(cmd: list[str], timeout: int = TIMEOUT) -> str:
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


def run_ps(script: str, timeout: int = TIMEOUT) -> str:
    """Run a PowerShell snippet, forcing UTF-8 output so parsing is stable."""
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;" + script
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full], timeout=timeout
    )


def default_gateway() -> str | None:
    out = run_ps(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric | Select-Object -First 1;"
        " if ($r) { $r.NextHop }"
    )
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
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
    result = run(["ping", "-n", "4", "-w", "2000", gw])
    return f"Gateway: {gw}\n{result}"


# NOTE: intended for probing the user's own LAN/router; not restricted to any allowlist since this is a
# single-host offline diagnostic tool, not a multi-tenant service.
@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host (IP or hostname) to check reachability and latency. Use for the router, LAN devices, or any address you have permission to probe."""
    count = max(1, min(count, 10))
    return run(["ping", "-n", str(count), "-w", "2000", host], timeout=count * 3 + 10)


@mcp.tool()
def traceroute_host(host: str) -> str:
    """Trace the network path (hop by hop) to a host. Useful to see where connectivity breaks between this machine and the router/internet."""
    # tracert ships with Windows; -w is per-hop timeout (ms), -h caps the hop count.
    return run(["tracert", "-w", "2000", "-h", "15", host], timeout=90)


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve a hostname to its IP address(es) using the system resolver. Failing DNS while the gateway is pingable usually means WAN/internet, not LAN, is down."""
    out = run_ps(
        f"$a = Resolve-DnsName -Name '{hostname}' -Type A -ErrorAction SilentlyContinue |"
        " Where-Object {$_.IPAddress};"
        " if ($a) { $a.IPAddress -join \"`n\" } else { 'no A record / lookup failed' }"
    )
    return out or "no A record / lookup failed"


@mcp.tool()
def list_network_interfaces() -> str:
    """List local network interfaces, their state (up/down), and assigned IP addresses. Use to check whether this machine has a valid IP/link before blaming the router."""
    return run_ps(
        "Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object ifIndex | ForEach-Object {"
        " $ips = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue |"
        " Where-Object {$_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 'IPv6'} |"
        " ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }) -join ' ';"
        " '{0,-22} {1,-8} {2}' -f $_.Name, $_.Status, $ips"
        " } | Out-String"
    )


@mcp.tool()
def arp_scan_lan() -> str:
    """Discover live devices on the LAN (MAC + IP) from the local ARP table. Requires being on the LAN; does not need internet. Useful to confirm the router and other devices are actually present on the network during an outage."""
    # Windows has no built-in arp-scan; the ARP cache (`arp -a`) shows hosts this
    # machine has recently talked to and needs no admin rights.
    return run(["arp", "-a"])


def _expand_ports(spec: str, cap: int = 256) -> list[int]:
    if spec.strip() == "top-100":
        return _TOP_PORTS
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            ports.update(range(max(1, lo), min(hi, 65535) + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)[:cap]


_TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636,
    993, 995, 1080, 1194, 1433, 1521, 1723, 1900, 2049, 2082, 2083, 3128, 3306,
    3389, 3690, 4444, 5000, 5060, 5222, 5353, 5432, 5555, 5900, 5901, 6000, 6379,
    6667, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 27017,
]


def _tcp_scan(host: str, ports: list[int], timeout_ms: int = 250) -> list[int]:
    """Connect-scan a list of TCP ports via PowerShell; returns the open ones."""
    if not ports:
        return []
    port_csv = ",".join(str(p) for p in ports)
    script = (
        f"$h='{host}'; $open=@();"
        f" foreach ($p in @({port_csv})) {{"
        "   $c = New-Object System.Net.Sockets.TcpClient;"
        "   try {"
        "     $iar = $c.BeginConnect($h,$p,$null,$null);"
        f"     if ($iar.AsyncWaitHandle.WaitOne({timeout_ms})) {{"
        "       try { $c.EndConnect($iar); $open += $p } catch {}"
        "     }"
        "   } catch {} finally { $c.Close() }"
        " }"
        " ($open | Sort-Object) -join ','"
    )
    # Give the whole sweep enough time: worst case ~ ports * timeout.
    budget = int(len(ports) * (timeout_ms / 1000.0)) + 10
    out = run_ps(script, timeout=budget)
    return [int(x) for x in re.findall(r"\d+", out)]


@mcp.tool()
def port_scan(host: str, ports: str = "1-1024") -> str:
    """Scan a host's TCP ports to see which services are open (e.g. the router's admin/management interfaces). Use only against your own router/devices for troubleshooting or a basic security check. `ports` is a port spec, e.g. '1-1024', '22,80,443', or 'top-100'."""
    if shutil.which("nmap"):
        if ports == "top-100":
            args = ["nmap", "-F", "-T4", host]
        else:
            args = ["nmap", "-p", ports, "-T4", host]
        return run(args, timeout=90)
    # No nmap: fall back to a built-in TCP connect scan (capped for responsiveness).
    wanted = _expand_ports(ports)
    if not wanted:
        return "error: no valid ports in spec"
    open_ports = _tcp_scan(host, wanted)
    note = "" if len(wanted) < 256 else " (list capped at 256 ports — install nmap for full scans)"
    if open_ports:
        listing = "\n".join(f"{p}/tcp open" for p in open_ports)
        return f"Open TCP ports on {host}{note}:\n{listing}"
    return f"No open TCP ports found on {host} among {len(wanted)} scanned{note}."


@mcp.tool()
def router_quick_audit() -> str:
    """Run a quick composite check against the default gateway: reachability, open management ports (21,22,23,53,80,443,8080,8443), and a note on any risky-looking open services (telnet, unauthenticated admin ports). Good first call for 'is my router OK' questions."""
    gw = default_gateway()
    if not gw:
        return "No default gateway configured — cannot audit router."
    ping_result = run(["ping", "-n", "2", "-w", "2000", gw])
    ping_summary_match = re.search(r"Packets:.*", ping_result)
    ping_summary = ping_summary_match.group(0) if ping_summary_match else ping_result
    audit_ports = [21, 22, 23, 53, 80, 443, 8080, 8443]

    if shutil.which("nmap"):
        scan_result = run(["nmap", "-p", "21,22,23,53,80,443,8080,8443", "-T4", gw], timeout=45)
        open_ports = {int(m) for m in re.findall(r"^(\d+)/tcp\s+open", scan_result, re.M)}
        port_lines = "\n".join(
            line for line in scan_result.splitlines() if re.match(r"^\d+/tcp\s", line)
        ) or scan_result
    else:
        open_ports = set(_tcp_scan(gw, audit_ports))
        port_lines = (
            "\n".join(f"{p}/tcp open" for p in sorted(open_ports))
            or "none of the checked management ports are open"
        )

    flags = []
    if 23 in open_ports:
        flags.append("Port 23 (telnet) is OPEN — telnet is unencrypted and a common router weakness; disable it if not needed.")
    if 21 in open_ports:
        flags.append("Port 21 (FTP) is OPEN — check if this is required; FTP credentials are sent in plaintext.")
    flag_text = "\n".join(flags) if flags else "No obviously risky ports flagged among the common set checked."
    return f"Gateway: {gw}\nPing: {ping_summary}\n\nOpen ports scanned:\n{port_lines}\n\n{flag_text}"


@mcp.tool()
def check_internet() -> str:
    """Composite WAN/internet check: ping a public IP, resolve a hostname, and fetch a web page. Distinguishes 'LAN up but internet down' from 'DNS broken' from 'all good'. Use after check_gateway_reachable when diagnosing internet problems."""
    results = []
    ip_ping = run(["ping", "-n", "2", "-w", "2000", "1.1.1.1"])
    # Windows ping reports "Lost = N (P% loss)".
    loss = re.search(r"\((\d+(?:\.\d+)?)%\s+loss\)", ip_ping)
    ip_ok = loss is not None and float(loss.group(1)) == 0
    m = re.search(r"Packets:.*", ip_ping)
    results.append(f"Ping 1.1.1.1 (raw IP): {m.group(0) if m else ip_ping}")

    dns = run_ps(
        "$a = Resolve-DnsName -Name 'google.com' -Type A -ErrorAction SilentlyContinue |"
        " Where-Object {$_.IPAddress} | Select-Object -First 1;"
        " if ($a) { $a.IPAddress }"
    )
    dns_ok = bool(re.search(r"^\d+\.\d+\.\d+\.\d+", dns, re.M))
    results.append(f"DNS lookup google.com: {dns.splitlines()[0] if dns_ok else 'FAILED — ' + dns}")

    http = run(["curl", "-sI", "-m", "8", "-o", "NUL", "-w", "%{http_code} in %{time_total}s",
                "http://connectivitycheck.gstatic.com/generate_204"])
    http_ok = http.startswith("204") or http.startswith("200")
    results.append(f"HTTP check: {http}")

    if ip_ok and dns_ok and http_ok:
        verdict = "VERDICT: Internet connectivity looks fully working."
    elif ip_ok and not dns_ok:
        verdict = "VERDICT: Raw internet (IP) works but DNS is broken — check the router's DNS settings or the adapter's DNS servers."
    elif not ip_ok:
        verdict = "VERDICT: No internet at IP level — if the gateway pings OK, the problem is upstream (modem/ISP/WAN)."
    else:
        verdict = "VERDICT: Partial connectivity — DNS resolves but web traffic fails; possible captive portal or firewall."
    return "\n".join(results) + f"\n{verdict}"


@mcp.tool()
def wifi_status() -> str:
    """Show Wi-Fi connection details for this machine: SSID, signal strength, radio type, channel, and rates. Weak signal or low rate explains slow or flaky connections. Use when the user is on Wi-Fi and reports slowness or drops."""
    out = run(["netsh", "wlan", "show", "interfaces"])
    if "no wireless interface" in out.lower() or "not running" in out.lower():
        return "No wireless interfaces found (this machine may be on Ethernet only, or the WLAN service is off)."
    # Windows reports signal as a quality percentage rather than dBm.
    sig = re.search(r"Signal\s*:\s*(\d+)%", out)
    if sig:
        pct = int(sig.group(1))
        quality = (
            "excellent" if pct >= 75 else
            "good" if pct >= 50 else
            "fair" if pct >= 30 else
            "weak — expect slowness/drops"
        )
        out += f"\nSignal assessment: {pct}% ({quality})"
    return out


@mcp.tool()
def dns_server_check(hostname: str = "google.com", server: str = "") -> str:
    """Test DNS resolution against a specific DNS server (e.g. the router, 1.1.1.1, or 8.8.8.8). Leave `server` empty to test the system default. Comparing the router's DNS vs a public one isolates whether the router's DNS relay is the problem."""
    server_arg = f" -Server '{server}'" if server else ""
    script = (
        "$sw = [System.Diagnostics.Stopwatch]::StartNew();"
        f" $a = Resolve-DnsName -Name '{hostname}' -Type A{server_arg} -ErrorAction SilentlyContinue |"
        " Where-Object {$_.IPAddress};"
        " $sw.Stop();"
        " if ($a) {"
        "   'Server: ' + $(if ('" + server + "') {'" + server + "'} else {'(system default)'});"
        f"   'Name:   {hostname}';"
        "   'Answers: ' + (($a.IPAddress) -join ', ');"
        "   'Query time: ' + $sw.ElapsedMilliseconds + ' ms'"
        " } else {"
        "   'status: NXDOMAIN / SERVFAIL / no answer (query failed)'"
        " }"
    )
    return run_ps(script)


@mcp.tool()
def http_check(url: str) -> str:
    """Fetch a URL's headers and report HTTP status plus timing breakdown (DNS, connect, total). Use to check whether a specific website/service is reachable and how slow each phase is."""
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return run([
        "curl", "-sI", "-m", "10", "-o", "NUL", "-w",
        "HTTP %{http_code}  dns=%{time_namelookup}s  connect=%{time_connect}s  tls=%{time_appconnect}s  total=%{time_total}s  (%{url_effective})",
        url,
    ])


@mcp.tool()
def listening_ports() -> str:
    """List TCP/UDP ports this machine is listening on (local services). Use to check whether an expected local service (SSH, web server, etc.) is actually running and bound."""
    tcp = run_ps(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |"
        " Sort-Object LocalPort |"
        " ForEach-Object { 'TCP {0,-24} :{1}' -f $_.LocalAddress, $_.LocalPort } |"
        " Get-Unique | Out-String"
    )
    udp = run_ps(
        "Get-NetUDPEndpoint -ErrorAction SilentlyContinue |"
        " Sort-Object LocalPort |"
        " ForEach-Object { 'UDP {0,-24} :{1}' -f $_.LocalAddress, $_.LocalPort } |"
        " Get-Unique | Out-String"
    )
    both = "\n".join(s for s in (tcp.strip(), udp.strip()) if s)
    return both or run(["netstat", "-an"])


@mcp.tool()
def show_routes() -> str:
    """Show the IPv4 routing table. Use to spot missing default routes, wrong metrics, or VPN/route conflicts when traffic goes to the wrong place."""
    return run(["route", "print", "-4"])


@mcp.tool()
def interface_stats(interface: str = "") -> str:
    """Show packet/error/drop counters for network interfaces. Rising errors or drops indicate a bad cable, driver issue, or interference. Leave `interface` empty for all interfaces."""
    if interface:
        script = (
            f"Get-NetAdapterStatistics -Name '{interface}' -ErrorAction SilentlyContinue |"
            " Format-List Name,ReceivedBytes,ReceivedUnicastPackets,ReceivedDiscardedPackets,"
            "ReceivedPacketErrors,SentBytes,SentUnicastPackets,OutboundDiscardedPackets,"
            "OutboundPacketErrors | Out-String"
        )
    else:
        script = (
            "Get-NetAdapterStatistics -ErrorAction SilentlyContinue |"
            " Format-Table Name,ReceivedBytes,ReceivedPacketErrors,ReceivedDiscardedPackets,"
            "SentBytes,OutboundPacketErrors,OutboundDiscardedPackets -AutoSize | Out-String"
        )
    return run_ps(script)


if __name__ == "__main__":
    mcp.run(transport="stdio")
