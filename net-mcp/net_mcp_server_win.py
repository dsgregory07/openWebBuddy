#!/usr/bin/env python3
"""MCP server exposing local network diagnostic tools for offline router/LAN troubleshooting.

Windows port of net_mcp_server.py: same tool names and semantics, but the underlying
commands are the Windows equivalents (ping -n, tracert, netsh wlan, netstat, route,
Resolve-DnsName, arp) instead of the Linux ones (ping -c, traceroute, iw, ss, ip, dig).
"""
import os
import re
import shutil
import socket
import sys
import time
import urllib.request

# Shared helpers + tunable config live at the repo root; both MCP servers import them.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from net_common import (  # noqa: E402
    run, run_ps, ps_quote, default_gateway, local_subnet_24, env_int, PING_WAIT_MS,
)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("net-diag")

# --- Tunable knobs (env-overridable; defaults preserve the previous hardcoded values) ---
TRACEROUTE_WAIT_MS = env_int("NETDIAG_TRACEROUTE_WAIT_MS", 2000)  # tracert -w, per-hop (ms)
TRACEROUTE_MAX_HOPS = env_int("NETDIAG_TRACEROUTE_MAX_HOPS", 15)  # tracert -h
TCP_SCAN_TIMEOUT_MS = env_int("NETDIAG_TCP_SCAN_TIMEOUT_MS", 250)  # per-port connect timeout
TCP_SCAN_CAP = env_int("NETDIAG_TCP_SCAN_CAP", 256)  # max ports the built-in fallback scans
HTTP_TIMEOUT = env_int("NETDIAG_HTTP_TIMEOUT", 10)  # curl -m for http_check (s)
CONNCHECK_TIMEOUT = env_int("NETDIAG_CONNCHECK_TIMEOUT", 8)  # curl -m for check_internet (s)
WIFI_SIGNAL_EXCELLENT = env_int("NETDIAG_WIFI_EXCELLENT", 75)  # signal percent thresholds
WIFI_SIGNAL_GOOD = env_int("NETDIAG_WIFI_GOOD", 50)
WIFI_SIGNAL_FAIR = env_int("NETDIAG_WIFI_FAIR", 30)
DISCO_SWEEP_TIMEOUT_MS = env_int("NETDIAG_DISCO_SWEEP_TIMEOUT_MS", 300)  # per-host ping in dev_disco's sweep
DISCO_SWEEP_BUDGET_MS = env_int("NETDIAG_DISCO_SWEEP_BUDGET_MS", 6000)  # overall sweep wait cap
DISCO_SSDP_TIMEOUT = env_int("NETDIAG_DISCO_SSDP_TIMEOUT", 3)  # seconds to wait for SSDP replies
DISCO_SSDP_FETCH_TIMEOUT = env_int("NETDIAG_DISCO_SSDP_FETCH_TIMEOUT", 2)  # per-device description fetch (s)


def _fmt_bytes(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{int(x)} B" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} TB"


def _summarize_ping(raw: str) -> str:
    """Boil Windows ping output down to a couple of lines; pass through anything unparseable."""
    stats = re.search(
        r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)"
        r"\s*\((\d+(?:\.\d+)?)%\s*loss\)",
        raw,
    )
    if not stats:
        return raw
    sent, received, _lost, loss_pct = stats.groups()
    target = re.search(r"Pinging\s+(\S+?)(?:\s+\[(\S+)\])?\s+with", raw)
    if target:
        label = f"{target.group(1)} [{target.group(2)}]" if target.group(2) else target.group(1)
    else:
        label = "host"
    line = f"Ping {label}: sent={sent} received={received} loss={loss_pct}%"
    rtt = re.search(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms", raw)
    if rtt:
        line += f", rtt min/avg/max = {rtt.group(1)}/{rtt.group(3)}/{rtt.group(2)} ms"
    problems = []
    for pat, msg in (
        (r"Request timed out", "request timed out"),
        (r"Destination host unreachable", "destination host unreachable"),
        (r"General failure", "general failure (local TCP/IP stack or adapter problem)"),
        (r"transmit failed", "transmit failed (local adapter problem)"),
        (r"TTL expired", "TTL expired in transit (possible routing loop)"),
    ):
        n = len(re.findall(pat, raw, re.IGNORECASE))
        if n:
            problems.append(f"{msg} x{n}")
    if problems:
        line += "\nProblems: " + "; ".join(problems)
    # Windows counts "Destination host unreachable" replies as received packets.
    if int(received) > 0 and re.search(r"Destination host unreachable", raw, re.IGNORECASE):
        line += "\nNote: 'unreachable' replies count as received - treat this ping as FAILED."
    return line


def _find_nmap_data_file(filename: str) -> str | None:
    """Locate a data file bundled with nmap's install (nmap-mac-prefixes, nmap-services)
    without needing to run nmap.exe itself - a plain file read is enough for a vendor/name
    lookup. Returns None if nmap is not installed (callers degrade gracefully)."""
    nmap_path = shutil.which("nmap")
    candidates = []
    if nmap_path:
        candidates.append(os.path.join(os.path.dirname(nmap_path), filename))
    for base in (
        os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"), r"C:\Program Files", r"C:\Program Files (x86)",
    ):
        if base:
            candidates.append(os.path.join(base, "Nmap", filename))
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


_OUI_CACHE: dict | None = None


def _load_oui_table() -> dict:
    """MAC-prefix (first 3 bytes, no separators) -> vendor name, from nmap's bundled
    nmap-mac-prefixes (IEEE OUI registry, ~52k entries). Cached after first load. Empty dict
    (not an error) if nmap is not installed - vendor lookups just come back empty."""
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    _OUI_CACHE = {}
    path = _find_nmap_data_file("nmap-mac-prefixes")
    if path:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        _OUI_CACHE[parts[0].upper()] = parts[1].strip()
        except OSError:
            pass
    return _OUI_CACHE


def _vendor_for_mac(mac: str) -> str | None:
    prefix = re.sub(r"[:-]", "", mac).upper()[:6]
    return _load_oui_table().get(prefix)


_SVC_CACHE: dict | None = None


def _load_service_names() -> dict:
    """(port, proto) -> service name, from nmap's bundled nmap-services. Cached after first
    load. Lets the no-nmap port_scan fallback label services by port number, same as the
    nmap-backed path, without needing nmap.exe at scan time - just its data file."""
    global _SVC_CACHE
    if _SVC_CACHE is not None:
        return _SVC_CACHE
    _SVC_CACHE = {}
    path = _find_nmap_data_file("nmap-services")
    if path:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip() or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 2 and "/" in parts[1]:
                        p, _, proto = parts[1].strip().partition("/")
                        if p.isdigit():
                            _SVC_CACHE[(int(p), proto)] = parts[0].strip()
        except OSError:
            pass
    return _SVC_CACHE


def _parse_grepable_ports(gout: str) -> list[tuple[int, str, str]]:
    """Parse an nmap grepable (-oG -) 'Ports:' field. Returns (port, proto, service) for
    OPEN ports only - the same shape port_scan's no-nmap fallback produces, so both paths
    render identically regardless of whether nmap happens to be installed."""
    m = re.search(r"Ports:\s*(.*?)(?:\tIgnored State|\n|$)", gout)
    if not m:
        return []
    entries = []
    for item in m.group(1).split(","):
        fields = item.strip().split("/")
        if len(fields) >= 5 and fields[1] == "open":
            entries.append((int(fields[0]), fields[2], fields[4] or "?"))
    return entries


def _ssdp_discover(timeout: float = DISCO_SSDP_TIMEOUT) -> dict:
    """Send one SSDP M-SEARCH (UDP multicast) and fetch each responder's device description.
    Returns {ip: {"friendlyName":..., "manufacturer":..., "modelName":...}} for whatever
    fields each device published (missing keys just mean that device didn't include them).

    Pure Python (socket + urllib) - no nmap, no admin rights. SSDP is UDP multicast, not raw
    packet injection, so this is Wi-Fi-safe and works with or without Npcap. Devices that
    don't speak SSDP (many IoT devices use their own proprietary discovery instead) simply
    do not appear here - absence is not proof a device is unreachable, just that this one
    channel didn't find it.
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    locations: dict[str, str] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            ip = addr[0]
            if ip in locations:
                continue
            m = re.search(r"LOCATION:\s*(\S+)", data.decode(errors="replace"), re.IGNORECASE)
            if m:
                locations[ip] = m.group(1)
        sock.close()
    except OSError:
        return {}
    results = {}
    for ip, loc in locations.items():
        try:
            with urllib.request.urlopen(loc, timeout=DISCO_SSDP_FETCH_TIMEOUT) as resp:
                xml = resp.read(4096).decode(errors="replace")
        except Exception:
            continue
        info = {}
        for tag in ("friendlyName", "manufacturer", "modelName"):
            m = re.search(f"<{tag}>(.*?)</{tag}>", xml)
            if m:
                info[tag] = m.group(1).strip()
        if info:
            results[ip] = info
    return results


# tools below use run()/run_ps() and return compact summaries; anything unparseable
# falls through as the raw command output so no information is ever lost.


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
    summary = _summarize_ping(run(["ping", "-n", "4", "-w", str(PING_WAIT_MS), gw]))
    low = summary.lower()
    if "loss=0%" in summary and "unreachable" not in low:
        verdict = "VERDICT: LAN OK - the router answers."
    elif "loss=100%" in summary or "unreachable" in low:
        verdict = "VERDICT: router NOT reachable - the problem is on the LAN side (adapter, cable/Wi-Fi link, or the router itself), not the internet."
    else:
        verdict = "VERDICT: partial packet loss to the router - flaky LAN link (cable/Wi-Fi/interference)."
    return f"Gateway: {gw}\n{summary}\n{verdict}"


# NOTE: intended for probing the user's own LAN/router; not restricted to any allowlist since this is a
# single-host offline diagnostic tool, not a multi-tenant service.
@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """Ping a host (IP or hostname) to check reachability and latency. Use for the router, LAN devices, or any address you have permission to probe. Returns a one-line loss/latency summary."""
    count = max(1, min(count, 10))
    return _summarize_ping(run(["ping", "-n", str(count), "-w", str(PING_WAIT_MS), host], timeout=count * 3 + 10))


@mcp.tool()
def traceroute_host(host: str) -> str:
    """Trace the network path (hop by hop) to a host. Useful to see where connectivity breaks between this machine and the router/internet. One line per hop; '*' means that hop did not answer."""
    # tracert ships with Windows; -w is per-hop timeout (ms), -h caps the hop count.
    raw = run(["tracert", "-w", str(TRACEROUTE_WAIT_MS), "-h", str(TRACEROUTE_MAX_HOPS), host], timeout=90)
    # tracert output is whitespace-padded; collapse it so it costs fewer tokens to read.
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in raw.splitlines()]
    return "\n".join(ln for ln in lines if ln)


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve a hostname to its IP address(es), OR - given an IP instead - resolve it back to a name via reverse DNS, falling back to a NetBIOS name query if there is no PTR record. Failing DNS while the gateway is pingable usually means WAN/internet, not LAN, is down. The reverse direction is useful for naming a device dev_disco found but could not otherwise identify: most home routers have no local PTR records, but a Windows/SMB device often still answers NetBIOS; non-Windows devices typically answer neither, which is a normal result, not an error."""
    hostname = hostname.strip()
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        out = run_ps(
            f"$a = Resolve-DnsName -Name '{ps_quote(hostname)}' -Type A -ErrorAction SilentlyContinue |"
            " Where-Object {$_.IPAddress};"
            " if ($a) { $a.IPAddress -join \"`n\" } else { 'no A record / lookup failed' }"
        )
        return out or "no A record / lookup failed"
    # IP given: try reverse DNS first, then NetBIOS.
    ip = ps_quote(hostname)
    ptr = run_ps(
        f"$a = Resolve-DnsName -Name '{ip}' -Type PTR -ErrorAction SilentlyContinue;"
        " if ($a) { ($a | Select-Object -First 1).NameHost }"
    ).strip()
    if ptr and not ptr.startswith("error:") and not ptr.startswith("[exit"):
        return f"{hostname} -> {ptr} (reverse DNS)"
    nb = run(["nbtstat", "-A", hostname], timeout=15)
    m = re.search(r"^\s*(\S+)\s+<20>\s+UNIQUE", nb, re.M) or re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", nb, re.M)
    if m:
        return f"{hostname} -> {m.group(1)} (NetBIOS name)"
    return (
        f"{hostname}: no reverse-DNS record and no NetBIOS response. This is a normal result "
        "for most non-Windows devices (routers, IoT, phones) and for LANs with no local DNS "
        "server registering DHCP client names - it does not mean the device is unreachable."
    )


@mcp.tool()
def list_network_interfaces() -> str:
    """List local network interfaces with state (up/down), link speed, and assigned IP addresses. Use to check whether this machine has a valid IP/link before blaming the router. An adapter that is Up with only a 169.254.x.x IP means DHCP failed."""
    out = run_ps(
        "Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object ifIndex | ForEach-Object {"
        " $ips = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue |"
        " Where-Object {$_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 'IPv6'} |"
        " ForEach-Object { \"$($_.IPAddress)/$($_.PrefixLength)\" }) -join ' ';"
        " '{0,-22} {1,-8} {2,-10} {3}' -f $_.Name, $_.Status, $_.LinkSpeed, $ips"
        " } | Out-String"
    )
    if out.startswith("error:") or out.startswith("[exit"):
        return out
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        return out
    return "name / status / speed / IPs\n" + "\n".join(lines)


@mcp.tool()
def dev_disco(host: str = "") -> str:
    """Discover and IDENTIFY devices on the LAN - not just a bare IP list. Leave `host` empty to actively sweep the whole local subnet; pass a single IP to focus identification on just that device. Combines three signals: (1) an active ping sweep so results reflect who is up right now, not stale traffic; (2) SSDP/UPnP - many devices (routers, smart TVs, streaming boxes, speakers) self-announce a real name/manufacturer/model, which is a CONFIRMED identity, not a guess; (3) MAC-vendor lookup (from nmap's offline OUI database) for devices SSDP does not catch - this is a hint from the manufacturer prefix, not a confirmed identity. Use this instead of ping/arp alone whenever the question is 'what is on my network' or 'what is this device'. Some devices answer none of these channels and stay 'identity unknown' - that does not mean they are not present, only that they did not self-announce."""
    single = host.strip()
    target_ip = single or None
    subnet = None
    if not target_ip:
        subnet = local_subnet_24()
        if not subnet:
            return "error: could not determine the local subnet (no IPv4 on the default-route interface). Pass a specific IP instead."

    # 1) Active freshness sweep - a single ping for a targeted host, or a concurrent sweep of
    # the whole /24 via .NET's async Ping (no nmap needed, same async pattern _tcp_scan uses).
    if target_ip:
        run(["ping", "-n", "1", "-w", str(PING_WAIT_MS), target_ip])
        live_ips = {target_ip}
    else:
        base = subnet.rsplit(".", 1)[0] + "."
        sweep = run_ps(
            f"$base='{base}';"
            " $tasks = 1..254 | ForEach-Object {"
            "   $p = New-Object System.Net.NetworkInformation.Ping;"
            f"   $p.SendPingAsync(\"$base$_\", {DISCO_SWEEP_TIMEOUT_MS})"
            " };"
            f" [System.Threading.Tasks.Task]::WaitAll($tasks, {DISCO_SWEEP_BUDGET_MS}) | Out-Null;"
            " $tasks | Where-Object { $_.Result.Status -eq 'Success' } |"
            " ForEach-Object { $_.Result.Address.ToString() }",
            timeout=int(DISCO_SWEEP_BUDGET_MS / 1000) + 10,
        )
        live_ips = set(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", sweep))

    # 2) SSDP/UPnP identity merge - confirmed device-reported name/manufacturer/model.
    ssdp = _ssdp_discover()

    # 3) Structured ARP read (Get-NetNeighbor - richer than 'arp -a' text parsing) for MAC,
    # then vendor lookup for whatever SSDP did not identify. Get-NetNeighbor returns entries
    # from EVERY interface (VPNs, VirtualBox host-only adapters, etc.), including placeholder
    # rows with no real MAC - so exclude Unreachable/Incomplete states and the null MAC here,
    # and scope to this subnet below so an unrelated interface's table can't pollute the sweep.
    arp_out = run_ps(
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
        " Where-Object { $_.State -notin @('Unreachable','Incomplete')"
        " -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |"
        " ForEach-Object { $_.IPAddress + '|' + $_.LinkLayerAddress + '|' + $_.State }"
    )
    mac_by_ip = {}
    for line in arp_out.splitlines():
        parts = line.split("|")
        if len(parts) == 3 and re.match(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$", parts[1]):
            mac_by_ip[parts[0]] = parts[1]

    if not target_ip:
        # Full sweep: scope every signal to THIS subnet so another interface's neighbor
        # table (or a stray SSDP responder on a different virtual network) cannot leak in.
        prefix = subnet.rsplit(".", 1)[0] + "."
        mac_by_ip = {ip: mac for ip, mac in mac_by_ip.items() if ip.startswith(prefix)}
        ssdp = {ip: info for ip, info in ssdp.items() if ip.startswith(prefix)}

    all_ips = live_ips | set(ssdp) | set(mac_by_ip)
    if target_ip:
        all_ips &= {target_ip}
    if not all_ips:
        where = f"at {target_ip}" if target_ip else f"on {subnet}"
        return f"dev_disco: no devices found {where}."

    label = f"on {target_ip}" if target_ip else f"- active sweep of {subnet}"
    lines = [f"Device discovery {label} ({len(all_ips)} device(s)):"]
    for ip in sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        bits = [ip]
        if ip in ssdp:
            d = ssdp[ip]
            identity = " - ".join(v for v in (d.get("friendlyName"), d.get("manufacturer"), d.get("modelName")) if v)
            bits.append(f"{identity}  [SSDP confirmed]")
        else:
            mac = mac_by_ip.get(ip)
            vendor = _vendor_for_mac(mac) if mac else None
            bits.append(f"vendor: {vendor}  [MAC-based guess, not confirmed]" if vendor else "identity unknown")
        if ip in mac_by_ip:
            bits.append(f"({mac_by_ip[ip]})")
        bits.append("up" if ip in live_ips else "in ARP cache (not answering ping right now)")
        lines.append("  " + "  ".join(bits))
    lines.append(
        "SSDP identities are self-reported by the device (confirmed); vendor-only entries are "
        "a MAC-prefix guess, not a confirmed identity. 'identity unknown' means neither channel "
        "caught it - the device may still be present but silent on both."
    )
    return "\n".join(lines)


def _expand_ports(spec: str, cap: int = TCP_SCAN_CAP) -> list[int]:
    if spec.strip() == "top-100":
        return _top_ports()
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


# nmap's own top-100 TCP ports by real-world frequency (from its bundled nmap-services
# database - the same data --top-ports 100 / -F reads). Read directly from that file so this
# fallback scans the SAME 100 ports nmap would, instead of a smaller, differently-ranked list.
_FALLBACK_TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]


def _top_ports() -> list[int]:
    """nmap's real top-100 if its data file is present (kept in exact sync with the nmap-
    backed scan path); the verified static fallback above otherwise. Either way this is the
    SAME 100 ports port_scan's two code paths will scan under the 'top-100' label."""
    path = _find_nmap_data_file("nmap-services")
    if not path:
        return _FALLBACK_TOP_100
    try:
        rows = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 3 and parts[1].endswith("/tcp"):
                    port = parts[1].split("/", 1)[0]
                    if port.isdigit():
                        try:
                            rows.append((float(parts[2]), int(port)))
                        except ValueError:
                            continue
        if not rows:
            return _FALLBACK_TOP_100
        rows.sort(key=lambda r: (-r[0], r[1]))
        return sorted(p for _freq, p in rows[:100])
    except OSError:
        return _FALLBACK_TOP_100


def _tcp_scan(host: str, ports: list[int], timeout_ms: int = TCP_SCAN_TIMEOUT_MS) -> list[int]:
    """Connect-scan a list of TCP ports via PowerShell; returns the open ones."""
    if not ports:
        return []
    port_csv = ",".join(str(p) for p in ports)
    script = (
        f"$h='{ps_quote(host)}'; $open=@();"
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
    """Scan a host's TCP ports to see which services are open (e.g. the router's admin/management interfaces). Use only against your own router/devices for troubleshooting or a basic security check. `ports` is a port spec, e.g. '1-1024', '22,80,443', or 'top-100' (the SAME 100 ports whether or not nmap is installed). Output is an open-port list with service names; it cannot distinguish closed from filtered - for that, or full service/version detection, use the net-vuln tools."""
    if shutil.which("nmap"):
        # -sT (connect) + -Pn: an unprivileged connect scan that never opens the network
        # adapter for raw packet injection - so it cannot knock a USB Wi-Fi adapter offline
        # the way a raw SYN scan can. For filtered-vs-closed / service versions, use net-vuln.
        # -oG -: grepable output, parsed into the SAME shape as the no-nmap fallback below,
        # so the model gets consistent output regardless of whether nmap happens to be present.
        args = ["nmap", "-sT", "-Pn", "-T4", "-oG", "-"]
        args += ["-F"] if ports == "top-100" else ["-p", ports]
        args.append(host)
        gout = run(args, timeout=90)
        m_status = re.search(r"Status:\s*(\S+)", gout)
        if not m_status:
            return gout or "error: nmap returned no output."
        if m_status.group(1) != "Up":
            return f"Port scan of {host}: host did not respond (nmap)."
        entries = _parse_grepable_ports(gout)
        ignored = re.search(r"Ignored State:\s*(\w+)\s*\((\d+)\)", gout)
        tail = f" ({ignored.group(2)} {ignored.group(1)})" if ignored else ""
        if entries:
            listing = "\n".join(f"{p}/{proto} open  {svc}" for p, proto, svc in entries)
            return f"Open TCP ports on {host} (nmap connect scan, ports {ports}){tail}:\n{listing}"
        return f"No open TCP ports found on {host} (nmap connect scan, ports {ports}){tail}."
    # No nmap: fall back to a built-in TCP connect scan (capped for responsiveness), labeling
    # ports from nmap's bundled service-name data (no nmap.exe needed, just its data file).
    wanted = _expand_ports(ports)
    if not wanted:
        return "error: no valid ports in spec"
    open_ports = _tcp_scan(host, wanted)
    svc_names = _load_service_names()
    note = "" if len(wanted) < TCP_SCAN_CAP else f" (list capped at {TCP_SCAN_CAP} ports - install nmap for full scans)"
    if open_ports:
        listing = "\n".join(f"{p}/tcp open  {svc_names.get((p, 'tcp'), '?')}" for p in open_ports)
        return f"Open TCP ports on {host} (connect scan, ports {ports}){note}:\n{listing}"
    return f"No open TCP ports found on {host} among {len(wanted)} scanned (connect scan, ports {ports}){note}."


@mcp.tool()
def router_quick_audit() -> str:
    """Run a quick composite check against the default gateway: reachability, open management ports (21,22,23,53,80,443,8080,8443), and a flag if telnet (23) or FTP (21) - both plaintext-credential protocols - are open among them. Good first call for 'is my router OK' questions."""
    gw = default_gateway()
    if not gw:
        return "No default gateway configured — cannot audit router."
    ping_result = run(["ping", "-n", "2", "-w", str(PING_WAIT_MS), gw])
    ping_summary_match = re.search(r"Packets:.*", ping_result)
    ping_summary = ping_summary_match.group(0) if ping_summary_match else ping_result
    audit_ports = [21, 22, 23, 53, 80, 443, 8080, 8443]

    if shutil.which("nmap"):
        # -sT -Pn: Wi-Fi-safe connect scan (see port_scan); derive the port list from
        # audit_ports so the two never drift out of sync.
        scan_result = run(["nmap", "-sT", "-Pn", "-p", ",".join(str(p) for p in audit_ports), "-T4", gw], timeout=45)
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
    ip_ping = run(["ping", "-n", "2", "-w", str(PING_WAIT_MS), "1.1.1.1"])
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

    http = run(["curl", "-sI", "-m", str(CONNCHECK_TIMEOUT), "-o", "NUL", "-w", "%{http_code} in %{time_total}s",
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
    kv = {}
    for line in out.splitlines():
        m = re.match(r"\s*([^:]+?)\s*:\s*(.+?)\s*$", line)
        if m:
            kv.setdefault(m.group(1), m.group(2))
    state = kv.get("State")
    if not state:
        return out  # unexpected shape - hand back the raw output
    if state.lower() != "connected":
        return f"Wi-Fi interface '{kv.get('Name', '?')}' is {state} - not connected to any network."
    lines = [
        f"Wi-Fi: connected to SSID '{kv.get('SSID', '?')}' "
        f"(channel {kv.get('Channel', '?')}, {kv.get('Radio type', '?')}, BSSID {kv.get('BSSID', '?')})"
    ]
    # Windows reports signal as a quality percentage rather than dBm.
    sig = re.search(r"(\d+)%", kv.get("Signal", ""))
    if sig:
        pct = int(sig.group(1))
        quality = (
            "excellent" if pct >= WIFI_SIGNAL_EXCELLENT else
            "good" if pct >= WIFI_SIGNAL_GOOD else
            "fair" if pct >= WIFI_SIGNAL_FAIR else
            "weak - expect slowness/drops"
        )
        lines.append(f"Signal: {pct}% ({quality})")
    rx = kv.get("Receive rate (Mbps)")
    tx = kv.get("Transmit rate (Mbps)")
    if rx or tx:
        lines.append(f"Rates: receive {rx or '?'} Mbps / transmit {tx or '?'} Mbps")
    if kv.get("Authentication"):
        lines.append(f"Auth: {kv['Authentication']}")
    return "\n".join(lines)


@mcp.tool()
def dns_server_check(hostname: str = "google.com", server: str = "") -> str:
    """Test DNS resolution against a specific DNS server (e.g. the router, 1.1.1.1, or 8.8.8.8). Leave `server` empty to test the system default. Comparing the router's DNS vs a public one isolates whether the router's DNS relay is the problem."""
    hn = ps_quote(hostname)
    server_arg = f" -Server '{ps_quote(server)}'" if server else ""
    server_label = ps_quote(server if server else "(system default)")
    script = (
        "$sw = [System.Diagnostics.Stopwatch]::StartNew();"
        f" $a = Resolve-DnsName -Name '{hn}' -Type A{server_arg} -ErrorAction SilentlyContinue |"
        " Where-Object {$_.IPAddress};"
        " $sw.Stop();"
        " if ($a) {"
        f"   'Server: {server_label}';"
        f"   'Name:   {hn}';"
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
        "curl", "-sI", "-m", str(HTTP_TIMEOUT), "-o", "NUL", "-w",
        "HTTP %{http_code}  dns=%{time_namelookup}s  connect=%{time_connect}s  tls=%{time_appconnect}s  total=%{time_total}s  (%{url_effective})",
        url,
    ])


@mcp.tool()
def listening_ports() -> str:
    """List TCP/UDP ports this machine is listening on (local services), grouped by bind address. Use to check whether an expected local service (SSH, web server, etc.) is actually running and bound."""
    tcp = run_ps(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |"
        " ForEach-Object { $_.LocalAddress + '|' + $_.LocalPort }"
    )
    udp = run_ps(
        "Get-NetUDPEndpoint -ErrorAction SilentlyContinue |"
        " ForEach-Object { $_.LocalAddress + '|' + $_.LocalPort }"
    )

    def _group(raw: str, proto: str) -> list[str]:
        by_addr: dict[str, set[int]] = {}
        for line in raw.splitlines():
            if "|" not in line:
                continue
            addr, _, port = line.rpartition("|")
            try:
                by_addr.setdefault(addr.strip(), set()).add(int(port))
            except ValueError:
                continue
        out = []
        for addr in sorted(by_addr):
            ports = sorted(by_addr[addr])
            shown = ", ".join(str(p) for p in ports[:40])
            extra = f" (+{len(ports) - 40} more)" if len(ports) > 40 else ""
            out.append(f"{proto} on {addr}: {shown}{extra}")
        return out

    lines = _group(tcp, "TCP") + _group(udp, "UDP")
    if not lines:
        return run(["netstat", "-an"])
    lines.append("(0.0.0.0 / :: = listening on all interfaces; 127.0.0.1 / ::1 = loopback only)")
    return "\n".join(lines)


@mcp.tool()
def show_routes() -> str:
    """Summarize the IPv4 routing table: default route(s), on-link subnets, and any gateway routes. Use to spot missing default routes, wrong metrics, or VPN/route conflicts when traffic goes to the wrong place."""
    raw = run_ps(
        "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
        " ForEach-Object { $_.DestinationPrefix + '|' + $_.NextHop + '|' + $_.InterfaceAlias + '|' + $_.RouteMetric }"
    )
    rows = [ln.split("|") for ln in raw.splitlines() if ln.count("|") == 3]
    if not rows:
        return run(["route", "print", "-4"])
    defaults, subnets, gateway_routes = [], [], []
    omitted = 0
    for dest, nexthop, iface, metric in rows:
        if dest == "0.0.0.0/0":
            defaults.append(f"0.0.0.0/0 via {nexthop} ({iface}, metric {metric})")
        elif dest.startswith("127.") or re.match(r"2(2[4-9]|3\d|4\d|5[0-5])\.", dest):
            omitted += 1  # loopback/multicast/broadcast noise
        elif nexthop == "0.0.0.0":
            if dest.endswith("/32"):
                omitted += 1  # on-link host routes (own IP, subnet broadcast)
            else:
                subnets.append(f"{dest} ({iface})")
        else:
            gateway_routes.append(f"{dest} via {nexthop} ({iface}, metric {metric})")
    lines = []
    if defaults:
        lines.append("Default route: " + "; ".join(defaults))
    else:
        lines.append("NO DEFAULT ROUTE - this machine has no path to the internet (DHCP failure or misconfiguration).")
    if subnets:
        lines.append("On-link subnets: " + ", ".join(subnets))
    if gateway_routes:
        lines.append("Other routes via a gateway:\n  " + "\n  ".join(gateway_routes))
    if omitted:
        lines.append(f"({omitted} loopback/multicast/broadcast/host entries omitted)")
    return "\n".join(lines)


@mcp.tool()
def interface_stats(interface: str = "") -> str:
    """Show packet/error/drop counters for network interfaces, one line per adapter. Rising errors or drops indicate a bad cable, driver issue, or interference. Leave `interface` empty for all interfaces."""
    sel = f" -Name '{ps_quote(interface)}'" if interface else ""
    raw = run_ps(
        "Get-NetAdapterStatistics" + sel + " -ErrorAction SilentlyContinue |"
        " ForEach-Object { $_.Name + '|' + $_.ReceivedBytes + '|' + $_.ReceivedPacketErrors"
        " + '|' + $_.ReceivedDiscardedPackets + '|' + $_.SentBytes + '|' + $_.OutboundPacketErrors"
        " + '|' + $_.OutboundDiscardedPackets }"
    )
    rows = [ln.split("|") for ln in raw.splitlines() if ln.count("|") == 6]
    if not rows:
        return raw or f"No statistics available{' for ' + interface if interface else ''} (adapter down or name wrong — see list_network_interfaces)."
    lines = []
    issues = False
    for name, rxb, rxe, rxd, txb, txe, txd in rows:
        try:
            lines.append(
                f"{name}: rx {_fmt_bytes(int(rxb))} (errors {rxe}, drops {rxd}), "
                f"tx {_fmt_bytes(int(txb))} (errors {txe}, drops {txd})"
            )
            issues = issues or any(int(x) for x in (rxe, rxd, txe, txd))
        except ValueError:
            lines.append(f"{name}: rx {rxb} B (errors {rxe}, drops {rxd}), tx {txb} B (errors {txe}, drops {txd})")
    lines.append(
        "Non-zero error/drop counters suggest a bad cable, driver problem, or interference."
        if issues else "No packet errors or drops on any listed adapter."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
