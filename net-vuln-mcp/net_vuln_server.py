#!/usr/bin/env python3
"""MCP server exposing nmap-powered network security-assessment tools (the "net-vuln" category).

Companion to net-mcp/net_mcp_server_win.py (the "net-diag" category). net-diag answers
"is my network working"; net-vuln answers "what is exposed / is my network secure",
assessed from THIS host's perspective against the user's own machine / LAN / router.

Every tool shells out to nmap, asks for XML on stdout (-oX -), and parses that into a
compact summary. If nmap (or Npcap, for raw-packet scans) is missing, tools return a
clear message and never a crash or a silently-wrong answer. Scans are bounded (-T4 +
--host-timeout + --max-retries + a per-call subprocess timeout) so one can never hang the
tool loop. Same code style as net_mcp_server_win.py: compact summaries, raw passthrough on
parse failure so no information is lost.

SAFETY: own machine / LAN / router only. No NSE external/intrusive/exploit/dos/brute/fuzzer
scripts are ever run - only the bundled version detection and the curated, read-only
penny_special banner grab (categories safe/discovery).
"""
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("net-vuln")

TIMEOUT = 15
# Scripts (custom NSE) live next to this file.
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
PENNY_NSE = os.path.join(SCRIPTS_DIR, "penny_special.nse")


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


def run_ps(script: str, timeout: int = 30) -> str:
    """Run a PowerShell snippet, forcing UTF-8 output so parsing is stable.

    Higher default timeout than TIMEOUT: powershell.exe startup alone can take >10s when
    a local model is saturating the CPU during inference.
    """
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;" + script
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full], timeout=timeout
    )


# ---------------------------------------------------------------------------
# nmap capability detection + bounded invocation
# ---------------------------------------------------------------------------
_CAPS: dict | None = None

# nmap emits one of these when a scan type needs raw packets it cannot get (no Npcap, or
# Npcap installed admin-only and we are unprivileged). Case-insensitive substring match.
_RAW_FAIL_SIGNS = (
    "npcap",
    "winpcap",
    "wpcap",
    "requires raw",
    "requires root",
    "requires r00t",
    "requires privileged",
    "only works if you are root",
    "operation not permitted",
    "failed to open device",
    "dnet: failed",
    "there are no interfaces",
    "socket troubles",
    "raw socket",          # "Couldn't open a raw socket or eth handle" (Npcap driver not loaded)
    "eth handle",
    "couldn't open",
)


def _npcap_raw_ready() -> bool:
    """True only if Npcap's runtime is installed AND its kernel driver is RUNNING.

    Raw scans need the driver loaded. A stopped/half-loaded driver makes -sS/-sX fail; worse,
    on a USB Wi-Fi adapter, opening it for raw injection can drop the Wi-Fi link. So unless
    the driver is actually up we report raw as UNAVAILABLE and the tools stick to connect
    scans (which never touch the adapter at the raw layer). nmap's own runtime error is still
    a backstop via _raw_unavailable().
    """
    dll = any(os.path.exists(p) for p in (
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
    ))
    if not dll:
        return False
    out = run_ps("(Get-Service npcap -ErrorAction SilentlyContinue).Status")
    return "running" in out.lower()


def _find_nmap() -> str | None:
    """Locate nmap.exe. The Windows installer does not always add nmap to PATH, so fall
    back to the standard install dirs - otherwise a background process (mcpo) that
    inherited a PATH without Nmap would never find it even though it is installed."""
    p = shutil.which("nmap")
    if p:
        return p
    for base in (
        os.environ.get("ProgramW6432"),
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ):
        if base:
            cand = os.path.join(base, "Nmap", "nmap.exe")
            if os.path.exists(cand):
                return cand
    return None


def nmap_capabilities() -> dict:
    """Return {present, version, raw, path}. Cached after the first call."""
    global _CAPS
    if _CAPS is not None:
        return _CAPS
    path = _find_nmap()
    if not path:
        _CAPS = {"present": False, "version": None, "raw": False, "path": None}
        return _CAPS
    version = "unknown"
    try:
        proc = subprocess.run(
            [path, "--version"], capture_output=True, text=True, errors="replace", timeout=15
        )
        m = re.search(r"Nmap version (\S+)", proc.stdout or "")
        if m:
            version = m.group(1)
    except Exception:
        pass
    _CAPS = {"present": True, "version": version, "raw": _npcap_raw_ready(), "path": path}
    return _CAPS


def _nmap_missing_msg() -> str:
    return (
        "error: nmap is not installed. Install it (its Windows installer bundles Npcap) "
        "from https://nmap.org/download.html, leaving 'Restrict Npcap to Administrators "
        "only' UNCHECKED so raw-packet scans run without a UAC prompt. Until then, "
        "net-diag's port_scan can still do a basic open-port check."
    )


def _raw_unavailable(*texts: str) -> bool:
    low = " ".join(t for t in texts if t).lower()
    return any(sign in low for sign in _RAW_FAIL_SIGNS)


def _nmap_error(xml: str) -> str:
    """Extract the errormsg from an nmap <finished exit="error"> element, else "".

    A raw-socket failure (e.g. Npcap driver not loaded) still writes a well-formed XML
    document to stdout whose runstats say exit="error", so a non-empty stdout does NOT
    mean the scan succeeded - callers must check this too.
    """
    try:
        fin = ET.fromstring(xml).find("runstats/finished")
    except ET.ParseError:
        return ""
    if fin is not None and fin.get("exit") == "error":
        return fin.get("errormsg", "nmap reported an error")
    return ""


def _run_nmap(extra_args: list[str], timeout: int) -> tuple[str, str]:
    """Run nmap with -oX - appended. Returns (xml_stdout, stderr_or_error).

    stderr is where nmap prints warnings (incl. raw-packet failures); stdout is the XML.
    """
    caps = nmap_capabilities()
    cmd = [caps["path"] or "nmap"] + extra_args + ["-oX", "-"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout
        )
        return (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return "", "error: 'nmap' is not installed"
    except subprocess.TimeoutExpired:
        return "", f"error: nmap timed out after {timeout}s"


def _clean_host(host: str) -> str | None:
    """Reject empty / flag-like targets so a hostname can never inject nmap options."""
    host = (host or "").strip()
    if not host or host.startswith("-"):
        return None
    return host


# ---------------------------------------------------------------------------
# Local network context (gateway + subnet), reused from net-diag's approach
# ---------------------------------------------------------------------------
def default_gateway() -> str | None:
    out = run_ps(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric | Select-Object -First 1;"
        " if ($r) { $r.NextHop }"
    )
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
    return m.group(1) if m else None


def local_ipv4() -> str | None:
    """The IPv4 address of the interface that owns the default route."""
    out = run_ps(
        "$c = Get-NetIPConfiguration -ErrorAction SilentlyContinue |"
        " Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1;"
        " if ($c) { ($c.IPv4Address | Select-Object -First 1).IPAddress }"
    )
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
    return m.group(1) if m else None


def local_subnet_24() -> str | None:
    """Derive the local /24 (e.g. 192.168.1.0/24) from this host's primary IPv4."""
    ip = local_ipv4()
    if not ip:
        return None
    a, b, c, _d = ip.split(".")
    return f"{a}.{b}.{c}.0/24"


# ---------------------------------------------------------------------------
# nmap XML parsing helpers
# ---------------------------------------------------------------------------
def _parse_hosts(xml_text: str):
    """Yield parsed <host> dicts from an nmap XML document, or raise ET.ParseError."""
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state") if status is not None else "unknown"
        addrs = {a.get("addrtype"): a for a in h.findall("address")}
        ipv4 = addrs["ipv4"].get("addr") if "ipv4" in addrs else None
        ipv6 = addrs["ipv6"].get("addr") if "ipv6" in addrs else None
        mac = addrs["mac"].get("addr") if "mac" in addrs else None
        vendor = addrs["mac"].get("vendor") if "mac" in addrs else None
        hostname = None
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            scripts = [
                (s.get("id"), s.get("output"))
                for s in p.findall("script")
            ]
            ports.append({
                "portid": p.get("portid"),
                "protocol": p.get("protocol"),
                "state": st.get("state") if st is not None else "unknown",
                "reason": st.get("reason") if st is not None else "",
                "name": svc.get("name") if svc is not None else "",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
                "extrainfo": svc.get("extrainfo") if svc is not None else "",
                "scripts": scripts,
            })
        extraports = []
        for ep in h.findall("ports/extraports"):
            extraports.append((ep.get("state"), ep.get("count")))
        hosts.append({
            "ip": ipv4 or ipv6, "mac": mac, "vendor": vendor,
            "hostname": hostname, "state": state,
            "ports": ports, "extraports": extraports,
        })
    return hosts


def _svc_label(port: dict) -> str:
    """'ssh OpenSSH 8.4' style label from a parsed port's service fields."""
    bits = [port["name"]] if port["name"] else []
    prodver = " ".join(x for x in (port["product"], port["version"]) if x).strip()
    if prodver:
        bits.append(prodver)
    if port["extrainfo"]:
        bits.append(f"({port['extrainfo']})")
    return " ".join(bits).strip()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def discover_lan(subnet: str = "") -> str:
    """Actively discover live devices on the local network with an nmap ping/ARP sweep (nmap -sn). Leave `subnet` empty to auto-scan this host's own /24 (e.g. 192.168.1.0/24), or pass a CIDR like '192.168.1.0/24'. Stronger than net-diag's arp_scan_lan, which only reads the passive ARP cache - this probes every address. Use to inventory what is actually on the network. Own LAN only."""
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    target = subnet.strip() or local_subnet_24()
    if not target:
        return "error: could not determine the local subnet (no IPv4 on the default-route interface). Pass a subnet like '192.168.1.0/24'."
    if target.startswith("-"):
        return "error: invalid subnet."
    xml, err = _run_nmap(["-sn", "-T4", "--host-timeout", "30s", target], timeout=150)
    if not xml:
        return err or "error: nmap returned no output."
    try:
        hosts = _parse_hosts(xml)
    except ET.ParseError:
        return f"[nmap output could not be parsed as XML]\n{xml[:1500]}"
    up = [h for h in hosts if h["state"] == "up"]
    if not up:
        nerr = _nmap_error(xml)
        if nerr:
            hint = " (if you just installed Npcap, REBOOT so its driver loads)" if _raw_unavailable(nerr) else ""
            return f"LAN discovery on {target} did not complete: {nerr}{hint}"
        return f"LAN discovery on {target} (nmap -sn): no live hosts responded."
    lines = [f"LAN discovery on {target} (nmap -sn): {len(up)} host(s) up"]
    for h in up:
        name = f"  ({h['hostname']})" if h["hostname"] else ""
        mac = f"  {h['mac']}" if h["mac"] else ""
        vendor = f" [{h['vendor']}]" if h["vendor"] else ""
        lines.append(f"  {h['ip'] or '?':<15}{name}{mac}{vendor}")
    lines.append(
        "Note: -sn finds hosts that answer ARP/ping; a device configured to stay silent "
        "may still be present."
    )
    return "\n".join(lines)


@mcp.tool()
def scan_ports(host: str, ports: str = "top-100") -> str:
    """Scan a host's TCP ports and report real open / closed / FILTERED states (nmap SYN scan -sS, falling back to a connect scan -sT if raw packets are unavailable). Unlike net-diag's port_scan, this distinguishes 'filtered' (a firewall is silently dropping the port) from 'closed' (nothing is listening). `ports` is an nmap port spec; the default 'top-100' is a LIGHT, fast scan of the 100 most common ports (keep scans light by default) - only widen to '1-1024' or '1-65535' when the user explicitly wants a thorough scan. Other examples: '22,80,443'. Use against your own hosts/router to see what is exposed and what a firewall is hiding."""
    host = _clean_host(host)
    if not host:
        return "error: no host given (or host looks like a flag)."
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    port_args = ["--top-ports", "100"] if ports.strip() == "top-100" else ["-p", ports]
    base = port_args + ["-T4", "-Pn", "--host-timeout", "120s", "--max-retries", "2", host]

    scan_type = "-sS"
    fallback_note = ""
    if caps["raw"]:
        # --send-ip: raw IP layer instead of raw ethernet - gentler on Wi-Fi adapters.
        xml, err = _run_nmap(["-sS", "--send-ip"] + base, timeout=150)
        # nmap writes error-XML to stdout on a raw-socket failure, so check both the
        # stderr and the XML errormsg - not just whether stdout is empty.
        if _raw_unavailable(err, _nmap_error(xml)):
            scan_type = "-sT"
            fallback_note = " (SYN scan could not open a raw socket - is the Npcap driver running? - so used a connect scan -sT, which cannot report 'filtered')"
            xml, err = _run_nmap(["-sT"] + base, timeout=150)
    else:
        scan_type = "-sT"
        fallback_note = " (raw-packet scanning unavailable - Npcap driver not running; used an unprivileged connect scan -sT, which cannot report 'filtered'. This mode does not touch the Wi-Fi adapter at the raw layer.)"
        xml, err = _run_nmap(["-sT"] + base, timeout=150)

    if not xml:
        return err or "error: nmap returned no output."
    try:
        hosts = _parse_hosts(xml)
    except ET.ParseError:
        return f"[nmap output could not be parsed as XML]\n{xml[:1500]}"
    if not hosts:
        nerr = _nmap_error(xml)
        if nerr:
            return f"Port scan of {host} ({scan_type}) did not complete: {nerr}"
        return f"Port scan of {host} ({scan_type}): host did not respond."
    h = hosts[0]
    shown = [p for p in h["ports"] if p["state"] != "closed"]
    lines = [f"Port scan of {host} (nmap {scan_type}, ports {ports}){fallback_note}:"]
    if shown:
        for p in shown:
            svc = f"  {p['name']}" if p["name"] else ""
            pp = f"{p['portid']}/{p['protocol']}"
            lines.append(f"  {pp:<8} {p['state']:<10}{svc}")
    else:
        lines.append("  no open or filtered ports among those scanned.")
    tallies = []
    open_n = sum(1 for p in h["ports"] if p["state"] == "open")
    filt_n = sum(1 for p in h["ports"] if p["state"] == "filtered")
    if open_n:
        tallies.append(f"{open_n} open")
    if filt_n:
        tallies.append(f"{filt_n} filtered")
    for state, count in h["extraports"]:
        tallies.append(f"{count} {state}")
    if tallies:
        lines.append("Summary: " + ", ".join(tallies) + ".")
    return "\n".join(lines)


@mcp.tool()
def service_scan(host: str, ports: str = "top-100") -> str:
    """Identify the service and version running on each open TCP port (nmap -sV), e.g. '80/tcp open http Apache 2.4.58'. This turns open ports into an actual attack-surface inventory - the core of a host-perspective security assessment. Version detection is slow per port, so `ports` defaults to a LIGHT 'top-100' scan (keep it light) - only widen to '1-1024' etc. when the user asks for thorough. Other examples: '22,80,443'. A detected version is NOT itself a vulnerability; report it, do not invent CVEs. Own hosts/router only."""
    host = _clean_host(host)
    if not host:
        return "error: no host given (or host looks like a flag)."
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    port_args = ["--top-ports", "100"] if ports.strip() == "top-100" else ["-p", ports]
    # Force -sT (connect) under -sV: version detection does not need raw packets, and an
    # unqualified -sV would default to a SYN scan that fails if the Npcap driver is not up.
    # --version-intensity 2 (light) keeps a single slow TLS/app probe from eating the whole
    # host-timeout; it still identifies the common services this tool cares about.
    xml, err = _run_nmap(
        ["-sT", "-sV", "--version-intensity", "2"] + port_args
        + ["-T4", "-Pn", "--host-timeout", "90s", "--max-retries", "1", host],
        timeout=120,
    )
    if not xml:
        return err or "error: nmap returned no output."
    try:
        hosts = _parse_hosts(xml)
    except ET.ParseError:
        return f"[nmap output could not be parsed as XML]\n{xml[:1500]}"
    if not hosts:
        nerr = _nmap_error(xml)
        if nerr:
            return f"Service scan of {host} did not complete: {nerr}"
        return f"Service scan of {host} (nmap -sV): host did not respond."
    h = hosts[0]
    open_ports = [p for p in h["ports"] if p["state"] == "open"]
    lines = [f"Service scan of {host} (nmap -sV, ports {ports}):"]
    if not open_ports:
        filt = sum(1 for p in h["ports"] if p["state"] == "filtered")
        extra = f" ({filt} filtered)" if filt else ""
        lines.append(f"  no open TCP ports among those scanned{extra}.")
        return "\n".join(lines)
    for p in open_ports:
        label = _svc_label(p) or "unknown"
        pp = f"{p['portid']}/{p['protocol']}"
        lines.append(f"  {pp:<8} open  {label}")
    lines.append(
        f"Summary: {len(open_ports)} service(s) on open ports. A version string is not "
        "itself a vulnerability - do not claim a CVE you have not verified."
    )
    return "\n".join(lines)


@mcp.tool()
def grinch_scan(host: str = "", ports: str = "top-100") -> str:
    """Probe a firewall with an Xmas scan (nmap -sX) - the "grinch" scan. Leave `host` empty to target the default gateway (router). The Xmas scan sets the FIN/PSH/URG flags and distinguishes 'closed' (the host sent a RST - actively refusing) from 'open|filtered' (silence - either listening or silently dropped), revealing ports a firewall drops that a SYN/connect scan cannot show as cleanly. `ports` defaults to a LIGHT 'top-100' scan (keep it light); widen to '1-1024' etc. only when needed. Needs raw packets (Npcap). CRITICAL: the Xmas scan does NOT work against Windows hosts - Windows RSTs every port, so it reports ALL ports 'closed'. If the target is Windows or every port is closed, the scan is INCONCLUSIVE; say so and use scan_ports/service_scan instead. It is effective against Linux/BSD/embedded targets, i.e. most routers. Own router/hosts only. NOTE: this is a raw-packet scan; on a USB Wi-Fi adapter it can briefly drop the Wi-Fi link - warn the user before running it, and prefer scan_ports/service_scan if a stable connection matters."""
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    # Refuse BEFORE running nmap when raw is not ready: attempting -sX would open the network
    # adapter for raw injection, which on a USB Wi-Fi adapter can drop the Wi-Fi link.
    if not caps["raw"]:
        return (
            "grinch_scan: the Xmas scan needs raw-packet capture (the Npcap driver), which is "
            "not currently available. If you just installed nmap/Npcap, REBOOT so the driver "
            "loads (it is set to start at boot). Heads-up: on a USB Wi-Fi adapter a raw scan "
            "can briefly drop the Wi-Fi connection. For a Wi-Fi-safe check use scan_ports or "
            "service_scan (they use connect scans and do not touch the adapter at the raw layer)."
        )
    target = _clean_host(host) if host.strip() else default_gateway()
    if not target:
        return "error: no host given and no default gateway found (not on a LAN?)."
    label = "gateway " if not host.strip() else ""
    port_args = ["--top-ports", "100"] if ports.strip() == "top-100" else ["-p", ports]
    # --send-ip: send at the raw IP layer, not raw ethernet - gentler on Wi-Fi adapters that
    # break when nmap injects raw ethernet frames.
    xml, err = _run_nmap(
        ["-sX", "-T4", "-Pn", "--send-ip"] + port_args + ["--host-timeout", "90s", "--max-retries", "2", target],
        timeout=120,
    )
    # -sX needs raw packets. On failure nmap may write nothing, OR an error-XML to stdout,
    # so check stderr AND the XML errormsg.
    if _raw_unavailable(err, _nmap_error(xml)):
        return (
            f"grinch_scan ({label}{target}): the Xmas scan needs raw-packet capture, which "
            "nmap could not get. If you just installed nmap/Npcap, REBOOT so the Npcap "
            "driver loads (or start it as admin: 'net start npcap'). Also ensure Npcap was "
            "installed with 'Restrict to Administrators only' UNCHECKED. For now use "
            "scan_ports/service_scan (they work without raw packets)."
        )
    if not xml:
        return err or "error: nmap returned no output."
    try:
        hosts = _parse_hosts(xml)
    except ET.ParseError:
        return f"[nmap output could not be parsed as XML]\n{xml[:1500]}"
    if not hosts:
        nerr = _nmap_error(xml)
        if nerr:
            return f"grinch_scan ({label}{target}) did not complete: {nerr}"
        return f"grinch_scan ({label}{target}): host did not respond."
    h = hosts[0]
    lines = [f"Xmas scan of {label}{target} (nmap -sX):"]
    shown = [p for p in h["ports"] if p["state"] != "closed"]
    if shown:
        for p in shown:
            svc = f"  {p['name']}" if p["name"] else ""
            pp = f"{p['portid']}/{p['protocol']}"
            lines.append(f"  {pp:<8} {p['state']:<13}{svc}")
    open_filt = sum(1 for p in h["ports"] if p["state"] in ("open|filtered", "open", "filtered"))
    closed_n = sum(1 for p in h["ports"] if p["state"] == "closed")
    for state, count in h["extraports"]:
        if state == "closed":
            closed_n += int(count) if count and count.isdigit() else 0
        elif state in ("open|filtered", "filtered"):
            open_filt += int(count) if count and count.isdigit() else 0
    lines.append(f"Summary: {open_filt} open|filtered, {closed_n} closed.")
    # The all-closed signature = a target that RSTs everything (Windows, or a host that
    # rejects malformed packets). Xmas cannot characterize it; flag as inconclusive.
    if open_filt == 0 and closed_n > 0:
        lines.append(
            "INCONCLUSIVE: every port answered 'closed' (RST). This is exactly how Windows "
            "hosts (and some others) respond to an Xmas scan, so it cannot characterize this "
            "target. Use scan_ports / service_scan instead."
        )
    else:
        lines.append(
            "'open|filtered' means the port was silent (listening OR silently dropped by a "
            "firewall); 'closed' means the host actively refused (RST)."
        )
    return "\n".join(lines)


@mcp.tool()
def penny_special(host: str, ports: str = "top-100") -> str:
    """Flag known-risky services on a host by grabbing each open TCP port's banner and matching it against a curated table (telnet, FTP, SMB/SMBv1, obsolete SSH/HTTP, VNC, etc.) - the custom 'penny_special' NSE script (categories safe, discovery; read-only, NOT an exploit). Runs an unprivileged connect scan (nmap -sT), so it works without Npcap. `ports` defaults to a LIGHT 'top-100' scan (keep it light); widen to '1-1024' or a specific list like '22,23,21,80,443' only when needed. Report exactly what it flags; the absence of a flag is NOT proof the host is safe. Own hosts/router only."""
    host = _clean_host(host)
    if not host:
        return "error: no host given (or host looks like a flag)."
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    if not os.path.exists(PENNY_NSE):
        return f"error: penny_special NSE script not found at {PENNY_NSE}."
    port_args = ["--top-ports", "100"] if ports.strip() == "top-100" else ["-p", ports]
    xml, err = _run_nmap(
        ["-sT", "-Pn", "-T4"] + port_args
        + ["--host-timeout", "120s", "--script", PENNY_NSE, host],
        timeout=150,
    )
    if not xml:
        return err or "error: nmap returned no output."
    try:
        hosts = _parse_hosts(xml)
    except ET.ParseError:
        return f"[nmap output could not be parsed as XML]\n{xml[:1500]}"
    if not hosts:
        nerr = _nmap_error(xml)
        if nerr:
            return f"penny_special scan of {host} did not complete: {nerr}"
        return f"penny_special scan of {host}: host did not respond."
    h = hosts[0]
    open_ports = [p for p in h["ports"] if p["state"] == "open"]
    lines = [f"Risky-service scan of {host} (penny_special NSE):"]
    if not open_ports:
        lines.append("  no open TCP ports found to inspect.")
        return "\n".join(lines)
    flagged = 0
    for p in open_ports:
        notes = [out.strip() for sid, out in p["scripts"] if sid == "penny_special" and out]
        svc = p["name"] or "?"
        pp = f"{p['portid']}/{p['protocol']}"
        if notes:
            joined = " | ".join(notes)
            # Only "RISK:" notes are actual flags; a plain "banner:" line is just context.
            if any(n.startswith("RISK:") for n in notes):
                flagged += 1
            lines.append(f"  {pp:<8} {svc}: {joined}")
        else:
            lines.append(f"  {pp:<8} {svc}: no risk flag")
    tail = (
        f"{flagged} risky service(s) flagged."
        if flagged
        else "No known-risky services flagged."
    )
    lines.append(tail + " Absence of a flag is not proof of safety.")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
