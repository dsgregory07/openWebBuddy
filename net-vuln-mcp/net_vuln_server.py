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

SAFETY: intended for systems you own or are explicitly authorized to test. The tools run
nmap's own version/OS detection and its 'default'/'vuln' NSE scripts (which FIND known
issues, read-only) plus the curated penny_special banner flagger. They never run
'dos'/'exploit'/'brute' scripts - this is assessment, not attack. Every scan is bounded
(-T4 + --host-timeout + --script-timeout + a subprocess ceiling) so it cannot hang the
tool loop. Raw-packet modes (-sX, -O, -A) are used only on a wired link; on Wi-Fi, where
raw injection is impossible, each tool drops to a connect-based path automatically.
"""
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

# Shared helpers + tunable config live at the repo root; both MCP servers import them.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from net_common import (  # noqa: E402
    run, run_ps, default_gateway, local_subnet_24, env_int,
)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("net-vuln")

# Scripts (custom NSE) live next to this file.
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
PENNY_NSE = os.path.join(SCRIPTS_DIR, "penny_special.nse")

# --- Tunable knobs (env-overridable; defaults preserve the previous hardcoded values).
# *_HOST_TIMEOUT is nmap's per-target cap (seconds); *_TIMEOUT is the subprocess ceiling
# that stops a scan from ever hanging the tool loop. Raise these on a slow link. ---
DISCOVER_HOST_TIMEOUT = env_int("NETVULN_DISCOVER_HOST_TIMEOUT", 30)
DISCOVER_TIMEOUT = env_int("NETVULN_DISCOVER_TIMEOUT", 150)
SCAN_HOST_TIMEOUT = env_int("NETVULN_SCAN_HOST_TIMEOUT", 120)
SCAN_TIMEOUT = env_int("NETVULN_SCAN_TIMEOUT", 150)
SCAN_MAX_RETRIES = env_int("NETVULN_SCAN_MAX_RETRIES", 2)
SERVICE_HOST_TIMEOUT = env_int("NETVULN_SERVICE_HOST_TIMEOUT", 90)
SERVICE_TIMEOUT = env_int("NETVULN_SERVICE_TIMEOUT", 120)
SERVICE_MAX_RETRIES = env_int("NETVULN_SERVICE_MAX_RETRIES", 1)
SERVICE_VERSION_INTENSITY = env_int("NETVULN_VERSION_INTENSITY", 2)
GRINCH_HOST_TIMEOUT = env_int("NETVULN_GRINCH_HOST_TIMEOUT", 90)
GRINCH_TIMEOUT = env_int("NETVULN_GRINCH_TIMEOUT", 120)
GRINCH_MAX_RETRIES = env_int("NETVULN_GRINCH_MAX_RETRIES", 2)
PENNY_TOP_PORTS = env_int("NETVULN_PENNY_TOP_PORTS", 50)  # default port breadth (snappy)
PENNY_INV_HOST_TIMEOUT = env_int("NETVULN_PENNY_INV_HOST_TIMEOUT", 60)  # phase 1 per-host cap (s)
PENNY_INV_TIMEOUT = env_int("NETVULN_PENNY_INV_TIMEOUT", 90)  # phase 1 subprocess cap
PENNY_SCRIPT_HOST_TIMEOUT = env_int("NETVULN_PENNY_SCRIPT_HOST_TIMEOUT", 120)  # phase 2 per-host cap
PENNY_TIMEOUT = env_int("NETVULN_PENNY_TIMEOUT", 180)  # phase 2 subprocess cap
PENNY_SCRIPT_TIMEOUT = env_int("NETVULN_PENNY_SCRIPT_TIMEOUT", 30)  # per-NSE-script cap (s)


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


def _active_iface_is_wifi() -> bool:
    """True if the interface that owns the default route is Wi-Fi (Native 802.11).

    Raw packet injection (ARP sweep, -sS, -sX, -O) does NOT work on a Wi-Fi NIC under Npcap:
    the scan fails, and the failed injection can knock the adapter off Wi-Fi. So when the
    active interface is wireless we report raw as unavailable and the tools use their
    connect-based paths, which never touch the adapter at the raw layer.
    """
    out = run_ps(
        "$c = Get-NetIPConfiguration -ErrorAction SilentlyContinue |"
        " Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1;"
        " if ($c) { (Get-NetAdapter -InterfaceIndex $c.InterfaceIndex"
        " -ErrorAction SilentlyContinue).PhysicalMediaType }"
    )
    return "802.11" in out.lower()


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
    """Return {present, version, raw, wifi, path}. Cached after the first call."""
    global _CAPS
    if _CAPS is not None:
        return _CAPS
    path = _find_nmap()
    if not path:
        _CAPS = {"present": False, "version": None, "raw": False, "wifi": False, "path": None}
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
    wifi = _active_iface_is_wifi()
    # raw needs the Npcap driver AND a non-Wi-Fi active interface: raw injection does not work
    # on a Native-802.11 adapter, so we report raw=False there and the tools use their
    # connect-safe paths instead of firing a doomed (and Wi-Fi-dropping) raw scan.
    raw = _npcap_raw_ready() and not wifi
    _CAPS = {"present": True, "version": version, "raw": raw, "wifi": wifi, "path": path}
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
        # OS fingerprint (from -O / -A), best guess only.
        osmatch = None
        om = h.find("os/osmatch")
        if om is not None:
            osmatch = (om.get("name"), om.get("accuracy"))
        # Host-level script output: some vuln/discovery NSE scripts attach here, not to a port.
        hostscripts = [
            (s.get("id"), s.get("output"))
            for s in h.findall("hostscript/script")
        ]
        hosts.append({
            "ip": ipv4 or ipv6, "mac": mac, "vendor": vendor,
            "hostname": hostname, "state": state,
            "ports": ports, "extraports": extraports,
            "osmatch": osmatch, "hostscripts": hostscripts,
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
    """Actively discover live devices on the local network with an nmap ping/ARP sweep (nmap -sn). Leave `subnet` empty to auto-scan this host's own /24 (e.g. 192.168.1.0/24), or pass a CIDR like '192.168.1.0/24'. This probes every address for a real inventory. For WHAT a device is (not just its IP), prefer net-diag's dev_disco - it adds SSDP/vendor identity that this tool does not. Systems you own or are authorized to test only."""
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    target = subnet.strip() or local_subnet_24()
    if not target:
        return "error: could not determine the local subnet (no IPv4 on the default-route interface). Pass a subnet like '192.168.1.0/24'."
    if target.startswith("-"):
        return "error: invalid subnet."
    # ARP sweep (-sn) needs raw packets. On Wi-Fi / no Npcap, --unprivileged makes nmap do a
    # connect-based discovery instead: it works over Wi-Fi and never touches the raw layer.
    if caps["raw"]:
        disc, mode = ["-sn", "-T4", "--host-timeout", f"{DISCOVER_HOST_TIMEOUT}s"], "nmap -sn"
    else:
        disc = ["-sn", "--unprivileged", "-T4", "--host-timeout", f"{DISCOVER_HOST_TIMEOUT}s"]
        mode = "nmap -sn --unprivileged, Wi-Fi-safe"
    xml, err = _run_nmap(disc + [target], timeout=DISCOVER_TIMEOUT)
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
        return f"LAN discovery on {target} ({mode}): no live hosts responded."
    lines = [f"LAN discovery on {target} ({mode}): {len(up)} host(s) up"]
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
    base = port_args + ["-T4", "-Pn", "--host-timeout", f"{SCAN_HOST_TIMEOUT}s", "--max-retries", str(SCAN_MAX_RETRIES), host]

    scan_type = "-sS"
    fallback_note = ""
    if caps["raw"]:
        # --send-ip: raw IP layer instead of raw ethernet - gentler on Wi-Fi adapters.
        xml, err = _run_nmap(["-sS", "--send-ip"] + base, timeout=SCAN_TIMEOUT)
        # nmap writes error-XML to stdout on a raw-socket failure, so check both the
        # stderr and the XML errormsg - not just whether stdout is empty.
        if _raw_unavailable(err, _nmap_error(xml)):
            scan_type = "-sT"
            fallback_note = " (SYN scan could not open a raw socket - is the Npcap driver running? - so used a connect scan -sT, which cannot report 'filtered')"
            xml, err = _run_nmap(["-sT"] + base, timeout=SCAN_TIMEOUT)
    else:
        scan_type = "-sT"
        fallback_note = " (raw-packet scanning unavailable - Npcap driver not running; used an unprivileged connect scan -sT, which cannot report 'filtered'. This mode does not touch the Wi-Fi adapter at the raw layer.)"
        xml, err = _run_nmap(["-sT"] + base, timeout=SCAN_TIMEOUT)

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
    """Identify the service and version running on each open TCP port (nmap -sV), e.g. '80/tcp open http Apache 2.4.58'. This turns open ports into an actual attack-surface inventory - the core of a host-perspective security assessment. Version detection is slow per port, so `ports` defaults to a LIGHT 'top-100' scan (keep it light) - only widen to '1-1024' etc. when the user asks for thorough. Other examples: '22,80,443'. A detected version is NOT itself a vulnerability; report it, do not invent CVEs. Systems you own or are authorized to test only."""
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
        ["-sT", "-sV", "--version-intensity", str(SERVICE_VERSION_INTENSITY)] + port_args
        + ["-T4", "-Pn", "--host-timeout", f"{SERVICE_HOST_TIMEOUT}s", "--max-retries", str(SERVICE_MAX_RETRIES), host],
        timeout=SERVICE_TIMEOUT,
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
    """Firewall / packet-filter assessment of a host - the "grinch" scan. Leave `host` empty to target the default gateway (router), or pass any host you own or are authorized to test. It maps which ports a firewall SILENTLY DROPS (filtered) vs ACTIVELY REFUSES (closed) vs allows (open). Two modes, chosen automatically: on a wired/raw-capable link it runs a true Xmas scan (nmap -sX, FIN/PSH/URG flags) which can slip past some stateless filters; on Wi-Fi - where raw packets are impossible - it runs a connect-based probe (nmap -sT --reason) that reads the same distinction from TCP reason codes (conn-refused = closed, no-response = filtered). `ports` defaults to a LIGHT 'top-100'; widen only when needed. CAVEAT: the Xmas mode cannot characterize Windows hosts (they RST every port -> all 'closed'); on a Windows target the connect mode still gives a valid closed/filtered read. Systems you own or are explicitly authorized to test only."""
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    target = _clean_host(host) if host.strip() else default_gateway()
    if not target:
        return "error: no host given and no default gateway found (not on a LAN?)."
    label = "gateway " if not host.strip() else ""
    port_args = ["--top-ports", "100"] if ports.strip() == "top-100" else ["-p", ports]

    # Mode selection. raw (Ethernet) -> real Xmas scan. If raw fails at runtime (driver
    # stopped since startup) or we are on Wi-Fi, fall back to a connect-based probe that
    # never opens the adapter for raw injection.
    xmas = False
    xml = err = ""
    if caps["raw"]:
        xml, err = _run_nmap(
            ["-sX", "-T4", "-Pn", "--send-ip"] + port_args
            + ["--host-timeout", f"{GRINCH_HOST_TIMEOUT}s", "--max-retries", str(GRINCH_MAX_RETRIES), target],
            timeout=GRINCH_TIMEOUT,
        )
        if _raw_unavailable(err, _nmap_error(xml)):
            xml = ""  # raw genuinely unavailable - use the connect probe instead
        else:
            xmas = True
    if not xmas:
        xml, err = _run_nmap(
            ["-sT", "--reason", "-T4", "-Pn"] + port_args
            + ["--host-timeout", f"{GRINCH_HOST_TIMEOUT}s", "--max-retries", str(GRINCH_MAX_RETRIES), target],
            timeout=GRINCH_TIMEOUT,
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

    if xmas:
        lines = [f"Firewall probe of {label}{target} (nmap -sX Xmas scan):"]
        for p in [p for p in h["ports"] if p["state"] != "closed"]:
            svc = f"  {p['name']}" if p["name"] else ""
            lines.append(f"  {p['portid']}/{p['protocol']:<4} {p['state']:<13}{svc}")
        open_filt = sum(1 for p in h["ports"] if p["state"] in ("open|filtered", "open", "filtered"))
        closed_n = sum(1 for p in h["ports"] if p["state"] == "closed")
        for state, count in h["extraports"]:
            c = int(count) if count and count.isdigit() else 0
            if state == "closed":
                closed_n += c
            elif state in ("open|filtered", "filtered"):
                open_filt += c
        lines.append(f"Summary: {open_filt} open|filtered, {closed_n} closed.")
        if open_filt == 0 and closed_n > 0:
            lines.append(
                "INCONCLUSIVE: every port answered 'closed' (RST) - the signature of a Windows "
                "host (or one that rejects malformed packets). Xmas cannot characterize it; use "
                "scan_ports / service_scan, or re-run against a Linux/embedded target."
            )
        else:
            lines.append(
                "'open|filtered' = silent (listening OR silently dropped by a firewall); "
                "'closed' = actively refused (RST)."
            )
        return "\n".join(lines)

    # Connect-based firewall map (Wi-Fi / no raw): -sT --reason distinguishes closed
    # (conn-refused = RST) from filtered (no-response = silently dropped).
    lines = [f"Firewall probe of {label}{target} (connect-based, nmap -sT --reason; Wi-Fi-safe, no raw packets):"]
    for p in [p for p in h["ports"] if p["state"] != "closed"]:
        svc = f"  {p['name']}" if p["name"] else ""
        reason = f"  ({p['reason']})" if p["reason"] else ""
        lines.append(f"  {p['portid']}/{p['protocol']:<4} {p['state']:<10}{svc}{reason}")
    open_n = sum(1 for p in h["ports"] if p["state"] == "open")
    filt_n = sum(1 for p in h["ports"] if p["state"] == "filtered")
    closed_n = sum(1 for p in h["ports"] if p["state"] == "closed")
    for state, count in h["extraports"]:
        c = int(count) if count and count.isdigit() else 0
        if state == "closed":
            closed_n += c
        elif state == "filtered":
            filt_n += c
        elif state == "open":
            open_n += c
    lines.append(f"Summary: {open_n} open, {filt_n} filtered (silently dropped), {closed_n} closed (actively refused).")
    if filt_n == 0:
        lines.append(
            "No silently-dropped ports: this firewall REFUSES (RST) rather than drops. For the "
            "raw Xmas technique (evades some stateless filters), use a wired connection."
        )
    else:
        lines.append(
            "'filtered' = firewall silently dropped the probe; 'closed' = actively refused (RST). "
            "For the raw Xmas technique, use a wired connection."
        )
    return "\n".join(lines)


@mcp.tool()
def penny_special(host: str, ports: str = "") -> str:
    """Vulnerability assessment of a host: OS fingerprint, service versions, and nmap's read-only 'default' + 'vuln' NSE scripts (known-CVE / misconfig checks like http-vuln-*, smb-vuln-*, ssl-enum-ciphers, http-security-headers) plus the curated penny_special banner flagger. Two modes, chosen automatically: on a wired/raw-capable link it runs the full aggressive scan (OS detection + version + default + vuln scripts + traceroute); on Wi-Fi - where raw packets are impossible - it drops OS detection/traceroute and runs the connect-safe subset (nmap -sT -sV + default + vuln scripts). `ports` defaults to a SMALL top-50 set so the heavy scripts stay snappy - pass 'top-100' or a spec like '22,80,443' to widen. It never runs dos/exploit/brute scripts. A script finding is a LEAD to verify, NOT a confirmed exploitable vuln, and a version string alone is not a CVE. Systems you own or are explicitly authorized to test only."""
    host = _clean_host(host)
    if not host:
        return "error: no host given (or host looks like a flag)."
    caps = nmap_capabilities()
    if not caps["present"]:
        return _nmap_missing_msg()
    spec = ports.strip()
    if not spec or spec == "top-50":
        port_args, ports_label = ["--top-ports", str(PENNY_TOP_PORTS)], f"top-{PENNY_TOP_PORTS}"
    elif spec == "top-100":
        port_args, ports_label = ["--top-ports", "100"], "top-100"
    else:
        port_args, ports_label = ["-p", spec], spec

    # PHASE 1 - fast inventory (open ports + versions, plus OS/traceroute on a wired link),
    # bounded short so it always returns. The slow vuln scripts run separately in phase 2, so
    # a script that overruns never costs you the port/version/OS inventory.
    if caps["raw"]:
        inv = ["-sS", "-O", "-sV", "--version-intensity", str(SERVICE_VERSION_INTENSITY), "--traceroute"]
        mode = "OS + version, then vuln scripts (full)"
    else:
        inv = ["-sT", "-sV", "--version-intensity", str(SERVICE_VERSION_INTENSITY)]
        mode = "connect-safe: version, then vuln scripts (OS detect needs Ethernet)"
    xml, err = _run_nmap(
        inv + port_args + ["-T4", "-Pn", "--host-timeout", f"{PENNY_INV_HOST_TIMEOUT}s", host],
        timeout=PENNY_INV_TIMEOUT,
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
            return f"Vulnerability assessment of {host} did not complete: {nerr}"
        return f"Vulnerability assessment of {host}: host did not respond."
    h = hosts[0]
    open_ports = [p for p in h["ports"] if p["state"] == "open"]

    # PHASE 2 - vuln scripts on the OPEN ports only (best-effort, bounded). Skipped when
    # nothing is open. If it overruns its host-timeout, nmap discards the host, so we keep the
    # phase-1 inventory and say the scripts did not finish rather than losing everything.
    port_scripts, host_scripts, scripts_note = {}, [], ""
    if open_ports:
        openspec = ",".join(p["portid"] for p in open_ports)
        scriptset = f"default,vuln,{PENNY_NSE}" if os.path.exists(PENNY_NSE) else "default,vuln"
        sx, _serr = _run_nmap(
            ["-sT", "-Pn", "-T4", "-p", openspec, "--script", scriptset,
             "--script-timeout", f"{PENNY_SCRIPT_TIMEOUT}s",
             "--host-timeout", f"{PENNY_SCRIPT_HOST_TIMEOUT}s", host],
            timeout=PENNY_TIMEOUT,
        )
        try:
            sh = _parse_hosts(sx) if sx else []
        except ET.ParseError:
            sh = []
        if sh and not _nmap_error(sx):
            for p in sh[0]["ports"]:
                if p["scripts"]:
                    port_scripts[p["portid"]] = p["scripts"]
            host_scripts = sh[0].get("hostscripts", [])
        else:
            scripts_note = (
                f"  [vuln scripts did not finish within {PENNY_SCRIPT_HOST_TIMEOUT}s - the "
                "inventory below is complete; narrow `ports` or raise "
                "NETVULN_PENNY_SCRIPT_HOST_TIMEOUT for full script coverage]"
            )

    def _is_hit(sid: str, out: str) -> bool:
        low = out.lower()
        if sid.startswith("penny") and "RISK:" in out:
            return True
        return any(k in low for k in ("vulnerable", "cve-", "state: likely vulnerable"))

    lines = [f"Vulnerability assessment of {host} (nmap {mode}, ports {ports_label}):"]
    if h.get("osmatch"):
        name, acc = h["osmatch"]
        lines.append(f"  OS guess: {name} ({acc}% match)")
    if scripts_note:
        lines.append(scripts_note)
    findings = 0
    if not open_ports:
        filt = sum(1 for p in h["ports"] if p["state"] == "filtered")
        lines.append(f"  no open TCP ports among those scanned{f' ({filt} filtered)' if filt else ''}.")
    for p in open_ports:
        lines.append(f"  {p['portid']}/{p['protocol']:<4} open  {_svc_label(p) or (p['name'] or '?')}")
        for sid, out in port_scripts.get(p["portid"], []):
            if not out or out.lstrip().startswith("ERROR") or "Script execution failed" in out:
                continue  # skip scripts that could not run - noise, not findings
            if _is_hit(sid, out):
                findings += 1
            lines.append(f"       [{sid}] {' '.join(out.split())[:300]}")
    for sid, out in host_scripts:
        if not out or out.lstrip().startswith("ERROR") or "Script execution failed" in out:
            continue
        if _is_hit(sid, out):
            findings += 1
        lines.append(f"  [host {sid}] {' '.join(out.split())[:300]}")
    lines.append(
        f"{findings} potential finding(s) flagged - VERIFY each; an nmap script hit is a lead, "
        "not a confirmed exploitable vuln, and a version alone is not a CVE."
        if findings else
        "No vuln-script findings flagged. Absence of a flag is not proof of safety."
    )
    if not caps["raw"]:
        lines.append(
            "Connect-safe mode (Wi-Fi): OS detection and traceroute skipped - use a wired "
            "connection for the full scan."
        )
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
