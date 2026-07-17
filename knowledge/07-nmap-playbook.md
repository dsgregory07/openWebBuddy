# Nmap assessment playbook (net-vuln recipes)

Goal-oriented recipes: pick the user's actual question, run the matching net-vuln tool, read
the result correctly. This is the "what do I do" companion to `06-nmap-security-assessment.md`
(which explains the scan types) and `03-router-security.md` (router hardening). Every scan is
against your own machine / LAN / router only.

Grounded in the five net-vuln tools as they are actually built. Where a recipe names an nmap
technique, that is what the tool runs under the hood - you invoke the TOOL, never raw nmap.

## Recipe index (question -> tool)

| The user wants to know... | Tool | Under the hood |
|---------------------------|------|----------------|
| What devices are on my network? | `discover_lan` | `nmap -sn` ping/ARP sweep |
| What ports are open / firewalled on a host? | `scan_ports` | `-sS` SYN, falls back to `-sT` connect |
| What software/versions are actually running? | `service_scan` | `-sT -sV` version detection |
| Is any old/risky service exposed? | `penny_special` | `-sT` + curated banner-match NSE |
| Is my router's firewall dropping ports? | `grinch_scan` | `-sX` Xmas (router/Linux targets only) |

If unsure which host to target: `discover_lan` first to get the inventory, then point the
other tools at a specific IP. The gateway/router IP is the default target for `grinch_scan`.

## Recipe 1 - Inventory the network

Question: "What's connected to my network / did an unknown device join?"

- Run `discover_lan` with no argument (auto-scans this host's own /24), or pass a CIDR like
  `192.168.1.0/24` for a specific range.
- Read the result as a device list: IP, hostname if known, MAC, and vendor. The MAC vendor is
  the fastest way to identify a mystery device (e.g. "Espressif" = an ESP32/IoT gadget,
  "Raspberry Pi" = a Pi).
- Caveat to state: `-sn` only finds devices that answer ARP/ping. A host set to stay silent
  can still be present, so "N hosts up" is a floor, not a guaranteed total.
- Scope note: the tool forces a /24. On a wider subnet (e.g. a /22) pass the explicit CIDR to
  cover the full range.

## Recipe 2 - What is exposed on a host

Question: "What ports are open on my PC / this device / the router?"

- Run `scan_ports <ip>`. Default `ports` is `top-100` (light and fast - keep it light). Only
  widen to `1-1024` or `1-65535` when the user explicitly asks for a thorough scan, and warn
  that it takes longer.
- Read the three states as distinct facts (this is the whole point of the tool):
  - **open** = something is listening. Report it; open is not itself a vulnerability.
  - **filtered** = a firewall silently dropped the probe (no reply).
  - **closed** = reachable host, nothing listening there.
- Only the SYN path (`-sS`) can report **filtered**. If the output says it fell back to a
  connect scan (`-sT`, because the Npcap driver was not running), then "filtered" is not
  distinguishable - a missing port just means "not open among those scanned," never "confirmed
  closed." Say which mode ran.

## Recipe 3 - Turn open ports into an attack-surface inventory

Question: "What software (and version) is actually running on the open ports?"

- Run `service_scan <ip>`. It probes each open port (`-sV`) and names the real service, e.g.
  `80/tcp open http Apache 2.4.58` or `22/tcp open ssh OpenSSH 8.4`.
- Prefer this over the port-number guess. Without `-sV`, nmap labels a port from a static
  table (it would call 3000 "ppp", 8000 "http-alt"); `service_scan` returns what is really
  there ("Uvicorn", "OpenWrt uHTTPd").
- Hard rule when reporting: **a version string is not a CVE.** Naming "OpenSSH 8.4" is an
  inventory entry, not a confirmed vulnerability. Never claim a specific CVE you did not
  verify. Port/version state is not patch state.
- This is the core of a host-perspective assessment: run it on the open ports `scan_ports`
  found, then describe the real exposed surface.

## Recipe 4 - Hunt for known-risky services

Question: "Do I have anything old or insecure listening - telnet, FTP, SMBv1, VNC?"

- Run `penny_special <ip>`. It grabs each open port's banner and matches it against a curated
  risk table (telnet, FTP, SMB, obsolete SSH/HTTP, VNC, etc.). Connect-based (`-sT`), so it
  needs no Npcap and is Wi-Fi-safe.
- Read each line as flag-or-not: a `RISK:` note is a flag; a plain `banner:` line is just
  context. The summary counts only `RISK:` flags.
- Interpret a flag as a REMINDER TO CHECK, not a detection. It flags port 445 with "ensure
  SMBv1 is disabled" because SMB is open - it did NOT detect that SMBv1 is enabled (modern
  Windows disables SMBv1 by default). Say "SMB is open; verify SMBv1 is off," not "SMBv1 is
  present."
- Hard rule: **absence of a flag is not proof of safety.** The table is curated, not
  exhaustive.

## Recipe 5 - Probe the router's firewall

Question: "Is my router's firewall actually dropping ports, or just refusing them?"

- Run `grinch_scan` with no argument to target the default gateway (router). The Xmas scan
  (`-sX`) separates **closed** (host sent a RST - actively refusing) from **open|filtered**
  (silence - either listening or silently dropped).
- CRITICAL - do not run this at a Windows host. Windows RSTs every port, so `-sX` reports ALL
  ports "closed" and the result is meaningless. The tool flags this as INCONCLUSIVE; when you
  see it, say so and switch to `scan_ports`/`service_scan`. Xmas is only meaningful against
  Linux/BSD/embedded targets, which is most routers.
- Two preconditions the tool enforces for you:
  - It needs raw packets (the Npcap driver RUNNING). If the driver is down, the tool REFUSES
    up front with a reboot message and never touches the network adapter - it does not even
    try nmap.
  - Raw scans on a USB Wi-Fi adapter can briefly drop the Wi-Fi link. Warn the user before
    running it; if a stable connection matters, prefer the connect-based tools instead.

## Chaining the recipes

Follow the assessment order in `06-nmap-security-assessment.md`:
`discover_lan` -> `scan_ports` -> `service_scan` -> `penny_special`, with `grinch_scan` only
for the router's firewall (skip it for Windows hosts). Stop when the user's question is
answered - you rarely need all five. A "what's exposed on my PC" question is recipes 2+3; a
"what's on my network" question is recipe 1 alone.

## Localhost vs LAN IP

See "Localhost vs the network address" in `06-nmap-security-assessment.md`: scanning
**127.0.0.1** shows what is RUNNING (including loopback-only services like this stack's
OpenWebUI:3000 and mcpo:8000); scanning the **LAN IP** shows what is EXPOSED. For an exposure
verdict, scan the LAN IP, ideally in SYN mode so filtered-vs-closed is visible.

## Timing, safety, and honesty

- Keep scans LIGHT by default (`top-100`). Widen the port range only when the user asks for a
  thorough scan, and tell them it will take longer. All tools are already time-bounded and
  will report a clean timeout rather than hang.
- Own machine / LAN / router only. The tools never run intrusive/exploit/DoS/brute NSE
  scripts - only version detection and the read-only `penny_special` banner grab.
- Wi-Fi-safe tools (no raw packets, never touch the adapter at the raw layer): `service_scan`,
  `penny_special`, and `scan_ports` when it is in connect (`-sT`) mode. Raw scans (`scan_ports`
  SYN mode, `grinch_scan`) need the Npcap driver and can disturb a USB Wi-Fi link.
- If a tool says nmap or the Npcap driver is unavailable, relay its message verbatim (usually:
  install nmap, or REBOOT so the Npcap driver loads) - do not pretend a scan succeeded, and do
  not fabricate results. An errored tool means the check is BROKEN, not that the host is clean.

## Protocol / port reference (reading what the tools return)

When a tool reports a port, translate the number into its protocol so the finding is
meaningful. `scan_ports` names ports from a static table (a guess); `service_scan` (`-sV`) and
`penny_special` confirm from the banner. Trust the confirmed name over the guess.

| Port(s) | Protocol / service | How to read it in a result |
|---------|--------------------|----------------------------|
| 21 | FTP | Cleartext. Flagged by penny_special. Note if WAN-reachable. |
| 22 | SSH | Encrypted remote admin - normal. Only a concern at v1 (see risk table). |
| 23 | Telnet | Cleartext remote admin - should not be open anywhere. Always a flag. |
| 25 / 587 | SMTP mail submission | Mail server. Uncommon on a home host; note if unexpected. |
| 53 | DNS | Normal on a router; a host serving 53 is unusual. |
| 80 | HTTP | Web server. Normal on a router (admin page) and this stack. Unencrypted. |
| 110 / 143 | POP3 / IMAP mail | Legacy mail; note if unexpected on a home LAN. |
| 135 | MSRPC (Windows RPC) | Normal on Windows. Not a finding by itself. |
| 137-139 | NetBIOS | Legacy Windows name/SMB service. penny_special flags it; disable if unused. |
| 443 | HTTPS | Encrypted web. Normal on a router and many services. |
| 445 | SMB (microsoft-ds) | Windows file sharing. Normal on a LAN; flagged to verify SMBv1 is OFF and it is not WAN-exposed. |
| 1433 | MS-SQL | Database - should be LAN/localhost only. Flagged if exposed. |
| 1900 | SSDP / UPnP | Router/media discovery. Common; note if UPnP is unwanted. |
| 3000 | OpenWebUI (this stack) | Loopback-only in this stack - appears when scanning 127.0.0.1, not the LAN IP. |
| 3306 | MySQL | Database - LAN/localhost only. Flagged if exposed. |
| 3389 | RDP (ms-wbt-server) | Windows Remote Desktop. Top ransomware entry point - flagged; never WAN-expose. |
| 5040 | Windows svchost | Normal Windows local service. Not a finding. |
| 5357 | WSDAPI (Web Services for Devices) | Normal Windows discovery service. Not a finding. |
| 5900 | VNC | Remote desktop, often weak auth. Flagged; LAN-only + strong password. |
| 6379 | Redis | Default has no auth. Flagged if exposed; bind to localhost + password. |
| 8000 | mcpo (this stack) | Loopback-only in this stack; appears only when scanning 127.0.0.1. |
| 8080 / 8443 | HTTP-alt / HTTPS-alt | Proxies, admin panels, dev servers. Identify with service_scan. |
| 11434 | Ollama (this stack) | Loopback-only; appears only when scanning 127.0.0.1. |
| 27017 | MongoDB | Historically shipped no auth. Flagged if exposed. |
| 161 | SNMP | Often left on the 'public' community. Flagged; disable or set a private community. |
| 69 | TFTP | No authentication - a config-leak vector. Flagged; disable if unused. |
| 513 / 514 | rlogin / rsh | Legacy cleartext remote shell. Flagged; disable. |

Rule of thumb: 135/139/445/5040/5357 open on a Windows box, and 53/80/443 on a router, are the
normal baseline - report them as expected, not as risks. Escalate when a database, remote-
desktop, or cleartext-admin protocol is open, ESPECIALLY on the LAN IP (reachable) rather than
just loopback.

## The penny_special risk table (what a flag means)

`penny_special` matches the service name + banner (case-insensitive substring) against this
curated, read-only table. A match becomes a `RISK:` note; anything else is just a `banner:`
line. The match is on the banner text a service volunteers - it confirms the SERVICE is
present, not that the specific weakness is active (e.g. SMB open != SMBv1 enabled).

| Match token | Flag raised |
|-------------|-------------|
| `telnet` | Cleartext remote admin - disable it. |
| `ftp` | Cleartext credentials/data - prefer SFTP/FTPS, avoid WAN. |
| `microsoft-ds` | SMB (445): verify SMBv1 disabled (EternalBlue/WannaCry) and not WAN-exposed. |
| `netbios` | NetBIOS (137-139): legacy LAN exposure - disable if unused. |
| `smbv1` | SMBv1 detected: obsolete and exploitable - disable it. |
| `ssh-1` / `ssh-1.99` | SSHv1 or v1 fallback advertised - broken crypto, force SSHv2. |
| `vnc` | Remote desktop, often weak/no auth - LAN-only + strong password. |
| `rdp` / `ms-wbt-server` | RDP (3389): ransomware entry point - never WAN-expose, use VPN/NLA. |
| `rlogin` / `rsh` | Legacy unauthenticated cleartext shell - disable. |
| `tftp` | No authentication - config-leak vector, disable if unused. |
| `snmp` | Often left on 'public' community - disable or set a private community. |
| `http-proxy` | Open proxy - can relay traffic, restrict access. |
| `mysql` / `ms-sql` / `mongodb` / `redis` | Database exposed - bind to localhost/LAN, require auth. |
| `vsftpd 2.3.4` | This exact build shipped with a known backdoor - upgrade immediately. |

Report the flags exactly as raised, as items to VERIFY. The table is curated, not exhaustive:
no flag is not proof of safety, and a flagged service is a lead to check, not a confirmed hole.

## Result anatomy (how each tool's output is shaped)

Each tool returns compact text lines. Parse them like this:

- **discover_lan**: header `... N host(s) up`, then one line per host:
  `IP  (hostname)  MAC [vendor]`. Hostname/MAC/vendor appear only when known - the MAC vendor
  is the best clue for a mystery device. A trailing note reminds you silent hosts can be missed.
- **scan_ports**: header names the scan mode actually used (`-sS` or `-sT`) and echoes any
  fallback note; then `port/proto  state  service` for every non-closed port, then
  `Summary: X open, Y filtered, Z closed.` If the summary/mode says connect (`-sT`), treat
  "filtered" as unavailable - closed and filtered are indistinguishable in that mode.
- **service_scan**: `port/proto open  <name product version (extrainfo)>` per open port. The
  product/version is the inventory value; the closing summary reminds you a version is not a CVE.
- **penny_special**: `port/proto  service: RISK: <note> (banner: ...)` for a flag,
  `port/proto  service: banner: <text>` for context only, or `... no risk flag`. The count in
  the tail includes only `RISK:` lines.
- **grinch_scan**: `port/proto  state  service` where state is `open|filtered` or `closed`,
  then `Summary: A open|filtered, B closed.` If it says INCONCLUSIVE (every port closed), the
  target RST-answered everything (Windows-like) and the Xmas scan told you nothing - fall back
  to scan_ports/service_scan.

Cross-cutting result rules:
- A tool line beginning `error:` or containing an nmap `did not complete` / raw-socket /
  REBOOT message is a FAILED check - report it as broken, never as "clean" or "no issues."
- `[nmap output could not be parsed as XML]` followed by raw text means parsing failed and the
  tool passed the raw output through so nothing is lost - summarize it cautiously and say it is
  unparsed.
- Keep open / closed / filtered / open|filtered strictly distinct when you summarize; collapsing
  them (e.g. calling filtered "closed") is the most common way these results get misreported.
