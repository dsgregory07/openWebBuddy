# Nmap scanning and reading results (net-vuln tools)

Scope: how the net-vuln tools scan, what each result actually means, and the mistakes to
avoid when turning a scan into a finding. Companion to `03-router-security.md`. All scans
are your own machine / LAN / router only.

## The scan types behind the tools

| Tool | nmap technique | Needs raw packets (Npcap)? | What it is |
|------|----------------|----------------------------|------------|
| `discover_lan` | `-sn` ping/ARP sweep | ARP does; falls back to TCP/ICMP | Finds live hosts, no port scan |
| `scan_ports` | `-sS` SYN, else `-sT` connect | SYN yes; connect no | Port states: open/closed/filtered |
| `service_scan` | `-sT -sV` | No (connect-based) | Service + version on open ports |
| `grinch_scan` | `-sX` Xmas | Yes | Firewall probe of the router |
| `penny_special` | `-sT` + custom NSE | No (connect-based) | Banner grab + risky-service flags |

- **Connect scan (`-sT`)** completes a full TCP handshake through the OS. It needs no
  special privileges and works even when the Npcap driver is not loaded. Its limitation:
  it cannot see "filtered" - a firewalled port and an unreachable one both just look "not
  open."
- **SYN scan (`-sS`)** sends a half-open probe using raw packets. It is faster and, crucially,
  distinguishes filtered from closed. It needs the Npcap driver running.
- **Xmas scan (`-sX`)** sets the FIN/PSH/URG flags. A closed port replies RST; an open or
  firewalled port stays silent. Useful only against Linux/BSD/embedded targets (routers).

## Port states - keep them distinct

| State | Meaning | Do NOT say |
|-------|---------|-----------|
| **open** | Something is listening and accepting connections | "vulnerable" (open is not a flaw) |
| **closed** | Host is reachable but nothing is listening on that port | "filtered" |
| **filtered** | A firewall silently dropped the probe - no reply at all | "closed" |
| **open\|filtered** | Xmas/UDP scans: silence could mean listening OR dropped | pick one without evidence |

Only `scan_ports` in SYN mode (and `grinch_scan`) can report **filtered**. A plain connect
scan cannot - for it, a missing port means "not open among those scanned," never "confirmed
closed."

## The three interpretation mistakes to avoid

1. **An open port is not a vulnerability.** Ports 135, 445, 5357 open on a Windows box, or
   53/80/443 on a router, are normal. Report what is open; do not imply risk that was not
   found.
2. **A version string is not a CVE.** `service_scan` naming "Apache 2.4.58" or "OpenSSH 8.4"
   is an inventory entry, not a confirmed vulnerability. Never claim a specific CVE you did
   not verify. Port/version state is not patch state.
3. **A risky-service flag is a reminder to CHECK, not a detection.** `penny_special` flags
   port 445 with "ensure SMBv1 is disabled" because SMB is open - it did NOT detect that
   SMBv1 is enabled. On modern Windows, SMBv1 is off by default. Say "SMB is open; verify
   SMBv1 is disabled," not "SMBv1 is present."

## Localhost vs the network address - they answer different questions

- Scanning **127.0.0.1** (loopback) bypasses the Windows Firewall and shows everything the
  machine is listening on, including services bound only to loopback (e.g. this stack's own
  OpenWebUI on 3000 and mcpo on 8000). It tells you what is running, NOT what is exposed.
- Scanning the machine's **LAN IP** (e.g. 192.168.x.x) shows what other devices on the
  network can actually reach - the real attack surface. Loopback-only services disappear;
  firewalled services show as filtered.
- So "open on localhost" does not mean "exposed." For an exposure assessment, scan the LAN
  IP, ideally with SYN so filtered vs closed is visible.

## Service names: guessed vs probed

Without `-sV`, nmap labels a port from a static table by number (e.g. it calls 3000 "ppp",
8000 "http-alt"). Those are guesses. `service_scan` (`-sV`) actually probes the port and
returns the real service ("Uvicorn", "OpenWrt uHTTPd"). Trust the `-sV` result over the
port-number guess, and say when a name is only a guess.

## A sane assessment order

1. `discover_lan` - what is on the network (inventory).
2. `scan_ports` on a target - what is open / filtered.
3. `service_scan` on the open ports - what is actually running.
4. `penny_special` - flag anything on the known-risky list to verify.
5. `grinch_scan` - only for the router's firewall behavior (skip for Windows hosts; they
   answer "closed" to every Xmas probe, which is inconclusive).

## Safe-scanning notes (this machine)

- Own machine / LAN / router only. Never intrusive/exploit/DoS/brute scripts.
- Keep scans light by default (top-100 ports); widen only when a thorough scan is asked for,
  and expect it to take longer.
- Raw scans (`-sS`/`-sX`) need the Npcap driver running and, on a USB Wi-Fi adapter, can
  briefly drop the Wi-Fi link. The connect-based tools (`service_scan`, `penny_special`, and
  `scan_ports` in connect mode) never touch the adapter at the raw layer and are Wi-Fi-safe.
