# Home router security and port reference

Scope: interpreting `router_quick_audit` and `port_scan` results against a home router,
and hardening it. These two net-diag tools focus on OPEN ports - when nmap is installed they
run it as a connect scan (`nmap -sT`), otherwise a built-in connect scan capped at 256 ports.
Either way, treat "not listed" as "not open among the ports scanned," never "confirmed
closed"; for reliable closed-vs-filtered use the net-vuln `scan_ports` tool.

If the nmap-powered **net-vuln** tools are enabled (see "The net-vuln security tools"
below), you have stronger options: `scan_ports` reports real open / closed / **filtered**
states, `service_scan` names the service and version on each open port, `grinch_scan`
probes the router firewall with an Xmas scan, and `discover_lan` actively inventories the
LAN. Prefer them for a security assessment; keep `router_quick_audit`/`port_scan` for a
quick open-port glance when net-vuln is toggled off.

## Common home-router ports and what an OPEN one means

| Port | Service | Open on a home router means |
|------|---------|-----------------------------|
| 53   | DNS | Normal - the router runs a DNS relay/forwarder for the LAN. Expected. |
| 80   | HTTP admin | The web admin page (unencrypted). Normal on the LAN side; must NOT be open on the WAN/internet side. |
| 443  | HTTPS admin | The web admin page (encrypted). Normal on the LAN side. Preferred over 80. |
| 8080 | Alt HTTP admin | Alternate admin port. Fine on LAN; risky if exposed to WAN. |
| 8443 | Alt HTTPS admin | Alternate secure admin port. Fine on LAN. |
| 22   | SSH | Some routers/OpenWrt. Fine if you set it up; investigate if you did not. |
| 23   | Telnet | RISK. Unencrypted remote admin. Should be OFF. See below. |
| 21   | FTP | RISK on the router itself. Plaintext credentials. Usually a USB-share feature - disable if unused. |
| 139/445 | SMB | File sharing (router USB storage). Never safe to expose to WAN; limit to LAN. |
| 1900 | UPnP/SSDP | UPnP discovery. Convenient but a known attack surface; disable if you do not need automatic port forwarding. |
| 5000/49152+ | UPnP control / TR-069 | Vendor management. TR-069 (7547) is ISP remote management - normal but has had serious vulnerabilities. |

Typical healthy home router seen from the LAN: 53, 80, and/or 443 open. That is the normal
baseline, not a problem.

## Risk flags the audit raises

- **Port 23 (telnet) OPEN**: telnet sends everything, including the admin password, in
  cleartext. It is a top cause of router botnet compromise. Disable it in the router admin
  (often under Administration / Remote Management / System). If it cannot be disabled, that
  firmware is a liability.
- **Port 21 (FTP) OPEN**: usually the router's USB file-share over FTP. Credentials are
  plaintext. Disable FTP sharing or switch to a secure alternative; never forward it to the
  internet.

## Hardening checklist (home router)

1. **Change the default admin password.** Default creds are the number-one router risk.
   Use a long unique password.
2. **Disable remote/WAN administration.** Admin (80/443/8080) should be reachable from the
   LAN only, never the internet. Check "Remote Management" is OFF.
3. **Turn off telnet and any plaintext service** (23, 21) unless you truly need them.
4. **Disable UPnP** if you do not knowingly rely on it - it lets apps open ports without
   asking. Some games/consoles want it; trade off consciously.
5. **Disable WPS** (the push-button/PIN pairing) - the PIN method is brute-forceable.
6. **Update firmware.** Out-of-date router firmware is how known exploits get in. Check the
   admin page for updates, or enable auto-update if offered.
7. **Use WPA2 or WPA3** for Wi-Fi, never WEP or open. `wifi_status` shows the auth type.
8. **Change the default SSID** if it reveals the router model (helps attackers pick an
   exploit). Optional but easy.
9. **Guest network** for visitors and IoT gadgets, isolated from your main LAN.

## Interpreting "is my router OK?"

A clean result is: gateway reachable, only 53/80/443 open, no telnet/FTP, WPA2/WPA3 in
use, firmware current. Say that plainly - a healthy router is a valid finding. Only flag
what the tools actually found open; do not warn about ports that were not in the scanned
set.

## What the scan CANNOT tell you

- Whether the router is reachable *from the internet* (the tools scan from inside the LAN).
  WAN exposure has to be checked from outside or in the router's config.
- Whether a service is patched. An open 443 admin page can still be running vulnerable
  firmware. Port state is not vulnerability state.
- Closed vs filtered. With net-diag's `port_scan`/`router_quick_audit` (a connect scan,
  whether via `nmap -sT` or the built-in fallback), a port "not open among those scanned" may
  be firewalled or simply not listening - it cannot distinguish them reliably. The net-vuln
  `scan_ports` tool CAN: it reports "filtered" (a firewall is silently dropping the port)
  separately from "closed" (nothing listening).

## The net-vuln security tools (nmap)

When the net-vuln category is enabled, these assess the network from this host's
perspective. They need nmap installed (its Windows installer bundles Npcap); if nmap is
missing they return a clear message instead of a result. Own machine / LAN / router only.

- **`discover_lan`** - active LAN sweep (nmap -sn). A real inventory of live devices. For
  WHAT a device is (not just its IP), prefer net-diag's `dev_disco` - it adds SSDP/vendor
  identity that this tool does not.
- **`scan_ports`** - open / closed / **filtered** per port (nmap SYN scan, connect-scan
  fallback if raw packets are unavailable). Report "filtered" and "closed" distinctly.
- **`service_scan`** - service + version per open port (nmap -sV), e.g.
  "80/tcp open http Apache 2.4.58". A version is NOT itself a vulnerability - do not claim
  a CVE you have not verified; port/version state is not patch state.
- **`grinch_scan`** - Xmas-scan firewall probe of the router (nmap -sX, default target the
  gateway). It reveals ports a firewall silently drops. CAVEAT: it cannot characterize
  Windows hosts - they answer "closed" to every port - so if every port is closed or the
  target is Windows, the result is inconclusive; use `scan_ports`/`service_scan` instead.
- **`penny_special`** - a custom, read-only NSE banner grab that flags known-risky services
  (telnet, FTP, SMB/SMBv1, obsolete SSH/HTTP, exposed databases, ...). It only reads
  banners; absence of a flag is not proof of safety.

None of these run intrusive/exploit/dos/brute NSE scripts, and they stay on your own
machine, LAN, and router.
