# Home router security and port reference

Scope: interpreting `router_quick_audit` and `port_scan` results against a home router,
and hardening it. The tools report OPEN ports only and cannot distinguish closed from
filtered, so "not listed" means "not open among the ports scanned," never "confirmed
closed."

## Common home-router ports and what an OPEN one means

| Port | Service | Open on a home router means |
|------|---------|-----------------------------|
| 53   | DNS | Normal - the router runs a DNS relay/forwarder for the LAN. Expected. |
| 80   | HTTP admin | The web admin page (unencrypted). Normal on the LAN side; must NOT be open on the WAN/internet side. |
| 443  | HTTPS admin | The web admin page (encrypted). Normal on the LAN side. Preferred over 80. |
| 8080 | Alt HTTP admin | Alternate admin/管理 port. Fine on LAN; risky if exposed to WAN. |
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
- Closed vs filtered. A port "not open among those scanned" may be firewalled or simply not
  listening; the connect scan cannot distinguish them.
