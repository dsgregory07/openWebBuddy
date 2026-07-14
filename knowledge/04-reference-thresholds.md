# Network reference: normal vs bad numbers (home LAN)

Scope: quick thresholds for judging tool output. These are practical home-network rules of
thumb, not datacenter SLAs.

## Ping latency (round-trip time)

To the local gateway (router) on the LAN:
- Ethernet: under 1-2 ms is normal. Over ~10 ms to your own router suggests a problem.
- Wi-Fi: 2-10 ms typical; occasional spikes to 20-50 ms under load are normal.
To a public IP (e.g. 1.1.1.1) over the internet:
- Under 30 ms excellent, 30-60 ms good, 60-100 ms okay, over 100 ms noticeable for gaming
  and calls, over 150 ms sluggish.
Packet loss:
- 0% is the only "good" for a wired LAN. Any sustained loss to your own gateway is a
  problem (bad cable, Wi-Fi, or overloaded router).
- 1-2% loss on the internet path is tolerable for browsing, bad for calls/gaming.
- 100% loss = that target is unreachable at that layer.

Windows ping note: "Destination host unreachable" replies are COUNTED AS RECEIVED by
Windows. A summary that says 0% loss but mentions "unreachable" is a FAILED ping, not a
success. Trust the tool's flag.

## Wi-Fi signal (Windows percentage)

- 75-100%: excellent, full speed expected.
- 50-74%: good, fine for everything.
- 30-49%: fair, may slow under load or at range.
- Below 30%: weak, expect slowness and drops. Fix placement before blaming the ISP.

## Wi-Fi link rate

- 2.4 GHz (802.11n): tens to ~150 Mbps link rate typical. Fine for browsing, weak for 4K
  or large transfers.
- 5 GHz (802.11ac/ax): several hundred Mbps to 1+ Gbps link rate. This is where speed
  lives.
- A link rate far below the band's ceiling with a strong signal = negotiated down; suspect
  an old client radio or a forced legacy mode.

## Interface addresses (list_network_interfaces)

- A normal private LAN IPv4: 192.168.x.x, 10.x.x.x, or 172.16-31.x.x.
- 169.254.x.x = APIPA = DHCP FAILED. The adapter is up but got no lease. Not usable for
  internet.
- No IPv4 at all on an "Up" adapter = misconfiguration or a disabled DHCP client.
- Link speed 0 / adapter "Disconnected" = no link (cable out, or Wi-Fi not associated).

## Interface errors and drops (interface_stats)

- 0 errors / 0 drops is normal and expected on a healthy adapter.
- Small static counts that never grow: usually harmless historical blips.
- Counts that RISE while you retest: active problem - bad cable, failing port, driver
  issue, or (Wi-Fi) interference.

## Routing table (show_routes)

- Exactly one default route (0.0.0.0/0) via your gateway is normal.
- NO default route = no path to the internet (DHCP failure or misconfig).
- Two default routes with different metrics: usually a VPN or a second adapter; the lower
  metric wins. Unexpected ones can hijack traffic - check for rogue VPNs.

## DNS resolution time (dns_server_check)

- Under 20-30 ms from a local/router resolver is good; cached answers are near-instant.
- 100+ ms consistently, or timeouts, means a slow or failing resolver - test a public one
  (1.1.1.1, 8.8.8.8) to compare.

## Listening ports on this PC (listening_ports)

- 127.0.0.1 / ::1 bindings = loopback only, not reachable from the network. Safe.
- 0.0.0.0 / :: bindings = listening on ALL interfaces, reachable from the LAN. Make sure
  each such service is one you intend to expose.
- Common benign Windows listeners: 135, 139, 445 (SMB/RPC), 5040, 5353 (mDNS), 3389 (RDP,
  only if you enabled Remote Desktop).

## HTTP status codes (http_check)

- 200 = OK. 204 = OK, no content (used for connectivity checks). 301/302 = redirect
  (normal). 401/403 = reachable but auth/forbidden. 404 = reachable, page missing.
  5xx = server-side error (the site's problem, not yours). Connection refused / timeout =
  not reachable at all.
