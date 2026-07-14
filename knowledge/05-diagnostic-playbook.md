# Diagnostic playbook: symptom -> tool sequence -> likely cause

Scope: maps a user's plain-language complaint to the right tool chain and the conclusions
each result supports. Complements the system prompt; this is the "what does the pattern
mean" layer.

## "The internet is down" / "nothing loads"

Chain: check_gateway_reachable -> check_internet -> (dns_server_check or traceroute_host).
Call list_network_interfaces first only if the adapter is suspect.

Result patterns:
- Gateway unreachable + adapter has 169.254.x.x -> DHCP failed (Layer 1). Local problem.
- Gateway unreachable + adapter has a valid IP -> router down or bad link (Layer 3).
- Gateway OK + check_internet 100% loss to 1.1.1.1 -> WAN/ISP outage (Layer 5). Upstream.
- Gateway OK + IP ping OK + DNS fails -> DNS broken (Layer 4). Compare resolvers.
- Everything passes -> not a connectivity outage. Ask what "down" means (one site? one app?
  slow?) and pivot to http_check for the specific site.

## "Is my router OK?" / "is my network secure?"

Chain: router_quick_audit (one call covers ping + management-port scan + risk flags).
Follow with port_scan only if the user wants a wider range than the 8 audited ports.

Result patterns:
- Reachable + only 53/80/443 open + no flags -> healthy. Say so plainly.
- Telnet (23) or FTP (21) open -> call it out as a risk; point to the hardening steps.
- Gateway unreachable -> this is a connectivity problem, not a security one; switch to the
  "internet is down" chain.

## "Why is Wi-Fi slow?" / "Wi-Fi keeps dropping"

Chain: wifi_status -> interface_stats. Add check_internet if they mean slow *internet*
rather than slow *link*.

Result patterns:
- Weak signal (<50%) -> placement/range problem.
- Good signal but 2.4 GHz + 802.11n -> move to 5 GHz.
- Good signal + rising interface errors -> driver/hardware/interference.
- Everything clean but internet still slow -> WAN throughput/ISP, not Wi-Fi. Speed-test.

## "I can't reach [specific site or device]"

Chain: confirm lower layers with check_internet if broad; then http_check <url> for a
website, or ping_host + port_scan <host> for a device/service.

Result patterns:
- Other sites work, this one does not: http_check shows the status. 5xx = their server.
  Timeout/refused = their end or a block. Slow total time = their end or the path.
- A LAN device pings but the expected port is not open -> the host is up but the service is
  down or bound to loopback only. Reachability is not availability.
- Nothing resolves -> back to the DNS chain.

## "Is something on my network I don't recognize?"

Chain: arp_scan_lan. Remember this is the ARP CACHE, not a sweep - it lists only devices
this PC has recently exchanged traffic with, so absence proves nothing. For a real
inventory the user needs to check the router's DHCP client list.

## "My local service/server isn't working"

Chain: listening_ports on this PC.
- Service bound to 127.0.0.1 only -> works locally, not reachable from other devices.
  Rebind to 0.0.0.0 if LAN access is intended.
- Port not listed at all -> the service is not running or crashed.
- Bound to 0.0.0.0 as expected but remote clients still fail -> check Windows Firewall for
  that port.

## Cross-cutting reminders

- Fix the lowest broken layer first; higher tests are meaningless below a break.
- A healthy result is a real, reportable diagnosis - do not manufacture a fault.
- Every claim in the answer must trace to a tool result. If a check was not run, it belongs
  in UNVERIFIED, not in DIAGNOSIS.
