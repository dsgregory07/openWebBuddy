# Fixing "no internet" / "internet is down" (home Windows PC)

Scope: a single Windows machine on a home LAN that has lost internet access. Assumes the
net-diag tools have already localized the failing layer. This document is the fix guide
for the NEXT STEPS section, organized by which layer the tools found broken.

## How to read the layers

The diagnosis lands on one of these layers. Fix the lowest broken layer first; a lower
break makes every higher test meaningless.

1. Adapter / IP (this PC has no usable address)
2. Wi-Fi link (associated to the AP or not)
3. Gateway / router (the box at 192.168.x.1)
4. DNS (names do not resolve, but raw IPs work)
5. WAN / internet (LAN is fine, nothing beyond the router works)

## Layer 1 - Adapter or IP address problem

Symptoms from tools: `list_network_interfaces` shows the adapter Down, or Up with only a
`169.254.x.x` address (APIPA = DHCP failed), or no IPv4 at all. `show_routes` reports
"NO DEFAULT ROUTE".

What it means: the PC never got a valid lease from the router, so it has no path anywhere.
This is a local problem, not an ISP outage.

Fixes, in order:
1. Renew the DHCP lease. Open Command Prompt or PowerShell and run:
   `ipconfig /release` then `ipconfig /renew`
2. If still `169.254.x.x`: disable and re-enable the adapter.
   PowerShell (admin): `Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false; Start-Sleep 3; Enable-NetAdapter -Name "Wi-Fi"`
   (Use the adapter name from `list_network_interfaces` - could be "Ethernet".)
3. Reset the TCP/IP stack if the adapter is stuck (admin, then reboot):
   `netsh int ip reset` and `netsh winsock reset`
4. Confirm the router's DHCP server is on and has free addresses (router admin page,
   LAN / DHCP settings). A DHCP pool that is full or disabled starves new clients.
5. If only this PC is affected and others get addresses fine, suspect the adapter driver:
   update it in Device Manager, or roll back a recent driver update.

## Layer 2 - Wi-Fi link problem

Symptoms: `wifi_status` shows the interface disconnected, or connected to the wrong SSID,
or authentication failing.

Fixes:
1. Reconnect to the correct SSID; re-enter the passphrase if auth is failing (a changed
   Wi-Fi password is a common cause).
2. "Forget" the network in Windows Wi-Fi settings and rejoin - clears a stale/wrong saved key.
3. If the SSID is not listed at all, confirm the router's radio is on and broadcasting
   (some routers hide the SSID or disable a band).
4. Slow-but-connected is a different problem - see the Wi-Fi performance guide.

## Layer 3 - Gateway / router not reachable

Symptoms: `check_gateway_reachable` returns 100% loss or "router NOT reachable" while the
adapter has a valid (non-169.254) IP on the router's subnet.

What it means: the PC has an address but cannot talk to the router. Either the router is
down/frozen, or the link between PC and router is bad.

Fixes:
1. Power-cycle the router: unplug it, wait 30 seconds, plug back in, wait ~2 minutes for
   full boot. This clears the large majority of "router froze" cases.
2. On Ethernet: reseat the cable at both ends; try a different port on the router; try a
   known-good cable. `interface_stats` showing rising rx/tx errors points straight here.
3. On Wi-Fi: move closer to the router and retest - a weak link can drop the gateway ping.
4. If other devices also cannot reach the router, it is the router (or its power supply),
   not this PC.

## Layer 4 - DNS broken (raw IP works, names do not)

Symptoms: `check_internet` verdict is "Raw internet (IP) works but DNS is broken";
`dns_server_check` fails against the system/router resolver but a public one (1.1.1.1,
8.8.8.8) succeeds.

What it means: packets reach the internet, but the resolver turning names into addresses
is failing. Usually the router's DNS relay, occasionally a bad DNS setting on the PC.

Fixes:
1. Compare resolvers: if `dns_server_check` with `server=1.1.1.1` works but the default
   fails, the router's DNS is the culprit. Reboot the router first.
2. Set the PC to a public resolver as an immediate workaround (admin PowerShell):
   `Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 1.1.1.1,8.8.8.8`
   Revert with `-ResetServerAddresses` once the router is fixed.
3. Flush the local DNS cache after any change: `ipconfig /flushdns`
4. On the router, set upstream DNS to a known-good public resolver if the ISP's DNS is
   flaky.

## Layer 5 - WAN / internet down (LAN fine, nothing beyond the router)

Symptoms: gateway pings fine, but `check_internet` shows 100% loss to 1.1.1.1;
`traceroute_host` dies at or just past the router / first ISP hop.

What it means: your LAN is healthy; the outage is upstream - the modem, the line, or the
ISP. Nothing you change on the PC fixes this.

Fixes:
1. Power-cycle the modem (if separate from the router): unplug 30-60 seconds, plug back in,
   wait for the online/link light to go solid before testing.
2. If router and modem are one unit, power-cycle it and check the WAN/internet indicator
   light - a red or off light means no signal from the ISP.
3. Check the ISP's outage page or app from your phone (on cellular data). A confirmed area
   outage means wait it out.
4. Check for an unpaid-bill / suspended-service notice - some ISPs redirect all traffic to
   a captive page, which shows as "DNS resolves but web fails" (partial connectivity).

## General escalation order (when unsure)

Reboot the PC's adapter, then reboot the router, then reboot the modem, then call the ISP.
Cheapest and least disruptive first. Do not change router config to fix what a 2-minute
power-cycle fixes.
