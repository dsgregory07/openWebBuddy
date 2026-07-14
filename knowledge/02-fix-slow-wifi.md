# Fixing slow or flaky Wi-Fi (home Windows PC)

Scope: the connection works but is slow, laggy, or keeps dropping. Uses `wifi_status`
(signal %, radio type, channel, rates) and `interface_stats` (errors/drops).

## Reading wifi_status on Windows

Windows reports signal as a **percentage**, not dBm. The tool grades it:
- 75-100% excellent, 50-74% good, 30-49% fair, below 30% weak (expect slowness/drops).
Rough dBm equivalent for reference: 75% ~= -57 dBm, 50% ~= -67 dBm, 30% ~= -77 dBm.

Radio type tells you the Wi-Fi generation:
- 802.11n = Wi-Fi 4 (older, slower, often 2.4 GHz only)
- 802.11ac = Wi-Fi 5 (5 GHz, much faster)
- 802.11ax = Wi-Fi 6/6E (newest, fastest)

Channel tells you the band:
- Channels 1-14 = 2.4 GHz (longer range, slower, crowded, only 1/6/11 are non-overlapping)
- Channels 36+ = 5 GHz (shorter range, faster, far less congested)

Receive/transmit rate (Mbps) is the negotiated link rate. If signal is good but the rate
is low, the client and AP negotiated down - often an old radio or a 2.4 GHz-only link.

## Cause: weak signal (below ~50%)

- Move closer to the router or remove obstructions (walls, floors, metal, microwaves,
  fish tanks). Every wall costs signal; brick/concrete costs a lot.
- Reposition the router: central, elevated, out in the open - not in a cabinet or behind
  the TV.
- Consider a mesh node or extender for a distant room. This is the real fix for "great in
  the living room, useless in the bedroom."

## Cause: stuck on 2.4 GHz when 5 GHz is available

If `wifi_status` shows a 2.4 GHz channel (1-11) and an 802.11n radio type but the router
supports 5 GHz:
- Connect to the 5 GHz SSID explicitly if the bands have separate names
  (e.g. "MyNet" vs "MyNet-5G").
- If one SSID covers both bands (band steering), forget and rejoin near the router so it
  associates on 5 GHz.
- 2.4 GHz maxes out far lower and shares airspace with Bluetooth, microwaves, and
  neighbors - it will always feel slow under load.

## Cause: channel congestion (2.4 GHz especially)

- In a dense area, many networks pile onto the same 2.4 GHz channels. In the router admin
  page, set the 2.4 GHz channel to 1, 6, or 11 (whichever is least used) instead of Auto.
- Prefer 5 GHz, which has many non-overlapping channels and far less neighbor interference.

## Cause: interface errors / drops (hardware or interference)

If `interface_stats` shows non-zero and rising rx/tx errors or discards:
- Update the Wi-Fi adapter driver (Device Manager, or the laptop vendor's site).
- Disable USB power management on the adapter (Device Manager > adapter > Power Management
  > uncheck "Allow the computer to turn off this device to save power").
- On a USB Wi-Fi dongle, try a different USB port (USB 3.0 ports can radiate 2.4 GHz noise;
  use a USB 2.0 port or an extension cable to move the dongle away).
- Persistent errors with a strong signal usually mean a driver or hardware fault, not the
  router.

## Cause: it is not the Wi-Fi at all

Slow *internet* over healthy Wi-Fi is a WAN/ISP throughput issue, not a link issue. If
`wifi_status` is good (strong signal, 5 GHz, high rate) and `interface_stats` is clean,
the bottleneck is upstream - run an internet speed test and compare to the plan you pay
for. Do not chase Wi-Fi settings when the link is already fine.

## Quick wins to try first

1. Reboot the router (clears a slow/overloaded radio).
2. Move to 5 GHz.
3. Move closer / clear line of sight.
4. Update the adapter driver.
