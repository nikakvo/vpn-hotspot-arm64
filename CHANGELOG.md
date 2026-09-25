# Changelog

Tested on Poco F6 Pro, Xiaomi.eu ROM (HyperOS 3, Android 16), kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU), with WireGuard (kernel backend) and v2rayNG. Part of a set with DNSCrypt Proxy Arm64 and ipset-arm64.

## 1.0-r12

First release. Devices on your hotspot (Wi-Fi, USB, Bluetooth) go through the phone's VPN.

* **Routing through any VPN** — detected from Android's own VPN rules, both the root WireGuard kind (all users) and `VpnService` apps such as v2rayNG, Proton VPN or OpenVPN that leave their own uid out (split rules); reconnects (new routing table) and server switches (new interface) are followed in about 2 seconds
* **Kill switch** (on by default) — no VPN → devices get no internet, rejected at once instead of hanging
* **Dead tunnel detection** — sending into the VPN for 20 s with nothing coming back triggers one ping through the tunnel; no answer and the VPN counts as down until it answers again
* **No leak window** — a guard rule blocks devices while rules are rebuilt, and a new hotspot is blocked from its first packet until it is routed
* **Old connections ended** — when the tunnel takes over after devices went out directly, or the VPN switches server, devices' open connections are closed so they reopen through the current tunnel (Android's tether offload, and VPN servers that all give the same inside address, would otherwise keep them on the old path); a small static helper, `bin/vhs-ctflush`, source in `src/`
* **IPv6 not forwarded**, **TCP MSS** follows the tunnel's MTU
* **Client DNS** — handled by DNSCrypt Proxy when present (its queries go through the VPN); otherwise sent to a fallback server (Quad9 by default) through the tunnel
* **Works with DNSCrypt Proxy and ipset** — the firewall order DNSCrypt → ipset → tunnel → Android is kept and checked on every pass
* **Plays well with Android and VPN apps** — tables are read with `iptables-save` (no firewall lock), all changes go in one `iptables-restore` per family, and the watchdog waits for network-event bursts to settle; WireGuard's `wg-quick`, which does not wait for the lock, no longer fails with "wg-quick returned 4 / 124"
* **WebUI** — route strip, exit address on demand, live protection checks, devices, settings (applied in the background, the page never freezes), log, help
* **CLI** — `ctl.sh status | set | clients | exitip | sync | log | diag`

### Development builds (tested on device, not published)

* r1 – r2: first routing core; replaced dozens of separate iptables calls per event with one `iptables-restore` and a settle delay after the phone showed netd timing out while WireGuard switched
* r3 – r4: WebUI; cyberpunk yellow theme; waits for netd when a VPN is half removed
* r5: table checks without the firewall lock (`iptables-save`) — WireGuard failed when any process held it
* r6: settings applied by the watchdog in the background (no WebUI freeze)
* r7: a VPN that is already up is taken at once, even with stale netd rules
* r8: dead tunnel detection; old direct connections ended when the tunnel takes over
* r9: VPN shown while the hotspot is off; exit check names the live tunnel; WebUI root bridge detection made robust
* r10: release candidate
* r11: `VpnService` VPNs (v2rayNG, …) were not recognised — their VPN rule leaves the app's own uid out; detection now covers any split rule, checked against netd's VPN return rule
* r12: VPNs without a `default` route (v2rayNG "bypass LAN", OpenVPN `0.0.0.0/1 + 128.0.0.0/1`) accepted; all client connections ended on a server switch; Help: guests with Private DNS
