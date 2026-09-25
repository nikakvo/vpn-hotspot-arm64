<p align="center">
  <img src="https://img.shields.io/badge/ARM64-only-fcee0a?style=flat-square" />
  <img src="https://img.shields.io/badge/v1.0--r12-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/SukiSU%20%2F%20KernelSU%20%2F%20Magisk-compatible-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/WebUI-built%20in-fcee0a?style=flat-square" />
</p>

# VPN Hotspot — arm64

Your phone's VPN for the devices on your hotspot. Android's VPN protects only the apps on the phone; a laptop on your hotspot goes straight out through your mobile or Wi-Fi connection and shows your real address. This module sends everything those devices do **through the phone's VPN**, with a **kill switch**: no VPN, no internet for them — never your connection directly.

<img width="300" alt="VPN Hotspot WebUI" src="https://raw.githubusercontent.com/nikakvo/vpn-hotspot-arm64/main/vpn-hotspot-arm64.jpg" />

---

## Features

- **Any VPN app** — detected from Android's own VPN rules, whether the app covers everything (WireGuard kernel backend) or leaves itself out (v2rayNG, Proton VPN, OpenVPN and other `VpnService` apps); `tun0`, `wg-*` — followed automatically, including server switches
- **Any tethering** — Wi-Fi hotspot, USB, Bluetooth, several at once
- **Kill switch** — VPN down → devices get no internet, rejected at once (no hanging); on by default
- **Dead tunnel detection** — a VPN that is "connected" but no longer answers counts as down
- **No leak window** — while rules change, devices are blocked; a new hotspot is blocked from the first packet until it is routed
- **Old connections ended** — when the tunnel takes over, or the VPN switches server, devices' open connections are closed, so everything reopens through the current tunnel at once (phones keep connections open for a long time; without this they would keep the old exit)
- **IPv6 not forwarded** — nothing leaks around an IPv4 tunnel
- **Right packet size** — TCP MSS follows the tunnel's MTU (no stalled pages on WireGuard)
- **Self-healing** — reacts to network events in about 2 seconds, repairs rules Android moves or removes
- **Plays well with Android** — never holds the firewall lock while checking, so VPN apps connect and disconnect without errors
- **WebUI** — route at a glance, exit address on demand, every protection piece checked live, connected devices, settings, log

---

## How it works

```
device on the hotspot
      ↓
DNSCrypt Proxy + ipset filters (if installed)
      ↓
routing rule: everything from the hotspot → the VPN's table   (kill switch: else unreachable)
      ↓
address translation into the tunnel · MSS clamp
      ↓
VPN server → internet
```

Per hotspot interface: routing rules at priority 20400–20600 (just above Android's own tethering rule at 21000), a firewall chain that lets devices out only through the VPN, NAT into the tunnel, an MSS clamp and an IPv6 block. A watchdog keeps it true through hotspot on/off, new subnets, VPN reconnects (new routing table each time), server switches, MTU changes and Android reordering the firewall.

---

## Requirements

| | |
|---|---|
| CPU | arm64 |
| Root | SukiSU Ultra or KernelSU (WebUI built in) · APatch · Magisk (WebUI via MMRL or KSU WebUI Standalone) |
| Android | 12+ |
| VPN | any app that uses Android's VPN (see below) |

### Tested on

Poco F6 Pro (vermeer), Xiaomi.eu ROM (HyperOS 3, Android 16), custom kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU) (SukiSU Ultra), together with DNSCrypt Proxy Arm64 and ipset-arm64 — on Wi-Fi and on mobile data, with a Windows laptop and a stock (unrooted) Android phone as hotspot devices. Other devices, ROMs and kernels should work but are not tested — reports welcome.

### VPN apps

| App | Status |
|---|---|
| WireGuard (kernel backend, root) — Proton VPN WireGuard configs | tested on the device |
| v2rayNG (VPN mode, `tun0`) | tested on the device |
| WireGuard (userspace), Proton VPN app, OpenVPN, other `VpnService` apps | supported — same kind of VPN rules as v2rayNG (tested in the simulator); please report how it works for you |

---

## Installation

1. Flash `vpn-hotspot-arm64-vX.X.zip` in your root manager
2. Reboot
3. Connect your VPN, turn on the hotspot, connect a device
4. Open the WebUI — the route at the top shows **Clients → your VPN → Internet**

Settings are kept on update.

---

## WebUI

| Tab | |
|---|---|
| Dashboard | Route strip · exit address (tap **Check**) · tunnel (interface, table, MTU/MSS, answers) · protection checks · the networking set · watchdog |
| Devices | Connected devices: address, MAC, interface |
| Settings | Route through VPN · kill switch · dead tunnel detection · VPN interface (auto / choose) · DNS fallback · Check now / Rebuild / Report |
| Log | Filterable by level |

The dashboard reads only what the watchdog already wrote — opening it costs nothing and never touches the firewall.

---

## States

| State | Meaning |
|---|---|
| **Via VPN** | Devices use the VPN |
| **Blocked** | No VPN (or not responding), kill switch on — devices have no internet |
| **Direct** | No VPN, kill switch off — devices use your connection directly |
| **Idle** | Hotspot off — nothing installed |
| **Off** | Turned off in Settings — nothing installed |

---

## Settings

| Key | Default | |
|---|---|---|
| `ENABLED` | `1` | Route hotspot devices through the VPN |
| `KILL_SWITCH` | `1` | No VPN → devices blocked (`0`: they use your connection) |
| `TUNNEL_CHECK` | `1` | Sending 20 s with nothing coming back → one ping through the tunnel; no answer = VPN down |
| `VPN_IFACE` | `auto` | Or a fixed interface name when two VPNs run |
| `FALLBACK_DNS` | `9.9.9.9` | Devices' DNS through the tunnel when no local resolver takes it |

---

## The networking set

Three modules built to work together — each one works on its own, and each adds a layer for the phone **and everyone on its hotspot**:

| | Module | What it adds |
|---|---|---|
| 🟢 | [DNSCrypt Proxy Arm64](https://github.com/nikakvo/dnscrypt-proxy-android-arm64-only) | Encrypted DNS with ad / tracker blocklists — for the phone and for hotspot devices, even those with their own DNS server set |
| 🔵 | [ipset-arm64](https://github.com/nikakvo/ipset-arm64) | IP blocklists (FireHOL, Spamhaus) in the kernel — stops apps and devices that connect to hard-coded IP addresses, which DNS blocking cannot see |
| 🟡 | **VPN Hotspot Arm64** *(this module)* | Sends hotspot, USB and Bluetooth devices through the phone's VPN, with kill switch — Android's VPN only covers the phone's own apps |

```
device on your hotspot  /  app on the phone
   │  DNS      → DNSCrypt Proxy   encrypted, filtered
   │  traffic  → ipset            listed networks dropped
   ▼  hotspot  → VPN Hotspot      into your VPN (kill switch)
internet
```

- **Order is fixed and checked** by each module: DNSCrypt's hotspot filter → ipset → VPN Hotspot → Android. Nothing reaches the VPN around the two filters
- **With all three**, hotspot devices get your filtered DNS (DNSCrypt's own queries travel inside the VPN), your IP blocklists and your VPN exit — on Wi-Fi and on mobile data
- **VPN apps stay happy** — none of the three holds Android's firewall lock while checking, so WireGuard (`wg-quick`) and other VPN apps connect and disconnect without errors
- **On its own** it sends hotspot devices through the VPN with the kill switch; their DNS goes to a fallback server (Quad9) through the tunnel, without blocklists.

**Tested together** on a Poco F6 Pro (vermeer), Xiaomi.eu ROM (HyperOS 3, Android 16), kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU) (SukiSU Ultra), with WireGuard (kernel backend) and v2rayNG; hotspot devices: a Windows laptop and a stock Android phone. Other devices should work but are not tested — reports welcome.

---

## Files

| Path | |
|---|---|
| `/data/adb/vpn-hotspot.conf` | Settings |
| `/data/adb/vpn-hotspot.log` | Log (last 1000 lines) |
| `/data/adb/vpn-hotspot-state/` | Runtime state, cleared at boot |
| `bin/vhs-ctflush` | Ends devices' old direct connections — static arm64, source in `src/` |

---

## Command line

```sh
# as root
sh /data/adb/modules/vpn-hotspot/ctl.sh status
sh /data/adb/modules/vpn-hotspot/ctl.sh set KILL_SWITCH 0
sh /data/adb/modules/vpn-hotspot/ctl.sh set VPN_IFACE auto
sh /data/adb/modules/vpn-hotspot/ctl.sh clients
sh /data/adb/modules/vpn-hotspot/ctl.sh exitip
sh /data/adb/modules/vpn-hotspot/ctl.sh sync          # check now
sh /data/adb/modules/vpn-hotspot/ctl.sh sync force    # rebuild everything
sh /data/adb/modules/vpn-hotspot/ctl.sh log 100
sh /data/adb/modules/vpn-hotspot/ctl.sh diag          # full report
```

---

## Verify

On a device connected to your hotspot:

```
curl https://ifconfig.me          → the VPN's address
```

Then turn the VPN off: the device loses internet at once (kill switch), and gets it back through the VPN when it reconnects. Use `curl` or a private window — a browser tab may keep showing a cached result.

---

## Notes

- **Speed** — the module adds no measurable cost; the tunnel and the hotspot radio set the limit. A 2.4 GHz hotspot tops out near 100 Mbit/s — set it to 5 GHz.
- **Tether offload** — Android accelerates tethering past the firewall, but only for traffic to your normal connection, never into the VPN; no setting is changed.
- **Guests with Private DNS** — a phone with Private DNS set to a hostname (e.g. `dns.adguard-dns.com`) gets no DNS while DNSCrypt Proxy blocks DoT for hotspot clients. The guest sets Private DNS to *Automatic* (then your filtered DNSCrypt is used), or you turn off *Block DoT for hotspot clients* in DNSCrypt Proxy (their encrypted DNS then works through your VPN, without your filters)
- **DNS lines in VPN configs** — with DNSCrypt Proxy you can remove `DNS =` from WireGuard configs; DNS never needs the VPN provider's resolver.

---

## Uninstall

Remove the module in your root manager and reboot. Every rule is removed at once; settings and log are deleted. Tethering is Android's normal one again.

---

## Build `vhs-ctflush`

```sh
zig cc -target aarch64-linux-musl -static -Os -o bin/vhs-ctflush src/vhs-ctflush.c
```
