#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/common.sh - shared by post-fs-data.sh, service.sh, ctl.sh, uninstall.sh
#
# Only defines variables and functions; sourcing it does nothing else.
# POSIX sh: runs under mksh + toybox (ksu.exec, WebUI) and busybox ash in
# standalone mode (the root manager's service.sh / installer). No bashisms.

MODULE_ID="vpn-hotspot"
MODDIR="${MODDIR:-/data/adb/modules/$MODULE_ID}"

# ── Paths ────────────────────────────────────────────────────────────────────
CONF="/data/adb/vpn-hotspot.conf"
STATE_DIR="/data/adb/vpn-hotspot-state"
LOG="/data/adb/vpn-hotspot.log"
MODPROP="$MODDIR/module.prop"

WD_PIDFILE="$STATE_DIR/watchdog.pid"
MON_PIDFILE="$STATE_DIR/monitor.pid"
MON_FIFO="$STATE_DIR/monitor.fifo"
TICK_FILE="$STATE_DIR/tick"
STATUS_FILE="$STATE_DIR/status"
APPLIED_FILE="$STATE_DIR/applied"
LOCK_DIR="$STATE_DIR/lock"

# netd's table-name file. Android's ip reads it, so rules print names.
RT_TABLES="/data/misc/net/rt_tables"

# Watchdog period. Network events (link, address, rule changes) wake it at
# once; the tick only catches what produces no event (iptables changes).
TICK=10
# After a network event wait until it has been quiet this long (netd sends
# bursts while a VPN or hotspot comes up), but never longer than SETTLE_MAX.
SETTLE=2
SETTLE_MAX=10
# While netd is half-way through adding or removing a VPN network the
# module waits (the kill switch rule already holds clients), at most this
# long. Seen on the phone: netd stuck with a half-removed VPN.
NETD_WAIT=6
NETD_BUSY_FILE="$STATE_DIR/netd_busy"
# Tunnel health: sending through the VPN for this long without receiving
# anything makes the watchdog probe it (ping 1.1.1.1 / 9.9.9.9 through the
# interface). A tunnel that does not answer counts as down: kill switch on
# -> clients blocked, off -> clients use the normal uplink.
TUNNEL_SILENT=20
TUNNEL_FILE="$STATE_DIR/tunnel"
# Cuts clients' conntrack entries (see src/vhs-ctflush.c)
CTFLUSH="$MODDIR/bin/vhs-ctflush"
LAST_VPN_FILE="$STATE_DIR/last_vpn"   # tunnel the clients used last
# Which kind of VPN the clients used last (wg-shield | android). Kept across
# reboots: it decides whether "WG Shield turned off" means "go direct".
LAST_SRC_FILE="${VHS_LAST_SRC:-/data/adb/vpn-hotspot-last-source}"

# ip rule priorities. Android's tether rule is 21000 ("iif <tether> lookup
# <upstream>"); everything here sits just above it so it wins, and below
# netd's own rules (<= 20000) so nothing of Android's is overridden.
PREF_GUARD=20350   # temporary block while rules are rebuilt (no leak window)
PREF_LOCAL=20400   # client <-> tether subnet stays local
PREF_VPN=20500     # everything else from clients -> the VPN's table
PREF_KILL=20600    # kill switch: nothing falls through to the plain uplink

# Chain names
C_FWD="VHS_FWD"      # filter FORWARD (v4)
C_FWD6="VHS_FWD6"    # filter FORWARD (v6): clients' IPv6 is not forwarded
C_POST="VHS_POST"    # nat POSTROUTING: MASQUERADE into the tunnel
C_MSS="VHS_MSS"      # mangle FORWARD: MSS clamp for the tunnel MTU
C_PRE="VHS_PRE"      # nat PREROUTING: client DNS fallback

# ── Settings ─────────────────────────────────────────────────────────────────
# KEY=value, read FRESH from the file on every call: the long-lived watchdog
# must never undo a change made a moment ago from ctl.sh / the WebUI.
SETTINGS_KEYS="ENABLED KILL_SWITCH VPN_IFACE FALLBACK_DNS TUNNEL_CHECK"

conf_default() {
  case "$1" in
    ENABLED) echo 1 ;;
    KILL_SWITCH) echo 1 ;;
    TUNNEL_CHECK) echo 1 ;;
    VPN_IFACE) echo auto ;;
    FALLBACK_DNS) echo 9.9.9.9 ;;
  esac
}

conf_valid() { # <KEY> <value>
  case "$1" in
    ENABLED | KILL_SWITCH | TUNNEL_CHECK)
      case "$2" in 0 | 1) return 0 ;; esac ;;
    VPN_IFACE)
      [ "$2" = auto ] && return 0
      case "$2" in *[!A-Za-z0-9_.-]* | "") return 1 ;; esac
      [ "${#2}" -le 15 ] && return 0 ;;
    FALLBACK_DNS)
      _is_ipv4 "$2" && return 0 ;;
  esac
  return 1
}

_is_ipv4() {
  case "$1" in *[!0-9.]* | "" | .* | *. | *..*) return 1 ;; esac
  _o=$1; _n=0
  while [ -n "$_o" ]; do
    _p=${_o%%.*}
    [ "$_p" -le 255 ] 2>/dev/null || { unset _o _n _p; return 1; }
    _n=$((_n + 1))
    case "$_o" in *.*) _o=${_o#*.} ;; *) _o="" ;; esac
  done
  [ "$_n" -eq 4 ]; _r=$?
  unset _o _n _p
  return $_r
}

conf_get() { # <KEY> -> value (default when missing or invalid)
  _cv=$(sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -n 1)
  conf_valid "$1" "$_cv" || _cv=$(conf_default "$1")
  echo "$_cv"
  unset _cv
}

conf_set() { # <KEY> <value>
  conf_valid "$1" "$2" || return 1
  mkdir -p "${CONF%/*}" 2>/dev/null
  { grep -v "^$1=" "$CONF" 2>/dev/null; echo "$1=$2"; } > "$CONF.tmp" &&
    mv -f "$CONF.tmp" "$CONF"
}

# Missing keys are added with their default; existing values are kept.
conf_init() {
  [ -f "$CONF" ] || : > "$CONF"
  for _k in $SETTINGS_KEYS; do
    grep -q "^$_k=" "$CONF" 2>/dev/null || echo "$_k=$(conf_default "$_k")" >> "$CONF"
  done
  unset _k
}

# ── Logging ──────────────────────────────────────────────────────────────────
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_info()  { echo "$(_ts) [INFO] $*"  >> "$LOG"; }
log_warn()  { echo "$(_ts) [WARN] $*"  >> "$LOG"; }
log_error() { echo "$(_ts) [ERROR] $*" >> "$LOG"; }

# Keep the last 1000 lines. Runs at boot and every few minutes in the
# watchdog (the log used to be trimmed only at boot and grew until the next
# reboot).
log_trim() {
  [ -f "$LOG" ] || return 0
  _lc=$(wc -l < "$LOG" 2>/dev/null)
  if [ "${_lc:-0}" -gt 1200 ] 2>/dev/null; then
    tail -n 1000 "$LOG" > "$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG"
  fi
  unset _lc
}

# Empty the log in place (same file, same owner/mode); writers append on
# every line, so the next line simply starts the new log.
log_clear() {
  rm -f "$LOG.tmp"
  : > "$LOG"
}

# ── Tools ────────────────────────────────────────────────────────────────────
# ip: Android's iproute2, never busybox's applet. In busybox standalone mode
# (service.sh) "ip" would be busybox's, which can neither print uidrange
# rules (VPN detection) nor run "ip monitor".
if [ -z "$IP_BIN" ]; then
  if [ -x /system/bin/ip ]; then
    IP_BIN=/system/bin/ip
  else
    IP_BIN=$(command -v ip 2>/dev/null)
    case "$IP_BIN" in /*) ;; *) IP_BIN="" ;; esac
  fi
fi
ip() { [ -n "$IP_BIN" ] || return 127; "$IP_BIN" "$@"; }

# iptables / ip6tables always wait for the xtables lock (-w). Without it a
# command fails at once while netd or another module holds the lock, and a
# failed check reads as "rule missing" (dnscrypt-proxy r15 inserted a jump
# twice that way). The working -w form is probed once per boot.
IPT_WAIT_FILE="$STATE_DIR/ipt_wait"
if [ -z "$IPT4_BIN" ]; then
  IPT4_BIN=$(command -v iptables 2>/dev/null)
  case "$IPT4_BIN" in /*) ;; *) IPT4_BIN="" ;; esac
  IPT6_BIN=$(command -v ip6tables 2>/dev/null)
  case "$IPT6_BIN" in /*) ;; *) IPT6_BIN="" ;; esac
  IPT_W="-"
fi

_ipt_wait_init() {
  [ "$IPT_W" != "-" ] && return 0
  if [ -f "$IPT_WAIT_FILE" ]; then
    IPT_W=""
    read -r IPT_W 2>/dev/null < "$IPT_WAIT_FILE"
    return 0
  fi
  [ -n "$IPT4_BIN" ] || { IPT_W=""; return 0; }
  for _iw in "-w 5" "-w"; do
    # shellcheck disable=SC2086
    if "$IPT4_BIN" $_iw -S OUTPUT >/dev/null 2>&1; then
      IPT_W=$_iw
      mkdir -p "$STATE_DIR" 2>/dev/null
      echo "$IPT_W" > "$IPT_WAIT_FILE" 2>/dev/null
      unset _iw
      return 0
    fi
  done
  IPT_W=""; unset _iw
  _ipt_w_retry=1
}

iptables() {
  _ipt_wait_init
  [ -n "$IPT4_BIN" ] || return 127
  # shellcheck disable=SC2086
  "$IPT4_BIN" $IPT_W "$@"
  _ipt_rc=$?
  [ -n "$_ipt_w_retry" ] && { IPT_W="-"; unset _ipt_w_retry; }
  return $_ipt_rc
}

ip6tables() {
  _ipt_wait_init
  [ -n "$IPT6_BIN" ] || return 127
  # shellcheck disable=SC2086
  "$IPT6_BIN" $IPT_W "$@"
  _ipt_rc=$?
  [ -n "$_ipt_w_retry" ] && { IPT_W="-"; unset _ipt_w_retry; }
  return $_ipt_rc
}

# ip6tables usable at all (always on Android; not in every test sandbox)
has_ip6t() { ip6tables -S FORWARD >/dev/null 2>&1; }

# iptables-restore: all our changes to a family in ONE call, so the xtables
# lock is taken once instead of once per rule. netd configures a VPN with
# many iptables commands of its own; a module firing dozens of separate
# calls at the same moment can make netd's commands time out (seen on the
# phone in 1.0-r1: WireGuard failed with "wg-quick returned 124" and netd
# kept a half-removed VPN network).
if [ -z "$IPTR4_BIN" ]; then
  IPTR4_BIN=$(command -v iptables-restore 2>/dev/null)
  case "$IPTR4_BIN" in /*) ;; *) IPTR4_BIN="" ;; esac
  IPTR6_BIN=$(command -v ip6tables-restore 2>/dev/null)
  case "$IPTR6_BIN" in /*) ;; *) IPTR6_BIN="" ;; esac
  IPTR_W="-"
fi
IPTR_WAIT_FILE="$STATE_DIR/iptr_wait"

# Reading the tables WITHOUT the xtables lock: iptables-save never takes it
# (iptables -S / -L may). WireGuard's wg-quick runs iptables without -w and
# fails outright if anyone holds the lock at that instant (seen on the
# phone: "Another app is currently holding the xtables lock" -> "wg-quick
# returned 4"). So the watchdog's checks must not touch the lock at all.
if [ -z "$IPTS4_BIN" ]; then
  IPTS4_BIN=$(command -v iptables-save 2>/dev/null)
  case "$IPTS4_BIN" in /*) ;; *) IPTS4_BIN="" ;; esac
  IPTS6_BIN=$(command -v ip6tables-save 2>/dev/null)
  case "$IPTS6_BIN" in /*) ;; *) IPTS6_BIN="" ;; esac
fi

# ipt_dump <4|6> <table>: the table in "iptables -S" form (-P / -N / -A
# lines), from iptables-save when available. Fails if the table cannot be
# read (e.g. no IPv6).
ipt_dump() {
  if [ "$1" = 6 ]; then _db=$IPTS6_BIN; _dc=ip6tables; else _db=$IPTS4_BIN; _dc=iptables; fi
  if [ -n "$_db" ]; then
    _dt=$("$_db" -t "$2" 2>/dev/null) || { unset _db _dc _dt; return 1; }
    case "$_dt" in *"*$2"*) ;; *) unset _db _dc _dt; return 1 ;; esac
    printf '%s\n' "$_dt" | sed -n -e 's/^:\([^ ]*\) - .*/-N \1/p' -e 's/^:\([^ ]*\) \([A-Z][A-Z]*\) .*/-P \1 \2/p' -e '/^-A /p'
    unset _db _dc _dt
    return 0
  fi
  "$_dc" -t "$2" -S 2>/dev/null; _dr=$?
  unset _db _dc
  return $_dr
}

_iptr_wait_init() {
  [ "$IPTR_W" != "-" ] && return 0
  if [ -f "$IPTR_WAIT_FILE" ]; then
    IPTR_W=""; read -r IPTR_W 2>/dev/null < "$IPTR_WAIT_FILE"; return 0
  fi
  IPTR_W=""
  [ -n "$IPTR4_BIN" ] || return 0
  for _iw in "-w 5" "-w" ""; do
    # shellcheck disable=SC2086
    if printf '*filter\nCOMMIT\n' | "$IPTR4_BIN" $_iw --noflush >/dev/null 2>&1; then
      IPTR_W=$_iw
      mkdir -p "$STATE_DIR" 2>/dev/null
      echo "$IPTR_W" > "$IPTR_WAIT_FILE" 2>/dev/null
      break
    fi
  done
  unset _iw
}

_ipt_line() { # <cmd> <table> <rule line>
  # shellcheck disable=SC2086
  "$1" -t "$2" $3 2>/dev/null
}

# ipt_restore <4|6>  - reads iptables-restore input (applied with
# --noflush) on stdin. Without the restore tool: one command per line.
ipt_restore() {
  if [ "$1" = 6 ]; then _rb=$IPTR6_BIN; _rt=ip6tables; else _rb=$IPTR4_BIN; _rt=iptables; fi
  if [ -n "$_rb" ]; then
    _iptr_wait_init
    # shellcheck disable=SC2086
    "$_rb" $IPTR_W --noflush
    _rr=$?
    unset _rb _rt
    return $_rr
  fi
  _rtab=filter; _rr=0
  while read -r _rl; do
    case "$_rl" in
      '' | '#'*) ;;
      '*'*) _rtab=${_rl#\*} ;;
      COMMIT) ;;
      :*) _rn=${_rl#:}; _rn=${_rn%% *}
          "$_rt" -t "$_rtab" -N "$_rn" 2>/dev/null || "$_rt" -t "$_rtab" -F "$_rn" 2>/dev/null || _rr=1 ;;
      *) _ipt_line "$_rt" "$_rtab" "$_rl" || _rr=1 ;;
    esac
  done
  unset _rb _rt _rtab _rl _rn
  return $_rr
}

# ── Lock ─────────────────────────────────────────────────────────────────────
# The watchdog and a ctl.sh command can rebuild at the same moment. The lock
# holds the owner's pid; a lock whose owner is gone is taken over.
vhs_lock() {
  mkdir -p "$STATE_DIR" 2>/dev/null
  _lw=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    _lp=""
    read -r _lp 2>/dev/null < "$LOCK_DIR/pid"
    if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
      rm -rf "$LOCK_DIR"; continue
    fi
    _lw=$((_lw + 1))
    if [ "$_lw" -ge 100 ]; then   # ~10 s: owner hung
      rm -rf "$LOCK_DIR"; continue
    fi
    sleep 0.1 2>/dev/null || sleep 1
  done
  echo "$$" > "$LOCK_DIR/pid"
  unset _lw _lp
}
vhs_unlock() { rm -rf "$LOCK_DIR" 2>/dev/null; }

# ── Detection ────────────────────────────────────────────────────────────────
# Table id of a name in netd's rt_tables (empty if unknown)
rt_id() { awk -v n="$1" '$2 == n { print $1; exit }' "$RT_TABLES" 2>/dev/null; }
rt_name() { awk -v n="$1" '$1 == n { print $2; exit }' "$RT_TABLES" 2>/dev/null; }

# Downstream interfaces of the running tethering (space-separated), from
# two sources so a new hotspot is seen as early as possible:
#   netd's tetherctrl_FORWARD (per downstream/upstream pair)
#     -A tetherctrl_FORWARD -i <down> -o <up> -g tetherctrl_counters
#   netd's tether routing rule
#     21000: from all iif <down> lookup <upstream>
# tether_ifaces [<filter dump> <ip rule dump>]  (fetched when not given)
tether_ifaces() {
  if [ "$#" -ge 2 ]; then _tf=$1; _tr=$2
  else _tf=$(ipt_dump 4 filter); _tr=$(ip rule 2>/dev/null); fi
  _tl=""
  for _ti in $({
      printf '%s\n' "$_tf" | sed -n -e '/^-A tetherctrl_FORWARD /!d' -e '/--state/d' \
        -e '/-[gj] tetherctrl_counters/s/.* -i \([A-Za-z0-9_.-]*\) .*/\1/p'
      printf '%s\n' "$_tr" | sed -n 's/^21000:.* iif \([A-Za-z0-9_.-]*\) .*/\1/p'
    } | sort -u); do
    [ -d "/sys/class/net/$_ti" ] || continue
    _tl="${_tl:+$_tl }$_ti"
  done
  echo "$_tl"
  unset _tf _tr _tl _ti
}

# IPv4 subnet of a tether interface, from Android's local_network table
tether_net() {
  _ln=$(rt_id local_network); [ -n "$_ln" ] || _ln=local_network
  ip -4 route show table "$_ln" dev "$1" 2>/dev/null | awk '$1 ~ /\// { print $1; exit }'
  unset _ln
}

# Interface flags say "up"
_if_up() {
  _fl=$(cat "/sys/class/net/$1/flags" 2>/dev/null) || return 1
  [ $((_fl & 1)) -eq 1 ]; _r=$?
  unset _fl
  return $_r
}

# The active VPN. Sets VPN_IF, VPN_TID, VPN_MTU (all empty when none).
# auto: Android's own VPN rules name it, for any VPN app:
#   13000: from all fwmark 0x0/0x20000 iif lo uidrange <A-B> lookup <vpn>
#   12000: from all iif <vpn> lookup local_network   (return path to LANs)
# A root WireGuard (kernel backend, via netd) covers "uidrange 0-99999";
# a VpnService app (v2rayNG, Proton, OpenVPN, ...) leaves its own uid out,
# so its range is split ("0-10233", "10235-99999") - any uidrange counts.
# Physical networks have uidrange rules too ("uidrange 0-0 lookup wlan0"),
# so a table only counts when netd also gave it the VPN return rule; when
# no such rule exists, a VPN-like name (tun*, wg*, ppp*, ipsec*, tap*) does.
# The VPN counts as ready when its interface is up and its table has routes
# through it; while it (re)connects clients are treated as "no VPN".
vpn_candidates() { # -> table names/ids, best first (no duplicates)
  _vr=$(ip rule 2>/dev/null)
  _vret=$(printf '%s\n' "$_vr" | sed -n 's/.* iif \([A-Za-z0-9_.-]*\) lookup local_network *$/\1/p' | grep -v '^lo$')
  _vall=$(printf '%s\n' "$_vr" | grep 'uidrange' | grep -v 'uidrange 0-0 ' | awk '{ print $NF }' | awk '!s[$0]++')
  for _vx in $_vall; do
    case "$_vx" in *[!0-9]*) _vxn=$_vx ;; *) _vxn=$(rt_name "$_vx") ;; esac
    if printf '%s\n' "$_vret" | grep -qx -- "$_vxn"; then echo "$_vx"; continue; fi
    case "$_vxn" in tun* | wg* | ppp* | ipsec* | tap*) echo "$_vx" ;; esac
  done
  unset _vr _vret _vall _vx _vxn
}

vpn_detect() {
  VPN_IF=""; VPN_TID=""; VPN_MTU=""; WGS_TUNNEL=""
  _vs=$(conf_get VPN_IFACE)
  # WG Shield first: in auto mode, or when its interface is chosen by hand
  if [ "$_vs" = auto ] || [ "$_vs" = wgs0 ]; then
    wgs_detect && { unset _vs; return 0; }
    [ "$_vs" = wgs0 ] && { unset _vs; return 1; }
  fi
  if [ "$_vs" = auto ]; then
    # Every VPN uid rule, in order: a stale one left by netd (its
    # interface gone) must not hide the VPN that is really up.
    _vc=$(vpn_candidates)
  else
    _vc=$_vs
  fi
  for _vt in $_vc; do
    case "$_vt" in
      *[!0-9]*) _vn=$_vt ;;
      *) _vn=$(rt_name "$_vt") ;;
    esac
    [ -n "$_vn" ] && [ -d "/sys/class/net/$_vn" ] && _if_up "$_vn" || continue
    _vid=$(rt_id "$_vn")
    [ -n "$_vid" ] || _vid=$_vn
    # Routed at all: WireGuard puts "default", v2rayNG / OpenVPN often cover
    # the internet with smaller blocks (0.0.0.0/1 + 128.0.0.0/1, or many
    # blocks leaving private ranges out for "bypass LAN")
    ip route show table "$_vid" 2>/dev/null | grep -qE "^(default|[0-9.]+/[0-9]+) .*dev $_vn( |\$)" || continue
    VPN_IF=$_vn; VPN_TID=$_vid
    VPN_MTU=$(cat "/sys/class/net/$_vn/mtu" 2>/dev/null)
    case "$VPN_MTU" in '' | *[!0-9]*) VPN_MTU=1420 ;; esac
    unset _vs _vc _vt _vn _vid
    return 0
  done
  unset _vs _vc _vt _vn _vid
  return 1
}

# WG Shield Arm64 (kernel WireGuard module of the same set) routes the phone
# with its own policy rules: Android knows no VPN, so none of the rules
# above name it. It publishes its tunnel in a status file (contract, stable):
#   state=up|handshaking|down|paused|off|error  iface=wgs0  table=51820
#   tunnel=<name>  endpoint=<ip:port>  ...
# Used only while it says "up" and its interface and table really route; in
# every other state it counts as no VPN (clients: kill switch). While a VPN
# app is connected WG Shield pauses itself, so Android's VPN is found instead.
WGS_MODDIR="${VHS_WGS_MODDIR:-/data/adb/modules/wg-shield}"
WGS_STATUS="${VHS_WGS_STATUS:-/data/adb/wg-shield-state/status}"
WGS_TUNNEL=""
wgs_detect() {
  WGS_TUNNEL=""
  [ -f "$WGS_MODDIR/module.prop" ] && [ ! -f "$WGS_MODDIR/disable" ] && [ ! -f "$WGS_MODDIR/remove" ] || return 1
  _ws=""; _wi=""; _wt=""; _wn=""
  while IFS='=' read -r _k _v; do
    case "$_k" in state) _ws=$_v ;; iface) _wi=$_v ;; table) _wt=$_v ;; tunnel) _wn=$_v ;; esac
  done 2>/dev/null < "$WGS_STATUS"
  _wr=1
  if [ "$_ws" = up ] && [ -n "$_wi" ] && [ -n "$_wt" ] && [ -d "/sys/class/net/$_wi" ] && _if_up "$_wi" &&
     ip route show table "$_wt" 2>/dev/null | grep -qE "^default .*dev $_wi( |\$)"; then
    VPN_IF=$_wi; VPN_TID=$_wt; WGS_TUNNEL=${_wn:-WG Shield}
    VPN_MTU=$(cat "/sys/class/net/$_wi/mtu" 2>/dev/null)
    case "$VPN_MTU" in '' | *[!0-9]*) VPN_MTU=1420 ;; esac
    _wr=0
  fi
  unset _ws _wi _wt _wn _k _v
  return $_wr
}

# The user turned WG Shield off or paused it (not a failure): the phone goes
# direct, and so do the clients - but only when WG Shield was the VPN the
# clients used last. A VPN app that drops is never taken as "off by the user".
# Sets WGS_DIRECT (off | paused) when it applies.
WGS_DIRECT=""
wgs_direct() {
  WGS_DIRECT=""
  [ -f "$WGS_MODDIR/module.prop" ] && [ ! -f "$WGS_MODDIR/disable" ] && [ ! -f "$WGS_MODDIR/remove" ] || return 1
  _ls=""; read -r _ls 2>/dev/null < "$LAST_SRC_FILE"
  [ "$_ls" = wg-shield ] || { unset _ls; return 1; }
  _ws=""; _wr=""
  while IFS='=' read -r _k _v; do
    case "$_k" in state) _ws=$_v ;; reason) _wr=$_v ;; esac
  done 2>/dev/null < "$WGS_STATUS"
  case "$_ws" in
    off) WGS_DIRECT=off ;;
    paused) [ "$_wr" = user ] && WGS_DIRECT=paused ;;
  esac
  unset _ls _ws _wr _k _v
  [ -n "$WGS_DIRECT" ]
}

# ── Tunnel health ────────────────────────────────────────────────────────────
_tun_probe() { # <iface>: any answer through the tunnel
  for _pt in 1.1.1.1 9.9.9.9; do
    ping -c 1 -W 2 -I "$1" "$_pt" >/dev/null 2>&1 && { unset _pt; return 0; }
  done
  unset _pt
  return 1
}

# tunnel_health <iface> -> sets VPN_HEALTH (ok | dead). Only the watchdog
# updates the record (VHS_HEALTH_UPDATE=1) - everything else just reads it,
# so a status query never pings.
tunnel_health() {
  VPN_HEALTH=ok
  [ "$(conf_get TUNNEL_CHECK)" = 1 ] || { rm -f "$TUNNEL_FILE"; return 0; }
  _hi=""; _hr=""; _ht=""; _hs=""; _hh=""
  read -r _hi _hr _ht _hs _hh 2>/dev/null < "$TUNNEL_FILE"
  if [ "$VHS_HEALTH_UPDATE" != 1 ]; then
    [ "$_hi" = "$1" ] && [ -n "$_hh" ] && VPN_HEALTH=$_hh
    unset _hi _hr _ht _hs _hh; return 0
  fi
  _rx=$(cat "/sys/class/net/$1/statistics/rx_bytes" 2>/dev/null)
  _tx=$(cat "/sys/class/net/$1/statistics/tx_bytes" 2>/dev/null)
  _now=$(date +%s)
  if [ "$_hi" != "$1" ] || [ -z "$_hs" ]; then _hr=$_rx; _ht=$_tx; _hs=$_now; _hh=ok; fi
  if [ "$_rx" != "$_hr" ]; then
    _hs=$_now; VPN_HEALTH=ok                    # received something: alive
    [ "$_hh" = dead ] && log_info "tunnel $1 answers again"
  elif [ "$_hh" = dead ] || { [ "$_tx" != "$_ht" ] && [ $((_now - _hs)) -ge "$TUNNEL_SILENT" ]; }; then
    if _tun_probe "$1"; then
      VPN_HEALTH=ok; _hs=$_now
      _rx=$(cat "/sys/class/net/$1/statistics/rx_bytes" 2>/dev/null)
      [ "$_hh" = dead ] && log_info "tunnel $1 answers again"
    else
      VPN_HEALTH=dead
      [ "$_hh" = dead ] || log_warn "tunnel $1 not responding (sending, nothing received for $((_now - _hs))s, probe failed)"
    fi
  else
    VPN_HEALTH=$_hh
  fi
  echo "$1 $_rx $_tx $_hs $VPN_HEALTH" > "$TUNNEL_FILE" 2>/dev/null
  unset _hi _hr _ht _hs _hh _rx _tx _now
}

# Some local resolver already takes the phone's own DNS (dnscrypt-proxy or
# similar: nat OUTPUT DNATs :53 to loopback). Then the clients' DNS, which
# Android's dnsmasq forwards from the phone itself, is already handled and
# travels through the VPN with the resolver.
local_dns_active() { # [nat dump]
  if [ "$#" -ge 1 ]; then printf '%s\n' "$1"; else ipt_dump 4 nat; fi |
    grep -qE -- '^-A OUTPUT .*--dport 53 .*-j DNAT --to-destination 127\.'
}

# ── Siblings (same set) ──────────────────────────────────────────────────────
# Module ids: dnscrypt-proxy-android, ipset_arm64 (repo name ipset-arm64).
sibling_state() { # <module-id> [other id] -> absent | disabled | enabled
  _sd="/data/adb/modules/$1"
  [ ! -f "$_sd/module.prop" ] && [ -n "$2" ] && _sd="/data/adb/modules/$2"
  if [ ! -f "$_sd/module.prop" ]; then echo absent
  elif [ -f "$_sd/disable" ] || [ -f "$_sd/remove" ]; then echo disabled
  else echo enabled; fi
  unset _sd
}

# ── Watchdog helpers ─────────────────────────────────────────────────────────
wd_pid() {
  _wp=""
  read -r _wp 2>/dev/null < "$WD_PIDFILE"
  [ -n "$_wp" ] && kill -0 "$_wp" 2>/dev/null && echo "$_wp"
  unset _wp
}
wake_watchdog() { _p=$(wd_pid); [ -n "$_p" ] && kill -USR1 "$_p" 2>/dev/null; unset _p; }
# A settings change: the watchdog applies it at once (no settle wait).
# Returns 1 when no watchdog runs - the caller applies it itself.
apply_now() { _p=$(wd_pid); [ -n "$_p" ] && kill -USR2 "$_p" 2>/dev/null; _r=$?; unset _p; return $_r; }

# ── Module status line (description in the root manager) ─────────────────────
DESC_BASE="Routes hotspot and tethering clients through the phone's VPN, with kill switch."
set_description() { # <status text>
  [ -f "$MODPROP" ] || return 0
  sed -i "s|^description=.*|description=$DESC_BASE Status: $1|" "$MODPROP" 2>/dev/null
}
