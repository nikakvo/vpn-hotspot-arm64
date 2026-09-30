#!/system/bin/sh
# uninstall.sh - remove every rule, stop the watchdog, delete data.
MODDIR=${0%/*}
if [ -f "$MODDIR/sh/common.sh" ] && [ -f "$MODDIR/sh/rules.sh" ]; then
  . "$MODDIR/sh/common.sh"
  . "$MODDIR/sh/rules.sh"
  # Stop the watchdog first and wait for it: a pass in progress would put
  # the rules straight back (its TERM trap runs only after the pass).
  _p=$(wd_pid)
  if [ -n "$_p" ]; then
    kill "$_p" 2>/dev/null
    _w=0
    while kill -0 "$_p" 2>/dev/null && [ "$_w" -lt 50 ]; do sleep 0.1 2>/dev/null || sleep 1; _w=$((_w + 1)); done
    kill -9 "$_p" 2>/dev/null
  fi
  _m=""; read -r _m 2>/dev/null < "$MON_PIDFILE"
  # shellcheck disable=SC2086
  [ -n "$_m" ] && kill $_m 2>/dev/null
  vhs_lock
  vhs_teardown
  vhs_unlock
else
  # Library missing: remove by name / priority with the plain tools
  for _pr in 20350 20400 20500 20600; do
    _n=0; while ip rule del pref "$_pr" 2>/dev/null; do _n=$((_n + 1)); [ "$_n" -ge 64 ] && break; done
  done
  for _s in "filter FORWARD VHS_FWD" "nat POSTROUTING VHS_POST" "mangle FORWARD VHS_MSS" "nat PREROUTING VHS_PRE"; do
    set -- $_s
    while iptables -w -t "$1" -D "$2" -j "$3" 2>/dev/null; do :; done
    iptables -w -t "$1" -F "$3" 2>/dev/null; iptables -w -t "$1" -X "$3" 2>/dev/null
  done
  while ip6tables -w -D FORWARD -j VHS_FWD6 2>/dev/null; do :; done
  ip6tables -w -F VHS_FWD6 2>/dev/null; ip6tables -w -X VHS_FWD6 2>/dev/null
fi
rm -rf /data/adb/vpn-hotspot-state
rm -f /data/adb/vpn-hotspot.conf /data/adb/vpn-hotspot.conf.tmp
rm -f /data/adb/vpn-hotspot.log /data/adb/vpn-hotspot.log.tmp
rm -f /data/adb/vpn-hotspot-last-source
