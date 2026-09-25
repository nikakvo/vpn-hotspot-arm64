#!/system/bin/sh
# service.sh - the watchdog.
#
# Keeps the routing/firewall in line with reality: hotspot on/off, subnet
# changes, VPN up/down/reconnect (new routing table), server switch (new
# interface name), MTU changes, netd reordering or flushing FORWARD, the
# sibling modules pausing. Settings are read fresh on every pass.
#
# Reaction: "ip monitor" (link, address and rule events) wakes the loop at
# once. A new hotspot is blocked immediately (kill switch); the full pass
# runs when the burst of events has settled (~2-3 s after a VPN reconnect).
# The TICK is the safety net for what produces no netlink event (iptables
# changes by netd or other modules).

MODDIR=${0%/*}
. "$MODDIR/sh/common.sh"
. "$MODDIR/sh/rules.sh"
VHS_HEALTH_UPDATE=1   # only the watchdog measures the tunnel

until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done

mkdir -p "$STATE_DIR"
conf_init
log_trim

# One watchdog only
_old=$(wd_pid)
if [ -n "$_old" ] && [ "$_old" != "$$" ]; then
  log_warn "watchdog already running (pid $_old) - not starting another"
  exit 0
fi
echo "$$" > "$WD_PIDFILE"
log_info "watchdog started (pid $$, tick ${TICK}s)"

WAKE=0
trap 'WAKE=1' USR1
trap 'NOW=1' USR2   # settings changed: pass at once
NOW=0
trap '_wd_exit' TERM INT HUP

_mon_stop() {
  _mp=""
  read -r _mp 2>/dev/null < "$MON_PIDFILE"
  # shellcheck disable=SC2086
  [ -n "$_mp" ] && kill $_mp 2>/dev/null
  rm -f "$MON_PIDFILE" "$MON_FIFO"
  unset _mp
}

_mon_alive() {
  _mp=""
  read -r _mp 2>/dev/null < "$MON_PIDFILE"
  [ -n "$_mp" ] || { unset _mp; return 1; }
  for _p in $_mp; do kill -0 "$_p" 2>/dev/null || { unset _mp _p; return 1; }; done
  unset _mp _p
  return 0
}

# ip monitor -> fifo -> reader that pokes the watchdog. Both pids are kept
# so they can be stopped cleanly (a pipeline in a subshell would leave
# "ip monitor" orphaned).
_mon_start() {
  _mon_stop
  [ -n "$IP_BIN" ] || return 1
  rm -f "$MON_FIFO"
  mkfifo "$MON_FIFO" 2>/dev/null || return 1
  "$IP_BIN" monitor link address rule > "$MON_FIFO" 2>/dev/null &
  _m1=$!
  _wd=$$
  ( while read -r _l; do kill -USR1 "$_wd" 2>/dev/null || exit 0; done < "$MON_FIFO" ) &
  _m2=$!
  echo "$_m1 $_m2" > "$MON_PIDFILE"
  unset _m1 _m2 _wd
  sleep 0.2 2>/dev/null
  _mon_alive
}

_wd_exit() {
  _mon_stop
  rm -f "$WD_PIDFILE"
  log_info "watchdog stopped"
  exit 0
}

if _mon_start; then
  log_info "network events: on (ip monitor)"
else
  log_warn "network events unavailable - tick only (${TICK}s)"
fi

# After an event: block any new tether interface at once (ip rule only),
# then wait until the burst is over (SETTLE s without events, at most
# SETTLE_MAX) before the full pass touches iptables. netd is busy exactly
# then - a VPN coming up or going down, a hotspot starting - and must not
# have to wait for our xtables lock.
_ev_win=0; _ev_n=0
_count_event() {
  _now=$(date +%s)
  if [ $((_now - _ev_win)) -ge 60 ]; then _ev_win=$_now; _ev_n=0; fi
  _ev_n=$((_ev_n + 1))
  echo "$_ev_win $_ev_n" > "$STATE_DIR/events"
  unset _now
}

_settle() {
  _s0=$(date +%s)
  while :; do
    _count_event
    vhs_quick_guard
    WAKE=0
    sleep "$SETTLE" &
    _sp=$!
    wait "$_sp" 2>/dev/null
    kill "$_sp" 2>/dev/null
    [ "$NOW" = 1 ] && break
    [ "$WAKE" = 1 ] || break
    [ $(( $(date +%s) - _s0 )) -ge "$SETTLE_MAX" ] && break
  done
  WAKE=0
  unset _s0 _sp
}

while :; do
  WAKE=0; NOW=0
  vhs_sync
  _src=$?
  date +%s > "$TICK_FILE"
  _mon_alive || _mon_start >/dev/null 2>&1
  [ "$NOW" = 1 ] && continue
  if [ "$WAKE" = 1 ] || [ "$_src" = 2 ]; then
    _settle
    continue
  fi
  sleep "$TICK" &
  _sp=$!
  wait "$_sp" 2>/dev/null
  kill "$_sp" 2>/dev/null
  [ "$NOW" = 1 ] && continue
  [ "$WAKE" = 1 ] && _settle
done
