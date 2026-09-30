#!/system/bin/sh
# ctl.sh - the single command-line interface. The WebUI calls only this.
# Output is KEY=value lines (ok=1 / ok=0 + error=...) unless noted.

MODDIR=${0%/*}
. "$MODDIR/sh/common.sh"
. "$MODDIR/sh/rules.sh"

_yn() { if "$@" >/dev/null 2>&1; then echo 1; else echo 0; fi; }

cmd_status() {
  [ -f "$STATUS_FILE" ] || vhs_sync
  cat "$STATUS_FILE" 2>/dev/null
  echo "enabled=$(conf_get ENABLED)"
  echo "vpn_iface_setting=$(conf_get VPN_IFACE)"
  echo "fallback_dns_setting=$(conf_get FALLBACK_DNS)"
  _since=""; read -r _since _ss 2>/dev/null < "$STATE_DIR/since"
  echo "since=${_since}"
  # watchdog
  _wp=$(wd_pid)
  echo "watchdog=$([ -n "$_wp" ] && echo running || echo stopped)"
  _tk=""; read -r _tk 2>/dev/null < "$TICK_FILE"
  if [ -n "$_tk" ]; then echo "tick_age=$(( $(date +%s) - _tk ))"; else echo "tick_age="; fi
  _mp=""; read -r _mp 2>/dev/null < "$MON_PIDFILE"
  _ma=0
  if [ -n "$_mp" ]; then _ma=1; for _p in $_mp; do kill -0 "$_p" 2>/dev/null || _ma=0; done; fi
  echo "events=$([ "$_ma" = 1 ] && echo on || echo off)"
  _ew=""; _en=""; read -r _ew _en 2>/dev/null < "$STATE_DIR/events"
  if [ -n "$_ew" ] && [ $(( $(date +%s) - _ew )) -lt 60 ]; then echo "events_per_min=$_en"; else echo "events_per_min=0"; fi
  # rules (fresh check against the tables, not the cached state)
  vhs_snap; vhs_plan >/dev/null 2>&1; _expect
  _v=$(vhs_verify)
  if [ -n "$_v" ]; then echo "rules=repairing"; echo "rules_problem=$_v"
  elif [ "$E_FWD" -gt 0 ]; then echo "rules=ok"
  else echo "rules=none"; fi
  if [ "$E_FWD" -gt 0 ]; then echo "forward_position=$(_fwd_state "$S_F" "$C_FWD")"; else echo "forward_position=-"; fi
  # siblings
  echo "dnscrypt=$(sibling_state dnscrypt-proxy-android)"
  echo "dnscrypt_hotspot=$([ "$(_jcount "$S_F" FORWARD DNSC_HS_FWD)" -gt 0 ] && echo 1 || echo 0)"
  echo "local_dns=$(_yn local_dns_active "$S_N")"
  echo "ipset=$(sibling_state ipset_arm64 ipset-arm64)"
  echo "wgshield=$(sibling_state wg-shield)"
  echo "ipset_forward=$([ "$(_jcount "$S_F" FORWARD IPSA_FWD)" -gt 0 ] && echo 1 || echo 0)"
  echo "clients=$(vhs_clients | grep -c .)"
  echo "ok=1"
  unset _since _ss _wp _tk _mp _ma _p _ew _en _v
}

# Cheap snapshot for the WebUI, polled every few seconds: files only (the
# watchdog's last pass + settings + clients). No iptables call, so the
# page never competes with netd for the xtables lock.
cmd_poll() {
  cat "$STATUS_FILE" 2>/dev/null
  for _k in $SETTINGS_KEYS; do echo "set_$_k=$(conf_get "$_k")"; done
  echo "version=$(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null)"
  _since=""; read -r _since _ss 2>/dev/null < "$STATE_DIR/since"
  echo "since=${_since}"
  echo "now=$(date +%s)"
  _wp=$(wd_pid)
  echo "watchdog=$([ -n "$_wp" ] && echo running || echo stopped)"
  _tk=""; read -r _tk 2>/dev/null < "$TICK_FILE"
  if [ -n "$_tk" ]; then echo "tick_age=$(( $(date +%s) - _tk ))"; else echo "tick_age="; fi
  _mp=""; read -r _mp 2>/dev/null < "$MON_PIDFILE"
  _ma=0
  if [ -n "$_mp" ]; then _ma=1; for _p in $_mp; do kill -0 "$_p" 2>/dev/null || _ma=0; done; fi
  echo "events=$([ "$_ma" = 1 ] && echo on || echo off)"
  echo "dnscrypt=$(sibling_state dnscrypt-proxy-android)"
  echo "ipset=$(sibling_state ipset_arm64 ipset-arm64)"
  echo "wgshield=$(sibling_state wg-shield)"
  echo "wgshield_state=$(sed -n 's/^state=//p' "$WGS_STATUS" 2>/dev/null | head -n 1)"
  _ti=""
  for _e in $(sed -n 's/^tethers=//p' "$STATUS_FILE" 2>/dev/null); do _ti="$_ti ${_e%%=*}"; done
  # shellcheck disable=SC2086
  [ -n "$_ti" ] && vhs_clients $_ti | while read -r _ci _cip _cm _cs; do echo "client=$_ci $_cip $_cm $_cs"; done
  echo "ok=1"
  unset _k _since _ss _wp _tk _mp _ma _p _e _ti
}

# Public exit address of the phone's traffic, one request on demand. The
# phone's own traffic (root included) goes through the VPN like the
# clients', so this is the clients' exit too. Plain HTTP on purpose: no
# TLS tool is guaranteed on Android; the answer is not sensitive.
_http_get() { # <host> <path>
  if command -v curl >/dev/null 2>&1; then
    curl -s -m 8 "http://$1$2" 2>/dev/null && return 0
  fi
  for _bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
    [ -x "$_bb" ] || continue
    "$_bb" wget -q -T 8 -O - "http://$1$2" 2>/dev/null && { unset _bb; return 0; }
  done
  unset _bb
  if command -v nc >/dev/null 2>&1; then
    printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: vpn-hotspot\r\nConnection: close\r\n\r\n' "$2" "$1" |
      timeout 10 nc "$1" 80 2>/dev/null   # headers stay: the fields are searched by name
    return 0
  fi
  return 1
}

_json_str() { # <json> <key>
  printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" | head -n 1
}

cmd_exitip() {
  # which way the phone's own traffic goes right now (not the cached status)
  _via=""; vpn_detect && _via=$VPN_IF
  _j=$(_http_get ip-api.com '/json/?fields=status,country,countryCode,city,isp,query')
  _ip=$(_json_str "$_j" query)
  if [ -n "$_ip" ]; then
    echo "ip=$_ip"; echo "country=$(_json_str "$_j" country)"; echo "cc=$(_json_str "$_j" countryCode)"
    echo "city=$(_json_str "$_j" city)"; echo "isp=$(_json_str "$_j" isp)"
  else
    _j=$(_http_get ipinfo.io /json)
    _ip=$(_json_str "$_j" ip)
    [ -n "$_ip" ] || { echo "ok=0"; echo "error=no answer from ip-api.com or ipinfo.io"; unset _via _j _ip; return 1; }
    echo "ip=$_ip"; echo "country=$(_json_str "$_j" country)"; echo "cc=$(_json_str "$_j" country)"
    echo "city=$(_json_str "$_j" city)"; echo "isp=$(_json_str "$_j" org)"
  fi
  echo "via=$_via"
  echo "ok=1"
  unset _via _j _ip
}

cmd_set() { # <KEY> <value>
  case " $SETTINGS_KEYS " in *" $1 "*) ;; *) echo "ok=0"; echo "error=unknown setting: $1"; return 1 ;; esac
  if ! conf_valid "$1" "$2"; then echo "ok=0"; echo "error=invalid value for $1: $2"; return 1; fi
  _old=$(conf_get "$1")
  conf_set "$1" "$2" || { echo "ok=0"; echo "error=cannot write $CONF"; return 1; }
  [ "$_old" != "$2" ] && log_info "setting $1: $_old -> $2"
  # Returns at once: the watchdog applies it within a moment, so the WebUI
  # never waits for a rebuild (or for the xtables lock behind it).
  if apply_now; then echo "applied=watchdog"
  else vhs_sync; echo "applied=now"; echo "state=$P_STATE"; fi
  echo "$1=$2"
  echo "ok=1"
  unset _old
}

cmd_clients() {
  # iface ip mac state
  vhs_clients
}

cmd_diag() { # everything needed for a bug report, plain text
  echo "== status"; cmd_status
  echo "== settings"; cat "$CONF" 2>/dev/null
  echo "== ip rule"; ip rule 2>&1
  echo "== FORWARD"; iptables -S FORWARD 2>&1
  echo "== $C_FWD"; iptables -L "$C_FWD" -v -n 2>&1
  echo "== nat POSTROUTING"; iptables -t nat -S POSTROUTING 2>&1
  echo "== $C_POST"; iptables -t nat -L "$C_POST" -v -n 2>&1
  echo "== nat PREROUTING"; iptables -t nat -S PREROUTING 2>&1
  echo "== $C_PRE"; iptables -t nat -L "$C_PRE" -v -n 2>&1
  echo "== $C_MSS"; iptables -t mangle -L "$C_MSS" -v -n 2>&1
  echo "== ip6 FORWARD"; ip6tables -S FORWARD 2>&1
  echo "== $C_FWD6"; ip6tables -L "$C_FWD6" -v -n 2>&1
  echo "== tetherctrl_FORWARD"; iptables -L tetherctrl_FORWARD -v -n 2>&1
  echo "== clients"; vhs_clients
  for _e in $P_TETHERS; do
    _c=$(ip neigh show dev "${_e%%=*}" 2>/dev/null | awk '$1 !~ /:/ { print $1; exit }')
    [ -n "$_c" ] && { echo "== route for client $_c"; ip route get 1.1.1.1 from "$_c" iif "${_e%%=*}" 2>&1; }
  done
  echo "== bpf offload"
  dumpsys tethering 2>/dev/null | grep -E -A4 'mCurrentConnectionCount|IPv4 Upstream Information' | head -16
  echo "== hotspot radio"
  for _e in $P_TETHERS; do command -v iw >/dev/null 2>&1 && iw dev "${_e%%=*}" info 2>&1 | grep -E 'channel|type'; done
  echo "== log"; tail -n 60 "$LOG" 2>/dev/null
  unset _e _c
}

cmd_help() {
  cat <<'EOF'
VPN Hotspot - ctl.sh
  status              state, VPN, tethering, rules, watchdog, siblings
  exitip              public exit address (one HTTP request through the VPN)
  set KEY VALUE       change a setting (applied at once)
      ENABLED 0|1
      KILL_SWITCH 0|1     1 = no VPN -> clients have no internet
      VPN_IFACE auto|<iface>
      FALLBACK_DNS <ipv4> client DNS via the tunnel when no local resolver
  clients             connected clients: iface ip mac state
  sync                re-check now; "sync force" rebuilds everything
  log [N]             last N log lines (default 50)
  log clear           empty the log
  diag                full report for troubleshooting
EOF
}

case "$1" in
  status) cmd_status ;;
  poll) cmd_poll ;;
  exitip) cmd_exitip ;;
  set) shift; cmd_set "$1" "$2" ;;
  clients) cmd_clients ;;
  sync)
    if [ "$2" = force ]; then vhs_sync 1; else vhs_sync; fi
    cat "$STATUS_FILE" 2>/dev/null; echo "ok=1" ;;
  log)
    case "$2" in
      clear)
        if log_clear 2>/dev/null; then echo "ok=1"; else echo "ok=0"; echo "error=cannot write $LOG"; exit 1; fi ;;
      *) tail -n "${2:-50}" "$LOG" 2>/dev/null ;;
    esac ;;
  diag) vhs_snap; vhs_plan >/dev/null 2>&1; cmd_diag ;;
  help | -h | --help | "") cmd_help ;;
  *) echo "ok=0"; echo "error=unknown command: $1"; exit 2 ;;
esac
