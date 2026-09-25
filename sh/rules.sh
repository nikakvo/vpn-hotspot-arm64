#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/rules.sh - routing and firewall for tethering clients. Needs common.sh.
#
# Why this is needed: Android's VPN covers apps on the phone only (uid
# rules). Tethered traffic is routed by one rule per downstream straight to
# the upstream network, around the VPN:
#     21000: from all iif wlan2 lookup wlan0        (or rmnet_dataN)
#
# What this adds, per tethered interface T (subnet NET), VPN interface V
# (routing table TID) - measured and tested on the phone in Stage 0:
#   ip rule 20400  iif T to NET lookup local_network
#   ip rule 20500  iif T lookup TID              everything else -> VPN
#   ip rule 20600  iif T unreachable             kill switch
#   nat    POSTROUTING -> VHS_POST   -s NET -o V MASQUERADE
#   filter FORWARD     -> VHS_FWD    T -> V accept, V -> T established,
#                                    anything else from/to T rejected
#   mangle FORWARD     -> VHS_MSS    TCP MSS = MTU(V) - 40
#   filter FORWARD v6  -> VHS_FWD6   clients' IPv6 not forwarded (no leak
#                                    around an IPv4-only tunnel)
#   nat    PREROUTING  -> VHS_PRE    client DNS -> FALLBACK_DNS via the
#                                    tunnel, only while no local resolver
#                                    (dnscrypt-proxy) takes the phone's DNS
#
# FORWARD order contract with the sibling modules: VHS_FWD ACCEPTs, so its
# jump must stay BELOW DNSC_HS_FWD (dnscrypt-proxy) and IPSA_FWD
# (ipset-arm64), or clients would bypass both. It sits directly above
# tetherctrl_FORWARD (netd's, ends in DROP) and is re-checked every tick.
#
# Offload: Android's BPF tether offload only takes flows NATed to an
# upstream address. Ours are NATed to the VPN address; on the phone the BPF
# flow table stayed empty with 100+ MB through the tunnel (Wi-Fi and mobile
# uplink). Offload settings are therefore left alone.
#
# States:
#   disabled     ENABLED=0 - nothing installed
#   idle         no tethering - nothing installed
#   vpn          clients go through the VPN
#   blocked      no VPN, kill switch on - clients have no internet
#   passthrough  no VPN, kill switch off - Android's normal tethering
#
# A rebuild never opens a leak window: while the rules are replaced for a
# state that must not reach the plain uplink (vpn, blocked), a guard rule
# (20350 iif T unreachable) blocks the clients and is removed last.
#
# Living next to netd (1.0-r2): the tables are read with one call per
# table, all firewall changes of a rebuild go in one iptables-restore call
# per family, and the watchdog lets a burst of network events settle
# before it touches anything. A hotspot that appears in the meantime is
# blocked at once with the guard rule (ip rule only, no xtables lock).

# ── Snapshot: every table read once, without the xtables lock ───────────────
vhs_snap() {
  S_F=$(ipt_dump 4 filter)
  S_N=$(ipt_dump 4 nat)
  S_M=$(ipt_dump 4 mangle)
  if S_F6=$(ipt_dump 6 filter) && [ -n "$S_F6" ]; then S_V6=1; else S_V6=0; S_F6=""; fi
  S_IR=$(ip rule 2>/dev/null)
}

# ── Plan: what should be installed now ───────────────────────────────────────
# Needs vhs_snap. Sets P_STATE P_SIG P_KS P_DNS P_FB, VPN_*, and
# P_TETHERS = "T=NET ..." (NET "-" while Android has not configured it yet).
vhs_plan() {
  P_STATE=""; P_TETHERS=""; P_DNS=none; P_FB=""; P_TUN=""
  P_KS=$(conf_get KILL_SWITCH)
  VPN_IF=""; VPN_TID=""; VPN_MTU=""
  if [ "$(conf_get ENABLED)" != 1 ]; then
    P_STATE=disabled; P_SIG="disabled"; return 0
  fi
  for _pt in $(tether_ifaces "$S_F" "$S_IR"); do
    _pn=$(tether_net "$_pt")
    P_TETHERS="${P_TETHERS:+$P_TETHERS }$_pt=${_pn:--}"
  done
  unset _pt _pn
  if [ -z "$P_TETHERS" ]; then
    # nothing to route; still report a connected VPN (status/WebUI only -
    # not part of the signature, so a VPN change alone rebuilds nothing)
    vpn_detect
    P_STATE=idle; P_SIG="idle"; return 0
  fi
  P_TUN=""
  if vpn_detect; then
    tunnel_health "$VPN_IF"
    P_TUN=$VPN_HEALTH
  fi
  if [ -n "$VPN_IF" ] && [ "$P_TUN" = ok ]; then
    P_STATE=vpn
    if local_dns_active "$S_N"; then P_DNS=local; else P_DNS=fallback; P_FB=$(conf_get FALLBACK_DNS); fi
  elif [ "$P_KS" = 1 ]; then
    P_STATE=blocked
  else
    P_STATE=passthrough
  fi
  P_SIG="state=$P_STATE ks=$P_KS vpn=$VPN_IF table=$VPN_TID mtu=$VPN_MTU tunnel=$P_TUN dns=$P_DNS fb=$P_FB tethers=$P_TETHERS"
}

# What one tether interface gets: route (through the VPN), block (kill
# switch) or none (Android's normal tethering).
_t_mode() { # <net>
  if [ "$P_STATE" = vpn ] && [ "$1" != - ]; then echo route
  elif [ "$P_KS" = 1 ] && { [ "$P_STATE" = vpn ] || [ "$P_STATE" = blocked ]; }; then echo block
  else echo none; fi
}

# Expected sizes of everything, from the plan
_expect() {
  E_R=0; E_B=0
  for _e in $P_TETHERS; do
    case "$(_t_mode "${_e#*=}")" in route) E_R=$((E_R + 1)) ;; block) E_B=$((E_B + 1)) ;; esac
  done
  E_FWD=$((E_R * 6 + E_B * 2)); E_FWD6=$(( (E_R + E_B) * 2 ))
  E_POST=$E_R; E_PRE=0; [ "$P_DNS" = fallback ] && E_PRE=$((E_R * 2))
  E_MSS=0; [ "$E_R" -gt 0 ] && E_MSS=2
  E_KILL=$E_B; [ "$P_KS" = 1 ] && E_KILL=$((E_KILL + E_R))
  unset _e
}

# ── Text helpers (on the snapshot) ───────────────────────────────────────────
_scount() { # <dump> <chain> -> number of rules, -1 if the chain is absent
  printf '%s\n' "$1" | awk -v c="$2" '$1 == "-N" && $2 == c { e = 1 } $1 == "-A" && $2 == c { n++ } END { print (e ? n + 0 : -1) }'
}
_jcount() { # <dump> <parent> <chain>
  printf '%s\n' "$1" | awk -v j="-A $2 -j $3" '$0 == j { n++ } END { print n + 0 }'
}
_rcount() { printf '%s\n' "$S_IR" | grep -c "^$1:"; }

# FORWARD placement: one jump, below every sibling jump, above
# tetherctrl_FORWARD. Prints ok / missing / duplicate / above-sibling /
# below-tetherctrl.
_fwd_state() { # <filter dump> <chain>
  printf '%s\n' "$1" | awk -v me="$2" '
    /^-A FORWARD / {
      n++
      if ($0 == "-A FORWARD -j " me) { c++; pos = n }
      if ($0 == "-A FORWARD -j DNSC_HS_FWD" || $0 == "-A FORWARD -j IPSA_FWD") sib = n
      if ($0 == "-A FORWARD -j tetherctrl_FORWARD" && !tp) tp = n
    }
    END {
      if (c == 0) { print "missing"; exit }
      if (c > 1) { print "duplicate"; exit }
      if (sib && pos < sib) { print "above-sibling"; exit }
      if (tp && pos > tp) { print "below-tetherctrl"; exit }
      print "ok"
    }'
}

# Position for our jump once our old jumps are gone: tetherctrl's place
_fwd_pos() { # <filter dump> <chain>
  printf '%s\n' "$1" | awk -v me="$2" '
    /^-A FORWARD / { if ($0 == "-A FORWARD -j " me) next; n++
      if ($0 == "-A FORWARD -j tetherctrl_FORWARD") { print n; exit } }'
}

# ── Verify: does the system match the plan? ──────────────────────────────────
# Prints nothing when it does, else a short reason (for the log). Uses the
# snapshot: no extra table reads.
vhs_verify() {
  _why=""
  _add() { _why="${_why:+$_why, }$1"; }
  [ "$(_rcount "$PREF_GUARD")" = 0 ] || _add "guard left"
  [ "$(_rcount "$PREF_LOCAL")" = "$E_R" ] || _add "ip rule $PREF_LOCAL"
  [ "$(_rcount "$PREF_VPN")" = "$E_R" ] || _add "ip rule $PREF_VPN"
  [ "$(_rcount "$PREF_KILL")" = "$E_KILL" ] || _add "ip rule $PREF_KILL"
  _vchain "$S_F" FORWARD "$C_FWD" "$E_FWD" || _add "$C_FWD"
  if [ "$E_FWD" -gt 0 ]; then
    _pl=$(_fwd_state "$S_F" "$C_FWD"); [ "$_pl" = ok ] || _add "FORWARD jump $_pl"
  fi
  _vchain "$S_N" POSTROUTING "$C_POST" "$E_POST" || _add "$C_POST"
  _vchain "$S_N" PREROUTING "$C_PRE" "$E_PRE" || _add "$C_PRE"
  _vchain "$S_M" FORWARD "$C_MSS" "$E_MSS" || _add "$C_MSS"
  if [ "$S_V6" = 1 ]; then
    _vchain "$S_F6" FORWARD "$C_FWD6" "$E_FWD6" || _add "$C_FWD6"
    if [ "$E_FWD6" -gt 0 ]; then
      _pl=$(_fwd_state "$S_F6" "$C_FWD6"); [ "$_pl" = ok ] || _add "FORWARD6 jump $_pl"
    fi
  fi
  echo "$_why"
  unset _why _pl
}

_vchain() { # <dump> <parent> <chain> <expected rules>: chain+jump as expected
  _vc=$(_scount "$1" "$3"); _vj=$(_jcount "$1" "$2" "$3")
  if [ "$4" -gt 0 ]; then [ "$_vc" = "$4" ] && [ "$_vj" = 1 ]
  else [ "$_vc" = -1 ] && [ "$_vj" = 0 ]; fi
}

# ── Firewall: one iptables-restore input per family ─────────────────────────
# Our jumps are removed and put back, our chains are declared (created or
# flushed) and filled, or removed when nothing is expected.
# _gen_chain <dump> <parent> <chain> <expected> <jump position|append>
# Rules for the chain come on stdin, one per line.
_gen_chain() {
  _gn=$(_jcount "$1" "$2" "$3")
  while [ "$_gn" -gt 0 ]; do echo "-D $2 -j $3"; _gn=$((_gn - 1)); done
  if [ "$4" -gt 0 ]; then
    echo ":$3 - [0:0]"
    while read -r _gr; do [ -n "$_gr" ] && echo "-A $3 $_gr"; done
    if [ "$5" = append ]; then echo "-A $2 -j $3"; else echo "-I $2 $5 -j $3"; fi
  elif [ "$(_scount "$1" "$3")" != -1 ]; then
    echo "-F $3"; echo "-X $3"
  fi
  unset _gn _gr
}

_rules_fwd() { # VHS_FWD
  for _e in $P_TETHERS; do
    _t=${_e%%=*}
    case "$(_t_mode "${_e#*=}")" in
      route)
        echo "-i $_t -o $VPN_IF -m state --state INVALID -j DROP"
        echo "-i $_t -o $VPN_IF -j ACCEPT"
        echo "-i $VPN_IF -o $_t -m state --state RELATED,ESTABLISHED -j ACCEPT"
        echo "-i $VPN_IF -o $_t -j DROP"
        echo "-i $_t -j REJECT"
        echo "-o $_t -j DROP" ;;
      block)
        echo "-i $_t -j REJECT"
        echo "-o $_t -j DROP" ;;
    esac
  done
}

_rules_post() { # VHS_POST
  for _e in $P_TETHERS; do
    [ "$(_t_mode "${_e#*=}")" = route ] && echo "-s ${_e#*=} -o $VPN_IF -j MASQUERADE"
  done
  return 0
}

_rules_pre() { # VHS_PRE
  [ "$P_DNS" = fallback ] || return 0
  for _e in $P_TETHERS; do
    if [ "$(_t_mode "${_e#*=}")" = route ]; then
      echo "-i ${_e%%=*} -p udp --dport 53 -j DNAT --to-destination $P_FB:53"
      echo "-i ${_e%%=*} -p tcp --dport 53 -j DNAT --to-destination $P_FB:53"
    fi
  done
}

_rules_mss() { # VHS_MSS
  _ms=$(( ${VPN_MTU:-1420} - 40 ))
  echo "-o $VPN_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $_ms"
  echo "-i $VPN_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $_ms"
}

_rules_fwd6() { # VHS_FWD6
  for _e in $P_TETHERS; do
    case "$(_t_mode "${_e#*=}")" in
      route | block) echo "-i ${_e%%=*} -j REJECT"; echo "-o ${_e%%=*} -j DROP" ;;
    esac
  done
}

_gen4() {
  _pos=$(_fwd_pos "$S_F" "$C_FWD"); [ -n "$_pos" ] || _pos=append
  echo "*filter"
  _rules_fwd | _gen_chain "$S_F" FORWARD "$C_FWD" "$E_FWD" "$_pos"
  echo "COMMIT"
  echo "*nat"
  _rules_post | _gen_chain "$S_N" POSTROUTING "$C_POST" "$E_POST" 1
  _rules_pre | _gen_chain "$S_N" PREROUTING "$C_PRE" "$E_PRE" 1
  echo "COMMIT"
  echo "*mangle"
  { [ "$E_MSS" -gt 0 ] && _rules_mss; } | _gen_chain "$S_M" FORWARD "$C_MSS" "$E_MSS" 1
  echo "COMMIT"
  unset _pos
}

_gen6() {
  _pos=$(_fwd_pos "$S_F6" "$C_FWD6"); [ -n "$_pos" ] || _pos=append
  echo "*filter"
  _rules_fwd6 | _gen_chain "$S_F6" FORWARD "$C_FWD6" "$E_FWD6" "$_pos"
  echo "COMMIT"
  unset _pos
}

# ── ip rules ─────────────────────────────────────────────────────────────────
_rules_del_pref() { # <pref>
  _dn=0
  while ip rule del pref "$1" 2>/dev/null; do
    _dn=$((_dn + 1)); [ "$_dn" -ge 64 ] && break
  done
  unset _dn
}

_ip_rules_build() {
  _lnt=$(rt_id local_network); [ -n "$_lnt" ] || _lnt=local_network
  for _e in $P_TETHERS; do
    _t=${_e%%=*}; _n=${_e#*=}
    case "$(_t_mode "$_n")" in
      route)
        ip rule add pref "$PREF_LOCAL" iif "$_t" to "$_n" lookup "$_lnt"
        ip rule add pref "$PREF_VPN" iif "$_t" lookup "$VPN_TID"
        [ "$P_KS" = 1 ] && ip rule add pref "$PREF_KILL" iif "$_t" unreachable ;;
      block)
        ip rule add pref "$PREF_KILL" iif "$_t" unreachable ;;
    esac
  done
  unset _lnt _e _t _n
}

# ── Guard (ip rule only - no xtables lock, safe to use at any moment) ────────
_guard_add() { # <iface...>
  for _g in "$@"; do ip rule add pref "$PREF_GUARD" iif "$_g" unreachable 2>/dev/null; done
  unset _g
}

# Called by the watchdog right when an event arrives: a tether interface
# that none of our rules covers yet is blocked until the full pass (after
# the burst settles) has set it up. Only with the kill switch on.
vhs_quick_guard() {
  [ "$(conf_get ENABLED)" = 1 ] && [ "$(conf_get KILL_SWITCH)" = 1 ] || return 0
  _qr=$(ip rule 2>/dev/null)
  for _qt in $(printf '%s\n' "$_qr" | sed -n 's/^21000:.* iif \([A-Za-z0-9_.-]*\) .*/\1/p' | sort -u); do
    printf '%s\n' "$_qr" | grep -qE "^20(350|500|600):.* iif $_qt( |\$)" && continue
    _guard_add "$_qt"
  done
  unset _qr _qt
}

# ── Apply ────────────────────────────────────────────────────────────────────
# Rebuild everything for the current plan. Returns 1 if the firewall part
# failed (tables changed under us) - the caller passes again.
_apply() {
  _af=0
  # Guard first for every tether that must not reach the plain uplink
  for _e in $P_TETHERS; do
    [ "$(_t_mode "${_e#*=}")" = none ] || _guard_add "${_e%%=*}"
  done
  _rules_del_pref "$PREF_LOCAL"
  _rules_del_pref "$PREF_VPN"
  _rules_del_pref "$PREF_KILL"
  _gen4 | ipt_restore 4 || { _af=1; log_warn "iptables-restore (IPv4) failed - retrying"; }
  if [ "$S_V6" = 1 ]; then
    _gen6 | ipt_restore 6 || { _af=1; log_warn "ip6tables-restore failed - retrying"; }
  fi
  _ip_rules_build
  _rules_del_pref "$PREF_GUARD"
  unset _e
  return $_af
}

vhs_teardown() {
  vhs_snap
  P_STATE=disabled; P_TETHERS=""; P_KS=0; P_DNS=none; VPN_IF=""; VPN_TID=""; VPN_MTU=""
  _expect
  _apply
  rm -f "$APPLIED_FILE"
}

# ── netd mid-change ──────────────────────────────────────────────────────────
# A VPN network that netd is still adding or removing shows in the rules as
#   17000: from all iif lo oif wg-x [detached] ...   (interface already gone)
# or as its uid rule pointing at a table whose interface no longer exists.
# Prints what was seen; nothing when netd looks settled.
_netd_busy() {
  if printf '%s\n' "$S_IR" | grep -q '\[detached\]'; then echo "detached VPN rules"; return 0; fi
  for _nt in $(printf '%s\n' "$S_IR" | grep 'uidrange' | grep -v 'uidrange 0-0 ' | awk '{ print $NF }' | sort -u); do
    case "$_nt" in *[!0-9]*) _nn=$_nt ;; *) _nn=$(rt_name "$_nt") ;; esac
    # no name any more (netd already dropped it from its table list) or
    # no interface: the network is half removed
    if [ -z "$_nn" ] || [ ! -d "/sys/class/net/$_nn" ]; then
      echo "VPN rules for missing ${_nn:-table $_nt}"; unset _nt _nn; return 0
    fi
  done
  unset _nt _nn
  return 1
}

# ── Sync: make the system match the plan ─────────────────────────────────────
# vhs_sync [1 = rebuild even when nothing changed]. Takes the lock. Returns
# 2 when the caller should pass again soon (something changed under us).
vhs_sync() {
  _rc=0
  vhs_lock
  vhs_snap
  vhs_plan
  _expect
  _cur=""
  read -r _cur 2>/dev/null < "$APPLIED_FILE"
  _prev_state=${_cur%% *}; _prev_state=${_prev_state#state=}
  _reason=""
  if [ "$1" = 1 ]; then
    _reason=forced
  elif [ "$_cur" != "$P_SIG" ]; then
    _reason=changed
  else
    _reason=$(vhs_verify)
    [ -n "$_reason" ] && log_warn "repairing: $_reason"
  fi

  # netd is still changing the VPN network: do not touch the tables now.
  # Clients are safe meanwhile (kill switch rule; guard for new tethers).
  # Only while going towards "no VPN": a VPN that is already up and routable
  # is taken at once (stale rules of the previous tunnel do not matter).
  if [ -n "$_reason" ] && [ "$P_STATE" != vpn ]; then
    _busy=$(_netd_busy)
    if [ -n "$_busy" ]; then
      _b0=""; read -r _b0 2>/dev/null < "$NETD_BUSY_FILE"
      [ -n "$_b0" ] || { _b0=$(date +%s); echo "$_b0" > "$NETD_BUSY_FILE"; log_info "waiting for Android to finish the VPN change ($_busy) before switching to $P_STATE${P_TUN:+, tunnel $P_TUN}"; }
      if [ $(( $(date +%s) - _b0 )) -lt "$NETD_WAIT" ]; then
        _write_status waiting
        vhs_unlock
        unset _cur _reason _busy _b0 _prev_state
        return 2
      fi
      log_warn "Android left the VPN change unfinished for ${NETD_WAIT}s ($_busy) - continuing"
    fi
    rm -f "$NETD_BUSY_FILE"
    unset _busy _b0
  fi

  if [ -n "$_reason" ]; then
    _apply || _rc=2
    echo "$P_SIG" > "$APPLIED_FILE"
    if [ "$_rc" = 0 ]; then
      vhs_snap
      _post=$(vhs_verify)
      [ -n "$_post" ] && { log_warn "changed during rebuild: $_post - passing again"; _rc=2; }
    fi
    # Clients may still have connections that went out directly (module
    # off, kill switch off without VPN, tunnel dead, hotspot just started):
    # Android's offload keeps them alive past the firewall. End them - the
    # devices reopen them at once, through the tunnel.
    if [ "$P_STATE" = vpn ]; then
      # Another server (another interface) than the one clients used last:
      # their open connections would carry on through the new server with
      # the old exit - Proton gives every server the same inside address
      # (10.2.0.2), so nothing breaks them. End all of them.
      _lv=""; read -r _lv 2>/dev/null < "$LAST_VPN_FILE"
      if [ -n "$_lv" ] && [ "$_lv" != "$VPN_IF" ]; then
        _cut_direct all "server changed ($_lv -> $VPN_IF)"
      else
        case "$_prev_state" in vpn | blocked) ;; *) _cut_direct ;; esac
      fi
      echo "$VPN_IF" > "$LAST_VPN_FILE"
      unset _lv
    fi
    case "$_reason" in
      changed) _log_state_change "$_prev_state" ;;
      forced) _log_state_change "$P_STATE" quiet ;;
    esac
  fi
  if [ "$_rc" = 0 ]; then _write_status ok; else _write_status repairing; fi
  vhs_unlock
  unset _cur _reason _post _prev_state
  return $_rc
}

_cut_direct() { # [all <why>]  (default: only what went out directly)
  [ -x "$CTFLUSH" ] || return 0
  _cn=""
  for _e in $P_TETHERS; do
    [ "$(_t_mode "${_e#*=}")" = route ] && _cn="$_cn ${_e#*=}"
  done
  [ -n "$_cn" ] || { unset _cn _e; return 0; }
  _ck=""
  if [ "$1" != all ]; then
    # keep what is already NATed to the tunnel's own address
    _ck=$(ip -4 addr show dev "$VPN_IF" 2>/dev/null | awk '$1 == "inet" { sub(/\/.*/, "", $2); print $2; exit }')
  fi
  # shellcheck disable=SC2086
  _co=$("$CTFLUSH" ${_ck:+-k "$_ck"} $_cn 2>&1)
  case "$_co" in
    *"deleted=0"*) ;;
    *deleted=*)
      if [ "$1" = all ]; then log_info "$2: ended ${_co##*deleted=} client connection(s) - they reopen through the new server"
      else log_info "ended ${_co##*deleted=} direct connection(s) of clients - they reopen through the VPN"; fi ;;
    *) log_warn "could not end client connections: $_co" ;;
  esac
  unset _cn _e _ck _co
}

_tether_names() { _tn=""; for _e in $P_TETHERS; do _tn="${_tn:+$_tn }${_e%%=*}"; done; echo "$_tn"; unset _tn _e; }

_log_state_change() { # <previous state> [quiet]
  case "$P_STATE" in
    vpn) _m="clients on $(_tether_names) -> VPN $VPN_IF (table $VPN_TID, mtu $VPN_MTU, dns $P_DNS${P_FB:+ $P_FB})"
         _d="✅ Hotspot via $VPN_IF" ;;
    blocked) _m="no VPN${P_TUN:+ ($VPN_IF not responding)} - kill switch: clients on $(_tether_names) blocked"
             _d="⛔ Waiting for VPN (clients blocked)" ;;
    passthrough) _m="no VPN${P_TUN:+ ($VPN_IF not responding)} - kill switch off: clients on $(_tether_names) use the normal uplink"
                 _d="⚠️ No VPN (kill switch off)" ;;
    idle) _m="no tethering"; _d="💤 Idle (no hotspot)" ;;
    disabled) _m="disabled"; _d="⏸️ Disabled" ;;
  esac
  if [ "$2" != quiet ] && { [ "$1" != "$P_STATE" ] || [ "$P_STATE" = vpn ]; }; then
    log_info "$_m"
  fi
  set_description "$_d"
  echo "$(date +%s) $P_STATE" > "$STATE_DIR/since"
  unset _m _d
}

# One word per protection piece, for the WebUI (from the snapshot the pass
# already holds - no extra table reads): ok | bad | off (not needed now)
_chk() { if [ "$1" -gt 0 ]; then if _vchain "$2" "$3" "$4" "$1"; then echo ok; else echo bad; fi; else echo off; fi; }
_write_checks() {
  if [ "$E_R" -gt 0 ]; then
    if [ "$(_rcount "$PREF_LOCAL")" = "$E_R" ] && [ "$(_rcount "$PREF_VPN")" = "$E_R" ]; then echo "chk_route=ok"; else echo "chk_route=bad"; fi
  else echo "chk_route=off"; fi
  if [ "$E_KILL" -gt 0 ]; then
    if [ "$(_rcount "$PREF_KILL")" = "$E_KILL" ]; then echo "chk_kill=ok"; else echo "chk_kill=bad"; fi
  else echo "chk_kill=off"; fi
  echo "chk_nat=$(_chk "$E_POST" "$S_N" POSTROUTING "$C_POST")"
  _cf=$(_chk "$E_FWD" "$S_F" FORWARD "$C_FWD")
  [ "$_cf" = ok ] && [ "$(_fwd_state "$S_F" "$C_FWD")" != ok ] && _cf=bad
  echo "chk_forward=$_cf"
  if [ "$E_FWD" -gt 0 ]; then echo "forward_position=$(_fwd_state "$S_F" "$C_FWD")"; else echo "forward_position=-"; fi
  echo "chk_mss=$(_chk "$E_MSS" "$S_M" FORWARD "$C_MSS")"
  if [ "$S_V6" = 1 ]; then echo "chk_ipv6=$(_chk "$E_FWD6" "$S_F6" FORWARD "$C_FWD6")"; else echo "chk_ipv6=off"; fi
  if [ "$E_PRE" -gt 0 ]; then echo "chk_dns=$(_chk "$E_PRE" "$S_N" PREROUTING "$C_PRE")"
  elif [ "$P_DNS" = local ]; then echo "chk_dns=ok"; else echo "chk_dns=off"; fi
  echo "dnscrypt_hotspot=$([ "$(_jcount "$S_F" FORWARD DNSC_HS_FWD)" -gt 0 ] && echo 1 || echo 0)"
  echo "ipset_forward=$([ "$(_jcount "$S_F" FORWARD IPSA_FWD)" -gt 0 ] && echo 1 || echo 0)"
  echo "local_dns=$(local_dns_active "$S_N" && echo 1 || echo 0)"
  unset _cf
}

_write_status() { # [rules state]
  {
    echo "state=$P_STATE"
    echo "kill_switch=$P_KS"
    echo "vpn=$VPN_IF"
    echo "vpn_table=$VPN_TID"
    echo "vpn_mtu=$VPN_MTU"
    echo "tunnel=$P_TUN"
    echo "dns=$P_DNS"
    echo "fallback_dns=$P_FB"
    echo "tethers=$P_TETHERS"
    echo "rules=${1:-ok}"
    _write_checks
    echo "updated=$(date +%s)"
  } > "$STATUS_FILE.tmp" 2>/dev/null && mv -f "$STATUS_FILE.tmp" "$STATUS_FILE"
}

# ── Clients ──────────────────────────────────────────────────────────────────
# One line per client: <iface> <ip|-> <mac> <connected|active|stale>
# Wi-Fi: the driver's station list (Android's own count). Other tethering
# (USB, Bluetooth): the neighbour table.
vhs_clients() { # [iface ...]  (default: detect)
  if [ "$#" -gt 0 ]; then _cl="$*"; else _cl=$(tether_ifaces); fi
  for _ci in $_cl; do
    _nb=$(ip neigh show dev "$_ci" 2>/dev/null)
    if command -v iw >/dev/null 2>&1 && _sd=$(iw dev "$_ci" station dump 2>/dev/null); then
      for _mac in $(printf '%s\n' "$_sd" | sed -n 's/^Station \([0-9a-fA-F:]*\) .*/\1/p'); do
        _cip=$(printf '%s\n' "$_nb" | awk -v m="$_mac" '
          { for (i = 2; i <= NF; i++) if (tolower($i) == tolower(m)) { if ($1 !~ /:/) { print $1; exit } } }')
        echo "$_ci ${_cip:--} $_mac connected"
      done
    else
      printf '%s\n' "$_nb" | awk -v i="$_ci" '
        $1 !~ /:/ {
          m = ""; s = ""
          for (k = 2; k <= NF; k++) {
            if ($k ~ /^[0-9a-fA-F][0-9a-fA-F](:[0-9a-fA-F][0-9a-fA-F])+$/ && length($k) == 17) m = $k
            if ($k == "REACHABLE" || $k == "DELAY" || $k == "PROBE" || $k == "PERMANENT") s = "active"
            if ($k == "STALE" && s == "") s = "stale"
          }
          if (m != "" && s != "") print i, $1, m, s
        }'
    fi
  done
  unset _ci _cl _nb _sd _mac _cip
}
