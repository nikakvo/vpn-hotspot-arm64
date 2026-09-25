#!/system/bin/sh
# customize.sh - installer (KernelSU / SukiSU / APatch / Magisk)
# shellcheck disable=SC2034
SKIPUNZIP=0

_V=$(sed -n 's/^version=//p' "$MODPATH/module.prop" 2>/dev/null)
ui_print " "
ui_print "******************************"
ui_print "*     VPN Hotspot Arm64      *"
_bl=$(( (28 - ${#_V}) / 2 )); [ "$_bl" -lt 0 ] && _bl=0
_br=$(( 28 - ${#_V} - _bl )); [ "$_br" -lt 0 ] && _br=0
ui_print "*$(printf '%*s' "$_bl" '')$_V$(printf '%*s' "$_br" '')*"
ui_print "******************************"
ui_print "*        Tears Burn          *"
ui_print "******************************"
ui_print " "
unset _bl _br

MODDIR="$MODPATH"
. "$MODPATH/sh/common.sh"

# ── Requirements ─────────────────────────────────────────────────────────────
ui_print "- Checking requirements"
[ "$ARCH" = arm64 ] || ui_print "  ! Built and tested on arm64 (this device: ${ARCH:-unknown})"
[ -n "$IP_BIN" ] || abort "  ! ip (iproute2) not found - cannot route clients"
[ -n "$IPT4_BIN" ] || abort "  ! iptables not found"
ip rule >/dev/null 2>&1 || abort "  ! 'ip rule' does not work on this device"
ui_print "  ip: $IP_BIN"

if [ -r /proc/config.gz ]; then
  _cfg=$(zcat /proc/config.gz 2>/dev/null)
  for _k in CONFIG_IP_MULTIPLE_TABLES CONFIG_NETFILTER_XT_TARGET_MASQUERADE CONFIG_NETFILTER_XT_TARGET_TCPMSS; do
    case "$_cfg" in
      *"$_k=y"* | *"$_k=m"*) ;;
      *) ui_print "  ! kernel: $_k not set - clients may not reach the VPN" ;;
    esac
  done
  unset _cfg _k
fi
_mon=$(timeout 1 "$IP_BIN" monitor link 2>&1 >/dev/null; echo "rc=$?")
case "$_mon" in
  *"rc=0"* | *"rc=124"* | *"rc=143"*) ui_print "  network events: ip monitor OK" ;;
  *) ui_print "  ! ip monitor unavailable - VPN changes handled every 10 s" ;;
esac
unset _mon

# ── Settings ─────────────────────────────────────────────────────────────────
if [ -f "$CONF" ]; then
  ui_print "- Keeping your settings ($CONF)"
else
  ui_print "- Default settings: kill switch ON, VPN auto-detect"
fi
conf_init

# ── The set ──────────────────────────────────────────────────────────────────
ui_print "- Companion modules"
case "$(sibling_state dnscrypt-proxy-android)" in
  enabled) ui_print "  DNSCrypt Proxy Arm64: installed - clients' DNS stays encrypted" ;;
  disabled) ui_print "  DNSCrypt Proxy Arm64: disabled - client DNS via $(conf_get FALLBACK_DNS) through the VPN" ;;
  *) ui_print "  DNSCrypt Proxy Arm64: not installed - client DNS via $(conf_get FALLBACK_DNS) through the VPN" ;;
esac
case "$(sibling_state ipset_arm64 ipset-arm64)" in
  enabled) ui_print "  ipset-arm64: installed - its hotspot filter keeps working" ;;
  *) ui_print "  ipset-arm64: not installed" ;;
esac

# ── Update in place ──────────────────────────────────────────────────────────
# A running watchdog belongs to the old version: it keeps clients routed
# until the reboot and is replaced then. Nothing is stopped here, so the
# clients are never left without the rules in between.
if [ -n "$(wd_pid)" ]; then
  ui_print "- Previous version keeps running until you reboot"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
[ -f "$MODPATH/bin/vhs-ctflush" ] && set_perm "$MODPATH/bin/vhs-ctflush" 0 0 0755
for _f in "$MODPATH"/*.sh "$MODPATH"/sh/*.sh; do
  [ -f "$_f" ] && set_perm "$_f" 0 0 0755
done
unset _f

ui_print " "
ui_print "- Done. Reboot, then turn on the hotspot with your VPN connected."
ui_print "  Status: su -c \"sh /data/adb/modules/vpn-hotspot/ctl.sh status\""
ui_print " "
