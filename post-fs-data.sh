#!/system/bin/sh
# post-fs-data.sh - early boot: clear the previous boot's runtime state.
# Nothing is routed yet at this point (no tethering, no VPN), so there is
# nothing to install; the watchdog (service.sh) takes over after boot.
MODDIR=${0%/*}
[ -f "$MODDIR/sh/common.sh" ] || exit 0
. "$MODDIR/sh/common.sh"
mkdir -p "$STATE_DIR"
rm -rf "$LOCK_DIR"
rm -f "$WD_PIDFILE" "$MON_PIDFILE" "$MON_FIFO" "$TICK_FILE" "$STATUS_FILE" \
      "$APPLIED_FILE" "$IPT_WAIT_FILE" "$STATE_DIR/events" "$STATE_DIR/since" "$STATE_DIR/netd_busy" "$STATE_DIR/tunnel" "$STATE_DIR/last_vpn" "$STATE_DIR/iptr_wait"
