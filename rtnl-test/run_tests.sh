#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# run_tests.sh - verify the CAN per-device receive list lock rework
#                (vy-0002: replace RTNL in raw/isotp/bcm bind+release).
#
# Two things are checked:
#
#   1. Correctness (KASAN / lockdep / list accounting).
#      A bound socket's device is churned between network namespaces while
#      the socket is released, which is the use-after-free the rework fixes
#      (can_rx_unregister() no longer depends on the device's namespace).
#      vcan/isotp/bcm are exercised. The run passes only if the kernel log
#      stays clean (no KASAN report, no WARNING/BUG, no lockdep splat, no
#      "receive list entry not found").
#
#   2. RTNL decoupling (the actual goal of the rework).
#      The time of an unrelated `ip link add/del` is measured on an idle
#      system and again while several CAN_RAW sockets rebind with a full
#      512-filter set. Before the rework the loaders hold RTNL across the
#      filter churn and the probe's max latency explodes; after it, raw
#      bind/release take no RTNL and the probe stays near baseline. The
#      rtnl_mutex row from /proc/lock_stat is captured for both phases.
#
# Must run as root on the kernel under test. It only touches throwaway
# vcan/dummy interfaces and a dedicated netns, and cleans them up.
#
# Env knobs:
#   LOADERS   number of raw rebind loaders        (default 4)
#   FILTERS   filters per raw socket              (default 512)
#   LOAD_T    seconds per load phase              (default 15)
#   RACE_T    seconds of netns churn              (default 20)
#   PROBE_N   ip link add/del iterations          (default 200)
set -u

here="$(cd "$(dirname "$0")" && pwd)"
CANBIND="$here/canbind"
LOCKSTAT="$here/lockstat.sh"
PROBE="$here/rtnl_probe.sh"

LOADERS="${LOADERS:-4}"
FILTERS="${FILTERS:-512}"
LOAD_T="${LOAD_T:-15}"
RACE_T="${RACE_T:-20}"
PROBE_N="${PROBE_N:-200}"

NS=canrtnl_ns
RACEDEV=vcanrace
DEV0=vcan0
DEV1=vcan1
MARKER="canrtnl-test-$$-$(date +%s)"

pids=()
rc=0

say()  { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
fail() { printf '   FAIL: %s\n' "$*" >&2; rc=1; }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }; }

have() { command -v "$1" >/dev/null 2>&1; }

modprobe_q() { modprobe "$1" 2>/dev/null || true; }

mark_dmesg() { echo "$MARKER $1" > /dev/kmsg 2>/dev/null || true; }

# Scan the kernel log produced since MARKER for trouble. Returns non-zero
# and prints the offending lines if anything bad shows up.
scan_dmesg() {
	local log
	log="$(dmesg | sed -n "/$MARKER/,\$p")"
	local pat bad
	pat='KASAN|use-after-free|BUG:|WARNING:|general protection'
	pat="$pat|kernel NULL pointer|possible recursive locking|lockdep"
	pat="$pat|INFO: possible|held lock|receive list entry not found"
	bad="$(printf '%s\n' "$log" | grep -E -i "$pat" | grep -v "$MARKER")"
	if [ -n "$bad" ]; then
		printf '%s\n' "$bad"
		return 1
	fi
	return 0
}

cleanup() {
	local p
	for p in "${pids[@]:-}"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null
	done
	wait 2>/dev/null
	# Pull the race device back if it is parked in the netns.
	ip -n "$NS" link set "$RACEDEV" netns 1 2>/dev/null
	ip link del "$RACEDEV" 2>/dev/null
	ip link del "$DEV0" 2>/dev/null
	ip link del "$DEV1" 2>/dev/null
	ip netns del "$NS" 2>/dev/null
}
trap cleanup EXIT

###############################################################################
need_root
[ -x "$CANBIND" ] || { echo "build first: make -C $here" >&2; exit 1; }
have ip || { echo "need iproute2" >&2; exit 1; }

say "preflight"
modprobe_q vcan
modprobe_q can-isotp
modprobe_q can-bcm
isotp_ok=1; bcm_ok=1
mark_dmesg start

ip link add "$DEV0" type vcan 2>/dev/null; ip link set "$DEV0" up
ip link add "$DEV1" type vcan 2>/dev/null; ip link set "$DEV1" up
ip link add "$RACEDEV" type vcan 2>/dev/null; ip link set "$RACEDEV" up
ip netns add "$NS" 2>/dev/null
info "interfaces: $DEV0 $DEV1 $RACEDEV, netns: $NS"
if [ -e /proc/lock_stat ]; then
	info "lock_stat: available"
else
	info "lock_stat: NOT available (CONFIG_LOCK_STAT=n) - skipping lock rows"
fi

###############################################################################
say "scenario 1: namespace churn vs release (correctness)"
# Long-lived holders bound to the race device, in each protocol.
start_holder() {
	"$CANBIND" -p "$1" -i "$RACEDEV" -f "$FILTERS" >/dev/null 2>"$here/.$1.err" &
	echo $!
}

race_until=$(( $(date +%s) + RACE_T ))
iter=0
while [ "$(date +%s)" -lt "$race_until" ]; do
	hpids=()
	hpids+=("$(start_holder raw)")
	if [ "$isotp_ok" = 1 ]; then
		p="$(start_holder isotp)"; hpids+=("$p")
	fi
	if [ "$bcm_ok" = 1 ]; then
		p="$(start_holder bcm)"; hpids+=("$p")
	fi
	# Give the binds a moment, detect unsupported protocols once.
	sleep 0.05
	if [ "$iter" -eq 0 ]; then
		grep -q "not loaded" "$here/.isotp.err" 2>/dev/null && {
			isotp_ok=0; info "isotp unsupported - skipped"; }
		grep -q "not loaded" "$here/.bcm.err" 2>/dev/null && {
			bcm_ok=0; info "bcm unsupported - skipped"; }
	fi
	# Move the still-bound device into the netns and back. This sends
	# NETDEV_UNREGISTER/REGISTER and changes dev_net() under the holders.
	ip link set "$RACEDEV" netns "$NS" 2>/dev/null
	ip -n "$NS" link set "$RACEDEV" up 2>/dev/null
	ip -n "$NS" link set "$RACEDEV" netns 1 2>/dev/null
	ip link set "$RACEDEV" up 2>/dev/null
	# Close the sockets -> release path removes the filters.
	for p in "${hpids[@]}"; do kill "$p" 2>/dev/null; done
	wait "${hpids[@]}" 2>/dev/null
	iter=$((iter + 1))
done
info "churn iterations: $iter"
if scan_dmesg; then
	info "kernel log clean after churn"
else
	fail "kernel log shows a defect after churn (see lines above)"
fi
rm -f "$here"/.raw.err "$here"/.isotp.err "$here"/.bcm.err

###############################################################################
say "scenario 2: RTNL latency, idle baseline"
base="$("$PROBE" "$PROBE_N")"
info "$base"

say "scenario 2: RTNL latency under raw filter-rebind load"
if [ -e /proc/lock_stat ]; then
	"$LOCKSTAT" reset >/dev/null
fi
for ((i = 0; i < LOADERS; i++)); do
	"$CANBIND" -L -i "$DEV0" -I "$DEV1" -f "$FILTERS" -t "$LOAD_T" \
		>"$here/.load.$i" 2>/dev/null &
	pids+=("$!")
done
sleep 1	# let the loaders ramp up
loaded="$("$PROBE" "$PROBE_N")"
info "$loaded"
wait "${pids[@]}" 2>/dev/null
pids=()
for ((i = 0; i < LOADERS; i++)); do
	[ -s "$here/.load.$i" ] && info "$(cat "$here/.load.$i")"
	rm -f "$here/.load.$i"
done

if [ -e /proc/lock_stat ]; then
	say "rtnl_mutex contention during load (/proc/lock_stat)"
	"$LOCKSTAT" show rtnl_mutex
fi

if scan_dmesg; then
	info "kernel log clean after load"
else
	fail "kernel log shows a defect after load (see lines above)"
fi

###############################################################################
say "result"
# Pull the comparable 'max=' field out of both probe lines.
base_max="$(printf '%s' "$base"   | sed -n 's/.*max=\([0-9]*\)us.*/\1/p')"
load_max="$(printf '%s' "$loaded" | sed -n 's/.*max=\([0-9]*\)us.*/\1/p')"
info "ip link add/del max latency: idle=${base_max:-?}us  under-load=${load_max:-?}us"
info "(expectation after the rework: under-load stays close to idle;"
info " a large jump means raw bind/release still serialize on RTNL)"

if [ "$rc" -eq 0 ]; then
	echo
	echo "PASS: no kernel defects detected"
else
	echo
	echo "FAILURES detected - inspect the lines above and full dmesg"
fi
exit "$rc"
