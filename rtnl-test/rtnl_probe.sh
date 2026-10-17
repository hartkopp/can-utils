#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# rtnl_probe.sh - measure how long an ordinary RTNL operation stalls.
#
# Repeatedly creates and deletes a dummy interface. Each `ip link add`
# and `del` takes rtnl_lock(), so the wall-clock time of this loop tracks
# how long an unrelated RTNL user (NetworkManager, container setup, plain
# `ip link`) waits behind whoever else holds RTNL.
#
# Run it once with no CAN load for a baseline, then again while the raw
# rebind loaders run. Before the per-device-lock rework the loaders hold
# RTNL across up to 512 filter (un)registrations, so the max latency here
# climbs sharply; after it, the loaders never take RTNL and the numbers
# stay close to the baseline.
#
#   rtnl_probe.sh [iterations] [dummy-name]
set -u

iters="${1:-200}"
dev="${2:-rtnlprobe0}"

command -v ip >/dev/null || { echo "rtnl_probe: need iproute2" >&2; exit 1; }

ip link del "$dev" 2>/dev/null

ns_now() { date +%s%N; }

max=0 sum=0 min=0 n=0
for ((i = 0; i < iters; i++)); do
	t0=$(ns_now)
	ip link add "$dev" type dummy 2>/dev/null || continue
	ip link del "$dev" 2>/dev/null
	t1=$(ns_now)
	d=$(( (t1 - t0) / 1000 ))	# microseconds
	n=$((n + 1))
	sum=$((sum + d))
	[ "$d" -gt "$max" ] && max=$d
	{ [ "$min" -eq 0 ] || [ "$d" -lt "$min" ]; } && min=$d
done

if [ "$n" -eq 0 ]; then
	echo "rtnl_probe: no successful iterations (need root?)" >&2
	exit 1
fi

printf 'rtnl_probe: n=%d min=%dus avg=%dus max=%dus\n' \
	"$n" "$min" "$((sum / n))" "$max"
