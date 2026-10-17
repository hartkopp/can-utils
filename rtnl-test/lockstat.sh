#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# lockstat.sh - snapshot the rtnl_mutex contention from /proc/lock_stat.
#
# Requires a kernel built with CONFIG_LOCK_STAT=y.
#
#   lockstat.sh reset          clear the accumulated statistics
#   lockstat.sh show [name]    print the rows for a lock (default rtnl_mutex)
#
# The "show" output keeps the /proc/lock_stat header so the columns
# (con-bounces, contentions, waittime-min/avg/max/total, ...) stay labeled.
set -u

STAT=/proc/lock_stat

die() { echo "lockstat: $*" >&2; exit 1; }

[ -e "$STAT" ] || die "$STAT missing - build the kernel with CONFIG_LOCK_STAT=y"

case "${1:-show}" in
reset)
	# Writing to /proc/lock_stat clears the accumulated data.
	echo 0 > "$STAT" || die "cannot reset (need root?)"
	echo "lock_stat reset"
	;;
show)
	name="${2:-rtnl_mutex}"
	# Print the two header lines, then every data row mentioning the lock.
	# Rows wrap onto a continuation line, which we keep via the trailing
	# match on lines that start with whitespace+at.
	awk -v pat="$name" '
		NR <= 2 { print; next }
		$0 ~ pat { print; show = 1; next }
		show && $0 ~ /^[[:space:]]+at / { print; next }
		{ show = 0 }
	' "$STAT"
	;;
*)
	die "usage: $0 {reset|show [lockname]}"
	;;
esac
