// SPDX-License-Identifier: GPL-2.0
/*
 * canbind - load/hold helper for verifying the CAN per-device receive
 * list lock rework (replacing RTNL in raw/isotp/bcm bind and release).
 *
 * Two jobs, selected by options:
 *
 *   load  (-L): bind a CAN_RAW socket carrying up to CAN_RAW_FILTER_MAX
 *               filters alternately to two interfaces. Each rebind makes
 *               the kernel remove N filters from the old device and add N
 *               to the new one - the path that used to run under RTNL.
 *               Reports the achieved bind rate.
 *
 *   hold  (default): bind one socket (raw, isotp or bcm) to an interface
 *               and keep it open until SIGINT/SIGTERM, which closes it and
 *               runs the protocol's release path. Used by the netns churn
 *               scenario to keep a bound socket alive while its device is
 *               moved between network namespaces.
 *
 * This is a test tool. It prints to stderr and exits non-zero on setup
 * errors so a driving script can tell a skipped protocol (e.g. missing
 * module) from a real failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/bcm.h>
#include <linux/can/isotp.h>
#include <linux/can/raw.h>

/* Keep in sync with the kernel's CAN_RAW_FILTER_MAX. */
#ifndef CAN_RAW_FILTER_MAX
#define CAN_RAW_FILTER_MAX 512
#endif

static volatile sig_atomic_t stop;

static void on_sig(int sig)
{
	(void)sig;
	stop = 1;
}

static int if_index(int s, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "canbind: SIOCGIFINDEX(%s): %s\n",
			name, strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}

static int raw_prepare(int nfilters)
{
	struct can_filter *f;
	int s, i;

	s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (s < 0) {
		fprintf(stderr, "canbind: socket(CAN_RAW): %s\n",
			strerror(errno));
		return -1;
	}

	if (nfilters > 0) {
		f = calloc(nfilters, sizeof(*f));
		if (!f) {
			fprintf(stderr, "canbind: out of memory\n");
			close(s);
			return -1;
		}
		/* Distinct SFF ids so each becomes its own receiver entry. */
		for (i = 0; i < nfilters; i++) {
			f[i].can_id = i & CAN_SFF_MASK;
			f[i].can_mask = CAN_SFF_MASK;
		}
		if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, f,
			       nfilters * sizeof(*f)) < 0) {
			fprintf(stderr, "canbind: CAN_RAW_FILTER(%d): %s\n",
				nfilters, strerror(errno));
			free(f);
			close(s);
			return -1;
		}
		free(f);
	}
	return s;
}

static int raw_bind(int s, int ifindex)
{
	struct sockaddr_can addr;

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifindex;
	return bind(s, (struct sockaddr *)&addr, sizeof(addr));
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * Rebind a filter-laden CAN_RAW socket between two interfaces for a fixed
 * duration and report the bind rate. One bind == one add+remove of all
 * filters, so this is the raw_bind()/raw_setsockopt() RTNL stress.
 */
static int run_load(const char *if1, const char *if2, int nfilters,
		    double seconds)
{
	int s, idx1, idx2, cur;
	unsigned long n = 0;
	double start, t;

	s = raw_prepare(nfilters);
	if (s < 0)
		return 1;

	idx1 = if_index(s, if1);
	idx2 = if_index(s, if2);
	if (idx1 < 0 || idx2 < 0) {
		close(s);
		return 1;
	}

	/* Bind once so an unbound->bound transition is not counted. */
	if (raw_bind(s, idx1) < 0) {
		fprintf(stderr, "canbind: bind(%s): %s\n", if1,
			strerror(errno));
		close(s);
		return 1;
	}

	start = now_s();
	cur = idx2;
	while (!stop) {
		if (raw_bind(s, cur) < 0) {
			/* ENODEV is expected while a concurrent mover has the
			 * device in another namespace; keep going.
			 */
			if (errno != ENODEV) {
				fprintf(stderr, "canbind: rebind: %s\n",
					strerror(errno));
				close(s);
				return 1;
			}
		}
		cur = (cur == idx1) ? idx2 : idx1;
		n++;
		if ((n & 0x3ff) == 0) {
			t = now_s() - start;
			if (seconds > 0 && t >= seconds)
				break;
		}
	}

	t = now_s() - start;
	close(s);
	printf("load %s<->%s filters=%d binds=%lu time=%.3fs rate=%.0f/s\n",
	       if1, if2, nfilters, n, t, t > 0 ? n / t : 0.0);
	return 0;
}

static int hold_raw(const char *ifname, int nfilters)
{
	int s = raw_prepare(nfilters);
	int idx;

	if (s < 0)
		return 1;
	idx = if_index(s, ifname);
	if (idx < 0 || raw_bind(s, idx) < 0) {
		if (idx >= 0)
			fprintf(stderr, "canbind: bind(%s): %s\n", ifname,
				strerror(errno));
		close(s);
		return 1;
	}
	fprintf(stderr, "canbind: raw bound to %s (%d filters), holding\n",
		ifname, nfilters);
	while (!stop)
		pause();
	close(s);
	return 0;
}

static int hold_isotp(const char *ifname)
{
	struct sockaddr_can addr;
	int s, idx;

	s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
	if (s < 0) {
		fprintf(stderr, "canbind: socket(CAN_ISOTP): %s%s\n",
			strerror(errno),
			errno == EPROTONOSUPPORT ? " (module not loaded?)" : "");
		return 2; /* distinct: likely unsupported */
	}
	idx = if_index(s, ifname);
	if (idx < 0) {
		close(s);
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = idx;
	addr.can_addr.tp.tx_id = 0x123;
	addr.can_addr.tp.rx_id = 0x321;
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "canbind: isotp bind(%s): %s\n", ifname,
			strerror(errno));
		close(s);
		return 1;
	}
	fprintf(stderr, "canbind: isotp bound to %s, holding\n", ifname);
	while (!stop)
		pause();
	close(s);
	return 0;
}

static int hold_bcm(const char *ifname, int nsub)
{
	struct {
		struct bcm_msg_head mh;
	} msg;
	struct sockaddr_can addr;
	int s, idx, i;

	s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (s < 0) {
		fprintf(stderr, "canbind: socket(CAN_BCM): %s%s\n",
			strerror(errno),
			errno == EPROTONOSUPPORT ? " (module not loaded?)" : "");
		return 2;
	}
	idx = if_index(s, ifname);
	if (idx < 0) {
		close(s);
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = idx;
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "canbind: bcm connect(%s): %s\n", ifname,
			strerror(errno));
		close(s);
		return 1;
	}
	/* Each RX_SETUP with a distinct can_id registers one receiver. */
	for (i = 0; i < nsub; i++) {
		memset(&msg, 0, sizeof(msg));
		msg.mh.opcode = RX_SETUP;
		msg.mh.flags = RX_FILTER_ID;
		msg.mh.can_id = i & CAN_SFF_MASK;
		msg.mh.nframes = 0;
		if (write(s, &msg, sizeof(msg.mh)) < 0) {
			fprintf(stderr, "canbind: bcm RX_SETUP %d: %s\n", i,
				strerror(errno));
			close(s);
			return 1;
		}
	}
	fprintf(stderr, "canbind: bcm bound to %s (%d subs), holding\n",
		ifname, nsub);
	while (!stop)
		pause();
	close(s);
	return 0;
}

static void usage(const char *p)
{
	fprintf(stderr,
"usage: %s [-p raw|isotp|bcm] [-i ifname] [-I ifname2]\n"
"          [-f nfilters] [-L] [-t seconds]\n"
"\n"
"  -p proto     protocol for hold mode (default raw)\n"
"  -i ifname    interface to bind (default vcan0)\n"
"  -I ifname2   second interface for -L rebind load (default vcan1)\n"
"  -f nfilters  raw/bcm filters, max %d (default %d)\n"
"  -L           load mode: rebind raw socket between -i and -I\n"
"  -t seconds   load duration, 0 = until signal (default 10)\n"
"\n"
"Exit: 0 ok, 1 error, 2 protocol unsupported (module not loaded).\n",
		p, CAN_RAW_FILTER_MAX, CAN_RAW_FILTER_MAX);
}

int main(int argc, char **argv)
{
	const char *proto = "raw";
	const char *if1 = "vcan0";
	const char *if2 = "vcan1";
	int nfilters = CAN_RAW_FILTER_MAX;
	int load = 0;
	double seconds = 10.0;
	struct sigaction sa;
	int c;

	while ((c = getopt(argc, argv, "p:i:I:f:Lt:h")) != -1) {
		switch (c) {
		case 'p': proto = optarg; break;
		case 'i': if1 = optarg; break;
		case 'I': if2 = optarg; break;
		case 'f': nfilters = atoi(optarg); break;
		case 'L': load = 1; break;
		case 't': seconds = atof(optarg); break;
		case 'h': usage(argv[0]); return 0;
		default: usage(argv[0]); return 1;
		}
	}

	if (nfilters < 0 || nfilters > CAN_RAW_FILTER_MAX) {
		fprintf(stderr, "canbind: nfilters out of range 0..%d\n",
			CAN_RAW_FILTER_MAX);
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sig;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (load)
		return run_load(if1, if2, nfilters, seconds);

	if (!strcmp(proto, "raw"))
		return hold_raw(if1, nfilters);
	if (!strcmp(proto, "isotp"))
		return hold_isotp(if1);
	if (!strcmp(proto, "bcm"))
		return hold_bcm(if1, nfilters);

	fprintf(stderr, "canbind: unknown proto '%s'\n", proto);
	return 1;
}
