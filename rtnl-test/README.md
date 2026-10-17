# CAN per-device receive-list lock test harness

Verifies the rework that gives `struct can_dev_rcv_lists` its own spinlock
and removes `rtnl_lock()` from the `raw`, `isotp` and `bcm` bind/release
paths (patch *"can: protect the receive lists with a per-device lock"*).

It checks the two things that patch has to get right:

1. **Correctness** — `can_rx_unregister()` must find and remove a socket's
   filters even after the bound device moved to another network namespace.
   The harness churns a bound device between namespaces while releasing the
   socket, across `raw`/`isotp`/`bcm`, and fails if the kernel log shows a
   KASAN report, a `WARNING`/`BUG`, a lockdep splat, or the
   `receive list entry not found` warning.

2. **RTNL decoupling** — the point of the rework. It times an unrelated
   `ip link add/del` while several `CAN_RAW` sockets rebind a full
   512-filter set. Before the rework those rebinds hold RTNL across the
   filter churn, so the probe's max latency spikes; after it they take no
   RTNL and the probe stays near its idle baseline.

## Kernel config

- `CONFIG_CAN_VCAN=m/y`, `CONFIG_CAN_ISOTP`, `CONFIG_CAN_BCM`, `CONFIG_CAN_RAW`
- `CONFIG_PROVE_LOCKING=y` (lockdep) — catches a wrong lock order
- `CONFIG_KASAN=y` — catches the use-after-free directly
- `CONFIG_LOCK_STAT=y` — enables the `/proc/lock_stat` rtnl_mutex row
  (optional; the latency probe works without it)

## Build

```
make -C rtnl-test
```

(`canbind` only needs the CAN uapi headers shipped in `../include`.)

## Run

As root, on the kernel under test:

```
sudo ./run_tests.sh
```

Tunables via environment:

| var       | default | meaning                                   |
|-----------|---------|-------------------------------------------|
| `LOADERS` | 4       | parallel raw rebind loaders               |
| `FILTERS` | 512     | filters per raw socket (`CAN_RAW_FILTER_MAX`) |
| `LOAD_T`  | 15      | seconds of rebind load                    |
| `RACE_T`  | 20      | seconds of namespace churn                |
| `PROBE_N` | 200     | `ip link add/del` iterations per probe    |

Longer `RACE_T` widens the correctness search; a few minutes under KASAN is
a good soak before submitting.

## What a good result looks like

```
== scenario 2: RTNL latency, idle baseline
   rtnl_probe: n=200 min=... avg=... max=180us
== scenario 2: RTNL latency under raw filter-rebind load
   rtnl_probe: n=200 min=... avg=... max=240us        <- close to idle
...
PASS: no kernel defects detected
```

On an **unpatched** kernel the same load phase drives the under-load `max`
far above the baseline (RTNL is held across 512 (un)registrations), and the
`rtnl_mutex` row in `/proc/lock_stat` shows a large `waittime-max`. On the
**patched** kernel the two maxima stay close and the `rtnl_mutex`
contention from this workload disappears.

## Files

| file             | purpose                                                  |
|------------------|----------------------------------------------------------|
| `canbind.c`      | bind helper: raw rebind **load** mode, or **hold** a raw/isotp/bcm socket |
| `run_tests.sh`   | orchestrator for both scenarios + kernel-log scan        |
| `rtnl_probe.sh`  | times `ip link add/del` (RTNL stall probe)               |
| `lockstat.sh`    | reset / show the `rtnl_mutex` rows of `/proc/lock_stat`  |

## Notes

- Everything runs against throwaway `vcan`/`dummy` interfaces and a
  dedicated netns, all removed on exit.
- `isotp`/`bcm` are skipped automatically if the module is missing; `raw`
  is always exercised.
- The harness detects regressions statistically — run it long, ideally
  under KASAN + lockdep, rather than once.
