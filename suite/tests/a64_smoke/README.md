# AArch64 real-workload smoke gate

Most AArch64 DR bugs found while running Seedbox (JIT'd runtimes under DR with a
deterministic-replay "progress" client) showed up only with two conditions together:
a client that instruments every block the way Seedbox's does, and the application
pinned to one CPU.  The property tests in `../a64_prop/` check DR's contracts one at a
time; this gate runs small real programs under exactly those conditions, so a change
that breaks them fails here before it reaches Seedbox.

Each test runs its workload natively first (the oracle), then under

    taskset -c 0 drrun -opt_speed -disable_traces -ldstex2cas \
        -no_hw_cache_consistency -fake_ctr_dic \
        -c libclient.a64_progress_like.dll.so \
        --instructions-per-progress-call BUDGET --progress-points-per-block 1 -- WORKLOAD

and passes when both runs exit 0, the native output ends in `ok`, and the output under
DR is identical to the native output (`run_smoke.sh`).  The workloads check their own
results (each concurrent computation is redone sequentially, every count printed is
fixed by the arguments), so the output does not depend on timing.

| Test | Workload |
| --- | --- |
| `a64_smoke.go.b*` | `go/main.go`: goroutines on one P, the collector with a 5% heap goal and finalizers, stack growth and copying, asynchronous preemption, `os/signal`, and 96 child processes (each a fresh Go runtime start under DR) |
| `a64_smoke.python.b*` | `gil_threads.py`: CPython threads handing the GIL over every 200 µs, with a condition-variable ping-pong |
| `a64_smoke.c_flush.b*` | `jit_signals.c flush`: a thread rewrites and calls code while workers run register-heavy loops and take `tgkill` signals |
| `a64_smoke.c_jit.b*` | `jit_signals.c jit`: writers rewrite and flush `movz; ret` slots that executors call under a SIGUSR1 stream, while a mapper maps, runs and unmaps code pages |
| `a64_smoke.c_exclusive.b*` | `jit_signals.c exclusive`: `ldxr`/`stxr` increments across flushes and signals must come out exact |

Each test exists once per budget in `A64_SMOKE_BUDGETS`.  By default, so as not to
lengthen CI, only a release build defines the tests, at Seedbox's own budget (50000),
with one run under DR per workload.  Configure with `-DA64_LONG_TESTS=ON` for the full
gate: budgets `1000;50000` (the small one stresses the progress clean call), two or
three runs under DR for the workloads whose failures were intermittent, and the
tests in debug builds too.  The client is
`../client-interface/a64_progress_like.dll.c`; see its header for the options.

The Go and Python tests need `go` and `python3` at configure time; without them the
tests are still listed and report themselves skipped.  Java is left out: the JIT stress
tests cover HotSpot.

## Running it

From a build directory configured with `-DBUILD_TESTS=ON` on AArch64 Linux:

    ninja a64_smoke_tests
    ctest -L a64_smoke --output-on-failure

By default this takes about a minute and a half in release; with `A64_LONG_TESTS`,
about five minutes in release and about seventeen in debug.  Logs of every run (native and under
DR, stdout and stderr) are kept in `suite/tests/a64_smoke/logs/` in the build
directory.  To run one workload by hand, take its command from `ctest -V -N -R NAME`.

What it has caught: with the drreg app-value load marks of ff2e7b30d but without
9961d0a7c's fix to the state-restoration walk, `a64_smoke.go.b1000` (an `A64_LONG_TESTS` test) fails (Go child
processes die with `fatal error: unlock of unlocked lock`, the failure Seedbox saw);
it passes with the fix.
