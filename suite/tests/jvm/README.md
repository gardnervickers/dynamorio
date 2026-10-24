# HotSpot JIT stress for DR

`JitStress.java` makes HotSpot rewrite code constantly while threads fault and
are interrupted in that code; `jitstress.py` runs it under `drrun` and judges
the run.  The target is the window between HotSpot writing code and DR
flushing what it built from the old code: a fault, signal or client redirect
there makes DR translate a thread by decoding the *new* code.

## Scenarios (`-Dscenario=`)

| Scenario | What it churns | Floors (from `-Xlog`) |
|---|---|---|
| `IcNull` | 8 sites, each one non-inlined interface call (`CompileCommand=dontinline`, `TypeProfileWidth=0`): monomorphic, bimorphic and megamorphic receiver phases; a definer thread defines and drops hidden receiver classes and calls `System.gc()` (class unloading cleans inline caches); null receivers fault in the callee's inline cache check (C2 leaves that null check implicit); they wait until C2 has compiled every `icsite` (a non-null warm-up outside the checksum, gated on `Compiler.codelist`) | C2 compiles of all 8 `icsite`s, NPEs dispatched in C2's `icsite` (all of them), class unloads, made-not-entrant |
| `DeoptCycle` | chains of small methods with live longs and a scalar-replaced object, through bursts of unstable_if, range_check, class_check and null_check traps under unlimited-trap flags; a third subclass loaded half way | deopts (`trap_bci=` lines), made-not-entrant, C2 recompiles of `dc1..3` |
| `JfrNpe` | Seedbox's `Jfr` probe "exec 1 npe" (its InlineCacheBuffer crash): JFR execution sampling every 1 ms over implicit null checks, with ZGC | C2 compile of `step`, execution samples |
| `Redefine` | Seedbox's `RedefineWrongMethod`/`RedefineOldFrames`: a hot caller in compiled code while the class is redefined between two versions with threads parked inside it | redefinitions, C2 recompiles of `capture` |

The program needs only JDK 21 language and library features (it compiles
with `javac --release 21`; IcNull's hidden classes are copies of a template
class file), so it can also run as a Seedbox probe on its JDK 21 image.
Every scenario is bounded by operation counts; every result is independent of
scheduling and of which code ran (all receivers compute the same function),
every call is checked against a model in the program (`MISMATCH`), and the
`RESULT` line must equal two native runs and one `-Xint` run.

## Runner

    jitstress.py run --drrun BUILD/bin64/drrun --scenario IcNull --seed 1 \
        [--dr-profile seedbox|default] [--dr-ops '...'] [--cpus 1] \
        [--client BUILD/suite/tests/bin/libclient.a64_progress_like.dll.so --budget 50000] \
        [--ops N] [--threads N] [--jvm '...'] [--repeat N] [--keep]
    jitstress.py smoke --drrun ... --set quick|ic|client [--client ...]
    jitstress.py soak  --drrun ... [--client ...] --minutes 60 --seed0 1000

- DR profiles: `seedbox` = `-opt_speed -disable_traces -ldstex2cas
  -no_hw_cache_consistency -fake_ctr_dic` (elision on, software cache
  consistency: DR learns of code writes only from IC IVAU), `default` = none.
- `--cpus 1` pins the JVM to one CPU (`taskset`; the regime in which Seedbox's
  races became deterministic); `--cpus 2` is the secondary regime.  JVM
  ergonomics are fixed with `-XX:ActiveProcessorCount=2`.
- `--client`: the Seedbox-shaped progress client
  (`client.a64_progress_like.dll`); `--budget` is its
  `--instructions-per-progress-call` (Seedbox: 50000; try 5000 and 500 too).
- References (2 native runs and `-Xint`) are cached under `--work/refs`.
- Verdicts: `PASS`, `SEMANTIC_FAILURE` (RESULT differs or a `MISMATCH`),
  `VM_CRASH` (hs_err, with the fault-pc plausibility check: does the
  instruction at the reported pc access `si_addr` given the registers? an
  `IMPLAUSIBLE` crash points at DR's translation, though hs_err reads the bytes
  after any patch), `DR_FAILURE`, `TIMEOUT` (after `jcmd Thread.print` and
  per-thread `/proc` state into `hang.txt`), `INSUFFICIENT_STRESS` (a floor
  was not reached: not a pass), `CONFIGURATION_ERROR` (a flag was rejected,
  references disagree), `REFERENCE_FAILURE`.
- Every non-PASS prints the run directory (stdout, stderr, `jvm.log`, hs_err)
  and a `REPRO:` line with scenario, seed, DR options, client, CPU count, DR
  commit and the full JVM command line.

## ctest

Label `JVM`, defined only when CMake finds a JDK 25 and Python 3.  By default,
so as not to lengthen CI, there is one test, in release builds only:
`jvm.jitstress_quick` (the `quick` set: one IcNull case under Seedbox's options,
one CPU, 20000 operations; about a minute in a release build, including the native and
-Xint references).  With `-DA64_LONG_TESTS=ON` there are instead
`jvm.jitstress_ic_smoke` (IcNull under Seedbox's options and under DR's
defaults, one CPU) and `jvm.jitstress_client_smoke` (DeoptCycle and IcNull
under the client at budget 50000), 3-7 minutes each in a release build on the
shared VM; a debug build has `jvm.jitstress_ic_smoke` only (about 17 minutes),
as under a debug DR with the client C2 compiles too little to reach the
client set's floors.  A smoke case
below its floors is rerun with another seed, up to twice (HotSpot's code shape varies
between runs).  The C regression for the elided-call window, independent of
HotSpot, is `api.a64_prop_jit_patch` (`api/a64_prop_jit.c`, patch mode).

## Calibration (JDK 25.0.4, release DR, one CPU, Seedbox's options)

IcNull's null receivers used to start after a fixed warm-up, whatever code
`icsite` was in by then: 9 of 80 Seedbox runs, on every DR build, had no NPE
through C2's `icsite`.  Either C2's `icsite` came after the null receivers (on
one CPU the compiler threads can get little time; the NPEs went through C1's
`icsite`), or null receivers reached the interpreted `icsite`, where each
counts a null_check trap, and C2 then compiled an explicit null check with a
preallocated NPE instead of the implicit one.  Now the workers first make
non-null calls, outside the checksum, until `Compiler.codelist` (through the
DiagnosticCommand MBean) shows a C2 `icsite` in use at every site (STATS
`gateSetupMs`, `gateMs`, `gateOps`, `gateC2Sites`; at most `-DgateSecs`, default
120), and `icsite` is compiled in the foreground
(`CompileCommand=BackgroundCompilation`) so that C2's comes soon.  Every NPE
goes through C2's implicit null check, also with the C2 compiler thread at
nice 19.  The MBean server costs about 40 s under DR at startup, and the gate
another 13-26 s.

IcNull is the elided-call (`605b07ebc`) reproducer on JDK 25: at `a4a30e738`
every run crashes within 15-50 s, with or without the client and on 1 or 2
CPUs: `SIGSEGV si_addr 0x8` (the null receiver's klass load in the old
callee's inline cache check, elided into the caller's block) reported at
`~RuntimeStub::Shared Runtime resolve_virtual_call_blob+4`, which is not a
load (fault-pc plausibility `IMPLAUSIBLE`): the call site had been reset to the
resolve stub by inline cache cleaning after class unloading.  It passes on
master, and at `a4a30e738` with `-max_elide_jmp 0 -max_elide_call 0` or with
DR's default (hardware) cache consistency.  JfrNpe (Seedbox's original find,
on JDK 21's InlineCacheBuffer) does not reproduce it on JDK 25.

## Soak

`jitstress.py soak --minutes M` draws scenario, DR profile (2:1 Seedbox),
CPU count (3:1 one CPU) and, with `--client`, client budgets 50000/5000/500,
with consecutive seeds from `--seed0`, until the time is up, and prints a
tally.  Run one soak at a time on a shared machine; keep failing run
directories (`--work/runs`), and rerun a failure's `REPRO:` line with
`--repeat 3` before calling it flaky.
