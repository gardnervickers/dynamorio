# AArch64 codegen benchmarks and guards

These tests measure what DR spends generating code on AArch64. They also pin down what that code must keep doing, so an optimization can be judged on both. Two kinds of code generation are covered:

1. **Block building.** DR decodes the block, the client instruments it (drmgr, drreg), then DR mangles, encodes and emits it.
2. **Instrumented code.** The code a client's instrumentation becomes: charge points, drreg spills and restores, and clean calls.

Each test prints benchmark lines, which are never compared, and fails only on a guard. Guards are deterministic and do not depend on timing.

| Test | What it does |
| --- | --- |
| `api.a64_codegen_ir` | Decode, encode and flags queries over libc's executable text and over pseudo-random words |
| `api.a64_codegen_build` | Builds and runs chains of distinct blocks under static DR, in one child per client mode and DR option set |
| `api.a64_codegen_scale` | The same binary in its scaling mode: whether the cost per block grows as the code cache does |

## Running

From a build directory configured with `-DBUILD_TESTS=ON` on AArch64 Linux:

    ninja a64_codegen_tests
    ctest -L a64_codegen -V        # -V shows the benchmark lines

Release builds take a couple of minutes. To benchmark or investigate, run the binaries directly. `suite/tests/bin/api.a64_codegen_ir -reps 10 -bench-only` gives steadier numbers. `suite/tests/bin/api.a64_codegen_build -modes progress -ops seedbox -blocks 20000` runs one configuration on a bigger chain. Both print usage for unknown arguments. Benchmark numbers from a release build are the ones that matter; debug DR's are dominated by its checks.

## api.a64_codegen_ir

Every application instruction in a block goes through the following IR work:

- It is decoded by `decode_common()`. There is no fast decode on AArch64.
- At emit, it is re-encoded and compared with the live word (`copy_and_re_relativize_raw_instr()`).
- When a client or drreg asks for the flags of a meta instruction, DR looks its opcode up (`instr_get_eflags()`). Debug DR also encodes the instruction and decodes the encoding again, and asserts the two answers agree.

**Benchmarks.** These use the host's CPU features and report the best of `-reps` passes, in ns per instruction, over the libc instructions the host can encode:

| Benchmark | What it measures |
| --- | --- |
| `decode` | `decode_from_copy()` |
| `encode` | `instr_encode_to_copy()` of decoded instructions |
| `eflags_new` | The first `instr_get_eflags()` of a new instruction (made with `instr_build()`, as a client would): an opcode lookup |
| `reenc_check` | Decode, encode and compare |

**Guards.** These run with all CPU features enabled, over libc and over `-random` words:

- `decode_sizeof()` and `decode_next_pc()` agree with decode.
- Every decodable word encodes, and the encoding is the original word or an alias that decodes to the same instruction.
- The same instruction made anew encodes identically, has length 4, and is accepted by `instr_is_encoding_possible()`, which ignores reachability. It gives the same `instr_get_eflags()`/`instr_get_arith_flags()` answer as the decoder recorded, pc-relative instructions included.

Words the decoder does not know (`OP_xx`) are counted, not checked.

The instructions are made with the drcontext of a thread DR has set up (`dr_app_setup()`), as in block building. `-standalone` uses `dr_standalone_init()` instead.

## api.a64_codegen_build

The chain is a sequence of distinct blocks. Each block has `-len` pseudo-random instructions: ALU, flag-setting and flag-reading, movz/movk, loads and stores to a scratch area at x0, all on x1–x17. Each block ends in a CBNZ to the next one. The test runs the chain natively for the expected result and time. It then runs it under static DR in a child per configuration.

**Client modes**

| Mode | What the client does |
| --- | --- |
| `dr` | Nothing; no client events at all |
| `bbhook` | Registers an empty drmgr insertion event, which forces full decode and translation recording |
| `progress` | One charge point per block, in the shape of Seedbox's client (`client-interface/a64_progress_like.dll.c`) |
| `progress4` | Four charge points per block |
| `cleancall` | A clean call to an empty function per block |
| `cleancall_ool` | The same, forced out of line (`DR_CLEANCALL_ALWAYS_OUT_OF_LINE`): DR's `clean_call_save`/`clean_call_restore` routines save and restore the whole context, and the callee returns |

**DR option sets**

- `default`: `-disable_traces`.
- `seedbox`: the a64_smoke options, `-opt_speed -disable_traces -ldstex2cas -no_hw_cache_consistency -fake_ctr_dic`.
- `private`: `-disable_traces -thread_private`, for thread-private caches. Not run by default; pick it with `-ops`.
- `traces`: `-enable_traces`, scaling mode only. The chains are laid out in reverse, so every block is the target of a backward branch and so a trace head, and each chain runs 52 times, past `-trace_threshold`.

`-ops` takes a comma-separated list; `all` is `default,seedbox`.

**Benchmarks**

| Line | What it measures |
| --- | --- |
| `build` | The first run of fresh copies of the chain, minus native time, per block and per instruction. Best of `-reps`, then the first, median and last, then every rep in order. Each copy is built into a bigger code cache than the one before, so a cost that grows with the cache makes later reps dearer, which the best hides: a `note` says so when the last rep costs over 1.5x the first. |
| `exec` | Repeated runs of a built copy, per block, as a multiple of native |
| `size` | Code-cache bytes per block (`dr_fragment_size()`) |

**Guards**

- **result:** every run under DR leaves the same registers and memory as the native run.
- **fragments:** after a build, every block has a fragment, and the basic block count rose by at least the number of blocks.
- **size:** the bytes per block are within `budgets[]` in `api/a64_codegen_build.c`, for the default chain. A change that grows the code must raise the budget on purpose. A change that shrinks it is told to lower the budget, which ratchets the gain in.
- **verbatim:** on a copy built with a marker (the client stores each block's code-cache address to a table), every application instruction is in its fragment bit for bit. It must sit at a code-cache address that `dr_app_pc_from_cache_pc()` translates back to its own application address. This guards encode-at-emit shortcuts and translation recording. It applies to every mode except `dr`, which has no client events to insert the marker.

**Scaling mode (`-scale N`)**

The free-list bug fixed in 62f76c5f4 made emit's cost per block grow with the size of the code cache (127, 374 and 1097 KSTATS ticks per block at 40k, 100k and 340k blocks), and the `build` line did not show it. With `-scale N`, each configuration instead builds N distinct blocks, as chains of `-slice` blocks (default 10000) made before DR starts and run one after another. It reports, for each `-bucket` of them (default N/10):

- the median and mean over its chains of thread CPU time per built block (CLOCK_THREAD_CPUTIME_ID, which counts DR's time on the thread and not other processes'), and
- with a KSTATS build of DR (`-DKSTATS=ON`), each phase's ticks per block: `bb` is `bb_building`, which includes `decode`, `client`, `mangle` and `emit`; `trace` is `trace_building`; `other` is the CPU time outside `bb_building` (dispatch, linking a block in, context switches). The test reads these with `dr_kstat_get()` (`core/stats.c`), which exists only in KSTATS builds and which the test finds with a weak reference, and passes `-kstats` and a temporary `-logdir` itself.

Any metric whose last bucket costs more than `-limit` (1.5) times its first, by more than a floor that keeps noise in small numbers out (300 ns of CPU, 3 ticks), is reported as `GROWS`. With `-scale-guard`, the test fails if the cheapest chain of the last bucket costs more than `-limit` times the median of the first bucket. Noise only adds time, so this does not fail by chance. The ctest `api.a64_codegen_scale` runs 300k blocks in release, modes `dr` and `progress`, Seedbox's options, with the guard. With 62f76c5f4 reverted it fails: progress costs 29, 51 and 71 µs per block in buckets of 100k, and the guard's ratio is 2.05. Debug runs it small, without the guard.

`-layout` (a comma-separated list) lays the code out to exercise structures that the default chains do not:

| Layout | What it does |
| --- | --- |
| `sparse` | Each page of blocks is its own mapping, between inaccessible pages, so DR tracks a region for each |
| `rwx` | The code is writable, as a JIT's |
| `onemap` | All the chains are in one mapping, as a JIT's code cache is |
| `hub` | Each block ends in a CBZ to one block that never runs, and falls through to the next, so the hub's future fragment collects an incoming link from every block |
| `reverse` | The blocks are in reverse order, so each branches backward to the next and is a trace head (forced by `-ops traces`) |

`-flushes K` makes the app invalidate one line in each of K chains after each bucket, as a JIT does after changing code. The chains are spread from the newest to the oldest, as blocks of different ages sit at different places in lists such as the hub's incoming links. Under the seedbox options that is `dc cvau; dsb; ic ivau; dsb; isb`, which DR handles itself (`-no_hw_cache_consistency`). With hardware cache consistency it is a write to writable code (`rwx`), or else an mprotect. The test reports the CPU time of each flush, and how many blocks the flushed chains and the bucket's build again afterward, which is how far the flush reached.

For example:

    api.a64_codegen_build -scale 1000000 -modes dr -ops default,seedbox,private
    api.a64_codegen_build -scale 300000 -modes dr -ops seedbox -layout onemap,rwx -flushes 3

Two things matter if you change the test:

- **The fragment queries run with the thread native**, after `dr_app_stop()` and before `dr_app_cleanup()`. Under static DR, DR's own code runs from the code cache. A lookup made there would take the fragment table lock, and then wait for that same lock when DR builds the lookup's next block.
- **The marker must stay set once it is used.** Translation instruments the block again, and it must produce the same code.
