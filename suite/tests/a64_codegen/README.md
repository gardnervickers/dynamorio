# AArch64 codegen benchmarks and guards

These tests measure what DR spends generating code on AArch64. They also pin down what that code must keep doing, so an optimization can be judged on both. Two kinds of code generation are covered:

1. **Block building.** DR decodes the block, the client instruments it (drmgr, drreg), then DR mangles, encodes and emits it.
2. **Instrumented code.** The code a client's instrumentation becomes: charge points, drreg spills and restores, and clean calls.

Each test prints benchmark lines, which are never compared, and fails only on a guard. Guards are deterministic and do not depend on timing.

| Test | What it does |
| --- | --- |
| `api.a64_codegen_ir` | Decode, encode and flags queries over libc's executable text and over pseudo-random words |
| `api.a64_codegen_ir_shared` | The same with the shared `libdynamorio.so`, in standalone mode, as offline decoders use DR |
| `api.a64_codegen_build` | Builds and runs chains of distinct blocks under static DR, in one child per client mode and DR option set |
| `api.a64_codegen_scale` | The same binary in its scaling mode: whether the cost per block grows as the code cache does, and how far a flush of one line reaches |
| `api.a64_codegen_patch` | The same binary patching a block across a page boundary while other threads run it: no stale code |
| `api.a64_codegen_ibl` | The same binary patching a hot indirect-branch target: no ibl table entry outlives a flush |

## Running

From a build directory configured with `-DBUILD_TESTS=ON` on AArch64 Linux:

    ninja a64_codegen_tests
    ctest -L a64_codegen -V        # -V shows the benchmark lines

Release builds take a couple of minutes. To benchmark or investigate, run the binaries directly. `suite/tests/bin/api.a64_codegen_ir -reps 10 -bench-only` gives steadier numbers. `suite/tests/bin/api.a64_codegen_build -modes progress -ops seedbox -blocks 20000` runs one configuration on a bigger chain, and `-fault-blocks 0` leaves out the faults guard. Both print usage for unknown arguments. Benchmark numbers from a release build are the ones that matter; debug DR's are dominated by its checks.

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

Words the decoder does not know (`OP_xx`) are counted, not checked. The libc corpus is libc's whole executable segment, which also holds its symbol and relocation tables, `.rodata` and `.eh_frame`, so almost all of its `OP_xx` words are data. The `guard libc executable sections` line counts the words and `OP_xx` words of the executable sections alone (`.plt`, `.text`), found from libc's section headers. `-list-xx` prints each `OP_xx` word there with its offset in libc, to compare with `llvm-objdump -d --mattr=+all`.

The instructions are made with the drcontext of a thread DR has set up (`dr_app_setup()`), as in block building. `-standalone` uses `dr_standalone_init()` instead, as `api.a64_codegen_ir_shared` does. Under static DR, standalone mode's global heap is libc's malloc. With the shared library it is DR's own heap, whose lock was costly there (see PROGRESS.md).

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
| `fault` | Time per fault of the built fault chain (see the faults guard): DR's signal delivery and translation, with native's alongside |

**Guards**

- **result:** every run under DR leaves the same registers and memory as the native run.
- **fragments:** after a build, every block has a fragment, and the basic block count rose by at least the number of blocks.
- **size:** the bytes per block are within `budgets[]` in `api/a64_codegen_build.c`, for the default chain. A change that grows the code must raise the budget on purpose. A change that shrinks it is told to lower the budget, which ratchets the gain in.
- **verbatim:** on a copy built with a marker (the client stores each block's code-cache address to a table), every application instruction is in its fragment bit for bit. It must sit at a code-cache address that `dr_app_pc_from_cache_pc()` translates back to its own application address. This guards encode-at-emit shortcuts and translation recording. It applies to every mode except `dr`, which has no client events to insert the marker.
- **faults:** DR's fault translation through each client's instrumentation. A separate chain of `-fault-blocks` blocks (default 324; ctest on debug DR uses 162) has one faulting load or store per block, to a guard page. Every 81 blocks cover each of the 9 positions (before each of the 8 instructions, or before the CBNZ) with each of 9 kinds: `ldr`/`str`/`ldp`/`stp` of GPRs, `ldr` of a Q register, a `str` through sp, and the stolen register x28 as base, data and destination. The blocks of the second and fourth 81 also have the marker, which leaves drreg spills pending a lazy restore at the fault. The chain runs natively, then twice under DR (as DR builds it, then built), with a SIGSEGV handler that records the frame and resumes after the faulting instruction. Every frame under DR must equal the native one: signal, `si_code`, `si_addr`, pc, sp, PSTATE, FAR, ESR, x0–x30, FPSR, FPCR and v0–v31. Only PSTATE.SSBS is masked, because it is not deterministic in a frame even natively. Each fault resumes from its native frame, so a wrong frame is reported once rather than in every later block, and the run's result must still match native's. The guard is part of the default mode, not of the scaling, patch or ibl modes.

**Scaling mode (`-scale N`)**

The free-list bug fixed in 62f76c5f4 made emit's cost per block grow with the size of the code cache (127, 374 and 1097 KSTATS ticks per block at 40k, 100k and 340k blocks), and the `build` line did not show it. With `-scale N`, each configuration instead builds N distinct blocks, as chains of `-slice` blocks (default 10000) made before DR starts and run one after another. It reports, for each `-bucket` of them (default N/10):

- the median and mean over its chains of thread CPU time per built block (CLOCK_THREAD_CPUTIME_ID, which counts DR's time on the thread and not other processes'), and
- with a KSTATS build of DR (`-DKSTATS=ON`), each phase's ticks per block: `bb` is `bb_building`, which includes `decode`, `client`, `mangle` and `emit`; `trace` is `trace_building`; `other` is the CPU time outside `bb_building` (dispatch, linking a block in, context switches). The test reads these with `dr_kstat_get()` (`core/stats.c`), which exists only in KSTATS builds and which the test finds with a weak reference, and passes `-kstats` and a temporary `-logdir` itself.

Any metric whose last bucket costs more than `-limit` (1.5) times its first, by more than a floor that keeps noise in small numbers out (300 ns of CPU, 3 ticks), is reported as `GROWS`. With `-scale-guard`, the test fails if the cheapest chain of the last bucket costs more than `-limit` times the median of the first bucket. That rides out a noisy chain or two, but not a slowdown of the whole last bucket (throttling, a slower core, contention for memory: the shared VM often sits at a load of 50–150), so it is for a quiet machine. With 62f76c5f4 reverted it fails: progress costs 29, 51 and 71 µs per block in buckets of 100k, and the guard's ratio is 2.05.

The ctest `api.a64_codegen_scale` gates on what does not depend on timing. It runs 300k blocks in release, modes `dr` and `progress`, Seedbox's options, with all chains in one writable mapping and every block calling one shared stub (`-layout onemap,rwx,fanin`, as a JIT's code cache), and flushes a line in 4 chains after each bucket with `-flush-limit auto`. Without `-sw_flush_granule` a flush takes every block of the mapping, and the limit fails it. The timing guard is added only when CMake's `A64_CODEGEN_TIMING_GUARD` is on. Debug runs it small.

`-layout` (a comma-separated list) lays the code out to exercise structures that the default chains do not:

| Layout | What it does |
| --- | --- |
| `sparse` | Each page of blocks is its own mapping, between inaccessible pages, so DR tracks a region for each |
| `rwx` | The code is writable, as a JIT's |
| `onemap` | All the chains are in one mapping, as a JIT's code cache is |
| `perpage` | Each block on a page of its own, so a few blocks span many pages (with `-sw_flush_granule`, a fragment-list region each) |
| `hub` | Each block ends in a CBZ to one block of its chain that never runs, and falls through to the next, so each chain's hub collects an incoming link from each of its blocks (the fan-in stays at `-slice`) |
| `fanin` | Each block ends in a BL to one stub shared by all chains (a RET) that returns to the next block, as a JIT's code calls its runtime stubs, so the stub's incoming list grows with every block built (`onemap` only; the flush lines report the fan-in) |
| `reverse` | The blocks are in reverse order, so each branches backward to the next and is a trace head (forced by `-ops traces`) |

`-flushes K` makes the app invalidate one line in each of K chains after each bucket, as a JIT does after changing code. The chains are spread from the newest to the oldest, as blocks of different ages sit at different places in lists such as the hub's incoming links. Under the seedbox options that is `dc cvau; dsb; ic ivau; dsb; isb`, which DR handles itself (`-no_hw_cache_consistency`). With hardware cache consistency it is a write to writable code (`rwx`), or else an mprotect. After each flush the test runs every chain built so far and counts the blocks that build again, which is how far that flush reached; it reports the mean and the most. That count does not depend on timing: `-flush-limit N` fails the test if any one flush is over N, and `-flush-limit auto` sets N to twice the blocks of a `-sw_flush_granule` region (at least a page, read with `dr_get_integer_option()`), plus 8.

`-range-flush` (with `onemap`) ends the run by flushing the whole mapping three ways: a line on each page (a flush per page), every line (DR joins them into one flush), and the mapping's munmap. `-descending` runs the chains from the highest address down, so each new fragment-list region goes before all the others in DR's sorted vectors. With `perpage` these show the cost of flushes and inserts with many regions.

The page size is the host's (`sysconf`), for the layouts and the protection changes.

For example:

    api.a64_codegen_build -scale 1000000 -modes dr -ops default,seedbox,private
    api.a64_codegen_build -scale 300000 -modes dr -ops seedbox -layout onemap,rwx,fanin -flushes 4 -flush-limit auto
    api.a64_codegen_build -scale 32768 -slice 4096 -bucket 8192 -modes dr -ops seedbox -layout onemap,rwx,perpage -range-flush

**Patch test (`-patch N`)**

`api.a64_codegen_patch` checks that code patched as a JIT patches it does not run stale, in two tests, as the architecture allows two ways of patching code other threads run. Both use a block that crosses a page boundary, so it is on the fragment lists of both pages, and invalidate the patched line (`dc cvau; dsb; ic ivau; dsb; isb`). The patching thread must get the new code at once.

- **Phased:** a four-instruction function returns A + B, with the adds on either side of the boundary. An ADD may not be rewritten while another thread may execute it, so patch t (1 to N) waits until every worker has checked t-1 and is waiting, rewrites A or B (alternating) so that the function returns t, and publishes t. Each worker waits for t, synchronizes, calls, must get t, and acknowledges it.
- **Concurrent:** a B on the far side of the boundary, which may be rewritten while other threads execute it, is pointed at one of 64 targets in turn while the workers keep calling. A worker that has seen patch s published must get s or a later one (never an earlier one, never anything else); the patching thread waits for every worker to have checked a patch before making the next.

Every worker checks its first call and every patch, and synchronizes with `ldar; cbnz; isb` in one asm block, so the ISB depends on the loaded patch number at any optimization level. Without the check that a block crossing into another fragment-list region is put on its list (`check_thread_vm_area()`'s stop), every far-side patch runs stale and the test fails. The ctest runs 1000 patches with 3 workers in modes `dr` and `progress`, under both option sets (with hardware cache consistency DR finds the change from the write). Traces are off in both.

**ibl test (`-ibl N`)**

`api.a64_codegen_ibl` checks that no ibl table entry outlives a flush. A function made a trace head (a stub after it branches back to it) is called indirectly until it is hot, from the hot loop and from a block of its own, then rewritten and invalidated (a flush with all threads synched), then the cache is churned with a fresh chain and the function called indirectly again, first from a block outside any trace: it must return the new value. It is a smoke test: nothing checks that the trace is in both the trace and the bb ibl tables at the flush, and it passed with the ibl walk skipped regardless of traces, so it does not cover a trace's bb-table entry outliving the trace (which is why the walk stays on with traces). With `-ops ibtraces_shared` (traces on, in the bb ibl tables too, both table kinds shared; `-no_xl8_code_copy`, as blocks that keep a copy of writable code do not join traces) the function becomes a trace, which the test checks. It also runs under the seedbox options. `-ops ibtraces` (shared bb and private trace ibl tables) crashes in this test, on 62f76c5f4 as well, so the ctest leaves it out; debug DR runs only the seedbox options, as `-ops ibtraces_shared` trips a debug assert there (monitor.c's `unlink_ibt_trace_head()`: a private trace head with shared bb ibl tables), on 62f76c5f4 as well.

Three things matter if you change the test:

- **The fragment queries run with the thread native**, after `dr_app_stop()` and before `dr_app_cleanup()`. Under static DR, DR's own code runs from the code cache. A lookup made there would take the fragment table lock, and then wait for that same lock when DR builds the lookup's next block.
- **The marker must stay set once it is used.** Translation instruments the block again, and it must produce the same code. The fault chain's marker is decided by the block alone and is set before DR starts.
- **The fault chain is entered with every register fixed.** `a64cg_fault_enter()` loads x0–x30, sp, v0–v31, FPSR and FPCR from fixed values. The chain, its data, its stack and its guard pages are mapped before the children fork, so every address in a frame is the same natively and in each child.
