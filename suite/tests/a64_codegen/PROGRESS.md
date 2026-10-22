# Codegen speed-up work: progress notes

Branch `claude/codegen-speed`, from master 25842b959, 2026-10-15. Scope agreed: (1) DR block building and (2) the speed and size of instrumented code, with benchmarks plus guards. Running the tests is covered in README.md here; this file records what was done, what was measured, and what to do next.

## Done

- **`api.a64_codegen_ir`** (`suite/tests/api/a64_codegen_ir.c`): IR benchmarks and guards.
  - Benchmarks for decode, encode, flags of a new instruction, and decode+encode+compare, over libc's text.
  - Guards over libc plus 1M random words: round trip, encoding of a newly built instruction, and flags agreement.
- **`api.a64_codegen_build`** (`suite/tests/api/a64_codegen_build.c`): builds and runs chains of 4000 distinct 8-instruction blocks under static DR.
  - Covers 5 client modes × 2 option sets (`default`; `seedbox` = the a64_smoke options).
  - Benchmarks: build cost per block, execution cost per block, code-cache bytes per block.
  - Guards:
    - **result:** the output matches the native run.
    - **fragments:** every block has a fragment, and the basic block count rose accordingly.
    - **size:** code-cache bytes per block stay within budget. This ratchets: a decrease asks for the budget to be lowered.
    - **verbatim:** each application instruction is in its fragment bit for bit, at an address that `dr_app_pc_from_cache_pc()` translates back to its own pc.
- Wiring: `suite/tests/a64_codegen/a64_codegen.cmake` is included on AArch64 Linux. The tests carry ctest label `a64_codegen`, and target `a64_codegen_tests` builds them.
- **Verified:** both tests pass on release and debug DR in the Fedora 44 aarch64 Lima VM (Apple Silicon host, gcc 16.2). Release takes about 1s + 10s; debug about 2s + 2min. Code sizes are identical between release and debug, so the budgets apply to both.

## Smaller out-of-line clean calls (next step 3, branch `claude/cg-ccshrink`)

A clean call whose callee DR cannot analyze, such as the progress refill that calls `dr_redirect_execution()`, saves the whole context out of line (`clean_call_save`/`clean_call_restore` gencode). On AArch64 each call site still swapped stacks inline and loaded the routines' addresses with MOVZ/MOVK, so a site cost 27 instructions besides the callee's arguments and call. Now the two routines do the whole switch, stack swap included, and a site is down to 7:

    save:    str x30, [x28, #clean_call_x30]      ; app x30 through a TLS slot
             ldr x30, [x28, #clean_call_save]     ; routine address from TLS
             blr x30
             (ldr x30, [sp, #x30]                 ; only if an argument reads x30)
    restore: ldr x30, [sp, #x28]                  ; TLS base from the saved mcontext
             ldr x30, [x30, #clean_call_restore]
             blr x30
             ldr x30, [x28, #clean_call_x30]

What the callee and the app see is unchanged: the same `priv_mcontext_t` on DR's stack, the app SP in the mcontext's xsp slot, the same scratch slots (TLS_REG0_SLOT and the mcontext's x0) plus one new DR-only TLS slot for x30. The `DR_NOTE_CALL_SEQUENCE_START/END` region for translation now covers only the instructions between the save's return and the restore's call (see "Review follow-up" below). The routines keep their return address in x30 throughout, so a signal arriving in them still finds the fragment (`find_next_fragment_from_gencode()`). The restore takes the TLS base from the saved mcontext rather than the stolen register, because a callee need not preserve it (client.cleancall-opt-1's `out_of_line` callee clobbers every GPR, and caught the first version that used x28 there). Inline (partially saved) clean calls and other architectures are unchanged.

| mode | bytes/block before | after |
| --- | --- | --- |
| progress | 288.0 | 208.0 |
| progress4 | 774.1 | 454.1 |
| cleancall | 316.0 | 316.0 (its analyzable empty callee gets a partial inline save, which this does not change) |

That is 80 bytes per charge point. The budgets are lowered to match. Execution timings were within the VM's noise.

Remaining bytes in a charge point that are not clean-call machinery: drreg emits the scratch register's app-value load twice after the call (once for `drreg_get_app_value()`, once for the lazy restore at unreserve), 4 bytes per point.

### Review follow-up (Codex's review, then merged with master)

- **TLS layout.** The three new `spill_state_t` slots moved the IBL tables that follow it from offset 224 to 248, so the return lookup's mask (248) and table pointer (256) straddled a 64-byte line: every return lookup touched two TLS lines. `spill_state_t` is now padded to 256 bytes, which puts all three mask/table pairs in the first 48 bytes of one line; `asm_offsets.c` asserts that the tables follow the spill slots at a multiple of the pair size. Offsets used by the assembly (`spill_state_t_OFFSET_*`) and every other TLS slot are unchanged; the IBL and client slots derive theirs from the structures.
- **Translation at the new boundaries.** `client.a64_cleancall_ool` (`suite/tests/client-interface/a64_cleancall_ool.c`) forces clean calls out of line (plain, ten arguments with x30 in a register and a stack position, a READS|WRITES callee that changes x30, SP, the stolen register, x5, NZCV and V3 with `dr_set_mcontext()`, the same with `dr_redirect_execution()`, a call skipped by a meta CBZ, and an app fault right after the call) and checks the whole state after each. Its `sweep` mode ptraces the app thread and, at every instruction from the call site through both routines (151 for a returning call; 147 before this branch), delivers a SIGUSR1 (which must reach the app once, at the block's end, with the call's result) or lets a pending `dr_suspend_all_other_threads_ex()` signal arrive (the suspension must retry or give exactly the state before or after the call). `stress` adds a 50 µs timer and a suspending thread to plain runs. With the translations DR computes from a rebuilt instruction list, every point already passed. With `DR_EMIT_STORE_TRANSLATIONS` (`sweep store`), where the call's region is a flag on the stored entries, it failed on this branch as reviewed, and on master's inline switch too, in two ways, both fixed:
  - `translate_restore_clean_call()` took the context from `dr_get_mcontext_priv()`, which for a suspended thread being read with `dr_get_mcontext()` returns the client's cached context while this very translation fills it, i.e. the untranslated registers (x30 holding `clean_call_save`'s address at the site's BLR; the callee address in x11 inside the region), and takes the stolen register's value from the translating thread's TLS. It now reads the thread's own frame on the dstack, SP from its mcontext and the stolen register from its TLS.
  - The region started before the save, so at the three instructions before it the frame was an earlier call's (x0 was 0: i#4219). An out-of-line site's region now starts after the save returns and ends before the final load of x30: outside it, a synch is refused and retries.
  Each fix alone still failed; both together pass. (`recreate_app_state_from_ilist()` skips zero-length instructions before the walk sees them, so the region's labels never set `in_clean_call` there: that path refuses a synch anywhere in a clean call. Left as is.)
- **Returning out-of-line calls.** `api.a64_codegen_build` has a new `cleancall_ool` mode: an empty callee forced out of line (`DR_CLEANCALL_ALWAYS_OUT_OF_LINE`) at each block start, which returns. The review noted that the shrink moves work into the shared routines and adds memory traffic on the returning path: 4 more instructions are executed per call (151 vs 147).

Measured on the merged tree (release, `default` options, busy VM; "master" is master's core with this branch's tests):

| mode | bytes/block master → here | exec ns/block, 3 runs, master → here |
| --- | --- | --- |
| progress | 288.0 → 208.0 | 7.6–10.0 → 3.7–3.8 |
| progress4 | 774.1 → 454.1 | 14.4–16.0 → 9.9–12.9 |
| cleancall | 316.0 → 316.0 | 12.3–15.6 → 13.7–14.3 |
| cleancall_ool | 244.0 → 164.0 | 34.9–38.5 → 35.7–41.3 |

The same in the `seedbox` option set. KSTATS ticks per built block (41.7 ns each; `-scale 40000`, 3 interleaved runs, release `-DKSTATS=ON`):

| mode | bb_building | client | mangling | emit | build ns/block |
| --- | --- | --- | --- | --- | --- |
| progress | 225–235 → 173–180 | 86–93 → 71–73 | 28–31 → 21–22 | 73–79 → 50–55 | 10.2k–10.8k → 8.0k–8.5k |
| progress4 | 622–653 → 380–401 | 244–259 → 168–177 | 85–90 → 52–54 | 217–235 → 113–121 | 27.7k–28.5k → 17.3k–17.9k |
| cleancall_ool | 181–203 → 133–139 | 65–72 → 51–53 | 25–27 → 17–18 | 60–70 → 38–40 | 8.7k–9.7k → 6.4k–6.6k |

The returning call's execution cost is within the noise. The client step shrinks too: the clean call's instructions are created while it inserts the call. An indirect-branch microbenchmark (a BLR to one of 512 functions, its RET, and a switch's BR per iteration; drrun, 7 interleaved runs, median ns per iteration) shows no difference between master, this branch without the TLS padding, and with it: 36.8, 36.5 and 35.6 hot; 51.3, 51.0 and 51.6 with 8 random loads from 64 MB per iteration to evict the TLS lines.

## Baselines (release DR, VM on Apple Silicon)

These are single-run numbers. Expect roughly ±10% between runs.

IR, ns per instruction over the 365k libc instructions the host can encode:

| decode | encode | eflags_new | reenc_check |
| --- | --- | --- | --- |
| 38 | 25 | 90 | 58 |

Blocks, per block of 8 instructions plus a CBNZ:

| mode | build ns/block | exec ns/block | bytes/block |
| --- | --- | --- | --- |
| dr | 2,500 | 2.9 | 124 |
| bbhook | 8,300 | 2.9 | 124 |
| progress | 14,500 | 8.1 | 288 |
| progress4 | 29,700 | 12–14 | 774.1 |
| cleancall | 16,500 | 12.3 | 316 |

The `seedbox` option set is within noise of `default` for every mode.

## What the numbers already say

1. **Just having a bb hook triples block-building cost** (2.5 → 8.3 µs/block), before the client inserts anything. The extra work is full decode plus translation recording (`record_translation`) plus drmgr's passes. This is the biggest fixed cost Seedbox pays and the first place to look.
2. **The progress client adds about 6 µs/block on top of that**, and each extra charge point about 5 µs. The clean-call machinery dominates both the time and the size: 288 → 774 bytes going from 1 to 4 points. The refill callee calls `dr_redirect_execution`, so the clean-call analysis bails out, and every point gets the full out-of-line save/restore sequence (about 30–45 instructions per site).
3. **Decode costs about 1.5× encode**, and `eflags_new` (≈ encode + full decode + heap) costs about 3.5× encode. On AArch64, `decode_eflags_usage()` does a full `decode_common()` (XXX i#2374). drreg asks for flags on the meta instructions it sees.
4. **The emit-time re-encode check** (`copy_and_re_relativize_raw_instr`, a fork change) costs about 58 ns for every app instruction. Next to 2.5 µs for a whole block that is small: under 20% of `dr`-mode build time for 8-instruction blocks.

## Scaling survey and fixes (branch `claude/cg-bench2`)
The free-list bug (62f76c5f4) made emit's cost per block grow with the size of the code cache, and the benchmark's best-of-reps build time hid it. `api.a64_codegen_build -scale N` now builds N distinct blocks per configuration and reports the cost per block of each bucket of them, and `api.a64_codegen_scale` guards it (README.md has the details). The guard fails with 62f76c5f4 reverted: progress costs 29, 51 and 71 µs per block in buckets of 100k. The ctest also flushes lines of a JIT-like mapping and fails if a flush takes more than 1000 blocks with it, a count that does not depend on timing; with `-sw_flush_granule 0` (fix 2 below undone) it fails at 25–30k blocks per flush.
The free-list bug (62f76c5f4) made emit's cost per block grow with the size of the code cache, and the benchmark's best-of-reps build time hid it. `api.a64_codegen_build -scale N` now builds N distinct blocks per configuration and reports the cost per block of each bucket of them (README.md has the details). Its timing guard (`-scale-guard`) fails with 62f76c5f4 reverted: progress costs 29, 51 and 71 µs per block in buckets of 100k. That guard needs a quiet machine, as a slowdown of a whole bucket fails it too, so the ctest `api.a64_codegen_scale` adds it only with CMake's `A64_CODEGEN_TIMING_GUARD`. What the ctest gates on does not depend on timing: it flushes lines of a JIT-like mapping and fails if any one flush makes more blocks build again than twice a `-sw_flush_granule` region holds (214 with 4K pages); with `-sw_flush_granule 0` (fix 2 below undone) it fails at 25–30k blocks per flush. `api.a64_codegen_patch` checks that patched code never runs stale (README.md).


### Survey

Release build in the shared VM, thread CPU time per built block (ns), first and last bucket. "Flat" means within about 10%, which is the noise between runs on this machine.

| Structure | How it was exercised | Result |
| --- | --- | --- |
| Shared bb cache, fcache units, fragment hashtable resizing, heap | `dr`, 1M blocks, `default` and `seedbox` options (124 MB of cache) | Flat: 2772 → 2947 and 2805 → 2967 |
| Thread-private caches (`-thread_private`, cache resizing) | `dr`, 1M blocks; `progress`, 400k | Flat: 2699 → 2854; 15592 → 16207 |
| Heap free lists under a client (drreg, clean calls) | `progress`, 400k, `default` | Flat: 16297 → 15946 |
| Writable (JIT-like) code | `dr`, 500k, `-layout rwx`, both option sets | Flat: 2924 → 3067; 3163 → 3166 |
| Traces | `dr`, 100k, `-ops traces` (every block a trace head) | Flat: 17869 → 20953 (1.12x; most of it is the 52 runs' trace-head exits) |
| Incoming-link lists, building | `dr`, 300k, `-layout hub` (one target with an incoming link from every block) | Flat: 2824 → 2678 |
| Incoming-link lists, flushing | `-layout hub,rwx -flushes 8`, `seedbox` (a hub per chain: fan-in 10k) | **Grew** with the hub's list: each deleted block walked it to remove its link. Fixed (below) |
| Incoming-link lists and ibl tables, flushing, growing fan-in | `-layout onemap,rwx,fanin -flushes 8`, `seedbox`, 400k (one stub that every block calls: fan-in 100k → 400k) | **Grew** with the fan-in: 13.4, 30.5, 44.2 and 58.3 ms per flush without fix 3; 0.42, 1.05, 1.35 and 2.07 ms with it, all in a walk of the whole ibl table. Fixed (below): 68–79 µs, flat |
| Many fragment-list regions: building, and flushing a whole range | `-layout onemap,rwx,perpage -range-flush`, `seedbox`, 32k blocks on 32k pages | **Grew**: 8.6 → 29.9 µs per block building (a linear scan per new region); a flush of every line 430 ms, a line per page 1145 ms, the munmap 247 ms (a search from the start of the vector per region removed). Fixed (below) |
| Inserting regions before all the others | the same, `-descending` | **Grows**: 7.1 → 24.3 µs per block (shifting the sorted vector); flat with `-sw_flush_granule 64K`. Not fixed (below) |
| vmarea lists and the module check | `dr`, 500k, `-layout sparse` (4900 mappings) | **Superlinear**: 24200 → 11085, all of it in reading /proc/self/maps for each new region. Fixed (below) |
| `-no_hw_cache_consistency` IC IVAU flushes | `dr`, `-layout onemap,rwx -flushes 5`, `seedbox` | **Grew** with the cache: a flush of one line deleted every fragment of the line's mapping. Fixed (below) |
| Coarse units | | Not applicable: `-coarse_units` is not implemented on AArch64 (i#1575) |

Notes:
- The fragment hashtables double, so a resize lands in one bucket. The medians of chains show no step.
- vmarea vectors are sorted arrays. Adding an area shifts the ones after it, and DR's memmove copies a byte at a time when moving up (a memmove instead of the element loop measured the same). Appending, as a JIT's code heap mostly grows, shifts nothing.
- With hardware cache consistency (the default options), a write to writable code also flushes the whole mapping (10k blocks per flush in `-layout rwx`). The fix below is only for `-no_hw_cache_consistency`, which is what Seedbox uses.

### Fixes

1. **Region queries read all of /proc/self/maps.** `check_thread_vm_area()` calls `os_check_new_app_module()` for each region new to it, which asks the OS about the region (i#1760) by reading and parsing the maps file up to it. In the sparse layout, each new region cost about 1.8 ms at first, and less as the regions above it were used. `memquery_from_os()` now asks with the PROCMAP_QUERY ioctl (Linux 6.11+) and reads the file only when the kernel lacks it or the address is in no region. Sparse layout: 24200 → 3919 ns per block in the first bucket, flat after. The contiguous layout is unchanged. This also matters after every software-consistency flush: the flushed region is new again to the next block built in it.
2. **A flush of one line deleted a whole mapping's fragments.** Without hardware cache consistency the app flushes code with IC IVAU, and a flush deletes every fragment on the fragment list of each region it overlaps. Those regions were whole (merged) executable areas, so one line of a JIT's code cache flushed all of it, at a cost that grew with the cache: 9.8 → 22 ms per flush in `-layout onemap,rwx`, rebuilding 20k blocks per flush. Now, without hardware cache consistency, the fragment-list regions of code other than unmodified images are at most `-sw_flush_granule` bytes (default 4 KB, at least a page), aligned; a block that crosses a boundary is on both lists, as blocks crossing regions already were. The same probe costs 70 µs per flush and rebuilds about 105 blocks, flat. Building 1M blocks in one mapping (10k regions) costs the same as before within the noise.
3. **Removing an incoming link walked the target's list.** With flushes that small, the next cost was in `incoming_remove_link()`: each deleted block searched its exit targets' incoming lists for its link, and a block that many others branch to (the hub; a JIT's runtime stubs) has a list as long as the number of blocks. A direct linkstub now records where its predecessor on the list is, as a 4-byte offset in padding it already had (so no memory is added), and removal checks it against the list and unlinks in O(1); it falls back to the walk if the offset is unknown or wrong, and on 32-bit builds. Hub layout, 400k blocks, 8 flushes per bucket, interleaved runs: 4.3–5.3 ms → 57–73 µs per flush, flat. Peak RSS is the same (159 MB), and building costs the same within the noise. The offset is an invariant every change to a list maintains (the removal reads the entry it points to), checked in debug builds at each change.
4. **Flushes of many regions were quadratic** (Codex's review of fix 2). Each flush's areas were removed one by one with `remove_vm_area()`, which searches the vector from its start, and each flush walked the whole vector for the areas it overlaps; `add_vm_area()` also scanned from the start, the vector grew by 100 entries at a time, and a shared flush queued a pending-deletion entry per area. Now the overlapping areas are found by binary search and removed with one shift, `add_vm_area()` starts at the first area that can touch the new one, vectors grow by half, and a flush queues one pending entry. `-layout onemap,rwx,perpage -range-flush`, 32k blocks on 32k pages: building 8.6 → 29.9 µs per block before, 4.9 µs flat after; a line per page 1145 → 463 ms; every line 430 → 207 ms; the munmap 247 → 15 ms.
5. **Each synch-all flush walked every ibl table** (found with the fan-in layout). `flush_fragments_synchall_start()` removed the ibl entries of every tag in the flushed executable area by walking each table, and so cost the size of the table: every return point of a JIT's code. The walk is there for coarse-grain fragments, and, as Codex's second review pointed out, for traces that `-bb_ibt_table_includes_traces` puts in the bb tables too, which removing a fragment from its own tables does not reach, and for mixed sharing of the bb and trace tables. It is now skipped only without `-coarse_units` and without traces (AArch64's defaults, and Seedbox's options): then only the bb tables hold targets, and each fragment is removed from every one that can hold it as it is deleted. Fan-in layout (Seedbox's options): 0.42 → 2.07 ms per flush as the table grew, now 68–79 µs flat. `api.a64_codegen_ibl` covers it with and without traces; it did not reproduce a stale trace entry with the walk skipped unconditionally, so the narrowing rests on reading the code.

`-no_procmap_query` turns off fix 1's ioctl (`-procmap_query` is on by default), for a seccomp filter that would kill or trap it rather than let it fail.

### Where the time per built block goes now

perf `cpu-clock` profiles of `-scale` runs (200k blocks; 60k for `progress4`), `seedbox` options, with all three fixes. The shares are of the samples under `build_basic_block_fragment()`, which is 77% of all samples in `dr` mode (the rest is mostly the test making its chains) and 92–97% in the others.

| Mode | client | decode | mangle | emit | freeing the ilist | other |
| --- | --- | --- | --- | --- | --- | --- |
| dr | — | 17% | 18% | 37% | 4% | 24% |
| bbhook | 65% | 6% | 5% | 13% | 1% | 10% |
| progress | 52% | 3% | 10% | 20% | 3% | 12% |
| progress4 | 44% | 2% | 14% | 26% | 6% | 8% |

- The client share is drreg's liveness analysis (`instr_writes_to_exact_reg()`, `opnd_uses_reg()`, `instr_reg_in_src()`, `instr_get_predicate()`, `drvector_set_entry()` lead the self time), which `claude/cg-drregcost` addresses. Emit and mangling grow with the clean-call code, which `claude/cg-ccshrink` shrinks.
- In `dr` mode, emit is i-cache maintenance (`clear_icache()`, 8% of block building: one IC IVAU sequence for the new fragment and one for each incoming link patched), future fragments for unbuilt exit targets (about 8%: a lookup, a heap allocation and a hashtable add for each exit, and a lookup and free when the target is built), and encoding exit stubs. Mangling is a dozen predicate calls on every instruction (`instr_get_rel_target()` alone is 15% of it, copying operands one by one), and decode is `decoder_v80()`.
- None of these is a single large cost. The i-cache syncs must stay in order with the patches they cover, so merging them is not safe for other threads.

### Found and not fixed

- **A pre-existing intermittent assert in debug, with signals and flushes:** `link.c:1786 "fake fragment_t has no exit stubs!"` from `client.a64_prop_cleancall drreg`'s `nohwcc-progress*` variants (about 1 run in 4 with `-n 40` under load). It also happens on 187084747, before any of the fixes above: 2 of 8 seeds. `info->interrupted` (signal.c) records the fragment a delayed signal arrived in, so it can be relinked when the signal is delivered. Nothing clears it when that fragment is flushed in between, and `dispatch_enter_dynamorio()` handles an IC IVAU flush before `dispatch_exit_fcache()` delivers the signal. The related `link.c:637` assert (`a64_prop_flush`'s `reset_all` variant: `last_exit` not among `last_fragment`'s exits) was seen once on 187084747 as well.
- **Traces of writable code with shared bb ibl tables trip a debug assert**, `monitor.c:584 TESTANY(FRAG_SHARED, f->flags)` in `unlink_ibt_trace_head()` (`api.a64_codegen_build -ibl 10 -ops ibtraces_shared` on debug DR), on 62f76c5f4 as well.
- **Shared bb and private trace ibl tables, with traces in the bb tables, crash** (`api.a64_codegen_build -ibl 1 -ops ibtraces`: SIGSEGV every run), on 62f76c5f4 as well as here, with or without the ibl walk. Not investigated; not the default on any platform.
- **With hardware cache consistency, a write to writable code still flushes the whole mapping** (`-layout rwx -flushes`, default options: 5–12 ms per flush, 10k blocks rebuilt). `-sw_flush_granule` applies only without hardware consistency.
- **Inserting a fragment-list region before all the others shifts the sorted vector**: 7.1 → 24.3 µs per block with 32k regions inserted in descending order (`-layout onemap,rwx,perpage -descending`). A JIT's code mostly goes in ascending order, which appends; a region flushed and built again in the middle shifts half. `-sw_flush_granule 64K` makes the same run flat (3.0 → 3.3 µs), at the cost of about 16 times as many blocks per flush. A structure with cheap inserts (a tree, or a gap) would fix it for good.

## Findings along the way

- **Standalone decoding with the shared `libdynamorio.so` was 20× slower** (830 vs 38 ns/instr). Every IR heap allocation and free takes the global heap's recursive lock. The lock's owner check calls `d_r_get_thread_id()`, which makes a `gettid` syscall when the thread has no DR TLS. Standalone users such as raw2trace and other offline decoders may pay this. It was not seen with static DR standalone. Not investigated further.
- **`instr_get_eflags()` on a new pc-relative instruction encoded it into a DR heap buffer**, where the target can be out of range. Release then answered 0 flags; debug asserted "instr_get_eflags: invalid instr". The guard skipped pc-relative instructions for that reason; there were 72k of them in libc. **Fixed** on branch `claude/cg-eflags`:
  - DR already falls back to encoding without the reachability check (`instr_encode_ignore_reachability()`), as x86 and ARM32 do. On AArch64 every pc-relative operand honoured that except the literal of a load literal (`memlit`: LDR, LDRSW, PRFM), so only those failed. `encode_opnd_memlit()` now encodes an unreachable target as offset 0 when `!di->check_reachable`, like `encode_pc_off()`. The generated encoders pass it `di` (`codec.py`). This also fixes `instr_is_encoding_possible()`, `instr_get_isa_feature()` and disassembly of new load-literal instructions.
  - `instr_get_eflags()` no longer encodes new AArch64 instructions at all (next step 4, below). `codec.py` generates `opcode_eflags.h` from codec.txt's flags field, which the decoder already applies per opcode. `instr_eflags_from_opcode()` adds the operand-dependent mrs/msr cases, which it shares with `decode_common()`. OP_xx and OP_ldstex still take the encode path. Debug DR still encodes and decodes, and asserts the two answers agree.
  - The guard now checks all 72k pc-relative libc instructions (129k of the random words) and adds `instr_is_encoding_possible()`. Before the encoder fix, debug DR hit the assert on the first literal load in libc.
- **About 14% of libc's words decode as `OP_xx`** (59.7k of 428.6k), meaning the decoder doesn't know them. They are counted, not checked.
- **Test-design pitfalls**, written down in README.md:
  - Under static DR, the fragment query APIs deadlock when called from app code. DR's own code runs in the cache, and building its next block waits on the table lock the thread holds. Query after `dr_app_stop()` instead.
  - Client instrumentation must be the same when DR re-instruments a block for translation. A marker cleared after the run made every translation off by the marker's length, and the verbatim guard caught it.
- KSTATS can't give a per-phase breakdown on AArch64 (decode, mangle and emit times), because `proc_get_timestamp()` is unimplemented there and returns 0 (`core/arch/aarch64/proc.c`).

## Next steps

1. **Per-phase timing.** Implement `proc_get_timestamp()` with CNTVCT_EL0, so KSTATS works on a release `-DKSTATS=ON` build (`bb_decoding`, `mangling`, `emit`). Then the 2.5 → 8.3 µs gap can be split between decode, the client step and translation recording.
2. **Cut the bb-hook fixed cost.** Candidates:
   - check what `record_translation` costs for non-faulting blocks;
   - avoid drmgr's per-instruction passes when only one insertion callback is registered;
   - see whether drreg's per-block backward liveness pass (every instruction × every GPR) can stay as is.
3. ~~**Shrink clean-call sites for redirecting callees.**~~ Done: see "Smaller out-of-line clean calls" above. A possible follow-up is to send more clean calls out of line now that an out-of-line site is smaller than any inline save (the `cleancall` mode's empty callee costs 192 bytes inline), which trades speed for size.
4. **Make flags queries cheaper.** Done for new instructions: `eflags_new` went from 90 to 7 ns per instruction (release), an opcode table lookup instead of an encode and a full decode. Still open: `decode_eflags_usage()` on raw bits does a full decode (i#2374); it could decode just the opcode and use the same table.
5. **Possibly add a fault-translation guard to `api.a64_codegen_build`**: a faulting instruction per block, with pc and registers compared to native. The a64_prop tests already cover this property randomly, so it is lower priority.
6. **Run the benchmarks on real hardware** (Seedbox's machines) to get trustworthy absolute numbers. The VM's native time of about 0.45 ns per 10-instruction block suggests the host CPU executes this chain very wide, so treat the exec ratios as rough.
