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
