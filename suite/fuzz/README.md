# AArch64 IR fuzzers

libFuzzer harnesses for DynamoRIO's AArch64 decoder, encoder, disassembler and
instruction/operand queries.  They link against `drdecode_fuzz`, a copy of the
static decoder library built with ASan/UBSan and with internal `ASSERT`s kept
(the standalone decoder normally compiles them out even in debug builds).

| Harness | Input | Checks |
| --- | --- | --- |
| `a64_decode_fuzzer` | header + raw A64 words | decode never fails (unknown words become `OP_xx`); disassembly stays inside the buffer at every size; operand/instr queries and `instr_compute_address_ex()` (including SVE scatter/gather with a fuzzed machine context and NULL out-params); re-encoding at the same pc, and at a fuzzed pc, either fails cleanly or decodes back to the same instruction |
| `a64_encode_fuzzer` | header + template word + operand mutations | the encoder never silently changes what it was asked to encode: mutated operands (out-of-range immediates, wrong element sizes, W/X swaps, displacements, extends, operand counts, flags) either fail to encode or decode back unchanged; valid requests (an unmutated template, or one with its general-purpose registers renamed) must encode and decode back unchanged; the seed test fails if fewer than `DR_FUZZ_MIN_ENCODED` mutated requests encode (`DR_FUZZ_STATS=1` prints the counts) |
| `a64_semantics_fuzzer` | header + raw A64 words | answers checked against independent models: scalar address computation, `instr_is_mov_constant()`, register-use queries (incl. implicit FFR), memory read/write queries, `reg_{get,set}_value_ex()` bounds and round-trips; x0-x7 come from the input and x8-x30/SP are derived from them (aliases, zero, extensions, top bit), so every base/index register sees non-zero values |

Any sanitizer report, DR internal `ASSERT`, or failed check aborts so libFuzzer
keeps the input.  `CLIENT_ASSERT`s (API usage errors) are findings in the
decode and semantics harnesses, whose inputs can't misuse the API; the encode
harness ignores them by default, as a release build would
(`DR_FUZZ_STRICT_CLIENT_ASSERTS=1` makes them fatal).

## Building and running

Requires an AArch64 Linux host and clang with libFuzzer:

    CC=clang CXX=clang++ cmake -DDEBUG=ON -DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF \
        -DBUILD_CLIENTS=OFF -DBUILD_SAMPLES=OFF -DBUILD_EXT=OFF <src>
    ninja a64_decode_fuzzer a64_encode_fuzzer a64_semantics_fuzzer \
        a64_decode_fuzzer_seeds a64_encode_fuzzer_seeds a64_semantics_fuzzer_seeds
    ctest -R '^fuzz\.'              # seed corpora + regressions, once each
    ./bin64/a64_encode_fuzzer -fork=4 -ignore_crashes=1 -max_total_time=1800 \
        -artifact_prefix=crashes/ corpus suite/fuzz/seeds/a64_encode_fuzzer

`FUZZ_SANITIZER_FLAGS` sets the sanitizers.  With a compiler other than clang
(or `-DFUZZ_ENGINE=replay`) the harnesses link `replay_main.c` instead, which
only runs saved inputs, so the tests still work.

Seed corpora are generated at build time by `make_seeds.py` from the
`suite/tests/api/dis-a64*.txt` test vectors, which cover every opcode the
decoder knows.  `regressions/<harness>/` holds inputs that each found a bug
fixed alongside these harnesses; `fuzz.<harness>.regressions` replays them.

`triage.py HARNESS CRASH_DIR...` replays saved crashes and groups them by
failure site, so a campaign's crashes reduce to a list of distinct bugs.

## Known issues

`DR_FUZZ_KNOWN` (comma-separated, or `all`) tells the harnesses to step around
a known bug so a campaign finds new ones; the names are listed in
`fuzz_common.h`.  They all name bugs that have since been fixed and are kept for
running the harnesses against older trees.  The CTest tests set it from the
`FUZZ_KNOWN_ISSUES` cache variable, which is empty: no known issue is open.
Non-power-of-2 SVE vector lengths (VL 1152, 1280, 1408, 1664, 1792 and 1920),
once stepped around as `sve-vl-non-pow2`, now have `OPSZ_*` values for their Z
and P register sizes and are fuzzed like the others.

## Equivalent representations

The encode harness accepts a few differences that are not encoder bugs, where
the request and the decoded result are the same instruction:

* TBZ/TBNZ on a bit below 32 may name the X or the W register.
* SYS/SYSL operands can spell an operation DR decodes by name (DC, IC...),
  accepted only when the encoding holds exactly the requested op1, CRn, CRm,
  op2 and register.
* A logical immediate's raw N:immr:imms operand is only produced by the
  decoder when the field is non-canonical.
* A scaled index shifted by 0 is the same as an unscaled one.
* Predicates on instructions without a merging/zeroing form decode with no
  /m or /z qualifier, and address-only operands (ADR, ADRP) have no size.

## Spec cross-check

The decoder tables were also checked against Arm's machine-readable A64 ISA
specification and LLVM's disassembler.  Words the specification reserves are
covered as known-undecodable (`xx`) vectors in `suite/tests/api/dis-a64.txt`
and by `test_sve_reserved` in `ir_aarch64_negative.c`, so the existing API
tests guard them.
