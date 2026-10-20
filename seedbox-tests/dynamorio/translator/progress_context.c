/* Public application oracle for the actual progress client, including redirects.
 * This is a focused diagnostic: it does not substitute for managed workloads.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct snapshot {
    uint64_t gpr[31], sp;
    unsigned char simd[32][16];
    uint64_t nzcv, fpcr, fpsr, expected_sp;
};
_Static_assert(offsetof(struct snapshot, simd) == 256, "assembly SIMD offset");
_Static_assert(offsetof(struct snapshot, nzcv) == 768, "assembly flags offset");
_Static_assert(sizeof(struct snapshot) == 800, "assembly snapshot size");
extern void progress_context_probe(struct snapshot *);

int main(void)
{
    struct snapshot state;
    uint64_t fpcr, fpsr;
    __asm__ volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(fpcr), "=r"(fpsr));
    progress_context_probe(&state);
    unsigned bad = 0;
    for (unsigned i = 0; i < 31; ++i) {
        if (state.gpr[i] != 256 + i) {
            fprintf(stderr, "progress-context: x%u expected=%#x actual=%#llx\n",
                    i, 256 + i, (unsigned long long)state.gpr[i]);
            ++bad;
        }
    }
    for (unsigned i = 0; i < 32; ++i) {
        for (unsigned j = 0; j < 16; ++j) {
            if (state.simd[i][j] != 64 + i) {
                fprintf(stderr, "progress-context: v%u byte=%u expected=%#x actual=%#x\n",
                        i, j, 64 + i, state.simd[i][j]);
                ++bad;
            }
        }
    }
    if (state.sp != state.expected_sp || state.nzcv != 0xa0000000 ||
        state.fpcr != fpcr || state.fpsr != fpsr) {
        fprintf(stderr, "progress-context: sp=%#llx expected=%#llx nzcv=%#llx "
                "fpcr=%#llx expected=%#llx fpsr=%#llx expected=%#llx\n",
                (unsigned long long)state.sp, (unsigned long long)state.expected_sp,
                (unsigned long long)state.nzcv,
                (unsigned long long)state.fpcr, (unsigned long long)fpcr,
                (unsigned long long)state.fpsr, (unsigned long long)fpsr);
        ++bad;
    }
    if (bad != 0)
        return 1;
    puts("progress-context: 31 GPRs, SP, 32 SIMD registers, NZCV, FPCR, FPSR preserved");
    return 0;
}
