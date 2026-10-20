/* Public application state at a multi-instruction block entry. No DR internals. */
.text
.p2align 2
.global progress_context_probe
.type progress_context_probe, %function
progress_context_probe:
    sub sp, sp, #1040
    str x0, [sp, #1024]
    str x19, [sp, #800]
    str x20, [sp, #808]
    str x21, [sp, #816]
    str x22, [sp, #824]
    str x23, [sp, #832]
    str x24, [sp, #840]
    str x25, [sp, #848]
    str x26, [sp, #856]
    str x27, [sp, #864]
    str x28, [sp, #872]
    str x29, [sp, #880]
    str x30, [sp, #888]
    stp q8, q9, [sp, #896]
    stp q10, q11, [sp, #928]
    stp q12, q13, [sp, #960]
    stp q14, q15, [sp, #992]
    mov x0, sp
    str x0, [sp, #792]
    mov x0, #0xa0000000
    msr nzcv, x0
    movi v0.16b, #64
    movi v1.16b, #65
    movi v2.16b, #66
    movi v3.16b, #67
    movi v4.16b, #68
    movi v5.16b, #69
    movi v6.16b, #70
    movi v7.16b, #71
    movi v8.16b, #72
    movi v9.16b, #73
    movi v10.16b, #74
    movi v11.16b, #75
    movi v12.16b, #76
    movi v13.16b, #77
    movi v14.16b, #78
    movi v15.16b, #79
    movi v16.16b, #80
    movi v17.16b, #81
    movi v18.16b, #82
    movi v19.16b, #83
    movi v20.16b, #84
    movi v21.16b, #85
    movi v22.16b, #86
    movi v23.16b, #87
    movi v24.16b, #88
    movi v25.16b, #89
    movi v26.16b, #90
    movi v27.16b, #91
    movi v28.16b, #92
    movi v29.16b, #93
    movi v30.16b, #94
    movi v31.16b, #95
    mov x0, #256
    mov x1, #257
    mov x2, #258
    mov x3, #259
    mov x4, #260
    mov x5, #261
    mov x6, #262
    mov x7, #263
    mov x8, #264
    mov x9, #265
    mov x10, #266
    mov x11, #267
    mov x12, #268
    mov x13, #269
    mov x14, #270
    mov x15, #271
    mov x16, #272
    mov x17, #273
    mov x18, #274
    mov x19, #275
    mov x20, #276
    mov x21, #277
    mov x22, #278
    mov x23, #279
    mov x24, #280
    mov x25, #281
    mov x26, #282
    mov x27, #283
    mov x28, #284
    mov x29, #285
    mov x30, #286
    b progress_context_capture
.global progress_context_capture
progress_context_capture:
    /* With budget 1 this block must refill before its first STP. The client
     * must redirect to this application PC with the complete input state. */
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mov x0, sp
    str x0, [sp, #248]
    stp q0, q1, [sp, #256]
    stp q2, q3, [sp, #288]
    stp q4, q5, [sp, #320]
    stp q6, q7, [sp, #352]
    stp q8, q9, [sp, #384]
    stp q10, q11, [sp, #416]
    stp q12, q13, [sp, #448]
    stp q14, q15, [sp, #480]
    stp q16, q17, [sp, #512]
    stp q18, q19, [sp, #544]
    stp q20, q21, [sp, #576]
    stp q22, q23, [sp, #608]
    stp q24, q25, [sp, #640]
    stp q26, q27, [sp, #672]
    stp q28, q29, [sp, #704]
    stp q30, q31, [sp, #736]
    mrs x0, nzcv
    str x0, [sp, #768]
    mrs x0, fpcr
    str x0, [sp, #776]
    mrs x0, fpsr
    str x0, [sp, #784]
    ldr x0, [sp, #1024]
    mov x1, sp
    mov x2, #50
1:
    ldp x3, x4, [x1], #16
    stp x3, x4, [x0], #16
    subs x2, x2, #1
    b.ne 1b
    ldp q8, q9, [sp, #896]
    ldp q10, q11, [sp, #928]
    ldp q12, q13, [sp, #960]
    ldp q14, q15, [sp, #992]
    ldr x19, [sp, #800]
    ldr x20, [sp, #808]
    ldr x21, [sp, #816]
    ldr x22, [sp, #824]
    ldr x23, [sp, #832]
    ldr x24, [sp, #840]
    ldr x25, [sp, #848]
    ldr x26, [sp, #856]
    ldr x27, [sp, #864]
    ldr x28, [sp, #872]
    ldr x29, [sp, #880]
    ldr x30, [sp, #888]
    add sp, sp, #1040
    ret
.size progress_context_probe, .-progress_context_probe
.section .note.GNU-stack,"",%progbits
