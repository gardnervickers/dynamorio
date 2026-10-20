/* **********************************************************
 * Copyright (c) 2018-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Public client: prove actual application execution separately in every image
 * and fork child. This measures no guest/progress instrumentation profile. */
#include "dr_api.h"
#include <sys/time.h>
#include <sys/syscall.h>
#include <signal.h>

static app_pc lo[16], hi[16];
static uint segments;
static volatile int *timer_stage,*timer_sample;
static void real_timer(void *dc,dr_mcontext_t *mc) {
    (void)dc; (void)mc;
    int value=0;size_t got=0;
    DR_ASSERT(dr_safe_read((void *)timer_stage,sizeof value,&value,&got) && got==sizeof value);
    if(value==1) { value=2;DR_ASSERT(dr_safe_write((void *)timer_stage,sizeof value,&value,NULL)); }
}
static void sample_timer(void *dc,dr_mcontext_t *mc) {
    void *tag=NULL;
    DR_ASSERT(mc->pc!=NULL);
    (void)dr_where_am_i(dc,mc->pc,&tag);
    int value=1;DR_ASSERT(dr_safe_write((void *)timer_sample,sizeof value,&value,NULL));
}
static bool filter_syscall(void *dc,int nr) { (void)dc;return nr==SYS_setitimer; }
static void post_syscall(void *dc,int nr) {
    (void)dc;(void)nr;static bool once;
    if(!once) { once=true;for(int i=0;i<500000;i++) { dr_mark_safe_to_suspend(dr_get_current_drcontext(),true);dr_mark_safe_to_suspend(dr_get_current_drcontext(),false); } }
}
static int executed_pids[4096];
static app_pc suspend_pc,after_suspend;
/* Only the dedicated queued-clean-call probe exports this marker. Ordinary
 * observer workloads keep their existing callbacks and instrumentation. */
static app_pc queue_probe_pc;
static uint queue_probe_visits;
static volatile sig_atomic_t queue_probe_events,queue_probe_active;
static dr_signal_action_t queue_probe_signal(void *dc,dr_siginfo_t *info) {
    (void)dc;
    if(info->sig==SIGUSR1) {
        DR_ASSERT(!queue_probe_active && !info->blocked);
        queue_probe_events++;
        dr_fprintf(STDERR,"unix-queue-probe: delivered=%u after-return=1\n",queue_probe_events);
    }
    return DR_SIGNAL_DELIVER;
}
/* The observer deliberately has no libc dependency. Use the public Linux
 * syscall ABI for this probe, not an application function or a DR private API. */
static long queue_probe_syscall(long number,long a0,long a1,long a2,long a3) {
#ifdef AARCH64
    register long x0 __asm__("x0")=a0;
    register long x1 __asm__("x1")=a1;
    register long x2 __asm__("x2")=a2;
    register long x3 __asm__("x3")=a3;
    register long x8 __asm__("x8")=number;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory","cc");
    return x0;
#else
    register long r10 __asm__("r10")=a3;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(number),"D"(a0),"S"(a1),"d"(a2),"r"(r10):"rcx","r11","memory","cc");
    return result;
#endif
}
static void queue_probe(void) {
    /* Revisit the same application loop before sending. No application syscall
     * or new application branch follows the send until its handler runs. */
    if(++queue_probe_visits!=4096)return;
    siginfo_t info={0};
    info.si_signo=SIGUSR1;info.si_code=SI_QUEUE;
    info.si_pid=dr_get_process_id();info.si_value.sival_int=77;
    info.si_uid=(uid_t)queue_probe_syscall(SYS_getuid,0,0,0,0);
    queue_probe_active=true;
    DR_ASSERT(queue_probe_syscall(SYS_rt_tgsigqueueinfo,info.si_pid,dr_get_thread_id(dr_get_current_drcontext()),SIGUSR1,(long)&info)==0);
    uint64 pending=0;
    DR_ASSERT(queue_probe_syscall(SYS_rt_sigpending,(long)&pending,sizeof pending,0,0)==0);
    DR_ASSERT(queue_probe_events==0);
    dr_fprintf(STDERR,"unix-queue-probe: queued=1 inside-clean-call=1 delivered-before-return=0 kernel-pending=%u\n",(uint)((pending>>(SIGUSR1-1))&1));
    queue_probe_active=false;
}
static volatile int *waiter_tid;
static app_pc *alias_rx_address,*alias_loop_lo_address,*alias_loop_hi_address;
static size_t *alias_size_address;
static int *alias_transaction_address;
static void suspend_target(void) {
    int target=0;size_t got=0;
    DR_ASSERT(dr_safe_read((void *)waiter_tid,sizeof target,&target,&got) && got==sizeof target && target>0);
    app_pc flush_start=lo[0],loop_lo=NULL,loop_hi=NULL;
    size_t flush_size=(size_t)(hi[0]-lo[0]);
    if(alias_rx_address!=NULL) {
        DR_ASSERT(dr_safe_read(alias_rx_address,sizeof flush_start,&flush_start,NULL));
        DR_ASSERT(dr_safe_read(alias_size_address,sizeof flush_size,&flush_size,NULL));
        DR_ASSERT(dr_safe_read(alias_loop_lo_address,sizeof loop_lo,&loop_lo,NULL));
        DR_ASSERT(dr_safe_read(alias_loop_hi_address,sizeof loop_hi,&loop_hi,NULL));
        DR_ASSERT(flush_start!=NULL && flush_size>0 && loop_lo>=flush_start && loop_hi>loop_lo && loop_hi<=flush_start+flush_size);
    }
    int transaction=0;ptr_uint_t target_flags=0;
    if(alias_transaction_address)DR_ASSERT(dr_safe_read(alias_transaction_address,sizeof transaction,&transaction,NULL));
    DR_ASSERT(transaction>=0 && transaction<=2);
    void **contexts;uint suspended=0,missed=0;bool found=false;
    if(transaction!=2) {
    bool all=dr_suspend_all_other_threads(&contexts,&suspended,&missed);
    for(uint i=0;i<suspended;i++)if(dr_get_thread_id(contexts[i])==(thread_id_t)target) {
        found=true;
        if(alias_rx_address!=NULL) {
            dr_mcontext_t observed={sizeof observed,DR_MC_CONTROL};
            DR_ASSERT(dr_get_mcontext(contexts[i],&observed));
            DR_ASSERT(observed.pc>=loop_lo && observed.pc<loop_hi);
            target_flags=observed.xflags;
        }
    }
    bool resumed=dr_resume_all_other_threads(contexts,suspended);
    DR_ASSERT(all && missed==0 && found && resumed);
    }
    if(transaction==1) {
        dr_fprintf(STDERR,"unix-alias-control: suspend-only=1 alias-pc=1 flags=%x\n",(uint)target_flags);
        return;
    }
    dr_mcontext_t mc={sizeof mc,DR_MC_ALL};
    DR_ASSERT(dr_get_mcontext(dr_get_current_drcontext(),&mc));
    mc.pc=after_suspend;
    DR_ASSERT(dr_flush_region(flush_start,flush_size));
    if(transaction==2)dr_fprintf(STDERR,"unix-alias-control: flush-only=1\n");
    else if(alias_rx_address)dr_fprintf(STDERR,"unix-client: suspended=%d resumed=1 flushed=1 alias-pc=1 flags=%x\n",target,(uint)target_flags);
    else dr_fprintf(STDERR,"unix-client: suspended=%d resumed=1 flushed=1\n",target);
    dr_redirect_execution(&mc);
    DR_ASSERT(false);
}
static void first_thread_execution(void *dc) {
    /* A fork inherits the calling thread's client TLS, while a new thread's
     * field starts empty. Re-arm only this public per-thread witness. */
    dr_set_tls_field(dc,NULL);
}
static void count(void) {
    void *dc=dr_get_current_drcontext();
    if(dr_get_tls_field(dc)!=NULL)return;
    dr_set_tls_field(dc,(void *)1);
    /* CLONE_VM without CLONE_THREAD shares this client allocation with a
     * distinct process. Register the public process ID exactly once per image;
     * a single shared boolean would hide that child's actual execution. */
    int pid=dr_get_process_id();unsigned slot=(unsigned)pid%4096;
    for(unsigned probe=0;probe<4096;probe++,slot=(slot+1)%4096) {
        int seen=__atomic_load_n(&executed_pids[slot],__ATOMIC_ACQUIRE);
        if(seen==pid)return;
        if(seen==0 && __atomic_compare_exchange_n(&executed_pids[slot],&seen,pid,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            dr_fprintf(STDERR,"unix-client: pid=%d executed=1\n",pid);return;
        }
        if(seen==pid)return;
    }
    DR_ASSERT(false);
}
static dr_emit_flags_t block(void *dc, void *tag, instrlist_t *bb, bool trace, bool translating) {
    instr_t *first = instrlist_first_app(bb);
    (void)tag; (void)trace; (void)translating;
    if (first != NULL) {
        app_pc pc = instr_get_app_pc(first);
        if(pc==queue_probe_pc)dr_insert_clean_call(dc,bb,first,(void *)queue_probe,false,0);
        if(pc==suspend_pc)dr_insert_clean_call(dc,bb,first,(void *)suspend_target,false,0);
        for (uint i = 0; i < segments; i++) {
            if (pc >= lo[i] && pc < hi[i]) {
                dr_insert_clean_call(dc, bb, first, (void *)count, false, 0);
                break;
            }
        }
    }
    return DR_EMIT_DEFAULT;
}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)id; (void)argc; (void)argv;
    module_data_t *app = dr_get_main_module();
    DR_ASSERT(app != NULL && app->num_segments <= 16);
    for (uint i = 0; i < app->num_segments; i++) {
        if ((app->segments[i].prot & DR_MEMPROT_EXEC) != 0) {
            lo[segments] = app->segments[i].start;
            hi[segments++] = app->segments[i].end;
        }
    }
    DR_ASSERT(segments > 0);
    queue_probe_pc=(app_pc)dr_get_proc_address(app->handle,"unix_queue_probe");
    if(queue_probe_pc)dr_register_signal_event(queue_probe_signal);
    suspend_pc=(app_pc)dr_get_proc_address(app->handle,"unix_request_suspend");
    after_suspend=(app_pc)dr_get_proc_address(app->handle,"unix_after_suspend");
    DR_ASSERT((suspend_pc==NULL)==(after_suspend==NULL));
    waiter_tid=(volatile int *)dr_get_proc_address(app->handle,"unix_waiter_tid");
    DR_ASSERT((suspend_pc==NULL)==(waiter_tid==NULL));
    alias_transaction_address=(int *)dr_get_proc_address(app->handle,"unix_alias_transaction");
    alias_rx_address=(app_pc *)dr_get_proc_address(app->handle,"unix_alias_rx");
    alias_size_address=(size_t *)dr_get_proc_address(app->handle,"unix_alias_size");
    alias_loop_lo_address=(app_pc *)dr_get_proc_address(app->handle,"unix_alias_loop_lo");
    alias_loop_hi_address=(app_pc *)dr_get_proc_address(app->handle,"unix_alias_loop_hi");
    DR_ASSERT((alias_rx_address==NULL)==(alias_size_address==NULL));
    DR_ASSERT((alias_rx_address==NULL)==(alias_loop_lo_address==NULL));
    DR_ASSERT((alias_rx_address==NULL)==(alias_loop_hi_address==NULL));
    timer_stage=(volatile int *)dr_get_proc_address(app->handle,"unix_timer_stage");
    timer_sample=(volatile int *)dr_get_proc_address(app->handle,"unix_timer_sample");
    if(timer_stage) {
        DR_ASSERT(timer_sample!=NULL);
        dr_track_where_am_i();DR_ASSERT(dr_is_tracking_where_am_i());
        DR_ASSERT(dr_set_itimer(ITIMER_REAL,25,real_timer));
        DR_ASSERT(dr_set_itimer(ITIMER_VIRTUAL,10,sample_timer));
        dr_register_filter_syscall_event(filter_syscall);
        dr_register_post_syscall_event(post_syscall);
    }
    dr_free_module_data(app);
    dr_register_thread_init_event(first_thread_execution);
    dr_register_fork_init_event(first_thread_execution);
    dr_register_bb_event(block);
}
