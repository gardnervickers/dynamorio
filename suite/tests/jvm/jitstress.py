#!/usr/bin/env python3
# **********************************************************
# Copyright (c) 2026 Google, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

"""Runs JitStress.java under DynamoRIO and judges the run (see README.md).

    jitstress.py run   --drrun DRRUN --scenario IcNull --seed 1 [--dr-profile seedbox]
                       [--client SO [--budget N]] [--cpus 1] ...
    jitstress.py smoke --drrun DRRUN --set quick|ic|client [--client SO]
    jitstress.py soak  --drrun DRRUN [--client SO] --minutes 30

Every case: the program is run twice natively and once with -Xint (references,
cached), then under drrun on a pinned CPU set.  Verdicts: PASS,
SEMANTIC_FAILURE, VM_CRASH, DR_FAILURE, TIMEOUT, INSUFFICIENT_STRESS,
CONFIGURATION_ERROR.  Anything but PASS prints a REPRO line.
"""

import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "JitStress.java")

DR_PROFILES = {
    # Seedbox's options: elision, no traces, software cache consistency.
    "seedbox": ["-opt_speed", "-disable_traces", "-ldstex2cas",
                "-no_hw_cache_consistency", "-fake_ctr_dic"],
    "default": [],
}

BASE_JVM = ["-Xmx384m", "-Xss1m", "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash",
            # Fixed ergonomics (GC, compiler threads) whatever the CPU set.
            "-XX:ActiveProcessorCount=2"]

# Unlimited traps: every implicit null check stays a signal, every trap
# deoptimizes and recompiles (Seedbox's "deoptstorm").
DEOPTSTORM = ["-XX:PerBytecodeTrapLimit=1000000", "-XX:PerMethodTrapLimit=1000000",
              "-XX:PerMethodRecompilationCutoff=-1", "-XX:PerBytecodeRecompilationCutoff=-1"]

SCENARIOS = {
    "IcNull": {
        "jvm": ["-XX:CompileCommand=quiet",
                "-XX:CompileCommand=dontinline,*::icsite",
                "-XX:CompileCommand=dontinline,*::f",
                # No receiver or argument profiles: C2 keeps a real virtual call
                # and does not speculate on the receiver (with argument
                # profiling, some runs stopped raising the NPE in icsite).
                "-XX:TypeProfileWidth=0", "-XX:TypeProfileLevel=0",
                # Compile icsite in the foreground (the thread that asks for a
                # compile waits for it): the null receivers wait for C2's icsite
                # (JitStress.java's gate), which then comes soon even when the
                # compiler threads get little CPU (one CPU, Seedbox's scheduler).
                "-XX:CompileCommand=BackgroundCompilation,*::icsite,false",
                "-XX:CompileThresholdScaling=0.05"],
        "ops": 100000, "threads": 4, "c2_target": r"JitStress\$S\d::icsite",
    },
    "DeoptCycle": {
        "jvm": DEOPTSTORM + ["-XX:-OmitStackTraceInFastThrow",
                             "-XX:CompileThresholdScaling=0.05"],
        "ops": 40000, "threads": 3, "c2_target": r"JitStress\$DeoptCycle::dc[123]",
    },
    "JfrNpe": {
        "jvm": ["-XX:+UseZGC"],
        "ops": 300000, "threads": 3, "c2_target": r"JitStress\$JfrNpe::step",
    },
    "Redefine": {
        "jvm": [],
        "ops": 20, "threads": 1, "c2_target": r"JitStressRTarget::capture",
    },
}

# Floors: counts from -Xlog (see count_log) a run must reach, or its verdict is
# INSUFFICIENT_STRESS.  Calibrated on JDK 25.0.4 (release) for the default
# ops; scaled by ops/default (except SITE_FLOORS).
FLOORS = {
    # npe_through_icsite: NPEs dispatched in C2's icsite (OptoRuntime logs each
    # frame it unwinds; C1 and the interpreter do not), i.e. null receivers
    # reaching the callee's inline cache check from C2's code (C2 leaves that
    # null check implicit; the scenario has no other way to raise one there).
    # The null receivers wait for C2's icsite (JitStress.java's gate), so every
    # one counts (100% of ~20K natively and under DR, also with the C2 compiler
    # thread at nice 19); before, 67-100% natively and 0 in 9 of 80 Seedbox runs.
    "IcNull": {"compiles": 200, "c2_icsites": 8, "npe_through_icsite": 15000,
               "class_unloads": 20, "made_not_entrant": 50},
    # c2_target: C2 (re)compiles of dc1-3; 5-7 with a release DR, 4 with a debug one.
    "DeoptCycle": {"compiles": 100, "deopts": 100, "made_not_entrant": 50, "c2_target": 3},
    # C2 turns step's NPE into a branch to its handler (no exception object, no
    # log line): the implicit null checks are not countable from -Xlog.
    "JfrNpe": {"compiles": 50, "c2_target": 1, "execution_samples": 1},
    "Redefine": {"compiles": 50, "c2_target": 2, "redefinitions": 20},
}

# Floors that count sites, not events: not scaled by ops.
SITE_FLOORS = {"c2_icsites"}

XLOG = ("-Xlog:jit+compilation=debug,deoptimization=debug,exceptions=info,"
        "codecache=info,class+unload=info,redefine+class=info"
        ":file={log}:uptime,tid,level,tags:filecount=0")


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# Building the program.

def ensure_jar(work, javac, jar_tool):
    with open(SOURCE, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()[:16]
    d = os.path.join(work, "jar-" + digest)
    jar = os.path.join(d, "jitstress.jar")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(work, "build.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not os.path.exists(jar):
            tmp = d + ".tmp%d" % os.getpid()
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(os.path.join(tmp, "classes"))
            subprocess.run([javac, "-d", os.path.join(tmp, "classes"), SOURCE], check=True)
            with open(os.path.join(tmp, "manifest.txt"), "w") as m:
                m.write("Main-Class: JitStress\nPremain-Class: JitStress\n"
                        "Can-Redefine-Classes: true\nCan-Retransform-Classes: true\n")
            subprocess.run([jar_tool, "cfm", os.path.join(tmp, "jitstress.jar"),
                            os.path.join(tmp, "manifest.txt"), "-C",
                            os.path.join(tmp, "classes"), "."], check=True)
            shutil.rmtree(d, ignore_errors=True)
            os.rename(tmp, d)
    return jar, digest


# ---------------------------------------------------------------------------
# Running one JVM.

class Run:
    pass


def run_jvm(cmd, rundir, timeout, env=None):
    """Runs cmd in its own process group; on timeout, dumps threads and kills."""
    os.makedirs(rundir, exist_ok=True)
    r = Run()
    r.cmd = cmd
    r.dir = rundir
    t0 = time.time()
    with open(os.path.join(rundir, "stdout"), "wb") as out, \
            open(os.path.join(rundir, "stderr"), "wb") as err:
        p = subprocess.Popen(cmd, stdout=out, stderr=err, cwd=rundir,
                             start_new_session=True, env=env)
        r.timed_out = False
        try:
            r.rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            r.timed_out = True
            hang_diagnostics(p.pid, rundir)
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            r.rc = p.wait()
    r.secs = time.time() - t0
    with open(os.path.join(rundir, "stdout"), errors="replace") as f:
        r.stdout = f.read()
    with open(os.path.join(rundir, "stderr"), errors="replace") as f:
        r.stderr = f.read()
    r.result = None
    for line in r.stdout.splitlines():
        if line.startswith("RESULT "):
            r.result = line.strip()
    m = re.search(r"mismatches=(\d+)", r.result or "")
    r.mismatches = int(m.group(1)) if m else None
    r.hs_err = sorted(f for f in os.listdir(rundir) if f.startswith("hs_err"))
    return r


def hang_diagnostics(pid, rundir):
    """Best effort, bounded; perturbs the process (marked as such)."""
    path = os.path.join(rundir, "hang.txt")
    with open(path, "w") as f:
        f.write("# diagnostics taken after the timeout: they perturb the run\n")
        f.flush()
        for what, cmd in (("jcmd Thread.print", ["jcmd", str(pid), "Thread.print"]),
                          ("thread states", ["sh", "-c",
                                             "for t in /proc/%d/task/*; do echo $t; "
                                             "cat $t/stat $t/wchan 2>/dev/null; echo; "
                                             "done" % pid]),
                          # Under DR, frames in the code cache are unwound badly,
                          # but threads waiting inside DR show where.
                          ("gdb backtraces", ["gdb", "-p", str(pid), "-batch", "-nx",
                                              "-ex", "set pagination off",
                                              "-ex", "thread apply all bt 12"])):
            if shutil.which(cmd[0]) is None:
                continue
            f.write("## %s\n" % what)
            f.flush()
            try:
                subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=90)
            except Exception as e:  # noqa: BLE001 - diagnostics only
                f.write("(%s)\n" % e)


# ---------------------------------------------------------------------------
# hs_err parsing and the fault-pc plausibility check.

def parse_hs_err(path):
    with open(path, errors="replace") as f:
        text = f.read()
    h = {"path": path}
    m = re.search(r"#\s+(SIG\w+) \(0x[0-9a-f]+\) at pc=(0x[0-9a-f]+)", text)
    if m:
        h["signal"], h["pc"] = m.group(1), int(m.group(2), 16)
    m = re.search(r"#\s+Internal Error \((.*)\)", text)
    if m:
        h["internal_error"] = m.group(1)
    m = re.search(r"# Problematic frame:\n#\s*(.*)", text)
    if m:
        h["frame"] = m.group(1).strip()
    m = re.search(r"si_addr: (0x[0-9a-f]+)", text)
    if m:
        h["si_addr"] = int(m.group(1), 16)
    m = re.search(r"si_code: (\d+) \((\w+)\)", text)
    if m:
        h["si_code"] = m.group(2)
    m = re.search(r"Current thread \([^)]*\):\s*(.*)", text)
    if m:
        h["thread"] = m.group(1).strip()[:160]
    regs = {}
    for name, val in re.findall(r"\b(R\d+|sp|pc)\s*=\s*(0x[0-9a-f]+)", text):
        key = name.lower()
        if key not in regs:
            regs[key] = int(val, 16)
    h["regs"] = regs
    # "Instructions: (pc=0x...)" then "  0xADDR:   b0 b1 b2 ..." lines in memory
    # order (the pc's line marked "=>"); older JDKs group 4 bytes.
    words = {}
    m = re.search(r"Instructions: \((?:size=\d+, )?pc=(0x[0-9a-f]+)\)\n((?:(?:=>)?\s*0x[0-9a-f]+:.*\n)+)",
                  text)
    if m:
        mem = {}
        for line in m.group(2).splitlines():
            addr, _, rest = line.replace("=>", " ").strip().partition(":")
            a = int(addr, 16)
            for g in rest.split():
                if not re.fullmatch(r"[0-9a-f]{2}|[0-9a-f]{8}", g):
                    break
                for b in bytes.fromhex(g):
                    mem[a] = b
                    a += 1
        for a in mem:
            if a % 4 == 0 and all(a + i in mem for i in range(4)):
                words[a] = int.from_bytes(bytes(mem[a + i] for i in range(4)), "little")
    h["words"] = words
    h["plausibility"], h["plausibility_why"] = plausibility(h)
    return h


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def mem_access(w):
    """Returns (base register, offset or None if not computable, kind) for an
    AArch64 load/store, or None for other instructions."""
    rn = (w >> 5) & 31
    if (w & 0x3B000000) == 0x39000000:          # unsigned scaled immediate
        size = w >> 30
        if (w & 0x04800000) == 0x04800000:      # 128-bit SIMD
            size = 4
        return rn, ((w >> 10) & 0xfff) << size, "ldr/str imm"
    if (w & 0x3B200000) == 0x38000000:          # unscaled / pre / post index
        idx = (w >> 10) & 3
        imm = sext((w >> 12) & 0x1ff, 9)
        return rn, 0 if idx == 1 else imm, "ldur/stur"
    if (w & 0x3B200C00) == 0x38200800:          # register offset
        return rn, None, "ldr/str reg"
    if (w & 0x3B200C00) == 0x38200000:          # LSE atomics
        return rn, 0, "atomic"
    if (w & 0x3A000000) == 0x28000000:          # load/store pair
        opc = w >> 30
        scale = 2 + (opc >> 1) if not (w & 0x04000000) else 2 + opc
        imm = sext((w >> 15) & 0x7f, 7) << scale
        idx = (w >> 23) & 3
        return rn, 0 if idx == 1 else imm, "ldp/stp"
    if (w & 0x3F000000) == 0x08000000:          # exclusives, acquire/release
        return rn, 0, "exclusive"
    if (w & 0x3B000000) == 0x19000000 and (w & 0x00200000) == 0:  # ldapr/stlur
        return rn, sext((w >> 12) & 0x1ff, 9), "ldapur"
    return None


def plausibility(h):
    """Does the instruction at the reported pc access si_addr?  Evidence, not
    proof: hs_err reads the bytes at crash time, after any patch."""
    if h.get("signal") not in ("SIGSEGV", "SIGBUS") or "pc" not in h or "si_addr" not in h:
        return "UNKNOWN", "not a memory fault with pc and si_addr"
    w = h["words"].get(h["pc"])
    if w is None:
        return "UNKNOWN", "no instruction bytes at pc"
    acc = mem_access(w)
    if acc is None:
        return "IMPLAUSIBLE", "instruction 0x%08x at pc is not a load or store" % w
    rn, off, kind = acc
    base = h["regs"].get("sp" if rn == 31 else "r%d" % rn)
    if base is None:
        return "UNKNOWN", "%s 0x%08x: no value for base x%d" % (kind, w, rn)
    if off is None:
        ok = abs(h["si_addr"] - base) < (1 << 32)
        return ("PLAUSIBLE" if ok else "IMPLAUSIBLE",
                "%s 0x%08x base x%d=0x%x si_addr 0x%x" % (kind, w, rn, base, h["si_addr"]))
    ea = (base + off) & (2**64 - 1)
    ok = ea <= h["si_addr"] < ea + 64 or (h["si_addr"] & ~0xfff) == ((ea + 63) & ~0xfff)
    return ("PLAUSIBLE" if ok else "IMPLAUSIBLE",
            "%s 0x%08x: x%d=0x%x + %d = 0x%x vs si_addr 0x%x" % (kind, w, rn, base, off, ea,
                                                                 h["si_addr"]))


# ---------------------------------------------------------------------------
# Churn counts from -Xlog.

def count_log(path, stdout, c2_target=None):
    """Counts completed events (not requests) in the -Xlog file."""
    c = {k: 0 for k in ("compiles", "c2_compiles", "made_not_entrant", "deopts",
                        "npe_created", "npe_through_icsite", "compiled_exceptions",
                        "class_unloads", "redefinitions", "c2_target")}
    c2_icsites = set()
    if os.path.exists(path):
        with open(path, errors="replace") as f:
            for line in f:
                # "[uptime][tid][level][tags   ] message"
                tags, _, msg = line.partition("] ")
                msg = msg.strip()
                if "[jit,compilation" in tags:
                    if "made not entrant" in msg:
                        c["made_not_entrant"] += 1
                        continue
                    c["compiles"] += 1
                    # "<id> <flags> <level> <method> (<size> bytes)"
                    m = re.match(r"\d+\s+[%sbn!]*\s*(\d)\s+(\S+)", msg)
                    if m and m.group(1) == "4":
                        c["c2_compiles"] += 1
                        if c2_target and re.search(c2_target, m.group(2)):
                            c["c2_target"] += 1
                        m2 = re.search(r"JitStress\$(S\d)::icsite", m.group(2))
                        if m2:
                            c2_icsites.add(m2.group(1))
                elif "[deoptimization" in tags:
                    if "trap_bci=" in msg:
                        c["deopts"] += 1
                elif "[exceptions" in tags:
                    if msg.startswith("Exception <a 'java/lang/NullPointerException'"):
                        c["npe_created"] += 1
                    if "thrown in C1 compiled method" in msg or "thrown in C2 compiled method" in msg \
                            or re.match(r"Exception <a [^>]*> \(0x", msg):
                        c["compiled_exceptions"] += 1
                    if "NullPointerException" in msg and "'icsite'" in msg and "[Exception ()" in msg:
                        c["npe_through_icsite"] += 1
                elif "[class,unload" in tags:
                    c["class_unloads"] += 1
    c["c2_icsites"] = len(c2_icsites)
    m = re.search(r"executionSamples=(\d+)", stdout or "")
    c["execution_samples"] = int(m.group(1)) if m else 0
    m = re.search(r"redefinitions=(\d+)", stdout or "")
    c["redefinitions"] = int(m.group(1)) if m else 0
    return c


# ---------------------------------------------------------------------------
# Cases.

def dr_commit(drrun, override):
    if override:
        return override
    env = os.environ.get("JITSTRESS_DR_COMMIT")
    if env:
        return env
    build = os.path.dirname(os.path.dirname(os.path.abspath(drrun)))
    src = None
    try:
        with open(os.path.join(build, "CMakeCache.txt"), errors="replace") as f:
            for line in f:
                if line.startswith("CMAKE_HOME_DIRECTORY:"):
                    src = line.split("=", 1)[1].strip()
    except OSError:
        pass
    if src:
        try:
            out = subprocess.run(["git", "-C", src, "rev-parse", "--short=12", "HEAD"],
                                 capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                return out.stdout.strip()
        except Exception:  # noqa: BLE001
            pass
        for name in (".dr_commit", "DR_COMMIT"):
            p = os.path.join(src, name)
            if os.path.exists(p):
                return open(p).read().strip()
    try:
        out = subprocess.run([drrun, "-version"], capture_output=True, text=True, timeout=30)
        return "unknown (%s)" % (out.stdout.strip() or out.stderr.strip())[:80]
    except Exception:  # noqa: BLE001
        return "unknown"


def jvm_cmd(java, jar, scenario, seed, ops, threads, extra_jvm, logpath, rundir):
    sc = SCENARIOS[scenario]
    flags = (BASE_JVM + sc["jvm"] + extra_jvm +
             ["-XX:ErrorFile=" + os.path.join(rundir, "hs_err_%p.log"),
              XLOG.format(log=logpath),
              "-javaagent:" + jar, "-Djava.io.tmpdir=" + rundir,
              "-Dscenario=" + scenario, "-Dseed=%d" % seed, "-Dops=%d" % ops,
              "-Dthreads=%d" % threads])
    return [java] + flags + ["-cp", jar, "JitStress"], flags


def cpu_list(ncpus, seed):
    cpus = sorted(os.sched_getaffinity(0))
    if ncpus <= 0 or ncpus >= len(cpus):
        return cpus
    start = seed % len(cpus)
    return [cpus[(start + i) % len(cpus)] for i in range(ncpus)]


def references(args, jar, digest, scenario, seed, ops, threads, extra_jvm):
    """Two native runs and one -Xint run (cached).  Returns (result, error)."""
    key = hashlib.sha256(json.dumps([digest, scenario, seed, ops, threads, extra_jvm,
                                     args.java, BASE_JVM, SCENARIOS[scenario]["jvm"]])
                         .encode()).hexdigest()[:16]
    cache = os.path.join(args.work, "refs", key + ".json")
    if os.path.exists(cache):
        with open(cache) as f:
            d = json.load(f)
        return d["result"], d.get("error"), d.get("native_secs", 0)
    results, error, native_secs = [], None, 0
    for i, mode in enumerate(("native1", "native2", "xint")):
        rundir = os.path.join(args.work, "refs", key + "." + mode)
        shutil.rmtree(rundir, ignore_errors=True)
        os.makedirs(rundir)
        extra = extra_jvm + (["-Xint"] if mode == "xint" else [])
        cmd, _ = jvm_cmd(args.java, jar, scenario, seed, ops, threads, extra,
                         os.path.join(rundir, "jvm.log"), rundir)
        r = run_jvm(cmd, rundir, args.ref_timeout * (4 if mode == "xint" else 1))
        if mode == "native1":
            native_secs = r.secs
        if r.rc != 0 or r.result is None or r.mismatches:
            if re.search(r"Unrecognized VM option|Could not create the Java Virtual Machine|"
                         r"CONFIGURATION_ERROR|Improperly specified VM option", r.stdout + r.stderr):
                error = "CONFIGURATION_ERROR: %s rejected: %s" % (mode, (r.stderr or r.stdout)[-400:])
            else:
                error = "reference %s failed (rc %s, %s): %s" % (
                    mode, r.rc, "timeout" if r.timed_out else "no RESULT" if r.result is None
                    else "mismatches", (r.stdout + r.stderr)[-600:])
            break
        results.append(r.result)
        shutil.rmtree(rundir, ignore_errors=True)
    if error is None and len(set(results)) != 1:
        error = "CONFIGURATION_ERROR: references differ (nondeterministic workload): %s" % results
    d = {"result": results[0] if results else None, "error": error, "native_secs": native_secs}
    if error is None or error.startswith("CONFIGURATION_ERROR"):
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        with open(cache, "w") as f:
            json.dump(d, f)
    return d["result"], error, native_secs


DR_FAILURE_RE = re.compile(r"SYSLOG_ERROR|Internal Error|ASSERT|DynamoRIO.*(?:Error|error)|"
                           r"Application .* \(\d+\)\..*(?:Error|Internal)|<.*Unrecoverable|"
                           r"CURIOSITY", re.S)


def run_case(args, case, jar, digest, commit):
    """case: dict(scenario, seed, dr_profile, client, budget, cpus, ops, threads)."""
    scenario, seed = case["scenario"], case["seed"]
    sc = SCENARIOS[scenario]
    ops = case.get("ops") or sc["ops"]
    threads = case.get("threads") or sc["threads"]
    extra_jvm = list(case.get("jvm", []))
    ref, ref_err, native_secs = references(args, jar, digest, scenario, seed, ops, threads,
                                           extra_jvm)
    name = "%s.s%d.%s.%s.cpu%d" % (scenario, seed, case["dr_profile"],
                                    ("budget%d" % case["budget"]) if case.get("client") else "noclient",
                                    case["cpus"])
    rundir = os.path.join(args.work, "runs", name + ".%d" % int(time.time() * 1000))
    shutil.rmtree(rundir, ignore_errors=True)
    os.makedirs(rundir)
    logpath = os.path.join(rundir, "jvm.log")
    jcmd, jflags = jvm_cmd(args.java, jar, scenario, seed, ops, threads, extra_jvm, logpath, rundir)
    drops = DR_PROFILES[case["dr_profile"]] + shlex.split(case.get("dr_ops", "") or "")
    client = []
    if case.get("client"):
        client = ["-c", case["client"], "--instructions-per-progress-call", str(case["budget"])]
    cpus = cpu_list(case["cpus"], seed)
    cmd = (["taskset", "-c", ",".join(map(str, cpus)), args.drrun] + drops + client +
           ["--"] + jcmd)
    repro = ("REPRO: python3 %s run --drrun %s --scenario %s --seed %d --dr-profile %s%s "
             "--cpus %d --ops %d --threads %d%s%s  # DR %s; DR options: %s; JVM flags: %s" % (
                 os.path.abspath(__file__), args.drrun, scenario, seed, case["dr_profile"],
                 (" --client %s --budget %d" % (case["client"], case["budget"])) if case.get("client") else "",
                 case["cpus"], ops, threads,
                 (" --dr-ops %s" % shlex.quote(case["dr_ops"])) if case.get("dr_ops") else "",
                 (" --jvm %s" % shlex.quote(" ".join(extra_jvm))) if extra_jvm else "",
                 commit, " ".join(drops + client) or "(defaults)", " ".join(jflags)))
    verdict, why = "PASS", ""
    counts = {}
    r = None
    if ref_err:
        verdict = "CONFIGURATION_ERROR" if ref_err.startswith("CONFIGURATION_ERROR") else "REFERENCE_FAILURE"
        why = ref_err
    else:
        # Generous: the shared machine is loaded and DR's overhead on one CPU
        # with the client is up to ~100x.
        timeout = args.timeout if args.timeout else max(300, native_secs * 200) * args.timeout_scale
        r = run_jvm(cmd, rundir, timeout)
        counts = count_log(logpath, r.stdout, sc.get("c2_target"))
        floors = {k: v if k in SITE_FLOORS else max(1, int(v * ops / sc["ops"]))
                  for k, v in FLOORS[scenario].items()}
        if args.no_floors:
            floors = {}
        low = {k: (counts.get(k, 0), v) for k, v in floors.items() if counts.get(k, 0) < v}
        crash = [parse_hs_err(os.path.join(rundir, f)) for f in r.hs_err]
        if r.timed_out:
            verdict, why = "TIMEOUT", "no exit within %ds (see hang.txt)" % timeout
        elif crash:
            h = crash[0]
            verdict = "VM_CRASH"
            why = "%s at pc 0x%x si_addr 0x%x (%s) in %s; fault-pc plausibility %s: %s" % (
                h.get("signal", "?"), h.get("pc", 0), h.get("si_addr", 0), h.get("si_code", "?"),
                h.get("frame", h.get("internal_error", "?")), h["plausibility"], h["plausibility_why"])
        elif DR_FAILURE_RE.search(r.stderr) and r.result is None:
            verdict, why = "DR_FAILURE", r.stderr.strip()[-600:]
        elif r.result is None or r.rc != 0:
            verdict = "SEMANTIC_FAILURE" if r.result else "VM_CRASH"
            why = "exit %s, %s: %s" % (r.rc, "RESULT " + r.result if r.result else "no RESULT",
                                        (r.stdout + r.stderr).strip()[-600:])
        elif r.result != ref:
            verdict, why = "SEMANTIC_FAILURE", "RESULT differs from the references:\n  got  %s\n  want %s" % (
                r.result, ref)
        elif low:
            verdict = "INSUFFICIENT_STRESS"
            why = ", ".join("%s %d < %d" % (k, have, want) for k, (have, want) in sorted(low.items()))
    secs = r.secs if r else 0
    log("%-20s %-40s %6.1fs  %s" % (verdict, name, secs,
                                     " ".join("%s=%d" % kv for kv in sorted(counts.items()) if kv[1])))
    if verdict != "PASS":
        log("  " + why.replace("\n", "\n  "))
        log("  run dir: " + rundir)
        log("  " + repro)
    elif not args.keep:
        shutil.rmtree(rundir, ignore_errors=True)
    if args.verbose and verdict == "PASS":
        log("  " + repro)
    return verdict, counts, secs


# ---------------------------------------------------------------------------
# Commands.

SMOKE_SETS = {
    # The default ctest (jvm.jitstress_quick): one short IcNull case under
    # Seedbox's options on one CPU (the "ic" set's first case, at a fifth of
    # its operations).
    "quick": [dict(scenario="IcNull", seed=1, dr_profile="seedbox", cpus=1, ops=20000)],
    # The elided-call (icfix) class: IcNull under Seedbox's options (fails at
    # a4a30e738, before 605b07ebc) and under DR's defaults, on one CPU.
    "ic": [dict(scenario="IcNull", seed=1, dr_profile="seedbox", cpus=1),
           dict(scenario="IcNull", seed=1, dr_profile="default", cpus=1, ops=50000)],
    # With the progress-like client at Seedbox's budget: DeoptCycle and IcNull.
    # (Smaller budgets slow JVM startup on one CPU by minutes: soak only.)
    "client": [dict(scenario="DeoptCycle", seed=1, dr_profile="seedbox", cpus=1, client=True,
                    budget=50000),
               dict(scenario="IcNull", seed=2, dr_profile="seedbox", cpus=1, client=True,
                    budget=50000, ops=50000)],
}

# Code shape varies from run to run (HotSpot's compilation timing): a smoke
# case below its floors is rerun with the next seed this many times before it
# counts as failed.  Other verdicts are never retried.
SMOKE_STRESS_RETRIES = 2


def resolve_client(case, args):
    if case.get("client") is True:
        if not args.client:
            return None
        case = dict(case, client=args.client)
    return case


def cmd_cases(args, cases, stress_retries=0):
    jar, digest = ensure_jar(args.work, args.javac, args.jar)
    commit = dr_commit(args.drrun, args.dr_commit)
    log("jitstress: DR %s (%s), java %s, work %s" % (commit, args.drrun, args.java, args.work))
    bad = 0
    for case in cases:
        case = resolve_client(case, args)
        if case is None:
            log("CONFIGURATION_ERROR  client case without --client")
            bad += 1
            continue
        verdict, _, _ = run_case(args, case, jar, digest, commit)
        for _ in range(stress_retries):
            if verdict != "INSUFFICIENT_STRESS":
                break
            case = dict(case, seed=case["seed"] + 100)
            log("  (below the floors: rerunning with seed %d)" % case["seed"])
            verdict, _, _ = run_case(args, case, jar, digest, commit)
        if verdict != "PASS":
            bad += 1
    log("jitstress: %d of %d cases failed" % (bad, len(cases)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "smoke", "soak"])
    ap.add_argument("--drrun", required=True)
    ap.add_argument("--java", default="java")
    ap.add_argument("--javac", default="javac")
    ap.add_argument("--jar", default="jar")
    ap.add_argument("--work", default=os.path.join(os.getcwd(), "jitstress-work"))
    ap.add_argument("--dr-commit")
    ap.add_argument("--timeout", type=int, default=0, help="seconds per DR run (default: from native time)")
    ap.add_argument("--timeout-scale", type=float, default=1.0,
                    help="multiplies the default DR-run timeout (e.g. for a debug DR)")
    ap.add_argument("--ref-timeout", type=int, default=300, help="seconds per native reference run")
    ap.add_argument("--keep", action="store_true", help="keep run dirs of passing runs")
    ap.add_argument("--no-floors", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    # run
    ap.add_argument("--scenario", choices=sorted(SCENARIOS))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--dr-profile", choices=sorted(DR_PROFILES), default="seedbox")
    ap.add_argument("--dr-ops", default="", help="extra DR options")
    ap.add_argument("--jvm", default="", help="extra JVM flags")
    ap.add_argument("--client", help="progress-like client (libclient.a64_progress_like.dll.so)")
    ap.add_argument("--budget", type=int, default=50000, help="--instructions-per-progress-call")
    ap.add_argument("--cpus", type=int, default=1)
    ap.add_argument("--ops", type=int)
    ap.add_argument("--threads", type=int)
    ap.add_argument("--repeat", type=int, default=1)
    # smoke / soak
    ap.add_argument("--set", choices=sorted(SMOKE_SETS))
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--seed0", type=int, default=1000)
    args = ap.parse_args()
    if shutil.which(args.java) is None and not os.path.exists(args.java):
        log("CONFIGURATION_ERROR: no java (%s)" % args.java)
        return 2
    if args.command == "run":
        if not args.scenario:
            ap.error("run needs --scenario")
        case = dict(scenario=args.scenario, seed=args.seed, dr_profile=args.dr_profile,
                    dr_ops=args.dr_ops, cpus=args.cpus, ops=args.ops, threads=args.threads,
                    jvm=shlex.split(args.jvm), client=args.client, budget=args.budget)
        cases = []
        for i in range(args.repeat):
            cases.append(dict(case, seed=args.seed + i))
        return cmd_cases(args, cases)
    if args.command == "smoke":
        if not args.set:
            ap.error("smoke needs --set")
        return cmd_cases(args, [dict(c) for c in SMOKE_SETS[args.set]], SMOKE_STRESS_RETRIES)
    # soak: weighted random cases until the time runs out.
    rnd = random.Random(args.seed0)
    jar, digest = ensure_jar(args.work, args.javac, args.jar)
    commit = dr_commit(args.drrun, args.dr_commit)
    log("jitstress soak: DR %s, %.0f minutes, seed0 %d" % (commit, args.minutes, args.seed0))
    end = time.time() + args.minutes * 60
    tally = {}
    seed = args.seed0
    while time.time() < end:
        case = dict(scenario=rnd.choice(sorted(SCENARIOS)), seed=seed,
                    dr_profile=rnd.choice(["seedbox", "seedbox", "default"]),
                    cpus=rnd.choice([1, 1, 1, 2]))
        if args.client and rnd.random() < 0.5:
            case.update(client=args.client, budget=rnd.choice([50000, 5000, 500]))
        seed += 1
        verdict, _, _ = run_case(args, case, jar, digest, commit)
        tally[verdict] = tally.get(verdict, 0) + 1
    log("jitstress soak: " + ", ".join("%s %d" % kv for kv in sorted(tally.items())))
    return 0 if set(tally) <= {"PASS", "INSUFFICIENT_STRESS"} else 1


if __name__ == "__main__":
    sys.exit(main())
