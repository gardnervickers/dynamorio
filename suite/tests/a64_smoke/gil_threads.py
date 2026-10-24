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

"""The Python workload of the AArch64 real-workload smoke tests (README.md).

CPython threads contend for the GIL, handed over every few hundred
microseconds (the eval loop's forced switches go through condition variables
and futexes), while they run dictionary, string, exception, hashing and
sorting code and a strict ping-pong over a condition variable.  Every
concurrent result is recomputed in one thread and must agree; the output
depends only on the arguments.

Usage: gil_threads.py [THREADS [ITERS]]
"""

import hashlib
import sys
import threading

THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 6
ITERS = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
sys.setswitchinterval(0.0002)


def fail(msg):
    sys.stderr.write("FAIL: %s\n" % msg)
    sys.exit(1)


def work(seed, iters):
    table = {}
    words = []
    x = seed * 2654435761 + 1
    caught = 0
    for i in range(iters):
        x = (x * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        key = x % 211
        table[key] = table.get(key, 0) + (x >> 40)
        if i % 7 == 0:
            words.append("%x-%d" % (x >> 48, i % 13))
        if i % 11 == 0:
            try:
                del table[(x >> 8) % 223]
            except KeyError:
                caught += 1
        if i % 997 == 0:
            words.sort()
            words = words[-64:]
    digest = hashlib.sha256()
    for k in sorted(table):
        digest.update(b"%d:%d;" % (k, table[k]))
    digest.update(",".join(words).encode())
    return "%s/%d" % (digest.hexdigest()[:16], caught)


results = [None] * THREADS
counter = [0]
counter_lock = threading.Lock()
start = threading.Barrier(THREADS + 2)


def worker(index):
    start.wait()
    results[index] = work(index, ITERS)
    for _ in range(ITERS // 100):
        with counter_lock:
            counter[0] += 1


# Two threads alternate strictly through a condition variable.
turn = [0]
cond = threading.Condition()
PINGS = ITERS // 20
pings = [0, 0]


def pinger(side):
    start.wait()
    for _ in range(PINGS):
        with cond:
            while turn[0] != side:
                cond.wait()
            pings[side] += 1
            turn[0] = 1 - side
            cond.notify()


threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
threads += [threading.Thread(target=pinger, args=(s,)) for s in (0, 1)]
for t in threads:
    t.start()
for t in threads:
    t.join()

for i in range(THREADS):
    want = work(i, ITERS)
    if results[i] != want:
        fail("thread %d computed %s, want %s" % (i, results[i], want))
if counter[0] != THREADS * (ITERS // 100):
    fail("counter %d, want %d" % (counter[0], THREADS * (ITERS // 100)))
if pings != [PINGS, PINGS]:
    fail("pings %s, want %d each" % (pings, PINGS))
print("threads %d iters %d" % (THREADS, ITERS))
print("work %s" % hashlib.sha256(" ".join(results).encode()).hexdigest()[:16])
print("counter %d pings %d" % (counter[0], sum(pings)))
print("ok")
