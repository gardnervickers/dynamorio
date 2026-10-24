// **********************************************************
// Copyright (c) 2026 Google, Inc.  All rights reserved.
// **********************************************************
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of Google, Inc. nor the names of its contributors may be
//   used to endorse or promote products derived from this software without
//   specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

// Command a64_smoke_go is the Go workload of the AArch64 real-workload smoke
// tests (see ../README.md): the Go runtime's own threads, signals and stack
// handling under DR.  It exercises goroutines on few Ps, the concurrent
// collector with a small heap goal and finalizers, goroutine stack growth and
// copying, asynchronous preemption (sysmon's SIGURG is the only way a
// call-free loop gives up its P), signals delivered through os/signal, and
// child processes started by Go's own clone/exec path.
//
// Usage: a64_smoke_go [SCALE [CHILDREN]]
//
// Every concurrent result is recomputed sequentially and must agree; the
// output depends only on SCALE, never on timing or scheduling.
package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func step(x uint64) uint64 {
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	return x
}

type cell struct {
	next *cell
	val  uint64
	data []byte
}

// shuffle pushes, pops, moves and rewrites cells of heap-allocated lists, with
// an occasional large buffer, and hashes what is left.
func shuffle(seed uint64, n int) uint64 {
	const lists = 32
	var heads [lists]*cell
	x := seed | 1
	for i := 0; i < n; i++ {
		x = step(x)
		j := x % lists
		switch (x >> 8) % 5 {
		case 0, 1:
			c := &cell{next: heads[j], val: x}
			if (x>>16)%16 == 0 {
				c.data = make([]byte, 1+(x>>24)%16384)
				c.data[len(c.data)-1] = byte(x)
			}
			heads[j] = c
		case 2:
			if heads[j] != nil {
				heads[j] = heads[j].next
			}
		case 3:
			if c := heads[j]; c != nil {
				k := (x >> 32) % lists
				heads[j] = c.next
				c.next = heads[k]
				heads[k] = c
			}
		case 4:
			d := uint64(0)
			for c := heads[j]; c != nil && d < 16; c = c.next {
				c.val = c.val*31 + d
				d++
			}
		}
	}
	h := fnv.New64a()
	var b [8]byte
	for _, head := range heads {
		for c := head; c != nil; c = c.next {
			v := c.val
			if c.data != nil {
				v ^= uint64(len(c.data))<<8 | uint64(c.data[len(c.data)-1])
			}
			for i := range b {
				b[i] = byte(v >> (8 * i))
			}
			h.Write(b[:])
		}
		h.Write([]byte{0xff})
	}
	return h.Sum64()
}

// deep recurses with large frames, passing a pointer into the caller's frame,
// so the goroutine's stack grows and is copied with live interior pointers.
//
//go:noinline
func deep(n int, p *uint64, x uint64) uint64 {
	var frame [48]uint64
	frame[n%48] = x ^ *p
	frame[(n+7)%48] = uint64(n)
	if n == 0 {
		return frame[0] + x
	}
	v := deep(n-1, &frame[n%48], step(x))
	return v ^ frame[n%48] + frame[(n+7)%48]
}

// spin's loop makes no calls, so only asynchronous preemption takes its P.
//
//go:noinline
func spin(stop *atomic.Bool) uint64 {
	x := uint64(1)
	for !stop.Load() {
		x = x*6364136223846793005 + 1442695040888963407
	}
	return x
}

func hashAll(v []uint64) uint64 {
	h := fnv.New64a()
	for _, x := range v {
		fmt.Fprintf(h, "%x,", x)
	}
	return h.Sum64()
}

// heap: the same mutations concurrently and sequentially, with collections
// and stack growth going on.
func heap(scale int) {
	const workers = 4
	ops := 30000 * scale
	want := make([]uint64, workers)
	for i := range want {
		want[i] = shuffle(uint64(i)+1, ops)
	}
	got := make([]uint64, workers)
	stacks := make([]uint64, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			got[i] = shuffle(uint64(i)+1, ops)
		}(i)
		go func(i int) {
			defer wg.Done()
			base := uint64(i)
			for r := 0; r < 4*scale; r++ {
				stacks[i] += deep(200+50*i, &base, uint64(r))
			}
		}(i)
	}
	wg.Wait()
	for i := range want {
		if got[i] != want[i] {
			fail("shuffle %d: %x concurrently, %x sequentially", i, got[i], want[i])
		}
		base, s := uint64(i), uint64(0)
		for r := 0; r < 4*scale; r++ {
			s += deep(200+50*i, &base, uint64(r))
		}
		if stacks[i] != s {
			fail("deep %d: %x concurrently, %x sequentially", i, stacks[i], s)
		}
	}
	fmt.Printf("heap %016x stacks %016x\n", hashAll(got), hashAll(stacks))
}

// preempt: call-free spinners on every P; the main goroutine only runs again
// once sysmon has preempted one of them.
func preempt(rounds int) {
	for r := 0; r < rounds; r++ {
		var stop atomic.Bool
		var wg sync.WaitGroup
		for i := 0; i < runtime.GOMAXPROCS(0); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				spin(&stop)
			}()
		}
		runtime.Gosched()
		stop.Store(true)
		wg.Wait()
	}
	fmt.Printf("preempt %d rounds\n", rounds)
}

type tracked struct {
	p   *int
	pad [6]uint64
}

//go:noinline
func garbage(n int, done *atomic.Int64) {
	for i := 0; i < n; i++ {
		v := i
		runtime.SetFinalizer(&tracked{p: &v}, func(*tracked) { done.Add(1) })
	}
}

// finalize: every finalizer runs after enough collections.
func finalize(n int) {
	var done atomic.Int64
	garbage(n, &done)
	for i := 0; i < 1000 && done.Load() < int64(n); i++ {
		runtime.GC()
		runtime.Gosched()
	}
	fmt.Printf("finalized %d of %d\n", done.Load(), n)
}

// signals: each SIGUSR1 sent to the process is received before the next.
func signals(n int) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	for i := 0; i < n; i++ {
		if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
			fail("kill: %v", err)
		}
		<-ch
	}
	fmt.Printf("signals %d\n", n)
}

// children: this program again as a child, computing shuffle, several at a
// time while the parent allocates.
func children(n, ops int) {
	self, err := os.Executable()
	if err != nil {
		fail("os.Executable: %v", err)
	}
	var stop atomic.Bool
	var churn sync.WaitGroup
	churn.Add(1)
	go func() {
		defer churn.Done()
		for i := uint64(0); !stop.Load(); i++ {
			_ = shuffle(i, 2000)
		}
	}()
	out := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(self, "child", strconv.Itoa(i+100), strconv.Itoa(ops))
			var stderr strings.Builder
			cmd.Stderr = &stderr
			b, err := cmd.Output()
			if err != nil {
				msg := stderr.String()
				if len(msg) > 2000 {
					msg = msg[:2000]
				}
				fail("child %d: %v; its stderr:\n%s", i, err, msg)
			}
			out[i] = strings.TrimSpace(string(b))
		}(i)
	}
	wg.Wait()
	stop.Store(true)
	churn.Wait()
	results := make([]uint64, n)
	for i := range out {
		if want := fmt.Sprintf("%x", shuffle(uint64(i+100), ops)); out[i] != want {
			fail("child %d printed %q, want %q", i, out[i], want)
		}
		results[i], _ = strconv.ParseUint(out[i], 16, 64)
	}
	fmt.Printf("children %d %016x\n", n, hashAll(results))
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "child" {
		seed, _ := strconv.ParseUint(os.Args[2], 10, 64)
		ops, _ := strconv.Atoi(os.Args[3])
		fmt.Printf("%x\n", shuffle(seed, ops))
		return
	}
	scale, kids := 1, 8
	if len(os.Args) > 1 {
		var err error
		if scale, err = strconv.Atoi(os.Args[1]); err != nil || scale < 1 {
			fail("usage: %s [SCALE [CHILDREN]]", os.Args[0])
		}
	}
	if len(os.Args) > 2 {
		var err error
		if kids, err = strconv.Atoi(os.Args[2]); err != nil || kids < 0 {
			fail("usage: %s [SCALE [CHILDREN]]", os.Args[0])
		}
	}
	// A small heap goal: many collections, with their write barriers and
	// stop-the-world handshakes.
	debug.SetGCPercent(5)
	heap(scale)
	preempt(5 * scale)
	finalize(2000 * scale)
	signals(50 * scale)
	children(kids, 5000*scale)
	fmt.Println("ok")
}
