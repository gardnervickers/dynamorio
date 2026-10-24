#!/bin/bash
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

# Runs one AArch64 real-workload smoke test (see README.md): the workload
# natively (the oracle), then under drrun with the progress-like client, both
# pinned to one CPU; passes when both exit 0, the native output matches the
# expected pattern (an ERE matched against each line, by default ^ok$) and the
# output under DR is identical to the native output.
#
# run_smoke.sh -name NAME -logdir DIR -drrun DRRUN -client CLIENT
#   [-client_args "BUDGET POINTS"] [-dr_ops "OPTIONS"] [-cpu N] [-timeout SECS]
#   [-reps N] [-expect REGEX] [-skip REASON] -- COMMAND [ARGS...]
#
# With -skip, prints REASON and exits 77 (ctest's SKIP_RETURN_CODE).

name=smoke
logdir=.
drrun=
client=
client_args="1000 1"
dr_ops="-opt_speed -disable_traces -ldstex2cas -no_hw_cache_consistency -fake_ctr_dic"
cpu=0
timeout=600
reps=1
expect='^ok$'
skip=
while [ $# -gt 0 ]; do
    case "$1" in
        -name) name=$2; shift 2 ;;
        -logdir) logdir=$2; shift 2 ;;
        -drrun) drrun=$2; shift 2 ;;
        -client) client=$2; shift 2 ;;
        -client_args) client_args=$2; shift 2 ;;
        -dr_ops) dr_ops=$2; shift 2 ;;
        -cpu) cpu=$2; shift 2 ;;
        -timeout) timeout=$2; shift 2 ;;
        -reps) reps=$2; shift 2 ;;
        -expect) expect=$2; shift 2 ;;
        -skip) skip=$2; shift 2 ;;
        --) shift; break ;;
        *) echo "run_smoke.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
if [ -n "$skip" ]; then
    echo "$name: skipped: $skip"
    exit 77
fi
if [ $# -eq 0 ] || [ -z "$drrun" ] || [ -z "$client" ]; then
    echo "run_smoke.sh: need -drrun, -client and a command" >&2
    exit 2
fi
mkdir -p "$logdir" || exit 2
log="$logdir/$name"
pin=()
if command -v taskset > /dev/null; then
    pin=(taskset -c "$cpu")
else
    echo "$name: taskset not found: not pinning to one CPU"
fi

# run TAG CMD...: runs CMD with a timeout, stdout to $log.TAG.out and stderr to
# $log.TAG.err; sets rc and secs.
run() {
    local tag=$1
    shift
    local start=$SECONDS
    timeout -k 10 "$timeout" "${pin[@]}" "$@" > "$log.$tag.out" 2> "$log.$tag.err"
    rc=$?
    secs=$((SECONDS - start))
}

# show out|err TAG: the end of the output, or the start of the errors (where a
# runtime's crash report begins).
show() {
    if [ "$1" = out ]; then
        echo "--- last 20 lines of $log.$2.out"
        tail -n 20 "$log.$2.out"
    else
        echo "--- first 30 lines of $log.$2.err"
        head -n 30 "$log.$2.err"
    fi
}

run native "$@"
if [ $rc -ne 0 ] || ! grep -Eq "$expect" "$log.native.out"; then
    echo "$name: FAIL: the native run (the oracle) exited $rc after ${secs}s" \
         "or its output does not match '$expect'"
    show out native
    show err native
    exit 1
fi
echo "$name: native run ok in ${secs}s: $(wc -l < "$log.native.out") lines of output"

for rep in $(seq 1 "$reps"); do
    tag=dr
    [ "$reps" -gt 1 ] && tag=dr$rep
    # shellcheck disable=SC2086 # The option strings are lists of words.
    run $tag "$drrun" $dr_ops -c "$client" $client_args -- "$@"
    if [ $rc -ne 0 ]; then
        what="exited $rc"
        [ $rc -eq 124 ] && what="timed out"
        echo "$name: FAIL: under DR (run $rep of $reps) the workload $what" \
             "after ${secs}s"
        show out $tag
        show err $tag
        exit 1
    fi
    if ! cmp -s "$log.native.out" "$log.$tag.out"; then
        echo "$name: FAIL: under DR (run $rep of $reps) the output differs" \
             "from the native run"
        diff "$log.native.out" "$log.$tag.out" | head -n 40
        show err $tag
        exit 1
    fi
    echo "$name: run $rep of $reps under DR ok in ${secs}s"
done
echo "$name: PASS (logs: $log.*)"
exit 0
