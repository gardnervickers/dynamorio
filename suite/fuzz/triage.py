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

"""Replays saved crash inputs through a harness and groups them by failure
signature (the failing check, sanitizer report location, or DR assert), so a
fuzzing run's crashes reduce to a list of distinct bugs with one reproducer
and one full report each.

  triage.py HARNESS INPUT_OR_DIR... [--json OUT]
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys

PATTERNS = [
    # Our own invariant checks: file:line plus the description up to the
    # first hex value, so the same check on different encodings groups.
    re.compile(r'FUZZ_CHECK failed: (\S+): .*\n\s*(.*)'),
    re.compile(r'DR internal ASSERT failed: (\S+:\d+): (.*)'),
    re.compile(r'DR CLIENT_ASSERT failed: (\S+)'),
    re.compile(r'(\S+:\d+:\d+): runtime error: (.*)'),
    re.compile(r'ERROR: AddressSanitizer: (\S+)[^\n]*(?:\n.*?)*?\n\s+#\d+ \S+ in (?!__asan|__interceptor|memcpy|memset|memmove)(\S+ \S+)'),
    re.compile(r'ERROR: libFuzzer: (\S+)'),
]
HEXISH = re.compile(r'0x[0-9a-f]+|\b[0-9a-f]{8}\b|(?<![\w.])-?\d+(?:\.\d+(?:e[+-]?\d+)?)?\b')
SRC_ROOT = re.compile(r'^.*?/(core|suite)/')


def signature(output):
    for pat in PATTERNS:
        m = pat.search(output)
        if m:
            # The first group is a source location: keep its line number.
            groups = [g.strip() for g in m.groups()]
            loc = SRC_ROOT.sub(r'\1/', groups[0])
            return ' | '.join([loc] + [HEXISH.sub('N', g) for g in groups[1:]])
    return 'no recognized failure'


def inputs(paths):
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                yield os.path.join(p, name)
        else:
            yield p


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('harness')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--json', help='write buckets with full reports here')
    args = ap.parse_args()

    buckets = collections.OrderedDict()
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:symbolize=1',
               UBSAN_OPTIONS='print_stacktrace=1')
    for path in inputs(args.paths):
        proc = subprocess.run([args.harness, path], capture_output=True, text=True,
                              errors='replace', env=env, timeout=120)
        if proc.returncode == 0:
            sig = 'passes now'
        else:
            sig = signature(proc.stderr)
        b = buckets.setdefault(sig, {'count': 0, 'example': path, 'report': proc.stderr})
        b['count'] += 1

    for sig, b in sorted(buckets.items(), key=lambda kv: -kv[1]['count']):
        print('%5d  %s\n       e.g. %s' % (b['count'], sig, b['example']))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(buckets, f, indent=1)


if __name__ == '__main__':
    main()
