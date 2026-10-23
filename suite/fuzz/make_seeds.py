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

"""Builds seed corpora for the suite/fuzz harnesses from the dis-a64*.txt
disassembler test vectors, which between them cover every opcode the A64
decoder knows.  Output is deterministic so corpora are reproducible.
"""

import argparse
import os
import random
import re
import struct
import sys

LINE = re.compile(r'^([0-9a-fA-F]{8})\s*:\s*(\S+)')
# Keep at most this many encodings per mnemonic per harness, spread across
# the input, so the corpus stays small but every form is represented.
PER_MNEMONIC = 48
ORIG_PC = 0x10000000


def read_vectors(paths):
    by_mnemonic = {}
    for path in paths:
        with open(path) as f:
            for line in f:
                m = LINE.match(line)
                if m:
                    by_mnemonic.setdefault(m.group(2), []).append(int(m.group(1), 16))
    words = []
    for mnemonic in sorted(by_mnemonic):
        encs = by_mnemonic[mnemonic]
        step = max(1, len(encs) // PER_MNEMONIC)
        words.extend((mnemonic, e) for e in encs[::step][:PER_MNEMONIC])
    return words


def decode_seed(rng, mnemonic, group):
    hdr = struct.pack('<BBBBQq', rng.randrange(16), rng.randrange(4),
                      rng.randrange(64), 1, ORIG_PC, rng.choice([4096, -4096, 1 << 20]))
    return hdr + b''.join(struct.pack('<I', w) for w in group)


def encode_seed(rng, word):
    out = struct.pack('<BBQI', rng.randrange(16), 0, ORIG_PC, word)
    for _ in range(rng.randrange(3)):
        out += struct.pack('<BBQ', rng.randrange(256), rng.randrange(14),
                           rng.getrandbits(64))
    return out


def semantics_seed(rng, word):
    return (struct.pack('<BI', rng.randrange(16), word) +
            bytes(rng.getrandbits(8) for _ in range(64)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--harness', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('vectors', nargs='+')
    args = ap.parse_args()

    rng = random.Random(args.harness)
    words = read_vectors(args.vectors)
    os.makedirs(args.out, exist_ok=True)
    seeds = []
    if args.harness == 'a64_decode_fuzzer':
        # Several encodings of one mnemonic per input.
        for i in range(0, len(words), 8):
            group = [w for _, w in words[i:i + 8]]
            seeds.append(decode_seed(rng, words[i][0], group))
    elif args.harness == 'a64_encode_fuzzer':
        seeds = [encode_seed(rng, w) for _, w in words]
        # The valid population (flags bit 1): each template with its
        # general-purpose registers renamed, which must encode.
        seeds += [struct.pack('<BBQIB', rng.randrange(16), 2, ORIG_PC, w,
                              rng.randrange(256)) for _, w in words]
        # Scratch-built instructions (flags bit 0): random opcode and operand
        # counts from the word, one (kind, payload) record per operand.
        for _ in range(2000):
            seed = struct.pack('<BBQI', rng.randrange(16), 1, ORIG_PC, rng.getrandbits(32))
            seed += b''.join(struct.pack('<BQ', rng.randrange(256), rng.getrandbits(64))
                             for _ in range(10))
            seeds.append(seed)
    elif args.harness == 'a64_semantics_fuzzer':
        seeds = [semantics_seed(rng, w) for _, w in words]
    else:
        sys.exit('unknown harness ' + args.harness)
    for i, seed in enumerate(seeds):
        with open(os.path.join(args.out, 'seed-%06d' % i), 'wb') as f:
            f.write(seed)
    print('%s: wrote %d seeds from %d encodings' % (args.harness, len(seeds), len(words)))


if __name__ == '__main__':
    main()
