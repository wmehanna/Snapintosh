#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin compat/vhe-tcr.h: TCR_EL2 from the FEAT_VHE layout to the non-VHE one.

QEMU's AAVMF hands q1n1 EL2 under VHE (HCR_EL2 0x408000038, TCR_EL2
0x580803510); the monitor clears E2H, so _start converts TCR_EL2 with this
function. Without it the value reads as PS=0 and q1n1's tables above 4 GiB
take an address size fault (snaplab run3, ESR_EL2 0x86000001). The harness is
compiled for the host with UBSan; the header is plain integer arithmetic.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
checks = []


def check(condition, label):
    checks.append((bool(condition), label))
    print(f'{"PASS" if condition else "FAIL"}  {label}')


HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include "vhe-tcr.h"
int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        printf("%llx %llx\n", (unsigned long long)vhe_tcr_to_el2(strtoull(argv[i], 0, 0)),
               (unsigned long long)vhe_tcr_bridge(strtoull(argv[i], 0, 0)));
    return 0;
}
'''
RES1 = (1 << 23) | (1 << 31)
MOVES = {32: 16, 33: 17, 34: 18, 37: 20, 39: 21, 40: 22, 41: 24, 43: 25, 44: 26,
         45: 27, 46: 28, 51: 29, 57: 30, 59: 32, **{b: b for b in (*range(0, 6), *range(8, 16))}}
DROPPED = [6, 7, *range(16, 32), 35, 36, 38, 42, *range(47, 51), *range(52, 57), 58, *range(60, 64)]

with tempfile.TemporaryDirectory() as tmp:
    source, binary = Path(tmp) / 'h.c', Path(tmp) / 'h'
    source.write_text(HARNESS)
    cc = os.environ.get('SNAP_HOST_CC', 'clang')
    subprocess.run([cc, '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', f'-I{ROOT / "compat"}', str(source), '-o', str(binary)],
                   check=True)
    inputs = [0x580803510] + [1 << b for b in MOVES] + [1 << b for b in DROPPED]
    bridges = [0x580803510, 0x580003510, 0x380803510, 0x280803510, 0x080803510, 0x2580803510]
    run = subprocess.run([str(binary), *map(hex, inputs + bridges)], check=True,
                         capture_output=True, text=True)
    pairs = [tuple(int(w, 16) for w in line.split()) for line in run.stdout.splitlines()]
    out = [a for a, _ in pairs[:len(inputs)]]
    bridged = [b for _, b in pairs[len(inputs):]]

aavmf, rest = out[0], out[1:]
check(aavmf == 0x80853510, f'AAVMF TCR_EL2 0x580803510 -> {aavmf:#x} (want 0x80853510)')
check((aavmf >> 16) & 7 == 5 and 0x43f667000 < 1 << 48,
      'its PS is 48 bits, so the q1n1 table at 0x43f667000 is in range')
moved = rest[:len(MOVES)]
for (src, dst), value in zip(MOVES.items(), moved):
    if value != (1 << dst) | RES1:
        check(False, f'bit {src} should land on bit {dst}, got {value:#x}')
check(all(v == (1 << d) | RES1 for (s, d), v in zip(MOVES.items(), moved)),
      'every VHE field lands on its non-VHE position (T0SZ..TG0, IPS, TBI0, HA, HD, HPD0, HWU, TBID0, TCMA0, DS)')
dropped = rest[len(MOVES):]
check(all(v == RES1 for v in dropped),
      'TTBR1 fields, EPD0, AS, TBI1, HPD1, NFD, E0PD and RES0 bits are dropped; RES1 23 and 31 always set')

# The bridge: valid in the VHE layout (TCR_EL1 format) and in the EL2 layout.
b = bridged[0]
check(b == 0x480853510, f'AAVMF bridge {b:#x} (want 0x480853510)')
check(b & 0xff3f == 0x3510, 'bridge keeps the TTBR0 walk (T0SZ, IRGN0, ORGN0, SH0, TG0)')
check((b >> 16) & 7 == 5 and not (b >> 32) & 1 and b & RES1 == RES1,
      'non-VHE view: PS = entry IPS (48 bits), DS (bit 32) clear, RES1 set')
check((b >> 32) & 7 == 4 and (b >> 23) & 1 and (b >> 30) & 3 == 2 and not (b >> 22) & 1,
      'VHE view: IPS 44 bits covers the 16 GiB guest, EPD1 set, TG1 4 KiB, A1 clear')
check(bridged[1] == 0, 'TTBR1 walks enabled (EPD1 clear): no bridge')
check(bridged[2] == 0 and bridged[3] == 0 and bridged[4] == 0,
      'entry IPS below 44 bits: no bridge (no encoding keeps DS and MTX clear)')
check(not (b >> 32) & 3, 'bits 32 (DS) and 33 (MTX) clear in the bridge')
check((b >> 16) & 0x3f == 5 and not b & ((1 << 22) | (0x3f << 24)),
      'VHE view: T1SZ carries only PS, A1/IRGN1/ORGN1/SH1 cleared (TTBR1 off by EPD1)')
check(bridged[5] >> 37 == 1, 'fields above IPS (TBI0 and up) are kept for the VHE view')

failed = [label for ok, label in checks if not ok]
print(f'{len(checks) - len(failed)}/{len(checks)} passed')
sys.exit(1 if failed else 0)
