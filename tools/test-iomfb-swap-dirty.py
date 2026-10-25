#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Regression guard for gen-iomfb-header.py: the generated IOMobileGraphicsFamily26A428.h must declare
# the three members the AdrenoDisplay kext unit uses, at the offsets evidenced from the KDK:
#   IOMFBSwapFields::dirtyValid  swap+0x228 bit 0   (getCurrentDirtyRegion_gated iomgf 0x2c7ac:
#                                                     ldrb w9,[swap,#0x228]; tbz w9,#0)
#   IOMFBSwapFields::dirtyRect   swap+0x1a1 Rect     (same function: add x9,swap,#0x1a1; unaligned)
#   IOSurface::getCacheMode()    __ZNK9IOSurface12getCacheModeEv (IOSurface 0x15894: ldr w0,[this,#0x9c])
# Checks the generator's emitted text directly (no KDK needed). If the header has already been generated,
# it is checked too.
import re
import runpy
from pathlib import Path

GEN = Path(__file__).with_name('gen-iomfb-header.py')
mod = runpy.run_path(str(GEN))
swap = mod['SWAP_FIELDS']
iosurface = mod['IOSURFACE_BLOCK']
checks = 0


def want(text, pattern, msg):
    global checks
    assert re.search(pattern, text), msg
    checks += 1


# Offset constants, exact values.
want(swap, r'kDirtyValid\s*=\s*0x228\b', 'dirty-valid offset must be swap+0x228')
want(swap, r'kDirtyRect\s*=\s*0x1a1\b', 'dirty-rect offset must be swap+0x1a1')
# dirtyValid: bool, reads kDirtyValid, masks bit 0.
want(swap, r'bool\s+dirtyValid\s*\(\s*const\s+IOMFBSwapIORequest\s*\*',
     'dirtyValid(const IOMFBSwapIORequest *) must return bool')
want(swap, r'dirtyValid\b[\s\S]{0,120}kDirtyValid[\s\S]{0,40}&\s*1',
     'dirtyValid must read kDirtyValid and test bit 0')
# dirtyRect: Rect by memcpy (unaligned) at kDirtyRect.
want(swap, r'Rect\s+dirtyRect\s*\(\s*const\s+IOMFBSwapIORequest\s*\*',
     'dirtyRect(const IOMFBSwapIORequest *) must return Rect')
want(swap, r'dirtyRect\b[\s\S]{0,160}memcpy[\s\S]{0,60}kDirtyRect',
     'dirtyRect must memcpy from kDirtyRect (unaligned)')
# getCacheMode on IOSurface: non-virtual, uint32_t, const.
want(iosurface, r'uint32_t\s+getCacheMode\s*\(\s*\)\s*const\s*;',
     'IOSurface must declare uint32_t getCacheMode() const')

# If the header exists in the tree, assert the same three appear in it.
header = GEN.parents[1] / 'gpu/adreno-kext/kext/include/IOMobileGraphicsFamily26A428.h'
if header.is_file():
    text = header.read_text()
    for token in ('kDirtyValid = 0x228', 'kDirtyRect = 0x1a1',
                  'bool dirtyValid(', 'Rect dirtyRect(', 'uint32_t getCacheMode() const'):
        assert token in text, f'generated header missing: {token}'
        checks += 1
    note = ' (and the generated header)'
else:
    note = ' (header not generated; generator text only)'

print(f'IOMFB swap dirty / getCacheMode members: {checks} checks passed{note}')
