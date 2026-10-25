# SPDX-License-Identifier: MIT
"""Admit a secondary's shared EL2 regime using actual firmware page tables.

Supported: the measured non-VHE, 4 KiB, 44-bit A16 EL2 regime, and a VHE
entry (QEMU AAVMF, HCR_EL2.E2H=1) read as the non-VHE regime the monitor
switches to (compat/vhe-tcr.h): TTBR0 only, 4 KiB, 44- to 48-bit VA and PA.
This does not create or edit tables. Call while the primary regime is stable.
"""
import struct


def vhe_tcr_to_el2(vhe):
    """compat/vhe-tcr.h vhe_tcr_to_el2, field by field (tools/test-vhe-tcr.py pins the C side)."""
    el2 = vhe & 0xff3f
    el2 |= ((vhe >> 32) & 7) << 16
    el2 |= ((vhe >> 37) & 1) << 20
    el2 |= ((vhe >> 39) & 3) << 21
    el2 |= ((vhe >> 41) & 1) << 24
    el2 |= ((vhe >> 43) & 0xf) << 25
    el2 |= ((vhe >> 51) & 1) << 29
    el2 |= ((vhe >> 57) & 1) << 30
    el2 |= ((vhe >> 59) & 1) << 32
    return el2 | (1 << 23) | (1 << 31)


def output_mask(tcr):
    """Descriptor output address bits for a non-VHE TCR_EL2 PS of 44 or 48 bits."""
    return (1 << (44 if (tcr >> 16) & 7 == 4 else 48)) - 4096


def validate_regime(memory):
    """(SCTLR, TCR, TTBR0, MAIR) as the monitor runs them: secondary_prepare_records
    compares these with its own EL2 registers after _start's E2H switch."""
    sctlr, tcr, ttbr, mair, hcr = (int(memory[k], 16) for k in ('sctlr', 'tcr', 'ttbr0', 'mair', 'hcr'))
    if hcr & (1 << 34):
        # VHE entry: TTBR1 walks must be off (EPD1), or the switch would drop a live half.
        if not (tcr >> 23) & 1:
            raise ValueError('unsupported primary EL2 memory regime')
        tcr = vhe_tcr_to_el2(tcr)
    if (sctlr & 0x1005 != 0x1005 or not 16 <= tcr & 63 <= 20 or (tcr >> 14) & 3 or
            (tcr >> 8) & 63 != 0x35 or (tcr >> 16) & 7 not in (4, 5) or
            ttbr & ~output_mask(tcr) or not ttbr):
        raise ValueError('unsupported primary EL2 memory regime')
    return sctlr, tcr, ttbr, mair


def verify(read, memory, ranges, ram_ranges):
    _, tcr, root, mair = validate_regime(memory)
    oa = output_mask(tcr)
    tables = set()

    def descriptor(table, slot):
        if not any(lo <= table and table+4096 <= hi for lo, hi in ram_ranges):
            raise ValueError('host table outside declared RAM')
        tables.add(table)
        return struct.unpack('<Q', read(table+slot*8, 8))[0]

    def walk(va):
        if not 0 <= va < 1 << 44:
            raise ValueError('host VA outside admitted TCR range')
        table = root
        for level, shift in enumerate((39, 30, 21, 12)):
            desc = descriptor(table, (va >> shift) & 511)
            form = desc & 3
            if (level == 3 and form == 3) or (level in (1, 2) and form == 1):
                mask = (1 << shift)-1
                if desc & oa & mask:
                    raise ValueError('misaligned host block descriptor')
                pa = (desc & oa & ~mask) | (va & mask)
                return pa, desc, shift
            if form != 3 or level == 3:
                raise ValueError('invalid host translation descriptor')
            table = desc & oa
        raise ValueError('missing host translation')

    witnesses = []
    for name, base, size, device in ranges:
        if size <= 0 or base % 4096:
            raise ValueError('invalid mapping request')
        for offset in range(0, size, 4096):
            va = base+offset
            pa, desc, shift = walk(va)
            attr = (mair >> (((desc >> 2) & 7)*8)) & 255
            if pa != va or not desc & (1 << 10) or desc & (1 << 7):
                raise ValueError('host range must be identity mapped, accessed and writable')
            if (device and attr != 0) or (not device and
                    (attr != 255 or (desc >> 8) & 3 != 3)):
                raise ValueError('incompatible shared RAM or Device memory attributes')
            if name == 'code' and desc & (1 << 54):
                raise ValueError('secondary code is not executable')
            witnesses.append(dict(name=name, va=hex(va), pa=hex(pa), desc=hex(desc),
                                  leaf_shift=shift, memory_attribute=hex(attr)))
    # These table pages are read through the primary's identity map. Check
    # that assumption as well; newly encountered intermediate tables follow.
    checked = set()
    while tables-checked:
        table = next(iter(tables-checked))
        pa, desc, _ = walk(table)
        if (pa != table or ((mair >> (((desc >> 2) & 7)*8)) & 255) != 255
                or (desc >> 8) & 3 != 3 or not desc & (1 << 10)):
            raise ValueError('host table is not identity-mapped normal WB memory')
        checked.add(table)
    return dict(mappings=witnesses, table_pages=[hex(p) for p in sorted(tables)])
