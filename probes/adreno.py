# SPDX-License-Identifier: MIT
"""Stage 4: the Adreno X2-90 in the guest's device tree and the monitor's params.

The monitor side is compat/adreno.h; the design is docs/ADRENO-STAGE4-20260925.md.
Power stays with q1n1: its `tools/a16gpu.py adopt` proves "CP idle after
cp-fence" read-only and writes the adoption record this module validates and
turns into struct adreno_params (ADRENO_PARAMS_WORDS words, field order).

The tree gains, all under /arm-io:
  * two `ranges` triples: child 0x7_03D0_0000 -> parent 0x03D00000 (the GPU
    aperture, 0xA0000) and an identity window for the virtual DART's registers;
  * `adreno`, the GPU node the AdrenoX2 kext matches (IONameMatch
    snapintosh,adreno-x2): reg = the passthrough windows only, interrupts =
    AIC 975 (the source the withdrawn /arm-io/sgx held), iommu-parent =
    mapper-adreno;
  * `dart-adreno` + `mapper-adreno`, dart-sio's property set with its own
    reg, interrupt (976, sgx's second), phandle, dart-id 31 and a
    [1 GiB, 4 GiB) window ([1 GiB, 16 GiB) with AdrenoSpec.va_wide, for a
    -DADRENO_VA_WIDE=1 monitor and kext: agents/gpu-va-wide). The monitor
    models its registers like SIO's and mirrors stream 0 into the Adreno
    SMMU's context bank 0.
With SNAP_SOFTGPU=1 (lab board, QEMU's snap-softgpu device; plans/p6-softgpu-integration.md W1) the tree gains one more
`ranges` triple for the device's page 0 and a last `reg` entry on `adreno`, named by `snapintosh,softgpu-reg`; see
SoftGpuSpec. Page 1 (the monitor's DMA-window page) is in neither.
Nothing in the tree names the q1n1 GPU arena: it is not guest memory, stage 2
never maps it, and the DART admits only guest-owned frames.
"""
from dataclasses import dataclass
import json
import struct

PARAMS_WORDS = 16
# compat/adreno.h, checked against the header by tools/test-adreno-image.py.
GPU_PA = 0x03D00000
PASS0_END = 0x03D37000
PASS1_PA, PASS1_END = 0x03D3C000, 0x03D40000
CX_MISC_PA, CX_MISC_END = 0x03D9E000, 0x03DA0000
APERTURE_END = 0x03DA0000               # the tree's GPU range stops before the SMMU
CHILD_BASE = 0x7_03D0_0000              # plan: arm-io child 0x7_03D0_0000 -> 0x03D00000
DART_REG = 0x7_1000_0000                # virtual DART registers (stage 2 leaves it absent)
DART_SPAN = 0x20000
DART_ID = 31
DART_IRQ = 976
GPU_IRQ = 975
INTID = 0x14C                           # glymur.dtsi GIC_SPI 300; A16 ACPI GFX_INTERRUPT
WINDOW_BASE, WINDOW_END = 0x4000_0000, 0x1_0000_0000
POOL_BYTES = (3 + ((WINDOW_END - WINDOW_BASE) >> 21)) * 0x1000
# ADRENO_VA_WIDE (compat/adreno.h; agents/gpu-va-wide FAILURE-MODES.md): CB0 T0SZ 30, window [1 GiB, 16 GiB),
# one level-2 table per GiB then one level-3 table per 2 MiB, all preallocated (a mirror failure is terminal), in
# a monitor-private reservation (xnuboot.gpu_pool_reservation) instead of the arena's snap_smmu pool.
WINDOW_END_WIDE = 0x4_0000_0000
CB0_T0SZ, CB0_T0SZ_WIDE = 32, 30
GPU_VA_BITS_PROPERTY = 'snapintosh,gpu-va-bits'     # the wide kext refuses to start without 34 here
POOL_RESERVATION_ALIGN = 0x10000


# SoftGPU device page (compat/softgpu.h, checked by tools/test-adreno-image.py).
SOFTGPU_MAGIC = int.from_bytes(b'SNAPSGP1', 'little')
SOFTGPU_F_PAGE0 = 1
SOFTGPU_PARAMS_WORDS = 5
SOFTGPU_PAGE = 0x1000
SOFTGPU_WINDOW = (0x0C000000, 0x0E000000)   # compat/softgpu.h SOFTGPU_WINDOW_LO/HI
SOFTGPU_INTID_FIRST, SOFTGPU_INTID_LAST = 32, 1019
SOFTGPU_CHILD_BASE = 0x7_0000_0000      # arm-io child address of page 0 = this + its physical address (0x7_0C00_0000)
SOFTGPU_COMPATIBLE = 'snapintosh,softgpu'
SOFTGPU_REG_PROPERTY = 'snapintosh,softgpu-reg'     # the ADT interface to the kext (index into the adreno node's reg)


def window_end(wide=False):
    return WINDOW_END_WIDE if wide else WINDOW_END


def pool_bytes(wide=False):
    """compat/adreno.h ADRENO_POOL_BYTES: (ADRENO_L2_TABLES + ADRENO_L3_TABLES) pages."""
    span = window_end(wide) - WINDOW_BASE
    return ((span >> 30) + (span >> 21)) * 0x1000


def pool_reservation_bytes():
    """The wide pool's monitor-private reservation: pool_bytes(True) on the 64 KiB grid (0x1E10000)."""
    return (pool_bytes(True) + POOL_RESERVATION_ALIGN - 1) & ~(POOL_RESERVATION_ALIGN - 1)


assert pool_bytes() == POOL_BYTES and pool_bytes(True) == 0x1E0F000
CHIP_ID = 0x44070041                    # q1n1 Stage 1: 0x44070001 | 4 slices << 4 (PROVEN)
GICD_A16 = 0x17000000                   # q1n1 gicv3.c: MADT on BIOS312 (PROVEN)
F_ENABLE, F_CX_MISC, F_DART, F_RING, F_TZ_DONE, F_SELF_IRQ, F_RECORD = 1, 2, 4, 8, 16, 32, 64
GPU_NODE = '/device-tree/arm-io/adreno'
DART_NODE = '/device-tree/arm-io/dart-adreno'
MAPPER_NODE = DART_NODE + '/mapper-adreno'
MATCH = 'snapintosh,adreno-x2'
SLOT_NODE = '/device-tree/arm-io/adreno-display'
SLOT_MATCH = 'snapintosh,adreno-display'
DISPLAY_TYPES = (b'display-subsystem', b'ext-display-subsystem')
TEMPLATE = '/device-tree/arm-io/dart-sio'
ADOPT_SCHEMA = 'q1n1-adreno-adopt-v1'
# The monitor fences on its own 64-byte line of cp-fence's memptrs page (q1n1
# writes rptr shadows at +0x0/+0x8 and fences at +0x40/+0x50/+0x60).
FENCE_OFF = 0x80


@dataclass(frozen=True)
class AdrenoSpec:
    dart: bool = True             # dart-adreno + iommu-parent, and the CB0 mirror
    cx_misc: bool = True          # CX_MISC read-only passthrough (optional in the plan)
    ring_at_seconds: int = 60     # the in-run test fence
    self_irq: bool = True         # one GICD_ISPENDR self-test of the IRQ path
    ring_test: bool = True        # Stage 4 monitor fences; off when the guest owns its ring
    display_slot: bool = False    # adreno-display replaces a withdrawn disp0 (display_slot())
    va_wide: bool = False         # ADRENO_VA_WIDE: [1 GiB, 16 GiB), CB0 T0SZ 30, pool outside the arena
    record_only: bool = False     # ADRENO_F_RECORD: the lab board has no GPU, adopt from the record

    def flags(self):
        return (F_ENABLE | (F_CX_MISC if self.cx_misc else 0) | (F_DART if self.dart else 0) |
                (F_RING if self.ring_test else 0) | (F_SELF_IRQ if self.self_irq else 0) |
                (F_RECORD if self.record_only else 0))


def passthrough(spec):
    """(pa, size, access) of every window the guest reaches, in the node's reg order."""
    windows = [(GPU_PA, PASS0_END - GPU_PA, 'rw'), (PASS1_PA, PASS1_END - PASS1_PA, 'rw')]
    if spec.cx_misc:
        windows.append((CX_MISC_PA, CX_MISC_END - CX_MISC_PA, 'ro'))
    return windows


def stage2_ranges(spec):
    """The monitor's stage-2 passthrough, as probes/xnuboot.stage2_ranges lists ranges."""
    return [(pa, pa + size, access, f'Adreno {"registers" if access == "rw" else "CX_MISC"} '
             '(Device-nGnRE)') for pa, size, access in passthrough(spec)]


# shadow/stage2.h leaf bits of the passthrough: S2_AP_RW or S2_AP_RO | S2_ATTRS_DEVICE
# (Device-nGnRE, SH inner, AF), upper S2_XN. tools/test-adreno-image.py derives them from the header.
S2_DEVICE_RW, S2_DEVICE_RO, S2_XN = 0x7C4, 0x744, 1 << 54


def stage2_audit_ranges(flags):
    """The passthrough as tools/stage2audit.py audits a stopped monitor's stage 2:
    [(lo, hi, low attributes, upper attributes)] from params.gpu.flags (0: none)."""
    if not flags & F_ENABLE:
        return []
    rows = [(GPU_PA, PASS0_END, S2_DEVICE_RW, S2_XN), (PASS1_PA, PASS1_END, S2_DEVICE_RW, S2_XN)]
    if flags & F_CX_MISC:
        rows.append((CX_MISC_PA, CX_MISC_END, S2_DEVICE_RO, S2_XN))
    return rows


@dataclass(frozen=True)
class SoftGpuSpec:
    """The QEMU SoftGPU device as the board's own tree names it: page 0's physical address and its GIC INTID."""
    page0: int
    intid: int

    def __post_init__(self):
        if (self.page0 & (SOFTGPU_PAGE - 1) or not SOFTGPU_WINDOW[0] <= self.page0 <= SOFTGPU_WINDOW[1] - 2 * SOFTGPU_PAGE or
                not SOFTGPU_INTID_FIRST <= self.intid <= SOFTGPU_INTID_LAST):
            raise ValueError(f'SoftGPU page 0 {self.page0:#x} / INTID {self.intid} are not a device page and an SPI')

    @property
    def page1(self):
        return self.page0 + SOFTGPU_PAGE

    @property
    def child(self):
        return SOFTGPU_CHILD_BASE + self.page0


def softgpu_params_words(spec):
    """struct softgpu_params (compat/softgpu.h), in field order."""
    if spec is None:
        raise ValueError('no SoftGPU spec')
    words = [SOFTGPU_MAGIC, SOFTGPU_F_PAGE0, spec.page0, spec.page1, spec.intid]
    assert len(words) == SOFTGPU_PARAMS_WORDS
    return words


def softgpu_rows(words):
    """compat/softgpu.h softgpu_rows: [(lo, hi)] of a valid block, or None."""
    if len(words) != SOFTGPU_PARAMS_WORDS:
        return None
    magic, flags, page0, page1, intid = words
    if (magic != SOFTGPU_MAGIC or flags != SOFTGPU_F_PAGE0 or page0 & (SOFTGPU_PAGE - 1) or
            not SOFTGPU_WINDOW[0] <= page0 <= SOFTGPU_WINDOW[1] - 2 * SOFTGPU_PAGE or page1 != page0 + SOFTGPU_PAGE or not SOFTGPU_INTID_FIRST <= intid <= SOFTGPU_INTID_LAST):
        return None
    return [(page0, page0 + SOFTGPU_PAGE)]


def softgpu_stage2_ranges(spec):
    """The monitor's stage-2 row for page 0, as probes/xnuboot.stage2_ranges lists ranges (page 1 is absent)."""
    if spec is None:
        return []
    return [(spec.page0, spec.page0 + SOFTGPU_PAGE, 'rw', 'SoftGPU page 0 (Device-nGnRE)')]


def softgpu_audit_ranges(words):
    """The page as tools/stage2audit.py audits a stopped monitor's stage 2: [(lo, hi, low, upper)] (none if invalid)."""
    return [(lo, hi, S2_DEVICE_RW, S2_XN) for lo, hi in softgpu_rows(words) or ()]


FDT_MAGIC = 0xD00DFEED


def parse_fdt(blob):
    """A flattened device tree as nested dicts: {'name', 'props': {name: bytes}, 'children': [...], 'parent'}.
    Just enough of the format for QEMU's `dumpdtb` output (version 17, no overlays); anything else raises ValueError."""
    if len(blob) < 40 or struct.unpack('>I', blob[:4])[0] != FDT_MAGIC:
        raise ValueError('not a flattened device tree')
    total, off_struct, off_strings, _, version, _, _, size_strings, size_struct = struct.unpack('>9I', blob[4:40])
    if version < 16 or total > len(blob) or off_struct + size_struct > total or off_strings + size_strings > total:
        raise ValueError('malformed device tree header')
    strings = blob[off_strings:off_strings + size_strings]
    root = {'name': '', 'props': {}, 'children': [], 'parent': None}
    node, at, end = None, off_struct, off_struct + size_struct
    while at < end:
        token = struct.unpack('>I', blob[at:at + 4])[0]
        at += 4
        if token == 1:
            stop = blob.index(b'\0', at)
            name = blob[at:stop].decode()
            at = (stop + 4) & ~3
            if node is None:
                node = root
            else:
                node = {'name': name, 'props': {}, 'children': [], 'parent': node}
                node['parent']['children'].append(node)
        elif token == 2:
            if node is None:
                raise ValueError('unbalanced device tree')
            node = node['parent']
        elif token == 3:
            length, name_off = struct.unpack('>II', blob[at:at + 8])
            data = blob[at + 8:at + 8 + length]
            at = (at + 8 + length + 3) & ~3
            name = strings[name_off:strings.index(b'\0', name_off)].decode()
            node['props'][name] = data
        elif token == 9:
            break
        elif token != 4:
            raise ValueError(f'unknown device tree token {token}')
    if node is not None:
        raise ValueError('unbalanced device tree')
    return root


def _cells(node, name, default):
    value = node['props'].get(name)
    return struct.unpack('>I', value)[0] if value else default


def _walk(node):
    yield node
    for child in node['children']:
        yield from _walk(child)


def _combine(blob, count):
    out = 0
    for (value,) in struct.iter_unpack('>I', blob[:4 * count]):
        out = out << 32 | value
    return out


def softgpu_from_dtb(blob):
    """the parse below, with every parse failure as ValueError."""
    try:
        return _softgpu_from_dtb(blob)
    except (TypeError, KeyError, IndexError, struct.error, ZeroDivisionError, RecursionError, UnicodeDecodeError) as error:
        raise ValueError(f'malformed device tree: {error!r}') from error


def _softgpu_from_dtb(blob):
    """The SoftGPU device in a QEMU `dumpdtb` tree: page 0 (reg 0, translated through every ancestor's `ranges`),
    page 1 must follow it, and the SPI of `interrupts`. Exactly one node with compatible `snapintosh,softgpu`;
    a missing node, a second one, a missing interrupt or a page 1 anywhere else raises ValueError."""
    root = parse_fdt(blob)
    found = [n for n in _walk(root)
             if SOFTGPU_COMPATIBLE.encode() in n['props'].get('compatible', b'').split(b'\0')]
    if len(found) != 1:
        raise ValueError(f'the tree names {len(found)} {SOFTGPU_COMPATIBLE} nodes, not one')
    node = found[0]
    parent = node['parent']
    ac, sc = _cells(parent, '#address-cells', 2), _cells(parent, '#size-cells', 1)
    reg = node['props'].get('reg', b'')
    if ac < 1 or sc < 1 or len(reg) != 8 * (ac + sc):
        raise ValueError('the SoftGPU node needs exactly two (address, size) reg entries')
    entries = [(_combine(reg[4 * (ac + sc) * i:], ac), _combine(reg[4 * (ac + sc) * i + 4 * ac:], sc)) for i in range(2)]
    physical = []
    for address, size in entries:
        level = parent
        while level['parent'] is not None:
            ranges = level['props'].get('ranges')
            if ranges:       # empty ranges is the identity
                outer = level['parent']
                ca, pa, cs = _cells(level, '#address-cells', 2), _cells(outer, '#address-cells', 2), _cells(level, '#size-cells', 1)
                width = 4 * (ca + pa + cs)
                for i in range(len(ranges) // width):
                    row = ranges[i * width:]
                    child, base, span = _combine(row, ca), _combine(row[4 * ca:], pa), _combine(row[4 * (ca + pa):], cs)
                    if child <= address and address + size <= child + span:
                        address = base + (address - child)
                        break
                else:
                    raise ValueError('a SoftGPU reg entry lies outside its parent bus ranges')
            level = level['parent']
        physical.append((address, size))
    (page0, size0), (page1, size1) = physical
    if size0 != SOFTGPU_PAGE or size1 != SOFTGPU_PAGE or page1 != page0 + SOFTGPU_PAGE:
        raise ValueError(f'SoftGPU pages {page0:#x}+{size0:#x}, {page1:#x}+{size1:#x} are not two adjacent 4 KiB pages')
    irq = node['props'].get('interrupts', b'')
    if len(irq) != 12:
        raise ValueError('the SoftGPU node needs one three-cell interrupt')
    kind, number, _ = struct.unpack('>3I', irq)
    if kind != 0:
        raise ValueError('the SoftGPU interrupt is not an SPI')
    return SoftGpuSpec(page0, number + 32)


def _phandle(dt):
    used = [struct.unpack('<I', props['AAPL,phandle'].value)[0]
            for props in dt.nodes.values() if 'AAPL,phandle' in props]
    return max(used) + 1


def _node(dt, parent, path, props):
    from appledt import Property
    if path in dt.nodes or parent not in dt.nodes:
        raise ValueError(f'{path}: already present or parent missing')
    dt.nodes[path] = {k: Property(k, v) for k, v in props.items()}
    dt.children[path] = []
    dt.children[parent].append(path)


def display_slot(dt):
    """AdrenoDisplay's entry in IOMobileFramebuffer.framework's display count.

    The framework enumerates only when /arm-io has a display-subsystem or
    ext-display-subsystem child and waits for one service per such child
    (gpu/adreno-kext/kext/src/AdrenoDisplay.h). Run after the Apple display pipe
    is withdrawn. No registers, interrupts or phandle, and no driver matches it:
    AdrenoDisplay still attaches under the accelerator."""
    bus = '/device-tree/arm-io'
    for child in dt.children[bus]:
        kind = dt.get(child, 'device_type')
        if kind is not None and bytes(kind).rstrip(b'\0') in DISPLAY_TYPES:
            raise ValueError(f'{child} is still a display-subsystem; withdraw it first')
    _node(dt, bus, SLOT_NODE, {'name': b'adreno-display\0',
                               'compatible': SLOT_MATCH.encode() + b'\0',
                               'device_type': b'display-subsystem\0'})
    return SLOT_NODE


def prepare_tree(dt, spec, owned=(), softgpu=None):
    """Add the ranges and nodes, all or nothing. `owned` is [(base, size)] the
    guest's memory and the monitor's: the virtual DART window must miss it.
    `softgpu` (SoftGpuSpec, SNAP_SOFTGPU=1): one more range for the device's page 0, appended as the last `reg` of
    the `adreno` node and named by `snapintosh,softgpu-reg` (its index). Page 1 is never added."""
    bus = '/device-tree/arm-io'
    raw = dt.nodes[bus]['ranges']
    if raw.placeholder or len(raw.value) % 24:
        raise ValueError('arm-io ranges are not resolved (child, parent, span) triples')
    ranges = list(struct.iter_unpack('<3Q', raw.value))
    add = [(CHILD_BASE, GPU_PA, APERTURE_END - GPU_PA)]
    if spec.dart:
        add.append((DART_REG, DART_REG, DART_SPAN))
    if softgpu is not None:
        add.append((softgpu.child, softgpu.page0, SOFTGPU_PAGE))
    for i, (c1, p1, s1) in enumerate(add):
        for c2, p2, s2 in add[i + 1:]:
            if c1 < c2 + s2 and c2 < c1 + s1 or p1 < p2 + s2 and p2 < p1 + s1:
                raise ValueError(f'new arm-io ranges {c1:#x} and {c2:#x} overlap')
    for child, parent, span in add:
        for c, p, s in ranges:
            if child < c + s and c < child + span:
                raise ValueError(f'arm-io child range {child:#x} overlaps {c:#x}')
            if parent < p + s and p < parent + span:
                raise ValueError(f'arm-io parent range {parent:#x} overlaps {p:#x}')
    for base, size in owned:
        if any(parent < base + size and base < parent + span for _, parent, span in add):
            raise ValueError('an Adreno window overlaps guest or monitor memory')
    aic = dt.get(bus + '/aic', 'AAPL,phandle')
    if aic is None or GPU_NODE in dt.nodes or DART_NODE in dt.nodes:
        raise ValueError('no AIC phandle, or the Adreno nodes already exist')
    # AIC 975/976 belong to /arm-io/sgx, which every audited profile withdraws.
    for path, props in dt.nodes.items():
        if 'interrupts' in props and path != bus + '/sgx' and not path.startswith(bus + '/sgx/'):
            irqs = struct.iter_unpack('<I', props['interrupts'].value[:len(props['interrupts'].value) // 4 * 4])
            if {GPU_IRQ, DART_IRQ} & {v for (v,) in irqs}:
                raise ValueError(f'{path} already uses AIC {GPU_IRQ} or {DART_IRQ}')
    phandle = _phandle(dt)
    gpu = {
        'name': b'adreno\0', 'compatible': MATCH.encode() + b'\0', 'device_type': b'adreno\0',
        'reg': b''.join(struct.pack('<QQ', CHILD_BASE + (pa - GPU_PA), size)
                        for pa, size, _ in passthrough(spec)),
        'interrupt-parent': aic, 'interrupts': struct.pack('<I', GPU_IRQ),
        'chip-id': struct.pack('<I', CHIP_ID),
        # HVC #0 with x0 = 0x42002801 or 0x42000c1b (compat/adreno.h allow-list).
        'snapintosh,smc-hvc': struct.pack('<I', 1),
        'AAPL,phandle': struct.pack('<I', phandle + 2),
    }
    if softgpu is not None:
        gpu[SOFTGPU_REG_PROPERTY] = struct.pack('<I', len(gpu['reg']) // 16)
        gpu['reg'] += struct.pack('<QQ', softgpu.child, SOFTGPU_PAGE)
    if spec.dart and not spec.ring_test:
        gpu['snapintosh,guest-fence-abi'] = struct.pack('<I', 1)
        gpu['snapintosh,guest-unmap-abi'] = struct.pack('<I', 1)
        gpu['snapintosh,guest-cache-abi'] = struct.pack('<I', 1)
        gpu['snapintosh,guest-fill32-abi'] = struct.pack('<I', 1)
        # ADRENO_GUEST_IB (compat/adreno-guest.h, compat/adreno-ib.c): the kext's IB path and its start probe.
        gpu['snapintosh,guest-ib-abi'] = struct.pack('<I', 1)
    if spec.va_wide:
        if not spec.dart:
            raise ValueError('the wide GPU VA window needs the virtual DART')
        gpu[GPU_VA_BITS_PROPERTY] = struct.pack('<I', 64 - CB0_T0SZ_WIDE)
    if spec.dart:
        template = dt.nodes[TEMPLATE]
        mapper = dt.nodes[TEMPLATE + '/mapper-sio']
        if any(p.placeholder for p in list(template.values()) + list(mapper.values())):
            raise ValueError('dart-sio is not resolved')
        dart = {k: bytes(v.value) for k, v in template.items()}
        dart.update({'name': b'dart-adreno\0', 'reg': struct.pack('<QQ', DART_REG, DART_SPAN),
                     'interrupts': struct.pack('<I', DART_IRQ),
                     'AAPL,phandle': struct.pack('<I', phandle),
                     'vm-base': struct.pack('<Q', WINDOW_BASE),
                     'vm-size': struct.pack('<Q', window_end(spec.va_wide) - WINDOW_BASE),
                     # Native t8110dart otherwise expects the high IOVA region.
                     # Presence selects its low-window table layout; the monitor
                     # still enforces our separate 1–4GiB aperture and stream0.
                     'noncompliant-dead-mappings': b'',
                     'dart-id': struct.pack('<I', DART_ID)})
        if set(dart) != set(template) | {'dart-id', 'noncompliant-dead-mappings'}:
            raise ValueError('dart-sio property set changed')
        mapped = {k: bytes(v.value) for k, v in mapper.items()}
        mapped.update({'name': b'mapper-adreno\0', 'AAPL,phandle': struct.pack('<I', phandle + 1),
                       'reg': struct.pack('<I', 0)})
        gpu['iommu-parent'] = struct.pack('<I', phandle + 1)
    dt.put(bus, 'ranges', raw.value + b''.join(struct.pack('<3Q', *r) for r in add))
    if spec.dart:
        _node(dt, bus, DART_NODE, dart)
        _node(dt, DART_NODE, MAPPER_NODE, mapped)
    _node(dt, bus, GPU_NODE, gpu)
    return dict(gpu=GPU_NODE, dart=DART_NODE if spec.dart else None, phandle=phandle)


STOP_ABI_PROPERTY = 'snapintosh,guest-stop-abi'      # compat/adreno-guest.h ADRENO_GUEST_STOP_PROPERTY
STOP_DELAY_PROPERTY = 'snapintosh,guest-stop-delay'  # ADRENO_GUEST_STOP_DELAY_PROPERTY


def advertise_early_stop(dt, delay_s):
    """ADRENO_GUEST_STOP on the GPU node, only for launches that enable the guest
    trigger (tools/early_stop.py). Without it the kext never issues the request."""
    if not 0 <= delay_s <= 3600:
        raise ValueError('early-stop delay outside [0, EARLY_STOP_DELAY_LIMIT]')
    dt.add(GPU_NODE, STOP_ABI_PROPERTY, struct.pack('<I', 1))
    dt.add(GPU_NODE, STOP_DELAY_PROPERTY, struct.pack('<I', delay_s))


NET_ABI_PROPERTY = 'snapintosh,guest-net-abi'        # compat/guest-net.h GUEST_NET_PROPERTY
NET_ABI = 1                                         # GUEST_NET_ABI


def advertise_guest_net(dt):
    """ADRENO_GUEST_NET on the GPU node, only for launches that enable the guest
    network (SNAP_EARLY_STOP=...,net). Without it SnapintoshVirtualEthernet never
    attaches a ring and keeps its carrier down (docs/GUEST-NETWORK-20261019.md)."""
    dt.add(GPU_NODE, NET_ABI_PROPERTY, struct.pack('<I', NET_ABI))


def load_adoption(path, info, wide=False):
    """q1n1's adoption record, checked against the live bootinfo it must describe (`wide`: from
    `a16gpu.py adopt --va-wide`, for an AdrenoSpec.va_wide launch)."""
    record = json.loads(open(path).read()) if isinstance(path, str) else dict(path)
    if record.get('schema') != ADOPT_SCHEMA:
        raise ValueError(f'adoption record schema {record.get("schema")!r} is not {ADOPT_SCHEMA}')
    arena = record['arena']
    checks = [
        (arena['base'] == info.get('gpu_arena_base') and arena['size'] == info.get('gpu_arena_size')
         and info.get('gpu_arena_flags'), 'the arena differs from bootinfo gpu_arena_*'),
        (record['gicd'] == info.get('gic_distributor'), 'the GIC distributor differs from bootinfo'),
        (record['stage_generation'] == info.get('stage_generation'),
         'the record comes from another q1n1 stage (adopt again after a chainload)'),
        (record['ready'] is True, 'q1n1 did not find the CP idle after cp-fence'),
    ]
    for ok, why in checks:
        if not ok:
            raise ValueError(f'adoption refused: {why}')
    validate_adoption(record, wide)
    return record


def validate_adoption(record, wide=False):
    """Layout checks the monitor repeats in part (adreno_adopt). `wide`: the record must come from
    `a16gpu.py cp-fence --va-wide` (CB0 T0SZ 30); otherwise from the default cp-fence (T0SZ 32)."""
    a0, size = record['arena']['base'], record['arena']['size']
    def inside(pa, n):
        return a0 <= pa and n <= size and pa - a0 <= size - n
    ring, fence, pool, cb0 = record['ring'], record['fence'], record['pool'], record['cb0']
    root = cb0['ttbr0'] & 0x0000FFFFFFFFF000
    spans = [('pool', pool['pa'], POOL_BYTES), ('ring', ring['pa'], ring['dwords'] * 4),
             ('fence', fence['pa'] & ~0x3F, 64), ('root', root, 0x1000)]
    if (a0 & 0xFFF or size & 0xFFF or not a0 or a0 + size > 1 << 36 or pool['pa'] & 0xFFF or
            pool['size'] < POOL_BYTES or ring['pa'] & 0xFFF or not 0 < ring['dwords'] <= 0x2000 or
            not 0 <= ring['wptr'] < ring['dwords'] or fence['pa'] & 3 or cb0['ttbr0'] & 0xFFF or
            not cb0['sctlr'] & 1 or (fence['va'] - fence['pa']) != (record['memptrs']['va'] -
                                                                     record['memptrs']['pa'])):
        raise ValueError('adoption record fields are malformed')
    for name, pa, n in spans:
        if not inside(pa, n):
            raise ValueError(f'adoption record: {name} lies outside the arena')
    for i, (n1, p1, s1) in enumerate(spans):
        for n2, p2, s2 in spans[i + 1:]:
            if p1 < p2 + s2 and p2 < p1 + s1:
                raise ValueError(f'adoption record: {n1} overlaps {n2}')
    if fence['va'] >> 30 or ring['va'] >> 30:
        raise ValueError('adoption record: CP buffers must sit below 1 GiB (CB0 root entry 0)')
    want = CB0_T0SZ_WIDE if wide else CB0_T0SZ
    if cb0['tcr'] & 0x3F != want or (cb0['tcr'] >> 14) & 3:
        raise ValueError(f'adoption record: CB0 TCR {cb0["tcr"]:#x} is not T0SZ {want} with a 4 KiB granule '
                         f'({"q1n1 cp-fence/adopt --va-wide" if wide else "the default cp-fence"} programs that)')


def params_words(spec, record, ring_at=None, pool_pa=None):
    """struct adreno_params, in field order. No spec: all zero (Stage 4 off). spec.va_wide: the pool word is
    pool_pa, the monitor-private reservation (xnuboot.gpu_pool_reservation), never the record's arena pool."""
    if spec is None:
        return [0] * PARAMS_WORDS
    if record is None:
        raise ValueError('an Adreno profile needs q1n1\'s adoption record (SNAP_ADRENO_ADOPT)')
    validate_adoption(record, spec.va_wide)
    if spec.va_wide:
        check_pool_reservation(record, pool_pa)
    elif pool_pa is not None:
        raise ValueError('a table reservation outside the arena needs the wide window (AdrenoSpec.va_wide)')
    flags = spec.flags() | (F_TZ_DONE if record.get('tz_init_done') else 0)
    words = [flags, record['gicd'], 0,                     # affinity: the monitor fills it
             record['arena']['base'], record['arena']['size'],
             record['cb0']['ttbr0'], record['cb0']['tcr'], record['cb0']['sctlr'],
             pool_pa if spec.va_wide else record['pool']['pa'],
             record['ring']['pa'], record['ring']['dwords'], record['ring']['wptr'],
             record['fence']['pa'], record['fence']['va'],
             spec.ring_at_seconds if ring_at is None else ring_at, 0]
    assert len(words) == PARAMS_WORDS
    return words


def check_pool_reservation(record, pool_pa, owned=()):
    """The wide pool (compat/adreno.c adreno_adopt repeats it): page aligned, no wrap, outside the arena, the CB0
    root page and every range in `owned` [(base, size)] (the guest's memory)."""
    if pool_pa is None or pool_pa & 0xFFF or not 0 < pool_pa < pool_pa + pool_bytes(True) <= 1 << 40:
        raise ValueError(f'wide GPU table pool {pool_pa!r}: missing, unaligned or out of range')
    end = pool_pa + pool_bytes(True)
    a0, size = record['arena']['base'], record['arena']['size']
    root = record['cb0']['ttbr0'] & 0x0000FFFFFFFFF000
    if pool_pa < a0 + size and a0 < end:
        raise ValueError('the wide GPU table pool overlaps the q1n1 arena')
    if pool_pa <= root < end:
        raise ValueError('the wide GPU table pool holds the CB0 root')
    for base, n in owned:
        if n and pool_pa < base + n and base < end:
            raise ValueError(f'the wide GPU table pool overlaps {base:#x}+{n:#x}')


def check_disjoint(record, ranges):
    """The arena must miss every range the guest or the monitor owns: [(base, size)]."""
    a0, size = record['arena']['base'], record['arena']['size']
    for base, n in ranges:
        if n and a0 < base + n and base < a0 + size:
            raise ValueError(f'the q1n1 GPU arena {a0:#x}+{size:#x} overlaps {base:#x}+{n:#x}')


def fixture_record(arena_base=0xFCC00000, generation=6, wide=False):
    """A record in the shape `a16gpu.py adopt` writes, for offline builds and tests (`wide`: after
    `cp-fence --va-wide`, CB0 T0SZ 30)."""
    tables = arena_base + 0x80000                     # q1n1 build_tables: CB0 half of 'tables'
    memptrs = arena_base + 0x148000
    return {'schema': ADOPT_SCHEMA, 'stage_generation': generation, 'ready': True,
            'arena': {'base': arena_base, 'size': 32 << 20}, 'gicd': GICD_A16,
            'cb0': {'ttbr0': tables, 'tcr': 0x802020 - CB0_T0SZ + (CB0_T0SZ_WIDE if wide else CB0_T0SZ),
                    'sctlr': 0x1167},
            'ring': {'pa': arena_base + 0x140000, 'va': 0x10100000, 'dwords': 8192, 'wptr': 22},
            'memptrs': {'pa': memptrs, 'va': 0x10200000},
            'fence': {'pa': memptrs + FENCE_OFF, 'va': 0x10200000 + FENCE_OFF},
            'pool': {'pa': arena_base + 0x1400000, 'size': 0x603000},
            'tz_init_done': True}


def record_for_stage(info, wide=False):
    """The fixture record retargeted at the stage that is booting now.

    q1n1 allocates its GPU arena on every stage, including QEMU's virt machine,
    and publishes gpu_arena_base/size (32 MiB, 2 MiB aligned, the same shape
    the fixture assumes), the GIC distributor and the stage generation in
    bootinfo. Taking those three from `info` makes the record describe this
    stage, which is exactly what load_adoption checks; the ring, fence, pool
    and CB0 root stay the fixture's, since no CP was started (tz_init_done
    false). This is the path for a stage that cannot run a16gpu's hardware
    pipeline (TCG): a16gpu stops at its GICD registry check there.
    """
    record = fixture_record(arena_base=info['gpu_arena_base'],
                            generation=info['stage_generation'], wide=wide)
    record['arena']['size'] = info['gpu_arena_size']
    record['gicd'] = info['gic_distributor']
    record['tz_init_done'] = False
    return record
