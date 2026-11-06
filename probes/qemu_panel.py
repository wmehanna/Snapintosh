# SPDX-License-Identifier: MIT
"""A full-size boot panel for QEMU runs: SNAP_QEMU_PANEL=WIDTHxHEIGHT.

EDK2's ramfb driver offers 800x600 and a few other small modes, so q1n1's GOP
capture hands XNU an 800x600 framebuffer while AdrenoDisplay reports the A16
panel's 2880x1800 mode. AdrenoDisplay copies a swap 1:1 from the top-left into
the boot framebuffer (PE_Video), so the host saw an 800x600 crop of every frame.

With SNAP_QEMU_PANEL set, the launcher takes a panel-sized range of
firmware-free RAM above the guest layout, describes it to XNU in place of the
GOP buffer, and re-points QEMU's ramfb at it through fw_cfg DMA, so the scanout
and the host display (HMP `screendump`) both carry the full frame. Only for
`--qemu`: the fw_cfg window is a QEMU virt device, not A16 hardware.
"""
import re
import struct

ENV = 'SNAP_QEMU_PANEL'
# QEMU virt fw_cfg: data +0, selector +8, DMA +0x10, all big-endian.
FW_CFG_BASE = 0x09020000
FW_CFG_FILE_DIR = 0x19
DMA_ERROR, DMA_READ, DMA_SELECT, DMA_WRITE = 0x01, 0x02, 0x08, 0x10
# DRM 'XR24': B, G, R, X bytes in memory, which is GOP format 1.
XRGB8888 = 0x34325258
ALIGN = 2 << 20
# The DMA descriptor and the fw_cfg file directory, after the pixels.
SCRATCH = 64 << 10
MIN_SIDE, MAX_SIDE = 16, 16000      # QEMU ramfb's accepted geometry


def requested(env):
    """(width, height) from SNAP_QEMU_PANEL, or None when unset or empty."""
    text = env.get(ENV, '').strip()
    if not text:
        return None
    match = re.fullmatch(r'(\d+)x(\d+)', text)
    if not match:
        raise ValueError(f'{ENV} must be WIDTHxHEIGHT, not {text!r}')
    width, height = int(match.group(1)), int(match.group(2))
    if not (MIN_SIDE <= width <= MAX_SIDE and MIN_SIDE <= height <= MAX_SIDE):
        raise ValueError(f'{ENV} {width}x{height} is outside {MIN_SIDE}..{MAX_SIDE}')
    return width, height


def allocation(width, height):
    """Bytes reserved: the pixels plus the DMA scratch, on the 2 MiB grid."""
    return (width * 4 * height + SCRATCH + ALIGN - 1) & -ALIGN


def place(free, size):
    """The top `size` bytes of the highest free span that holds them, 2 MiB aligned.

    `free` is [(low, high)] (monitor_work.firmware_free). The top keeps the
    panel clear of the guest layout, which free_region grows from the bottom."""
    for low, high in sorted(free, reverse=True):
        base = (high - size) & -ALIGN
        if base >= low and base + size <= high:
            return base
    raise ValueError(f'no firmware-free span holds a {size >> 20} MiB panel')


def describe(info, base, width, height):
    """A copy of q1n1's bootinfo with the GOP fields replaced by the new panel.

    fb_stride is in pixels, as q1n1 reports it; fb_size covers only the pixels,
    so the scratch after them never reaches the guest's stage 2."""
    return dict(info, fb_base=base, fb_size=width * 4 * height, fb_width=width,
                fb_height=height, fb_stride=width, fb_format=1,
                qemu_panel=(base, allocation(width, height)))


def excluded(info):
    """[(low, high)] for free_region to carve out, empty without a QEMU panel."""
    span = info.get('qemu_panel')
    return [(span[0], span[0] + span[1])] if span else []


def ramfb_config(base, width, height):
    """QEMU's RAMFBCfg: address, fourcc, flags, width, height, stride; big-endian."""
    return struct.pack('>QIIIII', base, XRGB8888, 0, width, height, width * 4)


def dma_access(control, length, address):
    """FWCfgDmaAccess: control, length, address; big-endian."""
    return struct.pack('>IIQ', control, length, address)


def find_file(directory, name):
    """The selector of fw_cfg file `name` in a FW_CFG_FILE_DIR blob."""
    if len(directory) < 4:
        raise ValueError('fw_cfg file directory is truncated')
    count = struct.unpack_from('>I', directory)[0]
    if 4 + count * 64 > len(directory):
        raise ValueError(f'fw_cfg file directory lists {count} files '
                         f'beyond its {len(directory)} bytes')
    for i in range(count):
        _, select, _, raw = struct.unpack_from('>IHH56s', directory, 4 + i * 64)
        if raw.split(b'\0', 1)[0].decode('ascii', 'replace') == name:
            return select
    raise ValueError(f'fw_cfg has no {name}')


def _bswap32(value):
    return int.from_bytes(value.to_bytes(4, 'little'), 'big')


def _dma(proxy, scratch, control, length, address, fw_cfg):
    proxy.writemem(scratch, dma_access(control, length, address))
    # The DMA register is big-endian; writing its low half starts the transfer.
    proxy.write32(fw_cfg + 0x10, _bswap32(scratch >> 32))
    proxy.write32(fw_cfg + 0x14, _bswap32(scratch & 0xffffffff))
    status = struct.unpack('>I', proxy.readmem(scratch, 4, live=True))[0]
    proxy.end_live()
    if status:
        raise ValueError(f'fw_cfg DMA {control:#x} ended with status {status:#x}')


def program(proxy, info, fw_cfg=FW_CFG_BASE):
    """Clear the panel, then point QEMU's ramfb at it. Returns the ramfb selector."""
    base, size = info['qemu_panel']
    pixels = info['fb_size']
    scratch = base + pixels
    if scratch + SCRATCH > base + size:
        raise ValueError('QEMU panel has no room for its DMA scratch')
    proxy.memset32(base, 0, pixels)
    listing = scratch + 64
    _dma(proxy, scratch, (FW_CFG_FILE_DIR << 16) | DMA_SELECT | DMA_READ,
         SCRATCH - 64, listing, fw_cfg)
    select = find_file(proxy.readmem(listing, SCRATCH - 64), 'etc/ramfb')
    config = scratch + 64
    proxy.writemem(config, ramfb_config(base, info['fb_width'], info['fb_height']))
    _dma(proxy, scratch, (select << 16) | DMA_SELECT | DMA_WRITE, 28, config, fw_cfg)
    return select
