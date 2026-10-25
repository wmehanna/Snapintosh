/* SPDX-License-Identifier: MIT */
#ifndef SNAP_GIC_LAYOUT_H
#define SNAP_GIC_LAYOUT_H
#include <stdint.h>
/* The host GIC geometry the monitor's secondaries use, as the host measured it
 * from the platform (ACPI MADT GICD/GICC/GICR records and each frame's
 * GICR_TYPER: tools/probe-a16-secondary.py gic_geometry) and passed in
 * struct secondary_config. Nothing here names a platform.
 *
 * On the A16 the host passes what used to be hardcoded: GICD 0x17000000,
 * redistributors [0x17080000, 0x17500000) with a 0x40000 stride (GICv4, VLPI
 * frames; q1n1 platform/uefi/gicv3.c). QEMU virt gic-version=3 gives GICD
 * 0x08000000 and redistributors from 0x080a0000 with a 0x20000 stride.
 *
 * A layout is: a 64 KiB aligned distributor outside the window, a 64 KiB
 * aligned, nonempty redistributor window that is a whole number of frames, and
 * a GICv3 (RD+SGI, 0x20000) or GICv4 (RD+SGI+VLPI+reserved, 0x40000) frame
 * stride. The window bound (64 MiB) matches the MADT GICR span the host
 * accepts (tools/probe-a16-cpus.py gic_entries). */
#define GIC_LAYOUT_SPAN_MAX UINT64_C(0x4000000)
static inline int gic_layout_valid(uint64_t gicd, uint64_t first, uint64_t end, uint64_t stride)
{
    return gicd && !(gicd & 0xffff) && first && !(first & 0xffff) &&
           (stride == UINT64_C(0x20000) || stride == UINT64_C(0x40000)) &&
           end > first && end - first <= GIC_LAYOUT_SPAN_MAX && !((end - first) % stride) &&
           (gicd >= end || gicd + 0x10000 <= first);
}
/* A redistributor frame base inside a layout gic_layout_valid accepted. */
static inline int gic_redistributor_valid(uint64_t r, uint64_t first, uint64_t end, uint64_t stride)
{
    return stride && r >= first && r < end && !((r - first) % stride);
}
#endif
