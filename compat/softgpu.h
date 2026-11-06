/* SPDX-License-Identifier: MIT */
/*
 * Opt-in passthrough of the QEMU SoftGPU device's guest page (page 0) for the lab board: -DSNAP_SOFTGPU=1 only.
 * Without the define probes/xnuboot.c does not include this header and the monitor is the same binary as before.
 * Plan: plans/p6-softgpu-integration.md, wave W1.
 *
 * What the guest reaches: exactly one 4 KiB page, the device's page 0 (0x0C000000 on `-machine virt` with one
 * snap-softgpu), identity-mapped at stage 2 as Device-nGnRE, read-write, execute-never. Page 1 (the monitor's
 * DMA-window and LOCK page, +0x1000) is never mapped: the block carries its address only so a later wave can
 * program it from EL2, and a guest access to it is a stage-2 fault.
 *
 * The loader (probes/run.py, probes/adreno.py) reads the address and the SPI from the device node of a QEMU
 * `dumpdtb` pre-pass and appends struct softgpu_params after struct params (after the i2c-input, QCC2072 and
 * display-timing blocks when those are built in too). The monitor takes nothing on trust: it checks the words
 * below and refuses the boot (-44 from the stage-2 preparation) on any difference, a missing block included.
 */
#pragma once
#include <stdint.h>
#include "stage2.h"

/* "SNAPSGP1", little-endian: the loader appended these words on purpose. */
#define SOFTGPU_MAGIC           0x3150475350414e53ULL
#define SOFTGPU_F_PAGE0         1u      /* page 0 as a read-write Device window */
#define SOFTGPU_PARAMS_WORDS    5
#define SOFTGPU_STAGE2_MAX      1u
#define SOFTGPU_PAGE            0x1000ULL
#define SOFTGPU_INTID_FIRST     32u     /* the first SPI */
#define SOFTGPU_INTID_LAST      1019u

struct softgpu_params {
    uint64_t magic;                     /* SOFTGPU_MAGIC */
    uint64_t flags;                     /* SOFTGPU_F_PAGE0 */
    uint64_t page0_pa;                  /* the guest page, 4 KiB aligned */
    uint64_t page1_pa;                  /* page0_pa + SOFTGPU_PAGE; never mapped into the guest */
    uint64_t intid;                     /* the interrupt as a GIC INTID (SPI number + 32) */
};
_Static_assert(sizeof(struct softgpu_params) == 8 * SOFTGPU_PARAMS_WORDS, "probes/adreno.py SOFTGPU_PARAMS_WORDS");

static inline int softgpu_valid(const struct softgpu_params *p)
{
    return p->magic == SOFTGPU_MAGIC && p->flags == SOFTGPU_F_PAGE0 && p->page0_pa && !(p->page0_pa & (SOFTGPU_PAGE - 1)) &&
           p->page0_pa < (1ULL << 48) && p->page1_pa == p->page0_pa + SOFTGPU_PAGE &&
           p->intid >= SOFTGPU_INTID_FIRST && p->intid <= SOFTGPU_INTID_LAST;
}

/* The stage-2 row of a valid parameter block, written to out (room for SOFTGPU_STAGE2_MAX). Returns 1, or -1 when the
 * block is not valid. Writes nothing on -1. */
static inline int softgpu_rows(const struct softgpu_params *p, struct stage2_range *out)
{
    if (!softgpu_valid(p)) return -1;
    out[0] = (struct stage2_range){p->page0_pa, p->page0_pa + SOFTGPU_PAGE, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
    return 1;
}

/* Whether pa lies in page 0 of a valid block (MAP_PAGE's evidence classification only). */
static inline int softgpu_window(const struct softgpu_params *p, uint64_t pa)
{
    return softgpu_valid(p) && pa >= p->page0_pa && pa < p->page0_pa + SOFTGPU_PAGE;
}
