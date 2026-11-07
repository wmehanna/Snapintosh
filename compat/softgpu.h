/* SPDX-License-Identifier: MIT */
/*
 * Opt-in passthrough of the QEMU SoftGPU device's guest page (page 0) for the lab board: -DSNAP_SOFTGPU=1 only.
 * Without the define probes/xnuboot.c does not include this header and the monitor is the same binary as before.
 * Plan: plans/p6-softgpu-integration.md, wave W1.
 *
 * What the guest reaches: exactly one 4 KiB page, the device's page 0 (0x0C000000 on `-machine virt` with one
 * snap-softgpu), identity-mapped at stage 2 as Device-nGnRE, read-write, execute-never. Page 1 (the monitor's
 * DMA-window and LOCK page, +0x1000) is never mapped: a guest access to it is a stage-2 fault. Wave W5 (below, and
 * compat/softgpu.c) programs page 1 from EL2: the DMA windows, derived from the stage-2 map, then LOCK.
 *
 * The loader (probes/run.py, probes/adreno.py) reads the address and the SPI from the device node of a QEMU
 * `dumpdtb` pre-pass and appends struct softgpu_params after struct params (after the i2c-input, QCC2072 and
 * display-timing blocks when those are built in too). The monitor takes nothing on trust: it checks the words
 * below and refuses the boot (-44 from the stage-2 preparation) on any difference, a missing block included.
 */
#pragma once
#include <stdint.h>
#include "stage2.h"
#include "softgpu_protocol.h"

/* "SNAPSGP1", little-endian: the loader appended these words on purpose. */
#define SOFTGPU_MAGIC           0x3150475350414e53ULL
#define SOFTGPU_F_PAGE0         1u      /* page 0 as a read-write Device window */
#define SOFTGPU_PARAMS_WORDS    5
#define SOFTGPU_STAGE2_MAX      1u
#define SOFTGPU_PAGE            0x1000ULL
#define SOFTGPU_WINDOW_LO       0x0c000000ULL   /* virt platform-bus window: the only place the device can sit */
#define SOFTGPU_WINDOW_HI       0x0e000000ULL   /* page 0 and page 1 both end at or below this */
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
    return p->magic == SOFTGPU_MAGIC && p->flags == SOFTGPU_F_PAGE0 && !(p->page0_pa & (SOFTGPU_PAGE - 1)) &&
           p->page0_pa >= SOFTGPU_WINDOW_LO && p->page0_pa + 2 * SOFTGPU_PAGE <= SOFTGPU_WINDOW_HI && p->page1_pa == p->page0_pa + SOFTGPU_PAGE &&
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

/* ---- Wave W5: DMA windows, LOCK and the interrupt (plans/p6-softgpu-integration.md W5, spec 1.3) ------------------------
 *
 * The device may touch guest memory only through the windows the monitor writes to page 1, and refuses RING_ENABLE until
 * LOCK. The invariant: the device never has more access to a page than stage 2 gives the guest kernel. So the windows
 * are not a second policy, they are the stage-2 rows (the same list stage2_build maps) minus what the monitor withholds,
 * and every narrowing reaches the device before it reaches stage 2:
 *
 *   softgpu_derive      pure: rows + cuts -> sorted, non-overlapping windows (RW rows READ|WRITE, RO rows READ, device
 *                       rows and everything unmapped left out, never a READ run merged into a READ|WRITE window)
 *   softgpu_mon_program table, WINDOW_COUNT, WINDOWS_GEN + 1, read WINDOWS_GEN_APPLIED back, read the table back; any
 *                       difference fails closed (no windows) and is an error
 *   softgpu_mon_lock    LOCK = 1, read back
 *
 * Register access goes through ops, so tools/test-softgpu-windows.c runs the same code against a model of page 1. */
#ifndef SOFTGPU_WINDOWS_MAX      /* the device has 64 (spec 1.3); a host test builds a smaller table to reach the limit rules */
#define SOFTGPU_WINDOWS_MAX     64u
#endif
#define SOFTGPU_ROWS_MAX        32u     /* stage-2 rows softgpu_derive reads */
#define SOFTGPU_CUTS_MAX        16u
#define SOFTGPU_PERM_READ       SGPU_WIN_READ
#define SOFTGPU_PERM_WRITE      SGPU_WIN_WRITE
#define SOFTGPU_MON_MAGIC       0x4e4f4d53u
#define SOFTGPU_MON_WINDOW_COUNT 0x004u
#define SOFTGPU_MON_LOCK        0x008u
#define SOFTGPU_MON_FEATURE0    0x00cu
#define SOFTGPU_MON_FEATURE1    0x010u
#define SOFTGPU_MON_GEN         0x014u
#define SOFTGPU_MON_GEN_APPLIED 0x018u
#define SOFTGPU_MON_WINDOW0     0x100u
#define SOFTGPU_APPLIED_POLLS   1024u

enum {
    SOFTGPU_OK = 0,
    SOFTGPU_E_ARG = -1,         /* rows or cuts malformed (unaligned, overlapping rows, over a list maximum) */
    SOFTGPU_E_TOO_MANY = -2,    /* writable runs alone exceed SOFTGPU_WINDOWS_MAX: the monitor refuses to lock (1.3) */
    SOFTGPU_E_DEVICE = -3,      /* no SMON magic, or the table read back differs: the device was failed closed */
    SOFTGPU_E_APPLIED = -4,     /* WINDOWS_GEN_APPLIED never reached the generation: the device was failed closed */
    SOFTGPU_E_LOCK = -5,        /* LOCK did not read back as set */
};

/* The device may keep at most `keep` (SOFTGPU_PERM_* bits, 0 = none) of what the rows give inside [lo, hi). The span is
 * widened to whole pages outward, so a cut can only remove access. */
struct softgpu_cut {
    uint64_t lo, hi;
    uint32_t keep;
};

int softgpu_derive(const struct stage2_range *rows, unsigned nrows, const struct softgpu_cut *cuts, unsigned ncuts,
                   struct sgpu_window *out, unsigned *nout);

struct softgpu_mon_ops {
    void *ctx;
    uint32_t (*rd)(void *ctx, uint64_t pa);
    void (*wr)(void *ctx, uint64_t pa, uint32_t v);
};

struct softgpu_mon {
    uint64_t page1;             /* physical address of page 1 */
    uint32_t gen;               /* last WINDOWS_GEN written */
    uint32_t nwin;              /* windows in the table the device holds (0 after a failure) */
    uint32_t locked;
    uint32_t failed;            /* a program or lock failed: the device was failed closed and stays so */
    uint32_t programs;
    uint32_t unconfirmed;       /* zero tables (fail-closed or close) the device never confirmed: it may still hold windows */
};

/* Read MON_MAGIC and start from generation 0. SOFTGPU_E_DEVICE when page 1 does not answer "SMON" or the device is not
 * fresh: LOCK set, or a table generation already written or applied (a monitorless=on device, or one a previous monitor
 * run used and nothing reset). Nothing is written. */
int softgpu_mon_open(const struct softgpu_mon_ops *ops, struct softgpu_mon *m, uint64_t page1_pa);
/* Write the table, apply it and prove it. On any failure the device is left with no windows (count 0, generation + 1),
 * m->failed is set and the error returned; a failed monitor accepts no further table. */
int softgpu_mon_program(const struct softgpu_mon_ops *ops, struct softgpu_mon *m, const struct sgpu_window *w,
                       unsigned n);
int softgpu_mon_lock(const struct softgpu_mon_ops *ops, struct softgpu_mon *m);
/* Take every window away and wait for the device to say so (WINDOWS_GEN_APPLIED), also from a failed monitor. 0 when the
 * device confirmed (count 0 read back); SOFTGPU_E_APPLIED or SOFTGPU_E_DEVICE otherwise, with m->unconfirmed set. */
int softgpu_mon_close(const struct softgpu_mon_ops *ops, struct softgpu_mon *m);

/* GIC route of the device's SPI at the monitor's EL2: disabled, level, group 1, priority, affinity; the SPI is enabled by
 * the forwarder (compat/irq-forward.c). SOFTGPU_E_ARG when the priority reads back zero (a Secure line). */
struct softgpu_gic_ops {
    void *ctx;
    uint32_t (*rd)(void *ctx, uint64_t pa);
    void (*wr)(void *ctx, uint64_t pa, uint32_t v);
};
int softgpu_gic_route(const struct softgpu_gic_ops *ops, uint64_t gicd, uint32_t intid, uint64_t affinity,
                      uint32_t priority);

/* The monitor's per-run state: page 1 and the table the device holds. Kept in struct root_ext (the wide root cache's arena
 * pages, so struct context keeps its page count) or, without SNAP_ROOT_CACHE_WIDE, at the end of struct context. */
struct softgpu_state {
    struct softgpu_mon mon;     /* page 1, generation, lock, failure */
    uint32_t const_ro;          /* the kernel const region is sealed: windows keep it read-only from now on */
    uint32_t stage;             /* 0 none, 1 windows programmed and locked, 2 LOCKDOWN downgrade applied */
    int32_t last;               /* the last SOFTGPU_* result of a derive or program, 0 ok */
    uint32_t windows;           /* windows in the current table */
    uint64_t downgrades;        /* tables narrowed ahead of a stage-2 change */
};
_Static_assert(sizeof(struct softgpu_state) == 56, "struct root_ext / struct context page counts were sized for this");

/* Everything the monitor withholds from the device on top of the stage-2 rows, as plain values (the glue fills it from
 * struct context and struct params; tools/test-softgpu-windows.c fills it by hand). All of it is a stage-2 fact. */
struct softgpu_facts {
    uint64_t work_base, work_end;       /* the monitor's table arena and vCPU runtime pages: no window */
    uint64_t trust_pa, trust_size;      /* the trust cache (0 = none): READ only, span stage2_trust_end() */
    uint64_t write_watch_pa;            /* the write-watch page (0 = none): READ only */
    uint64_t watch_pa, watch_count;     /* the handoff watch pages (guarded in stage 2): no window */
    uint64_t const_begin, const_end;    /* the kernel const region: READ only once LOCKDOWN sealed it (const_ro) */
};

/* The cuts for facts; room for SOFTGPU_CUTS_MAX. const_ro is passed explicitly so the downgrade is derived before stage 2
 * changes. Returns the number of cuts. */
unsigned softgpu_cuts(const struct softgpu_facts *f, int const_ro, struct softgpu_cut *cuts);

/* Derive the windows for rows + facts and make the device hold exactly them. 0, or a SOFTGPU_E_* after which the device has
 * no windows. The caller changes stage 2 only after this returns 0. */
int softgpu_apply(const struct softgpu_mon_ops *ops, struct softgpu_state *st, const struct stage2_range *rows,
                  unsigned nrows, const struct softgpu_facts *f, int const_ro);
/* Boot: open page 1 at page1_pa, program the boot table (const region still writable), LOCK. Non-zero: refuse the boot. */
int softgpu_prepare_windows(const struct softgpu_mon_ops *ops, struct softgpu_state *st, uint64_t page1_pa,
                            const struct stage2_range *rows, unsigned nrows, const struct softgpu_facts *f);
/* SPTM_FN_LOCKDOWN, before the const region is sealed: the device loses WRITE on it first. Does nothing, and writes no
 * register, when prepare never ran (stage 0: page 1 was never opened) or the downgrade is already applied. Non-zero: the
 * device did not confirm (it was failed closed) and the seal must be refused. */
int softgpu_lockdown_step(const struct softgpu_mon_ops *ops, struct softgpu_state *st, const struct stage2_range *rows,
                          unsigned nrows, const struct softgpu_facts *f);
/* The guest's memory is handed back: zero table, confirmed. Returns 0, or the error when the device never confirmed
 * (counted in st->mon.unconfirmed; the caller records it). */
int softgpu_close_step(const struct softgpu_mon_ops *ops, struct softgpu_state *st);
