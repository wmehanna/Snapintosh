/* SPDX-License-Identifier: MIT */
/* The monitor side of the SoftGPU device, wave W5 (plans/p6-softgpu-integration.md, spec 1.3): the DMA windows derived
 * from the stage-2 rows, their programming into page 1 with read-back, LOCK, and the GIC route of the device's SPI.
 * Pure: every register access goes through ops, so tools/test-softgpu-windows.c runs this file on the host. Built only
 * with -DSNAP_SOFTGPU=1 (probes/run.py OPTIONAL). */
#include "softgpu.h"

#define PAGE_MASK 0xfffULL
#define S2AP_MASK (3ULL << 6)
#define MEMATTR_MASK (0xfULL << 2)

static uint32_t row_perm(const struct stage2_range *r)
{
    /* Only Normal memory is guest RAM: Device rows (the Adreno windows, the SoftGPU page itself) are never DMA targets. */
    if ((r->low & MEMATTR_MASK) != S2_MEMATTR_NORMAL) return 0;
    if ((r->low & S2AP_MASK) == S2_AP_RW) return SOFTGPU_PERM_READ | SOFTGPU_PERM_WRITE;
    if ((r->low & S2AP_MASK) == S2_AP_RO) return SOFTGPU_PERM_READ;
    return 0;                   /* S2AP none or write-only: the kernel cannot read it, so neither may the device */
}

int softgpu_derive(const struct stage2_range *rows, unsigned nrows, const struct softgpu_cut *cuts, unsigned ncuts,
                   struct sgpu_window *out, unsigned *nout)
{
    enum { POINTS = 2 * (SOFTGPU_ROWS_MAX + SOFTGPU_CUTS_MAX) };
    uint64_t pts[POINTS];
    uint64_t clo[SOFTGPU_CUTS_MAX], chi[SOFTGPU_CUTS_MAX];
    struct sgpu_window seg[POINTS];
    unsigned np = 0, nseg = 0;
    if (!rows || !out || !nout || nrows > SOFTGPU_ROWS_MAX || ncuts > SOFTGPU_CUTS_MAX || (ncuts && !cuts)) return SOFTGPU_E_ARG;
    *nout = 0;
    for (unsigned i = 0; i < nrows; i++) {
        const struct stage2_range *r = &rows[i];
        if ((r->lo | r->hi) & PAGE_MASK || r->lo >= r->hi) return SOFTGPU_E_ARG;
        for (unsigned j = 0; j < i; j++)
            if (r->lo < rows[j].hi && rows[j].lo < r->hi) return SOFTGPU_E_ARG;
        if (!row_perm(r)) continue;
        pts[np++] = r->lo;
        pts[np++] = r->hi;
    }
    for (unsigned i = 0; i < ncuts; i++) {
        if (cuts[i].lo >= cuts[i].hi || cuts[i].hi > UINT64_MAX - PAGE_MASK || cuts[i].keep & ~3u) return SOFTGPU_E_ARG;
        clo[i] = cuts[i].lo & ~PAGE_MASK;
        chi[i] = (cuts[i].hi + PAGE_MASK) & ~PAGE_MASK;
        pts[np++] = clo[i];
        pts[np++] = chi[i];
    }
    for (unsigned i = 1; i < np; i++) {                 /* insertion sort: at most 96 points */
        uint64_t v = pts[i];
        unsigned j = i;
        for (; j && pts[j - 1] > v; j--) pts[j] = pts[j - 1];
        pts[j] = v;
    }
    for (unsigned k = 0; k + 1 < np; k++) {
        const uint64_t a = pts[k], b = pts[k + 1];
        uint32_t perm = 0;
        if (a == b) continue;
        for (unsigned i = 0; i < nrows; i++)
            if (rows[i].lo <= a && a < rows[i].hi) perm = row_perm(&rows[i]);
        for (unsigned i = 0; i < ncuts && perm; i++)
            if (clo[i] <= a && a < chi[i]) perm &= cuts[i].keep;
        if (!perm) continue;
        if (nseg && seg[nseg - 1].ipa_base + seg[nseg - 1].size == a && seg[nseg - 1].flags == perm) {
            seg[nseg - 1].size += b - a;
            continue;
        }
        seg[nseg] = (struct sgpu_window){.ipa_base = a, .size = b - a, .pa_base = a, .flags = perm};
        nseg++;
    }
    /* More runs than the device has windows: drop the smallest READ-only ones (the device then cannot sample from them).
     * A READ-only run is never merged into a neighbouring READ|WRITE window, which would grant a write stage 2 does not. */
    while (nseg > SOFTGPU_WINDOWS_MAX) {
        unsigned pick = nseg;
        for (unsigned i = 0; i < nseg; i++)
            if (seg[i].flags == SOFTGPU_PERM_READ && (pick == nseg || seg[i].size < seg[pick].size)) pick = i;
        if (pick == nseg) return SOFTGPU_E_TOO_MANY;
        for (unsigned i = pick; i + 1 < nseg; i++) seg[i] = seg[i + 1];
        nseg--;
    }
    for (unsigned i = 0; i < nseg; i++) out[i] = seg[i];
    *nout = nseg;
    return SOFTGPU_OK;
}

static uint64_t win_reg(unsigned i, unsigned word)
{
    return SOFTGPU_MON_WINDOW0 + 32ULL * i + 4ULL * word;
}

static void win_words(const struct sgpu_window *w, uint32_t out[8])
{
    out[0] = (uint32_t)w->ipa_base;  out[1] = (uint32_t)(w->ipa_base >> 32);
    out[2] = (uint32_t)w->size;      out[3] = (uint32_t)(w->size >> 32);
    out[4] = (uint32_t)w->pa_base;   out[5] = (uint32_t)(w->pa_base >> 32);
    out[6] = w->flags;               out[7] = w->reserved;
}

int softgpu_mon_open(const struct softgpu_mon_ops *ops, struct softgpu_mon *m, uint64_t page1_pa)
{
    *m = (struct softgpu_mon){.page1 = page1_pa};
    if (ops->rd(ops->ctx, page1_pa) != SOFTGPU_MON_MAGIC) return SOFTGPU_E_DEVICE;
    return SOFTGPU_OK;
}

/* Best effort, after a failure: no windows at all, applied as a new generation. */
static void fail_closed(const struct softgpu_mon_ops *ops, struct softgpu_mon *m)
{
    ops->wr(ops->ctx, m->page1 + SOFTGPU_MON_WINDOW_COUNT, 0);
    m->gen++;
    ops->wr(ops->ctx, m->page1 + SOFTGPU_MON_GEN, m->gen);
    m->nwin = 0;
    m->failed = 1;
}

int softgpu_mon_program(const struct softgpu_mon_ops *ops, struct softgpu_mon *m, const struct sgpu_window *w,
                       unsigned n)
{
    const uint64_t p1 = m->page1;
    if (m->failed) return SOFTGPU_E_DEVICE;
    if (n > SOFTGPU_WINDOWS_MAX || (n && !w)) return SOFTGPU_E_ARG;
    for (unsigned i = 0; i < n; i++) {
        if ((w[i].ipa_base | w[i].size | w[i].pa_base) & PAGE_MASK || !w[i].size || w[i].reserved ||
            (w[i].flags & ~3u) || !w[i].flags || w[i].ipa_base + w[i].size < w[i].ipa_base ||
            (i && w[i].ipa_base < w[i - 1].ipa_base + w[i - 1].size)) return SOFTGPU_E_ARG;
    }
    for (unsigned i = 0; i < n; i++) {
        uint32_t v[8];
        win_words(&w[i], v);
        for (unsigned k = 0; k < 8; k++) ops->wr(ops->ctx, p1 + win_reg(i, k), v[k]);
    }
    /* Rows past the new count are dead; clear what the previous table left so a read-back of the page is the table. */
    for (unsigned i = n; i < m->nwin; i++)
        for (unsigned k = 0; k < 8; k++) ops->wr(ops->ctx, p1 + win_reg(i, k), 0);
    ops->wr(ops->ctx, p1 + SOFTGPU_MON_WINDOW_COUNT, n);
    m->gen++;
    ops->wr(ops->ctx, p1 + SOFTGPU_MON_GEN, m->gen);
    unsigned polls = 0;
    while (ops->rd(ops->ctx, p1 + SOFTGPU_MON_GEN_APPLIED) != m->gen)
        if (++polls >= SOFTGPU_APPLIED_POLLS) { fail_closed(ops, m); return SOFTGPU_E_APPLIED; }
    /* Applied. Prove the device holds the table that was meant: count, then every word. */
    int same = ops->rd(ops->ctx, p1 + SOFTGPU_MON_WINDOW_COUNT) == n && ops->rd(ops->ctx, p1 + SOFTGPU_MON_GEN) == m->gen;
    for (unsigned i = 0; i < n && same; i++) {
        uint32_t v[8];
        win_words(&w[i], v);
        for (unsigned k = 0; k < 8; k++)
            if (ops->rd(ops->ctx, p1 + win_reg(i, k)) != v[k]) same = 0;
    }
    if (!same) { fail_closed(ops, m); return SOFTGPU_E_DEVICE; }
    m->nwin = n;
    m->programs++;
    return SOFTGPU_OK;
}

int softgpu_mon_lock(const struct softgpu_mon_ops *ops, struct softgpu_mon *m)
{
    if (m->failed) return SOFTGPU_E_DEVICE;
    ops->wr(ops->ctx, m->page1 + SOFTGPU_MON_LOCK, 1);
    if (ops->rd(ops->ctx, m->page1 + SOFTGPU_MON_LOCK) != 1) { m->failed = 1; return SOFTGPU_E_LOCK; }
    m->locked = 1;
    return SOFTGPU_OK;
}

#define GICD_IGROUPR_  0x080u
#define GICD_ICENABLER_ 0x180u
#define GICD_ICPENDR_  0x280u
#define GICD_IPRIORITYR_ 0x400u
#define GICD_ICFGR_    0xc00u
#define GICD_IROUTER_  0x6000u

int softgpu_gic_route(const struct softgpu_gic_ops *ops, uint64_t gicd, uint32_t intid, uint64_t affinity, uint32_t priority)
{
    const uint32_t bit = 1u << (intid % 32), shift = (intid % 4) * 8;
    const uint64_t group = gicd + GICD_IGROUPR_ + 4ULL * (intid / 32), cfg = gicd + GICD_ICFGR_ + 4ULL * (intid / 16);
    const uint64_t pri = gicd + GICD_IPRIORITYR_ + (intid & ~3u);
    if (intid < 32 || intid > 1019 || !priority || priority > 0xff) return SOFTGPU_E_ARG;
    ops->wr(ops->ctx, gicd + GICD_ICENABLER_ + 4ULL * (intid / 32), bit);
    ops->wr(ops->ctx, gicd + GICD_ICPENDR_ + 4ULL * (intid / 32), bit);
    ops->wr(ops->ctx, group, ops->rd(ops->ctx, group) | bit);                                      /* group 1 Non-secure */
    ops->wr(ops->ctx, cfg, ops->rd(ops->ctx, cfg) & ~(2u << (2 * (intid % 16))));                  /* level-sensitive */
    ops->wr(ops->ctx, pri, (ops->rd(ops->ctx, pri) & ~(0xffu << shift)) | priority << shift);
    ops->wr(ops->ctx, gicd + GICD_IROUTER_ + 8ULL * intid, (uint32_t)affinity);                  /* IRM 0 */
    ops->wr(ops->ctx, gicd + GICD_IROUTER_ + 8ULL * intid + 4, (uint32_t)(affinity >> 32));
    /* A Secure interrupt's priority byte is RAZ/WI to Non-secure software (compat/adreno.c adreno_gic_route). */
    if (!((ops->rd(ops->ctx, pri) >> shift) & 0xffu)) return SOFTGPU_E_ARG;
    return SOFTGPU_OK;
}
