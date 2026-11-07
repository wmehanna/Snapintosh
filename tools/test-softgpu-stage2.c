/* SPDX-License-Identifier: MIT */
/* W5 audit L1: the DMA windows must not drift from stage 2. The windows are derived from the base rows and the facts that
 * narrow them (compat/softgpu.c); stage 2 itself is built by shadow/stage2.c and narrowed by vcpu_stage2_prepare (trust cache
 * read-only, write-watch page read-only) and, at LOCKDOWN, const_region_seal. This test builds a real stage-2 tree with those
 * same calls, walks every page of it, and compares: for each page the device may hold exactly what stage 2 gives the guest
 * kernel, minus the pages the monitor withholds on purpose (its own work area and the guarded handoff pages).
 *
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror -Ishadow -Icompat \
 *      tools/test-softgpu-stage2.c compat/softgpu.c shadow/mmu.c shadow/shadow.c shadow/stage2.c -o /tmp/test-softgpu-stage2
 */
#include <stdio.h>
#include <string.h>
#include "softgpu.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RAM_BASE 0x82500000UL
#define RAM_SIZE (2UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;
static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    return 0;
}
static int ram_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(&ram[pa - RAM_BASE], &value, 8);
    return 0;
}
static uint64_t ram_alloc(void *ctx)
{
    (void)ctx;
    if (next_table + 0x1000 > RAM_BASE + RAM_SIZE) return 0;
    uint64_t t = next_table;
    next_table += 0x1000;
    memset(&ram[t - RAM_BASE], 0, 0x1000);
    return t;
}

#define TXSZ 28u
/* A board-shaped layout, scaled down so a page-by-page walk is cheap (a few thousand pages); boundaries stay unaligned to
 * 2 MiB on purpose so blocks and pages mix. All inside the 36-bit IPA space. */
#define RAM_LO   0x800000000ULL
#define RAM_HI   0x804000000ULL                 /* 64 MiB */
#define PANIC    (RAM_HI - 0x20000ULL)
#define SCRATCH  (PANIC + 0x8000ULL)
#define FB       0x810000000ULL
#define FB_SPAN  0x00080000ULL
#define WORK_LO  0x820000000ULL
#define WORK_HI  0x820400000ULL
#define CONST_LO 0x800400000ULL
#define CONST_HI 0x800c00000ULL
#define TRUST_LO 0x803800000ULL
#define TRUST_SZ 0x0000c4000ULL                 /* payload; the span is 0x4000 + (size rounded to 16 KiB) */
#define WWATCH   0x802100000ULL
#define WATCH    0x801f00000ULL
#define WATCH_N  3

static struct softgpu_facts facts(void)
{
    return (struct softgpu_facts){.work_base = WORK_LO, .work_end = WORK_HI, .trust_pa = TRUST_LO, .trust_size = TRUST_SZ,
                                  .write_watch_pa = WWATCH, .watch_pa = WATCH, .watch_count = WATCH_N,
                                  .const_begin = CONST_LO, .const_end = CONST_HI};
}

static unsigned base_rows(struct stage2_range *r)
{
    unsigned n = 0;
    r[n++] = (struct stage2_range){RAM_LO, PANIC, S2_AP_RW | S2_ATTRS, 0};
    r[n++] = (struct stage2_range){PANIC, SCRATCH, S2_AP_RO | S2_ATTRS, S2_XN};
    r[n++] = (struct stage2_range){SCRATCH, RAM_HI, S2_AP_RW | S2_ATTRS, 0};
    r[n++] = (struct stage2_range){FB, FB + FB_SPAN, S2_AP_RW | S2_ATTRS, S2_XN};
    r[n++] = (struct stage2_range){WORK_LO, WORK_HI, S2_AP_RO | S2_ATTRS, S2_XN};
    return n;
}

/* The device rows stage 2 also maps (never DMA targets) join the build but not the window rows. */
static const struct stage2_range device_row = {0x0c000000ULL, 0x0c001000ULL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};

/* Build stage 2 the way vcpu_stage2_prepare does (probes/xnuboot/stage2.c), from the same rows and facts. */
static int build_stage2(struct shadow *s, const struct stage2_range *rows, unsigned nrows, const struct softgpu_facts *f)
{
    struct stage2_range all[SOFTGPU_ROWS_MAX + 1];
    memcpy(all, rows, nrows * sizeof *rows);
    all[nrows] = device_row;
    if (stage2_build(s, all, nrows + 1)) return -1;
    if (!stage2_split(s, f->const_begin) || !stage2_split(s, f->const_end - 4096)) return -2;       /* const boundaries */
    {
        uint64_t begin = f->trust_pa, end = stage2_trust_end(begin, f->trust_size);
        if (!stage2_split(s, begin) || !stage2_split(s, end - 4096) || stage2_readonly(s, begin, end, 0)) return -3;
    }
    {
        uint64_t l3 = stage2_split(s, f->write_watch_pa);
        if (!l3) return -4;
        uint64_t *slot = (uint64_t *)(l3 - RAM_BASE + (uintptr_t)ram + 8 * ((f->write_watch_pa >> 12) & 511));
        *slot &= ~(1UL << 7);                                                  /* S2AP RW -> RO */
    }
    return 0;
}

static uint32_t s2_perm(const struct mmu_config *cfg, uint64_t ipa)
{
    struct mmu_leaf leaf;
    if (mmu_walk(cfg, ipa, ram_read, NULL, &leaf) < 0 || !leaf.valid) return 0;
    if ((leaf.descriptor & S2_AP_RW) == S2_AP_RW) return SOFTGPU_PERM_READ | SOFTGPU_PERM_WRITE;
    if ((leaf.descriptor & S2_AP_RW) == S2_AP_RO) return SOFTGPU_PERM_READ;
    return 0;
}

static uint32_t win_perm(const struct sgpu_window *w, unsigned n, uint64_t pa)
{
    for (unsigned i = 0; i < n; i++)
        if (pa >= w[i].ipa_base && pa - w[i].ipa_base < w[i].size) return w[i].flags;
    return 0;
}

static int withheld(uint64_t pa)
{
    /* the monitor's work area, the guarded handoff pages, and Device memory (mapped for the guest, never a DMA target) */
    return (pa >= WORK_LO && pa < WORK_HI) || (pa >= WATCH && pa < WATCH + WATCH_N * 0x1000ULL) ||
           (pa >= device_row.lo && pa < device_row.hi);
}

static void compare(const char *label, const struct mmu_config *cfg, const struct stage2_range *rows, unsigned nrows,
                    const struct softgpu_facts *f, int const_ro)
{
    struct softgpu_cut cuts[SOFTGPU_CUTS_MAX];
    struct sgpu_window w[SOFTGPU_WINDOWS_MAX];
    unsigned n = 0, bad_more = 0, bad_less = 0, pages = 0;
    CHECK(softgpu_derive(rows, nrows, cuts, softgpu_cuts(f, const_ro, cuts), w, &n) == SOFTGPU_OK);
    static const uint64_t spans[][2] = {{RAM_LO - 0x200000, RAM_HI + 0x200000}, {FB - 0x200000, FB + FB_SPAN + 0x200000},
                                        {WORK_LO - 0x200000, WORK_HI + 0x200000}, {0x0bfff000, 0x0c002000}};
    for (unsigned k = 0; k < sizeof spans / sizeof spans[0]; k++)
        for (uint64_t pa = spans[k][0]; pa < spans[k][1]; pa += 0x1000) {
            const uint32_t dev = win_perm(w, n, pa), want = withheld(pa) ? 0 : s2_perm(cfg, pa);
            pages++;
            if (dev & ~want) bad_more++;                   /* the device could do what the kernel cannot */
            else if (dev != want) bad_less++;              /* the device is narrower than it needs to be: drift the other way */
        }
    if (bad_more || bad_less) fprintf(stderr, "%s: %u pages give the device more than stage 2, %u less (of %u)\n", label, bad_more, bad_less, pages);
    CHECK(bad_more == 0);
    CHECK(bad_less == 0);
    CHECK(pages > 20000);
}

int main(void)
{
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    const unsigned nrows = base_rows(rows);
    const struct softgpu_facts f = facts();
    struct shadow s = {.txsz = TXSZ, .alloc = ram_alloc, .read = ram_read, .write = ram_write, .ctx = NULL};
    memset(ram, 0, sizeof ram);
    next_table = RAM_BASE;
    s.root = ram_alloc(NULL);
    CHECK(build_stage2(&s, rows, nrows, &f) == 0);
    struct mmu_config cfg = {.granule_shift = 12, .txsz = TXSZ, .root = s.root};

    /* sanity of the model itself: the narrowings reached the tree */
    CHECK(s2_perm(&cfg, RAM_LO) == 3 && s2_perm(&cfg, CONST_LO) == 3 && s2_perm(&cfg, TRUST_LO) == 1 && s2_perm(&cfg, WWATCH) == 1);
    CHECK(s2_perm(&cfg, WWATCH + 0x1000) == 3 && s2_perm(&cfg, stage2_trust_end(TRUST_LO, TRUST_SZ)) == 3);

    /* boot: the const region is writable to both */
    compare("boot", &cfg, rows, nrows, &f, 0);

    /* LOCKDOWN: const_region_seal makes the same range read-only in every vCPU's tree */
    CHECK(stage2_readonly(&s, CONST_LO, CONST_HI, 0) == 0);
    CHECK(s2_perm(&cfg, CONST_LO) == 1 && s2_perm(&cfg, CONST_HI - 0x1000) == 1 && s2_perm(&cfg, CONST_HI) == 3);
    compare("lockdown", &cfg, rows, nrows, &f, 1);

    printf("{\"softgpu_stage2_checks\":%u,\"softgpu_stage2_failures\":%u}\n", checks, failures);
    return failures != 0;
}
