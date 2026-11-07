/* SPDX-License-Identifier: MIT */
/* compat/softgpu.c (W5): window derivation from stage-2 rows, programming against a model of page 1, LOCK, the GIC route.
 *   clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow -Icompat \
 *       tools/test-softgpu-windows.c compat/softgpu.c -o /tmp/test-softgpu-windows && /tmp/test-softgpu-windows */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "softgpu.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RW (S2_AP_RW | S2_ATTRS)
#define RO (S2_AP_RO | S2_ATTRS)
#define DEV (S2_AP_RW | S2_ATTRS_DEVICE)
static struct stage2_range row(uint64_t lo, uint64_t hi, uint64_t low)
{
    return (struct stage2_range){lo, hi, low, low == RO ? S2_XN : 0};
}

/* ---- the board's layout, as vcpu_stage2_prepare builds it ---- */
#define RAM_LO   0x800000000ULL
#define PANIC    0x8ff000000ULL
#define SCRATCH  (PANIC + 0x8000ULL)
#define RAM_HI   0x900000000ULL
#define FB       0x92fc00000ULL
#define FB_SPAN  0x00800000ULL
#define WORK_LO  0x940000000ULL
#define WORK_HI  0x944000000ULL
#define CONST_LO 0x800800000ULL
#define CONST_HI 0x801000000ULL
#define TRUST_LO 0x8fe000000ULL
#define TRUST_HI 0x8fe100000ULL
#define WATCH    0x8f0000000ULL

static unsigned board_rows(struct stage2_range *r)
{
    unsigned n = 0;
    r[n++] = row(RAM_LO, PANIC, RW);
    r[n++] = row(PANIC, SCRATCH, RO);
    r[n++] = row(SCRATCH, RAM_HI, RW);
    r[n++] = row(FB, FB + FB_SPAN, RW);
    r[n++] = row(WORK_LO, WORK_HI, RO);
    r[n++] = row(0x0c000000ULL, 0x0c001000ULL, DEV);        /* SoftGPU page 0 */
    r[n++] = row(0x03d00000ULL, 0x03d37000ULL, DEV);        /* Adreno registers */
    return n;
}

static uint32_t perm_at(const struct sgpu_window *w, unsigned n, uint64_t pa)
{
    for (unsigned i = 0; i < n; i++)
        if (pa >= w[i].ipa_base && pa < w[i].ipa_base + w[i].size) return w[i].flags;
    return 0;
}

__attribute__((unused)) static void test_board(void)
{
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    struct sgpu_window w[SOFTGPU_WINDOWS_MAX];
    unsigned nrows = board_rows(rows), n = 0;
    struct softgpu_cut cuts[SOFTGPU_CUTS_MAX] = {
        {WORK_LO, WORK_HI, 0},                              /* monitor memory */
        {TRUST_LO, TRUST_HI, SOFTGPU_PERM_READ},            /* sealed read-only at prepare */
        {WATCH, WATCH + 0x2000, 0},                         /* guard pages */
    };
    CHECK(softgpu_derive(rows, nrows, cuts, 3, w, &n) == SOFTGPU_OK);
    /* RAM split by the watch pages and the trust cache, plus the panic page (READ), scratch to top, and the panel */
    CHECK(n == 7);
    CHECK(perm_at(w, n, RAM_LO) == 3 && perm_at(w, n, WATCH - 0x1000) == 3);
    CHECK(perm_at(w, n, WATCH) == 0 && perm_at(w, n, WATCH + 0x1fff) == 0 && perm_at(w, n, WATCH + 0x2000) == 3);
    CHECK(perm_at(w, n, TRUST_LO) == 1 && perm_at(w, n, TRUST_HI - 1) == 1 && perm_at(w, n, TRUST_HI) == 3);
    CHECK(perm_at(w, n, PANIC) == 1 && perm_at(w, n, SCRATCH - 1) == 1 && perm_at(w, n, SCRATCH) == 3);
    CHECK(perm_at(w, n, FB) == 3 && perm_at(w, n, FB + FB_SPAN - 1) == 3 && perm_at(w, n, FB + FB_SPAN) == 0);
    CHECK(perm_at(w, n, WORK_LO) == 0 && perm_at(w, n, WORK_HI - 1) == 0);               /* monitor memory excluded */
    CHECK(perm_at(w, n, 0x0c000000ULL) == 0 && perm_at(w, n, 0x03d00000ULL) == 0);        /* device rows never DMA targets */
    CHECK(perm_at(w, n, RAM_HI) == 0 && perm_at(w, n, RAM_LO - 0x1000) == 0);
    for (unsigned i = 0; i < n; i++) {
        CHECK(!(w[i].ipa_base & 0xfff) && !(w[i].size & 0xfff) && w[i].size && w[i].pa_base == w[i].ipa_base);
        CHECK(!w[i].reserved && (w[i].flags == 1 || w[i].flags == 3));
        if (i) CHECK(w[i].ipa_base >= w[i - 1].ipa_base + w[i - 1].size);
    }
    /* LOCKDOWN: the const region goes read-only first on the device */
    cuts[3] = (struct softgpu_cut){CONST_LO, CONST_HI, SOFTGPU_PERM_READ};
    unsigned m = 0;
    struct sgpu_window w2[SOFTGPU_WINDOWS_MAX];
    CHECK(softgpu_derive(rows, nrows, cuts, 4, w2, &m) == SOFTGPU_OK && m == 9);
    CHECK(perm_at(w2, m, CONST_LO) == 1 && perm_at(w2, m, CONST_HI - 1) == 1 && perm_at(w2, m, CONST_HI) == 3);
    CHECK(perm_at(w2, m, CONST_LO - 1) == 3);
    /* no cut ever widens: a cut asking for WRITE over a read-only row leaves it read-only */
    struct softgpu_cut wide = {PANIC, SCRATCH, 3};
    CHECK(softgpu_derive(rows, nrows, &wide, 1, w2, &m) == SOFTGPU_OK && perm_at(w2, m, PANIC) == 1);
    /* a cut is widened to whole pages outward */
    struct softgpu_cut odd = {RAM_LO + 0x10, RAM_LO + 0x1001, 0};
    CHECK(softgpu_derive(rows, nrows, &odd, 1, w2, &m) == SOFTGPU_OK && perm_at(w2, m, RAM_LO) == 0 &&
          perm_at(w2, m, RAM_LO + 0x1fff) == 0 && perm_at(w2, m, RAM_LO + 0x2000) == 3);
}

__attribute__((unused)) static void test_malformed(void)
{
    struct stage2_range rows[4];
    struct sgpu_window w[SOFTGPU_WINDOWS_MAX];
    unsigned n = 99;
    rows[0] = row(0x1000, 0x3000, RW);
    rows[1] = row(0x2000, 0x4000, RW);                                          /* overlaps rows[0] */
    CHECK(softgpu_derive(rows, 2, 0, 0, w, &n) == SOFTGPU_E_ARG);
    rows[1] = row(0x3000, 0x3800, RW);                                          /* unaligned */
    CHECK(softgpu_derive(rows, 2, 0, 0, w, &n) == SOFTGPU_E_ARG);
    rows[1] = row(0x4000, 0x4000, RW);                                          /* empty */
    CHECK(softgpu_derive(rows, 2, 0, 0, w, &n) == SOFTGPU_E_ARG);
    CHECK(softgpu_derive(rows, 1, 0, 1, w, &n) == SOFTGPU_E_ARG);               /* cuts without a list */
    struct softgpu_cut bad = {0x2000, 0x1000, 0};
    CHECK(softgpu_derive(rows, 1, &bad, 1, w, &n) == SOFTGPU_E_ARG);
    bad = (struct softgpu_cut){0x1000, 0x2000, 4};
    CHECK(softgpu_derive(rows, 1, &bad, 1, w, &n) == SOFTGPU_E_ARG);            /* a permission bit that does not exist */
    CHECK(softgpu_derive(rows, SOFTGPU_ROWS_MAX + 1, 0, 0, w, &n) == SOFTGPU_E_ARG);
    CHECK(softgpu_derive(0, 1, 0, 0, w, &n) == SOFTGPU_E_ARG);
    /* write-only S2AP and S2AP none give the device nothing */
    rows[0] = row(0x1000, 0x2000, (2ULL << 6) | S2_ATTRS);
    rows[1] = row(0x2000, 0x3000, S2_ATTRS);
    CHECK(softgpu_derive(rows, 2, 0, 0, w, &n) == SOFTGPU_OK && n == 0);
    /* an empty list is a valid, empty table */
    CHECK(softgpu_derive(rows, 0, 0, 0, w, &n) == SOFTGPU_OK && n == 0);
}

static void test_fragments(void)
{
#if SOFTGPU_WINDOWS_MAX == 8
    /* Built with -DSOFTGPU_WINDOWS_MAX=8: the over-the-limit rules of spec 1.3, unreachable with the production limits
     * (32 rows and 16 cuts make at most 64 runs). */
    struct stage2_range rows[1] = {row(0x100000000ULL, 0x100000000ULL + 0x40000ULL, RW)};
    struct sgpu_window w[8];
    struct softgpu_cut cuts[SOFTGPU_CUTS_MAX];
    unsigned n = 0;
    /* RW, RO(1), RW, RO(2), RW, RO(3), RW, RO(4), RW = 9 runs: the smallest READ-only run goes, the rest stay as they are */
    for (unsigned i = 0; i < 4; i++)
        cuts[i] = (struct softgpu_cut){0x100000000ULL + (2 * i + 1) * 0x5000ULL, 0x100000000ULL + (2 * i + 1) * 0x5000ULL + (i + 1) * 0x1000ULL,
                                       SOFTGPU_PERM_READ};
    CHECK(softgpu_derive(rows, 1, cuts, 4, w, &n) == SOFTGPU_OK && n == 8);
    CHECK(perm_at(w, n, 0x100000000ULL + 0x5000) == 0);                         /* the 1-page RO run was dropped, not merged */
    CHECK(perm_at(w, n, 0x100000000ULL + 0xf000) == 1 && perm_at(w, n, 0x100000000ULL + 0x19000) == 1);
    CHECK(perm_at(w, n, 0x100000000ULL + 0x23000) == 1);
    CHECK(perm_at(w, n, 0x100000000ULL) == 3 && perm_at(w, n, 0x100000000ULL + 0x6000) == 3);
    for (unsigned i = 0; i < n; i++) CHECK(!(w[i].flags == 1 && perm_at(w, n, w[i].ipa_base) != 1));
    /* writable runs alone over the limit: refuse (the monitor then refuses to lock) */
    for (unsigned i = 0; i < 9; i++)
        cuts[i] = (struct softgpu_cut){0x100000000ULL + (2 * i + 1) * 0x2000ULL, 0x100000000ULL + (2 * i + 1) * 0x2000ULL + 0x1000, 0};
    CHECK(softgpu_derive(rows, 1, cuts, 9, w, &n) == SOFTGPU_E_TOO_MANY);
#else
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    struct sgpu_window w[SOFTGPU_WINDOWS_MAX];
    struct softgpu_cut cuts[SOFTGPU_CUTS_MAX];
    unsigned n = 0;
    for (unsigned i = 0; i < SOFTGPU_ROWS_MAX; i++) rows[i] = row(0x100000000ULL + i * 0x100000ULL, 0x100000000ULL + i * 0x100000ULL + 0x80000ULL, RW);
    for (unsigned i = 0; i < SOFTGPU_CUTS_MAX; i++)
        cuts[i] = (struct softgpu_cut){0x100000000ULL + i * 0x100000ULL + 0x10000ULL, 0x100000000ULL + i * 0x100000ULL + 0x20000ULL, SOFTGPU_PERM_READ};
    /* the largest table the production limits can make: 16 rows in three runs, 16 in one */
    CHECK(softgpu_derive(rows, SOFTGPU_ROWS_MAX, cuts, SOFTGPU_CUTS_MAX, w, &n) == SOFTGPU_OK && n == 64);
    CHECK(SOFTGPU_WINDOWS_MAX == 64);
#endif
}

/* ---- a model of page 1 with fault injection ---- */
struct model {
    uint64_t page1;
    uint32_t reg[0x100 / 4 + 64 * 8];
    uint32_t applied;
    int never_apply, drop_word, no_magic, lock_stuck, ignore_count;
    unsigned writes;
    uint64_t write_log[512];
    uint64_t gen_write_at, count_write_at, last_window_write_at;
};
static uint32_t m_rd(void *ctx, uint64_t pa)
{
    struct model *m = ctx;
    uint32_t off = (uint32_t)(pa - m->page1);
    if (off == 0) return m->no_magic ? 0 : SOFTGPU_MON_MAGIC;
    if (off == SOFTGPU_MON_GEN_APPLIED) return m->applied;
    return m->reg[off / 4];
}
static void m_wr(void *ctx, uint64_t pa, uint32_t v)
{
    struct model *m = ctx;
    uint32_t off = (uint32_t)(pa - m->page1);
    m->writes++;
    if (off == SOFTGPU_MON_LOCK) { if (!m->lock_stuck) m->reg[off / 4] = v; return; }
    if (off == SOFTGPU_MON_WINDOW_COUNT) { m->count_write_at = m->writes; if (m->ignore_count) return; }
    if (off >= SOFTGPU_MON_WINDOW0) m->last_window_write_at = m->writes;
    if (m->drop_word && off == SOFTGPU_MON_WINDOW0 + 8) return;
    m->reg[off / 4] = v;
    if (off == SOFTGPU_MON_GEN) { m->gen_write_at = m->writes; if (!m->never_apply) m->applied = v; }
}

__attribute__((unused)) static void test_program(void)
{
    struct model m;
    struct softgpu_mon mon;
    const struct softgpu_mon_ops ops = {&m, m_rd, m_wr};
    struct sgpu_window w[3] = {
        {0x800000000ULL, 0x10000000ULL, 0x800000000ULL, 3, 0},
        {0x810000000ULL, 0x1000ULL, 0x810000000ULL, 1, 0},
        {0x820000000ULL, 0x2000ULL, 0x820000000ULL, 3, 0},
    };
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_OK && mon.gen == 0 && !mon.locked && !mon.failed);
    CHECK(softgpu_mon_program(&ops, &mon, w, 3) == SOFTGPU_OK && mon.gen == 1 && mon.nwin == 3);
    CHECK(m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 3 && m.applied == 1);
    CHECK(m.reg[(SOFTGPU_MON_WINDOW0 + 32) / 4 + 6] == 1 && m.reg[(SOFTGPU_MON_WINDOW0) / 4 + 1] == 8);
    CHECK(m.gen_write_at > m.last_window_write_at && m.gen_write_at > m.count_write_at);       /* table first, generation last */
    /* a second table: stale rows past the count are cleared */
    CHECK(softgpu_mon_program(&ops, &mon, w, 1) == SOFTGPU_OK && mon.gen == 2 && mon.nwin == 1);
    CHECK(m.reg[(SOFTGPU_MON_WINDOW0 + 64) / 4 + 2] == 0 && m.reg[(SOFTGPU_MON_WINDOW0 + 64) / 4 + 6] == 0);
    CHECK(softgpu_mon_program(&ops, &mon, w, 0) == SOFTGPU_OK && mon.nwin == 0 && mon.gen == 3);
    CHECK(softgpu_mon_lock(&ops, &mon) == SOFTGPU_OK && mon.locked && m.reg[SOFTGPU_MON_LOCK / 4] == 1);
    /* argument errors write nothing */
    unsigned before = m.writes;
    struct sgpu_window bad[2] = {w[0], w[0]};
    CHECK(softgpu_mon_program(&ops, &mon, bad, 2) == SOFTGPU_E_ARG);                            /* overlapping */
    bad[0] = w[1]; bad[1] = w[0];
    CHECK(softgpu_mon_program(&ops, &mon, bad, 2) == SOFTGPU_E_ARG);                            /* unsorted */
    bad[0] = w[0]; bad[0].flags = 0;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);                            /* no permission */
    bad[0] = w[0]; bad[0].flags = 4;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);
    bad[0] = w[0]; bad[0].size = 0x800;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);
    bad[0] = w[0]; bad[0].pa_base += 0x1000 + 1;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);
    bad[0] = w[0]; bad[0].reserved = 1;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);
    bad[0] = w[0]; bad[0].ipa_base = ~0xfffULL; bad[0].size = 0x2000;
    CHECK(softgpu_mon_program(&ops, &mon, bad, 1) == SOFTGPU_E_ARG);                            /* wraps */
    CHECK(softgpu_mon_program(&ops, &mon, w, SOFTGPU_WINDOWS_MAX + 1) == SOFTGPU_E_ARG);
    CHECK(softgpu_mon_program(&ops, &mon, 0, 1) == SOFTGPU_E_ARG);
    CHECK(m.writes == before && !mon.failed);

    /* the device never applies: fail closed with a new generation and zero windows, and no further table */
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL; m.never_apply = 1;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_OK);
    CHECK(softgpu_mon_program(&ops, &mon, w, 3) == SOFTGPU_E_APPLIED && mon.failed && mon.nwin == 0);
    CHECK(m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 0 && m.reg[SOFTGPU_MON_GEN / 4] == 2);
    m.never_apply = 0;
    CHECK(softgpu_mon_program(&ops, &mon, w, 3) == SOFTGPU_E_DEVICE);                           /* stays failed */
    CHECK(softgpu_mon_lock(&ops, &mon) == SOFTGPU_E_DEVICE && !mon.locked);

    /* a device that drops one table word, or the count: read-back catches it */
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL; m.drop_word = 1;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_OK);
    CHECK(softgpu_mon_program(&ops, &mon, w, 3) == SOFTGPU_E_DEVICE && mon.failed && m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 0);
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL; m.ignore_count = 1;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_OK);
    CHECK(softgpu_mon_program(&ops, &mon, w, 3) == SOFTGPU_E_DEVICE && mon.failed);

    /* no SMON magic: nothing is written */
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL; m.no_magic = 1;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_E_DEVICE && m.writes == 0);

    /* LOCK that does not read back */
    memset(&m, 0, sizeof m); m.page1 = 0x0c001000ULL; m.lock_stuck = 1;
    CHECK(softgpu_mon_open(&ops, &mon, m.page1) == SOFTGPU_OK && softgpu_mon_program(&ops, &mon, w, 1) == SOFTGPU_OK);
    CHECK(softgpu_mon_lock(&ops, &mon) == SOFTGPU_E_LOCK && !mon.locked && mon.failed);
}

/* ---- the GIC route ---- */
struct gic { uint32_t reg[0x8000 / 4]; int secure; };
static uint32_t g_rd(void *ctx, uint64_t pa) { struct gic *g = ctx; return g->reg[pa / 4]; }
static void g_wr(void *ctx, uint64_t pa, uint32_t v)
{
    struct gic *g = ctx;
    if (g->secure && pa >= 0x400 && pa < 0x800) return;       /* RAZ/WI priority of a Secure line */
    g->reg[pa / 4] = v;
}
__attribute__((unused)) static void test_gic(void)
{
    static struct gic g;
    const struct softgpu_gic_ops ops = {&g, g_rd, g_wr};
    memset(&g, 0, sizeof g);
    g.reg[0xc00 / 4 + 144 / 16] = 0xffffffffu;
    CHECK(softgpu_gic_route(&ops, 0, 144, 0x80000001ULL, 0x80) == SOFTGPU_OK);
    CHECK(g.reg[0x080 / 4 + 144 / 32] & (1u << (144 % 32)));                            /* group 1 */
    CHECK(!(g.reg[0xc00 / 4 + 144 / 16] & (2u << (2 * (144 % 16)))));                    /* level */
    CHECK(((g.reg[0x400 / 4 + 144 / 4] >> ((144 % 4) * 8)) & 0xff) == 0x80);
    CHECK(g.reg[0x6000 / 4 + 2 * 144] == 0x80000001u && g.reg[0x6000 / 4 + 2 * 144 + 1] == 0);
    CHECK(g.reg[0x180 / 4 + 144 / 32] == (1u << (144 % 32)));                           /* left disabled */
    g.secure = 1;
    g.reg[0x400 / 4 + 144 / 4] = 0;
    CHECK(softgpu_gic_route(&ops, 0, 144, 1, 0x80) == SOFTGPU_E_ARG);
    g.secure = 0;
    CHECK(softgpu_gic_route(&ops, 0, 31, 1, 0x80) == SOFTGPU_E_ARG);
    CHECK(softgpu_gic_route(&ops, 0, 1020, 1, 0x80) == SOFTGPU_E_ARG);
    CHECK(softgpu_gic_route(&ops, 0, 144, 1, 0) == SOFTGPU_E_ARG);
    CHECK(softgpu_gic_route(&ops, 0, 144, 1, 0x100) == SOFTGPU_E_ARG);
}

/* ---- the invariant, on random layouts: the device never has more than stage 2 gives ---- */
static uint64_t seed = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; }
__attribute__((unused)) static void test_random(void)
{
    enum { PAGES = 96 };
    for (unsigned round = 0; round < 3000; round++) {
        struct stage2_range rows[SOFTGPU_ROWS_MAX];
        struct softgpu_cut cuts[SOFTGPU_CUTS_MAX];
        uint32_t s2[PAGES] = {0}, cap[PAGES];
        unsigned nrows = 0, ncuts = rnd() % (SOFTGPU_CUTS_MAX + 1);
        for (unsigned p = 0; p < PAGES;) {
            unsigned len = 1 + (unsigned)(rnd() % 9), kind = (unsigned)(rnd() % 5);
            if (p + len > PAGES) len = PAGES - p;
            if (kind && nrows < SOFTGPU_ROWS_MAX) {
                uint64_t low = kind == 1 ? RO : kind == 2 ? DEV : kind == 3 ? RW : (2ULL << 6) | S2_ATTRS;
                rows[nrows++] = row(0x40000000ULL + p * 0x1000ULL, 0x40000000ULL + (p + len) * 0x1000ULL, low);
                for (unsigned q = p; q < p + len; q++) s2[q] = kind == 1 ? 1 : kind == 3 ? 3 : 0;
            }
            p += len + (unsigned)(rnd() % 3);
        }
        for (unsigned p = 0; p < PAGES; p++) cap[p] = 3;
        for (unsigned i = 0; i < ncuts; i++) {
            unsigned a = (unsigned)(rnd() % PAGES), len = 1 + (unsigned)(rnd() % 12);
            if (a + len > PAGES) len = PAGES - a;
            cuts[i] = (struct softgpu_cut){0x40000000ULL + a * 0x1000ULL + rnd() % 0x1000, 0x40000000ULL + (a + len) * 0x1000ULL - (rnd() % 0x800),
                                           (uint32_t)(rnd() % 4)};
            if (cuts[i].hi <= cuts[i].lo) cuts[i].hi = cuts[i].lo + 1;
            uint64_t lo = (cuts[i].lo & ~0xfffULL), hi = (cuts[i].hi + 0xfff) & ~0xfffULL;
            for (uint64_t pa = lo; pa < hi; pa += 0x1000) {
                unsigned q = (unsigned)((pa - 0x40000000ULL) / 0x1000);
                if (q < PAGES) cap[q] &= cuts[i].keep;
            }
        }
        struct sgpu_window w[SOFTGPU_WINDOWS_MAX];
        unsigned n = 0;
        int r = softgpu_derive(rows, nrows, cuts, ncuts, w, &n);
        if (r == SOFTGPU_E_TOO_MANY) continue;
        CHECK(r == SOFTGPU_OK && n <= SOFTGPU_WINDOWS_MAX);
        unsigned dropped_ok = 0;
        for (unsigned q = 0; q < PAGES; q++) {
            uint32_t got = perm_at(w, n, 0x40000000ULL + q * 0x1000ULL), want = s2[q] & cap[q];
            CHECK((got & ~want) == 0);                       /* never more than stage 2 and the cuts allow */
            if (got != want) dropped_ok++;
        }
        (void)dropped_ok;
        for (unsigned i = 0; i < n; i++) {
            CHECK(!(w[i].ipa_base & 0xfff) && !(w[i].size & 0xfff) && w[i].size);
            if (i) CHECK(w[i].ipa_base >= w[i - 1].ipa_base + w[i - 1].size);
            if (i) CHECK(!(w[i - 1].ipa_base + w[i - 1].size == w[i].ipa_base && w[i - 1].flags == w[i].flags));   /* maximal runs */
        }
        if (n < SOFTGPU_WINDOWS_MAX) {                        /* no READ dropped unless the table was full */
            for (unsigned q = 0; q < PAGES; q++)
                CHECK(perm_at(w, n, 0x40000000ULL + q * 0x1000ULL) == (s2[q] & cap[q]));
        }
    }
}

/* ---- the monitor's steps over the facts: boot table, LOCKDOWN downgrade, close, refusal of a used device ---- */
#define WWATCH   0x8f0800000ULL
#define P1       0x0c001000ULL

static struct softgpu_facts board_facts(void)
{
    return (struct softgpu_facts){
        .work_base = WORK_LO, .work_end = WORK_HI,
        .trust_pa = TRUST_LO, .trust_size = TRUST_HI - TRUST_LO - 0x4000,       /* stage2_trust_end() == TRUST_HI */
        .write_watch_pa = WWATCH,
        .watch_pa = WATCH, .watch_count = 2,
        .const_begin = CONST_LO, .const_end = CONST_HI};
}

/* What the device holds, decoded from the model's page 1 registers (count, then the table words): the behaviour the guest's
 * device would have, independent of how the monitor arrived at it. */
static uint32_t dev_perm(const struct model *m, uint64_t pa)
{
    const uint32_t n = m->reg[SOFTGPU_MON_WINDOW_COUNT / 4];
    for (uint32_t i = 0; i < n; i++) {
        const uint32_t *w = &m->reg[(SOFTGPU_MON_WINDOW0 + 32 * i) / 4];
        const uint64_t base = w[0] | (uint64_t)w[1] << 32, size = w[2] | (uint64_t)w[3] << 32;
        if (pa >= base && pa - base < size) return w[6];
    }
    return 0;
}

static unsigned span_all(const struct model *m, uint64_t lo, uint64_t hi, uint32_t want)
{
    unsigned bad = 0;
    for (uint64_t pa = lo; pa < hi; pa += 0x1000)
        if (dev_perm(m, pa) != want) bad++;
    return bad;
}

static void model_fresh(struct model *m)
{
    memset(m, 0, sizeof *m);
    m->page1 = P1;
}

__attribute__((unused)) static void test_lockdown(void)
{
    static struct model m;
    struct softgpu_state st;
    const struct softgpu_mon_ops ops = {&m, m_rd, m_wr};
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    const struct softgpu_facts f = board_facts();
    const unsigned nrows = board_rows(rows);
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_OK);
    CHECK(st.stage == 1 && st.mon.locked && !st.mon.failed && m.reg[SOFTGPU_MON_LOCK / 4] == 1);
    CHECK(m.applied == 1 && st.mon.gen == 1);
    /* the boot table: the const region is still writable to the device, the trust cache and the write-watch page are not */
    CHECK(span_all(&m, CONST_LO, CONST_HI, 3) == 0);
    CHECK(span_all(&m, TRUST_LO, TRUST_HI, 1) == 0 && dev_perm(&m, TRUST_HI) == 3 && dev_perm(&m, TRUST_LO - 0x1000) == 3);
    CHECK(dev_perm(&m, WWATCH) == 1 && dev_perm(&m, WWATCH - 0x1000) == 3 && dev_perm(&m, WWATCH + 0x1000) == 3);
    CHECK(span_all(&m, WATCH, WATCH + 0x2000, 0) == 0 && dev_perm(&m, WATCH + 0x2000) == 3);
    CHECK(span_all(&m, WORK_LO, WORK_HI, 0) == 0);
    CHECK(dev_perm(&m, 0x0c000000ULL) == 0 && dev_perm(&m, P1) == 0);                    /* the device's own pages */

    /* LOCKDOWN: the device is narrowed first. After it the whole const region is READ only, the cut ends exactly at its
     * edges, and nothing else moved. */
    const unsigned writes_before = m.writes;
    CHECK(softgpu_lockdown_step(&ops, &st, rows, nrows, &f) == SOFTGPU_OK);
    CHECK(st.stage == 2 && st.const_ro && st.downgrades == 1 && st.mon.gen == 2 && m.applied == 2 && m.writes > writes_before);
    CHECK(span_all(&m, CONST_LO, CONST_HI, 1) == 0);
    CHECK(dev_perm(&m, CONST_LO - 0x1000) == 3 && dev_perm(&m, CONST_HI) == 3);
    CHECK(span_all(&m, TRUST_LO, TRUST_HI, 1) == 0 && dev_perm(&m, TRUST_HI) == 3 && dev_perm(&m, TRUST_LO - 0x1000) == 3);
    CHECK(dev_perm(&m, WWATCH) == 1 && span_all(&m, WATCH, WATCH + 0x2000, 0) == 0 && span_all(&m, WORK_LO, WORK_HI, 0) == 0);
    CHECK(dev_perm(&m, RAM_LO) == 3 && dev_perm(&m, PANIC) == 1 && dev_perm(&m, SCRATCH) == 3 && dev_perm(&m, FB) == 3);
    CHECK(m.reg[SOFTGPU_MON_LOCK / 4] == 1);
    /* a second LOCKDOWN changes nothing and writes nothing */
    const unsigned writes_after = m.writes;
    CHECK(softgpu_lockdown_step(&ops, &st, rows, nrows, &f) == SOFTGPU_OK && m.writes == writes_after && st.downgrades == 1);

    /* hand-back: no windows, and the device says so */
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_OK && st.stage == 0);
    CHECK(m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 0 && st.mon.gen == 3 && m.applied == 3 && st.mon.unconfirmed == 0);
    CHECK(span_all(&m, RAM_LO, RAM_LO + 0x100000, 0) == 0);
    const unsigned writes_closed = m.writes;
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_OK && m.writes == writes_closed);       /* closed twice: nothing more */
}

__attribute__((unused)) static void test_lockdown_unprepared(void)
{
    /* M2: gpu_prepare returned before softgpu_prepare (GPU block off): page 1 was never opened. LOCKDOWN must not derive a
     * table or write one register, least of all to physical address 0 of a zeroed monitor. */
    static struct model m;
    struct softgpu_state st;
    const struct softgpu_mon_ops ops = {&m, m_rd, m_wr};
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    const struct softgpu_facts f = board_facts();
    const unsigned nrows = board_rows(rows);
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_lockdown_step(&ops, &st, rows, nrows, &f) == SOFTGPU_OK);
    CHECK(m.writes == 0 && st.stage == 0 && !st.const_ro && st.downgrades == 0 && st.mon.gen == 0 && !st.mon.failed);
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_OK && m.writes == 0);
}

__attribute__((unused)) static void test_lockdown_failure(void)
{
    static struct model m;
    struct softgpu_state st;
    const struct softgpu_mon_ops ops = {&m, m_rd, m_wr};
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    const struct softgpu_facts f = board_facts();
    const unsigned nrows = board_rows(rows);
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_OK);
    /* the device stops applying: the downgrade is refused (the seal must not happen), the device is failed closed, and the
     * monitor stays failed */
    m.never_apply = 1;
    CHECK(softgpu_lockdown_step(&ops, &st, rows, nrows, &f) == SOFTGPU_E_APPLIED);
    CHECK(!st.const_ro && st.stage == 1 && st.mon.failed && st.downgrades == 0 && m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 0);
    CHECK(st.mon.unconfirmed == 1);                       /* the zero table was not confirmed either: the device is suspect */
    m.never_apply = 0;
    CHECK(softgpu_lockdown_step(&ops, &st, rows, nrows, &f) == SOFTGPU_E_DEVICE && !st.const_ro);
    /* hand-back still takes the windows away and now gets the confirmation */
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_OK && m.reg[SOFTGPU_MON_WINDOW_COUNT / 4] == 0 && m.applied == st.mon.gen);

    /* a device that never confirms the zero table at hand-back is counted and reported, not ignored */
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_OK);
    m.never_apply = 1;
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_E_APPLIED && st.mon.unconfirmed == 1 && st.stage == 0);
    /* a device that ignores the count write is caught by the read-back */
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_OK);
    m.ignore_count = 1;
    CHECK(softgpu_close_step(&ops, &st) == SOFTGPU_E_DEVICE && st.mon.unconfirmed == 1);
}

__attribute__((unused)) static void test_prepare_refusals(void)
{
    static struct model m;
    struct softgpu_state st;
    const struct softgpu_mon_ops ops = {&m, m_rd, m_wr};
    struct stage2_range rows[SOFTGPU_ROWS_MAX];
    const struct softgpu_facts f = board_facts();
    const unsigned nrows = board_rows(rows);
    /* L2: a device a previous monitor used, or monitorless=on (LOCK set, generation 1 applied): refuse, touch nothing */
    model_fresh(&m);
    m.reg[SOFTGPU_MON_LOCK / 4] = 1;
    m.applied = 1;
    m.reg[SOFTGPU_MON_GEN / 4] = 1;
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_E_DEVICE && m.writes == 0 && st.stage == 0);
    model_fresh(&m);
    m.reg[SOFTGPU_MON_LOCK / 4] = 1;                                      /* LOCK alone is enough */
    CHECK(softgpu_mon_open(&ops, &st.mon, P1) == SOFTGPU_E_DEVICE && m.writes == 0);
    model_fresh(&m);
    m.reg[SOFTGPU_MON_GEN / 4] = 5;                                       /* so is a generation already written */
    CHECK(softgpu_mon_open(&ops, &st.mon, P1) == SOFTGPU_E_DEVICE && m.writes == 0);
    model_fresh(&m);
    m.applied = 3;                                                        /* or applied */
    CHECK(softgpu_mon_open(&ops, &st.mon, P1) == SOFTGPU_E_DEVICE && m.writes == 0);
    model_fresh(&m);
    CHECK(softgpu_mon_open(&ops, &st.mon, P1) == SOFTGPU_OK);
    /* an empty table is still a table; a device that never applies is refused before LOCK is written */
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, 0, &f) == SOFTGPU_OK);     /* an empty table is still a table */
    model_fresh(&m);
    memset(&st, 0, sizeof st);
    m.never_apply = 1;
    CHECK(softgpu_prepare_windows(&ops, &st, P1, rows, nrows, &f) == SOFTGPU_E_APPLIED && !st.mon.locked && st.stage == 0 &&
          m.reg[SOFTGPU_MON_LOCK / 4] == 0);
}

int main(void)
{
    test_fragments();
#if SOFTGPU_WINDOWS_MAX == 64
    test_board();
    test_malformed();
    test_program();
    test_gic();
    test_random();
    test_lockdown();
    test_lockdown_unprepared();
    test_lockdown_failure();
    test_prepare_refusals();
#endif
    printf("{\"softgpu_windows_checks\":%u,\"softgpu_windows_failures\":%u}\n", checks, failures);
    return failures != 0;
}
