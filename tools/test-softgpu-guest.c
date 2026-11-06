/* SPDX-License-Identifier: MIT */
/* compat/softgpu-guest.c against libsgpu's own validator (the device's decode path, p6d lib/sgpu_validate.c): every
 * descriptor, KERNEL stream, SUBMIT stream and binding table the C builders emit goes through sgpu_validate_desc and
 * sgpu_validate_stream; the ring (wrap, slot reuse, record check), the arena (order, wrap, no overlap of live
 * blocks), the 0x1010 header check, the completion mapping and the adreno_kernel_command routing of 0x1010 are
 * checked on top.
 *   P6D=/home/snap/p6d  (a tree with lib/sgpu_validate.c and include/sgpu_host.h)
 *   gcc -std=gnu11 -O1 -g -fsanitize=address,undefined -Wall -Icompat -I$P6D/include -o test-softgpu-guest \
 *       tools/test-softgpu-guest.c compat/softgpu-guest.c compat/adreno-ib-command.c compat/adreno-submit.c \
 *       compat/adreno-fill-command.c compat/adreno-resource-list.c compat/adreno-resource.c $P6D/lib/sgpu_validate.c
 *   ./test-softgpu-guest */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "softgpu-guest.h"
#include "sgpu_host.h"
#include "adreno-ib-command.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define STAMPS 129u
#define PANEL_ROWS_BYTES (2880u * 4u * 64u)

/* ---- a model of the device: validates and "executes" descriptors in ring order ---- */
struct model {
    uint8_t *arena;                    /* memory object 1 */
    uint64_t arena_size;
    struct sgpu_completion rec[SGPU_GUEST_RING_ENTRIES];
    uint64_t done_seqno, next_seqno;
    uint32_t head;                     /* RING_HEAD */
    uint32_t stamps[STAMPS];
    unsigned submits, kernels, mems;
    int32_t status_of[8];              /* statuses per executed descriptor, cleared per test */
};
static void sg_check_bt(const struct sgpu_bt_entry *bt, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) CHECK(bt[i].mem_id >= 1 && (bt[i].access & 3) && !(bt[i].access & ~3u));
}
/* Consume [head, tail) of the ring. Returns the first non-zero validation status (and completes it with that). */
static int device_run(struct model *m, struct sgpu_guest_ring *r, uint32_t tail)
{
    int first = 0;
    while (m->head != tail) {
        const struct sgpu_desc *d = &r->slots[m->head % r->entries];
        struct sgpu_val_err err;
        int st = d->seqno == m->next_seqno ? 0 : SGPU_E_FORMAT;
        CHECK(d->seqno == m->next_seqno);                              /* strictly +1, first is 1 */
        if (!st) st = sgpu_validate_desc(d, STAMPS, (d->flags & SGPU_DESC_BOOTSTRAP) ? 0 : m->arena_size, &err);
        if (!st && !(d->flags & SGPU_DESC_BOOTSTRAP)) {
            const struct sgpu_bt_entry *bt = (const struct sgpu_bt_entry *)(m->arena + d->bt_offset);
            st = sgpu_validate_stream(m->arena + d->stream_offset, d->stream_bytes, d->type == SGPU_DESC_KERNEL, bt,
                                      d->bt_count, &err);
            if (!st) sg_check_bt(bt, d->bt_count);
        }
        if (st) printf("  descriptor %llu refused %d: %s (op 0x%x)\n", (unsigned long long)d->seqno, st,
                       err.what ? err.what : "?", err.opcode);
        if (st && !first) first = st;
        d->type == SGPU_DESC_KERNEL ? m->kernels++ : m->submits++;
        if (!st && d->stamp_index != SGPU_GUEST_NO_STAMP) m->stamps[d->stamp_index] = d->stamp_value;
        struct sgpu_completion *c = &m->rec[m->head % r->entries];
        c->seqno = d->seqno; c->status = st; c->packet_offset = 0;
        m->done_seqno = d->seqno;
        m->next_seqno++;
        m->head++;
    }
    return first;
}
static uint32_t retire_all(struct sgpu_guest_ring *r, struct model *m, struct sgpu_guest_arena *a, int32_t *statuses)
{
    struct sgpu_completion c;
    uint32_t n = 0;
    while (sgpu_guest_ring_retire_one(r, m->rec, m->done_seqno, &c) == 1) {
        if (statuses) statuses[n] = c.status;
        n++;
    }
    if (a) sgpu_guest_arena_release(a, r->done_seqno);
    return n;
}

/* ---- bring-up of 1.9 and the F1 self-test, byte for byte what softgpu.cpp emits ---- */
static void test_bringup_selftest(void)
{
    static struct sgpu_desc slots[SGPU_GUEST_RING_ENTRIES];
    struct sgpu_guest_ring r;
    struct model m = {0};
    uint8_t boot[16384];
    struct sgpu_guest_arena arena;
    CHECK(sgpu_guest_ring_init(&r, slots, SGPU_GUEST_RING_ENTRIES) == 0);
    m.arena = calloc(1, SGPU_GUEST_ARENA_BYTES);
    m.arena_size = SGPU_GUEST_ARENA_BYTES;
    m.next_seqno = 1;
    sgpu_guest_arena_init(&arena, SGPU_GUEST_ARENA_BYTES);
    /* step 5: arena of 4 MiB as 256 scattered 16 KiB runs (every other page, so no coalescing) */
    struct sgpu_mem_run runs[256];
    uint32_t n = 0;
    for (uint64_t i = 0; i < 256; i++) CHECK(sgpu_guest_runs_add(runs, &n, 256, 0x80000000ull + i * 0x8000, 0x4000) == 0);
    CHECK(n == 256);
    int len = sgpu_guest_pkt_create_memory(boot, sizeof boot, 1, SGPU_MEM_ARENA, SGPU_GUEST_ARENA_BYTES, 0, 0, runs, n);
    CHECK(len == 48 + 256 * 16);
    struct sgpu_desc d;
    sgpu_guest_desc_kernel(&d, SGPU_DESC_BOOTSTRAP, 0xbc000000ull, len, SGPU_GUEST_NO_STAMP, 0);
    CHECK(sgpu_guest_ring_push(&r, &d) == 1);
    struct sgpu_val_err err;
    CHECK(sgpu_validate_desc(&r.slots[0], STAMPS, 0, &err) == 0);
    CHECK(sgpu_validate_stream(boot, len, 1, 0, 0, &err) == 0);
    /* a bootstrap stream is a KERNEL stream: the same bytes as a SUBMIT stream are refused */
    CHECK(sgpu_validate_stream(boot, len, 0, 0, 0, &err) == SGPU_E_OPCODE);
    m.head = 0;
    CHECK(device_run(&m, &r, r.produced) == 0);
    int32_t st[8];
    CHECK(retire_all(&r, &m, &arena, st) == 1 && st[0] == 0);
    /* step 6: probe STAMP into slot 128 (KERNEL, stream in the arena) */
    uint64_t off;
    CHECK(sgpu_guest_arena_alloc(&arena, 16, r.next_seqno, &off) == 0);
    CHECK(sgpu_guest_pkt_stamp(m.arena + off, 16, SGPU_GUEST_PROBE_STAMP, 0x600d) == 16);
    sgpu_guest_desc_kernel(&d, SGPU_DESC_IRQ, off, 16, SGPU_GUEST_NO_STAMP, 0);
    CHECK(sgpu_guest_ring_push(&r, &d) == 2);
    CHECK(device_run(&m, &r, r.produced) == 0 && retire_all(&r, &m, &arena, st) == 1);
    CHECK(arena.used == 0);
    /* a stamp index past STAMP_COUNT is refused by the device */
    CHECK(sgpu_guest_arena_alloc(&arena, 16, r.next_seqno, &off) == 0);
    sgpu_guest_pkt_stamp(m.arena + off, 16, 129, 1);
    sgpu_guest_desc_kernel(&d, 0, off, 16, 129, 1);
    CHECK(sgpu_guest_ring_push(&r, &d) == 3);
    CHECK(device_run(&m, &r, r.produced) == SGPU_E_FORMAT);
    CHECK(retire_all(&r, &m, &arena, st) == 1 && st[0] == SGPU_E_FORMAT);
    /* CREATE_CONTEXT 1, CREATE_MEMORY 2 over the panel's first 64 rows, then SUBMIT FILL_BUFFER with BT[0] */
    uint32_t total = 32 + 48 + 16;
    CHECK(sgpu_guest_arena_alloc(&arena, total, r.next_seqno, &off) == 0);
    uint8_t *p = m.arena + off;
    CHECK(sgpu_guest_pkt_create_context(p, 32, 1) == 32);
    struct sgpu_mem_run panel = { 0xbd000000ull, 0xb4000 };            /* 737,280 = 0xb4000 */
    CHECK(sgpu_guest_pkt_create_memory(p + 32, 64, 2, 0, PANEL_ROWS_BYTES, 0, 0, &panel, 1) == 64);
    sgpu_guest_desc_kernel(&d, 0, off, 32 + 64, SGPU_GUEST_NO_STAMP, 0);
    CHECK(sgpu_guest_ring_push(&r, &d) == 4);
    CHECK(device_run(&m, &r, r.produced) == 0 && retire_all(&r, &m, &arena, st) == 1);
    struct sgpu_guest_bt_in in = { 2, ADRENO_USAGE_WRITE, 0, 0, PANEL_ROWS_BYTES, 77 };
    CHECK(sgpu_guest_arena_alloc(&arena, 40 + 32, r.next_seqno, &off) == 0);
    CHECK(sgpu_guest_pkt_fill_buffer(m.arena + off, 40, 0, 0, PANEL_ROWS_BYTES, 0xff3080c0) == 40);
    CHECK(sgpu_guest_bt_build((struct sgpu_bt_entry *)(m.arena + off + 40), &in, 1) == 0);
    sgpu_guest_desc_submit(&d, 1, 1, SGPU_DESC_LAST | SGPU_DESC_IRQ, off, 40, off + 40, 1, SGPU_GUEST_NO_STAMP, 0, 0, 0);
    CHECK(sgpu_guest_ring_push(&r, &d) == 5);
    CHECK(device_run(&m, &r, r.produced) == 0);
    CHECK(((struct sgpu_bt_entry *)(m.arena + off + 40))->access == SGPU_ACCESS_WRITE);
    /* the same stream with the BT entry read-only is refused (FILL_BUFFER needs WRITE) */
    in.read_only = 1;
    sgpu_guest_bt_build((struct sgpu_bt_entry *)(m.arena + off + 40), &in, 1);
    CHECK(sgpu_validate_stream(m.arena + off, 40, 0, (struct sgpu_bt_entry *)(m.arena + off + 40), 1, &err) != 0);
    CHECK(retire_all(&r, &m, &arena, st) == 1 && arena.used == 0);
    /* sanity that the validator is live on our bytes: a flipped reserved field is refused */
    sgpu_guest_pkt_stamp(boot, 16, 1, 1);
    boot[2] = 2;                                                                      /* undefined packet flag */
    CHECK(sgpu_validate_stream(boot, 16, 1, 0, 0, &err) == SGPU_E_FORMAT);
    /* DESTROY_MEMORY and DESTROY_CONTEXT */
    uint8_t k[32];
    CHECK(sgpu_guest_pkt_destroy_memory(k, 16, 2) == 16 && sgpu_validate_stream(k, 16, 1, 0, 0, &err) == 0);
    CHECK(sgpu_guest_pkt_destroy_context(k, 16, 1) == 16 && sgpu_validate_stream(k, 16, 1, 0, 0, &err) == 0);
    CHECK(sgpu_guest_pkt_create_context(k, 31, 1) == SGPU_E_BOUNDS);
    free(m.arena);
}

/* ---- ring: wrap, slot reuse, record check ---- */
static void test_ring(void)
{
    static struct sgpu_desc slots[SGPU_GUEST_RING_ENTRIES];
    struct sgpu_guest_ring r;
    static struct sgpu_completion rec[SGPU_GUEST_RING_ENTRIES];
    struct sgpu_desc d;
    CHECK(sgpu_guest_ring_init(&r, slots, 15) == SGPU_E_FORMAT);
    CHECK(sgpu_guest_ring_init(&r, slots, 24) == SGPU_E_FORMAT);
    CHECK(sgpu_guest_ring_init(&r, slots, 512) == SGPU_E_FORMAT);
    CHECK(sgpu_guest_ring_init(&r, slots, 16) == 0);
    sgpu_guest_desc_kernel(&d, 0, 0, 0, SGPU_GUEST_NO_STAMP, 0);
    for (uint64_t i = 1; i <= 16; i++) CHECK(sgpu_guest_ring_push(&r, &d) == i);
    CHECK(sgpu_guest_ring_push(&r, &d) == 0 && sgpu_guest_ring_free(&r) == 0);        /* full until retired */
    struct sgpu_completion c;
    CHECK(sgpu_guest_ring_retire_one(&r, rec, 0, &c) == 0);                           /* nothing done yet */
    for (uint64_t i = 1; i <= 4; i++) { rec[(i - 1) % 16].seqno = i; rec[(i - 1) % 16].status = 0; }
    int n = 0;
    while (sgpu_guest_ring_retire_one(&r, rec, 4, &c) == 1) { n++; CHECK(c.seqno == (uint64_t)n); }
    CHECK(n == 4 && sgpu_guest_ring_free(&r) == 4);
    /* slot reuse: the pushes after retirement land in slots 0..3 with seqno 17.. and nothing else moves */
    for (uint64_t i = 17; i <= 20; i++) CHECK(sgpu_guest_ring_push(&r, &d) == i);
    CHECK(r.slots[0].seqno == 17 && r.slots[3].seqno == 20 && r.slots[4].seqno == 5);
    CHECK(sgpu_guest_ring_push(&r, &d) == 0);
    /* a stale or wrong record is never a completion (1.5): done says 5 but the record holds seqno 99 */
    rec[4].seqno = 99;
    CHECK(sgpu_guest_ring_retire_one(&r, rec, 5, &c) == SGPU_GUEST_E_RECORD && r.retired == 4);
    rec[4].seqno = 5;
    CHECK(sgpu_guest_ring_retire_one(&r, rec, 5, &c) == 1 && c.seqno == 5);
    /* many wraps through the free-running u32 counters */
    for (int round = 0; round < 1000; round++) {
        while (sgpu_guest_ring_free(&r)) {
            uint64_t s = sgpu_guest_ring_push(&r, &d);
            CHECK(s && r.slots[(r.produced - 1) % 16].seqno == s);
        }
        uint64_t top = r.next_seqno - 1;
        for (uint64_t s = r.done_seqno + 1; s <= top; s++) { rec[(r.retired) % 16].seqno = s; rec[r.retired % 16].status = 0;
            CHECK(sgpu_guest_ring_retire_one(&r, rec, top, &c) == 1 && c.seqno == s); }
        CHECK(r.retired == r.produced);
    }
    r.produced = r.retired = 0xfffffff0u;                                             /* u32 wrap of RING_TAIL */
    for (int i = 0; i < 16; i++) CHECK(sgpu_guest_ring_push(&r, &d));
    CHECK(r.produced == 0 && sgpu_guest_ring_free(&r) == 0 && sgpu_guest_ring_push(&r, &d) == 0);
    sgpu_guest_ring_reset(&r);
    CHECK(r.next_seqno == 1 && sgpu_guest_ring_free(&r) == 16 && sgpu_guest_ring_push(&r, &d) == 1);
}

/* ---- arena ---- */
static void test_arena(void)
{
    struct sgpu_guest_arena a;
    uint64_t o1, o2, o3;
    sgpu_guest_arena_init(&a, 1024);
    CHECK(sgpu_guest_arena_alloc(&a, 2000, 1, &o1) == SGPU_E_QUOTA);
    CHECK(sgpu_guest_arena_alloc(&a, 1024, 1, &o1) == SGPU_E_QUOTA);                  /* needs room for the wrap rule */
    CHECK(sgpu_guest_arena_alloc(&a, 600, 1, &o1) == 0 && o1 == 0);
    CHECK(sgpu_guest_arena_alloc(&a, 300, 2, &o2) == 0 && o2 == 600);
    CHECK(sgpu_guest_arena_alloc(&a, 200, 3, &o3) == SGPU_GUEST_BUSY);                /* 1024 - 900 = 124 free */
    sgpu_guest_arena_release(&a, 1);
    CHECK(sgpu_guest_arena_alloc(&a, 200, 3, &o3) == 0 && o3 == 0);                   /* wraps: 124 bytes wasted at the end */
    CHECK(a.used == 300 + 124 + 200 + 0 + 0 || a.used == 900 - 600 + 124 + 200);
    CHECK(sgpu_guest_arena_alloc(&a, 1, 4, &o1) == 0 && o1 == 200);
    sgpu_guest_arena_release(&a, 2);
    sgpu_guest_arena_release(&a, 3);
    sgpu_guest_arena_release(&a, 4);
    CHECK(a.used == 0 && a.count == 0);
    CHECK(sgpu_guest_arena_alloc(&a, 0, 5, &o1) == 0 && o1 == 0 && a.used == 8);      /* zero bytes reserve 8 */
    CHECK(sgpu_guest_arena_alloc(&a, 5, 5, &o2) == 0 && o2 == 8 && o2 % 8 == 0);
    /* regression: a block ending exactly at the end leaves end == size; the next one must start at 0, not at size */
    sgpu_guest_arena_init(&a, 1024);
    CHECK(sgpu_guest_arena_alloc(&a, 1016, 1, &o1) == 0 && sgpu_guest_arena_alloc(&a, 8, 2, &o2) == 0 && o2 == 1016);
    sgpu_guest_arena_release(&a, 1);
    CHECK(sgpu_guest_arena_alloc(&a, 16, 3, &o3) == 0 && o3 == 0);
    /* randomised: live blocks never overlap, offsets 8-aligned, within the arena, released strictly in seqno order */
    sgpu_guest_arena_init(&a, 1 << 16);
    struct { uint64_t off, bytes, seqno; } live[300];
    unsigned nlive = 0, head = 0;
    uint64_t seq = 1;
    srand(7);
    for (int i = 0; i < 20000; i++) {
        uint64_t bytes = (uint64_t)(rand() % 9000);
        uint64_t off;
        int rc = sgpu_guest_arena_alloc(&a, bytes, seq, &off);
        if (rc == 0) {
            CHECK(off % 8 == 0 && off + (bytes ? (bytes + 7) & ~7ull : 8) <= a.size);
            for (unsigned j = 0; j < nlive; j++) {
                const unsigned k = (head + j) % 300;
                uint64_t lo = live[k].off, hi = lo + live[k].bytes, b = bytes ? (bytes + 7) & ~7ull : 8;
                CHECK(off >= hi || off + b <= lo);
            }
            live[(head + nlive) % 300].off = off;
            live[(head + nlive) % 300].bytes = bytes ? (bytes + 7) & ~7ull : 8;
            live[(head + nlive) % 300].seqno = seq;
            nlive++;
            seq++;
        } else {
            CHECK(rc == SGPU_GUEST_BUSY);
            if (nlive) {                                                              /* the DONE handler catches up */
                unsigned drop = 1 + rand() % nlive;
                uint64_t upto = live[(head + drop - 1) % 300].seqno;
                head = (head + drop) % 300; nlive -= drop;
                sgpu_guest_arena_release(&a, upto);
            }
        }
        if (nlive >= 250) { uint64_t upto = live[(head + nlive - 1) % 300].seqno; head = 0; nlive = 0; sgpu_guest_arena_release(&a, upto); }
    }
}

/* ---- binding table ---- */
static void test_bt(void)
{
    struct sgpu_guest_bt_in in[6] = {
        { 3, ADRENO_USAGE_READ, 0, 16, 100, 1 }, { 4, ADRENO_USAGE_WRITE, 0, 0, 64, 2 },
        { 5, ADRENO_USAGE_READ | ADRENO_USAGE_WRITE, 1, 8, 8, 3 }, { 6, ADRENO_USAGE_SAMPLE, 0, 0, 1, 4 },
        { 7, ADRENO_USAGE_WRITE, 1, 0, 4, 5 }, { 8, 0, 0, 0, 4, 6 } };
    struct sgpu_bt_entry out[6];
    CHECK(sgpu_guest_bt_build(out, in, 6) == 0);
    CHECK(out[0].access == 1 && out[1].access == 2 && out[2].access == 1 && out[3].access == 1);
    CHECK(out[4].access == 1 && out[5].access == 1);                                   /* write-only on read-only: READ */
    CHECK(out[0].mem_id == 3 && out[0].offset == 16 && out[0].length == 100 && out[0].resource_id == 1);
    CHECK(sizeof out[0] == 32);
    in[2].mem_id = 0;
    CHECK(sgpu_guest_bt_build(out, in, 6) == SGPU_E_FORMAT);
}

/* ---- the 0x1010 header ---- */
static void mkcmd(uint8_t *c, uint32_t stream_bytes, uint64_t epoch)
{
    struct sgpu_kcmd_stream h = { SOFTGPU_KCMD_STREAM, 32 + stream_bytes, 1, 0, stream_bytes, 0, epoch };
    memset(c, 0xab, 32 + stream_bytes);
    memcpy(c, &h, 32);
}
static void test_kcmd(void)
{
    uint8_t c[128];
    const uint8_t *s;
    uint32_t n;
    mkcmd(c, 64, 5);
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == 0 && s == c + 32 && n == 64);
    CHECK(sgpu_guest_kcmd_stream(c, 128, 5, &s, &n) == 0);                             /* IOGPU's extent may be longer */
    CHECK(sgpu_guest_kcmd_stream(c, 95, 5, &s, &n) == SGPU_E_FORMAT);                  /* extent shorter than size */
    CHECK(sgpu_guest_kcmd_stream(c, 31, 5, &s, &n) == SGPU_E_FORMAT);
    CHECK(sgpu_guest_kcmd_stream(c, 96, 6, &s, &n) == SGPU_E_LOST);                    /* stale plug-in epoch */
    CHECK(sgpu_guest_kcmd_stream(0, 96, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[0] = 0x11;
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[8] = 2;                                                         /* version */
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[12] = 1;                                                        /* flags */
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[20] = 1;                                                        /* reserved0 */
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[4] = 100;                                                       /* size != 32 + stream_bytes */
    CHECK(sgpu_guest_kcmd_stream(c, 128, 5, &s, &n) == SGPU_E_FORMAT);
    mkcmd(c, 64, 5); c[16] = 60;                                                       /* stream_bytes not a multiple of 8 */
    CHECK(sgpu_guest_kcmd_stream(c, 96, 5, &s, &n) == SGPU_E_FORMAT);
    struct sgpu_kcmd_stream big = { SOFTGPU_KCMD_STREAM, 32 + 0x400008u, 1, 0, 0x400008u, 0, 5 };
    uint8_t bigc[32];
    memcpy(bigc, &big, 32);
    CHECK(sgpu_guest_kcmd_stream(bigc, 0x400008u + 32, 5, &s, &n) == SGPU_E_FORMAT);   /* over 4 MiB */
    struct sgpu_kcmd_stream wrap = { SOFTGPU_KCMD_STREAM, 24, 1, 0, 0xfffffff8u, 0, 5 };
    memcpy(bigc, &wrap, 32);
    CHECK(sgpu_guest_kcmd_stream(bigc, 32, 5, &s, &n) == SGPU_E_FORMAT);               /* 32 + stream_bytes overflow */
    mkcmd(c, 0, 5);
    CHECK(sgpu_guest_kcmd_stream(c, 32, 5, &s, &n) == 0 && n == 0);
}

static void test_status(void)
{
    CHECK(sgpu_guest_iogpu_status(SGPU_OK) == 0 && sgpu_guest_iogpu_status(SGPU_E_TIMEOUT) == 3);
    CHECK(sgpu_guest_iogpu_status(SGPU_E_RESET) == 5 && sgpu_guest_iogpu_status(SGPU_E_LOST) == 5);
    CHECK(sgpu_guest_iogpu_status(SGPU_E_BOUNDS) == 0xb && sgpu_guest_iogpu_status(SGPU_E_ACCESS) == 0xb &&
          sgpu_guest_iogpu_status(SGPU_E_MEMORY) == 0xb);
    CHECK(sgpu_guest_iogpu_status(SGPU_E_FORMAT) == 0xa && sgpu_guest_iogpu_status(SGPU_E_UNSUPPORTED) == 0xa &&
          sgpu_guest_iogpu_status(SGPU_E_SKIPPED) == 0xa && sgpu_guest_iogpu_status(-1000) == 0xa);
    int32_t seg[4] = { SGPU_OK, SGPU_E_SKIPPED, SGPU_E_BOUNDS, SGPU_E_COMPILE };
    CHECK(sgpu_guest_first_failure(seg, 4) == SGPU_E_BOUNDS && sgpu_guest_first_failure(seg, 2) == SGPU_OK);
}

/* ---- adreno_kernel_command routes 0x1010 ---- */
static int fences, ibs, streams;
static const void *seen;
static uint64_t seen_bytes;
static int op_fence(void *c) { (void)c; fences++; return 0; }
static int op_ib(void *c, const void *p, uint64_t b) { (void)c; (void)p; (void)b; ibs++; return 0; }
static int op_stream(void *c, const void *p, uint64_t b) { (void)c; seen = p; seen_bytes = b; streams++; return SGPU_E_LOST; }
static void test_dispatch(void)
{
    uint8_t c[96];
    mkcmd(c, 64, 1);
    const struct adreno_kernel_ops with = { 0, op_fence, 0, op_ib, op_stream };
    const struct adreno_kernel_ops without = { 0, op_fence, 0, op_ib };                /* the existing initializer shape */
    CHECK(adreno_kernel_command(c, sizeof c, &with) == SGPU_E_LOST);
    CHECK(streams == 1 && seen == c && seen_bytes == sizeof c && fences == 0 && ibs == 0);
    CHECK(adreno_kernel_command(c, sizeof c, &without) == ADRENO_SUBMIT_E_COMMAND);    /* unchanged without the op */
    struct adreno_submit_header f = { ADRENO_KCMD_FENCE, 8 };
    CHECK(adreno_kernel_command(&f, 8, &with) == 0 && fences == 1 && streams == 1);
    struct adreno_submit_header g = { ADRENO_KCMD_IOGPU_TIMESTAMP, 8 };
    CHECK(adreno_kernel_command(&g, 8, &with) == ADRENO_SUBMIT_GENERIC);
    uint32_t u[8] = { 0x1011, 32 };
    CHECK(adreno_kernel_command(u, sizeof u, &with) == ADRENO_SUBMIT_E_COMMAND && streams == 1);
}


/* ---- the W2 audit fixes (plans/p6-w2-fixes.md), as far as they are decisions in compat/softgpu-guest.c ---- */
/* 1. A map's object is retired by whatever unpins its backing: after the take the stream finds no id (so it creates a
 *    new object over the new pages) and the old id goes to the DESTROY queue exactly once. */
static void test_obj_retire(void)
{
    struct sgpu_guest_obj o = {0};
    uint64_t epoch = 0;
    CHECK(sgpu_guest_obj_get(&o, 7) == 0 && sgpu_guest_obj_take(&o, &epoch) == 0);
    sgpu_guest_obj_set(&o, 42, 7);
    CHECK(sgpu_guest_obj_get(&o, 7) == 42);
    CHECK(sgpu_guest_obj_get(&o, 8) == 0);                              /* another epoch: forgotten by a reset */
    /* backing swap: unpin -> take; a stream after it must not bind id 42 */
    CHECK(sgpu_guest_obj_take(&o, &epoch) == 42 && epoch == 7);
    CHECK(sgpu_guest_obj_get(&o, 7) == 0);
    CHECK(sgpu_guest_obj_take(&o, &epoch) == 0);                        /* a second unpin queues nothing */
    sgpu_guest_obj_set(&o, 43, 7);                                      /* the new pages get a new object */
    CHECK(sgpu_guest_obj_get(&o, 7) == 43);
}
/* 2, 6. DESTROY failures stay out of streams; device statuses stay in range; host codes do not leak. */
static void test_results(void)
{
    CHECK(sgpu_guest_housekeeping_result(0) == 0);
    CHECK(sgpu_guest_housekeeping_result(SGPU_E_OBJECT) == 0 && sgpu_guest_housekeeping_result(SGPU_E_FORMAT) == 0);
    CHECK(sgpu_guest_housekeeping_result(SGPU_E_QUOTA) == 0 && sgpu_guest_housekeeping_result(SGPU_GUEST_BUSY) == 0);
    CHECK(sgpu_guest_housekeeping_result(SGPU_E_LOST) == SGPU_E_LOST && sgpu_guest_housekeeping_result(SGPU_E_TIMEOUT) == SGPU_E_LOST);
    CHECK(sgpu_guest_housekeeping_result(SGPU_GUEST_E_RECORD) == SGPU_E_LOST);
    CHECK(sgpu_guest_device_status(0) == 0 && sgpu_guest_device_status(SGPU_E_SKIPPED) == SGPU_E_SKIPPED);
    CHECK(sgpu_guest_device_status(SGPU_E_FORMAT) == SGPU_E_FORMAT && sgpu_guest_device_status(SGPU_E_LOST) == SGPU_E_LOST);
    CHECK(sgpu_guest_device_status(1) == SGPU_E_HOST && sgpu_guest_device_status(0x7fffffff) == SGPU_E_HOST);
    CHECK(sgpu_guest_device_status(-16) == SGPU_E_HOST && sgpu_guest_device_status(-92) == SGPU_E_HOST);
    CHECK(sgpu_guest_device_status((int32_t)0x80000000) == SGPU_E_HOST);
    /* 1 would be ADRENO_SUBMIT_GENERIC at objects.cpp: IOGPU would run the command natively */
    CHECK(sgpu_guest_public_result(sgpu_guest_device_status(ADRENO_SUBMIT_GENERIC)) != ADRENO_SUBMIT_GENERIC);
    CHECK(sgpu_guest_public_result(SGPU_GUEST_BUSY) == SGPU_E_QUOTA && sgpu_guest_public_result(SGPU_GUEST_E_RECORD) == SGPU_E_LOST);
    CHECK(sgpu_guest_public_result(0) == 0 && sgpu_guest_public_result(SGPU_E_TIMEOUT) == SGPU_E_TIMEOUT);
    CHECK(sgpu_guest_public_result(ADRENO_SUBMIT_E_UNCERTAIN) == ADRENO_SUBMIT_E_UNCERTAIN);
    CHECK(sgpu_guest_public_result(ADRENO_SUBMIT_E_INACTIVE) == ADRENO_SUBMIT_E_INACTIVE);
    /* 3. an unconfirmed reset never reports the device lost (IOGPU would unpin pages it may still write) */
    CHECK(sgpu_guest_reset_result(SGPU_E_LOST, 1) == SGPU_E_LOST);
    CHECK(sgpu_guest_reset_result(SGPU_E_LOST, 0) == ADRENO_SUBMIT_E_UNCERTAIN);
    CHECK(sgpu_guest_reset_result(ADRENO_SUBMIT_E_UNCERTAIN, 1) == ADRENO_SUBMIT_E_UNCERTAIN);
}
/* 4. the run pool and the distinct-map set */
static void test_pool(void)
{
    uint32_t cap = 0, steps = 0;
    while ((cap = sgpu_guest_pool_grow(cap))) { steps++; CHECK(cap >= 64 && cap <= SGPU_GUEST_POOL_MAX_RUNS); }
    CHECK(steps == 11 && sgpu_guest_pool_grow(SGPU_GUEST_POOL_MAX_RUNS) == 0);   /* 64, 128 ... 65536 */
    CHECK(sgpu_guest_pool_grow(0) == 64 && sgpu_guest_pool_grow(64) == 128 && sgpu_guest_pool_grow(40000) == SGPU_GUEST_POOL_MAX_RUNS);
    CHECK(sgpu_guest_set_slots(0) == 16 && sgpu_guest_set_slots(8) == 16 && sgpu_guest_set_slots(9) == 32);
    CHECK(sgpu_guest_set_slots(65535) == 131072);
    /* a list of 65535 entries naming 3 distinct maps captures 3 map's runs, not 65535 */
    const uint32_t slots = sgpu_guest_set_slots(65535);
    uint64_t *tab = calloc(slots, sizeof *tab);
    uint64_t maps[3] = { 0xffffff8000100000ull, 0xffffff8000100100ull, 0xffffff8000200000ull };
    unsigned captured = 0;
    for (unsigned i = 0; i < 65535; i++) {
        int r = sgpu_guest_set_add(tab, slots, maps[i % 3]);
        CHECK(r == 0 || r == 1);
        captured += r == 1;
    }
    CHECK(captured == 3);
    free(tab);
    /* every distinct key of a full-size list is accepted, once */
    tab = calloc(slots, sizeof *tab);
    for (unsigned i = 0; i < 65535; i++) CHECK(sgpu_guest_set_add(tab, slots, 0xffffff8000000000ull + (uint64_t)i * 0x40) == 1);
    for (unsigned i = 0; i < 65535; i++) CHECK(sgpu_guest_set_add(tab, slots, 0xffffff8000000000ull + (uint64_t)i * 0x40) == 0);
    free(tab);
    uint64_t small[16] = {0};
    for (unsigned i = 1; i <= 16; i++) CHECK(sgpu_guest_set_add(small, 16, i * 16) == 1);
    CHECK(sgpu_guest_set_add(small, 16, 17 * 16) == SGPU_E_QUOTA && sgpu_guest_set_add(small, 16, 16) == 0);
    CHECK(sgpu_guest_set_add(small, 16, 0) == SGPU_E_FORMAT && sgpu_guest_set_add(small, 12, 5) == SGPU_E_FORMAT);
}
/* 8. the self-test target must lie inside the panel */
static void test_range(void)
{
    const uint64_t base = 0xbd000000ull, len = 2880ull * 1800 * 4;
    CHECK(sgpu_guest_range_inside(base, PANEL_ROWS_BYTES, base, len));
    CHECK(sgpu_guest_range_inside(base + len - 64, 64, base, len) && sgpu_guest_range_inside(base, len, base, len));
    CHECK(!sgpu_guest_range_inside(base + len - 63, 64, base, len) && !sgpu_guest_range_inside(base, len + 1, base, len));
    CHECK(!sgpu_guest_range_inside(base - 1, 16, base, len) && !sgpu_guest_range_inside(base + len, 1, base, len));
    CHECK(!sgpu_guest_range_inside(base, 0, base, len));
    CHECK(!sgpu_guest_range_inside(0xfffffffffffff000ull, 0x2000, 0xfffffffffffff000ull, 0x1000));    /* no overflow */
    CHECK(!sgpu_guest_range_inside(base, ~0ull, base, len) && !sgpu_guest_range_inside(0, 16, base, len));
}
/* 2, 5. A stream of 300 new maps: each CREATE completes before the next (so a device refusal never records an id and
 * the ring never fills); a SUBMIT meeting a full ring drains and retries instead of leaking SGPU_GUEST_BUSY. */
static void test_create_flow(void)
{
    static struct sgpu_desc slots[SGPU_GUEST_RING_ENTRIES];
    struct sgpu_guest_ring r;
    struct sgpu_guest_arena arena;
    struct model m = {0};
    struct sgpu_desc d;
    int32_t st[SGPU_GUEST_RING_ENTRIES];
    m.arena = calloc(1, SGPU_GUEST_ARENA_BYTES);
    m.arena_size = SGPU_GUEST_ARENA_BYTES;
    m.next_seqno = 1;
    CHECK(sgpu_guest_ring_init(&r, slots, SGPU_GUEST_RING_ENTRIES) == 0);
    sgpu_guest_arena_init(&arena, SGPU_GUEST_ARENA_BYTES);
    struct sgpu_mem_run run = { 0x80000000ull, 0x4000 };
    uint32_t recorded = 0, refused = 0;
    for (uint32_t id = 2; id < 302; id++) {
        uint64_t off;
        CHECK(sgpu_guest_arena_alloc(&arena, 64, r.next_seqno, &off) == 0);
        /* every 7th object is refused by the device: size 0 is a malformed CREATE the validator rejects */
        int bad = id % 7 == 0;
        int len = sgpu_guest_pkt_create_memory(m.arena + off, 64, id, 0, 0x4000, 0, 0, &run, 1);
        CHECK(len == 64);
        if (bad) m.arena[off + 2] = 2;                                   /* undefined packet flag */
        sgpu_guest_desc_kernel(&d, 0, off, 64, SGPU_GUEST_NO_STAMP, 0);
        CHECK(sgpu_guest_ring_push(&r, &d) != 0);
        int dev = device_run(&m, &r, r.produced);
        CHECK(retire_all(&r, &m, &arena, st) == 1);
        CHECK((st[0] != 0) == bad && (dev != 0) == bad);
        if (!st[0]) recorded++; else refused++;                          /* the id is recorded only on a completed OK */
    }
    CHECK(recorded + refused == 300 && refused == 43 && recorded == 257);
    CHECK(r.retired == r.produced && arena.used == 0);
    /* a full ring at SUBMIT time: push says busy, a drain frees it, the retry takes it */
    sgpu_guest_desc_kernel(&d, 0, 0, 0, SGPU_GUEST_NO_STAMP, 0);
    while (sgpu_guest_ring_free(&r)) CHECK(sgpu_guest_ring_push(&r, &d) != 0);
    CHECK(sgpu_guest_ring_push(&r, &d) == 0);                            /* sgPush -> SGPU_GUEST_BUSY */
    CHECK(sgpu_guest_public_result(SGPU_GUEST_BUSY) == SGPU_E_QUOTA);    /* what used to reach IOGPU as 0xa */
    CHECK(retire_all(&r, &m, &arena, 0) == 0);                           /* nothing executed yet: still full */
    device_run(&m, &r, r.produced);
    CHECK(retire_all(&r, &m, &arena, st) == SGPU_GUEST_RING_ENTRIES);
    CHECK(sgpu_guest_ring_push(&r, &d) != 0);
    free(m.arena);
}

/* ---- a long mixed run: descriptors of every kind through ring, arena and device model, wrapping both ---- */
static void test_soak(void)
{
    static struct sgpu_desc slots[SGPU_GUEST_RING_ENTRIES];
    struct sgpu_guest_ring r;
    struct sgpu_guest_arena a;
    struct model m = {0};
    struct sgpu_val_err err;
    m.arena = calloc(1, SGPU_GUEST_ARENA_BYTES);
    m.arena_size = SGPU_GUEST_ARENA_BYTES;
    m.next_seqno = 1;
    sgpu_guest_ring_init(&r, slots, 64);
    sgpu_guest_arena_init(&a, SGPU_GUEST_ARENA_BYTES);
    uint64_t submitted = 0;
    srand(11);
    for (int i = 0; i < 6000; i++) {
        uint32_t bt_count = (uint32_t)(rand() % 6), sbytes = 40 * (1 + rand() % 40);
        uint64_t total = (uint64_t)sbytes + 32ull * bt_count, off;
        int rc = sgpu_guest_arena_alloc(&a, total * (1 + rand() % 50), r.next_seqno, &off);   /* some are large */
        if (rc == 0 && !sgpu_guest_ring_free(&r)) {                                    /* ring full: undo is the retire below */
            rc = SGPU_GUEST_BUSY;
        }
        if (rc) {
            CHECK(rc == SGPU_GUEST_BUSY);
            CHECK(device_run(&m, &r, r.produced) == 0);
            retire_all(&r, &m, &a, 0);
            continue;
        }
        uint8_t *p = m.arena + off;
        for (uint32_t k = 0; k < sbytes / 40; k++) sgpu_guest_pkt_fill_buffer(p + 40 * k, 40, rand() % (bt_count ? bt_count : 1), 0, 8, 1);
        struct sgpu_guest_bt_in in[6];
        for (uint32_t k = 0; k < bt_count; k++) { in[k].mem_id = 1 + k; in[k].usage = ADRENO_USAGE_WRITE; in[k].read_only = 0;
                                                  in[k].offset = 0; in[k].length = 8; in[k].resource_id = k; }
        sgpu_guest_bt_build((struct sgpu_bt_entry *)(p + sbytes), in, bt_count);
        struct sgpu_desc d;
        if (!bt_count) {                                                               /* no BT: FILL_BUFFER would be refused */
            sgpu_guest_pkt_stamp(p, 16, 1, (uint32_t)i); sgpu_guest_desc_kernel(&d, 0, off, 16, 3, (uint32_t)i);
        } else
            sgpu_guest_desc_submit(&d, 1, 1 + i % 9, i % 3 ? 0 : SGPU_DESC_LAST, off, sbytes, off + sbytes, bt_count, 2, (uint32_t)i, 0, 0);
        CHECK(sgpu_guest_ring_push(&r, &d) != 0);
        submitted++;
        if (i % 7 == 0) { CHECK(device_run(&m, &r, r.produced) == 0); retire_all(&r, &m, &a, 0); }
    }
    CHECK(device_run(&m, &r, r.produced) == 0);
    retire_all(&r, &m, &a, 0);
    CHECK(m.kernels + m.submits == submitted && r.retired == r.produced && a.used == 0);
    (void)err;
    free(m.arena);
}

int main(void)
{
    test_bringup_selftest();
    test_ring();
    test_arena();
    test_bt();
    test_kcmd();
    test_status();
    test_obj_retire();
    test_results();
    test_pool();
    test_range();
    test_create_flow();
    test_dispatch();
    test_soak();
    printf("test-softgpu-guest: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
