/* SPDX-License-Identifier: MIT */
/* See softgpu-guest.h. Little endian only (the descriptors are written in place). */
#include <string.h>
#include "softgpu-guest.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the SoftGPU wire format is little endian"
#endif

int sgpu_guest_ring_init(struct sgpu_guest_ring *r, struct sgpu_desc *slots, uint32_t entries)
{
    if (!r || !slots || entries < 16 || entries > SGPU_GUEST_RING_ENTRIES || (entries & (entries - 1)))
        return SGPU_E_FORMAT;
    r->slots = slots;
    r->entries = entries;
    sgpu_guest_ring_reset(r);
    return 0;
}
void sgpu_guest_ring_reset(struct sgpu_guest_ring *r)
{
    memset(r->slots, 0, (size_t)r->entries * sizeof *r->slots);
    r->produced = r->retired = 0;
    r->next_seqno = 1;
    r->done_seqno = 0;
}
uint32_t sgpu_guest_ring_free(const struct sgpu_guest_ring *r)
{
    return r->entries - (r->produced - r->retired);
}
uint64_t sgpu_guest_ring_push(struct sgpu_guest_ring *r, const struct sgpu_desc *d)
{
    if (!sgpu_guest_ring_free(r)) return 0;
    struct sgpu_desc *slot = &r->slots[r->produced % r->entries];
    *slot = *d;
    slot->seqno = r->next_seqno;
    r->produced++;
    return r->next_seqno++;
}
int sgpu_guest_ring_retire_one(struct sgpu_guest_ring *r, const struct sgpu_completion *rec, uint64_t done_seqno,
                               struct sgpu_completion *out)
{
    if (r->retired == r->produced) return 0;
    const uint64_t expect = r->done_seqno + 1;
    if (expect > done_seqno) return 0;
    const struct sgpu_completion *c = &rec[r->retired % r->entries];
    uint64_t seq = ((const volatile struct sgpu_completion *)c)->seqno;
    if (seq != expect) return SGPU_GUEST_E_RECORD;
    out->seqno = seq;
    out->status = ((const volatile struct sgpu_completion *)c)->status;
    out->packet_offset = ((const volatile struct sgpu_completion *)c)->packet_offset;
    r->retired++;
    r->done_seqno = expect;
    return 1;
}

void sgpu_guest_arena_init(struct sgpu_guest_arena *a, uint64_t size)
{
    memset(a, 0, sizeof *a);
    a->size = size & ~7ull;
}
int sgpu_guest_arena_alloc(struct sgpu_guest_arena *a, uint64_t bytes, uint64_t seqno, uint64_t *offset)
{
    if (bytes > a->size - 8) return SGPU_E_QUOTA;
    bytes = bytes ? (bytes + 7) & ~7ull : 8;
    if (a->count == SGPU_GUEST_FIFO) return SGPU_GUEST_BUSY;
    if (!a->used) a->end = 0;                          /* empty: start over, the longest run is free */
    const int wrap = a->end + bytes > a->size;         /* the block does not fit before the end: it starts at 0 */
    uint64_t waste = wrap ? a->size - a->end : 0;
    if (a->size - a->used < waste + bytes) return SGPU_GUEST_BUSY;
    *offset = wrap ? 0 : a->end;
    a->end = *offset + bytes;
    a->used += waste + bytes;
    uint32_t at = (a->head + a->count++) % SGPU_GUEST_FIFO;
    a->fifo[at].seqno = seqno;
    a->fifo[at].bytes = waste + bytes;
    return 0;
}
void sgpu_guest_arena_release(struct sgpu_guest_arena *a, uint64_t done_seqno)
{
    while (a->count && a->fifo[a->head].seqno <= done_seqno) {
        a->used -= a->fifo[a->head].bytes;
        a->head = (a->head + 1) % SGPU_GUEST_FIFO;
        a->count--;
    }
}

static struct sgpu_pkt *pkt(void *buf, uint32_t cap, uint32_t bytes, uint16_t opcode)
{
    if (!buf || cap < bytes) return 0;
    memset(buf, 0, bytes);
    struct sgpu_pkt *h = buf;
    h->opcode = opcode;
    h->size = bytes;
    return h;
}
int sgpu_guest_runs_add(struct sgpu_mem_run *runs, uint32_t *n, uint32_t cap, uint64_t gpa, uint64_t bytes)
{
    if (!bytes || ((gpa | bytes) & 0xfff) || gpa + bytes < gpa) return SGPU_E_FORMAT;
    if (*n && runs[*n - 1].gpa + runs[*n - 1].bytes == gpa) { runs[*n - 1].bytes += bytes; return 0; }
    if (*n >= cap) return SGPU_E_BOUNDS;
    runs[*n].gpa = gpa;
    runs[*n].bytes = bytes;
    (*n)++;
    return 0;
}
int sgpu_guest_pkt_create_context(void *buf, uint32_t cap, uint32_t ctx_id)
{
    struct sgpu_create_context *p = (struct sgpu_create_context *)pkt(buf, cap, sizeof *p, SGPU_OP_CREATE_CONTEXT);
    if (!p) return SGPU_E_BOUNDS;
    p->ctx_id = ctx_id;
    return sizeof *p;
}
int sgpu_guest_pkt_destroy_context(void *buf, uint32_t cap, uint32_t ctx_id)
{
    struct sgpu_destroy_context *p = (struct sgpu_destroy_context *)pkt(buf, cap, sizeof *p, SGPU_OP_DESTROY_CONTEXT);
    if (!p) return SGPU_E_BOUNDS;
    p->ctx_id = ctx_id;
    return sizeof *p;
}
int sgpu_guest_pkt_create_memory(void *buf, uint32_t cap, uint32_t mem_id, uint32_t flags, uint64_t size,
                                 uint64_t gpu_va, uint32_t head, const struct sgpu_mem_run *runs, uint32_t nruns)
{
    if (!mem_id || !size || size > 1ull << 32 || head > 16383 || !nruns || nruns > SGPU_GUEST_MAX_RUNS || !runs)
        return SGPU_E_FORMAT;
    const uint32_t bytes = sizeof(struct sgpu_create_memory) + nruns * (uint32_t)sizeof *runs;
    struct sgpu_create_memory *p = (struct sgpu_create_memory *)pkt(buf, cap, bytes, SGPU_OP_CREATE_MEMORY);
    if (!p) return SGPU_E_BOUNDS;
    p->mem_id = mem_id;
    p->flags = flags;
    p->size = size;
    p->gpu_va = gpu_va;
    p->head = head;
    p->run_count = nruns;
    memcpy((uint8_t *)buf + sizeof *p, runs, (size_t)nruns * sizeof *runs);
    return (int)bytes;
}
int sgpu_guest_pkt_destroy_memory(void *buf, uint32_t cap, uint32_t mem_id)
{
    struct sgpu_destroy_memory *p = (struct sgpu_destroy_memory *)pkt(buf, cap, sizeof *p, SGPU_OP_DESTROY_MEMORY);
    if (!p) return SGPU_E_BOUNDS;
    p->mem_id = mem_id;
    return sizeof *p;
}
int sgpu_guest_pkt_stamp(void *buf, uint32_t cap, uint32_t index, uint32_t value)
{
    struct sgpu_stamp *p = (struct sgpu_stamp *)pkt(buf, cap, sizeof *p, SGPU_OP_STAMP);
    if (!p) return SGPU_E_BOUNDS;
    p->index = index;
    p->value = value;
    return sizeof *p;
}
int sgpu_guest_pkt_fill_buffer(void *buf, uint32_t cap, uint32_t bt, uint64_t offset, uint64_t bytes, uint32_t value)
{
    struct sgpu_fill_buffer *p = (struct sgpu_fill_buffer *)pkt(buf, cap, sizeof *p, SGPU_OP_FILL_BUFFER);
    if (!p) return SGPU_E_BOUNDS;
    p->dst.bt = bt;
    p->dst.offset = offset;
    p->bytes = bytes;
    p->value = value;
    return sizeof *p;
}

void sgpu_guest_desc_kernel(struct sgpu_desc *d, uint16_t flags, uint64_t stream_offset, uint32_t stream_bytes,
                            uint32_t stamp_index, uint32_t stamp_value)
{
    memset(d, 0, sizeof *d);
    d->type = SGPU_DESC_KERNEL;
    d->flags = flags;
    d->stream_offset = stream_offset;
    d->stream_bytes = stream_bytes;
    d->stamp_index = stamp_index;
    d->stamp_value = stamp_value;
}
void sgpu_guest_desc_submit(struct sgpu_desc *d, uint32_t ctx_id, uint32_t cb_id, uint16_t flags, uint64_t stream_offset,
                            uint32_t stream_bytes, uint64_t bt_offset, uint32_t bt_count, uint32_t stamp_index,
                            uint32_t stamp_value, uint32_t budget_ms, uint64_t tag)
{
    memset(d, 0, sizeof *d);
    d->type = SGPU_DESC_SUBMIT;
    d->flags = flags;
    d->ctx_id = ctx_id;
    d->stream_offset = stream_offset;
    d->stream_bytes = stream_bytes;
    d->bt_count = bt_count;
    d->bt_offset = bt_offset;
    d->stamp_index = stamp_index;
    d->stamp_value = stamp_value;
    d->budget_ms = budget_ms;
    d->cb_id = cb_id;
    d->tag = tag;
}
int sgpu_guest_bt_build(struct sgpu_bt_entry *out, const struct sgpu_guest_bt_in *in, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (!in[i].mem_id) return SGPU_E_FORMAT;
        uint32_t access = 0;
        if (in[i].usage & 5u) access |= SGPU_ACCESS_READ;            /* ADRENO_USAGE_READ | ADRENO_USAGE_SAMPLE */
        if ((in[i].usage & 2u) && !in[i].read_only) access |= SGPU_ACCESS_WRITE;
        out[i].mem_id = in[i].mem_id;
        out[i].access = access ? access : SGPU_ACCESS_READ;
        out[i].offset = in[i].offset;
        out[i].length = in[i].length;
        out[i].resource_id = in[i].resource_id;
    }
    return 0;
}

int sgpu_guest_kcmd_stream(const void *command, uint64_t available, uint64_t epoch, const uint8_t **stream,
                           uint32_t *stream_bytes)
{
    struct sgpu_kcmd_stream h;
    if (!command || available < sizeof h) return SGPU_E_FORMAT;
    const volatile uint8_t *src = command;
    uint8_t *dst = (uint8_t *)&h;
    for (unsigned i = 0; i < sizeof h; i++) dst[i] = src[i];
    if (h.type != SOFTGPU_KCMD_STREAM || h.version != 1 || h.flags || h.reserved0 || (h.stream_bytes & 7) ||
        h.stream_bytes > SGPU_MAX_STREAM_BYTES || h.size != sizeof h + h.stream_bytes || h.size > available)
        return SGPU_E_FORMAT;
    if (h.epoch != epoch) return SGPU_E_LOST;
    *stream = (const uint8_t *)command + sizeof h;
    *stream_bytes = h.stream_bytes;
    return 0;
}
uint32_t sgpu_guest_iogpu_status(int32_t s)
{
    switch (s) {
    case SGPU_OK: return SGPU_IOGPU_COMPLETED;
    case SGPU_E_TIMEOUT: return SGPU_IOGPU_HANG;
    case SGPU_E_RESET: case SGPU_E_LOST: return SGPU_IOGPU_VICTIM;
    case SGPU_E_BOUNDS: case SGPU_E_ACCESS: case SGPU_E_MEMORY: return SGPU_IOGPU_PAGE_FAULT;
    }
    return SGPU_IOGPU_INVALID;
}
int32_t sgpu_guest_first_failure(const int32_t *status, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++)
        if (status[i] != SGPU_OK && status[i] != SGPU_E_SKIPPED) return status[i];
    return SGPU_OK;
}
