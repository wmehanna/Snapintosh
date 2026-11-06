/* SPDX-License-Identifier: MIT */
/* Guest side of the SoftGPU transport (softgpu/SOFTGPU-PROTOCOL.md rev 6, plans/p6-softgpu-integration.md W2): the
 * descriptor ring, the arena allocator, KERNEL packet and binding-table builders, the 0x1010 kernel-command header
 * check and the completion mapping. Pure C, no allocation, no register access: the kext (AdrenoX2/softgpu.cpp) owns
 * every buffer and the MMIO; tools/test-softgpu-guest.c runs every byte emitted here through libsgpu's validator.
 * softgpu_protocol.h is a verbatim copy of the device's wire header (p6d include/); change both together. */
#pragma once
#include "softgpu_protocol.h"

#define SOFTGPU_KCMD_STREAM 0x1010u            /* adreno_submit_header.type of struct sgpu_kcmd_stream */
#define SGPU_GUEST_RING_ENTRIES 256u           /* RING_ENTRIES the kext programs (1.9) */
#define SGPU_GUEST_ARENA_BYTES 0x400000u       /* arena of this wave: 4 MiB (the spec's 16 MiB is a later size) */
#define SGPU_GUEST_NO_STAMP 0xffffffffu
#define SGPU_GUEST_PROBE_STAMP 128u            /* STAMP index of the start-time probe */
#define SGPU_GUEST_MAX_RUNS 65536u
/* Host-side only results of this file, outside the SGPU_E_* range. */
enum { SGPU_GUEST_BUSY = -100,                 /* ring or arena full: retire descriptors and retry */
       SGPU_GUEST_E_RECORD = -101 };           /* completion record does not match: RESET_DEVICE (1.5) */
/* IOGPU command-buffer status words (adreno-recover-guest.h) a descriptor result maps to (1.6). */
enum { SGPU_IOGPU_COMPLETED = 0, SGPU_IOGPU_HANG = 3, SGPU_IOGPU_VICTIM = 5, SGPU_IOGPU_INVALID = 0xa,
       SGPU_IOGPU_PAGE_FAULT = 0xb };

struct sgpu_guest_ring {
    struct sgpu_desc *slots;                   /* RING_BASE, `entries` of them */
    uint32_t entries;
    uint32_t produced, retired;                /* free-running; produced is the RING_TAIL value */
    uint64_t next_seqno;                       /* seqno of the next descriptor, first is 1 */
    uint64_t done_seqno;                       /* last seqno retire_one consumed */
};
#define SGPU_GUEST_FIFO 256u
struct sgpu_guest_arena {                      /* byte ring reclaimed in seqno order */
    uint64_t size, end, used;                  /* end: next allocation; used: live bytes incl. wrap waste */
    struct { uint64_t seqno, bytes; } fifo[SGPU_GUEST_FIFO];
    uint32_t head, count;
};
struct sgpu_guest_bt_in {                      /* one entry of IOGPU's segment resource list */
    uint32_t mem_id, usage;                    /* usage: ADRENO_USAGE_* bits */
    uint32_t read_only;                        /* backing direction is Out: never WRITE */
    uint64_t offset, length, resource_id;
};

#ifdef __cplusplus
extern "C" {
#endif
/* ---- ring (1.5) ---- */
int sgpu_guest_ring_init(struct sgpu_guest_ring *, struct sgpu_desc *slots, uint32_t entries);   /* 0 or SGPU_E_FORMAT */
void sgpu_guest_ring_reset(struct sgpu_guest_ring *);       /* after RESET_DEVICE: counters and slots to zero */
uint32_t sgpu_guest_ring_free(const struct sgpu_guest_ring *);
/* Copy d into the next slot with the next seqno; returns it, or 0 when `produced - retired == entries`. The caller
 * then issues dsb st and writes RING_TAIL = r->produced. */
uint64_t sgpu_guest_ring_push(struct sgpu_guest_ring *, const struct sgpu_desc *d);
/* Consume the next completion if done_seqno covers it: 1 and *out, 0 when none is due, SGPU_GUEST_E_RECORD when
 * rec[slot].seqno is not the expected one (nothing is consumed). rec is the status page's record array. */
int sgpu_guest_ring_retire_one(struct sgpu_guest_ring *, const struct sgpu_completion *rec, uint64_t done_seqno,
                               struct sgpu_completion *out);
/* ---- arena ---- */
void sgpu_guest_arena_init(struct sgpu_guest_arena *, uint64_t size);
/* 8-aligned contiguous block for descriptor `seqno` (seqnos nondecreasing): 0 and *offset, SGPU_GUEST_BUSY, or
 * SGPU_E_QUOTA when bytes can never fit. bytes 0 reserves 8. */
int sgpu_guest_arena_alloc(struct sgpu_guest_arena *, uint64_t bytes, uint64_t seqno, uint64_t *offset);
void sgpu_guest_arena_release(struct sgpu_guest_arena *, uint64_t done_seqno);   /* frees seqno <= done */
/* ---- KERNEL packets: bytes written, or SGPU_E_BOUNDS (cap too small) / SGPU_E_FORMAT ---- */
int sgpu_guest_runs_add(struct sgpu_mem_run *runs, uint32_t *n, uint32_t cap, uint64_t gpa, uint64_t bytes);   /* coalesces */
int sgpu_guest_pkt_create_context(void *buf, uint32_t cap, uint32_t ctx_id);
int sgpu_guest_pkt_destroy_context(void *buf, uint32_t cap, uint32_t ctx_id);
int sgpu_guest_pkt_create_memory(void *buf, uint32_t cap, uint32_t mem_id, uint32_t flags, uint64_t size,
                                 uint64_t gpu_va, uint32_t head, const struct sgpu_mem_run *runs, uint32_t nruns);
int sgpu_guest_pkt_destroy_memory(void *buf, uint32_t cap, uint32_t mem_id);
int sgpu_guest_pkt_stamp(void *buf, uint32_t cap, uint32_t index, uint32_t value);
/* A user packet, for the self-test. */
int sgpu_guest_pkt_fill_buffer(void *buf, uint32_t cap, uint32_t bt, uint64_t offset, uint64_t bytes, uint32_t value);
/* ---- descriptors (seqno is assigned by sgpu_guest_ring_push) ---- */
void sgpu_guest_desc_kernel(struct sgpu_desc *, uint16_t flags, uint64_t stream_offset, uint32_t stream_bytes,
                            uint32_t stamp_index, uint32_t stamp_value);
void sgpu_guest_desc_submit(struct sgpu_desc *, uint32_t ctx_id, uint32_t cb_id, uint16_t flags, uint64_t stream_offset,
                            uint32_t stream_bytes, uint64_t bt_offset, uint32_t bt_count, uint32_t stamp_index,
                            uint32_t stamp_value, uint32_t budget_ms, uint64_t tag);
/* Binding table: entry i is list position i. access = usage (READ or SAMPLE read, WRITE write) minus WRITE on a
 * read-only backing; an entry left with no access is READ. SGPU_E_FORMAT when mem_id is 0. */
int sgpu_guest_bt_build(struct sgpu_bt_entry *out, const struct sgpu_guest_bt_in *in, uint32_t n);
/* ---- ADRENO_KCMD 0x1010 (1.5) ---- */
/* Check the 32-byte header of a command IOGPU hands over (read once, volatile) against `epoch`. 0 with *stream and
 * *stream_bytes set; SGPU_E_FORMAT; SGPU_E_LOST when the command's epoch is not the current one. */
int sgpu_guest_kcmd_stream(const void *command, uint64_t available, uint64_t epoch, const uint8_t **stream,
                           uint32_t *stream_bytes);
/* Table of 1.6: the IOGPU status word of a descriptor result (SGPU_E_SKIPPED never maps alone: INVALID). */
uint32_t sgpu_guest_iogpu_status(int32_t sgpu_status);
/* Command-buffer result of its segments (1.5): the first that is neither OK nor SKIPPED, else OK. */
int32_t sgpu_guest_first_failure(const int32_t *status, uint32_t n);
#ifdef __cplusplus
}
#endif
