/* SPDX-License-Identifier: MIT */
/* softgpu_protocol.h - SoftGPU wire structures and constants (SOFTGPU-PROTOCOL.md revision 4).
 * Structs are copied verbatim from softgpu-wire-test.c; change both together. Plain C11, C++ ok. */
#ifndef SOFTGPU_PROTOCOL_H
#define SOFTGPU_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
#define SGPU_SA static_assert
#else
#define SGPU_SA _Static_assert
#endif
struct sgpu_window {               /* 32 bytes, page 1 at 0x100 + 32 * i */
    uint64_t ipa_base;             /* 4 KiB aligned */
    uint64_t size;                 /* 4 KiB multiple, > 0 */
    uint64_t pa_base;              /* host-side guest physical address the IPA range maps to */
    uint32_t flags;                /* b0 READ, b1 WRITE */
    uint32_t reserved;
};

struct sgpu_status_head {          /* 64 bytes at status page offset 0 */
    uint64_t done_seqno;           /*  0  store-release, after everything it covers */
    uint32_t ring_head;            /*  8  mirror of RING_HEAD */
    uint32_t device_state;         /* 12  mirror of STATUS */
    uint64_t current_seqno;        /* 16  descriptor the worker is executing, 0 when idle */
    uint64_t current_start_ns;     /* 24  DEVICE_TIME it started plus the excluded wait time so far
                                          (compile waits, JIT; 1.7), refreshed every 50 ms while
                                          STATUS.WAIT is set, so now - current_start_ns is
                                          execution time only */
    uint64_t device_epoch;         /* 32  +1 on every RESET_DEVICE, FATAL recovery, QEMU reset (1.8) */
    uint64_t vblank_count;         /* 40 */
    uint64_t vblank_time_ns;       /* 48 */
    uint32_t present_done_id;      /* 56 */
    uint32_t presents_dropped;     /* 60 */
};

struct sgpu_completion {           /* 16 bytes, rec[slot] at status page offset 0x1000 */
    uint64_t seqno;
    int32_t  status;
    uint32_t packet_offset;
};

struct sgpu_device_info {          /* 256 bytes at status page offset 0x40 (review m10) */
    uint32_t protocol_version;     /*   0  == VERSION register */
    uint32_t features0, features1; /*   4  == FEATURES0/1 */
    uint32_t air2ir3_api;          /*  12  air2ir3_api_version() */
    uint32_t air2ir3_abi;          /*  16  air2ir3_abi_version() */
    uint32_t air2ir3_cache;        /*  20  air2ir3_cache_format_version() */
    uint32_t max_texture_2d;       /*  24  16384 */
    uint32_t max_threads_per_group;/*  28  1024 */
    uint32_t max_threadgroup_mem;  /*  32  32768 */
    uint32_t max_color_attach;     /*  36  8 */
    uint32_t max_samples;          /*  40  4 */
    uint32_t thread_execution_width;/* 44  llvmpipe native vector width / 32 (8 on this AVX2 host) */
    uint64_t max_buffer_bytes;     /*  48  4 GiB */
    uint32_t reserved0[2];         /*  56 */
    char     compiler_id[96];      /*  64  air2ir3_compiler_id(), NUL-terminated */
    char     host_renderer[64];    /* 160  e.g. "llvmpipe (LLVM 18, 256 bits)", NUL-terminated */
    uint8_t  reserved1[32];        /* 224 */
};

struct sgpu_fault {                /* 256 bytes at status page offset 0x400 */
    uint64_t seqno;                /*   0  the descriptor that failed */
    int32_t  status;              /*   8  SGPU_E_* */
    uint32_t opcode;               /*  12  the failing packet's opcode, or 0 */
    uint32_t packet_offset;        /*  16  its byte offset in the stream, or 0 */
    uint32_t detail;               /*  20  a code-specific number (bad index, bad bt, ...) */
    uint32_t ctx_id;               /*  24 */
    uint32_t pad;                  /*  28 */
    char     message[224];         /*  32  UTF-8, NUL-terminated */
};

struct sgpu_desc {                 /* 64 bytes */
    uint16_t type;                 /*  0  SGPU_DESC_SUBMIT 1, SGPU_DESC_KERNEL 2 */
    uint16_t flags;                /*  2  b0 IRQ, b1 reserved (was LONG; compiles left the ring, 4.3),
                                          b2 LAST (of a command buffer), b15 BOOTSTRAP (1.9) */
    uint32_t ctx_id;               /*  4  SUBMIT: context (>= 1); KERNEL: 0 */
    uint64_t seqno;                /*  8  strictly increasing by 1, first is 1 */
    uint64_t stream_offset;        /* 16  byte offset of the packet stream in memory object 1 (the arena), 8-aligned */
    uint32_t stream_bytes;         /* 24  multiple of 8, 0 .. 4 MiB */
    uint32_t bt_count;             /* 28  SUBMIT: binding-table entries, 0 .. 65535; KERNEL: 0 */
    uint64_t bt_offset;            /* 32  byte offset of the binding table in memory object 1, 8-aligned */
    uint32_t stamp_index;          /* 40  IOGPU stamp to write on completion, or 0xffffffff */
    uint32_t stamp_value;          /* 44  value to write */
    uint32_t budget_ms;            /* 48  0 = BUDGET_MS register */
    uint32_t cb_id;                /* 52  SUBMIT: the kext's per-context command-buffer serial, >= 1,
                                          equal in every segment of one command buffer (1.5); KERNEL: 0 */
    uint64_t tag;                  /* 56  kext cookie, echoed only in traces */
};

struct sgpu_bt_entry {             /* 32 bytes: one IOGPU resource of the command buffer */
    uint32_t mem_id;               /*  0  memory object (2.1) */
    uint32_t access;               /*  4  b0 READ, b1 WRITE */
    uint64_t offset;               /*  8  byte offset of the resource inside the memory object */
    uint64_t length;               /* 16  bytes the resource covers */
    uint64_t resource_id;          /* 24  IOGPU resource ID (diagnostics only) */
};

struct sgpu_kcmd_stream {          /* 32 bytes, then stream_bytes of packets */
    uint32_t type;                 /*  0  0x1010 (adreno_submit_header.type) */
    uint32_t size;                 /*  4  32 + stream_bytes */
    uint32_t version;              /*  8  1 */
    uint32_t flags;                /* 12  0 */
    uint32_t stream_bytes;         /* 16  multiple of 8, <= 4 MiB */
    uint32_t reserved0;            /* 20  0 */
    uint64_t epoch;                /* 24  device epoch the plug-in's objects belong to (1.8, 4.6) */
};

struct sgpu_mem_run { uint64_t gpa; uint64_t bytes; };   /* gpa and bytes multiples of 4096 */

struct sgpu_pkt {                  /* 8 bytes */
    uint16_t opcode;
    uint16_t flags;                /* b0 OPTIONAL: an unknown opcode is skipped instead of failing */
    uint32_t size;                 /* bytes including this header, multiple of 8, >= 8, <= remaining stream */
};

struct sgpu_ref { uint32_t bt; uint32_t reserved; uint64_t offset; };  /* 16 bytes */

struct sgpu_create_context { struct sgpu_pkt h; uint32_t ctx_id, flags; uint32_t max_objects, reserved; uint64_t max_host_bytes; }; /* 32 */
struct sgpu_destroy_context { struct sgpu_pkt h; uint32_t ctx_id, reserved; };                                                   /* 16 */

struct sgpu_create_memory {        /* 48 + 16 * run_count */
    struct sgpu_pkt h;
    uint32_t mem_id;               /* new, unused id >= 1 */
    uint32_t flags;                /* b0 ARENA (id 1 only), b1 DISPLAY, b2 READ_ONLY (no BT entry may grant WRITE) */
    uint64_t size;                 /* 1 .. 4 GiB */
    uint64_t gpu_va;               /* IOGPU VA of the map, diagnostics; 0 for arena/display */
    uint32_t head;                 /* 0 .. 16383 */
    uint32_t run_count;            /* 1 .. 65536 */
    uint64_t reserved;
    /* struct sgpu_mem_run runs[run_count] follows at offset 48 */
};
struct sgpu_destroy_memory { struct sgpu_pkt h; uint32_t mem_id, reserved; };   /* 16 */
struct sgpu_stamp { struct sgpu_pkt h; uint32_t index, value; };                /* 16, index < STAMP_COUNT */

struct sgpu_texdesc {              /* 64 bytes */
    uint32_t bt;                   /*  0  binding-table index of the backing resource */
    uint32_t storage_format;       /*  4  MTLPixelFormat of the allocation */
    uint16_t texture_type;         /*  8  MTLTextureType (2D 2, 2DArray 3, 2DMS 4, Cube 5, CubeArray 6, 3D 7, Buffer 9, 1D 0 ...) */
    uint16_t flags;                /* 10  b0 VIEW_SWIZZLE, b1 FRAMEBUFFER_ONLY (informational) */
    uint8_t  swizzle[4];           /* 12  MTLTextureSwizzle r,g,b,a (Zero 0, One 1, Red 2, Green 3, Blue 4, Alpha 5) */
    uint32_t width, height, depth; /* 16  level-0 size of the allocation */
    uint32_t array_length;         /* 28  slices in the allocation (cube: 6 per cube) */
    uint64_t offset;               /* 32  byte offset of level 0, slice 0, sample 0 inside the resource */
    uint32_t row_pitch0;           /* 40  bytes per row (per block row) of level 0 */
    uint32_t slice_pitch;          /* 44  bytes between slices; 0 = computed (layout rule below) */
    uint8_t  mip_levels;           /* 48  levels in the allocation, 1..15 */
    uint8_t  base_level;           /* 49  first level of this view */
    uint8_t  level_count;          /* 50  levels in this view */
    uint8_t  sample_count;         /* 51  1, 2 or 4 */
    uint16_t base_slice;           /* 52  first slice of this view */
    uint16_t slice_count;          /* 54  slices in this view */
    uint32_t view_format;          /* 56  MTLPixelFormat of the view (== storage_format if not a view) */
    uint32_t reserved;             /* 60 */
};

struct sgpu_upload_shader {        /* 72 + inline bytes */
    struct sgpu_pkt h;
    uint32_t lib_id;               /* context-local id of this AIR module */
    uint32_t flags;                /* b0 INLINE (bytes follow at offset 72), else BT reference */
    uint8_t  air_sha256[32];       /* SHA-256 of the AIR module bytes */
    uint64_t air_bytes;            /* 1 .. 16 MiB (AdrenoCompilerInput's bound) */
    struct sgpu_ref src;           /* when !INLINE: where the bytes are (READ access) */
};  /* inline bytes padded to 8 */

struct sgpu_fconst {               /* 48 bytes: air2ir3_constant on the wire */
    int32_t  index;                /* >= 0, or -1 when named */
    uint16_t name_off, name_len;   /* relative to the pipeline packet, when index == -1 */
    uint32_t num_values;           /* 1..4 */
    uint32_t data_type;            /* MTLDataType, informational */
    double   values[4];            /* bool 0/1; converted by air2ir3 to the declared type */
};

struct sgpu_stage {                /* 24 bytes */
    uint32_t lib_id;               /* 0 = stage absent (fragment only: rasterisation without FS) */
    uint16_t entry_off, entry_len; /* entry point name */
    uint32_t const_off, const_count;   /* struct sgpu_fconst[] */
    uint32_t reserved[2];
};

struct sgpu_blend {                /* 8 bytes, MTL enums: air2ir3_blend plus the write mask */
    uint8_t enabled, rgb_op, alpha_op, src_rgb, dst_rgb, src_alpha, dst_alpha, write_mask;
};

struct sgpu_vertex_attr   { uint32_t index, format, offset, buffer_index; };      /* MTLVertexFormat */
struct sgpu_vertex_layout { uint32_t buffer_index, stride, step_function, step_rate; };

struct sgpu_result_ref { uint32_t bt; uint32_t capacity; uint64_t offset; };     /* WRITE access, 8-aligned; capacity >= 256
                                                                                     (pipelines) or >= 32 (sampler, dss) */

struct sgpu_create_render_pipeline {
    struct sgpu_pkt h;
    uint32_t pipe_id;
    uint32_t flags;                /* b0 RASTER_DISABLED, b1 ALPHA_TO_COVERAGE, b2 ALPHA_TO_ONE, b3 WANT_REFLECTION */
    struct sgpu_result_ref result;
    struct sgpu_stage vs, fs;
    uint32_t color_format[8];      /* MTLPixelFormat, 0 = none */
    struct sgpu_blend blend[8];
    uint32_t depth_format, stencil_format;
    uint32_t sample_count;         /* 1, 2, 4 */
    uint32_t input_topology;       /* MTLPrimitiveTopologyClass */
    uint32_t attr_off, attr_count;     /* sgpu_vertex_attr[], 0..31 */
    uint32_t layout_off, layout_count; /* sgpu_vertex_layout[], 0..31 */
    uint32_t reserved[2];
};  /* fixed part 216 bytes, then the variable data */

struct sgpu_create_compute_pipeline {
    struct sgpu_pkt h;
    uint32_t pipe_id, flags;       /* b3 WANT_REFLECTION */
    struct sgpu_result_ref result;
    struct sgpu_stage cs;
    uint32_t max_total_threads;    /* descriptor's maxTotalThreadsPerThreadgroup, 0 = device max */
    uint32_t threadgroup_size_is_multiple; /* MTL descriptor flag */
    uint32_t reserved[2];
};  /* fixed part 72 bytes */

struct sgpu_create_sampler {       /* 56 */
    struct sgpu_pkt h;
    uint32_t sampler_id;
    uint32_t reserved0;
    struct sgpu_result_ref result;  /* 16  creation record, struct sgpu_result_head (4.3, 4.6) */
    uint8_t  min_filter, mag_filter, mip_filter, max_anisotropy;   /* 32  MTLSamplerMinMagFilter, MTLSamplerMipFilter */
    uint8_t  s, t, r, border_color;                                 /* 36  MTLSamplerAddressMode, MTLSamplerBorderColor */
    uint8_t  normalized, compare, lod_average, reserved1;           /* 40  compare: MTLCompareFunction */
    float    lod_min, lod_max;                                      /* 44 */
    uint32_t reserved2;                                             /* 52 */
};

struct sgpu_stencil_face { uint8_t fail, depth_fail, pass, compare; uint32_t read_mask, write_mask; };  /* 12 */
struct sgpu_create_depth_stencil { /* 56 */
    struct sgpu_pkt h;
    uint32_t dss_id;
    uint8_t  depth_compare, depth_write, front_enabled, back_enabled;
    struct sgpu_result_ref result;  /* 16  creation record, struct sgpu_result_head (4.3, 4.6) */
    struct sgpu_stencil_face front, back;   /* 32, 44 */
};

struct sgpu_destroy_object { struct sgpu_pkt h; uint32_t type, id; };   /* type: 1 shader lib, 2 pipeline, 3 sampler, 4 dss */

struct sgpu_attachment {           /* 96 bytes */
    struct sgpu_texdesc tex;       /* bt == 0xffffffff: attachment absent */
    uint32_t level, slice, depth_plane;
    uint8_t  load, store;          /* MTLLoadAction, MTLStoreAction */
    uint16_t reserved;
    uint32_t clear[4];             /* colour: raw bits of the clear value in the format's type (f32 x4 for
                                      float/unorm, u32/i32 x4 for integer); depth: f32 in clear[0];
                                      stencil: u32 in clear[0] */
};

struct sgpu_resolve {              /* 80 bytes */
    uint32_t which;                /* 0..7 colour, 8 depth, 9 stencil */
    uint32_t level, slice, depth_plane;
    struct sgpu_texdesc tex;
};

struct sgpu_begin_render_pass {
    struct sgpu_pkt h;
    uint32_t width, height;        /* render area (renderTargetWidth/Height or smallest attachment) */
    uint32_t layers;               /* renderTargetArrayLength, 1 = not layered */
    uint32_t default_samples;      /* defaultRasterSampleCount, for attachment-less passes */
    uint32_t color_count;          /* 0..8; colour attachments follow at offset 64 */
    uint32_t resolve_count;        /* 0..10; resolves follow the depth and stencil attachments */
    struct sgpu_ref visibility;    /* visibilityResultBuffer, bt 0xffffffff = none, WRITE access */
    uint32_t reserved[4];
    /* struct sgpu_attachment color[color_count], depth, stencil; struct sgpu_resolve resolve[resolve_count] */
};

struct sgpu_set_pipeline { struct sgpu_pkt h; uint32_t pipe_id, reserved; };   /* 16, render or compute */

struct sgpu_set_state {            /* 136: only fields whose bit is set in `which` are applied */
    struct sgpu_pkt h;
    uint32_t which;                /* b0 viewport, b1 scissor, b2 cull, b3 winding, b4 fill, b5 depth clip,
                                      b6 depth bias, b7 blend colour, b8 stencil ref, b9 depth-stencil state,
                                      b10 visibility mode */
    uint32_t reserved0;
    float    viewport[6];          /* originX, originY, width, height, znear, zfar */
    uint32_t scissor[4];           /* x, y, width, height */
    uint32_t cull_mode, winding, fill_mode, depth_clip_mode;   /* MTL enums */
    float    depth_bias, depth_slope_scale, depth_bias_clamp, reserved1;
    float    blend_color[4];
    uint32_t stencil_ref_front, stencil_ref_back;
    uint32_t dss_id;               /* 0 = Metal default (depth disabled) */
    uint32_t visibility_mode;      /* MTLVisibilityResultMode */
    uint64_t visibility_offset;    /* into the pass's visibility buffer, 8-aligned */
    uint32_t reserved2[2];
};

struct sgpu_set_bindings {
    struct sgpu_pkt h;
    uint8_t  stage;                /* 0 vertex, 1 fragment, 2 compute */
    uint8_t  reserved0;
    uint16_t count;                /* entries that follow */
    uint32_t reserved1;
};
struct sgpu_binding_hdr { uint8_t kind; uint8_t reserved; uint16_t slot; uint32_t size; };   /* size incl. header */
/* kind 1 BUFFER   : hdr, uint32_t bt, uint32_t reserved, uint64_t offset             (24)  slot 0..30
   kind 2 BYTES    : hdr, uint32_t length, uint32_t reserved, data[length] pad to 8   (16+) slot 0..30, length <= 4096
   kind 3 TEXTURE  : hdr, struct sgpu_texdesc                                         (72)  slot 0..30
   kind 4 SAMPLER  : hdr, uint32_t sampler_id, uint32_t reserved, float lod_min_clamp,
                     float lod_max_clamp (setSamplerState:lodMinClamp:lodMaxClamp:) (24)  slot 0..15
   kind 5 UNBIND   : hdr, uint32_t what (1 buffer, 3 texture, 4 sampler), uint32_t r  (16)
   kind 6 TG_MEMORY: hdr, uint32_t length, uint32_t reserved                          (16)  compute only, slot 0..30 */

struct sgpu_draw {                 /* 32 */
    struct sgpu_pkt h;
    uint32_t primitive;            /* MTLPrimitiveType */
    uint32_t vertex_start, vertex_count, instance_count, base_instance, reserved;
};
struct sgpu_draw_indexed {         /* 48 */
    struct sgpu_pkt h;
    uint32_t primitive, index_type;  /* MTLIndexType: 0 UInt16, 1 UInt32 */
    uint32_t index_count, instance_count;
    int32_t  base_vertex; uint32_t base_instance;
    struct sgpu_ref index;         /* offset aligned to the index size */
};
struct sgpu_draw_indirect {        /* 40 */
    struct sgpu_pkt h;
    uint32_t primitive, reserved;
    struct sgpu_ref args;          /* MTLDrawPrimitivesIndirectArguments, 4-aligned */
    uint64_t reserved2;
};
struct sgpu_draw_indexed_indirect { /* 56 */
    struct sgpu_pkt h;
    uint32_t primitive, index_type;
    struct sgpu_ref index;
    struct sgpu_ref args;          /* MTLDrawIndexedPrimitivesIndirectArguments */
    uint64_t reserved;
};

struct sgpu_dispatch {             /* 40 */
    struct sgpu_pkt h;
    uint32_t mode;                 /* 0 dispatchThreadgroups, 1 dispatchThreads (non-uniform) */
    uint32_t grid[3];              /* threadgroups (mode 0) or threads (mode 1) */
    uint32_t threads_per_group[3]; /* product <= the pipeline's max total threads */
    uint32_t reserved;
};
struct sgpu_dispatch_indirect { struct sgpu_pkt h; uint32_t threads_per_group[3], reserved; struct sgpu_ref args; };  /* 40 */

struct sgpu_copy_buffer {          /* 48 */
    struct sgpu_pkt h;
    struct sgpu_ref src, dst;      /* dst WRITE access */
    uint64_t bytes;
};
struct sgpu_copy_texture {         /* 192 */
    struct sgpu_pkt h;
    struct sgpu_texdesc src, dst;
    uint32_t src_level, src_slice, dst_level, dst_slice;
    uint32_t src_origin[3], dst_origin[3], size[3];
    uint32_t slice_count;          /* consecutive slices */
};
struct sgpu_copy_buffer_texture {  /* 136 */
    struct sgpu_pkt h;
    uint32_t direction;            /* 0 buffer -> texture, 1 texture -> buffer */
    uint32_t options;              /* MTLBlitOption (depth/stencil aspect) */
    struct sgpu_ref buffer;
    uint32_t bytes_per_row, bytes_per_image;
    struct sgpu_texdesc tex;
    uint32_t level, slice;
    uint32_t origin[3], size[3];
};
struct sgpu_fill_buffer {          /* 40 */
    struct sgpu_pkt h;
    struct sgpu_ref dst;
    uint64_t bytes;
    uint32_t value;                /* low byte is the fill byte */
    uint32_t reserved;
};
struct sgpu_generate_mipmaps { struct sgpu_pkt h; struct sgpu_texdesc tex; };  /* 72: levels base+1 .. last of the view */

struct sgpu_fence {                /* 40: after all earlier work of this stream is complete ... */
    struct sgpu_pkt h;
    uint32_t flags;                /* b0 WRITE_VALUE: ... store `value` (8 bytes) at dst */
    uint32_t reserved;
    struct sgpu_ref dst;           /* WRITE access, 8-aligned */
    uint64_t value;
};
struct sgpu_timestamp { struct sgpu_pkt h; struct sgpu_ref dst; };   /* 24: u64 QEMU_CLOCK_VIRTUAL ns */
struct sgpu_debug_label { struct sgpu_pkt h; uint32_t kind, len; };  /* kind 0 insert, 1 push, 2 pop; text follows */

struct sgpu_result_head {          /* 32 bytes at result.offset: every creation record starts with it */
    uint32_t magic;                /*  0  0x52504753 "SGPR" */
    uint32_t state;                /*  4  0 pending (written by the plug-in), 1 done (host, store-release, last) */
    int32_t  status;               /*  8  SGPU_OK, SGPU_E_COMPILE, SGPU_E_UNSUPPORTED, SGPU_E_TIMEOUT, ... */
    uint32_t flags;                /* 12  b0 TRUNCATED (capacity too small, head still valid) */
    uint64_t request_tag;          /* 16  the plug-in's tag; the plug-in reads the record only when it matches */
    uint32_t bytes_written;        /* 24  head + body + text + reflection actually written */
    uint32_t reserved;             /* 28 */
};

struct sgpu_pipeline_result {      /* 256 bytes at result.offset; capacity >= 256 */
    struct sgpu_result_head head;  /*  0 */
    uint32_t error_off, error_len; /* 32  UTF-8 message, relative to the record */
    uint32_t refl_off, refl_len;   /* 40  JSON reflection (the sidecar's "reflection" object), if WANT_REFLECTION */
    uint32_t max_total_threads;    /* 48  compute: maxTotalThreadsPerThreadgroup */
    uint32_t thread_execution_width;   /* 52  compute: llvmpipe's native vector width / 32; 8 on this
                                          AVX2 host (review m4), reported by the host, never assumed */
    uint32_t static_threadgroup_bytes; /* 56  compute */
    uint32_t reserved0;            /* 60 */
    uint8_t  key[32];              /* 64  host cache key, diagnostics */
    uint8_t  reserved1[160];       /* 96 */
};  /* then text and JSON */

struct sgpu_present {              /* 64 */
    struct sgpu_pkt h;
    uint32_t present_id;           /* SoftDisplay's swap ID, increasing */
    uint32_t mem_id;               /* a DISPLAY memory object (or any kernel-registered one) */
    uint64_t offset;               /* first byte of the surface in the object */
    uint32_t format;               /* MTLPixelFormat: 80, 81, 94, 115 (scanout codes 1.2) */
    uint32_t width, height, row_pitch;
    int32_t  src_x, src_y;         /* source rectangle origin; size = the active mode, clipped */
    int32_t  dst_x, dst_y;         /* 0, 0 in version 1 (no scaling) */
    uint32_t flags;                /* b0 FLIP_AT_VBLANK (default 1), b1 BLANK (show black) */
    uint32_t reserved;
};

struct sgpu_set_cursor {           /* 48 */
    struct sgpu_pkt h;
    uint32_t flags;                /* b0 IMAGE (replace the image), b1 HIDE */
    uint32_t mem_id;
    uint64_t offset;
    uint32_t width, height, row_pitch;   /* <= 256 x 256 */
    uint32_t format;               /* 80 BGRA8, premultiplied alpha (QuartzCore's cursor layer) */
    int32_t  hot_x, hot_y;
};

/* ---- constants ---- */
#define SGPU_MAGIC 0x55504753u
#define SGPU_VERSION 0x00010000u
#define SGPU_MON_MAGIC 0x4e4f4d53u
#define SGPU_RESULT_MAGIC 0x52504753u
#define SGPU_MAX_STREAM_BYTES 0x400000u
#define SGPU_MAX_BT_COUNT 65535u
enum { SGPU_DESC_SUBMIT = 1, SGPU_DESC_KERNEL = 2 };
enum { SGPU_DESC_IRQ = 1u << 0, SGPU_DESC_LAST = 1u << 2, SGPU_DESC_BOOTSTRAP = 1u << 15 };
enum { SGPU_ACCESS_READ = 1, SGPU_ACCESS_WRITE = 2 };
enum { SGPU_MEM_ARENA = 1, SGPU_MEM_DISPLAY = 2, SGPU_MEM_READ_ONLY = 4 };
enum { SGPU_WIN_READ = 1, SGPU_WIN_WRITE = 2 };
enum { SGPU_PKT_OPTIONAL = 1 };
enum {
  SGPU_OK = 0, SGPU_E_FORMAT = -1, SGPU_E_OPCODE = -2, SGPU_E_BOUNDS = -3, SGPU_E_ACCESS = -4, SGPU_E_OBJECT = -5,
  SGPU_E_STATE = -6, SGPU_E_UNSUPPORTED = -7, SGPU_E_COMPILE = -8, SGPU_E_TIMEOUT = -9, SGPU_E_RESET = -10,
  SGPU_E_QUOTA = -11, SGPU_E_MEMORY = -12, SGPU_E_HOST = -13, SGPU_E_LOST = -14, SGPU_E_SKIPPED = -15
};
enum {
  SGPU_OP_NOP = 0x0000, SGPU_OP_CREATE_CONTEXT = 0x0100, SGPU_OP_DESTROY_CONTEXT = 0x0101,
  SGPU_OP_CREATE_MEMORY = 0x0110, SGPU_OP_DESTROY_MEMORY = 0x0111, SGPU_OP_PRESENT = 0x0120,
  SGPU_OP_SET_CURSOR = 0x0121, SGPU_OP_STAMP = 0x0130,
  SGPU_OP_UPLOAD_SHADER = 0x0200, SGPU_OP_CREATE_RENDER_PIPELINE = 0x0201, SGPU_OP_CREATE_COMPUTE_PIPELINE = 0x0202,
  SGPU_OP_CREATE_SAMPLER = 0x0203, SGPU_OP_CREATE_DEPTH_STENCIL = 0x0204, SGPU_OP_DESTROY_OBJECT = 0x0205,
  SGPU_OP_BEGIN_RENDER_PASS = 0x0300, SGPU_OP_END_RENDER_PASS = 0x0301, SGPU_OP_SET_RENDER_PIPELINE = 0x0302,
  SGPU_OP_SET_STATE = 0x0303, SGPU_OP_SET_BINDINGS = 0x0304, SGPU_OP_DRAW = 0x0305, SGPU_OP_DRAW_INDEXED = 0x0306,
  SGPU_OP_DRAW_INDIRECT = 0x0307, SGPU_OP_DRAW_INDEXED_INDIRECT = 0x0308, SGPU_OP_TEXTURE_BARRIER = 0x0309,
  SGPU_OP_BEGIN_COMPUTE_PASS = 0x0400, SGPU_OP_END_COMPUTE_PASS = 0x0401, SGPU_OP_SET_COMPUTE_PIPELINE = 0x0402,
  SGPU_OP_DISPATCH = 0x0403, SGPU_OP_DISPATCH_INDIRECT = 0x0404,
  SGPU_OP_COPY_BUFFER = 0x0500, SGPU_OP_COPY_TEXTURE = 0x0501, SGPU_OP_COPY_BUFFER_TEXTURE = 0x0502,
  SGPU_OP_FILL_BUFFER = 0x0503, SGPU_OP_GENERATE_MIPMAPS = 0x0504,
  SGPU_OP_FENCE = 0x0600, SGPU_OP_TIMESTAMP = 0x0601, SGPU_OP_DEBUG_LABEL = 0x0602
};
enum { SGPU_BIND_BUFFER = 1, SGPU_BIND_BYTES = 2, SGPU_BIND_TEXTURE = 3, SGPU_BIND_SAMPLER = 4, SGPU_BIND_UNBIND = 5, SGPU_BIND_TG_MEMORY = 6 };
enum { SGPU_OBJ_LIB = 1, SGPU_OBJ_PIPELINE = 2, SGPU_OBJ_SAMPLER = 3, SGPU_OBJ_DSS = 4 };
/* register offsets, page 0 (guest) */
enum { SGPU_REG_MAGIC=0x000, SGPU_REG_VERSION=0x004, SGPU_REG_FEATURES0=0x008, SGPU_REG_FEATURES1=0x00c,
  SGPU_REG_DRV_FEATURES0=0x010, SGPU_REG_DRV_FEATURES1=0x014, SGPU_REG_DRV_VERSION=0x018, SGPU_REG_STATUS=0x020,
  SGPU_REG_CONTROL=0x024, SGPU_REG_RING_BASE_LO=0x030, SGPU_REG_RING_BASE_HI=0x034, SGPU_REG_RING_ENTRIES=0x038,
  SGPU_REG_STATUS_PAGE_LO=0x040, SGPU_REG_STATUS_PAGE_HI=0x044, SGPU_REG_STAMP_BASE_LO=0x048, SGPU_REG_STAMP_BASE_HI=0x04c,
  SGPU_REG_STAMP_COUNT=0x050, SGPU_REG_BUDGET_MS=0x054, SGPU_REG_COMPILE_BUDGET_MS=0x058, SGPU_REG_RING_TAIL=0x060,
  SGPU_REG_RING_HEAD=0x064, SGPU_REG_DONE_SEQNO_LO=0x068, SGPU_REG_DONE_SEQNO_HI=0x06c, SGPU_REG_IRQ_STATUS=0x070,
  SGPU_REG_IRQ_MASK=0x074, SGPU_REG_IRQ_RAW=0x078, SGPU_REG_IRQ_MASK_SET=0x07c, SGPU_REG_IRQ_MASK_CLR=0x080,
  SGPU_REG_DISP_MODE_COUNT=0x100, SGPU_REG_DISP_MODE_INDEX=0x104, SGPU_REG_DISP_CTRL=0x108, SGPU_REG_DISP_STATUS=0x10c,
  SGPU_REG_VBLANK_COUNT_LO=0x110, SGPU_REG_VBLANK_COUNT_HI=0x114, SGPU_REG_VBLANK_TIME_LO=0x118, SGPU_REG_VBLANK_TIME_HI=0x11c,
  SGPU_REG_DEVICE_TIME_LO=0x120, SGPU_REG_DEVICE_TIME_HI=0x124, SGPU_REG_PRESENT_DONE_ID=0x128,
  SGPU_REG_CURSOR_CTRL=0x130, SGPU_REG_CURSOR_POS=0x134, SGPU_REG_DISP_MODE0=0x200, SGPU_REG_DBG_COUNTERS=0x800 };
enum { SGPU_ST_READY=1, SGPU_ST_RING_ENABLED=2, SGPU_ST_RESETTING=4, SGPU_ST_FATAL=8, SGPU_ST_LOCKED=16,
  SGPU_ST_ZERO_COPY=32, SGPU_ST_WINDOWS_STALE=64, SGPU_ST_WAIT=128 };
enum { SGPU_CTL_RING_ENABLE=1, SGPU_CTL_RESET_QUEUE=2, SGPU_CTL_RESET_DEVICE=4 };
enum { SGPU_IRQ_DONE=1, SGPU_IRQ_VBLANK=2, SGPU_IRQ_PRESENT=4, SGPU_IRQ_FAULT=8, SGPU_IRQ_RESET_DONE=16, SGPU_IRQ_FATAL=32 };
/* register offsets, page 1 (monitor) */
enum { SGPU_MREG_MAGIC=0x000, SGPU_MREG_WINDOW_COUNT=0x004, SGPU_MREG_LOCK=0x008, SGPU_MREG_FEATURE_MASK0=0x00c,
  SGPU_MREG_FEATURE_MASK1=0x010, SGPU_MREG_WINDOWS_GEN=0x014, SGPU_MREG_WINDOWS_GEN_APPLIED=0x018, SGPU_MREG_WINDOW0=0x100 };
/* features0 */
enum { SGPU_F_CORE=1u<<0, SGPU_F_ZERO_COPY=1u<<1, SGPU_F_DISPLAY=1u<<2, SGPU_F_CURSOR=1u<<3, SGPU_F_COMPUTE=1u<<4,
  SGPU_F_MRT8=1u<<5, SGPU_F_DEPTH_STENCIL=1u<<6, SGPU_F_FB_FETCH=1u<<7, SGPU_F_XR10=1u<<8, SGPU_F_HALF_FLOAT_RT=1u<<9,
  SGPU_F_MSAA4=1u<<10, SGPU_F_BUFFER_TEXTURE=1u<<11, SGPU_F_MIPMAPS=1u<<12, SGPU_F_INDIRECT=1u<<13, SGPU_F_TIMESTAMP=1u<<14,
  SGPU_F_BC=1u<<15, SGPU_F_AIR_2_2=1u<<16, SGPU_F_VBLANK_IRQ=1u<<17 };

/* ---- size and offset assertions (from softgpu-wire-test.c) ---- */
#define SZ(t, n) SGPU_SA(sizeof(struct t) == (n), #t " size");
#define OF(t, f, n) SGPU_SA(offsetof(struct t, f) == (n), #t "." #f " offset");
SZ(sgpu_window, 32) SZ(sgpu_status_head, 64) SZ(sgpu_completion, 16) SZ(sgpu_device_info, 256) SZ(sgpu_fault, 256)
SZ(sgpu_desc, 64) SZ(sgpu_bt_entry, 32) SZ(sgpu_kcmd_stream, 32) SZ(sgpu_mem_run, 16) SZ(sgpu_pkt, 8) SZ(sgpu_ref, 16)
SZ(sgpu_create_context, 32) SZ(sgpu_destroy_context, 16) SZ(sgpu_create_memory, 48) SZ(sgpu_destroy_memory, 16)
SZ(sgpu_stamp, 16) SZ(sgpu_texdesc, 64) SZ(sgpu_upload_shader, 72) SZ(sgpu_fconst, 48) SZ(sgpu_stage, 24)
SZ(sgpu_blend, 8) SZ(sgpu_vertex_attr, 16) SZ(sgpu_vertex_layout, 16) SZ(sgpu_result_ref, 16)
SZ(sgpu_create_render_pipeline, 216) SZ(sgpu_create_compute_pipeline, 72) SZ(sgpu_create_sampler, 56)
SZ(sgpu_stencil_face, 12) SZ(sgpu_create_depth_stencil, 56) SZ(sgpu_destroy_object, 16)
SZ(sgpu_attachment, 96) SZ(sgpu_resolve, 80) SZ(sgpu_begin_render_pass, 64) SZ(sgpu_set_pipeline, 16)
SZ(sgpu_set_state, 136) SZ(sgpu_set_bindings, 16) SZ(sgpu_binding_hdr, 8) SZ(sgpu_draw, 32)
SZ(sgpu_draw_indexed, 48) SZ(sgpu_draw_indirect, 40) SZ(sgpu_draw_indexed_indirect, 56) SZ(sgpu_dispatch, 40)
SZ(sgpu_dispatch_indirect, 40) SZ(sgpu_copy_buffer, 48) SZ(sgpu_copy_texture, 192) SZ(sgpu_copy_buffer_texture, 136)
SZ(sgpu_fill_buffer, 40) SZ(sgpu_generate_mipmaps, 72) SZ(sgpu_fence, 40) SZ(sgpu_timestamp, 24)
SZ(sgpu_debug_label, 16) SZ(sgpu_result_head, 32) SZ(sgpu_pipeline_result, 256) SZ(sgpu_present, 64) SZ(sgpu_set_cursor, 48)
OF(sgpu_window, ipa_base, 0) OF(sgpu_window, size, 8) OF(sgpu_window, pa_base, 16) OF(sgpu_window, flags, 24)
OF(sgpu_status_head, done_seqno, 0) OF(sgpu_status_head, ring_head, 8) OF(sgpu_status_head, device_state, 12)
OF(sgpu_status_head, current_seqno, 16) OF(sgpu_status_head, current_start_ns, 24)
OF(sgpu_status_head, device_epoch, 32) OF(sgpu_status_head, vblank_count, 40) OF(sgpu_status_head, vblank_time_ns, 48)
OF(sgpu_status_head, present_done_id, 56) OF(sgpu_status_head, presents_dropped, 60)
OF(sgpu_completion, seqno, 0) OF(sgpu_completion, status, 8) OF(sgpu_completion, packet_offset, 12)
OF(sgpu_device_info, protocol_version, 0) OF(sgpu_device_info, air2ir3_api, 12) OF(sgpu_device_info, max_buffer_bytes, 48)
OF(sgpu_device_info, compiler_id, 64) OF(sgpu_device_info, host_renderer, 160) OF(sgpu_device_info, reserved1, 224)
OF(sgpu_fault, seqno, 0) OF(sgpu_fault, status, 8) OF(sgpu_fault, opcode, 12) OF(sgpu_fault, packet_offset, 16)
OF(sgpu_fault, detail, 20) OF(sgpu_fault, ctx_id, 24) OF(sgpu_fault, message, 32)
OF(sgpu_desc, type, 0) OF(sgpu_desc, flags, 2) OF(sgpu_desc, ctx_id, 4) OF(sgpu_desc, seqno, 8)
OF(sgpu_desc, stream_offset, 16) OF(sgpu_desc, stream_bytes, 24) OF(sgpu_desc, bt_count, 28)
OF(sgpu_desc, bt_offset, 32) OF(sgpu_desc, stamp_index, 40) OF(sgpu_desc, stamp_value, 44)
OF(sgpu_desc, budget_ms, 48) OF(sgpu_desc, cb_id, 52) OF(sgpu_desc, tag, 56)
OF(sgpu_bt_entry, mem_id, 0) OF(sgpu_bt_entry, access, 4) OF(sgpu_bt_entry, offset, 8) OF(sgpu_bt_entry, length, 16)
OF(sgpu_bt_entry, resource_id, 24)
OF(sgpu_kcmd_stream, type, 0) OF(sgpu_kcmd_stream, size, 4) OF(sgpu_kcmd_stream, version, 8)
OF(sgpu_kcmd_stream, flags, 12) OF(sgpu_kcmd_stream, stream_bytes, 16) OF(sgpu_kcmd_stream, epoch, 24)
OF(sgpu_pkt, opcode, 0) OF(sgpu_pkt, flags, 2) OF(sgpu_pkt, size, 4)
OF(sgpu_create_memory, mem_id, 8) OF(sgpu_create_memory, flags, 12) OF(sgpu_create_memory, size, 16)
OF(sgpu_create_memory, gpu_va, 24) OF(sgpu_create_memory, head, 32) OF(sgpu_create_memory, run_count, 36)
OF(sgpu_create_memory, reserved, 40)
OF(sgpu_texdesc, bt, 0) OF(sgpu_texdesc, storage_format, 4) OF(sgpu_texdesc, texture_type, 8)
OF(sgpu_texdesc, flags, 10) OF(sgpu_texdesc, swizzle, 12) OF(sgpu_texdesc, width, 16) OF(sgpu_texdesc, height, 20)
OF(sgpu_texdesc, depth, 24) OF(sgpu_texdesc, array_length, 28) OF(sgpu_texdesc, offset, 32)
OF(sgpu_texdesc, row_pitch0, 40) OF(sgpu_texdesc, slice_pitch, 44) OF(sgpu_texdesc, mip_levels, 48)
OF(sgpu_texdesc, base_level, 49) OF(sgpu_texdesc, level_count, 50) OF(sgpu_texdesc, sample_count, 51)
OF(sgpu_texdesc, base_slice, 52) OF(sgpu_texdesc, slice_count, 54) OF(sgpu_texdesc, view_format, 56)
OF(sgpu_upload_shader, lib_id, 8) OF(sgpu_upload_shader, air_sha256, 16) OF(sgpu_upload_shader, air_bytes, 48)
OF(sgpu_upload_shader, src, 56)
OF(sgpu_fconst, values, 16)
OF(sgpu_create_sampler, sampler_id, 8) OF(sgpu_create_sampler, result, 16) OF(sgpu_create_sampler, min_filter, 32)
OF(sgpu_create_sampler, s, 36) OF(sgpu_create_sampler, normalized, 40) OF(sgpu_create_sampler, lod_min, 44)
OF(sgpu_create_sampler, lod_max, 48) OF(sgpu_create_sampler, reserved2, 52)
OF(sgpu_create_depth_stencil, dss_id, 8) OF(sgpu_create_depth_stencil, depth_compare, 12)
OF(sgpu_create_depth_stencil, result, 16) OF(sgpu_create_depth_stencil, front, 32) OF(sgpu_create_depth_stencil, back, 44)
OF(sgpu_create_compute_pipeline, result, 16)
OF(sgpu_create_render_pipeline, result, 16) OF(sgpu_create_render_pipeline, vs, 32) OF(sgpu_create_render_pipeline, fs, 56)
OF(sgpu_create_render_pipeline, color_format, 80) OF(sgpu_create_render_pipeline, blend, 112)
OF(sgpu_create_render_pipeline, depth_format, 176) OF(sgpu_create_render_pipeline, attr_off, 192)
OF(sgpu_attachment, level, 64) OF(sgpu_attachment, load, 76) OF(sgpu_attachment, clear, 80)
OF(sgpu_resolve, tex, 16)
OF(sgpu_begin_render_pass, color_count, 24) OF(sgpu_begin_render_pass, visibility, 32)
OF(sgpu_set_state, which, 8) OF(sgpu_set_state, viewport, 16) OF(sgpu_set_state, scissor, 40)
OF(sgpu_set_state, blend_color, 88) OF(sgpu_set_state, dss_id, 112) OF(sgpu_set_state, visibility_offset, 120)
OF(sgpu_draw_indexed, index, 32) OF(sgpu_draw_indirect, args, 16) OF(sgpu_draw_indexed_indirect, args, 32)
OF(sgpu_dispatch_indirect, args, 24) OF(sgpu_copy_texture, dst, 72) OF(sgpu_copy_buffer_texture, tex, 40)
OF(sgpu_fence, dst, 16) OF(sgpu_fence, value, 32)
OF(sgpu_result_head, magic, 0) OF(sgpu_result_head, state, 4) OF(sgpu_result_head, status, 8)
OF(sgpu_result_head, flags, 12) OF(sgpu_result_head, request_tag, 16) OF(sgpu_result_head, bytes_written, 24)
OF(sgpu_result_head, reserved, 28)
OF(sgpu_pipeline_result, head, 0) OF(sgpu_pipeline_result, error_off, 32) OF(sgpu_pipeline_result, error_len, 36)
OF(sgpu_pipeline_result, refl_off, 40) OF(sgpu_pipeline_result, refl_len, 44)
OF(sgpu_pipeline_result, max_total_threads, 48) OF(sgpu_pipeline_result, thread_execution_width, 52)
OF(sgpu_pipeline_result, static_threadgroup_bytes, 56) OF(sgpu_pipeline_result, reserved0, 60)
OF(sgpu_pipeline_result, key, 64) OF(sgpu_pipeline_result, reserved1, 96)
OF(sgpu_present, present_id, 8) OF(sgpu_present, offset, 16) OF(sgpu_present, format, 24)
OF(sgpu_present, src_x, 40) OF(sgpu_present, flags, 56)
OF(sgpu_set_cursor, offset, 16) OF(sgpu_set_cursor, hot_x, 40)
#undef SZ
#undef OF
#endif
