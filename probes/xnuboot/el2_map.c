/* SPDX-License-Identifier: MIT */
/* One EL2 stage-1 Device block for the A16 GPU aperture.
 *
 * The monitor reaches the GPU, the GIC and the arena through the EL2 stage-1
 * map it inherits: the firmware's identity map (platform/uefi/main.c live_map).
 * On QEMU that map covers the firmware's own MMIO and RAM and nothing at
 * 0x03C00000, so the first CX GDSC or GMU register read is a level-2
 * translation fault taken at EL2 (ESR 0x96000006, EC 0x25) and the run stops
 * before the guest does anything. One 2 MiB block covers the whole aperture
 * compat/adreno.h names (0x03D00000..0x03DA0000, inside 0x03C00000..0x03E00000)
 * and every later read, write and RD64 lands in it.
 *
 * The walk matches q1n1's q1n1_mmu_attr: 4 KiB granule, start level from T0SZ.
 * A block is written only into an entry the firmware left empty, so an address
 * it already maps keeps its own attributes; a walk that ends on a block or on
 * a level-3 table changes nothing.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#define EL2_GPU_BLOCK_BASE UINT64_C(0x03C00000)   /* 2 MiB-aligned, contains the GPU aperture */
#define EL2_GPU_BLOCK_SIZE UINT64_C(0x00200000)
#define EL2_PA_MASK UINT64_C(0x0000fffffffff000)
static uint64_t el2_block_desc(uint64_t pa, uint64_t mair)
{
    /* AF, AP[2:1] 0b01 (EL1 and EL0 read-write; 0b11 is read-only and made the
     * first TLBIASID store a permission fault), inner shareable, UXN and PXN,
     * and the AttrIndx of the first Device entry in MAIR_EL2 (0x04 or 0x00):
     * the shape the firmware gives its own MMIO blocks. */
    unsigned attr = 0;
    for (unsigned i = 0; i < 8; i++)
        if (((mair >> (8 * i)) & 0xf0) == 0) { attr = i; break; }
    return pa | 1 | ((uint64_t)attr << 2) | (UINT64_C(2) << 8) | (UINT64_C(1) << 6) |
           (UINT64_C(1) << 10) | (UINT64_C(3) << 53);
}
/* 1: a block was written; 0: the address is already covered; negative: the
 * regime is not the 4 KiB, T0SZ-described one this walker understands. */
static int el2_map_block(uint64_t ttbr, uint64_t tcr, uint64_t mair, uint64_t va, uint64_t pa)
{
    uint32_t t0sz = (uint32_t)(tcr & 63);
    if (((tcr >> 14) & 3) != 0 || t0sz < 16 || t0sz > 39) return -1;   /* 4 KiB granule only */
    uint32_t bits = 64 - t0sz;
    if ((va >> bits) || (pa >> bits)) return -1;
    int level = 4 - (int)((bits - 12 + 8) / 9);
    uint64_t table = ttbr & EL2_PA_MASK;
    for (; level < 3; level++) {
        uint32_t shift = 12 + 9 * (uint32_t)(3 - level);
        volatile uint64_t *entry = (volatile uint64_t *)(uintptr_t)
            (table + (((va >> shift) & 0x1ff) << 3));
        uint64_t d = *entry;
        if (d & 1) {
            if ((d & 3) == 1) return 0;      /* a block in the same window is already there */
            table = d & EL2_PA_MASK;
            continue;
        }
        /* Empty entry: nothing is mapped under it, so the block this level
         * accepts covers the window and collides with nothing. */
        *entry = el2_block_desc(pa & ~((UINT64_C(1) << shift) - 1), mair);
        return 1;
    }
    return 0;                                /* a level-3 table: any leaf is a page */
}
#define EL2_SOFTGPU_BLOCK_MASK (~(EL2_GPU_BLOCK_SIZE - 1))   /* 2 MiB: the platform-bus window page 1 sits in */
#if !defined(EL2_MAP_TEST)
#if SNAP_SOFTGPU
/* SNAP_SOFTGPU: the EL2 view of the device's page 1 (the DMA-window and LOCK page, +0x1000 from page 0). The guest has no
 * stage-2 mapping of it; only EL2 reaches it, through one Device block over its 2 MiB window as above. */
static int el2_map_softgpu(uint64_t page1)
{
    uint64_t sctlr, tcr, ttbr, mair;
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    if (!(sctlr & 1)) return 0;              /* MMU off: identity, every access is Device */
    __asm__ volatile("mrs %0, tcr_el2" : "=r"(tcr));
    __asm__ volatile("mrs %0, ttbr0_el2" : "=r"(ttbr));
    __asm__ volatile("mrs %0, mair_el2" : "=r"(mair));
    uint64_t block = page1 & EL2_SOFTGPU_BLOCK_MASK;
    int added = el2_map_block(ttbr, tcr, mair, block, block);
    record(context_of(), EV_EL2_MAP, block, EL2_GPU_BLOCK_SIZE, 1, (uint64_t)added);
    if (added > 0) __asm__ volatile("dsb sy; tlbi alle2; dsb sy; isb" ::: "memory");
    return added < 0 ? added : 0;
}
#endif
static int el2_map_gpu_aperture(void)
{
    uint64_t sctlr, tcr, ttbr, mair;
    __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
    if (!(sctlr & 1)) return 0;              /* MMU off: identity, every access is Device */
    __asm__ volatile("mrs %0, tcr_el2" : "=r"(tcr));
    __asm__ volatile("mrs %0, ttbr0_el2" : "=r"(ttbr));
    __asm__ volatile("mrs %0, mair_el2" : "=r"(mair));
    int added = el2_map_block(ttbr, tcr, mair, EL2_GPU_BLOCK_BASE, EL2_GPU_BLOCK_BASE);
    record(context_of(), EV_EL2_MAP, EL2_GPU_BLOCK_BASE, EL2_GPU_BLOCK_SIZE, 0, (uint64_t)added);
    if (added > 0) __asm__ volatile("dsb sy; tlbi alle2; dsb sy; isb" ::: "memory");
    return added < 0 ? added : 0;
}
#endif
