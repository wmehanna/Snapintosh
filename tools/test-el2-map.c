/* SPDX-License-Identifier: MIT */
/* tools/test-el2-map.c: probes/xnuboot/el2_map.c's walk, on fake 4 KiB tables.
 * The installer runs at EL2 against the firmware's own tables, which a host
 * test cannot touch, so what is checked here is the part that decides: which
 * level the regime starts at, whether the entry is empty, and what the block
 * descriptor says. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define EL2_MAP_TEST 1
#include "../probes/xnuboot/el2_map.c"
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static unsigned checks;
static uint64_t l0[512] __attribute__((aligned(4096)));
static uint64_t l1[512] __attribute__((aligned(4096)));
static uint64_t l2[512] __attribute__((aligned(4096)));
static uint64_t l3[512] __attribute__((aligned(4096)));
static void clear(void)
{
    for (unsigned i = 0; i < 512; i++) l0[i] = l1[i] = l2[i] = l3[i] = 0;
}
static void link_level1(void)
{
    l1[0] = (uint64_t)(uintptr_t)l2 | 3;   /* a table descriptor: valid, type table */
}
int main(void)
{
    /* EDK2's MAIR shape: Attr0 Normal WB, Attr1 Normal NC, Attr2 Device nGnRE,
     * Attr3 Device nGnRnE. The first Device entry is Attr2. */
    const uint64_t mair = UINT64_C(0x000440ff);
    const uint64_t base = EL2_GPU_BLOCK_BASE;
    /* T0SZ 32: 4 KiB granule, 32-bit VA, start at level 1 (q1n1_mmu_attr's
     * formula), so the GPU aperture is an L1 index 0 and an L2 index 30. */
    const uint64_t tcr = 32;

    clear();
    link_level1();
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, mair, base, base) == 1);
    uint64_t d = l2[(base >> 21) & 0x1ff];
    CHECK((d & 3) == 1);                                  /* block */
    CHECK((d & UINT64_C(0x0000ffffffe00000)) == base);     /* identity, 2 MiB aligned */
    CHECK(((d >> 2) & 7) == 2);                            /* AttrIndx: Device nGnRE */
    CHECK(((d >> 6) & 3) == 1);                            /* AP: EL1+EL0 readable and writable (0b11 is read-only) */
    CHECK(((d >> 10) & 1) == 1);                           /* AF */
    CHECK(((d >> 53) & 3) == 3);                           /* UXN and PXN */

    /* Idempotent: a second call finds a block and changes nothing. */
    const uint64_t before = l2[(base >> 21) & 0x1ff];
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, mair, base, base) == 0);
    CHECK(l2[(base >> 21) & 0x1ff] == before);

    /* An address the firmware already maps keeps its own attributes. */
    clear();
    link_level1();
    l2[(base >> 21) & 0x1ff] = base | 1 | (UINT64_C(1) << 2) | (UINT64_C(3) << 6) | (UINT64_C(1) << 10);
    const uint64_t own = l2[(base >> 21) & 0x1ff];
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, mair, base, base) == 0);
    CHECK(l2[(base >> 21) & 0x1ff] == own);

    /* An empty level 1 entry takes a 1 GiB block: still a valid answer, and
     * nothing else was there to lose. */
    clear();
    l1[0] = 0;
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, mair, base, base) == 1);
    CHECK((l1[0] & 3) == 1);
    CHECK((l1[0] & UINT64_C(0x0000ffffc0000000)) == 0);   /* 1 GiB aligned at 0 */

    /* A level-3 table is already page-granular: nothing to write. */
    clear();
    link_level1();
    l2[(base >> 21) & 0x1ff] = (uint64_t)(uintptr_t)l3 | 3;
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, mair, base, base) == 0);
    for (unsigned i = 0; i < 512; i++) CHECK(l3[i] == 0);

    /* T0SZ 25 describes the same 39-bit start level. */
    clear();
    link_level1();
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, 25, mair, base, base) == 1);

    /* Unsupported regimes and an address outside them: nothing written. */
    clear();
    link_level1();
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, (1 << 14) | 32, mair, base, base) == -1);  /* 64 KiB */
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, 15, mair, base, base) == -1);
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, 40, mair, base, base) == -1);
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, 32, mair, UINT64_C(1) << 32, UINT64_C(1) << 32) == -1);
    for (unsigned i = 0; i < 512; i++) CHECK(l2[i] == 0);

    /* An entry of 0x00 is Device-nGnRnE, so an unused MAIR slot is still a
     * Device answer: 0x44ff picks index 2, and 0x000440ff (EDK2's shape) does
     * the same. Only when no slot is Device at all (0xff and 0x44 everywhere)
     * does the walker leave AttrIndx 0. */
    clear();
    link_level1();
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, UINT64_C(0x00000000000440ff), base, base) == 1);
    CHECK(((l2[(base >> 21) & 0x1ff] >> 2) & 7) == 2);
    clear();
    link_level1();
    const uint64_t normal_only = UINT64_C(0x44444444444444ff);
    CHECK(el2_map_block((uint64_t)(uintptr_t)l1, tcr, normal_only, base, base) == 1);
    CHECK(((l2[(base >> 21) & 0x1ff] >> 2) & 7) == 0);

    /* The level-0 start (T0SZ 16) still walks and writes: the same code path
     * with one more index above. */
    clear();
    l0[0] = (uint64_t)(uintptr_t)l1 | 3;
    CHECK(el2_map_block((uint64_t)(uintptr_t)l0, 16, mair, base, base) == 1);
    CHECK((l1[0] & 3) == 1);

    printf("PASS %u el2-map checks\n", checks);
    return 0;
}
