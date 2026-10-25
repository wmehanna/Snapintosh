/* SPDX-License-Identifier: MIT */
#ifndef SNAP_VHE_TCR_H
#define SNAP_VHE_TCR_H
#include <stdint.h>
/* TCR_EL2 moved from its FEAT_VHE layout (HCR_EL2.E2H=1: the TCR_EL1 format)
 * to the non-VHE EL2 layout the monitor runs under (E2H=0), field by field
 * (Arm ARM, TCR_EL1 and TCR_EL2 register descriptions).
 *
 * Why: the A16's firmware enters EL2 with E2H=0 (q1n1 docs/A16-Q1N1-PROXY.md,
 * HCR_EL2 0x88000010), QEMU's AAVMF with E2H=1 and TGE=1 (snaplab, QEMU
 * 11.0.3 -cpu max: HCR_EL2 0x408000038, TCR_EL2 0x580803510). Clearing E2H
 * without this leaves AAVMF's value read in the non-VHE layout: PS=0 (4 GiB),
 * so the first walk of q1n1's tables above 4 GiB after a TLB flush takes an
 * address size fault at EL2 (snaplab run3: ESR_EL2 0x86000001, ELR = FAR = the
 * vector itself, looping). TTBR1 (EPD1, T1SZ, TG1, ...) has no non-VHE
 * counterpart and is dropped; so are EPD0 and bit 6, RES0 there. */
static inline uint64_t vhe_tcr_to_el2(uint64_t vhe)
{
    uint64_t el2 = vhe & 0xff3fULL;             /* T0SZ, IRGN0, ORGN0, SH0, TG0 */
    el2 |= ((vhe >> 32) & 7) << 16;             /* IPS    -> PS            */
    el2 |= ((vhe >> 37) & 1) << 20;             /* TBI0   -> TBI           */
    el2 |= ((vhe >> 39) & 3) << 21;             /* HA, HD -> HA, HD        */
    el2 |= ((vhe >> 41) & 1) << 24;             /* HPD0   -> HPD           */
    el2 |= ((vhe >> 43) & 0xf) << 25;           /* HWU059..062             */
    el2 |= ((vhe >> 51) & 1) << 29;             /* TBID0  -> TBID          */
    el2 |= ((vhe >> 57) & 1) << 30;             /* TCMA0  -> TCMA          */
    el2 |= ((vhe >> 59) & 1) << 32;             /* DS     -> DS            */
    return el2 | (1ULL << 23) | (1ULL << 31);   /* RES1 in the EL2 layout  */
}
/* A TCR_EL2 value valid in BOTH layouts, written before E2H changes.
 *
 * Why: QEMU applies an HCR_EL2.E2H write at the end of its translation block
 * (the EL2 MMU index changes), so the next fetch already walks with the new
 * layout; writing HCR_EL2 and TCR_EL2 back to back before one ISB is not
 * enough (snaplab run4: same fault, X30 just past the conversion call, TCR_EL2
 * still AAVMF's). The architecture allows that: an MSR may act before the ISB.
 *
 * Non-VHE view: T0SZ..TG0 unchanged, PS (18:16) = the entry IPS, bits 32 (DS)
 * and 33 (MTX) clear, RES1 23/31 set. VHE view: the same TTBR0 walk and
 * IPS (34:32) = 0b100, 44 bits, the only encoding of at least 44 bits that
 * leaves 32 and 33 clear. The TTBR1 fields are unused there (EPD1, bit 23,
 * set; 31 with 30 clear is TG1 = 4 KiB): A1, IRGN1, ORGN1 and SH1 are
 * cleared and T1SZ carries PS in its low bits. Returns 0, no bridge, when
 * TTBR1 walks are enabled or the entry IPS is below 44 bits. */
static inline uint64_t vhe_tcr_bridge(uint64_t vhe)
{
    uint64_t ips = (vhe >> 32) & 7;
    if (!((vhe >> 23) & 1) || ips < 4) return 0;
    uint64_t v = vhe & ~(0x7fff0000ULL | (7ULL << 32));
    return v | (ips << 16) | (1ULL << 23) | (1ULL << 31) | (4ULL << 32);
}
#endif
