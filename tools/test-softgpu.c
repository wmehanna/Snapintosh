/* SPDX-License-Identifier: MIT */
/* compat/softgpu.h: the monitor's allow-list for the SoftGPU device page (plans/p6-softgpu-integration.md W1).
 *   clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Ishadow -Icompat \
 *       tools/test-softgpu.c -o /tmp/test-softgpu && /tmp/test-softgpu */
#include <stdio.h>
#include <string.h>
#include "softgpu.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static int refused(struct softgpu_params p)
{
    struct stage2_range out[2];
    memset(out, 0x5a, sizeof out);
    int rows = softgpu_rows(&p, out);
    unsigned char untouched = 1;
    for (size_t i = 0; i < sizeof out; i++) untouched &= ((unsigned char *)out)[i] == 0x5a;
    return rows == -1 && untouched && !softgpu_window(&p, p.page0_pa);
}

int main(void)
{
    const struct softgpu_params good = {SOFTGPU_MAGIC, SOFTGPU_F_PAGE0, 0x0c000000ULL, 0x0c001000ULL, 144};
    CHECK(SOFTGPU_MAGIC == 0x3150475350414e53ULL && !memcmp(&good.magic, "SNAPSGP1", 8));
    struct stage2_range out[SOFTGPU_STAGE2_MAX + 1];
    memset(out, 0, sizeof out);
    CHECK(softgpu_rows(&good, out) == 1);
    /* one page, read-write Device-nGnRE, execute-never, identity */
    CHECK(out[0].lo == 0x0c000000ULL && out[0].hi == 0x0c001000ULL);
    CHECK(out[0].low == (S2_AP_RW | S2_ATTRS_DEVICE) && out[0].upper == S2_XN);
    CHECK(out[1].lo == 0 && out[1].hi == 0);                               /* exactly one row */
    /* page 1 is never reachable */
    CHECK(softgpu_window(&good, 0x0c000000ULL) && softgpu_window(&good, 0x0c000ffcULL));
    CHECK(!softgpu_window(&good, 0x0c001000ULL) && !softgpu_window(&good, 0x0bfffffcULL));
    /* anything else refuses and writes nothing */
    struct softgpu_params p = good; p.magic ^= 1; CHECK(refused(p));
    struct softgpu_params zero; memset(&zero, 0, sizeof zero); CHECK(refused(zero));    /* a loader without the block */
    p = good; p.flags = 0; CHECK(refused(p));
    p = good; p.flags = 3; CHECK(refused(p));
    p = good; p.page0_pa = 0; p.page1_pa = 0x1000; CHECK(refused(p));
    p = good; p.page0_pa += 0x800; p.page1_pa += 0x800; CHECK(refused(p));     /* unaligned */
    p = good; p.page1_pa = good.page0_pa + 0x2000; CHECK(refused(p));         /* page 1 elsewhere */
    p = good; p.page1_pa = good.page0_pa; CHECK(refused(p));
    p = good; p.page0_pa = 0x0bfff000ULL; p.page1_pa = 0x0c000000ULL; CHECK(refused(p));   /* below the bus window */
    p = good; p.page0_pa = 0x0e000000ULL; p.page1_pa = 0x0e001000ULL; CHECK(refused(p));   /* past the window */
    p = good; p.page0_pa = 0x0dfff000ULL; p.page1_pa = 0x0e000000ULL; CHECK(!refused(p));  /* last page in */
    p = good; p.page0_pa = 0x80000000ULL; p.page1_pa = 0x80001000ULL; CHECK(refused(p));   /* guest RAM side */
    p = good; p.page0_pa = 1ULL << 48; p.page1_pa = p.page0_pa + 0x1000; CHECK(refused(p));
    p = good; p.intid = 31; CHECK(refused(p));                                  /* a PPI */
    p = good; p.intid = 1020; CHECK(refused(p));                                /* special INTIDs */
    p = good; p.intid = 0; CHECK(refused(p));
    p = good; p.intid = 144; CHECK(!refused(p));
    printf("{\"softgpu_checks\":%u,\"softgpu_failures\":%u}\n", checks, failures);
    return failures != 0;
}
