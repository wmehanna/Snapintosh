/* SPDX-License-Identifier: MIT */
/* compat/gic-layout.h: the host GIC geometry the monitor accepts from
 * struct secondary_config. Build: cc -Icompat tools/test-gic-layout.c */
#include "gic-layout.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
int main(void)
{
    /* The A16 (MADT, GICv4): the former hardcoded window, unchanged. */
    const uint64_t a16d = 0x17000000, a16f = 0x17080000, a16e = 0x17500000, a16s = 0x40000;
    CHECK(gic_layout_valid(a16d, a16f, a16e, a16s));
    for (uint64_t r = a16f; r < a16e; r += a16s) CHECK(gic_redistributor_valid(r, a16f, a16e, a16s));
    CHECK(!gic_redistributor_valid(a16f - a16s, a16f, a16e, a16s));
    CHECK(!gic_redistributor_valid(a16e, a16f, a16e, a16s));
    CHECK(!gic_redistributor_valid(a16f + a16s / 2, a16f, a16e, a16s));
    CHECK(!gic_redistributor_valid(a16f + 8, a16f, a16e, a16s));
    /* QEMU virt gic-version=3, six CPUs: GICD 0x08000000, frames from 0x080a0000 every 0x20000. */
    const uint64_t vd = 0x08000000, vf = 0x080a0000, ve = 0x080a0000 + 6 * 0x20000, vs = 0x20000;
    CHECK(gic_layout_valid(vd, vf, ve, vs));
    for (uint64_t r = vf; r < ve; r += vs) CHECK(gic_redistributor_valid(r, vf, ve, vs));
    CHECK(!gic_redistributor_valid(vf + 0x10000, vf, ve, vs));   /* an SGI frame, not a redistributor */
    CHECK(!gic_redistributor_valid(ve, vf, ve, vs));
    /* A virt frame is not an A16 frame and the reverse: no platform default leaks through. */
    CHECK(!gic_redistributor_valid(vf, a16f, a16e, a16s));
    CHECK(!gic_redistributor_valid(a16f, vf, ve, vs));
    /* Refused layouts. */
    CHECK(!gic_layout_valid(0, vf, ve, vs));
    CHECK(!gic_layout_valid(vd + 0x1000, vf, ve, vs));          /* distributor not 64 KiB aligned */
    CHECK(!gic_layout_valid(vd, 0, ve, vs));
    CHECK(!gic_layout_valid(vd, vf + 0x1000, ve + 0x1000, vs)); /* window not 64 KiB aligned */
    CHECK(!gic_layout_valid(vd, vf, ve, 0x10000));              /* neither GICv3 nor GICv4 stride */
    CHECK(!gic_layout_valid(vd, vf, ve, 0));
    CHECK(!gic_layout_valid(vd, vf, vf, vs));                   /* empty */
    CHECK(!gic_layout_valid(vd, ve, vf, vs));                   /* reversed */
    CHECK(!gic_layout_valid(vd, vf, ve + 0x10000, vs));         /* not whole frames */
    CHECK(!gic_layout_valid(vd, vf, vf + GIC_LAYOUT_SPAN_MAX + vs, vs));
    CHECK(gic_layout_valid(vd, vf, vf + GIC_LAYOUT_SPAN_MAX, vs));
    CHECK(!gic_layout_valid(vf, vf, ve, vs));                   /* distributor inside the window */
    CHECK(!gic_layout_valid(ve - 0x10000, vf, ve, vs));
    CHECK(gic_layout_valid(ve, vf, ve, vs));                    /* adjacent above is fine */
    CHECK(gic_layout_valid(vf - 0x10000, vf, ve, vs));          /* adjacent below is fine */
    CHECK(!gic_redistributor_valid(vf, vf, ve, 0));
    printf("PASS: %u gic layout checks\n", checks);
    return 0;
}
