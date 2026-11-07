#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SoftGPU wave W1 offline (plans/p6-softgpu-integration.md): the monitor's allow-list, the QEMU dumpdtb parser on a
checked-in tree, the loader's words and the monitor source guards.

    python3 tools/test-softgpu.py

No target and no firmware: tools/fixtures/virt-softgpu.dtb is `qemu-system-aarch64 -machine
virt,virtualization=on,gic-version=3,dumpdtb=... -device ramfb -device snap-softgpu` (qemu-softgpu 4001a49, 32G memfd),
trimmed to its used size. The image-level checks (ADT reg, ranges, stage 2) are in tools/test-adreno-image.py.
"""
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
import adreno  # noqa: E402

HEADER = ROOT / 'compat/softgpu.h'
FIXTURE = (ROOT / 'tools/fixtures/virt-softgpu.dtb').read_bytes()
MUTATIONS = (
    ('no magic check', 'p->magic == SOFTGPU_MAGIC && ', ''),
    ('no flags check', 'p->flags == SOFTGPU_F_PAGE0 && ', ''),
    ('no window check', 'p->page0_pa >= SOFTGPU_WINDOW_LO && p->page0_pa + SOFTGPU_PAGE <= SOFTGPU_WINDOW_HI &&', ''),
    ('no alignment check', ' && !(p->page0_pa & (SOFTGPU_PAGE - 1))', ''),
    ('page 1 anywhere', 'p->page1_pa == p->page0_pa + SOFTGPU_PAGE &&', ''),
    ('any interrupt', ' &&\n           p->intid >= SOFTGPU_INTID_FIRST && p->intid <= SOFTGPU_INTID_LAST', ''),
    ('read-only', 'S2_AP_RW | S2_ATTRS_DEVICE', 'S2_AP_RO | S2_ATTRS_DEVICE'),
    ('executable', 'S2_ATTRS_DEVICE, S2_XN}', 'S2_ATTRS_DEVICE, 0}'),
    ('page 1 mapped', 'p->page0_pa + SOFTGPU_PAGE, S2_AP_RW', 'p->page0_pa + 2 * SOFTGPU_PAGE, S2_AP_RW'),
)


def compile_c(work, header_dir=None):
    out = work / 'test-softgpu'
    include = [f'-I{header_dir}'] if header_dir else []
    result = subprocess.run(['cc', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror',
                             *include, '-Ishadow', '-Icompat', 'tools/test-softgpu.c', '-o', str(out)], cwd=ROOT,
                            capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return subprocess.run([str(out)], capture_output=True, text=True)


class Monitor(unittest.TestCase):
    def test_host_model(self):
        with tempfile.TemporaryDirectory() as work:
            run = compile_c(Path(work))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('"softgpu_failures":0', run.stdout)

    def test_weakened_header_fails(self):
        text = HEADER.read_text()
        for name, old, new in MUTATIONS:
            with self.subTest(name), tempfile.TemporaryDirectory() as work:
                self.assertIn(old, text, name)
                (Path(work) / 'softgpu.h').write_text(text.replace(old, new, 1))
                self.assertNotEqual(compile_c(Path(work), work).returncode, 0, name)

    def test_constants_match_the_loader(self):
        text = HEADER.read_text()
        define = lambda name: int(re.search(rf'#define {name}\s+(0x[0-9a-fA-F]+|\d+)', text).group(1), 0)
        self.assertEqual(define('SOFTGPU_MAGIC'), adreno.SOFTGPU_MAGIC)
        self.assertEqual(define('SOFTGPU_F_PAGE0'), adreno.SOFTGPU_F_PAGE0)
        self.assertEqual(define('SOFTGPU_PARAMS_WORDS'), adreno.SOFTGPU_PARAMS_WORDS)
        self.assertEqual(define('SOFTGPU_PAGE'), adreno.SOFTGPU_PAGE)
        self.assertEqual((define('SOFTGPU_INTID_FIRST'), define('SOFTGPU_INTID_LAST')),
                         (adreno.SOFTGPU_INTID_FIRST, adreno.SOFTGPU_INTID_LAST))
        self.assertEqual(define('SOFTGPU_STAGE2_MAX'), 1)
        fields = re.search(r'struct softgpu_params \{(.*?)\n\};', text, re.S).group(1)
        self.assertEqual(re.findall(r'uint64_t (\w+);', fields), ['magic', 'flags', 'page0_pa', 'page1_pa', 'intid'])

    def test_monitor_source(self):
        src = read_source(ROOT / 'probes/xnuboot.c')
        self.assertIn('#ifndef SNAP_SOFTGPU\n#define SNAP_SOFTGPU 0\n#endif', src)
        self.assertEqual(src.count('#include "../compat/softgpu.h"'), 1)
        self.assertIn(f'#define PARAMS_WORDS {1154}', src)                  # struct params unchanged
        stage2 = read_source(ROOT / 'probes/xnuboot/stage2.c')
        self.assertIn('if (rows < 0) return -44;', stage2)
        for path, uses in ((ROOT / 'probes/xnuboot/stage2.c', ('softgpu_rows(', 'softgpu_block(')),
                           (ROOT / 'probes/xnuboot/sptm_dispatch.c', ('softgpu_window(', 'softgpu_block(')),
                           (ROOT / 'probes/xnuboot/report_layout.c', ('softgpu_block(',))):
            text = read_source(path)
            for use in uses:
                for at in [m.start() for m in re.finditer(re.escape(use), text)]:
                    # the closest preprocessor block opened before the use is SNAP_SOFTGPU's, still open
                    self.assertLess(text.rfind('#endif', 0, at), text.rfind('#if SNAP_SOFTGPU', 0, at), (path.name, use))

    def test_every_opt_in_combination_compiles(self):
        """The stage-2 range array is sized from named constants: it builds with the define absent, 0 and every
        opt-in block at once (the case that overflowed the old four-way #if ladder is the one that needs a new row)."""
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('clang not present')
        base = [clang, '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only', '-Ishadow',
                '-Icompat', '-fsyntax-only', '-Wall', '-Wextra', '-Werror', 'probes/xnuboot.c']
        for defines in ([], ['-DSNAP_SOFTGPU=0'], ['-DSNAP_SOFTGPU=1'],
                        ['-DSNAP_SOFTGPU=1', '-DSNAP_I2C_INPUT=1', '-DSNAP_QCC2072_WIFI=1', '-DSNAP_DISPLAY_TIMING=1']):
            with self.subTest(defines=defines):
                run = subprocess.run(base[:-1] + defines + base[-1:], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr[-2000:])

    def test_struct_params_is_unchanged(self):
        """The block is appended after struct params: its size and offsets do not move with the define."""
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('clang not present')
        sizes = set()
        for define in ('-DSNAP_SOFTGPU=0', '-DSNAP_SOFTGPU=1'):
            out = subprocess.run([clang, '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                                  '-Ishadow', '-Icompat', define, '-Xclang', '-fdump-record-layouts', '-fsyntax-only',
                                  'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True, check=True).stdout
            block = next(b for b in out.split('*** Dumping AST Record Layout') if re.search(r'^\s*0 \| struct params\n', b))
            sizes.add(re.findall(r'\[sizeof=(\d+),', block)[0])
        self.assertEqual(len(sizes), 1)


SOURCE = ROOT / 'compat/softgpu.c'
WINDOW_MUTATIONS = (
    ('device rows are DMA targets', 'if ((r->low & MEMATTR_MASK) != S2_MEMATTR_NORMAL) return 0;', ''),
    ('read-only rows are writable', 'if ((r->low & S2AP_MASK) == S2_AP_RO) return SOFTGPU_PERM_READ;',
     'if ((r->low & S2AP_MASK) == S2_AP_RO) return SOFTGPU_PERM_READ | SOFTGPU_PERM_WRITE;'),
    ('write-only rows are readable', 'return 0;                   /* S2AP none', 'return SOFTGPU_PERM_READ;                   /* S2AP none'),
    ('a cut can widen', 'perm &= cuts[i].keep;', 'perm |= cuts[i].keep;'),
    ('a cut is not widened outward', 'clo[i] = cuts[i].lo & ~PAGE_MASK;', 'clo[i] = cuts[i].lo;'),
    ('read-only runs merge into read-write windows', ' && seg[nseg - 1].flags == perm) {', ') {'),
    ('the drop rule drops writable runs', 'if (seg[i].flags == SOFTGPU_PERM_READ && (pick', 'if ((pick'),
    ('too many writable runs are tolerated', 'if (pick == nseg) return SOFTGPU_E_TOO_MANY;', 'if (pick == nseg) break;'),
    ('overlapping rows are accepted', 'if (r->lo < rows[j].hi && rows[j].lo < r->hi) return SOFTGPU_E_ARG;', ''),
    ('applied is not awaited', 'while (ops->rd(ops->ctx, p1 + SOFTGPU_MON_GEN_APPLIED) != m->gen)', 'while (0)'),
    ('the table is not read back', 'if (!same) {', 'if (0) {'),
    ('a failure leaves the windows', 'ops->wr(ops->ctx, m->page1 + SOFTGPU_MON_WINDOW_COUNT, 0);\n    m->gen++;', 'm->gen++;'),
    ('a failed device takes another table', 'if (m->failed) return SOFTGPU_E_DEVICE;\n    if (n > ', 'if (n > '),
    ('lock is not read back', '!= 1) { m->failed = 1; return SOFTGPU_E_LOCK; }', '!= 1) { }'),
    ('unsorted tables are programmed', ' ||\n            (i && w[i].ipa_base < w[i - 1].ipa_base + w[i - 1].size)) return SOFTGPU_E_ARG;', ') return SOFTGPU_E_ARG;'),
    ('a secure line is routed', 'if (!((ops->rd(ops->ctx, pri) >> shift) & 0xffu)) return SOFTGPU_E_ARG;', ''),
    ('stale rows survive a smaller table', 'for (unsigned i = n; i < m->nwin; i++)', 'for (unsigned i = n; i < 0; i++)'),
)


def build_windows(work, source, extra=()):
    out = work / 'test-softgpu-windows'
    result = subprocess.run(['cc', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror', *extra,
                             '-Ishadow', '-Icompat', 'tools/test-softgpu-windows.c', str(source), '-o', str(out)], cwd=ROOT,
                            capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return subprocess.run([str(out)], capture_output=True, text=True)


class Windows(unittest.TestCase):
    """W5: compat/softgpu.c derives the device's DMA windows from the stage-2 rows and proves them on the device."""

    def test_host_model(self):
        for extra in ((), ('-DSOFTGPU_WINDOWS_MAX=8u',)):          # the second reaches the over-the-limit rules
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as work:
                run = build_windows(Path(work), SOURCE, extra)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn('"softgpu_windows_failures":0', run.stdout)

    def test_weakened_source_fails(self):
        text = SOURCE.read_text()
        for name, old, new in WINDOW_MUTATIONS:
            with self.subTest(name), tempfile.TemporaryDirectory() as work:
                self.assertIn(old, text, name)
                mutant = Path(work) / 'softgpu.c'
                mutant.write_text(text.replace(old, new, 1).replace('#include "softgpu.h"', f'#include "{ROOT}/compat/softgpu.h"'))
                bad = False
                for extra in ((), ('-DSOFTGPU_WINDOWS_MAX=8u',)):
                    try:
                        bad |= build_windows(Path(work), mutant, extra).returncode != 0
                    except AssertionError:
                        bad = True
                self.assertTrue(bad, name)

    def test_limits_match_the_device(self):
        text = (ROOT / 'compat/softgpu.h').read_text()
        self.assertRegex(text, r'#ifndef SOFTGPU_WINDOWS_MAX[^\n]*\n#define SOFTGPU_WINDOWS_MAX\s+64u\n#endif')
        proto = (ROOT / 'compat/softgpu_protocol.h').read_text()
        self.assertIn('SGPU_MREG_WINDOW0=0x100', proto.replace(' ', ''))
        for name, value in (('SOFTGPU_MON_MAGIC', '0x4e4f4d53u'), ('SOFTGPU_MON_WINDOW_COUNT', '0x004u'), ('SOFTGPU_MON_LOCK', '0x008u'),
                            ('SOFTGPU_MON_GEN', '0x014u'), ('SOFTGPU_MON_GEN_APPLIED', '0x018u'), ('SOFTGPU_MON_WINDOW0', '0x100u')):
            self.assertRegex(text, rf'#define {name}\s+{value}')

    def test_monitor_wiring(self):
        glue = read_source(ROOT / 'probes/xnuboot/gpu_glue.c')
        dispatch = read_source(ROOT / 'probes/xnuboot/sptm_dispatch.c')
        # LOCKDOWN: the device is narrowed first, stage 2 second (spec 1.3), and a refusal stops before the seal
        lock = dispatch[dispatch.index('case SPTM_FN_LOCKDOWN:'):]
        self.assertLess(lock.index('softgpu_lockdown(c)'), lock.index('const_region_seal(c)'))
        self.assertRegex(lock, r'softgpu_lockdown\(c\)\) \{\s*record\(c,EV_MAP_FAILED[^;]*;\s*return 0;')
        self.assertIn('#if SNAP_SOFTGPU', dispatch[dispatch.rindex('#if', 0, dispatch.index('softgpu_lockdown(c)')):])
        # the boot windows come from the same rows stage 2 maps, are programmed before LOCK, and LOCK before the route
        self.assertIn('return stage2_base_rows(c,rows);', glue)
        prepare = glue[glue.index('static int64_t softgpu_prepare'):glue.index('static int softgpu_lockdown')]
        self.assertLess(prepare.index('softgpu_windows_apply(c,0)'), prepare.index('softgpu_mon_lock('))
        self.assertLess(prepare.index('softgpu_mon_lock('), prepare.index('softgpu_gic_route('))
        self.assertIn('softgpu_windows_apply(c,0) || softgpu_mon_lock', prepare)
        # monitor memory, the trust cache, the write-watch page, the handoff pages and (after LOCKDOWN) the const region
        cuts = glue[glue.index('static unsigned softgpu_windows_cuts'):glue.index('static int softgpu_windows_apply')]
        for needle in ('c->work_base,c->work_end,0', 'p->trust_cache.pa', 'p->write_watch_pa', 'p->watch_pa,p->watch_pa+p->watch_count*0x1000,0',
                       'if(const_ro)', 'p->const_begin,p->const_end,SOFTGPU_PERM_READ'):
            self.assertIn(needle, cuts)
        # the interrupt: the SoftGPU SPI replaces the Adreno line on AIC 975, and async.c matches the same INTID
        self.assertIn('irqfwd_add(&c->gpu.irq,(uint32_t)GPU_FWD_INTID(c),ADRENO_AIC_IRQ)', glue)
        self.assertIn('pending == GPU_FWD_INTID(c)', read_source(ROOT / 'probes/xnuboot/async.c'))
        # the windows go when the guest's memory is handed back
        quiesce = glue[glue.index('static int gpu_quiesce'):]
        self.assertLess(quiesce.index('softgpu_close(c)'), quiesce.index('ADRENO_S_ADOPTED'))
        # page 1 is EL2-mapped, never given to the guest
        self.assertIn('el2_map_softgpu(softgpu_block(p)->page1_pa)', read_source(ROOT / 'probes/xnuboot/prepare.c'))
        self.assertNotIn('page1_pa', read_source(ROOT / 'probes/xnuboot/stage2.c'))
        # the unsupported combination is a build error
        main = read_source(ROOT / 'probes/xnuboot.c')
        self.assertIn('#if SNAP_SOFTGPU && SNAP_USER_HW_WALK_S2RO\n/*', main)
        self.assertIn('#error "SNAP_SOFTGPU does not support SNAP_USER_HW_WALK_S2RO', main)

    def test_build_flag_selects_the_unit(self):
        self.assertIn("('-DSNAP_SOFTGPU=1', 'compat/softgpu.c')", read_source(ROOT / 'probes/run.py'))

    def test_hw_walk_with_softgpu_is_refused(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('clang not present')
        run = subprocess.run([clang, '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only', '-Ishadow', '-Icompat',
                              '-fsyntax-only', '-DSNAP_SOFTGPU=1', '-DSNAP_USER_HW_WALK=1', 'probes/xnuboot.c'],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('SNAP_SOFTGPU does not support SNAP_USER_HW_WALK_S2RO', run.stderr)


class Parser(unittest.TestCase):
    def test_fixture(self):
        spec = adreno.softgpu_from_dtb(FIXTURE)
        self.assertEqual(spec, adreno.SoftGpuSpec(0x0C000000, 144))           # plan 3.2: page 0, SPI 112 = INTID 144
        self.assertEqual((spec.page1, spec.child), (0x0C001000, 0x7_0C000000))

    def test_missing_node_refuses(self):
        for text in (b'snapintosh,softgpu', ):
            blob = FIXTURE.replace(text, b'snapintosh,softgpx')
            with self.assertRaisesRegex(ValueError, '0 snapintosh,softgpu nodes'):
                adreno.softgpu_from_dtb(blob)
        with self.assertRaises(ValueError):
            adreno.softgpu_from_dtb(b'')
        with self.assertRaises(ValueError):
            adreno.softgpu_from_dtb(b'\0' * 64)

    def test_hostile_trees_are_value_errors(self):
        import struct as st
        hdr = lambda body: st.pack('>10I', 0xD00DFEED, 40 + len(body) + 8, 40, 40 + len(body), 40, 17, 16, 0, 8, len(body)) + body + b'\0' * 8
        for body in (st.pack('>I', 3) + b'\0' * 8, st.pack('>3I', 1, 2, 9), b'\0' * 7):
            with self.subTest(body=body), self.assertRaises(ValueError):
                adreno.softgpu_from_dtb(hdr(body))

    def test_truncated_refuses(self):
        for cut in (8, 40, len(FIXTURE) // 2, len(FIXTURE) - 8):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                adreno.softgpu_from_dtb(FIXTURE[:cut])

    def test_two_devices_refuse(self):
        root = adreno.parse_fdt(FIXTURE)
        node = next(n for n in adreno._walk(root) if b'snapintosh,softgpu' in n['props'].get('compatible', b''))
        node['parent']['children'].append(dict(node, props=dict(node['props']), children=[]))
        with mock.patch.object(adreno, 'parse_fdt', return_value=root), self.assertRaisesRegex(ValueError, '2 snapintosh'):
            adreno.softgpu_from_dtb(FIXTURE)

    def edit(self, **props):
        """The fixture with one reg/interrupts property of the device node rewritten in place (same length)."""
        root = adreno.parse_fdt(FIXTURE)
        node = next(n for n in adreno._walk(root) if b'snapintosh,softgpu' in n['props'].get('compatible', b''))
        blob = bytearray(FIXTURE)
        for name, new in props.items():
            old = node['props'][name]
            assert len(old) == len(new)
            at = bytes(blob).index(old)
            blob[at:at + len(old)] = new
        return bytes(blob)

    def test_layouts_refuse(self):
        reg = struct.pack('>4I', 0x0, 0x1000, 0x1000, 0x1000)
        self.assertEqual(adreno.softgpu_from_dtb(self.edit(reg=reg)).page0, 0x0C000000)      # the control
        with self.assertRaisesRegex(ValueError, 'adjacent'):
            adreno.softgpu_from_dtb(self.edit(reg=struct.pack('>4I', 0x0, 0x1000, 0x3000, 0x1000)))
        with self.assertRaisesRegex(ValueError, 'adjacent'):
            adreno.softgpu_from_dtb(self.edit(reg=struct.pack('>4I', 0x0, 0x1000, 0x1000, 0x2000)))
        with self.assertRaisesRegex(ValueError, 'outside'):
            adreno.softgpu_from_dtb(self.edit(reg=struct.pack('>4I', 0x0, 0x1000, 0x4000000, 0x1000)))
        with self.assertRaisesRegex(ValueError, 'SPI'):
            adreno.softgpu_from_dtb(self.edit(interrupts=struct.pack('>3I', 1, 112, 4)))
        self.assertEqual(adreno.softgpu_from_dtb(self.edit(interrupts=struct.pack('>3I', 0, 200, 4))).intid, 232)
        with self.assertRaises(ValueError):
            adreno.softgpu_from_dtb(self.edit(interrupts=struct.pack('>3I', 0, 2000, 4)))      # INTID past the SPI range


class Prepass(unittest.TestCase):
    """probes/run.py: the dumpdtb pre-pass runs the board's own QEMU command line and refuses without the device."""

    @staticmethod
    def qemu(script):
        import os
        import stat
        import run
        work = Path(tempfile.mkdtemp())
        fake = work / 'qemu'
        fake.write_text(script)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        q = object.__new__(run.Qemu)
        q.drive, q.sock = 'format=raw,file=fat:rw:/nonexistent', str(work / 'sock')
        return run, q, fake, work

    def test_command_line(self):
        run, q, fake, work = self.qemu('#!/bin/sh\n')
        with mock.patch.object(run, 'QEMU', str(fake)), mock.patch.dict('os.environ', {'SNAP_QEMU_ARGS': '-device snap-softgpu'}):
            plain, dump = q.command(), q.command(',dumpdtb=/x.dtb')
        self.assertEqual(plain[:3], [str(fake), '-machine', 'virt,virtualization=on,gic-version=3'])
        self.assertEqual(dump[2], 'virt,virtualization=on,gic-version=3,dumpdtb=/x.dtb')
        self.assertEqual(plain[3:], dump[3:])                          # every other argument is the board's own
        self.assertEqual(plain[-2:], ['-device', 'snap-softgpu'])

    def test_dumpdtb_and_parse(self):
        fixture = ROOT / 'tools/fixtures/virt-softgpu.dtb'
        run, q, fake, work = self.qemu(f'#!/bin/sh\nfor a in "$@"; do case "$a" in *dumpdtb=*) cp {fixture} "${{a##*dumpdtb=}}";; esac; done\n')
        with mock.patch.object(run, 'QEMU', str(fake)):
            self.assertEqual(run.softgpu_prepass(q), adreno.SoftGpuSpec(0x0C000000, 144))

    def test_no_device_refuses(self):
        fixture = ROOT / 'tools/fixtures/virt-softgpu.dtb'
        run, q, fake, work = self.qemu(f'#!/bin/sh\nfor a in "$@"; do case "$a" in *dumpdtb=*) sed s/snapintosh,softgpu/snapintosh,nothing/ {fixture} > "${{a##*dumpdtb=}}";; esac; done\n')
        with mock.patch.object(run, 'QEMU', str(fake)), self.assertRaisesRegex(ValueError, 'not one'):
            run.softgpu_prepass(q)

    def test_qemu_failure_refuses(self):
        run, q, fake, work = self.qemu('#!/bin/sh\necho boom >&2\nexit 1\n')
        with mock.patch.object(run, 'QEMU', str(fake)), self.assertRaisesRegex(ValueError, 'dumpdtb failed'):
            run.softgpu_prepass(q)

    def test_env_needs_qemu_and_one(self):
        src = read_source(ROOT / 'probes/run.py')
        self.assertIn("ap.error('SNAP_SOFTGPU must be 1')", src)
        self.assertIn("if not args.qemu or args.probe != 'xnuboot':", src)
        self.assertIn("return verdict(EXIT_LOADER, f'SNAP_SOFTGPU=1 refused: {error}')", src)
        self.assertIn('xb.SOFTGPU = SOFTGPU_SPEC', src)


class Loader(unittest.TestCase):
    SPEC = adreno.SoftGpuSpec(0x0C000000, 144)

    def test_words_rows_and_audit(self):
        words = adreno.softgpu_params_words(self.SPEC)
        self.assertEqual(words, [adreno.SOFTGPU_MAGIC, 1, 0x0C000000, 0x0C001000, 144])
        self.assertEqual(adreno.softgpu_rows(words), [(0x0C000000, 0x0C001000)])
        self.assertEqual(adreno.softgpu_audit_ranges(words), [(0x0C000000, 0x0C001000, 0x7C4, 1 << 54)])
        for bad in ([0] * 5, [words[0], 3] + words[2:], [words[0], 1, 0x0C000800, 0x0C001800, 144],
                    [words[0], 1, 0x0C000000, 0x0C002000, 144], [words[0], 1, 0x0C000000, 0x0C001000, 31],
                    [words[0], 1, 0x0C000000, 0x0C001000, 1020], words[:4], []):
            self.assertIsNone(adreno.softgpu_rows(bad), bad)
            self.assertEqual(adreno.softgpu_audit_ranges(bad), [])
        self.assertEqual(adreno.softgpu_stage2_ranges(None), [])
        self.assertEqual(adreno.softgpu_stage2_ranges(self.SPEC),
                         [(0x0C000000, 0x0C001000, 'rw', 'SoftGPU page 0 (Device-nGnRE)')])

    def test_spec_refusals(self):
        for page0, intid in ((0, 144), (0x0C000800, 144), (0x0C000000, 31), (0x0C000000, 1020), (0x7_0C000000, 144), (0x0E000000, 144), (0x0BFFF000, 144), (0x80000000, 144)):
            with self.subTest(page0=page0, intid=intid), self.assertRaises(ValueError):
                adreno.SoftGpuSpec(page0, intid)


if __name__ == '__main__':
    unittest.main()
