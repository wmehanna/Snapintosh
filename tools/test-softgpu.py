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
import adreno  # noqa: E402

HEADER = ROOT / 'compat/softgpu.h'
FIXTURE = (ROOT / 'tools/fixtures/virt-softgpu.dtb').read_bytes()
MUTATIONS = (
    ('no magic check', 'p->magic == SOFTGPU_MAGIC && ', ''),
    ('no flags check', 'p->flags == SOFTGPU_F_PAGE0 && ', ''),
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
        for page0, intid in ((0, 144), (0x0C000800, 144), (0x0C000000, 31), (0x0C000000, 1020), (0x7_0C000000, 144)):
            with self.subTest(page0=page0, intid=intid), self.assertRaises(ValueError):
                adreno.SoftGpuSpec(page0, intid)


if __name__ == '__main__':
    unittest.main()
