#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acceptance tests for the QEMU full-size panel support."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import qemu_panel as qp


def make_fw_cfg_directory(files):
    """Build a synthetic directory in the format consumed by find_file."""
    directory = bytearray(struct.pack('>I', len(files)))
    for selector, name in files:
        raw = name.encode('ascii') + b'\0'
        directory.extend(struct.pack('>IHH56s', 0, selector, 0,
                                     raw.ljust(56, b'\0')))
    return bytes(directory)


class FakeProxy:
    """Minimal memory proxy with an emulated QEMU fw_cfg DMA device."""

    def __init__(self, directory, ramfb_selector,
                 fw_cfg=qp.FW_CFG_BASE):
        self.base = 0x10000000
        self.memory = bytearray(1 << 20)
        self.directory = bytes(directory)
        self.files = {ramfb_selector: b''}
        self.ramfb_selector = ramfb_selector
        self.fw_cfg = fw_cfg
        self.write32_calls = []
        self.memset_calls = []
        self.dma_calls = []
        self.ramfb_configs = []
        self.end_live_calls = 0
        self._dma_high = None
        self._dma_low = None

    def _offset(self, address, size):
        offset = address - self.base
        if offset < 0 or size < 0 or offset + size > len(self.memory):
            raise AssertionError(f'invalid fake memory access at {address:#x}')
        return offset

    def writemem(self, address, data):
        data = bytes(data)
        offset = self._offset(address, len(data))
        self.memory[offset:offset + len(data)] = data

    def readmem(self, address, size, live=False):
        offset = self._offset(address, size)
        return bytes(self.memory[offset:offset + size])

    def write32(self, address, value):
        value &= 0xffffffff
        self.write32_calls.append((address, value))
        if address == self.fw_cfg + 0x10:
            self._dma_high = value
        elif address == self.fw_cfg + 0x14:
            self._dma_low = value
            self._run_dma()

    def memset32(self, address, value, size):
        self.memset_calls.append((address, value, size))
        offset = self._offset(address, size)
        pattern = struct.pack('<I', value & 0xffffffff)
        self.memory[offset:offset + size] = (
            pattern * ((size + 3) // 4))[:size]

    def end_live(self):
        self.end_live_calls += 1

    @staticmethod
    def _swap32(value):
        return int.from_bytes((value & 0xffffffff).to_bytes(4, 'little'),
                              'big')

    def _run_dma(self):
        if self._dma_high is None or self._dma_low is None:
            raise AssertionError('fw_cfg DMA trigger is incomplete')
        scratch = ((self._swap32(self._dma_high) << 32) |
                   self._swap32(self._dma_low))
        offset = self._offset(scratch, 16)
        control, length, address = struct.unpack_from('>IIQ', self.memory,
                                                       offset)
        selector = control >> 16
        flags = control & 0xffff
        status = 0

        if not (flags & qp.DMA_SELECT):
            status = 1
        elif flags & qp.DMA_READ:
            if selector == qp.FW_CFG_FILE_DIR:
                data = self.directory
            else:
                data = self.files.get(selector)
            if data is None:
                status = 1
            else:
                self.writemem(address, data[:length].ljust(length, b'\0'))
        elif flags & qp.DMA_WRITE:
            if selector not in self.files:
                status = 1
            else:
                data = self.readmem(address, length)
                self.files[selector] = data
                if selector == self.ramfb_selector:
                    self.ramfb_configs.append((address, data))
        else:
            status = 1

        status_offset = self._offset(scratch, 4)
        self.memory[status_offset:status_offset + 4] = struct.pack('>I', status)
        self.dma_calls.append((control, length, address, selector, status))


class QemuPanelTests(unittest.TestCase):
    def test_requested_parses_supported_geometry(self):
        self.assertIsNone(qp.requested({}))
        self.assertIsNone(qp.requested({qp.ENV: ''}))
        self.assertIsNone(qp.requested({qp.ENV: '   \t'}))
        self.assertEqual(qp.requested({qp.ENV: '2880x1800'}),
                         (2880, 1800))
        self.assertEqual(qp.requested({qp.ENV: '  800x600  '}),
                         (800, 600))
        self.assertEqual(qp.requested({qp.ENV: '16x16000'}),
                         (16, 16000))

    def test_requested_refuses_malformed_geometry(self):
        for text in ('2880', '2880X1800', '2880x', 'x1800', '-1x10',
                     '10x-1', '10.5x20', '10x20.5', '10x20x30',
                     '10 x 20', '10x20junk', 'junk'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    qp.requested({qp.ENV: text})

    def test_requested_refuses_geometry_outside_limits(self):
        for width, height in ((qp.MIN_SIDE - 1, 16),
                              (16, qp.MIN_SIDE - 1),
                              (qp.MAX_SIDE + 1, 16),
                              (16, qp.MAX_SIDE + 1)):
            with self.subTest(width=width, height=height):
                with self.assertRaisesRegex(ValueError, qp.ENV):
                    qp.requested({qp.ENV: f'{width}x{height}'})

    def test_allocation_rounds_pixels_and_scratch_to_alignment(self):
        # 1024x496 pixels plus the scratch are exactly 2 MiB; one more row spills.
        self.assertEqual(qp.allocation(1024, 496), qp.ALIGN)
        self.assertEqual(qp.allocation(1024, 497), 2 * qp.ALIGN)
        self.assertEqual(qp.allocation(2880, 1800), 20 << 20)

        width, height = 800, 600
        raw = width * 4 * height + qp.SCRATCH
        expected = (raw + qp.ALIGN - 1) & -qp.ALIGN
        self.assertEqual(qp.allocation(width, height), expected)
        self.assertEqual(qp.allocation(width, height) % qp.ALIGN, 0)
        self.assertGreaterEqual(qp.allocation(width, height), raw)

    def test_place_reserves_top_of_highest_span(self):
        free = [(0x01000000, 0x01200000),
                (0x02000000, 0x02400000)]
        size = 0x00200000
        self.assertEqual(qp.place(free, size), 0x02200000)

    def test_place_refuses_when_no_span_holds_panel(self):
        free = [(0x01000000, 0x01200000),
                (0x02000000, 0x02200000)]
        with self.assertRaisesRegex(ValueError, 'no firmware-free span'):
            qp.place(free, 0x00400000)
        with self.assertRaisesRegex(ValueError, 'no firmware-free span'):
            qp.place([], 0x00200000)

    def test_describe_replaces_gop_geometry_and_preserves_other_fields(self):
        original = {
            'marker': 'preserved',
            'fb_base': 0xf9a20000,
            'fb_size': 800 * 600 * 4,
            'fb_width': 800,
            'fb_height': 600,
            'fb_stride': 800,
            'fb_format': 1,
        }
        base, width, height = 0x12000000, 320, 200
        described = qp.describe(original, base, width, height)

        self.assertEqual(described['marker'], 'preserved')
        self.assertEqual(described['fb_base'], base)
        self.assertEqual(described['fb_size'], width * 4 * height)
        self.assertEqual(described['fb_width'], width)
        self.assertEqual(described['fb_height'], height)
        self.assertEqual(described['fb_stride'], width)
        self.assertEqual(described['fb_format'], 1)
        self.assertEqual(described['qemu_panel'],
                         (base, qp.allocation(width, height)))
        self.assertNotIn('qemu_panel', original)
        self.assertEqual(original['fb_base'], 0xf9a20000)

    def test_excluded_returns_reserved_panel_span(self):
        self.assertEqual(qp.excluded({}), [])
        self.assertEqual(qp.excluded({'qemu_panel': None}), [])

        base, size = 0x12000000, 3 * qp.ALIGN
        self.assertEqual(qp.excluded({'qemu_panel': (base, size)}),
                         [(base, base + size)])

    def test_ramfb_config_has_expected_big_endian_layout(self):
        address = 0x123456789abcdef0
        width, height = 2880, 1800
        encoded = qp.ramfb_config(address, width, height)
        expected = struct.pack('>QIIIII', address, qp.XRGB8888, 0,
                               width, height, width * 4)
        self.assertEqual(encoded, expected)
        self.assertEqual(len(encoded), 28)
        self.assertEqual(struct.unpack('>QIIIII', encoded),
                         (address, 0x34325258, 0, 2880, 1800, 11520))

    def test_dma_access_has_expected_big_endian_layout(self):
        control = 0x12345678
        length = 0x10203040
        address = 0x123456789abcdef0
        encoded = qp.dma_access(control, length, address)
        expected = struct.pack('>IIQ', control, length, address)
        self.assertEqual(encoded, expected)
        self.assertEqual(len(encoded), 16)
        self.assertEqual(struct.unpack('>IIQ', encoded),
                         (control, length, address))

    def test_find_file_locates_selector_in_synthetic_directory(self):
        directory = make_fw_cfg_directory((
            (0x0021, 'etc/other'),
            (0x1234, 'etc/ramfb'),
        ))
        self.assertEqual(qp.find_file(directory, 'etc/ramfb'), 0x1234)
        self.assertEqual(qp.find_file(directory, 'etc/other'), 0x0021)
        with self.assertRaisesRegex(ValueError, 'has no etc/missing'):
            qp.find_file(directory, 'etc/missing')

    def test_find_file_refuses_truncated_directory(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            qp.find_file(b'\0\0\0', 'etc/ramfb')

        directory = bytearray(make_fw_cfg_directory(((0x1234, 'etc/ramfb'),)))
        directory[:4] = struct.pack('>I', 2)      # claims a second entry it does not hold
        with self.assertRaisesRegex(ValueError, 'beyond'):
            qp.find_file(bytes(directory), 'etc/ramfb')

    def test_program_uses_fw_cfg_dma_to_configure_ramfb(self):
        width, height = 64, 32
        base = 0x10000000
        selector = 0x1234
        directory = make_fw_cfg_directory((
            (0x0021, 'etc/other'),
            (selector, 'etc/ramfb'),
        ))
        info = qp.describe({'marker': 'panel'}, base, width, height)
        proxy = FakeProxy(directory, selector)

        self.assertEqual(qp.program(proxy, info), selector)

        pixels = width * 4 * height
        config_address = base + pixels + 64
        expected_config = qp.ramfb_config(base, width, height)
        self.assertEqual(proxy.ramfb_configs,
                         [(config_address, expected_config)])
        self.assertEqual(proxy.files[selector], expected_config)
        self.assertEqual(proxy.memset_calls, [(base, 0, pixels)])
        self.assertEqual(proxy.end_live_calls, 2)

        self.assertEqual(len(proxy.dma_calls), 2)
        self.assertEqual(
            proxy.dma_calls[0][0],
            (qp.FW_CFG_FILE_DIR << 16) | qp.DMA_SELECT | qp.DMA_READ)
        self.assertEqual(proxy.dma_calls[0][1], qp.SCRATCH - 64)
        self.assertEqual(
            proxy.dma_calls[1][0],
            (selector << 16) | qp.DMA_SELECT | qp.DMA_WRITE)
        self.assertEqual(proxy.dma_calls[1][1], 28)
        self.assertEqual(proxy.dma_calls[1][2], config_address)
        self.assertEqual([call[4] for call in proxy.dma_calls], [0, 0])

    def test_layout_region_never_takes_the_panel(self):
        import run
        free = [(0x4a0000000, 0x830000000)]
        size = qp.allocation(2880, 1800)
        base = qp.place(free, size)
        self.assertEqual((base, base + size), (0x82ec00000, 0x830000000))
        info = qp.describe({}, base, 2880, 1800)
        saved = run.monitor_work.firmware_free
        run.monitor_work.firmware_free = lambda proxy, info: list(free)
        try:
            start, end = run.free_region(None, info, 8 << 30, required_base=0x4a0000000,
                                         exclude=qp.excluded(info))
        finally:
            run.monitor_work.firmware_free = saved
        self.assertEqual(start, 0x4a0000000)
        self.assertLessEqual(end, base)


if __name__ == '__main__':
    unittest.main()
