#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SoftGPU wave W5 against the real device model, no guest: compat/softgpu.c programs page 1 of the softgpu QEMU over qtest and
compat/softgpu-guest.c drives its ring, so the window rules are checked end to end (plans/p6-softgpu-integration.md W5 pass).

    python3 tools/test-softgpu-qtest.py          (skips when /opt/qemu-11.0.3-softgpu or cc is missing)

Layout of the 256 MiB guest RAM at 0x40000000: ring, status page, bootstrap page, a 1 MiB arena, then four test pages: CONTROL
(ordinary RAM), RODATA (the trust cache: READ only), HIDDEN (the monitor's memory: no window) and CONST (read-write until the
LOCKDOWN downgrade). Checks: RING_ENABLE is refused before LOCK; CREATE_MEMORY over HIDDEN is SGPU_E_MEMORY; a WRITE binding
over RODATA is refused and the page is unchanged; CONTROL takes the write; after a table that makes CONST read-only is applied the
object created earlier over CONST can no longer be written (alias re-check), and a table that removes ordinary memory takes effect at
once. (A device that does not apply or keep a table is tests/test-softgpu-windows.c's model.)
"""
import ctypes
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QEMU = os.environ.get('SNAP_SOFTGPU_QEMU', '/opt/qemu-11.0.3-softgpu/bin/qemu-system-aarch64')
RAM, RAM_SIZE = 0x40000000, 0x10000000
RING, STATUS, BOOT, ARENA, ARENA_SIZE = RAM, RAM + 0x4000, RAM + 0x8000, RAM + 0x100000, 0x100000
CONTROL, RODATA, HIDDEN, CONST = RAM + 0x200000, RAM + 0x300000, RAM + 0x400000, RAM + 0x500000
P0, P1 = 0x0C000000, 0x0C001000
E_ACCESS, E_MEMORY = -4, -12
RD, WR = 1, 2
U64 = ctypes.c_uint64     # ctypes passes a bare int as a 32-bit C int: 64-bit parameters must be wrapped


class Stage2Range(ctypes.Structure):
    _fields_ = [('lo', ctypes.c_uint64), ('hi', ctypes.c_uint64), ('low', ctypes.c_uint64), ('upper', ctypes.c_uint64)]


class Cut(ctypes.Structure):
    _fields_ = [('lo', ctypes.c_uint64), ('hi', ctypes.c_uint64), ('keep', ctypes.c_uint32)]


class Window(ctypes.Structure):
    _fields_ = [('ipa_base', ctypes.c_uint64), ('size', ctypes.c_uint64), ('pa_base', ctypes.c_uint64),
                ('flags', ctypes.c_uint32), ('reserved', ctypes.c_uint32)]


RDF = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint64)
WRF = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32)


class MonOps(ctypes.Structure):
    _fields_ = [('ctx', ctypes.c_void_p), ('rd', RDF), ('wr', WRF)]


class Mon(ctypes.Structure):
    _fields_ = [('page1', ctypes.c_uint64), ('gen', ctypes.c_uint32), ('nwin', ctypes.c_uint32), ('locked', ctypes.c_uint32),
                ('failed', ctypes.c_uint32), ('programs', ctypes.c_uint32)]


class Qtest:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX)
        for _ in range(100):
            try:
                self.s.connect(path)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError('qtest socket')
        self.f = self.s.makefile('rw')

    def cmd(self, text):
        self.f.write(text + '\n')
        self.f.flush()
        line = self.f.readline().strip()
        if not line.startswith('OK'):
            raise RuntimeError(f'{text}: {line}')
        return line[2:].strip()

    def readl(self, a):
        return int(self.cmd(f'readl {a:#x}'), 16)

    def writel(self, a, v):
        self.cmd(f'writel {a:#x} {v:#x}')

    def read(self, a, n):
        return bytes.fromhex(self.cmd(f'read {a:#x} {n:#x}')[2:])

    def write(self, a, data):
        self.cmd(f'write {a:#x} {len(data):#x} 0x{data.hex()}')


class Board:
    """The device with a guest-side shadow ring, a bump arena and the monitor library bound to qtest."""

    def __init__(self, lib, q):
        self.lib, self.q = lib, q
        self.mon = Mon()
        self.ops = MonOps(None, RDF(lambda _c, pa: q.readl(pa)), WRF(lambda _c, pa, v: q.writel(pa, v)))
        self.shadow = ctypes.create_string_buffer(256 * 64)
        self.ring = ctypes.create_string_buffer(64)
        lib.sgpu_guest_ring_init(self.ring, self.shadow, 256)
        self.arena_at = 0x1000
        self.seq = 0

    def program(self, rows, cuts):
        win = (Window * 64)()
        n = ctypes.c_uint(0)
        r = self.lib.softgpu_derive((Stage2Range * len(rows))(*rows), len(rows), (Cut * max(1, len(cuts)))(*cuts), len(cuts), win,
                                    ctypes.byref(n))
        assert r == 0, r
        return self.lib.softgpu_mon_program(ctypes.byref(self.ops), ctypes.byref(self.mon), win, n.value), win, n.value

    def alloc(self, data):
        at = self.arena_at
        self.q.write(ARENA + at, data)
        self.arena_at = (at + len(data) + 7) & ~7
        return at

    def push(self, desc):
        seq = self.lib.sgpu_guest_ring_push(self.ring, desc)
        assert seq, 'ring full'
        slot = (seq - 1) % 256
        self.q.write(RING + 64 * slot, self.shadow.raw[64 * slot:64 * slot + 64])
        self.q.writel(P0 + 0x60, seq)
        return seq

    def wait(self, seq, seconds=20):
        end = time.time() + seconds
        while time.time() < end:
            done = struct.unpack('<Q', self.q.read(STATUS, 8))[0]
            if done >= seq:
                _, status, offset = struct.unpack('<QiI', self.q.read(STATUS + 0x1000 + 16 * ((seq - 1) % 256), 16))
                if os.environ.get('SGPU_DEBUG'):
                    print(f'descriptor {seq}: status {status} packet_offset {offset:#x}', file=sys.stderr)
                    if status:
                        fault = self.q.read(STATUS + 0x400, 256)
                        print('  fault:', struct.unpack_from('<QiIIII', fault), fault[32:].split(b'\0')[0], file=sys.stderr)
                return status
            time.sleep(0.02)
        raise TimeoutError(f'descriptor {seq}')

    def kernel(self, packet):
        at = self.alloc(packet)
        d = ctypes.create_string_buffer(64)
        self.lib.sgpu_guest_desc_kernel(d, 0, U64(at), len(packet), 0xffffffff, 0)
        return self.wait(self.push(d))

    def create_memory(self, mem_id, pa, size=0x4000, flags=0):
        run = struct.pack('<QQ', pa, size)
        buf = ctypes.create_string_buffer(48 + 16)
        n = self.lib.sgpu_guest_pkt_create_memory(buf, len(buf), mem_id, flags, U64(size), U64(0), 0, run, 1)
        assert n > 0
        return self.kernel(buf.raw[:n])

    def fill(self, mem_id, nbytes, value, at=0):
        pkt = ctypes.create_string_buffer(64)
        n = self.lib.sgpu_guest_pkt_fill_buffer(pkt, len(pkt), 0, U64(0), U64(nbytes), value)
        stream = self.alloc(pkt.raw[:n])
        bt = self.alloc(struct.pack('<IIQQQ', mem_id, WR, at, nbytes, 0))
        d = ctypes.create_string_buffer(64)
        self.seq += 1
        self.lib.sgpu_guest_desc_submit(d, 1, self.seq, 4, U64(stream), n, U64(bt), 1, 0xffffffff, 0, 0, U64(0))
        return self.wait(self.push(d))


def rows():
    return [Stage2Range(RAM, RAM + RAM_SIZE, (3 << 6) | (0xF << 2) | (3 << 8) | (1 << 10), 0)]


def cuts(const_ro=False):
    c = [Cut(HIDDEN, HIDDEN + 0x4000, 0), Cut(RODATA, RODATA + 0x4000, RD)]
    if const_ro:
        c.append(Cut(CONST, CONST + 0x4000, RD))
    return c


@unittest.skipUnless(os.path.exists(QEMU) and shutil.which('cc'), 'softgpu QEMU or cc missing')
class DeviceWindows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp())
        lib = cls.work / 'libsgw.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-std=gnu11', '-O1', '-Ishadow', '-Icompat', 'compat/softgpu.c', 'compat/softgpu-guest.c',
                        '-o', str(lib)], cwd=ROOT, check=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.sgpu_guest_ring_push.restype = ctypes.c_uint64
        cls.sock = str(cls.work / 'qt.sock')
        cls.proc = subprocess.Popen([QEMU, '-machine', 'virt', '-cpu', 'max', '-m', '256M', '-accel', 'qtest', '-qtest',
                                     f'unix:{cls.sock},server=on,wait=off', '-display', 'none', '-monitor', 'none', '-serial', 'none',
                                     '-device', 'snap-softgpu', '-S'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        cls.q = Qtest(cls.sock)

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_windows_end_to_end(self):
        q, lib = self.q, self.lib
        self.assertEqual(q.readl(P0), 0x55504753)
        self.assertEqual(q.readl(P1), 0x4E4F4D53)
        b = Board(lib, q)
        self.assertEqual(lib.softgpu_mon_open(ctypes.byref(b.ops), ctypes.byref(b.mon), P1), 0)
        # RING_ENABLE before LOCK is refused (also a device qtest)
        q.writel(P0 + 0x24, 1)
        self.assertEqual(q.readl(P0 + 0x20) & 2, 0)
        r, win, n = b.program(rows(), cuts())
        self.assertEqual(r, 0)
        self.assertEqual((b.mon.gen, q.readl(P1 + 0x14), q.readl(P1 + 0x18), q.readl(P1 + 4)), (1, 1, 1, n))
        self.assertEqual(n, 4)      # below RODATA, RODATA (READ), between RODATA and HIDDEN, above HIDDEN
        q.writel(P0 + 0x24, 1)
        self.assertEqual(q.readl(P0 + 0x20) & 2, 0, 'still refused: windows alone do not lock')
        self.assertEqual(lib.softgpu_mon_lock(ctypes.byref(b.ops), ctypes.byref(b.mon)), 0)
        self.assertEqual(q.readl(P0 + 0x20) & 0x10, 0x10)
        # bring-up (spec 1.9): version, features, ring, status page, ring enable
        q.writel(P0 + 0x18, 0x00010000)
        q.writel(P0 + 0x10, q.readl(P0 + 0x08) & 1)
        for off, val in ((0x30, RING), (0x40, STATUS)):
            q.writel(P0 + off, val & 0xffffffff)
            q.writel(P0 + off + 4, val >> 32)
        q.writel(P0 + 0x38, 256)
        q.writel(P0 + 0x24, 1)
        self.assertEqual(q.readl(P0 + 0x20) & 2, 2, 'RING_ENABLE accepted once locked')
        # arena = memory object 1, registered by a bootstrap descriptor read by GPA
        run = struct.pack('<QQ', ARENA, ARENA_SIZE)
        buf = ctypes.create_string_buffer(64)
        n_pkt = lib.sgpu_guest_pkt_create_memory(buf, len(buf), 1, 1, U64(ARENA_SIZE), U64(0), 0, run, 1)
        q.write(BOOT, buf.raw[:n_pkt])
        d = ctypes.create_string_buffer(64)
        lib.sgpu_guest_desc_kernel(d, 1 << 15, U64(BOOT), n_pkt, 0xffffffff, 0)
        self.assertEqual(b.wait(b.push(d)), 0)
        ctx = ctypes.create_string_buffer(32)
        n_ctx = lib.sgpu_guest_pkt_create_context(ctx, len(ctx), 1)
        self.assertEqual(b.kernel(ctx.raw[:n_ctx]), 0)

        # the monitor's memory has no window: the object cannot be made
        self.assertEqual(b.create_memory(2, HIDDEN), E_MEMORY)
        # the trust cache is readable but not writable: the object exists, a WRITE binding is refused, the page is unchanged
        q.write(RODATA, bytes([0x11]) * 64)
        self.assertEqual(b.create_memory(3, RODATA), 0)
        self.assertIn(b.fill(3, 4, 0xEE), (E_ACCESS, E_MEMORY))
        self.assertEqual(q.read(RODATA, 64), bytes([0x11]) * 64)
        # ordinary memory takes the same write
        q.write(CONTROL, bytes(64))
        self.assertEqual(b.create_memory(4, CONTROL), 0)
        self.assertEqual(b.fill(4, 64, 0x5A), 0)
        self.assertEqual(q.read(CONTROL, 64), bytes([0x5A]) * 64)
        # LOCKDOWN downgrade: CONST is writable now, then the table that makes it read-only is applied (device first)
        self.assertEqual(b.create_memory(5, CONST), 0)
        self.assertEqual(b.fill(5, 64, 0x33), 0)
        self.assertEqual(q.read(CONST, 64), bytes([0x33]) * 64)
        r, _, n2 = b.program(rows(), cuts(const_ro=True))
        self.assertEqual(r, 0)
        self.assertEqual((b.mon.gen, q.readl(P1 + 0x18)), (2, 2))
        self.assertEqual(q.readl(P0 + 0x20) & 0x40, 0, 'no descriptor was running: nothing went stale')
        self.assertIn(b.fill(5, 64, 0x44), (E_ACCESS, E_MEMORY), 'the earlier alias lost WRITE')
        self.assertEqual(q.read(CONST, 64), bytes([0x33]) * 64)
        self.assertEqual(b.create_memory(6, CONST), 0, 'a new object over the read-only run is fine')
        self.assertIn(b.fill(6, 64, 0x44), (E_ACCESS, E_MEMORY))
        self.assertEqual(q.read(CONST, 64), bytes([0x33]) * 64)
        # a table that makes ordinary memory unreachable: CREATE_MEMORY over it fails, memory untouched
        r, _, _ = b.program(rows(), cuts(const_ro=True) + [Cut(CONTROL, CONTROL + 0x4000, 0)])
        self.assertEqual(r, 0)
        self.assertEqual(b.create_memory(7, CONTROL), E_MEMORY)
        self.assertIn(b.fill(4, 64, 0x77), (E_ACCESS, E_MEMORY), 'the old object over CONTROL lost READ and WRITE')
        self.assertEqual(q.read(CONTROL, 64), bytes([0x5A]) * 64)
        # a table the monitor itself refuses (unsorted) writes nothing: the device keeps the generation it has
        bad = (Window * 2)(Window(CONTROL + 0x1000, 0x1000, CONTROL + 0x1000, 3, 0), Window(CONTROL, 0x1000, CONTROL, 3, 0))
        self.assertEqual(lib.softgpu_mon_program(ctypes.byref(b.ops), ctypes.byref(b.mon), bad, 2), -1)     # unsorted: refused before any write
        self.assertEqual(q.readl(P1 + 0x14), b.mon.gen)
        self.assertEqual(q.readl(P1 + 0x18), b.mon.gen)


if __name__ == '__main__':
    unittest.main()
