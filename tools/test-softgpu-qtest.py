#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SoftGPU wave W5 against the real device model, no guest: compat/softgpu.c programs page 1 of the softgpu QEMU over qtest and
compat/softgpu-guest.c drives its ring, so the window rules are checked end to end (plans/p6-softgpu-integration.md W5 pass).

    python3 tools/test-softgpu-qtest.py          (skips when /opt/qemu-11.0.3-softgpu or cc is missing)

SNAP_SOFTGPU_QEMU names the QEMU binary and SNAP_SOFTGPU_RENDERD the render process: every test runs twice, with the device
executing in process and (when the render process exists) with `renderd=` and guest RAM in a shared memfd, which is how the
board runs it. The renderd runs also prove the render process enforces the windows (W5 audit I2).

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
RENDERD = os.environ.get('SNAP_SOFTGPU_RENDERD', '/home/snap/src/renderd/build/renderd')
RAM, RAM_SIZE = 0x40000000, 0x10000000
RING, STATUS, BOOT, ARENA, ARENA_SIZE = RAM, RAM + 0x4000, RAM + 0x8000, RAM + 0x100000, 0x100000
CONTROL, RODATA, HIDDEN, CONST = RAM + 0x200000, RAM + 0x300000, RAM + 0x400000, RAM + 0x500000
BIG, BIG_SIZE = RAM + 0x1000000, 0x8000000      # 128 MiB: one FILL_BUFFER write-back long enough to be caught part way
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
                ('failed', ctypes.c_uint32), ('programs', ctypes.c_uint32), ('unconfirmed', ctypes.c_uint32)]


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

    def fill_async(self, mem_id, nbytes, value, at=0):
        """Queue a FILL_BUFFER over nbytes of the object and return its ring sequence number (wait() collects it)."""
        pkt = ctypes.create_string_buffer(64)
        n = self.lib.sgpu_guest_pkt_fill_buffer(pkt, len(pkt), 0, U64(0), U64(nbytes), value)
        stream = self.alloc(pkt.raw[:n])
        bt = self.alloc(struct.pack('<IIQQQ', mem_id, WR, at, nbytes, 0))
        d = ctypes.create_string_buffer(64)
        self.seq += 1
        self.lib.sgpu_guest_desc_submit(d, 1, self.seq, 4, U64(stream), n, U64(bt), 1, 0xffffffff, 0, 0, U64(0))
        return self.push(d)

    def fill(self, mem_id, nbytes, value, at=0):
        return self.wait(self.fill_async(mem_id, nbytes, value, at))


def rows():
    return [Stage2Range(RAM, RAM + RAM_SIZE, (3 << 6) | (0xF << 2) | (3 << 8) | (1 << 10), 0)]


def cuts(const_ro=False):
    c = [Cut(HIDDEN, HIDDEN + 0x4000, 0), Cut(RODATA, RODATA + 0x4000, RD)]
    if const_ro:
        c.append(Cut(CONST, CONST + 0x4000, RD))
    return c


class Windows:
    """The window rules against the real device model; RENDERD_PATH selects the backend (None: libsgpu in the QEMU process)."""
    RENDERD_PATH = None

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp())
        lib = cls.work / 'libsgw.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-std=gnu11', '-O1', '-Ishadow', '-Icompat', 'compat/softgpu.c', 'compat/softgpu-guest.c',
                        '-o', str(lib)], cwd=ROOT, check=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.sgpu_guest_ring_push.restype = ctypes.c_uint64

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def setUp(self):
        """A fresh device per test: LOCK and the ring are one-way."""
        self.sock = str(self.work / f'qt-{self.id().rsplit(".", 1)[-1]}.sock')
        if self.RENDERD_PATH:
            machine = ['-object', 'memory-backend-memfd,id=ram0,size=256M,share=on', '-machine', 'virt,memory-backend=ram0']
            device = f'snap-softgpu,renderd={self.RENDERD_PATH},renderd-allow-fault=on'
        else:
            machine = ['-machine', 'virt']
            device = 'snap-softgpu'
        self.log = open(self.work / 'qemu.log', 'wb')              # a pipe nobody reads fills up and stops QEMU
        self.proc = subprocess.Popen([QEMU, *machine, '-cpu', 'max', '-m', '256M', '-accel', 'qtest', '-qtest',
                                      f'unix:{self.sock},server=on,wait=off', '-display', 'none', '-monitor', 'none', '-serial', 'none',
                                      '-device', device, '-S'], stdout=subprocess.DEVNULL, stderr=self.log)
        self.q = Qtest(self.sock)
        self.lib = type(self).lib

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()
        self.log.close()

    def bring_up(self, cut_list):
        """Open the monitor, program the table, LOCK, then the spec 1.9 bring-up: ring, status page, arena object and context."""
        q, lib = self.q, self.lib
        b = Board(lib, q)
        self.assertEqual(lib.softgpu_mon_open(ctypes.byref(b.ops), ctypes.byref(b.mon), P1), 0)
        r, win, n = b.program(rows(), cut_list)
        self.assertEqual(r, 0)
        self.assertEqual(lib.softgpu_mon_lock(ctypes.byref(b.ops), ctypes.byref(b.mon)), 0)
        q.writel(P0 + 0x18, 0x00010000)
        q.writel(P0 + 0x10, q.readl(P0 + 0x08) & 1)
        for off, val in ((0x30, RING), (0x40, STATUS)):
            q.writel(P0 + off, val & 0xffffffff)
            q.writel(P0 + off + 4, val >> 32)
        q.writel(P0 + 0x38, 256)
        q.writel(P0 + 0x24, 1)
        self.assertEqual(q.readl(P0 + 0x20) & 2, 2, 'RING_ENABLE accepted once locked')
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
        return b, n

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
        # the trust cache is readable but not writable: the object exists, a WRITE binding is refused as ACCESS (spec 1.3), the
        # page is unchanged
        q.write(RODATA, bytes([0x11]) * 64)
        self.assertEqual(b.create_memory(3, RODATA), 0)
        self.assertEqual(b.fill(3, 4, 0xEE), E_ACCESS)
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
        self.assertEqual(b.fill(5, 64, 0x44), E_ACCESS, 'the earlier alias lost WRITE')
        self.assertEqual(q.read(CONST, 64), bytes([0x33]) * 64)
        self.assertEqual(b.create_memory(6, CONST), 0, 'a new object over the read-only run is fine')
        self.assertEqual(b.fill(6, 64, 0x44), E_ACCESS)
        self.assertEqual(q.read(CONST, 64), bytes([0x33]) * 64)
        # a table that makes ordinary memory unreachable: CREATE_MEMORY over it fails, memory untouched
        r, _, _ = b.program(rows(), cuts(const_ro=True) + [Cut(CONTROL, CONTROL + 0x4000, 0)])
        self.assertEqual(r, 0)
        self.assertEqual(b.create_memory(7, CONTROL), E_MEMORY)
        self.assertEqual(b.fill(4, 64, 0x77), E_MEMORY, 'the old object over CONTROL lost READ and WRITE: the memory is gone')
        self.assertEqual(q.read(CONTROL, 64), bytes([0x5A]) * 64)
        # a table the monitor itself refuses (unsorted) writes nothing: the device keeps the generation it has
        bad = (Window * 2)(Window(CONTROL + 0x1000, 0x1000, CONTROL + 0x1000, 3, 0), Window(CONTROL, 0x1000, CONTROL, 3, 0))
        self.assertEqual(lib.softgpu_mon_program(ctypes.byref(b.ops), ctypes.byref(b.mon), bad, 2), -1)     # unsorted: refused before any write
        self.assertEqual(q.readl(P1 + 0x14), b.mon.gen)
        self.assertEqual(q.readl(P1 + 0x18), b.mon.gen)

    def test_used_device_is_refused(self):
        """L2: a device a monitor already programmed (or monitorless=on) is not opened a second time."""
        q, lib = self.q, self.lib
        b = Board(lib, q)
        self.assertEqual(lib.softgpu_mon_open(ctypes.byref(b.ops), ctypes.byref(b.mon), P1), 0)
        self.assertEqual(b.program(rows(), cuts())[0], 0)
        again = Board(lib, q)
        self.assertEqual(lib.softgpu_mon_open(ctypes.byref(again.ops), ctypes.byref(again.mon), P1), -3)
        self.assertEqual(lib.softgpu_mon_lock(ctypes.byref(b.ops), ctypes.byref(b.mon)), 0)
        self.assertEqual(lib.softgpu_mon_open(ctypes.byref(again.ops), ctypes.byref(again.mon), P1), -3)

    def test_close_confirms_the_empty_table(self):
        """L3: the hand-back zero table is applied and read back on the real device."""
        q, lib = self.q, self.lib
        b, _ = self.bring_up(cuts())
        self.assertEqual(lib.softgpu_mon_close(ctypes.byref(b.ops), ctypes.byref(b.mon)), 0)
        self.assertEqual((q.readl(P1 + 4), q.readl(P1 + 0x14), q.readl(P1 + 0x18)), (0, b.mon.gen, b.mon.gen))
        self.assertEqual(b.mon.unconfirmed, 0)
        self.assertTrue(b.mon.failed == 0 and b.mon.nwin == 0)

    def stage_table(self, b, cut_list):
        """Write a table into page 1's staging registers without the generation: the device swaps only on the WINDOWS_GEN write."""
        win = (Window * 64)()
        n = ctypes.c_uint(0)
        self.assertEqual(self.lib.softgpu_derive((Stage2Range * 1)(*rows()), 1, (Cut * len(cut_list))(*cut_list), len(cut_list), win,
                                                 ctypes.byref(n)), 0)
        for i in range(n.value):
            words = struct.unpack('<8I', bytes(win[i]))
            for k, v in enumerate(words):
                self.q.writel(P1 + 0x100 + 32 * i + 4 * k, v)
        self.q.writel(P1 + 4, n.value)
        return n.value

    def frontier(self, base, pages):
        """First page of [base, base+pages*4096) whose first byte is still zero. A write-back goes front to back, so the
        predicate 'written' is monotone and a binary search finds it."""
        lo, hi = 0, pages
        while lo < hi:
            mid = (lo + hi) // 2
            if self.q.read(base + mid * 4096, 1) != b'\0':
                lo = mid + 1
            else:
                hi = mid
        return lo

    def test_downgrade_during_writeback_is_final(self):
        """M1: a FILL_BUFFER over 128 MiB ends in a write-back of the whole object. Part way through it the monitor takes WRITE
        away (the table is staged, so the only thing between the first byte and the downgrade is the WINDOWS_GEN write) and
        reads WINDOWS_GEN_APPLIED. From that read on not one byte may change under the old table: the frontier of the
        write-back is the same when the descriptor has ended."""
        q, lib = self.q, self.lib
        b, _ = self.bring_up(cuts())
        pages = BIG_SIZE // 4096
        self.assertEqual(b.create_memory(2, BIG, size=BIG_SIZE), 0)
        gen = b.mon.gen
        self.stage_table(b, cuts() + [Cut(BIG, BIG + BIG_SIZE, RD)])
        seq = b.fill_async(2, BIG_SIZE, 0x5A)
        deadline = time.time() + 30
        while q.read(BIG, 1) == b'\0':                      # the write-back has begun
            self.assertLess(time.time(), deadline, 'the write-back never started')
            if struct.unpack('<Q', q.read(STATUS, 8))[0] >= seq:
                _, status, offset = struct.unpack('<QiI', q.read(STATUS + 0x1000 + 16 * ((seq - 1) % 256), 16))
                self.fail(f'the descriptor ended with status {status} (packet offset {offset:#x}) before writing anything')
        q.writel(P1 + 0x14, gen + 1)                       # WINDOWS_GEN: the monitor's downgrade
        self.assertEqual(q.readl(P1 + 0x18), gen + 1, 'APPLIED')
        at_apply = self.frontier(BIG, pages)
        status = b.wait(seq)
        after = self.frontier(BIG, pages)
        self.assertLess(at_apply, pages, 'the downgrade did not land during the write-back: the race was not exercised')
        self.assertEqual(after, at_apply, f'{after - at_apply} pages were written after WINDOWS_GEN_APPLIED')
        self.assertIn(status, (E_MEMORY, E_ACCESS), 'the refused write-back fails the descriptor')


@unittest.skipUnless(os.path.exists(QEMU) and shutil.which('cc'), 'softgpu QEMU or cc missing')
class DeviceWindows(Windows, unittest.TestCase):
    """libsgpu in the QEMU process."""


@unittest.skipUnless(os.path.exists(QEMU) and os.path.exists(RENDERD) and shutil.which('cc'), 'softgpu QEMU, renderd or cc missing')
class DeviceWindowsRenderd(Windows, unittest.TestCase):
    """The device executes in the render process, guest RAM in a shared memfd (the board's configuration)."""
    RENDERD_PATH = RENDERD


if __name__ == '__main__':
    unittest.main()
