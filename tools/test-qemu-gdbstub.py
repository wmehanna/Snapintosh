#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The QEMU gdbstub client, against a stub that speaks the protocol.

What matters without a target: physical-memory mode is asked for before any
read (the arena is physical), reads and writes are framed and checksummed, a
stop reply the stub sends on its own schedule does not displace an answer, and
"continue" does not wait for the stop reply that answers it (that wait was 20
seconds per keystroke on the lab).
"""
import importlib.util
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('qemu_gdbstub', ROOT / 'tools' / 'qemu-gdbstub.py')
gdbstub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gdbstub)


class Stub:
    def __init__(self, path):
        self.path = path
        self.memory = {}
        self.seen = []
        self.continued = 0
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        link, _ = self.server.accept()
        buf = b''
        while True:
            data = link.recv(65536)
            if not data:
                return
            buf += data
            while b'#' in buf and len(buf) >= buf.index(b'#') + 3:
                start = buf.index(b'$')
                end = buf.index(b'#')
                body, buf = buf[start + 1:end], buf[end + 3:]
                link.sendall(b'+')
                self.seen.append(body)
                reply = self.answer(body)
                if reply is not None:
                    link.sendall(b'$' + reply + b'#' + f'{sum(reply) & 0xff:02x}'.encode())

    def answer(self, body):
        if body.startswith(b'qSupported'):
            return b'PacketSize=20020;qXfer:features:read+'
        if body.startswith(b'Qqemu.PhyMemMode'):
            return b'OK'
        if body == b'?':
            # A stop reply the client did not ask for, as the real stub sends.
            return b'T05core:01;'
        if body.startswith(b'm'):
            addr, size = (int(v, 16) for v in body[1:].split(b','))
            out = bytes(self.memory.get(addr + n, 0xa5) for n in range(size))
            return out.hex().encode()
        if body.startswith(b'M'):
            head, data = body[1:].split(b':', 1)
            addr, size = (int(v, 16) for v in head.split(b','))
            blob = bytes.fromhex(data.decode())
            assert len(blob) == size
            for n, byte in enumerate(blob):
                self.memory[addr + n] = byte
            return b'OK'
        if body == b'c':
            self.continued += 1
            return None
        return b'E01'


class Client(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.stub = Stub(Path(self.dir.name) / 'stub.sock')
        self.link = gdbstub.Rsp(str(self.stub.path), timeout=5)

    def tearDown(self):
        self.link.close()
        self.stub.server.close()
        self.stub.thread.join(timeout=1)
        self.dir.cleanup()

    def test_physical_memory_mode_is_requested(self):
        self.assertIn(gdbstub.PHY_MEM_MODE, self.stub.seen)

    def test_read_and_write(self):
        self.link.stop()
        self.link.write(0x6c19a9b08, b'Q1CONSV1')
        self.assertEqual(self.link.read(0x6c19a9b08, 8), b'Q1CONSV1')
        self.assertEqual(self.link.read(0x6c19a9b08 + 8, 2), bytes([0xa5, 0xa5]))

    def test_continue_does_not_wait(self):
        self.link.stop()
        before = time.monotonic()
        self.link.go()
        self.assertLess(time.monotonic() - before, 1.0)
        for _ in range(100):
            if self.stub.continued:
                break
            time.sleep(0.01)
        self.assertGreaterEqual(self.stub.continued, 1)

    def test_a_stop_reply_does_not_displace_an_answer(self):
        self.link.stop()
        self.link.go()
        self.assertEqual(self.link.read(0x1000, 4), bytes([0xa5]) * 4)


if __name__ == '__main__':
    unittest.main()
