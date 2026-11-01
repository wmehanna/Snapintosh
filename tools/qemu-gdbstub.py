#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest memory through QEMU's gdbstub, from the host, without GDB.

QEMU has no HMP memory-write command; pmemsave reads, nothing writes. A
"-gdb unix:PATH,server=on,wait=off" stub does both, and with
Qqemu.PhyMemMode:1 it addresses guest physical memory, which is what the
monitor's arena needs: the vCPUs run the guest's own stage-1 tables, so the
stub's default virtual addresses miss the arena entirely (E14).

    from qemu_gdbstub import Rsp
    link = Rsp('/home/snap/p3/RUN/gdb.sock')
    link.stop()
    value = link.read(work_at + offset, 8)
    link.write(address, b'...')
    link.go()

"continue" is answered only when the target stops again, so go() sends it
without waiting: waiting there costs the socket timeout per keystroke.
"""
import socket

PHY_MEM_MODE = b'Qqemu.PhyMemMode:1'


class Rsp:
    def __init__(self, path, timeout=20.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(timeout)
        self.buf = b''
        self.cmd(b'qSupported:multiprocess+;swbreak+;hwbreak+')
        self.cmd(PHY_MEM_MODE)

    def _packet(self):
        while True:
            while self.buf[:1] in (b'+', b'-'):
                self.buf = self.buf[1:]
            at = self.buf.find(b'$')
            if at >= 0:
                end = self.buf.find(b'#', at)
                if end < 0 or len(self.buf) < end + 3:
                    self.buf += self.s.recv(65536)
                    continue
                body = self.buf[at + 1:end]
                self.buf = self.buf[end + 3:]
                self.s.sendall(b'+')
                return body
            data = self.s.recv(65536)
            if not data:
                raise EOFError('gdbstub closed the socket')
            self.buf += data

    def cmd(self, body):
        self.s.sendall(b'$' + body + b'#' + f'{sum(body) & 0xff:02x}'.encode())
        return self._packet()

    def request(self, body, ok):
        """Send body and return the first reply that satisfies ok; stop replies
        and a late features answer arrive on the stub's own schedule."""
        self.s.sendall(b'$' + body + b'#' + f'{sum(body) & 0xff:02x}'.encode())
        while True:
            reply = self._packet()
            if ok(reply):
                return reply

    def stop(self):
        """Interrupt the target: m/M are answered only while it is stopped. The
        interrupt reply arrives when it worked; the '?' after it answers either
        way, so an already stopped target does not hang."""
        self.s.sendall(b'\x03')
        return self.request(b'?', lambda r: r[:1] in (b'S', b'T') or r.startswith(b'E'))

    def read(self, addr, length):
        out = b''
        while len(out) < length:
            size = min(4096, length - len(out))
            reply = self.request(b'm%x,%x' % (addr + len(out), size),
                                 lambda r: len(r) == 2 * size or r.startswith(b'E'))
            if reply.startswith(b'E'):
                raise RuntimeError(f'gdbstub error at {addr + len(out):#x}: {reply!r}')
            out += bytes.fromhex(reply.decode())
        return out

    def write(self, addr, data):
        for at in range(0, len(data), 1024):
            chunk = data[at:at + 1024]
            reply = self.request(b'M%x,%x:' % (addr + at, len(chunk)) + chunk.hex().encode(),
                                 lambda r: r in (b'OK', b'E'))
            if reply != b'OK':
                raise RuntimeError(f'gdbstub refused {addr + at:#x}: {reply!r}')

    def close(self):
        self.s.close()

    def go(self):
        """Resume without waiting for the stop reply that answers it."""
        self.s.sendall(b'$c#63')
