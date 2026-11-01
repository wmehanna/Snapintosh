#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Type into a running Snapintosh QEMU guest's console.

A launch with SNAP_EARLY_STOP=console keeps the monitor's DockChannel receive
ring (compat/shadow/dockchannel.h struct dc_rx, inside the context's
console_link), and XNU's serial_keyboard_poll drains it every 16 ms. Bytes go
in over QEMU's gdbstub, so nothing in the guest or the monitor changes:

    python3 tools/guest-type-qemu.py RUN 'launchctl list | head' [--env FILE]

RUN is the run directory: run.log names the monitor's work arena, gdb.sock is
the stub, and --env (default: the phase-5 autoload env) supplies the
SNAP_EXTRA_CFLAGS the monitor was built with, since the context's field
offsets move with its defines. The right layout is the one whose console-link
view carries Q1CONSV1 at the address the host computes.

Keep each CPU stop short (milliseconds): run.py's proxy link to q1n1 starves
while the vCPUs are stopped and the run dies with ProxyTimeout. Chunks stay
under 128 bytes because XNU masks the receive count to 7 bits, and a heredoc
needs its terminator on a line of its own, so type a CR first when unsure.
"""
import argparse
import importlib.util
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
from monitor_layout import MonitorLayout  # noqa: E402

spec = importlib.util.spec_from_file_location('qemu_gdbstub', ROOT / 'tools' / 'qemu-gdbstub.py')
gdbstub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gdbstub)

RING = 1024
MAGIC = 0x3156534e4f433151     # "Q1CONSV1"
DEFAULT_ENV = Path('/home/snap/p5/inst-ro-cryptex-graft-auxkc-adreno-autoload.env')


def work_arena(run):
    log = run / 'run.log'
    while True:
        text = log.read_text(errors='replace') if log.exists() else ''
        found = re.search(r'monitor work arena (0x[0-9a-f]+)', text)
        if found:
            return int(found.group(1), 16)
        if (run / 'stop.txt').exists():
            raise SystemExit('the run stopped before it named its work arena')
        time.sleep(1)


def define_sets(run, env):
    seen = []
    for path in (run / 'extra-env.txt', env):
        if path and Path(path).exists():
            match = re.search(r'SNAP_EXTRA_CFLAGS="([^"]*)"', Path(path).read_text(errors='replace'))
            if match:
                seen.append(tuple(match.group(1).split()))
    seen.append(())
    return seen


def locate(run, stub, env):
    work = work_arena(run)
    for flags in define_sets(run, env):
        layout = MonitorLayout(flags)
        link = work + layout.offset('context', 'console_link')
        magic = int.from_bytes(stub.read(link + layout.offset('console_link', 'view'), 8), 'little')
        if magic == MAGIC:
            return link + layout.offset('console_link', 'rx'), layout
    raise SystemExit('the console link is off: launch with SNAP_EARLY_STOP=console')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('run')
    ap.add_argument('text')
    ap.add_argument('--env', default=str(DEFAULT_ENV))
    ap.add_argument('--stall-ms', type=int, default=80)
    ap.add_argument('--step', type=int, default=64, help='bytes per CPU stop (under 128)')
    args = ap.parse_args()
    run = Path(args.run)
    sock = run / 'gdb.sock'
    while not sock.exists():
        time.sleep(0.5)
    stub = gdbstub.Rsp(str(sock))
    stub.stop()
    rx, layout = locate(run, stub, args.env)
    buf_at = rx + layout.offset('dc_rx', 'buf')
    data = args.text.encode()
    for at in range(0, len(data), args.step):
        chunk = data[at:at + args.step]
        for _ in range(600):
            head = int.from_bytes(stub.read(rx, 4), 'little')
            count = int.from_bytes(stub.read(rx + 4, 4), 'little')
            if RING - count >= len(chunk):
                break
            stub.go()
            time.sleep(0.02)
            stub.stop()
        else:
            raise SystemExit('the receive ring stayed full')
        pos = (head + count) % RING
        first = min(len(chunk), RING - pos)
        stub.write(buf_at + pos, chunk[:first])
        if first < len(chunk):
            stub.write(buf_at, chunk[first:])
        stub.write(rx + 4, (count + len(chunk)).to_bytes(4, 'little'))
        stub.go()
        time.sleep(args.stall_ms / 1000.0)
        stub.stop()
    stub.go()
    print(f'typed {len(data)} bytes into the ring at {rx:#x}')


if __name__ == '__main__':
    main()
