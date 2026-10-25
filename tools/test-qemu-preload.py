#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin probes/qemu_preload.py, the QEMU-only EFI preload of the xnuboot image.

The cache is content addressed: a chunk is copied from q1n1's resident copy
only when the current build made byte-identical data of the same length, at
whatever guest address this run placed it. Everything else must stay in
`chunks` so run.py uploads it over the proxy as before. No QEMU and no q1n1
build are needed; the proxy is a fake that models P_MEMCPY8 and the verifier.
"""
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import qemu_preload as qp                                       # noqa: E402

try:
    qp._real_manifest = qp._manifest
    qp._real_manifest([(qp.EFI_BLOB, 8, '00' * 32)])
except (ImportError, ValueError):
    qp._real_manifest = None
qp._manifest = lambda files: b'manifest:' + repr(files).encode()
MIN = qp.MIN_CHUNK
BASE = 0x4_0000_0000
checks = []


def check(condition, label):
    checks.append((bool(condition), label))
    print(f'{"PASS" if condition else "FAIL"}  {label}')


class FakeProxy:
    def __init__(self, resident, verify=1):
        self.resident, self.verify = resident, verify
        self.memory, self.copies, self.verified = {}, [], []

    def call(self, address, index, timeout=None):
        self.verified.append((address, index))
        return self.verify

    def memcpy8(self, dst, src, size):
        assert dst % 8 == 0 and src % 8 == 0 and size % 8 == 0, 'unaligned P_MEMCPY8'
        offset = src - BASE
        self.memory[dst] = bytes(self.resident[offset:offset + size])
        self.copies.append((dst, src, size))

    def assembled(self, pa, size):
        out = bytearray()
        for dst in sorted(self.memory):
            if pa <= dst < pa + size:
                out += self.memory[dst]
        return bytes(out)


def setup(chunks):
    folder = Path(tempfile.mkdtemp())
    esp = folder / 'qemu-esp'
    index = qp.write(esp, chunks)
    resident = (esp / qp.EFI_DIR / qp.BLOB).read_bytes() if index else b''
    cached = [dict(index=3, base=BASE, size=index['blob_size'], sha256=index['blob_sha256'])] if index else []
    return folder, esp, index, resident, cached


def blob(seed, size):
    return (hashlib.sha256(seed).digest() * (size // 32 + 1))[:size]


INFO = {'preload_verify': 0x1000}
A, B = blob(b'a', 3 * MIN), blob(b'b', MIN)

# 1. Same content at different guest addresses is copied (placement-independent).
qp.PENDING = None
folder, esp, index, resident, cached = setup({0x1000_0000: A, 0x2000_0000: B})
proxy = FakeProxy(resident)
chunks = {0x7000_0000: A, 0x7100_0000: B}
copied, count, note = qp.apply(proxy, INFO, cached, chunks, folder / qp.INDEX)
check(count == 2 and copied == len(A) + len(B), 'chunks moved to new addresses are still copied')
check(chunks == {}, 'copied chunks are removed from the upload set')
check(proxy.assembled(0x7000_0000, len(A)) == A and proxy.assembled(0x7100_0000, len(B)) == B,
      'copied bytes equal the chunk data')
check(proxy.verified == [(0x1000, 3)], 'resident verifier runs once with the cache index')
check(qp.PENDING is None, 'a full hit does not schedule a cache refresh')
check(len(index['entries']) == 2 and index['blob_size'] == len(resident), 'index matches the blob')

# 2. Small chunks are never cached nor copied.
qp.PENDING = None
small = blob(b's', MIN - 8)
folder, esp, index, resident, cached = setup({0x1000: small, 0x2000_0000: A})
chunks = {0x5000: small, 0x9000_0000: A}
qp.apply(FakeProxy(resident), INFO, cached, chunks, folder / qp.INDEX)
check(list(chunks) == [0x5000] and len(index['entries']) == 1, 'chunks below MIN_CHUNK stay on the UART path')

# 3. A large chunk with a non-multiple-of-8 length leaves its tail to upload.
qp.PENDING = None
odd = blob(b'o', MIN + 5)
folder, esp, index, resident, cached = setup({0x1000_0000: odd})
proxy = FakeProxy(resident)
chunks = {0x8000_0000: odd}
copied, count, _ = qp.apply(proxy, INFO, cached, chunks, folder / qp.INDEX)
aligned = len(odd) & ~7
check(copied == aligned and chunks == {0x8000_0000 + aligned: odd[aligned:]},
      'the unaligned tail stays at its own address for upload')
check(proxy.assembled(0x8000_0000, aligned) == odd[:aligned], 'the aligned part is copied exactly')

# 4. Changed content is uploaded and schedules a refresh.
qp.PENDING = None
folder, esp, index, resident, cached = setup({0x1000_0000: A})
changed = bytearray(A); changed[100] ^= 1; changed = bytes(changed)
chunks = {0x1000_0000: changed}
copied, count, note = qp.apply(FakeProxy(resident), INFO, cached, chunks, folder / qp.INDEX)
check(count == 0 and chunks == {0x1000_0000: changed}, 'a one-bit change is not copied from the cache')
check(qp.PENDING == {0x1000_0000: changed}, 'a miss schedules a refresh with the full chunk set')

# 5. A failed resident hash refuses the run.
qp.PENDING = None
folder, esp, index, resident, cached = setup({0x1000_0000: A})
try:
    qp.apply(FakeProxy(resident, verify=0), INFO, cached, {0x1000_0000: A}, folder / qp.INDEX)
    check(False, 'verifier failure raises')
except ValueError:
    check(True, 'verifier failure raises')

# 6. No index, or a cache q1n1 did not load, falls back and schedules a refresh.
qp.PENDING = None
chunks = {0x1000_0000: A}
result = qp.apply(FakeProxy(b''), INFO, [], chunks, Path(tempfile.mkdtemp()) / qp.INDEX)
check(result[:2] == (0, 0) and chunks == {0x1000_0000: A} and qp.PENDING == chunks,
      'missing index uploads everything and schedules a refresh')
qp.PENDING = None
folder, esp, index, resident, cached = setup({0x1000_0000: A})
result = qp.apply(FakeProxy(resident), INFO, [], dict(chunks), folder / qp.INDEX)
check(result[:2] == (0, 0) and qp.PENDING is not None, 'a cache that is not resident is not trusted')

# 7. Duplicate content is stored once.
folder, esp, index, resident, cached = setup({0x1000_0000: A, 0x2000_0000: A})
check(len(index['entries']) == 1 and index['blob_size'] == len(A), 'duplicate chunks share one blob entry')

# 7b. A chunk longer than the 8 MiB step is copied in bounded pieces.
qp.PENDING = None
big = blob(b'g', (8 << 20) + 3 * MIN)
folder, esp, index, resident, cached = setup({0x1000_0000: big})
proxy = FakeProxy(resident)
chunks = {0x6000_0000: big}
qp.apply(proxy, INFO, cached, chunks, folder / qp.INDEX)
check(len(proxy.copies) == 2 and max(s for _, _, s in proxy.copies) == 8 << 20
      and proxy.assembled(0x6000_0000, len(big)) == big, 'a 8 MiB+ chunk is copied in two bounded steps')

# 7c. A chunk at an address that is not 8-byte aligned is neither cached nor
# counted as a miss, so it cannot force a refresh on every run.
qp.PENDING = None
folder, esp, index, resident, cached = setup({0x1000_0004: A, 0x2000_0000: B})
check(len(index['entries']) == 1, 'unaligned guest address is left out of the cache')
chunks = {0x1000_0004: A, 0x2000_0000: B}
qp.apply(FakeProxy(resident), INFO, cached, chunks, folder / qp.INDEX)
check(list(chunks) == [0x1000_0004] and qp.PENDING is None,
      'unaligned chunk is uploaded without scheduling a refresh')

# 7d. The real q1n1 manifest format, and a foreign manifest is left alone.
real = qp.__dict__.get('_real_manifest')
if real is not None:
    qp._manifest = real
    folder, esp, index, resident, cached = setup({0x1000_0000: A})
    raw = (esp / qp.EFI_DIR / qp.MANIFEST).read_bytes()
    check(qp.EFI_BLOB.encode() in raw and len(raw) == 32 + 296, 'q1n1 manifest names the chunk blob')
    qp._manifest = lambda files: b'manifest:' + repr(files).encode()
foreign = Path(tempfile.mkdtemp()) / 'qemu-esp'
(foreign / qp.EFI_DIR).mkdir(parents=True)
(foreign / qp.EFI_DIR / qp.MANIFEST).write_bytes(b'\\Snapintosh\\basesystem.apfs')
check(qp.write(foreign, {0x1000_0000: A}) is None and not (foreign / qp.EFI_DIR / qp.BLOB).exists(),
      'a RAMDisk preload manifest is not overwritten')
qp.remove(foreign)
check((foreign / qp.EFI_DIR / qp.MANIFEST).exists(), 'nor removed')

# 8. remove() clears the ESP files and the host index; enabled() is opt-in.
qp.remove(esp)
check(not (esp / qp.EFI_DIR / qp.BLOB).exists() and not (esp / qp.EFI_DIR / qp.MANIFEST).exists()
      and not (folder / qp.INDEX).exists(), 'remove deletes blob, manifest and index')
check(qp.enabled({'SNAP_QEMU_PRELOAD': '1'}) and not qp.enabled({}), 'the cache is opt-in')

failed = [label for ok, label in checks if not ok]
print(f'{len(checks) - len(failed)}/{len(checks)} passed')
sys.exit(1 if failed else 0)
