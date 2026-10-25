#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QEMU-only bulk transfer of the xnuboot image through q1n1's EFI preload.

Why: under QEMU TCG the q1n1 proxy on the emulated PL011 writes guest memory at
about 43 KiB/s (snaplab, QEMU 11.0.3, 2026-10-25: 2 MiB in 47.5 s; reads 181
KiB/s; thread=single 20 KiB/s), so the 122.7 MiB image took tens of minutes per
boot. EDK2 can instead read the same bytes from the -drive fat:rw: ESP before
ExitBootServices, q1n1 keeps them resident and rehashes them on request
(q1n1/docs/SSD-PRELOAD.md), and the host copies them with P_MEMCPY8.

The cache is content addressed: chunks are stored with their length and
SHA-256, never their guest address, because run.py places the image from the
live EFI memory map. A chunk is copied only when the current build produced
byte-identical data of the same length; anything else is uploaded as before.
Stale or absent caches therefore cost time, never correctness.

  python3 probes/qemu_preload.py seed      # offline build -> build/qemu-esp
  SNAP_QEMU_PRELOAD=1 python3 probes/run.py xnuboot --qemu ...
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EFI_DIR = 'Snapintosh'
BLOB = 'qemu-chunks.bin'
EFI_BLOB = '\\Snapintosh\\qemu-chunks.bin'
MANIFEST = 'q1n1-preload.bin'
INDEX = 'qemu-chunks.json'           # host side, beside the ESP, not on it
MIN_CHUNK = 64 << 10                 # small chunks cost little over the UART
COPY_STEP = 8 << 20                  # same bound as q1n1 preload.copy_cached
# Set by apply() when the resident cache missed chunks; Qemu.__exit__ writes it
# after QEMU has stopped, so vvfat never sees the ESP change under it.
PENDING = None


def _manifest(files):
    sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
    import preload
    return preload.manifest(files)


def enabled(environ):
    return environ.get('SNAP_QEMU_PRELOAD') == '1'


def ours(esp):
    """Is the ESP manifest absent or this cache's own? q1n1 reads one fixed
    path, \\Snapintosh\\q1n1-preload.bin, which the RAMDisk preload uses too
    (q1n1/platform/uefi/preload.h), so a foreign manifest is never touched."""
    path = Path(esp) / EFI_DIR / MANIFEST
    return not path.exists() or EFI_BLOB.encode('ascii') in path.read_bytes()


def remove(esp):
    esp = Path(esp)
    if ours(esp):
        (esp / EFI_DIR / MANIFEST).unlink(missing_ok=True)
    for path in (esp / EFI_DIR / BLOB, esp.parent / INDEX):
        path.unlink(missing_ok=True)


def write(esp, chunks, min_chunk=MIN_CHUNK):
    """Store the large chunks (deduplicated by content) on the ESP."""
    esp = Path(esp)
    if not ours(esp):
        print(f'QEMU preload: {esp / EFI_DIR / MANIFEST} belongs to another preload; not replaced')
        return None
    folder = esp / EFI_DIR
    folder.mkdir(parents=True, exist_ok=True)
    entries, seen, offset = [], set(), 0
    whole = hashlib.sha256()
    with (folder / BLOB).open('wb') as out:
        for pa, body in sorted(chunks.items()):
            data = bytes(body)
            if len(data) < min_chunk or pa % 8:     # P_MEMCPY8 needs 8-byte targets
                continue
            digest = hashlib.sha256(data).hexdigest()
            if (len(data), digest) in seen:
                continue
            seen.add((len(data), digest))
            pad = b'\0' * ((-offset) % 8)     # P_MEMCPY8 wants 8-byte sources
            out.write(pad)
            whole.update(pad)
            offset += len(pad)
            out.write(data)
            whole.update(data)
            entries.append(dict(offset=offset, size=len(data), sha256=digest))
            offset += len(data)
    if not entries:
        remove(esp)
        return None
    index = dict(blob_sha256=whole.hexdigest(), blob_size=offset, entries=entries)
    (folder / MANIFEST).write_bytes(_manifest([(EFI_BLOB, offset, index['blob_sha256'])]))
    (esp.parent / INDEX).write_text(json.dumps(index))
    return index


def lookup(index):
    return {(e['size'], e['sha256']): e['offset'] for e in index['entries']}


def apply(proxy, info, cached_files, chunks, index_path, min_chunk=MIN_CHUNK):
    """Copy every chunk the resident cache holds; drop it from `chunks`.

    Returns (bytes copied, chunks copied, note). A tail that is not a multiple
    of 8 stays in `chunks` at its own address and is uploaded normally."""
    global PENDING
    full = dict(chunks)
    try:
        index = json.loads(Path(index_path).read_text())
    except (OSError, ValueError):
        PENDING = full
        return 0, 0, 'no cache index'
    entry = next((f for f in cached_files if f['sha256'] == index['blob_sha256']
                  and f['size'] == index['blob_size']), None)
    if entry is None:
        PENDING = full
        return 0, 0, 'cache not resident (q1n1 did not load it)'
    if proxy.call(info['preload_verify'], entry['index'], timeout=600) != 1:
        raise ValueError('resident chunk cache no longer matches its manifest')
    where = lookup(index)
    copied = count = missed = 0
    for pa in sorted(chunks):
        body = chunks[pa]
        if len(body) < min_chunk or pa % 8:         # never cached, see write()
            continue
        offset = where.get((len(body), hashlib.sha256(body).hexdigest()))
        if offset is None:
            missed += 1
            continue
        aligned = len(body) & ~7
        for step in range(0, aligned, COPY_STEP):
            proxy.memcpy8(pa + step, entry['base'] + offset + step, min(COPY_STEP, aligned - step))
        tail = bytes(body[aligned:])
        del chunks[pa]
        if tail:
            chunks[pa + aligned] = tail
        copied += aligned
        count += 1
    if missed:
        PENDING = full
    return copied, count, f'{missed} large chunks not cached' if missed else 'all large chunks cached'


def seed(guest_profile, firmware_dir, kernelcache, esp):
    """Build the image offline exactly as run_xnuboot does and cache it."""
    import importlib.util
    sys.path.insert(0, str(ROOT / 'probes'))
    spec = importlib.util.spec_from_file_location('xnuboot', ROOT / 'probes/xnuboot.py')
    xb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(xb)
    xb.configure_guest(guest_profile, firmware_dir)
    built = xb.build(str(kernelcache or xb.DEFAULT_KERNELCACHE))
    return write(esp, built['chunks'])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('action', choices=['seed', 'remove'])
    ap.add_argument('--guest-profile', default='j700ap-26A428')
    ap.add_argument('--firmware-dir')
    ap.add_argument('--kernelcache')
    ap.add_argument('--esp', type=Path, default=ROOT / 'build' / 'qemu-esp')
    args = ap.parse_args()
    if args.action == 'remove':
        remove(args.esp)
        return 0
    index = seed(args.guest_profile, args.firmware_dir, args.kernelcache, args.esp)
    if not index:
        print('nothing to cache')
        return 1
    print(f'{args.esp / EFI_DIR / BLOB}: {len(index["entries"])} chunks, '
          f'{index["blob_size"] / (1 << 20):.1f} MiB, sha256 {index["blob_sha256"][:16]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
