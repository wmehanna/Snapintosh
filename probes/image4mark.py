# SPDX-License-Identifier: MIT
"""Opt-in edits to the guest Image4 kext: failure marks, and the chain root.

Two independent switches, both rewriting the loader's copy of the stock
kernelcache and never the firmware file:

SNAP_IMAGE4_MARK=1 marks the routines the manifest trust evaluation calls
before it ever logs a manifest property, so the silent -1 becomes a number
that names the routine:

    Img4DecodeVerifyChainIM4C     MOVN W0, #0  ->  NOP     (keep the callback's code)
    Img4DecodeComputeDigest       MOVN W0, #0  ->  MOVZ W0, #0x61
    verify_signature_ml_dsa_87    MOVN W0, #0  ->  MOVZ W0, #0x71
    verify_signature_rsa4096_fixed MOVN W0, #0 ->  MOVZ W0, #0x81

Every routine is still entered, and the manifest init, digest, chain and
signature steps still run in order. The kext logs the code it got beside the
evaluation status ("Image4: manifest evaluation: failed: %d, %d"), so 0x61
names the digest's argument checks, 0x71 the PQC signature half, 0x81 the
RSA half or its layout checks, and any other new number is the callback code
the chain verifier used to overwrite with -1.

SNAP_IMAGE4_DDI_GLOBAL=1 makes the Cryptex1|Splat decode-implementation
selector store the Global table instead of the DDI one:

    CSEL X9, X8, X9, NE  ->  MOV X9, X8

The selector's x509/rsa4096 branch picks between verify_chain_img4_ddi
(anchor: "Apple DDI Secure Boot Root CA - G1" at 0xaf30) and
verify_chain_img4_ddi_global (anchor: "Apple Extra Content Global Root CA -
G1" at 0x7770) on a flag the Splat caller always passes as zero. A vmapple
ticket chains to the Extra Content root, so with the stock selector the chain
crack fails and the whole evaluation returns -1. The patch only changes which
anchor the Cryptex1 x509 path cracks against; nothing else reads that result.

Admission. Each edit is found by a signature only its code carries, every site
is checked byte for byte before it is written, and a kernel is admitted only
when its sha256 is in PINS. A kernel that matches more or fewer sites than the
reviewed layout is refused instead of patched unreviewed.
"""
import hashlib
import re

# 26A428 J700 kernelcache.release.mac17p (same pin as probes/refmodskip.py).
J700_26A428 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
PINS = (J700_26A428,)

MOVN_MINUS1 = bytes.fromhex('00008012')
MARKS = (
    # Img4DecodeVerifyChainIM4C, 0x1c674 on: sub sp,#0x1e0 and the five argument
    # saves; 0x1c794 is the `mov w0,#-1; b` every early abort reaches, which
    # throws away the callback's own code.
    ('chain', bytes.fromhex('ff8307d1f40307aaf60306aaf30305aaf50304aa'), (0x120,), 2,
     bytes.fromhex('1f2003d5')),
    # Img4DecodeComputeDigest: mov x8,x2; mov x2,x0; then the default -1 that
    # every argument check returns with.
    ('digest', bytes.fromhex('e80302aae20300aa00008012020300b4'), (8,), 3,
     (0x52800000 | (0x61 << 5)).to_bytes(4, 'little')),
    # verify_signature_ml_dsa_87: cbz w0; mov w0,#-1; b, its single -1 exit.
    ('ml-dsa', bytes.fromhex('c00000340000801205000014'), (4,), 2,
     (0x52800000 | (0x71 << 5)).to_bytes(4, 'little')),
    # verify_signature_rsa4096_fixed: its prologue and the three `mov w0,#-1`
    # exits (key/signature layout, fault-canary, null public key). The fourth
    # -1 is the csinv after ccrsa_verify, which keeps the verify code already.
    ('rsa', bytes.fromhex('fa67bba9f85f01a9f65702a9f44f03a9fd7b04a9fd030191ff8300d1f70300aa'),
     (0x7c, 0x144, 0x1c4), 2, (0x52800000 | (0x81 << 5)).to_bytes(4, 'little')),
)
# The selector's ddi/ddi_global csel, one site per kext copy; the two copies
# order the two tst/csel pairs differently, so each needs its own signature.
# The patch replaces `csel x9, x8, x9, ne` with `mov x9, x8`.
SELECTORS = (
    (bytes.fromhex('bf0200720911899adf0200720811899a'), 4, bytes.fromhex('0911899a'), 1,
     bytes.fromhex('e90308aa')),
    (bytes.fromhex('ff0200720911899abf0200720011899a'), 4, bytes.fromhex('0911899a'), 1,
     bytes.fromhex('e90308aa')),
)


def _site(image, data, where, signature, want):
    ranges = [(fileoff, fileoff + filesize)
              for _, _, _, fileoff, filesize in image.executable_segments]
    hits = [m.start() for m in re.finditer(re.escape(signature), bytes(data))
            if any(a <= m.start() and m.start() + len(signature) <= b for a, b in ranges)]
    if len(hits) != want:
        raise SystemExit(f'image4 {where}: {len(hits)} sites for {len(signature)}-byte '
                         f'signature, expected {want}')
    return hits


def patch(image, data, marks=True, ddi_global=True):
    """Apply the selected edits in the loader's copy."""
    digest = hashlib.sha256(image.data).hexdigest()
    if digest not in PINS:
        raise SystemExit(f'image4: unknown kernelcache {digest}')
    sites, offsets, closure = {}, {}, []
    if marks:
        for name, signature, sites_in_func, want, replacement in MARKS:
            hits = _site(image, data, name, signature, want)
            for hit in hits:
                for offset in sites_in_func:
                    at = hit + offset
                    if bytes(data[at:at + 4]) != MOVN_MINUS1:
                        raise SystemExit(f'image4 mark: unexpected {name} bytes at {at:#x}')
                    data[at:at + 4] = replacement
                    offsets.setdefault(name, []).append(at)
            sites[name] = len(hits) * len(sites_in_func)
            closure.append(replacement)
    if ddi_global:
        sites['ddi-global'] = 0
        for signature, offset, expected, want, replacement in SELECTORS:
            for hit in _site(image, data, 'ddi-global', signature, want):
                at = hit + offset
                if bytes(data[at:at + 4]) != expected:
                    raise SystemExit(f'image4 ddi-global: unexpected bytes at {at:#x}')
                data[at:at + 4] = replacement
                offsets.setdefault('ddi-global', []).append(at)
                sites['ddi-global'] += 1
            closure.append(replacement)
    return {'sites': sites, 'offsets': offsets,
            'closure_sha256': hashlib.sha256(b''.join(closure)).hexdigest()}
