#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Enable personality publication for a Snapintosh-owned AuxKC.

The collection builder inserts OSBundleRequireExplicitLoad. This explicit local
packaging step changes only that metadata flag in a new collection. It leaves
Apple code, driver code, fixups, UUIDs, offsets and section sizes unchanged.
Failure inventory: docs/ADRENO-AUXKC-AUTOLOAD-20260926.md.

One --bundle is the original single-kext form and writes the original record.
Several (AdrenoX2 plus SnapI2CHID, docs/A16-INPUT-INSTALLED-20261017.md) must
name exactly the collection's kexts, every one Snapintosh-owned, explicit-load
and carrying personalities; each gets the same one-token change, and nothing
else may differ, parsed or byte for byte.

--allow-foreign accepts a collection that also carries a kext kmutil pulled in
as a dependency (com.apple.driver.AppleMobileDevice beside AdrenoX2 in the TCG
board's collection). Only the named Snapintosh bundles are flipped; a foreign
entry keeps every byte and carries no explicit-load token of its own.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from auxkc import Collection

def prepare(raw, expected_sha256, bundle, allow_foreign=False):
    """bundle: one bundle id (the single-kext form), or a list of them.
    allow_foreign: the collection may also carry kexts kmutil pulled in (a
    dependency, such as com.apple.driver.AppleMobileDevice). Every entry that
    carries OSBundleRequireExplicitLoad is flipped, ours and dependencies alike;
    everything else keeps every byte."""
    multi = not isinstance(bundle, str)
    bundles = list(bundle) if multi else [bundle]
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=expected_sha256:
        raise ValueError('source collection hash differs from reviewed input')
    if not bundles or len(set(bundles))!=len(bundles):
        raise ValueError('bundle ids must be given once each')
    if not all(b.startswith('org.snapintosh.') for b in bundles):
        raise ValueError('autoload packaging is scoped to a Snapintosh-owned bundle')
    before=Collection(raw); info=before.prelink_info()
    entries=info['_PrelinkInfoDictionary']
    ids=[e.get('CFBundleIdentifier') for e in entries]
    flagged=[e for e in entries if e.get('OSBundleRequireExplicitLoad') is True]
    flagged_ids=[e.get('CFBundleIdentifier') for e in flagged]
    if len(ids)!=len(set(ids)) or not all(b in ids for b in bundles):
        raise ValueError('expected exactly the requested bundle'+('s' if multi else ''))
    if not allow_foreign and sorted(ids)!=sorted(bundles):
        raise ValueError('expected exactly the requested bundle'+('s' if multi else ''))
    if not all(b in flagged_ids for b in bundles):
        raise ValueError('expected an explicit-load-only input; refuse repeated transform')
    for entry in flagged:
        if not entry.get('IOKitPersonalities'):
            raise ValueError('bundle has no personalities to publish')
    address,size,offset=before.sections[('__PRELINK_INFO','__info')]
    section=raw[offset:offset+size]
    # Replace one indentation byte with the extra letter in false. XML length,
    # termination, Mach-O layout and every byte outside this token stay fixed.
    pattern=rb'(<key>OSBundleRequireExplicitLoad</key>[\t\r\n ]*)([\t ])<true/>'
    matches=list(re.finditer(pattern,section))
    if len(matches)!=len(flagged):
        raise ValueError('expected one boolean token with spare indentation per explicit-load entry')
    changed=bytearray(raw); spans=[]
    for match in matches:
        replacement=match.group(1)+b'<false/>'
        if len(replacement)!=match.end()-match.start():
            raise ValueError('metadata replacement changes byte length')
        start=offset+match.start();end=offset+match.end()
        changed[start:end]=replacement
        spans.append((start,end,raw[start:end].decode(),replacement.decode()))
    changed=bytes(changed)
    after=Collection(changed)
    expected=copy.deepcopy(info)
    for entry in expected['_PrelinkInfoDictionary']:
        if entry.get('CFBundleIdentifier') in flagged_ids:
            entry['OSBundleRequireExplicitLoad']=False
    if after.prelink_info()!=expected:
        raise ValueError('parsed metadata differs beyond the autoload flag')
    for name in ('segments','sections','entries','uuid','fixups','top','mh_vmaddr'):
        if getattr(before,name)!=getattr(after,name):
            raise ValueError('collection layout or identity changed: '+name)
    kept=[0]+[x for s,e,_,_ in spans for x in (s,e)]+[len(raw)]
    if len(changed)!=len(raw) or any(changed[a:b]!=raw[a:b] for a,b in zip(kept[0::2],kept[1::2])):
        raise ValueError('bytes outside the metadata token changed')
    common=dict(source_sha256=digest,
        output_sha256=hashlib.sha256(changed).hexdigest(),
        prelink_section=dict(address=address,size=size,file_offset=offset),
        foreign_bundles=sorted(set(ids)-set(bundles)),flipped_bundles=flagged_ids)
    boundary='Local metadata packaging only; personality publication and driver execution require a fresh guest.'
    count=sum(a!=b for a,b in zip(raw,changed))
    if not multi:
        start,end,original,replacement=spans[0]
        return changed,dict(bundle=bundle,**common,
            changed_range=[start,end],changed_byte_count=count,
            original_token=original,replacement_token=replacement,
            explicit_load_before=True,explicit_load_after=False,
            unchanged_executable_and_fixup_bytes=True,boundary=boundary)
    return changed,dict(bundles=bundles,**common,
        changed_ranges=[[s,e] for s,e,_,_ in spans],changed_byte_count=count,
        original_tokens=[o for _,_,o,_ in spans],replacement_tokens=[r for _,_,_,r in spans],
        explicit_load_before=True,explicit_load_after=False,
        unchanged_executable_and_fixup_bytes=True,boundary=boundary)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--bundle',required=True,action='append',
                        help='repeat for a several-kext collection')
    parser.add_argument('--allow-foreign',action='store_true',
                        help='the collection may also carry kexts kmutil added (a dependency); their bytes stay as they are')
    parser.add_argument('--record',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or args.record.exists():
        raise ValueError('fresh output and record paths required')
    raw,record=prepare(args.source.read_bytes(),args.expected_sha256,
                       args.bundle[0] if len(args.bundle)==1 else args.bundle,
                       allow_foreign=args.allow_foreign)
    record.update(source=str(args.source),output=str(args.output),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open('xb') as stream:stream.write(raw)
    with args.record.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(output=str(args.output),record=str(args.record),
                         sha256=record['output_sha256'],changed_bytes=record['changed_byte_count'])))

if __name__=='__main__':main()
