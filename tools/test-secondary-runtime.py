#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host launch admission tests; no physical CPU start or proxy connection."""
import copy
import runpy
import struct
import unittest
from unittest.mock import patch
from dataclasses import replace
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
API=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))

class Admission(unittest.TestCase):
    def test_explicit_profile_binding(self):
        import guestprofile as gp
        for profile in (gp.J700_26A428, gp.J700_26A428_NO_CLPC, gp.J700_26A428_NO_CLPC_TCG,
                        gp.J700_26A428_SEP_PRELOAD, gp.J700_26A428_BOOTFB,
                        gp.J700_26A428_BOOTFB_NUB):
            API['validate_guest_profile'](profile.name)
        changed = replace(gp.J700_26A428_BOOTFB, name='changed-cpu', boot_mpidr=0x100)
        with patch.dict(gp.PROFILES, {changed.name: changed}):
            with self.assertRaises(ValueError):
                API['validate_guest_profile'](changed.name)

    def setUp(self):
        self.inventory=dict(current_el=2,psci_compliant=True,psci_uses_hvc=False,
            boot_mpidr='0x0',features={f:0 for f in ('0xc4000003','0x84000002','0xc4000004')},
            gic=dict(distributors=[dict(base='0x17000000',version=4)]),cpus=[
                dict(mpidr=hex(i*0x100),flags=1,affinity_state=0 if i==0 else 1,
                     redistributor=hex(0x17080000+i*0x40000)) for i in range(6)])
        self.memory=dict(sctlr='0x10003000100d',tcr='0x80843514',ttbr0='0xa8f5a000',
                         mair='0xffbb4400',hcr='0x88000010')
    def test_measured_binding(self):
        words=API['config_words'](self.inventory,self.memory)
        self.assertEqual(len(struct.pack('<24Q',*words)),192)
        self.assertEqual(words[:4],(API['MAGIC'],192,0,2))
        self.assertEqual(words[9],0x100)
        self.assertEqual(words[15],0x170c0000)
        self.assertFalse(any(words[10:14]+words[16:20]))
        # GIC geometry words: the six-core fixture's own frame run, measured, not assumed.
        self.assertEqual(words[20:],(0x17000000,0x17080000,0x17080000+6*0x40000,0x40000))
    def test_no_launch_with_unknown_or_running_peer(self):
        for state in (0,2,None,-1):
            inventory=copy.deepcopy(self.inventory);inventory['cpus'][2]['affinity_state']=state
            with self.assertRaises(ValueError):API['config_words'](inventory,self.memory)
    def test_multiple_explicit_affinities(self):
        words=API['config_words'](self.inventory,self.memory,0xe)
        self.assertEqual(words[3],0xe)
        self.assertEqual(words[9:12],(0x100,0x200,0x300))
        self.assertEqual(words[15:18],(0x170c0000,0x17100000,0x17140000))
        for mask in (0,1,0x40,0x3f,-1,None):
            with self.assertRaises(ValueError):API['config_words'](self.inventory,self.memory,mask)
    def test_all_five_secondaries_have_distinct_physical_bindings(self):
        words=API['config_words'](self.inventory,self.memory,0x3e)
        self.assertEqual(words[3],0x3e)
        self.assertEqual(words[9:14],(0x100,0x200,0x300,0x400,0x500))
        self.assertEqual(words[15:20],tuple(0x17080000+i*0x40000 for i in range(1,6)))
        p_only=API['config_words'](self.inventory,self.memory,0x30)
        self.assertFalse(any(p_only[9:12]+p_only[15:18]))
        self.assertEqual(p_only[12:14],(0x400,0x500))
        for index in (4,5):
            bad=copy.deepcopy(self.inventory);bad['cpus'][index]['affinity_state']=0
            with self.assertRaises(ValueError):API['config_words'](bad,self.memory,0x3e)
    def test_refuse_bad_hardware_contract(self):
        changes=[('current_el',1),('psci_uses_hvc',True),('psci_compliant',False),('boot_mpidr','0x100')]
        for key,value in changes:
            inventory=copy.deepcopy(self.inventory);inventory[key]=value
            with self.assertRaises(ValueError):API['config_words'](inventory,self.memory)
        inventory=copy.deepcopy(self.inventory);inventory['cpus'][1]['redistributor']='0x17080000'
        with self.assertRaises(ValueError):API['config_words'](inventory,self.memory)
    def test_refuse_changed_memory_regime(self):
        for key,value in [('sctlr','0x0'),('tcr','0x80843515'),('ttbr0','0x0'),('hcr','0x400000000')]:
            memory={**self.memory,key:value}
            with self.assertRaises(ValueError):API['config_words'](self.inventory,memory)

class PrimeLayout(unittest.TestCase):
    """SNAP_SMP_PRIME=1: all six vCPUs on Prime cluster 1, vCPU 0 relocated (mask bit 0)."""
    def setUp(self):
        mpidrs=[c*0x10000+i*0x100 for c in range(3) for i in range(6)]
        self.inventory=dict(current_el=2,psci_compliant=True,psci_uses_hvc=False,
            boot_mpidr='0x0',features={f:0 for f in ('0xc4000003','0x84000002','0xc4000004')},
            gic=dict(distributors=[dict(base='0x17000000',version=4)]),cpus=[
                dict(mpidr=hex(m),flags=1,affinity_state=0 if m==0 else 1,
                     redistributor=hex(0x17080000+n*0x40000),efficiency_class=0 if m<0x10000 else 1)
                for n,m in enumerate(mpidrs)])
        self.memory=dict(sctlr='0x10003000100d',tcr='0x80843514',ttbr0='0xa8f5a000',
                         mair='0xffbb4400',hcr='0x88000010')
    def words(self,prime='1',mask=0x3e,inventory=None):
        with patch.dict('os.environ',{'SNAP_SMP_PRIME':prime}):
            return API['config_words'](inventory or self.inventory,self.memory,mask)
    def test_all_six_in_prime_cluster_one(self):
        words=self.words()
        self.assertEqual(words[2:4],(0,0x3f))
        self.assertEqual(words[8:14],tuple(0x10000+i*0x100 for i in range(6)))
        self.assertEqual(words[14:20],tuple(0x17080000+(6+i)*0x40000 for i in range(6)))
        partial=self.words(mask=0x6)
        self.assertEqual((partial[3],partial[8:11]),(0x7,(0x10000,0x10100,0x10200)))
        self.assertFalse(any(partial[11:14]+partial[17:20]))
    def test_default_layout_unchanged_on_eighteen_cores(self):
        words=self.words(prime='0')
        self.assertEqual(words[3],0x3e)
        self.assertEqual(words[8:14],(0,0x100,0x200,0x300,0x400,0x500))
        self.assertEqual((words[8],words[14]),(0,0))
    def test_refuse_a_layout_spanning_clusters(self):
        # q1n1 on a Prime core with the default secondaries: the v26 shape, mirrored.
        moved=copy.deepcopy(self.inventory);moved['boot_mpidr']='0x10000'
        for cpu in moved['cpus']:
            cpu['affinity_state']=0 if cpu['mpidr']=='0x10000' else 1
        with self.assertRaisesRegex(ValueError,'span physical clusters'):self.words(prime='0',inventory=moved)
    def test_refuse_a_lower_class_or_busy_target(self):
        for index in (6,8):   # 0x10000 (vCPU 0's target) and 0x10200
            low=copy.deepcopy(self.inventory);low['cpus'][index]['efficiency_class']=0
            with self.assertRaisesRegex(ValueError,'highest efficiency class'):self.words(inventory=low)
            busy=copy.deepcopy(self.inventory);busy['cpus'][index]['affinity_state']=0
            with self.assertRaises(ValueError):self.words(inventory=busy)
        unknown=copy.deepcopy(self.inventory);del unknown['cpus'][3]['efficiency_class']
        with self.assertRaises(ValueError):self.words(inventory=unknown)
        with self.assertRaises(ValueError):self.words(prime='2')
    def test_q1n1_cpu_cannot_be_the_target(self):
        moved=copy.deepcopy(self.inventory);moved['boot_mpidr']='0x10000'
        for cpu in moved['cpus']:
            cpu['affinity_state']=0 if cpu['mpidr']=='0x10000' else 1
        with self.assertRaises(ValueError):self.words(inventory=moved)

class PlatformGeometry(unittest.TestCase):
    """Phase 3: GIC and MPIDR layout from the platform (MADT + GICR_TYPER), A16 unchanged."""
    FEATURES={f:0 for f in ('0xc4000003','0x84000002','0xc4000004')}
    A16_MEMORY=dict(sctlr='0x10003000100d',tcr='0x80843514',ttbr0='0xa8f5a000',mair='0xffbb4400',hcr='0x88000010')
    # snaplab QEMU 11.0.3 AAVMF: HCR_EL2 0x408000038 (E2H, TGE), TCR_EL2 0x580803510 (VHE layout).
    QEMU_MEMORY=dict(sctlr='0x30c5183d',tcr='0x580803510',ttbr0='0x43ffff000',mair='0xffbb4400',hcr='0x408000038')
    def a16(self):
        """The A16 MADT: 18 cores, three clusters of six, GICC GICR bases 0x40000 apart, GICv4."""
        mpidrs=[c*0x10000+i*0x100 for c in range(3) for i in range(6)]
        return dict(current_el=2,psci_compliant=True,psci_uses_hvc=False,boot_mpidr='0x0',
            features=self.FEATURES,gic=dict(distributors=[dict(base='0x17000000',version=4)],redistributors=[]),
            cpus=[dict(mpidr=hex(m),flags=1,affinity_state=0 if m==0 else 1,
                       redistributor=hex(0x17080000+n*0x40000),efficiency_class=0 if m<0x10000 else 1)
                  for n,m in enumerate(mpidrs)])
    def virt(self,count=6):
        """QEMU virt gic-version=3: GICC records with no GICR base, one GICR range, Aff0 numbers CPUs."""
        return dict(current_el=2,psci_compliant=True,psci_uses_hvc=False,boot_mpidr='0x0',
            features=self.FEATURES,gic=dict(distributors=[dict(base='0x8000000',version=3)],
                                            redistributors=[dict(base='0x80a0000',span=0xf60000)]),
            cpus=[dict(mpidr=hex(i),flags=1,affinity_state=0 if i==0 else 1,redistributor='0x0',
                       efficiency_class=0) for i in range(count)])
    @staticmethod
    def typer(count,base=0x80a0000,stride=0x20000,vlpis=0):
        """GICR_TYPER per frame: affinity in [63:32], Last (bit 4) on the final frame."""
        frames={base+i*stride+8:(i<<32)|(0x10 if i==count-1 else 0)|vlpis for i in range(count)}
        def read64(pa):
            if pa not in frames:raise AssertionError(f'read outside the redistributor frames: {pa:#x}')
            return frames[pa]
        return read64
    def test_a16_result_is_the_former_constants(self):
        inventory=self.a16()
        geometry=API_PROBE['gic_geometry'](API_PROBE['fill_redistributors'](inventory,None))
        self.assertEqual((geometry['gicd'],geometry['first'],geometry['end'],geometry['stride']),
                         (0x17000000,0x17080000,0x17500000,0x40000))
        words=API['config_words'](inventory,self.A16_MEMORY,0x3e)
        self.assertEqual(words[8:14],(0,0x100,0x200,0x300,0x400,0x500))
        self.assertEqual(words[15:20],tuple(0x17080000+i*0x40000 for i in range(1,6)))
        self.assertEqual(words[20:],(0x17000000,0x17080000,0x17500000,0x40000))
        self.assertEqual(words[4:8],(0x10003000100d,0x80843514,0xa8f5a000,0xffbb4400))
        with patch.dict('os.environ',{'SNAP_SMP_PRIME':'1'}):
            prime=API['config_words'](inventory,self.A16_MEMORY,0x3e)
        self.assertEqual(prime[8:14],tuple(0x10000+i*0x100 for i in range(6)))
    def test_qemu_virt_from_madt_and_typer(self):
        inventory=API_PROBE['fill_redistributors'](self.virt(),self.typer(6))
        self.assertEqual([c['redistributor'] for c in inventory['cpus']],
                         [hex(0x80a0000+i*0x20000) for i in range(6)])
        words=API['config_words'](inventory,self.QEMU_MEMORY,0x3e)
        self.assertEqual(words[2:4],(0,0x3e))
        self.assertEqual(words[9:14],(1,2,3,4,5))
        self.assertEqual(words[15:20],tuple(0x80a0000+i*0x20000 for i in range(1,6)))
        self.assertEqual(words[20:],(0x8000000,0x80a0000,0x80a0000+6*0x20000,0x20000))
        # The regime words are what the monitor runs after clearing E2H (compat/vhe-tcr.h).
        self.assertEqual(words[5],0x80853510)
    def test_typer_walk_follows_vlpis_and_last(self):
        v4=self.virt(2);v4['gic']['distributors'][0]['version']=4
        API_PROBE['fill_redistributors'](v4,self.typer(2,stride=0x40000,vlpis=2))
        self.assertEqual([c['redistributor'] for c in v4['cpus']],['0x80a0000','0x80e0000'])
        # Last stops the walk: a CPU beyond it has no frame.
        with self.assertRaisesRegex(ValueError,'no redistributor'):
            API_PROBE['fill_redistributors'](self.virt(3),self.typer(2))
    def test_refuse_bad_platform_geometry(self):
        no_range=self.virt();no_range['gic']['redistributors']=[]
        with self.assertRaises(ValueError):API_PROBE['fill_redistributors'](no_range,self.typer(6))
        duplicate=self.typer(6)
        with self.assertRaisesRegex(ValueError,'two redistributors'):
            API_PROBE['fill_redistributors'](self.virt(),lambda pa:duplicate(pa)&~(0xff<<32)|(1<<32))
        cases=[('distributors',[]),('distributors',[dict(base='0x8000000',version=2)]),
               ('distributors',[dict(base='0x8001000',version=3)]),
               ('distributors',[dict(base='0x80a0000',version=3)])]      # inside the frames
        for key,value in cases:
            bad=API_PROBE['fill_redistributors'](self.virt(),self.typer(6));bad['gic'][key]=value
            with self.assertRaises(ValueError,msg=str(value)):API['config_words'](bad,self.QEMU_MEMORY,0x3e)
        gap=API_PROBE['fill_redistributors'](self.virt(),self.typer(6));gap['cpus'][5]['redistributor']='0x8160000'
        with self.assertRaisesRegex(ValueError,'contiguous'):API_PROBE['gic_geometry'](gap)
    def test_cluster_has_too_few_cores(self):
        inventory=API_PROBE['fill_redistributors'](self.virt(4),self.typer(4))
        API['config_words'](inventory,self.QEMU_MEMORY,0xe)
        with self.assertRaisesRegex(ValueError,'fewer cores'):API['config_words'](inventory,self.QEMU_MEMORY,0x3e)
    def test_vhe_regime_converted_like_the_monitor(self):
        regime=API_MAP['validate_regime'](self.QEMU_MEMORY)
        self.assertEqual(regime,(0x30c5183d,0x80853510,0x43ffff000,0xffbb4400))
        self.assertEqual(API_MAP['validate_regime'](self.A16_MEMORY),(0x10003000100d,0x80843514,0xa8f5a000,0xffbb4400))
        for key,value in [('tcr',hex(0x580803510&~(1<<23))),   # TTBR1 walks live (EPD1 clear)
                          ('tcr',hex(0x580803510&~(7<<32)|(3<<32))),   # IPS 42 bits
                          ('tcr',hex(0x580803510&~0x3f|12))]:   # T0SZ 12: 52-bit VA
            with self.assertRaises(ValueError,msg=value):API_MAP['validate_regime']({**self.QEMU_MEMORY,key:value})
    def test_python_vhe_conversion_matches_the_header(self):
        import random,subprocess,tempfile
        rng=random.Random(3);values=[0x580803510]+[rng.getrandbits(64) for _ in range(64)]
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'t.c';exe=Path(d)/'t'
            src.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include "vhe-tcr.h"\n'
                           'int main(int n,char **v){for(int i=1;i<n;i++)printf("%llx\\n",'
                           '(unsigned long long)vhe_tcr_to_el2(strtoull(v[i],0,16)));return 0;}\n')
            subprocess.run(['cc','-I',str(ROOT/'compat'),str(src),'-o',str(exe)],check=True)
            out=subprocess.run([str(exe),*(f'{v:x}' for v in values)],check=True,capture_output=True,text=True).stdout
        self.assertEqual([int(x,16) for x in out.split()],[API_MAP['vhe_tcr_to_el2'](v) for v in values])

API_PROBE=runpy.run_path(str(ROOT/'tools/probe-a16-secondary.py'))
API_MAP=runpy.run_path(str(ROOT/'tools/host-el2-mapping.py'))
if __name__=='__main__':unittest.main()
