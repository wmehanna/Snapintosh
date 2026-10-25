#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The QEMU TCG board profiles (probes/guestprofile.py): j700ap-26A428-no-clpc-tcg is
the RAM-image board with /arm-io/secure-repair withdrawn, and nothing else;
j700ap-26A428-bootfb-xars-uniform-no-audio-tcg is the A16 BaseSystem board with the
same withdrawal, so BaseSystem gets its BootPolicy os-type and CPSN replies.
The firmware-bundle check runs when the audited DeviceTree is present."""
import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import guestprofile as gp  # noqa: E402
from deferred import defer_subtrees  # noqa: E402

TREE = ROOT / 'downloads/extracted/j700ap/DeviceTree.j700ap'
REPAIR = '/device-tree/arm-io/secure-repair'


class TcgProfile(unittest.TestCase):
    def test_registered_and_only_withdraws_secure_repair(self):
        tcg, base = gp.get_profile('j700ap-26A428-no-clpc-tcg'), gp.J700_26A428_NO_CLPC
        self.assertIs(tcg, gp.J700_26A428_NO_CLPC_TCG)
        added = tcg.deferred_subtrees[len(base.deferred_subtrees):]
        self.assertEqual(tcg.deferred_subtrees[:len(base.deferred_subtrees)], base.deferred_subtrees)
        self.assertEqual([d.node for d in added], [REPAIR])
        for field in dataclasses.fields(base):
            if field.name not in ('name', 'deferred_subtrees'):
                self.assertEqual(getattr(tcg, field.name), getattr(base, field.name), field.name)

    def test_basesystem_tcg_is_the_a16_basesystem_board_with_the_tcg_withdrawal(self):
        tcg, base = gp.get_profile('j700ap-26A428-bootfb-xars-uniform-no-audio-tcg'), gp.J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO
        self.assertIs(tcg, gp.J700_26A428_BASESYSTEM_TCG)
        self.assertEqual(tcg.deferred_subtrees[:len(base.deferred_subtrees)], base.deferred_subtrees)
        self.assertEqual([d.node for d in tcg.deferred_subtrees[len(base.deferred_subtrees):]], [REPAIR])
        self.assertEqual(tcg.deferred_subtrees[-1], gp.J700_26A428_NO_CLPC_TCG.deferred_subtrees[-1])
        for field in dataclasses.fields(base):
            if field.name not in ('name', 'deferred_subtrees'):
                self.assertEqual(getattr(tcg, field.name), getattr(base, field.name), field.name)
    def test_basesystem_tcg_answers_bootpolicy_and_cpsn(self):
        # no-clpc-tcg has only the mailbox: bs-early-tasks never gets its
        # os-type reply and launchd stays in rc.cdrom (p4r6); without xars the
        # CPSN lookup panics "!booted" (p4r8).
        sep = gp.J700_26A428_BASESYSTEM_TCG.sep_asc
        self.assertTrue(sep.reply_transport and sep.rom_status and sep.service_bootstrap)
        self.assertTrue(sep.pnon_recovery and sep.xars_refusal)
        self.assertFalse(sep.pnon_refusal)
        self.assertIsNotNone(gp.J700_26A428_BASESYSTEM_TCG.sep_preload)
        self.assertFalse(gp.J700_26A428_NO_CLPC_TCG.sep_asc.pnon_recovery)
    def test_other_profiles_keep_secure_repair(self):
        for profile in gp.PROFILES.values():
            if profile not in (gp.J700_26A428_NO_CLPC_TCG, gp.J700_26A428_BASESYSTEM_TCG):
                self.assertNotIn(REPAIR, [d.node for d in profile.deferred_subtrees], profile.name)

    @unittest.skipUnless(TREE.exists(), 'audited firmware bundle absent')
    def test_withdrawal_matches_the_firmware_tree(self):
        import appledt
        dt = appledt.DeviceTree(TREE.read_bytes())
        spec = gp.J700_26A428_NO_CLPC_TCG.deferred_subtrees[-1]
        defer_subtrees(dt, (spec,))
        self.assertNotIn(REPAIR, dt.nodes)
        self.assertIn('/device-tree/arm-io/nub-gpio', dt.nodes)   # the NUB controller stays
        changed = appledt.DeviceTree(TREE.read_bytes())
        changed.nodes[REPAIR]['role'].value[:3] = b'AOP'
        with self.assertRaisesRegex(ValueError, 'deferred subtree changed'):
            defer_subtrees(changed, (spec,))


if __name__ == '__main__':
    unittest.main()
