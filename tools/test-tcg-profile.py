#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The QEMU TCG board profile j700ap-26A428-no-clpc-tcg (probes/guestprofile.py):
the RAM-image board with /arm-io/secure-repair withdrawn, and nothing else.
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

    def test_other_profiles_keep_secure_repair(self):
        for profile in gp.PROFILES.values():
            if profile is not gp.J700_26A428_NO_CLPC_TCG:
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
