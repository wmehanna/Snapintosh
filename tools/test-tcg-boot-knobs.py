#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""QEMU TCG boot knobs in probes/run.py: SNAP_QEMU_SMP and SNAP_CLOCK_DILATION.
No QEMU, no proxy: the vCPU count reaches the QEMU command line and the
declared host counter rate is the measured one times the dilation."""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run  # noqa: E402


def qemu_command(env):
    """The argv run.Qemu passes to Popen, from a fresh interpreter with env."""
    code = ('import sys, subprocess; sys.path.insert(0, "probes"); import run\n'
            'class P:\n'
            '    def __init__(self, argv, **kw): print(repr(argv)); raise SystemExit(0)\n'
            'subprocess.Popen = P\n'
            'from pathlib import Path\n'
            'q = run.Qemu.__new__(run.Qemu); q.sock = "/tmp/x.sock"; q.esp = Path("/tmp/esp")\n'
            'q.log = Path("/dev/null"); q.proc = None; q.drive = "format=raw,file=fat:rw:/tmp/esp"\n'
            'q.__enter__()\n')
    return subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True,
                          env={**os.environ, **env})


class ExtraCflags(unittest.TestCase):
    """SNAP_EXTRA_CFLAGS: an opt-in build recipe (e.g. the A16 control set) for QEMU runs."""
    def flags(self, value=None):
        env = {k: v for k, v in os.environ.items() if k != 'SNAP_EXTRA_CFLAGS'}
        if value is not None:
            env['SNAP_EXTRA_CFLAGS'] = value
        out = subprocess.run([sys.executable, '-c', 'import sys; sys.path.insert(0, "probes"); '
                              'import run; print(repr(run.FLAGS))'], cwd=ROOT, capture_output=True,
                             text=True, env=env, check=True).stdout
        return eval(out.strip())  # our own repr(list)
    def test_unset_keeps_the_default_flags(self):
        base = self.flags()
        self.assertEqual(base[-2:], ['-fno-stack-protector', '-mcmodel=tiny'])
        self.assertEqual(self.flags(''), base)
    def test_flags_are_appended_in_order(self):
        base = self.flags()
        got = self.flags('-Os -DSNAP_NATIVE_CALLS=1 "-DX=a b"')
        self.assertEqual(got, base + ['-Os', '-DSNAP_NATIVE_CALLS=1', '-DX=a b'])
class QemuSmp(unittest.TestCase):
    def smp(self, result):
        argv = eval(result.stdout.strip())  # our own repr(list) from qemu_command
        return argv[argv.index('-smp') + 1]

    def test_default_keeps_one_vcpu(self):
        env = {k: v for k, v in os.environ.items() if k != 'SNAP_QEMU_SMP'}
        result = subprocess.run([sys.executable, '-c', 'import sys; sys.path.insert(0, "probes"); '
                                 'import run; print(run.QEMU_SMP)'], cwd=ROOT, capture_output=True,
                                text=True, env=env)
        self.assertEqual(result.stdout.strip(), '1')

    def test_six_vcpus_reach_the_command_line(self):
        result = qemu_command({'SNAP_QEMU_SMP': '6'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.smp(result), '6')

    def test_invalid_counts_stop_before_qemu(self):
        for value in ('0', '7', 'six', '-1', ''):
            result = qemu_command({'SNAP_QEMU_SMP': value})
            self.assertNotEqual(result.returncode, 0, value)
            self.assertIn('SNAP_QEMU_SMP must be 1-6', result.stderr, value)


class ClockDilation(unittest.TestCase):
    def test_default_is_the_measured_rate(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SNAP_CLOCK_DILATION', None)
            self.assertEqual(run.host_timebase(19200000), 19200000)       # the A16
            self.assertEqual(run.host_timebase(1000000000), 1000000000)   # QEMU virt
        self.assertEqual(run.host_timebase(19200000, '1'), 19200000)

    def test_dilation_multiplies_the_declared_rate(self):
        self.assertEqual(run.host_timebase(1000000000, '4'), 4000000000)
        self.assertEqual(run.host_timebase(62500000, '16'), 1000000000)
        with patch.dict(os.environ, {'SNAP_CLOCK_DILATION': '3'}):
            self.assertEqual(run.host_timebase(19200000), 57600000)

    def test_refuse_out_of_range_or_wider_than_u32(self):
        for value in ('0', '17', 'x', '-2', '1.5', ''):
            with self.assertRaises(ValueError, msg=value):
                run.host_timebase(19200000, value)
        with self.assertRaisesRegex(ValueError, 'above 32 bits'):
            run.host_timebase(1000000000, '5')


class QuarantineOnQemu(unittest.TestCase):
    """SNAP_QEMU_READ_QUARANTINED: a QEMU-only way past an ownership quarantine."""
    def setUp(self):
        self.saved = run.ON_QEMU

    def tearDown(self):
        run.ON_QEMU = self.saved

    def test_ok_terminal_is_unchanged(self):
        for on in (False, True):
            run.ON_QEMU = on
            self.assertFalse(run.terminal_or_qemu_diagnostic(0, {}))

    def test_quarantine_stands_on_hardware_and_by_default(self):
        cases = [(False, {'SNAP_QEMU_READ_QUARANTINED': '1'}), (True, {}),
                 (True, {'SNAP_QEMU_READ_QUARANTINED': '0'})]
        for on, env in cases:
            run.ON_QEMU = on
            with self.assertRaises(run.XnubootQuarantined, msg=str((on, env))):
                run.terminal_or_qemu_diagnostic(0x51554e01, env)

    def test_qemu_opt_in_reads_the_report(self):
        run.ON_QEMU = True
        self.assertTrue(run.terminal_or_qemu_diagnostic(0x51554e01, {'SNAP_QEMU_READ_QUARANTINED': '1'}))
        with self.assertRaises(RuntimeError):         # a malformed terminal is never excused
            run.terminal_or_qemu_diagnostic('x', {'SNAP_QEMU_READ_QUARANTINED': '1'})


if __name__ == '__main__':
    unittest.main()
