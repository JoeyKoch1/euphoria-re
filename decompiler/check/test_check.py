import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check


class CheckTests(unittest.TestCase):
    def test_incomplete_output_fails(self):
        with self.assertRaises(RuntimeError):
            check.compare_outputs(['f 1', 'f 2'], ['f 1'])
        self.assertEqual(check.compare_outputs(['f 1'], ['f 1']), {})
        self.assertIn('f', check.compare_outputs(['f 1'], ['f 2']))

    def test_first_divergence_is_named(self):
        with self.assertRaises(RuntimeError) as raised:
            check.compare_outputs(['f 1', 'f 2', 'f 3'], ['f 1', 'f 9'])
        self.assertIn('line 2', str(raised.exception))

    def test_failed_and_empty_programs_fail(self):
        for code, output in [(1, 'f 1\n'), (0, '')]:
            result = subprocess.CompletedProcess(['sample'], code, output, 'failed')
            with patch.object(check, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    check.output_lines('sample')

    def test_commands_have_a_timeout(self):
        with patch.object(check.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sample', 60)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                check.run(['sample'])
            self.assertEqual(run.call_args.kwargs['timeout'], 60)


class ToolchainTests(unittest.TestCase):
    def test_gcc_only_flag_is_kept_for_gcc(self):
        self.assertIn('-fno-tree-switch-conversion',
                      check.GNU('gcc').object_cmd(64, 'O0', 'f.c', 'f.o'))
        self.assertNotIn('-fno-tree-switch-conversion',
                         check.GNU('clang').object_cmd(64, 'O0', 'f.c', 'f.o'))

    def test_msvc_uses_msvc_switches(self):
        command = check.MSVC('cl').object_cmd(64, 'O2', 'f.c', 'f.obj')
        self.assertIn('/O2', command)
        self.assertIn('/Fof.obj', command)

    def test_probe_blames_the_missing_32_bit_runtime(self):
        result = subprocess.CompletedProcess(['gcc'], 1, '', 'ld: cannot find -lmingw32')
        with tempfile.TemporaryDirectory() as out:
            check.OUT = out
            with patch.object(check, 'run', return_value=result):
                reason = check.probe(check.GNU('gcc'), 32)
        self.assertIn('32-bit', reason)


if __name__ == '__main__':
    unittest.main()
