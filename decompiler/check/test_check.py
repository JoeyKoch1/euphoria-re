import subprocess
import unittest
from unittest.mock import patch

import check


class CheckTests(unittest.TestCase):
    def test_incomplete_output_fails(self):
        with self.assertRaises(RuntimeError):
            check.compare_outputs(['f 1', 'f 2'], ['f 1'])
        self.assertEqual(check.compare_outputs(['f 1'], ['f 1']), {})
        self.assertIn('f', check.compare_outputs(['f 1'], ['f 2']))

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


if __name__ == '__main__':
    unittest.main()
