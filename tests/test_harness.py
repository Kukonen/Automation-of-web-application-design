"""Negative experiments use artificial secrets and never read a real .env."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'harness' / 'guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = guard.ROOT
        guard.ROOT = Path(self.temp.name)
        (guard.ROOT / '.env').write_text('TOKEN=ARTIFICIAL_CANARY_DO_NOT_EXPORT', encoding='utf-8')
        (guard.ROOT / 'public.txt').write_text('public', encoding='utf-8')

    def tearDown(self):
        guard.ROOT = self.previous
        self.temp.cleanup()

    def test_secret_denied(self):
        with self.assertRaises(PermissionError):
            guard.read_project('.env')

    def test_secret_case_denied(self):
        with self.assertRaises(PermissionError):
            guard.read_project('.ENV')

    def test_secret_variant_denied(self):
        with self.assertRaises(PermissionError):
            guard.read_project('.ENV.local')

    def test_secret_symlink_denied(self):
        alias = guard.ROOT / 'alias.txt'
        try:
            alias.symlink_to(guard.ROOT / '.env')
        except OSError:
            self.skipTest('Creating symlinks is unavailable in this Windows environment')
        with self.assertRaises(PermissionError):
            guard.read_project('alias.txt')

    def test_traversal_denied(self):
        with self.assertRaises(PermissionError):
            guard.read_project('../outside.txt')

    def test_absolute_denied(self):
        with self.assertRaises(PermissionError):
            guard.read_project(str(guard.ROOT / 'public.txt'))

    def test_public_file_allowed(self):
        self.assertEqual(guard.read_project('public.txt'), 'public')

    def test_arbitrary_shell_denied(self):
        with self.assertRaises(PermissionError):
            guard.execute('delete all files')

    def test_network_action_denied(self):
        with self.assertRaises(PermissionError):
            guard.execute('send-data')


if __name__ == '__main__':
    unittest.main()
