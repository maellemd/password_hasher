import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cracker

SCRIPT = Path(cracker.__file__).resolve()


class HashTests(unittest.TestCase):
    def test_md5(self):
        self.assertEqual(cracker.hash_password('abc', 'md5'), '900150983cd24fb0d6963f7d28e17f72')

    def test_sha256(self):
        self.assertEqual(cracker.hash_password('abc', 'sha256'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_verification(self):
        digest = cracker.hash_password('abc', 'sha256')
        self.assertTrue(cracker.check_if_match('abc', digest, 'sha256'))
        self.assertFalse(cracker.check_if_match('wrong', digest, 'sha256'))

    def test_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            cracker.hash_password('abc', 'unknown')

    def test_missing_dependency(self):
        with patch.dict(sys.modules, {'bcrypt': None}):
            with self.assertRaises(RuntimeError):
                cracker.hash_password('abc', 'bcrypt')

    @unittest.skipUnless(importlib.util.find_spec('bcrypt'), 'optional bcrypt unavailable')
    def test_bcrypt(self):
        first = cracker.hash_password('sample', 'bcrypt')
        second = cracker.hash_password('sample', 'bcrypt')
        self.assertNotEqual(first, second)
        self.assertTrue(cracker.check_if_match('sample', first, 'bcrypt'))
        self.assertFalse(cracker.check_if_match('wrong', first, 'bcrypt'))

    @unittest.skipUnless(importlib.util.find_spec('bcrypt'), 'optional bcrypt unavailable')
    def test_bcrypt_length(self):
        with self.assertRaises(ValueError):
            cracker.hash_password('é' * 37, 'bcrypt')

    def test_missing_wordlist(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                cracker.dictionary_attack(hashlib.md5(b'abc').hexdigest(), Path(folder) / 'missing.txt', 'md5')


class CliTests(unittest.TestCase):
    def test_help(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--bcrypt', result.stdout)

    def test_invalid_argument(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--unknown'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments', result.stderr)

    def test_other_working_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(SCRIPT)], cwd=folder, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Password Hasher', result.stdout)


if __name__ == '__main__':
    unittest.main()
