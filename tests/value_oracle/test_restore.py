import os
import tempfile
import unittest

import core
import restore


class RespTest(unittest.TestCase):
    def test_encoding(self):
        self.assertEqual(b'*2\r\n$3\r\nDEL\r\n$1\r\nk\r\n',
                         restore.resp('DEL', 'k'))

    def test_binary_and_numbers(self):
        self.assertEqual(b'*3\r\n$4\r\nSADD\r\n$2\r\n\x00\n\r\n$1\r\n7\r\n',
                         restore.resp('SADD', b'\x00\n', 7))


class RestorerConfigTest(unittest.TestCase):
    def settings(self, dump):
        return {k: 'x' for k in restore.REQUIRED} | {'dump': dump}

    def test_missing_section(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer(None)

    def test_missing_keys(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer({'dump': '/nonexistent'})

    def test_missing_dump(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer(self.settings('/nonexistent/dump.sql.gz'))

    def test_valid(self):
        with tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            restorer = restore.Restorer(self.settings(f.name))
            self.assertEqual(f.name, restorer.s['dump'])

    def test_cake_cache_clear_keeps_placeholders(self):
        with tempfile.TemporaryDirectory() as app, \
                tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            for sub in ('models', 'persistent'):
                d = os.path.join(app, 'tmp', 'cache', sub)
                os.makedirs(d)
                for name in ('empty', 'cake_model_x'):
                    open(os.path.join(d, name), 'w').close()
            restorer = restore.Restorer(
                self.settings(f.name) | {'app_dir': app})
            self.assertEqual('removed 2 files', restorer.clear_cake_caches())
            self.assertTrue(os.path.exists(
                os.path.join(app, 'tmp', 'cache', 'models', 'empty')))


if __name__ == '__main__':
    unittest.main()
