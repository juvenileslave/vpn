"""Fast role-local validation tests; real service acceptance lives in runtime_vm.sh."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

FILES = Path(__file__).resolve().parents[1] / 'files'
sys.path.insert(0, str(FILES))
from validate_content import validate
import lifecycle

PAGE = '<!doctype html><title>Imaginary landscapes</title><h1>Imaginary landscapes</h1><p>A locally curated collection of synthetic landscape observations, weather notes and illustrated journeys for a disposable exhibition.</p><link rel="stylesheet" href="site.css">'

class ContentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'index.html').write_text(PAGE)
        (self.root / 'site.css').write_text('body { color: #234; }')

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_manifest(self):
        self.assertEqual(validate(self.root), ['index.html', 'site.css'])
        (self.root / 'site.css').unlink()
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_no_external_resources(self):
        (self.root / 'index.html').write_text(PAGE + '<script src="https://tracker.example.test/pixel.js"></script>')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_no_service_embedding(self):
        (self.root / 'index.html').write_text(PAGE + '<iframe src="panel.html"></iframe>')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_no_symlink_or_hidden_material(self):
        (self.root / 'key.pem').symlink_to('/dev/null')
        with self.assertRaises(ValueError):
            validate(self.root)
        (self.root / 'key.pem').unlink()
        (self.root / '.secret').write_text('not public')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_no_empty_placeholder(self):
        (self.root / 'index.html').write_text('<title>health</title>ok')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_no_parent_escape(self):
        (self.root / 'index.html').write_text(PAGE + '<a href="../../outside.txt">outside</a>')
        with self.assertRaises(ValueError):
            validate(self.root)

class ParserTests(unittest.TestCase):
    def test_servers_keep_stream_and_ignore_nested_locations(self):
        parsed = lifecycle.servers('http { server { listen 80; server_name "cover.example.test"; location / { return 404; } } } stream { server { listen 8443; proxy_pass local; } }')
        self.assertEqual(parsed, [(False, [['listen', '80'], ['server_name', 'cover.example.test']]), (True, [['listen', '8443'], ['proxy_pass', 'local']])])

    def test_comment_cannot_invent_listener(self):
        self.assertEqual(lifecycle.servers('# listen 8443;\nserver {listen 80; # server_name fake;\nserver_name other.example.test;}'), [(False, [['listen', '80'], ['server_name', 'other.example.test']])])

class LifecycleTests(unittest.TestCase):
    def test_restore_restores_checked_renewal_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            old = root / 'checked-release'
            old.mkdir()
            checked = {'hostname': 'cover.example.test', 'port': 9443}
            (old / 'metadata.json').write_text(json.dumps({'settings': checked}))
            (old / 'site.conf').write_text('# checked owned configuration\n')
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'hostname': 'rejected.example.test', 'port': 19443}))
            with patch.multiple(lifecycle, ENABLED=root / 'enabled', ACTIVE=root / 'active',
                                PREVIOUS=root / 'previous', SETTINGS=settings):
                lifecycle.restore(str(old), None)
                self.assertEqual(json.loads(settings.read_text()), checked)
                self.assertEqual((root / 'enabled').resolve(), old / 'site.conf')
                self.assertEqual((root / 'active').resolve(), old)

if __name__ == '__main__':
    unittest.main()
