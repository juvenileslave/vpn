"""Filesystem transaction tests, not nginx/ACME/network acceptance."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'files'))
import lifecycle
import ownership


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.base = self.root / 'state'
        self.base.mkdir()
        self.enabled = self.root / 'enabled'
        self.settings = self.root / 'settings.json'
        self.previous = self.base / 'previous'
        self.active = self.base / 'active'
        self.pending = self.base / 'pending.json'
        self.constants = patch.multiple(lifecycle, BASE=self.base, ENABLED=self.enabled,
            SETTINGS=self.settings, PREVIOUS=self.previous, ACTIVE=self.active, PENDING=self.pending)
        self.constants.start()
        self.old = self.make_release('A', tls=True, port=9443)
        self.older = self.make_release('B', tls=True, port=19443)
        self.candidate = self.make_release('C', tls=True, port=28443)
        lifecycle.restore(str(self.old), str(self.older))

    def tearDown(self):
        self.constants.stop()
        self.temporary.cleanup()

    def make_release(self, name, *, tls, port):
        path = self.base / name
        path.mkdir()
        (path / 'site.conf').write_text(lifecycle.MARKER + '. Unit fixture\n')
        (path / 'metadata.json').write_text(json.dumps({'settings': {'port': port}}))
        if tls:
            (path / 'certificate').mkdir()
        return path

    def assert_restored(self):
        self.assertEqual(self.active.resolve(), self.old)
        self.assertEqual(self.previous.resolve(), self.older)
        self.assertEqual(self.enabled.resolve(), self.old / 'site.conf')
        self.assertEqual(json.loads(self.settings.read_text()), {'port': 9443})
        self.assertFalse(self.pending.exists())

    def test_interruption_at_every_commit_pointer_and_settings_write(self):
        for point in ('previous', 'active', 'settings'):
            with self.subTest(point=point):
                lifecycle.restore(str(self.old), str(self.older))
                real_link, real_json = lifecycle.link, lifecycle.atomic_json

                def interrupted_link(path, target):
                    real_link(path, target)
                    if path == self.base / point:
                        raise SystemExit('simulated process interruption, not a caught activation error')

                def interrupted_json(path, value):
                    real_json(path, value)
                    if point == 'settings' and path == self.settings:
                        raise SystemExit('simulated process interruption')

                with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'run'), \
                     patch.object(lifecycle.subprocess, 'run') as process, \
                     patch.object(lifecycle, 'health', return_value={'tls': True, 'http2': True}), \
                     patch.object(lifecycle, 'link', side_effect=interrupted_link), \
                     patch.object(lifecycle, 'atomic_json', side_effect=interrupted_json):
                    process.return_value.returncode = 0
                    with self.assertRaises(SystemExit):
                        lifecycle.activate(self.candidate)
                journal = json.loads(self.pending.read_text())
                self.assertEqual(journal['old'], str(self.old))
                self.assertEqual(journal['previous'], str(self.older))
                with patch.object(lifecycle, 'run'):
                    self.assertTrue(lifecycle.recover())
                    self.assertFalse(lifecycle.recover())
                self.assert_restored()

    def test_failed_activation_restores_distinct_older_target(self):
        with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'run'), \
             patch.object(lifecycle.subprocess, 'run') as process, \
             patch.object(lifecycle, 'health', side_effect=[RuntimeError('unhealthy'), {'tls': True}]):
            process.return_value.returncode = 0
            with self.assertRaises(RuntimeError):
                lifecycle.activate(self.candidate)
        self.assert_restored()

    def test_failed_first_activation_reloads_absent_owned_configuration(self):
        lifecycle.restore(None, None)
        with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'run') as run, \
             patch.object(lifecycle.subprocess, 'run') as process, \
             patch.object(lifecycle, 'health', side_effect=RuntimeError('unhealthy first candidate')):
            process.return_value.returncode = 0
            with self.assertRaises(RuntimeError):
                lifecycle.activate(self.candidate)
            self.assertEqual(sum(call.args == (['systemctl', 'reload', 'nginx'],)
                                 for call in run.call_args_list), 2)
        for path in (self.enabled, self.active, self.previous, self.settings, self.pending):
            self.assertFalse(os.path.lexists(path), path)

    def test_first_install_interruption_restores_absence(self):
        lifecycle.restore(None, None)
        real_link = lifecycle.link

        def interrupted_link(path, target):
            real_link(path, target)
            if path == self.enabled:
                raise SystemExit('first enabled link switch interrupted')

        with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'link', side_effect=interrupted_link):
            with self.assertRaises(SystemExit):
                lifecycle.activate(self.candidate)
        with patch.object(lifecycle, 'run'):
            lifecycle.recover()
        for path in (self.enabled, self.active, self.previous, self.settings, self.pending):
            self.assertFalse(os.path.lexists(path), path)

    def test_first_tls_interruption_restores_checked_http_and_no_rollback(self):
        http = self.make_release('bootstrap', tls=False, port=9443)
        lifecycle.restore(str(http), None)
        real_link = lifecycle.link

        def interrupted_link(path, target):
            real_link(path, target)
            if path == self.active:
                raise SystemExit('first TLS active pointer interrupted')

        with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'run'), \
             patch.object(lifecycle.subprocess, 'run') as process, \
             patch.object(lifecycle, 'health', return_value={'tls': True, 'http2': True}), \
             patch.object(lifecycle, 'link', side_effect=interrupted_link):
            process.return_value.returncode = 0
            with self.assertRaises(SystemExit):
                lifecycle.activate(self.old)
        with patch.object(lifecycle, 'run'):
            lifecycle.recover()
        self.assertEqual(self.active.resolve(), http)
        self.assertEqual(self.enabled.resolve(), http / 'site.conf')
        self.assertFalse(os.path.lexists(self.previous))
        with self.assertRaisesRegex(ValueError, 'No previous checked TLS'):
            lifecycle.rollback()

    def test_first_tls_never_retains_http_bootstrap_for_rollback(self):
        http = self.make_release('bootstrap', tls=False, port=9443)
        lifecycle.restore(str(http), None)
        with patch.object(lifecycle, 'validate_candidate'), patch.object(lifecycle, 'run'), \
             patch.object(lifecycle.subprocess, 'run') as process, \
             patch.object(lifecycle, 'health', return_value={'tls': True, 'http2': True}):
            process.return_value.returncode = 0
            lifecycle.activate(self.old)
        self.assertFalse(os.path.lexists(self.previous))
        with self.assertRaisesRegex(ValueError, 'No previous checked TLS'):
            lifecycle.rollback()
        # Even a manually reconstructed HTTP previous pointer is rejected.
        lifecycle.link(self.previous, http)
        with self.assertRaisesRegex(ValueError, 'No previous checked TLS'):
            lifecycle.rollback()
        self.assertEqual(self.active.resolve(), self.old)

    def test_two_tls_versions_toggle_with_their_settings(self):
        with patch.object(lifecycle, 'certificate'), patch.object(lifecycle, 'validate_candidate'), \
             patch.object(lifecycle, 'run'), patch.object(lifecycle.subprocess, 'run') as process, \
             patch.object(lifecycle, 'health', return_value={'tls': True, 'http2': True}):
            process.return_value.returncode = 0
            for target, previous, port in ((self.older, self.old, 19443), (self.old, self.older, 9443)):
                self.assertTrue(lifecycle.rollback()['tls'])
                self.assertEqual(self.active.resolve(), target)
                self.assertEqual(self.previous.resolve(), previous)
                self.assertEqual(json.loads(self.settings.read_text()), {'port': port})



class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.owned = self.root / 'owned'
        self.units = self.root / 'units'
        self.units.mkdir()
        self.patches = patch.multiple(ownership, OWNER_UID=os.getuid(),
            ROOTS={self.owned: (0o700, {'helper.py': 'helper', 'state': 'dir'})},
            UNIT_DIR=self.units, UNITS=('cover-test.service',), ENABLE_LINKS={},
            BASE=self.owned, ENABLED=self.root / 'enabled')
        self.patches.start()

    def tearDown(self):
        self.patches.stop()
        self.temporary.cleanup()

    def test_unmarked_root_is_unchanged_and_rejected(self):
        self.owned.mkdir(mode=0o751)
        foreign = self.owned / 'foreign'
        foreign.write_bytes(b'unrelated bytes')
        before = (self.owned.stat(), foreign.read_bytes())
        with self.assertRaisesRegex(ValueError, 'Unmarked owned root'):
            ownership.initialize()
        self.assertEqual(self.owned.stat(), before[0])
        self.assertEqual(foreign.read_bytes(), before[1])

    def test_partial_claim_reentry_and_unchanged_reapplication(self):
        self.assertTrue(ownership.initialize())
        claim = self.owned / '.cover-site-owner.json'
        self.assertEqual(claim.read_text(), ownership.marker(self.owned))
        before = claim.stat()
        self.assertFalse(ownership.initialize())
        after = claim.stat()
        self.assertEqual((after.st_mode, after.st_ino, after.st_mtime_ns, after.st_size),
                         (before.st_mode, before.st_ino, before.st_mtime_ns, before.st_size))
        (self.owned / 'helper.py').write_text(ownership.MARKER + '. Test helper\n')
        ownership.inspect()

    def test_foreign_helper_under_marked_root_is_rejected(self):
        ownership.initialize()
        helper = self.owned / 'helper.py'
        helper.write_text('unrelated executable\n')
        with self.assertRaisesRegex(ValueError, 'Unrelated helper'):
            ownership.inspect()

    def test_wrong_helper_type_and_symlink_root_are_rejected(self):
        ownership.initialize()
        (self.owned / 'helper.py').mkdir()
        with self.assertRaises(ValueError):
            ownership.inspect()
        (self.owned / 'helper.py').rmdir()
        target = self.root / 'target'
        self.owned.rename(target)
        self.owned.symlink_to(target)
        with self.assertRaises(ValueError):
            ownership.inspect()

    def test_unit_and_sidecar_require_independent_ownership(self):
        unit = self.units / 'cover-test.service'
        unit.write_text('[Service]\nExecStart=/bin/true\n')
        with self.assertRaisesRegex(ValueError, 'Unrelated helper or unit'):
            ownership.inspect()
        unit.write_text(ownership.MARKER + '\n[Service]\n')
        ownership.inspect()
        sidecar = self.units / 'cover-test.service.d'
        sidecar.mkdir()
        with self.assertRaisesRegex(ValueError, 'sidecar'):
            ownership.inspect()


if __name__ == '__main__':
    unittest.main()
