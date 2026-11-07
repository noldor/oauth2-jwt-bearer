"""Real native scanner controls; the binary and package image must be set up first."""

import importlib.util
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts/check_secrets.py'
spec = importlib.util.spec_from_file_location('secret_scan', MODULE)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SecretScannerControls(unittest.TestCase):
    def setUp(self):
        self.binary = Path(os.environ['BETTERLEAKS_BINARY']).resolve(strict=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='jwt-secret-control-')
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_allowed_text_and_changed_prohibited_token_are_distinguished(self):
        sample = self.source / 'sample.txt'
        sample.write_text('Public documentation. No credential values.\n')
        self.assertEqual([], scanner.scan(self.binary, 'noldors-oauth2-jwt-bearer:dev', self.source, self.root / 'allowed'))
        # Assembled synthetic candidates are never live credentials.
        sample.write_text('# betterleaks:allow\n' + 'ghp_' + 'AbCdEf0123456789' * 2 + 'abcd' + '\n')
        findings = scanner.scan(self.binary, 'noldors-oauth2-jwt-bearer:dev', self.source, self.root / 'prohibited')
        self.assertGreater(len(findings), 0)
        sample.write_text('ghp_' + '9876543210aBcDeF' * 2 + 'dcba' + '\n')
        changed = scanner.scan(self.binary, 'noldors-oauth2-jwt-bearer:dev', self.source, self.root / 'changed')
        self.assertGreater(len(changed), 0)
        self.assertTrue(all(set(item) == {'rule', 'path', 'line', 'commit'} for item in changed))

    def test_history_includes_removed_intermediate_and_merge_additions(self):
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root),
                       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                       'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}

        def git(*arguments):
            return subprocess.check_output(
                ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', *arguments],
                cwd=self.source, env=environment, stderr=subprocess.DEVNULL,
            ).decode().strip()

        git('init', '-q', '-b', 'master')
        (self.source / 'README.md').write_text('Allowed public text.\n')
        git('add', '.')
        git('commit', '-qm', 'base')
        candidate = self.source / 'candidate.txt'
        candidate.write_text('ghp_' + 'AbCdEf0123456789' * 2 + 'abcd' + '\n')
        git('add', '.')
        git('commit', '-qm', 'synthetic intermediate addition')
        intermediate = git('rev-parse', 'HEAD')
        git('rm', '-q', 'candidate.txt')
        git('commit', '-qm', 'remove intermediate fixture')
        transition = self.source / 'transition.txt'
        transition.symlink_to('README.md')
        git('add', '.')
        git('commit', '-qm', 'safe symlink')
        transition.unlink()
        transition.write_text('ghp_' + 'a1B2c3D4e5F6g7H8' * 2 + 'abcd' + '\n')
        git('add', '.')
        git('commit', '-qm', 'synthetic type transition')
        type_change = git('rev-parse', 'HEAD')
        git('rm', '-q', 'transition.txt')
        git('commit', '-qm', 'remove transitioned fixture')
        git('checkout', '-qb', 'feature')
        (self.source / 'feature.txt').write_text('Allowed feature text.\n')
        git('add', '.')
        git('commit', '-qm', 'feature')
        git('checkout', '-q', 'master')
        (self.source / 'master.txt').write_text('Allowed main text.\n')
        git('add', '.')
        git('commit', '-qm', 'main')
        git('merge', '--no-ff', '--no-commit', 'feature')
        (self.source / 'merge.txt').write_text('ghp_' + '9876543210aBcDeF' * 2 + 'dcba' + '\n')
        git('add', '.')
        git('commit', '-qm', 'synthetic merge-only addition')
        merge = git('rev-parse', 'HEAD')
        findings = scanner.scan(self.binary, 'noldors-oauth2-jwt-bearer:dev', self.source, self.root / 'history', mode='git', ref=merge)
        self.assertTrue(any(item['commit'] == intermediate for item in findings))
        self.assertTrue(any(item['commit'] == type_change for item in findings))
        self.assertTrue(any(item['commit'] == merge for item in findings))

    def test_untracked_broken_symlink_is_rejected_as_incomplete(self):
        subprocess.run(['git', 'init', '-q', str(self.source)], check=True)
        (self.source / 'allowed.txt').write_text('Public text.\n')
        (self.source / 'broken').symlink_to('missing-target')
        with patch.object(scanner, 'ROOT', self.source):
            with self.assertRaisesRegex(RuntimeError, 'Symbolic links'):
                scanner.snapshot_current(self.root / 'snapshot')

    def test_missing_scanner_image_is_an_error(self):
        (self.source / 'sample.txt').write_text('Public text.\n')
        with self.assertRaisesRegex(RuntimeError, 'did not produce a report'):
            scanner.scan(self.binary, 'jwt-bearer-missing-control-image:unavailable', self.source, self.root / 'error')

    def test_native_walk_covers_lockfiles_and_nested_current_text(self):
        nested = self.source / 'nested'
        nested.mkdir()
        (nested / 'composer.lock').write_text('ghp_' + 'AbCdEf0123456789' * 2 + 'abcd' + '\n')
        findings = scanner.scan(self.binary, 'noldors-oauth2-jwt-bearer:dev', self.source, self.root / 'lockfile')
        self.assertTrue(any(item['path'].endswith('composer.lock') for item in findings))


if __name__ == '__main__':
    unittest.main()
