"""Test credential scope and release contracts with local fakes only."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import test_pipeline as fixtures
import catalog
import harbor
import release
import job


class SecurityTests(fixtures.PipelineTests):
    def test_docker_credentials_excluded_from_build_context(self):
        dockerignore = Path('.dockerignore').read_text().splitlines()
        self.assertIn('.docker-job', dockerignore)

    def test_fast_auth_does_not_copy_production_config(self):
        os.environ.update(CI_PROJECT_DIR=str(self.root), WORKSPACE_REF_KIND='fast',
                          DOCKER_AUTH_CONFIG='{"auths":{"prod":{"auth":"not-a-real-secret"}}}')
        with patch.object(sys, 'argv', ['job.py', 'docker-auth']):
            job.main()
        path = self.root / '.docker-job/config.json'
        self.assertEqual(json.loads(path.read_text()), {'auths': {}})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with patch.object(sys, 'argv', ['job.py', 'cleanup-auth']):
            job.main()
        self.assertFalse(path.exists())

    def test_full_auth_accepts_json_not_base64_document(self):
        self.full()
        os.environ.update(CI_PROJECT_DIR=str(self.root), WORKSPACE_REF_KIND='main',
                          DOCKER_AUTH_CONFIG='{"auths":{"registry.example.test":{"auth":"fixture"}}}')
        with patch.object(sys, 'argv', ['job.py', 'docker-auth']):
            job.main()
        self.assertIn('registry.example.test', json.loads(Path('.docker-job/config.json').read_text())['auths'])

    def test_auth_rejects_outside_project_directory(self):
        os.environ.update(CI_PROJECT_DIR=str(self.root), DOCKER_CONFIG=str(self.root / '..'))
        with patch.object(sys, 'argv', ['job.py', 'cleanup-auth']):
            with self.assertRaises(SystemExit):
                job.main()

    def test_cleanup_auth_removes_nested_job_files_and_is_idempotent(self):
        os.environ['CI_PROJECT_DIR'] = str(self.root)
        nested = self.root / '.docker-job' / 'buildx' / 'instances'
        nested.mkdir(parents=True)
        (nested / 'builder.json').write_text('{}')
        (self.root / '.docker-job' / 'config.json').write_text('{}')
        with patch.object(sys, 'argv', ['job.py', 'cleanup-auth']):
            job.main()
            job.main()
        self.assertFalse((self.root / '.docker-job').exists())

    def test_cleanup_auth_removes_only_its_job_builder_before_config(self):
        os.environ['CI_PROJECT_DIR'] = str(self.root)
        os.environ['DOCKER_CONFIG'] = str(self.root / '.docker-job')
        config = self.root / '.docker-job'
        config.mkdir()
        (config / 'config.json').write_text('{}')
        (config / 'buildx-builder').write_text('workspace-ci-' + os.environ['CI_JOB_ID'] + '\n')
        calls = []
        def fake_run(command, capture=False):
            calls.append((command, config.exists()))
            if command[2] == 'ls':
                return 'workspace-ci-' + os.environ['CI_JOB_ID']
            return ''
        with patch.object(job, 'run', fake_run), patch.object(sys, 'argv', ['job.py', 'cleanup-auth']):
            job.main()
        self.assertEqual(calls[0][0][:4], ['docker', 'buildx', 'ls', '--format'])
        self.assertEqual(calls[1][0][:3], ['docker', 'buildx', 'rm'])
        self.assertTrue(calls[1][1])
        self.assertFalse(config.exists())

    def test_cleanup_auth_removes_credentials_but_reports_builder_cleanup_failure(self):
        os.environ['CI_PROJECT_DIR'] = str(self.root)
        config = self.root / '.docker-job'
        config.mkdir()
        (config / 'config.json').write_text('{}')
        (config / 'buildx-builder').write_text('workspace-ci-' + os.environ['CI_JOB_ID'] + '\n')
        def fail_builder(_command, capture=False):
            raise RuntimeError('docker daemon unavailable')
        with patch.object(job, 'run', fail_builder), patch.object(sys, 'argv', ['job.py', 'cleanup-auth']):
            with self.assertRaisesRegex(RuntimeError, 'daemon unavailable'):
                job.main()
        self.assertFalse((config / 'config.json').exists())
        self.assertTrue((config / 'buildx-builder').exists())

    def test_disabled_image_manual_selection_rejected(self):
        os.environ.update(CI_PIPELINE_SOURCE='web', IMAGE_SELECTION='vscode')
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_rc_branch_selects_only_requested_image(self):
        self.full()
        os.environ['CI_COMMIT_BRANCH'] = 'release/chrome/v0.1.0'
        result = catalog.plan()
        self.assertEqual(result['ref_kind'], 'rc')
        self.assertEqual([r['id'] for r in result['images']], ['chrome'])
        self.assertEqual(result['images'][0]['final_tag'], '0.1.0-rc')
        self.assertTrue(result['images'][0]['candidate_tag'].startswith('ci-p42-'))

    def test_failed_diff_base_is_not_silent_all_build(self):
        os.environ['CI_COMMIT_BEFORE_SHA'] = 'b'*40
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_readback_release_for_both_tag_patterns(self):
        self.full()
        os.environ.update(IMAGE_ID='chrome', WORKSPACE_REF_KIND='release',
                          CI_API_V4_URL='https://gitlab.example.test/api/v4', CI_PROJECT_ID='12', CI_JOB_TOKEN='fixture-token')
        immutable = 'registry.example.test/images/chrome@sha256:'+'b'*64
        catalog.write('out/chrome/promotion.json', {'image_id': 'chrome', 'promoted': 'registry.example.test/images/chrome:0.1.0', 'reference': immutable})
        catalog.write('out/chrome/evidence.json', {'reference': immutable})
        Path('out/chrome/summary.md').write_text('# fixture release\n')
        for tag in ('chrome/v0.1.0', 'release/chrome/v0.1.0'):
            os.environ['CI_COMMIT_TAG'] = tag
            payload = {'tag_name': tag, 'commit': {'id': os.environ['CI_COMMIT_SHA']}}
            # An existing matching release is idempotent; GET only, no writes.
            with patch.object(release.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(payload).encode())) as api:
                release.publish(None)
            self.assertEqual(api.call_count, 1)
            request = api.call_args.args[0]
            self.assertEqual(request.get_method(), 'GET')
            self.assertIn('%2F', request.full_url)

    def test_immutable_promotion_refuses_existing_other_digest(self):
        self.full()
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='ci-test', IMAGE_FINAL_TAG='0.1.0',
                          WORKSPACE_REF_KIND='release', CI_COMMIT_TAG='release/chrome/v0.1.0')
        candidate = catalog.ref(catalog.one('chrome'), 'ci-test')
        immutable = candidate.rsplit(':',1)[0]+'@sha256:'+'b'*64
        Path('out/chrome').mkdir(parents=True)
        Path('out/chrome/verified.txt').write_text(immutable)
        with patch.object(harbor, 'ensure_verified'), patch.object(harbor, 'Harbor') as client:
            client.return_value.digest.side_effect = ['sha256:'+'b'*64, 'sha256:'+'c'*64]
            with self.assertRaisesRegex(SystemExit, 'Immutable'):
                harbor.promote(None)
            client.return_value.tag.assert_not_called()
            client.return_value.untag.assert_not_called()

    def test_production_push_never_runs_on_unprotected_ref(self):
        import pipeline
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='fixture')
        with patch.object(pipeline, 'run') as command:
            with self.assertRaises(SystemExit):
                pipeline.build(type('Args', (), {'command': 'build'})())
            command.assert_not_called()


for method in list(fixtures.PipelineTests.__dict__):
    if method.startswith('test_') and method not in SecurityTests.__dict__:
        setattr(SecurityTests, method, None)


if __name__ == '__main__':
    unittest.main()
