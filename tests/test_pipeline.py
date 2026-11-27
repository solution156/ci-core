"""Local regression tests. Git fixtures are real; no registry/network access."""
import copy
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

CORE = Path(__file__).resolve().parents[1]
WORKSPACE = CORE.parent / 'workspace-images'
sys.path.insert(0, str(CORE / 'scripts'))
import catalog
import plan
from catalog import checked_path


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sdwf-tests-', dir=os.environ.get('TMPDIR'))
        self.root = Path(self.tmp.name)
        if WORKSPACE.is_dir():
            shutil.copytree(
                WORKSPACE,
                self.root,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('.git', 'out', 'reports', '__pycache__'),
            )
        else:
            # Standalone ci-core checkout: synthetic source fixture, not a claimed image build.
            rows = []
            for name in ('ubuntu', 'chrome', 'chrome-gpu', 'firefox', 'opera-browser', 'tor-browser', 'vscode'):
                folder = self.root / 'images' / name
                folder.mkdir(parents=True)
                (folder / 'Dockerfile').write_text('FROM scratch\nUSER 1000\n')
                deps = ['shared/browser/cleanup.sh'] if name in ('chrome', 'chrome-gpu', 'firefox', 'opera-browser') else []
                rows.append({'id': name, 'repository': name, 'context': '.', 'dockerfile': f'images/{name}/Dockerfile',
                             'platform': 'linux/amd64', 'enabled': name != 'vscode', 'version': '0.1.0', 'depends_on': deps})
            config = self.root / 'images/vscode/configs'
            config.mkdir(parents=True)
            (config / 'extensions.txt').write_text('fixture.extension\n')
            (config / 'extensions.lock').write_text('# uninitialized fixture\n')
            (self.root / 'images/vscode/validate').mkdir(parents=True)
            (self.root / 'images/vscode/validate/runtime.sh').write_text('#!/bin/sh\ntrue\n')
            rows[-1]['extension_lock'] = {'manifest': 'images/vscode/configs/extensions.txt',
                'lock': 'images/vscode/configs/extensions.lock', 'generated': '/opt/dwf-vscode/extensions.lock.generated'}
            rows[-1]['runtime_check'] = 'images/vscode/validate/runtime.sh'
            shared = self.root / 'shared/browser'
            shared.mkdir(parents=True)
            (shared / 'cleanup.sh').write_text('#!/bin/sh\ntrue\n')
            (self.root / '.dockerignore').write_text('.docker-job\nout\n')
            (self.root / 'images.json').write_text(json.dumps({'schema_version': 2, 'images': rows}))
        self.cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)
        self.addCleanup(self.tmp.cleanup)
        catalog.ROOT = self.root
        self.addCleanup(setattr, catalog, 'ROOT', self.cwd)
        self.env = patch.dict(os.environ, {
            'PIPELINE_KIND': 'fast', 'CI_COMMIT_BRANCH': 'feature/chrome',
            'CI_COMMIT_TAG': '', 'CI_PIPELINE_SOURCE': 'push',
            'CI_COMMIT_REF_PROTECTED': 'false', 'CI_COMMIT_BEFORE_SHA': '',
            'CI_MERGE_REQUEST_DIFF_BASE_SHA': '', 'IMAGE_SELECTION': 'auto',
            'CI_PIPELINE_ID': '42', 'CI_COMMIT_SHA': 'a' * 40,
            'CI_CORE_PROJECT': 'group/ci-core', 'CI_CORE_REF': 'v2.0.0',
            'HARBOR_REGISTRY': 'registry.example.test', 'HARBOR_PROJECT': 'images',
            'ROOT_PIPELINE_ID': '42', 'CI_JOB_ID': '12345',
            'CI_PROJECT_DIR': str(self.root),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.test')
        self.git('config', 'user.name', 'Local test')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', *args], text=True, stderr=subprocess.DEVNULL).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        sha = self.git('rev-parse', 'HEAD')
        os.environ['CI_COMMIT_SHA'] = sha
        return sha

    def full(self):
        os.environ.update(PIPELINE_KIND='full', CI_COMMIT_BRANCH='main', CI_COMMIT_REF_PROTECTED='true')

    def test_fast_catalog_allows_uninitialized_lock_but_full_plan_rejects_it(self):
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        import pipeline
        pipeline.validate(None)
        self.assertIn('vscode', [row['id'] for row in catalog.catalog(strict_locks=False)])
        self.full()
        with self.assertRaisesRegex(SystemExit, 'extensions.lock'):
            catalog.plan()

    def test_fast_vscode_smoke_resolves_and_exports_missing_lock(self):
        import pipeline
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        os.environ.update(IMAGE_ID='vscode', ROOT_PIPELINE_ID='42')
        calls = []
        def record(cmd, capture=False):
            calls.append(cmd)
            if cmd[1:3] == ['buildx', 'build']:
                pass
            elif cmd[1] == 'create':
                return 'c' * 64
            elif cmd[1] == 'cp':
                Path(cmd[-1]).write_text('fixture.extension@1.2.3' + chr(10))
            return ''
        with patch.object(pipeline, 'run', record), patch.object(pipeline, 'runtime_check'):
            pipeline.build(type('Args', (), {'command': 'smoke', 'dry_run': False})())
        build = next(command for command in calls if command[1:3] == ['buildx', 'build'])
        self.assertIn('--build-arg', build)
        self.assertIn('EXTENSION_MODE=resolve', build)
        self.assertTrue(Path('out/vscode/extensions.lock').is_file())
        self.assertTrue(any(command[1] == 'cp' for command in calls))
        self.assertTrue(any(command[1] == 'rm' for command in calls))

    def test_fast_smoke_resolves_runtime_check_when_lock_is_uninitialized(self):
        import pipeline
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        os.environ.update(IMAGE_ID='vscode', ROOT_PIPELINE_ID='42')
        calls = []
        def record(cmd, capture=False):
            calls.append(cmd)
            if cmd[1] == 'create':
                return 'c' * 64
            if cmd[1] == 'cp':
                Path(cmd[-1]).write_text('fixture.extension@1.2.3\n')
            return ''
        with patch.object(pipeline, 'run', record), patch.object(pipeline, 'runtime_check') as runtime:
            pipeline.build(type('Args', (), {'command': 'smoke', 'dry_run': False})())
        runtime.assert_called_once()
        generated = runtime.call_args.args[2]
        self.assertEqual(generated, '/opt/dwf-vscode/extensions.lock.generated')

    def test_runtime_check_points_to_generated_lock_with_docker_run_env(self):
        import pipeline
        # Self-contained: do not depend on a sibling consumer checkout being present.
        script = Path('runtime-check-fixture.sh')
        script.write_text('#!/bin/sh\ntrue\n')
        row = {'id': 'vscode', 'runtime_check': script.name}
        runs = []
        def record(cmd, capture=False, **kwargs):
            runs.append(cmd)
            return ''
        with patch.object(pipeline, 'run', record), patch.object(pipeline.subprocess, 'run', record):
            pipeline.runtime_check(row, 'registry.example.test/images/vscode:smoke-p42',
                                   '/opt/dwf-vscode/extensions.lock.generated')
        self.assertEqual(len(runs), 2)
        for command in runs:
            self.assertEqual(command[:2], ['docker', 'run'])
            self.assertNotIn('--build-arg', command)
            self.assertIn('--env', command)
            self.assertIn('EXTENSIONS_LOCK=/opt/dwf-vscode/extensions.lock.generated', command)

    def test_builder_network_driver_option_is_optional_and_validated(self):
        import pipeline
        os.environ.update(HTTP_PROXY='', HTTPS_PROXY='', NO_PROXY='', http_proxy='', https_proxy='', no_proxy='')
        os.environ.pop('BUILDX_BUILDER_NETWORK', None)
        commands = []
        with patch.object(pipeline, 'run', lambda cmd, capture=False: commands.append(cmd) or ''):
            pipeline.initialize_builder()
        self.assertFalse(any(arg.startswith('network=') for arg in commands[0]))
        os.environ['BUILDX_BUILDER_NETWORK'] = 'host'
        commands.clear()
        with patch.object(pipeline, 'run', lambda cmd, capture=False: commands.append(cmd) or ''):
            pipeline.initialize_builder()
        self.assertIn('network=host', commands[0])
        os.environ['BUILDX_BUILDER_NETWORK'] = 'host;rm -rf /'
        with patch.object(pipeline, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'BUILDX_BUILDER_NETWORK'):
                pipeline.initialize_builder()
            run.assert_not_called()

    def test_main_builds_all_enabled_even_without_diff(self):
        self.full()
        selected = catalog.plan()
        self.assertEqual(len(selected['images']), 6)
        self.assertEqual(selected['reason'], 'all-enabled-main')
        self.assertTrue(all(row['final_tag'] == row['version'] + '-dev'
                            for row in selected['images']))
        self.assertTrue(all(row['candidate_tag'].startswith('ci-p42-')
                            for row in selected['images']))

    def test_both_release_tag_patterns(self):
        for tag in ('chrome/v0.1.0', 'release/chrome/v0.1.0'):
            with self.subTest(tag=tag):
                os.environ.update(PIPELINE_KIND='release', CI_COMMIT_BRANCH='', CI_COMMIT_TAG=tag,
                                  CI_COMMIT_REF_PROTECTED='true')
                selected = catalog.plan()
                self.assertEqual([x['id'] for x in selected['images']], ['chrome'])
                self.assertEqual(selected['images'][0]['final_tag'], '0.1.0')

    def test_unprotected_full_rejected(self):
        os.environ.update(PIPELINE_KIND='full', CI_COMMIT_BRANCH='main')
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_release_version_mismatch_rejected(self):
        os.environ.update(PIPELINE_KIND='release', CI_COMMIT_BRANCH='', CI_COMMIT_TAG='chrome/v0.2.0',
                          CI_COMMIT_REF_PROTECTED='true')
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_fast_only_changed_image(self):
        before = self.git('rev-parse', 'HEAD')
        with open('images/chrome/Dockerfile', 'a') as f:
            f.write('\n# fixture change\n')
        self.commit()
        os.environ['CI_COMMIT_BEFORE_SHA'] = before
        self.assertEqual([x['id'] for x in catalog.plan()['images']], ['chrome'])

    def test_shared_change_selects_dependents(self):
        before = self.git('rev-parse', 'HEAD')
        with open('shared/browser/cleanup.sh', 'a') as f:
            f.write('\n# fixture change\n')
        self.commit()
        os.environ['CI_COMMIT_BEFORE_SHA'] = before
        ids = [x['id'] for x in catalog.plan()['images']]
        self.assertEqual(set(ids), {'chrome', 'chrome-gpu', 'firefox', 'opera-browser'})

    def test_mr_uses_mr_base(self):
        before = self.git('rev-parse', 'HEAD')
        with open('images/firefox/Dockerfile', 'a') as f:
            f.write('\n# fixture change\n')
        self.commit()
        os.environ.update(CI_PIPELINE_SOURCE='merge_request_event', CI_COMMIT_BRANCH='',
                          CI_MERGE_REQUEST_DIFF_BASE_SHA=before)
        self.assertEqual([x['id'] for x in catalog.plan()['images']], ['firefox'])

    def test_first_commit_no_changes_child_valid(self):
        plan.generate('generated.yml')
        data = yaml.safe_load(Path('generated.yml').read_text())
        self.assertIn('images:no-changes', data)

    def test_manual_selection_only_web(self):
        os.environ['IMAGE_SELECTION'] = 'chrome'
        with self.assertRaises(SystemExit):
            catalog.plan()
        os.environ['CI_PIPELINE_SOURCE'] = 'web'
        self.assertEqual([x['id'] for x in catalog.plan()['images']], ['chrome'])

    def test_protected_web_main_rejects_subset(self):
        self.full()
        os.environ.update(CI_PIPELINE_SOURCE='web', IMAGE_SELECTION='chrome')
        with self.assertRaisesRegex(SystemExit, 'main'):
            catalog.plan()

    def test_thin_consumer_needs_no_pipeline_kind(self):
        self.full()
        os.environ.pop('PIPELINE_KIND')
        self.assertEqual(catalog.plan()['mode'], 'full')
        os.environ['PIPELINE_KIND'] = 'fast'
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_generated_full_dag_no_missing_needs(self):
        self.full()
        plan.generate('generated.yml')
        generated = yaml.safe_load(Path('generated.yml').read_text())
        template = yaml.safe_load((CORE / 'templates/workspace-child.yaml').read_text())
        jobs = {k: v for k, v in generated.items() if isinstance(v, dict) and 'extends' in v}
        self.assertIn('evidence:chrome', jobs)
        self.assertIn('cleanup:chrome', jobs)
        for name, job in jobs.items():
            self.assertIn(job['extends'], template, name)
            for need in job['needs']:
                self.assertIn(need['job'], set(jobs) | {'ci:tools'}, name)
        for name in ('build:chrome', 'sign:chrome', 'promote:chrome'):
            self.assertTrue(jobs[name]['needs'])

    def test_vscode_enabled_empty_lock_fails_clearly(self):
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'lock'):
            catalog.catalog()

    def test_vscode_malformed_nonempty_lock_rejected(self):
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        Path('images/vscode/configs/extensions.lock').write_text('garbage\n')
        with self.assertRaisesRegex(SystemExit, 'lock'):
            catalog.catalog()

    def test_push_build_rejects_uninitialized_lock(self):
        import pipeline
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        self.full()
        os.environ.update(IMAGE_ID='vscode')
        with patch.object(pipeline, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'extensions.lock'):
                pipeline.build(type('Args', (), {'command': 'build', 'dry_run': False})())
            run.assert_not_called()

    def test_fast_plan_can_select_vscode_with_uninitialized_lock(self):
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'vscode')['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        os.environ.update(CI_PIPELINE_SOURCE='web', IMAGE_SELECTION='vscode')
        selected = catalog.plan()
        self.assertEqual(selected['mode'], 'fast')
        self.assertEqual([row['id'] for row in selected['images']], ['vscode'])
        plan.generate('generated.yml')
        generated = yaml.safe_load(Path('generated.yml').read_text())
        self.assertEqual(generated['build:vscode']['extends'], '.workspace-smoke')

    def test_parent_trigger_is_native_gitlab_trigger(self):
        data = yaml.safe_load((CORE / 'templates/workspace-parent.yaml').read_text())
        trigger = data['pipeline:images']
        self.assertNotIn('script', trigger)
        self.assertNotIn('image', trigger)
        self.assertEqual(trigger['trigger']['include'][0]['job'], 'prepare:plan')

    def test_runtime_build_pins_digest_from_buildkit_metadata(self):
        import pipeline
        args = type('Args', (), {'command': 'build', 'dry_run': False})()
        self.full()
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='ci-p42-' + os.environ['CI_COMMIT_SHA'][:12],
                          IMAGE_FINAL_TAG='0.1.0-dev')
        calls = []
        def fake_run(cmd, capture=False):
            calls.append(cmd)
            if cmd[:3] == ['docker', 'buildx', 'build']:
                metadata = Path(cmd[cmd.index('--metadata-file') + 1])
                metadata.parent.mkdir(parents=True, exist_ok=True)
                metadata.write_text(json.dumps({'containerimage.digest': 'sha256:' + 'b' * 64}))
            return ''
        with patch.object(pipeline, 'run', fake_run):
            pipeline.build(args)
        self.assertTrue(Path('out/chrome/built.txt').is_file())
        self.assertRegex(Path('out/chrome/built.txt').read_text(), '@sha256:[a-f0-9]{64}')
        self.assertEqual(calls[0][:3], ['docker', 'buildx', 'create'])
        self.assertEqual(calls[1][:3], ['docker', 'buildx', 'inspect'])
        self.assertEqual(calls[2][:3], ['docker', 'buildx', 'build'])

    def test_smoke_build_honors_per_image_build_settings(self):
        import pipeline
        data = json.loads(Path('images.json').read_text())
        dockerfile = Path('images/chrome/Dockerfile')
        lines = dockerfile.read_text().splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith('FROM '))
        lines[index] += ' AS runtime'
        dockerfile.write_text(chr(10).join(lines) + chr(10))
        next(r for r in data['images'] if r['id'] == 'chrome')['build'] = {
            'platform': 'linux/arm64', 'args': {'APP_VERSION': '1.2.3'}, 'target': 'runtime'}
        Path('images.json').write_text(json.dumps(data))
        os.environ.update(IMAGE_ID='chrome', ROOT_PIPELINE_ID='42')
        calls = []
        with patch.object(pipeline, 'run', lambda cmd, capture=False: calls.append(cmd) or ''), \
             patch.object(pipeline, 'runtime_check'):
            pipeline.build(type('Args', (), {'command': 'smoke', 'dry_run': False})())
        build = next(command for command in calls if command[1:3] == ['buildx', 'build'])
        self.assertEqual(build[build.index('--platform') + 1], 'linux/arm64')
        self.assertEqual(build[build.index('--target') + 1], 'runtime')
        self.assertIn('APP_VERSION=1.2.3', build)

    def test_smoke_build_uses_scoped_builder_and_load_output(self):
        import pipeline
        os.environ.update(IMAGE_ID='chrome', ROOT_PIPELINE_ID='42')
        calls = []
        with patch.object(pipeline, 'run', lambda cmd, capture=False: calls.append(cmd) or ''):
            pipeline.build(type('Args', (), {'command': 'smoke', 'dry_run': False})())
        self.assertEqual(calls[0][:3], ['docker', 'buildx', 'create'])
        self.assertEqual(calls[1][:3], ['docker', 'buildx', 'inspect'])
        build = calls[2]
        self.assertIn('--builder', build)
        self.assertIn('--load', build)
        self.assertNotIn('--push', build)
        self.assertNotIn('--provenance=mode=max', build)
        self.assertNotIn('--sbom=true', build)


if __name__ == '__main__':
    unittest.main()
