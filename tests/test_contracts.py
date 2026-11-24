"""Runtime/graph tests use command-recording doubles, NEVER contact real services."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import yaml
from test_pipeline import PipelineTests, CORE, WORKSPACE
import catalog
import pipeline
import harbor
import release


class Contracts(PipelineTests):
    # Reuse repository fixture but not inherited test methods.
    def test_effective_dag_stages_and_artifact_contracts(self):
        self.full()
        import plan
        plan.generate('generated.yml')
        generated = yaml.safe_load(Path('generated.yml').read_text())
        templates = yaml.safe_load((CORE / 'templates/workspace-child.yaml').read_text())
        common = yaml.safe_load((CORE / 'templates/common.yaml').read_text())
        merged = {**common, **templates, **generated}
        def effective(name):
            item = dict(merged[name])
            parent = item.pop('extends', None)
            return {**effective(parent), **item} if parent else item
        stages = templates['stages']
        expected_inputs = {
            'build': {'ci:tools'},
            'scan': {'build'}, 'patch': {'ci:tools', 'build', 'scan'},
            'verify:runtime': {'ci:tools', 'patch'}, 'verify:trivy': {'patch'},
            'gen-sbom': {'patch', 'verify:trivy', 'verify:runtime'},
            'evidence': {'ci:tools', 'build', 'scan', 'patch', 'verify:trivy', 'verify:runtime', 'gen-sbom'},
            'sign': {'evidence'}, 'promote': {'ci:tools', 'sign'}, 'cleanup': {'promote'},
        }
        for name, raw in generated.items():
            if not isinstance(raw, dict) or 'extends' not in raw:
                continue
            job = effective(name)
            prefix, image_id = name.rsplit(':', 1)
            self.assertIn('image', job, name)
            self.assertTrue(job.get('script'), name)
            needs = raw.get('needs', [])
            got = {n['job'].rsplit(':', 1)[0] if n['job'] != 'ci:tools' else 'ci:tools' for n in needs}
            self.assertEqual(got, expected_inputs[prefix], name)
            for need in needs:
                source = effective(need['job'])
                self.assertLessEqual(stages.index(source['stage']), stages.index(job['stage']), name)
                if need['job'] != 'ci:tools':
                    self.assertTrue(need['job'].endswith(':' + image_id), name)
            if prefix in ('scan', 'verify:trivy', 'gen-sbom', 'sign', 'promote'):
                self.assertNotIn('services', job, name)
            if prefix in ('build', 'patch', 'verify:runtime'):
                self.assertIn('services', job, name)
                self.assertEqual(job['resource_group'], '$HEAVY_RESOURCE_GROUP')

    def test_fast_never_emits_publish_jobs(self):
        os.environ.update(CI_PIPELINE_SOURCE='web', IMAGE_SELECTION='chrome')
        import plan
        plan.generate('generated.yml')
        data = yaml.safe_load(Path('generated.yml').read_text())
        self.assertIn('build:chrome', data)
        self.assertEqual(data['build:chrome']['extends'], '.workspace-smoke')
        self.assertFalse(any(k.startswith(('sign:', 'promote:', 'scan:', 'patch:')) for k in data))

    def test_scan_and_sbom_use_digest_files(self):
        cfg = yaml.safe_load((CORE / 'templates/workspace-child.yaml').read_text())
        self.assertIn('built.txt', cfg['.workspace-scan']['script'][0])
        self.assertIn('verified.txt', cfg['.workspace-sbom']['script'][0])
        self.assertIn('--exit-code 1', cfg['.workspace-verify-trivy']['script'][0])
        self.assertIn('trivy image --format cyclonedx', cfg['.workspace-sbom']['script'][0])
        for job in cfg.values():
            if isinstance(job, dict):
                for command in job.get('script', []):
                    self.assertIsInstance(command, str)
                    self.assertNotIn('docker system prune', command)

    def test_dind_proxy_values_are_forwarded_without_hardcoded_urls(self):
        cfg = yaml.safe_load((CORE / 'templates/workspace-child.yaml').read_text())
        service = cfg['.workspace-docker']['services'][0]
        job_variables = cfg['.workspace-docker']['variables']
        self.assertEqual(job_variables['DIND_HTTP_PROXY'], '$HTTP_PROXY')
        self.assertEqual(job_variables['DIND_HTTPS_PROXY'], '$HTTPS_PROXY')
        self.assertEqual(job_variables['DIND_NO_PROXY'], '$NO_PROXY')
        self.assertEqual(service['entrypoint'], ['/bin/sh', '-c'])
        wrapper = service['command'][0]
        self.assertIn('HTTP_PROXY="${DIND_HTTP_PROXY:-}"', wrapper)
        self.assertIn('HTTPS_PROXY="${DIND_HTTPS_PROXY:-}"', wrapper)
        self.assertIn('NO_PROXY="${DIND_NO_PROXY:-}"', wrapper)
        self.assertIn('exec dockerd-entrypoint.sh --tls=false', wrapper)
        self.assertNotIn('variables', service)
        self.assertNotIn('proxy.', json.dumps(service).lower())

    def test_production_build_uses_registry_cache_attestations_and_metadata_digest(self):
        self.full()
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='ci-p42-' + os.environ['CI_COMMIT_SHA'][:12],
                          IMAGE_FINAL_TAG='0.1.0-dev', HTTP_PROXY='http://proxy-user:secret@proxy.example.test:8080',
                          NO_PROXY='harbor.example.test,localhost')
        commands = []

        def record(cmd, capture=False):
            commands.append(cmd)
            if cmd[:3] == ['docker', 'buildx', 'build']:
                metadata = Path(cmd[cmd.index('--metadata-file') + 1])
                metadata.parent.mkdir(parents=True, exist_ok=True)
                metadata.write_text(json.dumps({'containerimage.digest': 'sha256:' + 'b' * 64}))
            return ''

        args = type('Args', (), {'command': 'build', 'dry_run': False})()
        with patch.object(pipeline, 'run', record):
            pipeline.build(args)
        builder = 'workspace-ci-' + os.environ['CI_JOB_ID']
        self.assertEqual(commands[0][:5], ['docker', 'buildx', 'create', '--name', builder])
        self.assertIn('--driver', commands[0])
        self.assertIn('docker-container', commands[0])
        self.assertIn('"env.HTTP_PROXY=http://proxy-user:secret@proxy.example.test:8080"', commands[0])
        self.assertIn('"env.NO_PROXY=harbor.example.test,localhost"', commands[0])
        self.assertEqual(commands[1], ['docker', 'buildx', 'inspect', builder, '--bootstrap'])
        build = commands[2]
        self.assertIn('--push', build)
        self.assertNotIn('--load', build)
        self.assertIn('--builder', build)
        self.assertIn(builder, build)
        self.assertIn('--cache-from', build)
        self.assertIn('--cache-to', build)
        self.assertIn('--provenance=mode=min', build)
        self.assertNotIn('--provenance=mode=max', build)
        self.assertIn('--sbom=true', build)
        self.assertIn('--metadata-file', build)
        immutable = Path('out/chrome/built.txt').read_text().strip()
        self.assertEqual(immutable, 'registry.example.test/images/chrome@sha256:' + 'b' * 64)

    def test_buildkit_proxy_values_are_redacted_from_command_log(self):
        import catalog
        output = io.StringIO()
        with patch.object(catalog.subprocess, 'run') as run_command:
            with contextlib.redirect_stdout(output):
                catalog.run(['docker', 'buildx', 'create', '--driver-opt',
                             '"env.HTTPS_PROXY=https://user:secret@proxy.example.test:8443"'])
        self.assertNotIn('user:secret', output.getvalue())
        self.assertIn('[REDACTED]', output.getvalue())

    def test_patch_without_fixes_still_records_pinned_digest(self):
        self.full()
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='ci-test')
        candidate = catalog.ref(catalog.one('chrome'), 'ci-test')
        immutable = candidate.rsplit(':', 1)[0] + '@sha256:' + 'b'*64
        catalog.write('out/chrome/build.json', {'candidate': candidate, 'commit': os.environ['CI_COMMIT_SHA'], 'reference': immutable})
        catalog.write('out/chrome/scan.json', {'Results': []})
        with patch.object(pipeline, 'run') as run:
            pipeline.patch(None)
        run.assert_not_called()
        self.assertEqual(json.loads(Path('out/chrome/patch.json').read_text())['reference'], immutable)

    def test_snapshot_detects_candidate_digest_race(self):
        self.full()
        os.environ.update(IMAGE_ID='chrome', IMAGE_CANDIDATE_TAG='ci-test')
        candidate = catalog.ref(catalog.one('chrome'), 'ci-test')
        catalog.write('out/chrome/build.json', {'candidate': candidate})
        catalog.write('out/chrome/patch.json', {'candidate': candidate, 'reference': candidate.rsplit(':',1)[0]+'@sha256:'+'b'*64})
        with patch.object(harbor, 'Harbor') as client:
            client.return_value.digest.return_value = 'sha256:'+'c'*64
            with self.assertRaisesRegex(SystemExit, 'digest'):
                harbor.snapshot(None)
        self.assertFalse(Path('out/chrome/verified.txt').exists())

    def test_bootstrap_rejects_push(self):
        os.environ['EXTENSION_BOOTSTRAP'] = 'vscode'
        with self.assertRaises(SystemExit):
            catalog.plan()

    def test_lock_runtime_never_pushes_and_extracts_artifact(self):
        os.environ.update(IMAGE_ID='vscode', WORKSPACE_REF_KIND='bootstrap', PARENT_PIPELINE_SOURCE='web')
        commands = []
        def record(cmd, capture=False):
            commands.append(cmd)
            if cmd[1] == 'create':
                return 'c'*64
            if cmd[1] == 'cp':
                Path(cmd[-1]).write_text('fixture.extension@1.2.3\n')
            return ''
        with patch.object(pipeline, 'run', record):
            pipeline.lock(None)
        self.assertTrue(Path('out/vscode/extensions.lock').exists())
        self.assertFalse(any(c[1] == 'push' for c in commands))
        self.assertTrue(any('EXTENSION_MODE=resolve' in c for c in commands))
        self.assertEqual(commands[-1][:2], ['docker', 'rm'])

    def test_valid_lock_can_enable_vscode(self):
        data = json.loads(Path('images.json').read_text())
        row = next(r for r in data['images'] if r['id'] == 'vscode')
        row['enabled'] = True
        Path('images.json').write_text(json.dumps(data))
        manifest = Path(row['extension_lock']['manifest']).read_text().splitlines()
        ids = [l.split('#',1)[0].strip() for l in manifest if l.split('#',1)[0].strip()]
        # Synthetic versions are test fixture ONLY, never persisted to real lockfile.
        Path(row['extension_lock']['lock']).write_text('\n'.join(x+'@1.2.3' for x in ids)+'\n')
        self.assertTrue(catalog.one('vscode')['enabled'])

    def test_inventory_change_only_selects_that_image(self):
        before = self.git('rev-parse', 'HEAD')
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'chrome')['version'] = '0.1.1'
        Path('images.json').write_text(json.dumps(data))
        self.commit()
        os.environ['CI_COMMIT_BEFORE_SHA'] = before
        self.assertEqual([r['id'] for r in catalog.plan()['images']], ['chrome'])

    def test_dry_run_cli_never_needs_docker_or_credentials(self):
        for name, action in [('pipeline', 'build'), ('harbor', 'promote'), ('release', 'publish')]:
            result = subprocess.run([sys_executable(), str(CORE/'scripts'/f'{name}.py'), action, '--dry-run'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DRY-RUN', result.stdout)


def sys_executable():
    import sys
    return sys.executable


# Avoid rerunning inherited tests twice; keep fixture helpers on a base-only class.
for method in list(PipelineTests.__dict__):
    if method.startswith('test_') and method not in Contracts.__dict__:
        setattr(Contracts, method, None)
del PipelineTests


if __name__ == '__main__':
    unittest.main()
