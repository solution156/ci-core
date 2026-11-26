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
            'verify:trivy': {'ci:tools', 'patch'},
            'verify:policy': {'ci:tools', 'patch', 'verify:trivy'},
            'verify:runtime': {'ci:tools', 'patch'},
            'gen-sbom': {'patch', 'verify:policy', 'verify:runtime'},
            'evidence': {'ci:tools', 'build', 'scan', 'patch', 'verify:trivy', 'verify:policy', 'verify:runtime', 'gen-sbom'},
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
        verify = cfg['.workspace-verify-trivy']['script'][0]
        gate = cfg['.workspace-verify-policy']['script'][0]
        self.assertIn('built.txt', cfg['.workspace-scan']['script'][0])
        self.assertIn('verified.txt', cfg['.workspace-sbom']['script'][0])
        self.assertIn('--exit-code 0', verify)
        self.assertIn('harbor.py gate', gate)
        self.assertIn('trivy image --format cyclonedx', cfg['.workspace-sbom']['script'][0])
        for job in cfg.values():
            if isinstance(job, dict):
                for command in job.get('script', []):
                    self.assertIsInstance(command, str)
                    self.assertNotIn('docker system prune', command)

    def test_catalog_supports_per_image_build_context_platform_args_and_target(self):
        import catalog
        context = Path('build-context/custom')
        context.mkdir(parents=True)
        (context / 'Dockerfile').write_text('FROM alpine:3.21 AS runtime\nUSER 1000\n')
        data = json.loads(Path('images.json').read_text())
        data['images'].append({
            'id': 'custom', 'repository': 'custom', 'version': '1.2.3', 'enabled': True,
            'depends_on': [],
            'build': {
                'context': 'build-context/custom', 'dockerfile': 'Dockerfile',
                'platform': 'linux/arm64', 'args': {'APP_VERSION': '1.2.3'}, 'target': 'runtime'
            }
        })
        Path('images.json').write_text(json.dumps(data))
        row = catalog.one('custom')
        self.assertEqual(catalog.build_config(row), {
            'context': 'build-context/custom', 'dockerfile': 'Dockerfile',
            'platform': 'linux/arm64', 'args': {'APP_VERSION': '1.2.3'}, 'target': 'runtime'
        })
        with patch.object(catalog, 'base_changes', return_value=('base', ['build-context/custom/app.py'])):
            selected, _ = catalog.changed_images(catalog.catalog(strict_locks=False))
        self.assertEqual(selected, ['custom'])

    def test_catalog_rejects_secret_like_build_arg_names(self):
        import catalog
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'chrome')['build'] = {
            'args': {'API_TOKEN': 'must-not-be-a-build-arg'}}
        Path('images.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'secret'):
            catalog.catalog()

    def test_gate_policy_artifact_is_generated_from_catalog(self):
        import pipeline
        os.environ.update(PIPELINE_KIND='full', GATE_PKG_TYPES='os', GATE_IGNORE_UNFIXED='true')
        pipeline.write_gate_policies(None)
        source = Path('out/gate-policy/chrome.sh').read_text()
        self.assertIn('POLICY_PKG_TYPES=os,library', source)
        self.assertIn('POLICY_IGNORE_UNFIXED=false', source)
        self.assertNotIn('GATE_PKG_TYPES', source)

    def test_vex_source_must_be_explicit_and_is_digest_audited(self):
        import catalog
        vex_dir = Path('vex/chrome')
        vex_dir.mkdir(parents=True)
        vex = vex_dir / 'reviewed.openvex.json'
        vex.write_text(json.dumps({
            '@context': 'https://openvex.dev/ns/v0.2.0',
            'statements': [{'vulnerability': 'CVE-2025-0001', 'status': 'not_affected',
                            'justification': 'component_not_present', 'products': [{'@id': 'pkg:oci/chrome'}]}]
        }))
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'chrome')['security_gate'] = {
            'vex_sources': ['vex/chrome/reviewed.openvex.json'],
            'justification': 'Reviewed VEX applies to a confirmed non-present component.',
            'review_by': '2099-12-31'}
        Path('images.json').write_text(json.dumps(data))
        evidence = catalog.security_policy_evidence(catalog.one('chrome'))
        self.assertEqual(evidence['vex_source_digests'][0]['path'], 'vex/chrome/reviewed.openvex.json')
        self.assertRegex(evidence['vex_source_digests'][0]['sha256'], r'^sha256:[a-f0-9]{64}$')

    def test_catalog_security_gate_defaults_to_strict(self):
        import catalog
        row = catalog.one('chrome')
        gate = catalog.security_gate(row)
        self.assertEqual(gate, {'severity': 'CRITICAL', 'pkg_types': 'os,library',
                                'ignore_unfixed': False, 'vex_sources': [],
                                'justification': '', 'review_by': ''})

    def test_catalog_security_gate_accepts_explicit_exception(self):
        import catalog
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'chrome')['security_gate'] = {
            'pkg_types': 'os', 'ignore_unfixed': True,
            'justification': 'Library vulnerabilities are reviewed outside this OS-only patch gate.',
            'review_by': '2099-12-31'}
        Path('images.json').write_text(json.dumps(data))
        gate = catalog.security_gate(catalog.one('chrome'))
        self.assertEqual(gate, {'severity': 'CRITICAL', 'pkg_types': 'os',
                                'ignore_unfixed': True, 'vex_sources': [],
                                'justification': 'Library vulnerabilities are reviewed outside this OS-only patch gate.',
                                'review_by': '2099-12-31'})

    def test_catalog_security_gate_rejects_unknown_pkg_type(self):
        import catalog
        data = json.loads(Path('images.json').read_text())
        next(r for r in data['images'] if r['id'] == 'chrome')['security_gate'] = {
            'pkg_types': 'os,bogus'}
        Path('images.json').write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'security_gate'):
            catalog.catalog()

    def test_plan_does_not_emit_security_policy_variables(self):
        import plan
        self.full()
        os.environ.update(CI_PIPELINE_SOURCE='web', IMAGE_SELECTION='chrome')
        plan.generate('generated.yml')
        data = yaml.safe_load(Path('generated.yml').read_text())
        for name in ('verify:trivy:chrome', 'verify:policy:chrome', 'promote:chrome'):
            self.assertFalse(any(key.startswith('GATE_') for key in data[name].get('variables', {})))
        self.assertIn('ci:tools', {need['job'] for need in data['verify:trivy:chrome']['needs']})
        self.assertIn('verify:trivy:chrome', {need['job'] for need in data['verify:policy:chrome']['needs']})

    def test_verify_gate_uses_catalog_policy_artifact(self):
        cfg = yaml.safe_load((CORE / 'templates/workspace-child.yaml').read_text())
        scan = cfg['.workspace-verify-trivy']['script'][0]
        gate = cfg['.workspace-verify-policy']['script'][0]
        self.assertIn('out/gate-policy/$IMAGE_ID.sh', scan)
        self.assertIn('POLICY_VEX_FILES', scan)
        self.assertIn('harbor.py gate', gate)
        self.assertNotIn('GATE_PKG_TYPES', scan)
        self.assertNotIn('GATE_IGNORE_UNFIXED', scan)
        self.assertNotIn('TRIVY_GATE_SEVERITY', scan)

    def test_run_redacts_proxy_values_but_shows_network_driver_opt(self):
        import catalog
        os.environ['BUILDX_BUILDER_NETWORK'] = ''  # value passed directly below
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(catalog.subprocess, 'run'):
            catalog.run(['docker', 'buildx', 'create',
                         '--driver-opt', 'network=host',
                         '--driver-opt', '"env.HTTPS_PROXY=http://proxy.invalid:3128"'])
        printed = out.getvalue()
        self.assertIn('network=host', printed)
        self.assertNotIn('proxy.invalid', printed)
        self.assertIn('env.HTTPS_PROXY=[REDACTED]', printed)

    def test_common_yaml_has_no_hardcoded_builder_network_default(self):
        cfg = (CORE / 'templates/common.yaml').read_text()
        self.assertNotIn('BUILDX_BUILDER_NETWORK:', cfg)

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
