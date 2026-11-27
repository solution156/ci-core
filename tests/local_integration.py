#!/usr/bin/env python3
"""Opt-in REAL local build/scan/sign integration, using a labeled fixture image.
NOT GitLab or Harbor integration and NOT a production workspace image build.
Only binds registry to loopback; no privileged containers or host Docker socket mounts.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import shlex
import urllib.request

CORE = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true', help='Opt in to local Docker builds, pulls and loopback test registry writes')
    p.add_argument('--output', type=Path, default=CORE / 'reports/local-integration')
    p.add_argument('--trivy-image', default='aquasec/trivy:0.67.2')
    p.add_argument('--cosign-image', default='ghcr.io/sigstore/cosign/cosign:v2.4.1')
    a = p.parse_args()
    if not a.run:
        print('Plan: temporary loopback registry -> fixture build/push -> digest -> Trivy scan/gate -> SBOM -> runtime -> evidence -> disposable-key sign/verify. Add --run.')
        return
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    runid = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
    name = 'sdwf-local-registry-' + runid
    report = {'scope': 'real local fixture integration; not production/GitLab/Harbor', 'steps': [], 'status': 'running'}
    env = os.environ.copy()
    # Never consume production credentials in this harness.
    for key in ('HARBOR_USER', 'HARBOR_PASSWORD', 'HARBOR_PULL_USER', 'HARBOR_PULL_PASSWORD', 'DOCKER_AUTH_CONFIG', 'COSIGN_PRIVATE_KEY', 'COSIGN_PASSWORD'):
        env.pop(key, None)
    started = False
    work = output / ('fixture-' + runid)
    work.mkdir()
    def run(step, cmd, *, cwd=None, extra=None):
        result = subprocess.run(cmd, cwd=cwd, env={**env, **(extra or {})}, capture_output=True, text=True, timeout=900)
        (output / (step + '.log')).write_text(result.stdout + result.stderr)
        report['steps'].append({'name': step, 'exit_code': result.returncode})
        print(step, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
        if result.returncode:
            raise RuntimeError(step + ' failed; see ' + str(output / (step + '.log')))
        return result.stdout.strip()
    try:
        run('docker-version', ['docker', 'version'])
        run('registry-pull', ['docker', 'pull', 'registry:2.8.3'])
        run('registry-start', ['docker', 'run', '-d', '--rm', '--name', name, '--label', 'sdwf.local-test=true', '-p', '127.0.0.1::5000', 'registry:2.8.3'])
        started = True
        details = json.loads(run('registry-inspect', ['docker', 'inspect', name]))[0]
        port = details['NetworkSettings']['Ports']['5000/tcp'][0]['HostPort']
        host = 'localhost:' + port
        folder = work / 'images/fixture'
        folder.mkdir(parents=True)
        (work / 'shared').mkdir()
        (folder / 'Dockerfile').write_text('''FROM alpine:3.21
USER root
RUN mkdir -p /dockerstartup /home/local && printf '#!/bin/sh\\nexec /bin/sh "$@"\\n' > /bin/bash && chmod 755 /bin/bash && chown 1000:0 /home/local
ENV HOME=/home/local
WORKDIR /home/local
USER 1000
''')
        (folder / '.dockerignore').write_text('')
        (work / '.dockerignore').write_text('.docker-job\nout\n')
        (work / 'images.json').write_text(json.dumps({'schema_version': 2, 'images': [{'id': 'fixture', 'repository': 'fixture', 'build': {'context': 'images/fixture', 'dockerfile': 'Dockerfile', 'platform': 'linux/amd64'}, 'enabled': True, 'version': '0.1.0', 'depends_on': []}]}))
        sha = 'a' * 40
        env.update(CI_JOB_ID=runid, CI_PROJECT_DIR=str(work), DOCKER_CONFIG=str(work / '.docker-job'),
                   BUILDX_BUILDER_NETWORK='host')
        env.update(IMAGE_ID='fixture', IMAGE_CANDIDATE_TAG='ci-local-' + runid,
                   IMAGE_FINAL_TAG='0.1.0-dev',
                   ROOT_PIPELINE_ID=runid, CI_PIPELINE_ID=runid, CI_COMMIT_SHA=sha,
                   CI_PROJECT_URL=work.as_uri(), CI_PROJECT_PATH='local/fixture',
                   CI_PIPELINE_URL=work.as_uri(), CI_COMMIT_BRANCH='main', CI_COMMIT_TAG='', CI_PIPELINE_SOURCE='push',
                   CI_COMMIT_REF_PROTECTED='true', WORKSPACE_REF_KIND='main',
                   HARBOR_REGISTRY=host, HARBOR_PROJECT='integration',
                   TRIVY_SCAN_SEVERITY='HIGH,CRITICAL',
                   AUTO_PATCH_OS='false', TRIVY_PATCH_SEVERITY='HIGH,CRITICAL')
        # Run the same build-gate entrypoint; wrappers only supply tools and a
        # loopback HTTP exception, never a production auth/TLS override.
        bindir = work / 'bin'
        bindir.mkdir()
        tmp = work / 'tmp'
        tmp.mkdir()
        auth = work / '.docker-job'
        auth.mkdir()
        (auth / 'config.json').write_text('{"auths": {}}')
        cache = output / 'trivy-cache'
        cache.mkdir(exist_ok=True)
        conf = work / 'registries.conf'
        conf.write_text('[[registry]]\nlocation = ' + json.dumps(host) + '\ninsecure = true\n')
        wrappers = {
            'trivy': ['-v', str(cache) + ':/root/.cache/trivy', a.trivy_image],
            'skopeo': ['--network', 'host', '-v', str(conf) + ':/etc/containers/registries.conf:ro',
                       'quay.io/skopeo/stable:v1.18.0'],
        }
        for cmd, extra in wrappers.items():
            wrapper = bindir / cmd
            wrapper.write_text('#!/bin/sh\nexec ' + shlex.join([
                'docker', 'run', '--rm', '-v', f'{work}:{work}', '-w', str(work), *extra,
            ]) + ' "$@"\n')
            wrapper.chmod(0o700)
        env.update(PATH=str(bindir) + ':' + env['PATH'], TMPDIR=str(tmp))
        run('build-gate-and-copy', [sys.executable, str(CORE / 'scripts/build_gate.py')], cwd=work)
        artifacts = work / 'out/fixture'
        immutable = (artifacts / 'verified.txt').read_text().strip()
        report['image_reference'] = immutable
        with urllib.request.urlopen(f'http://{host}/v2/integration/fixture/tags/list', timeout=10) as response:
            tags = json.load(response)['tags']
        if tags != [env['IMAGE_CANDIDATE_TAG']]:
            raise RuntimeError('Unexpected image tags before signing: ' + repr(tags))
        report['pre_sign_image_tags'] = tags
        run('registry-digest-readback', ['docker', 'pull', immutable])
        run('evidence', [sys.executable, str(CORE / 'scripts/release.py'), 'evidence'], cwd=work)
        keys = work / 'disposable-keys'
        keys.mkdir(mode=0o700)
        password = secrets.token_urlsafe(24)
        cosign = ['docker', 'run', '--rm', '--user', '0:0', '--network', 'host',
                  '-v', str(keys) + ':/keys', '-v', str(artifacts) + ':/evidence:ro', '-e', 'COSIGN_PASSWORD', a.cosign_image]
        keyenv = {'COSIGN_PASSWORD': password}
        run('cosign-keygen', [*cosign, 'generate-key-pair', '--output-key-prefix=/keys/cosign'], extra=keyenv)
        run('cosign-sign', [*cosign, 'sign', '--yes', '--key', '/keys/cosign.key', '--tlog-upload=false', '--allow-insecure-registry', immutable], extra=keyenv)
        run('cosign-public-key', [*cosign, 'public-key', '--key', '/keys/cosign.key', '--outfile', '/keys/verify.pub'], extra=keyenv)
        run('cosign-verify', [*cosign, 'verify', '--key', '/keys/verify.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', immutable], extra=keyenv)
        for kind, filename in [('cyclonedx', 'sbom.cdx.json'), ('slsaprovenance1', 'provenance.json')]:
            run('attest-' + kind, [*cosign, 'attest', '--yes', '--key', '/keys/cosign.key', '--tlog-upload=false', '--allow-insecure-registry', '--type', kind, '--predicate', '/evidence/' + filename, immutable], extra=keyenv)
            run('verify-' + kind, [*cosign, 'verify-attestation', '--key', '/keys/verify.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', '--type', kind, immutable], extra=keyenv)
        (keys / 'cosign.key').unlink(missing_ok=True)
        report['status'] = 'pass'
    except Exception as exc:
        report['status'] = 'fail'
        report['error'] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        if (work / '.docker-job' / 'buildx-builder').is_file():
            try:
                run('builder-cleanup', [sys.executable, str(CORE / 'scripts/job.py'), 'cleanup-auth'], cwd=work)
            except Exception:
                report['status'] = 'fail'
                report.setdefault('error', 'Fixture builder cleanup failed')
        # Only the container explicitly created in this run, with its anonymous volumes.
        if started:
            stopped = subprocess.run(['docker', 'rm', '-f', '-v', name], env=env, capture_output=True, text=True)
            report['cleanup_registry_exit_code'] = stopped.returncode
        for key in work.glob('disposable-keys/*.key'):
            key.unlink()
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Result:', output / 'result.json')
    if report['status'] != 'pass':
        sys.exit(1)


if __name__ == '__main__':
    main()
