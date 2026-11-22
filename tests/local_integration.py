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
import time

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
        (work / '.dockerignore').write_text('.docker-job\nout\n')
        (work / 'images.json').write_text(json.dumps({'schema_version': 2, 'images': [{'id': 'fixture', 'repository': 'fixture', 'context': '.', 'dockerfile': 'images/fixture/Dockerfile', 'platform': 'linux/amd64', 'enabled': True, 'version': '0.1.0', 'depends_on': []}]}))
        run('fixture-git-init', ['git', 'init', '-q'], cwd=work)
        run('fixture-git-add', ['git', 'add', '.'], cwd=work)
        run('fixture-git-commit', ['git', '-c', 'user.name=Local integration', '-c', 'user.email=local@example.test', 'commit', '-qm', 'Synthetic integration fixture, not production source'], cwd=work)
        sha = run('fixture-git-sha', ['git', 'rev-parse', 'HEAD'], cwd=work)
        env.update(IMAGE_ID='fixture', IMAGE_CANDIDATE_TAG='ci-local-' + runid,
                   ROOT_PIPELINE_ID=runid, CI_PIPELINE_ID=runid, CI_COMMIT_SHA=sha,
                   CI_PROJECT_URL=work.as_uri(), CI_PROJECT_PATH='local/fixture',
                   CI_PIPELINE_URL=work.as_uri(), CI_COMMIT_BRANCH='main', CI_COMMIT_TAG='',
                   CI_COMMIT_REF_PROTECTED='true', WORKSPACE_REF_KIND='main',
                   HARBOR_REGISTRY=host, HARBOR_PROJECT='integration',
                   TRIVY_SCAN_SEVERITY='HIGH,CRITICAL', TRIVY_GATE_SEVERITY='CRITICAL',
                   AUTO_PATCH_OS='false', TRIVY_PATCH_SEVERITY='HIGH,CRITICAL')
        # Source SHA comes from a real local fixture commit; it is NOT a GitLab pipeline.
        run('fixture-build-push', [sys.executable, str(CORE / 'scripts/pipeline.py'), 'build'], cwd=work)
        artifacts = work / 'out/fixture'
        immutable = (artifacts / 'built.txt').read_text().strip()
        report['image_reference'] = immutable
        run('registry-digest-readback', ['docker', 'pull', immutable])
        run('archive', ['docker', 'save', '-o', str(artifacts / 'image.tar'), immutable])
        cache = output / 'trivy-cache'
        cache.mkdir(exist_ok=True)
        trivy = ['docker', 'run', '--rm', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                 '-v', str(artifacts) + ':/work', '-v', str(cache) + ':/root/.cache/trivy', a.trivy_image]
        run('trivy-scan', [*trivy, 'image', '--input', '/work/image.tar', '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL', '--format', 'json', '--output', '/work/scan.json'])
        run('patch-no-mutation', [sys.executable, str(CORE / 'scripts/pipeline.py'), 'patch'], cwd=work)
        # No Harbor API here: the LOCAL checkpoint is read back from the real OCI registry.
        post = json.loads((artifacts / 'patch.json').read_text())['reference']
        if post != immutable:
            raise RuntimeError('Local fixture unexpectedly mutated during no-patch test')
        (artifacts / 'verified.txt').write_text(immutable + '\n')
        run('trivy-critical-gate', [*trivy, 'image', '--input', '/work/image.tar', '--scanners', 'vuln', '--severity', 'CRITICAL', '--exit-code', '1', '--format', 'json', '--output', '/work/verify.json'])
        run('runtime', [sys.executable, str(CORE / 'scripts/pipeline.py'), 'runtime'], cwd=work)
        run('sbom', [*trivy, 'image', '--input', '/work/image.tar', '--format', 'cyclonedx', '--output', '/work/sbom.cdx.json'])
        run('evidence', [sys.executable, str(CORE / 'scripts/release.py'), 'evidence'], cwd=work)
        keys = work / 'disposable-keys'
        keys.mkdir(mode=0o700)
        password = secrets.token_urlsafe(24)
        cosign = ['docker', 'run', '--rm', '--user', '0:0', '--network', 'host',
                  '-v', str(keys) + ':/keys', '-e', 'COSIGN_PASSWORD', a.cosign_image]
        keyenv = {'COSIGN_PASSWORD': password}
        run('cosign-keygen', [*cosign, 'generate-key-pair', '--output-key-prefix=/keys/cosign'], extra=keyenv)
        run('cosign-sign', [*cosign, 'sign', '--yes', '--key', '/keys/cosign.key', '--tlog-upload=false', '--allow-insecure-registry', immutable], extra=keyenv)
        run('cosign-verify', [*cosign, 'verify', '--key', '/keys/cosign.pub', '--insecure-ignore-tlog', '--allow-insecure-registry', immutable], extra=keyenv)
        (keys / 'cosign.key').unlink(missing_ok=True)
        report['status'] = 'pass'
    except Exception as exc:
        report['status'] = 'fail'
        report['error'] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
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
