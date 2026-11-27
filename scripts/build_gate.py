#!/usr/bin/env python3
"""Build, scan and remediate in one runner job. Copy only the approved archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile

import harbor
import pipeline
from catalog import document, env, fail, one, pipeline_mode, ref, require, run, security_gate, write


def manifest(transport, authfile=None):
    cmd = ['skopeo', 'inspect', '--raw']
    if authfile:
        cmd += ['--authfile', str(authfile)]
    raw = subprocess.run([*cmd, transport], check=True, stdout=subprocess.PIPE).stdout
    return 'sha256:' + hashlib.sha256(raw).hexdigest(), json.loads(raw)


def save_archive(local_image, archive):
    # Resolve the local tag once and run the runtime test against that same ID.
    # Docker's .Id can be a config hash or a manifest hash depending on its store.
    image_id = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', local_image], capture=True)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        fail('Docker local image ID không hợp lệ')
    run(['docker', 'image', 'save', '-o', str(archive), image_id])
    transport = 'docker-archive:' + str(archive)
    digest, config = manifest(transport)
    with tarfile.open(archive, 'r:') as bundle:
        manifest_file = bundle.extractfile('manifest.json')
        if manifest_file is None:
            raise ValueError('Missing Docker archive manifest')
        images = json.load(manifest_file)
        if len(images) != 1:
            fail('Expected one manifest in Docker archive')
        config_file = bundle.extractfile(images[0]['Config'])
        if config_file is None or config.get('config', {}).get('digest') != 'sha256:' + hashlib.sha256(config_file.read()).hexdigest():
            fail('Archive config digest không khớp manifest')
    return transport, digest, image_id


def trivy(archive, output, flags):
    run(['trivy', 'image', '--input', str(archive), *flags, '--output', str(output)])
    document(output)


def patch_local(local_image, patched_image, packages, user, arch, directory):
    if not re.fullmatch(r'[A-Za-z_0-9:.-]+', user):
        fail('Docker runtime user không hợp lệ')
    dockerfile = pathlib.Path(directory, 'Dockerfile')
    dockerfile.write_text('\n'.join([
        'FROM ' + local_image, 'USER root',
        'RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --only-upgrade '
        + ' '.join(packages) + ' && rm -rf /var/lib/apt/lists/*', 'USER ' + user, '',
    ]), encoding='utf-8')
    # The daemon's default docker driver can see the image loaded in this job.
    run(['docker', 'buildx', 'build', '--builder', 'default', '--load', '--pull=false',
         '--provenance=false', '--sbom=false', '--platform', arch, '-f', str(dockerfile),
         '-t', patched_image, *pipeline.build_arguments(), directory])


def copy_verified(source, destination, digest, authfile):
    if manifest(source)[0] != digest:
        fail('Archive digest đã đổi sau khi scan')
    run(['skopeo', 'copy', '--preserve-digests', '--authfile', str(authfile), source, destination])
    if manifest(destination, authfile)[0] != digest:
        fail('Registry digest không khớp archive đã qua gate')


def main():
    if pipeline_mode() == 'fast' or env('CI_COMMIT_REF_PROTECTED') != 'true':
        fail('Build gate chỉ chạy trên protected FULL/RELEASE')
    name = require('IMAGE_ID')
    row = one(name)
    candidate = ref(row, require('IMAGE_CANDIDATE_TAG'))
    repository = candidate.rsplit(':', 1)[0]
    job_id = require('CI_JOB_ID')
    if not job_id.isascii() or not job_id.isdigit():
        fail('CI_JOB_ID không hợp lệ')
    local_image = f'ci-local/{name}:{job_id}'
    patched = local_image + '-patched'
    p = lambda filename: pipeline.path(name, filename)
    policy = security_gate(row)
    present = [local_image]
    try:
        build = pipeline.build(argparse.Namespace(command='build'), local_tag=local_image)
        if not isinstance(build, dict):
            raise RuntimeError('Build settings unavailable')
        # Archives live outside the checkout and are never GitLab artifacts.
        with tempfile.TemporaryDirectory(prefix='ci-image-') as directory:
            archive = pathlib.Path(directory, 'image.tar')
            transport, original_digest, runtime_image = save_archive(local_image, archive)
            initial = repository + '@' + original_digest
            write(p('build.json'), {
                'id': name, 'version': row['version'], 'candidate': candidate,
                'reference': initial, 'commit': require('CI_COMMIT_SHA'), **build,
                'build_args': build['args'], 'root_pipeline': require('ROOT_PIPELINE_ID'),
            })
            trivy(archive, p('scan.json'), ['--scanners', 'vuln', '--ignorefile', '/dev/null',
                  '--severity', require('TRIVY_SCAN_SEVERITY'), '--format', 'json'])
            packages, excluded = pipeline.patch_candidates(document(p('scan.json')))
            final_digest = original_digest
            status = 'no-applicable-os-fixes'
            if packages and env('AUTO_PATCH_OS', 'true').lower() == 'true':
                user = run(['docker', 'image', 'inspect', '--format', '{{.Config.User}}', local_image], capture=True)
                present.append(patched)
                patch_dir = pathlib.Path(directory, 'patch')
                patch_dir.mkdir()
                patch_local(local_image, patched, packages, user, build['platform'], str(patch_dir))
                archive.unlink()
                transport, final_digest, runtime_image = save_archive(patched, archive)
                status = 'patched'
            elif packages:
                status = 'patch-disabled'
            immutable = repository + '@' + final_digest
            write(p('patch.json'), {'id': name, 'candidate': candidate, 'final_candidate': candidate,
                                    'build_reference': initial, 'status': status, 'reference': immutable,
                                    'available_packages': packages, 'excluded_packages': excluded,
                                    'requested_packages': packages if status == 'patched' else [],
                                    'transport': 'local-archive'})
            flags = ['--scanners', 'vuln', '--pkg-types', 'os,library', '--ignore-unfixed=false',
                     '--ignorefile', '/dev/null', '--exit-code', '0', '--format', 'json']
            for vex in policy['vex_sources']:
                flags += ['--vex', vex]
            trivy(archive, p('verify.json'), flags)
            harbor.gate(None)
            pipeline.runtime_check(row, runtime_image)
            write(p('runtime.json'), {'id': name, 'reference': immutable, 'result': 'pass'})
            trivy(archive, p('sbom.cdx.json'), ['--format', 'cyclonedx'])
            copy_verified(transport, 'docker://' + candidate, final_digest,
                          pathlib.Path(require('DOCKER_CONFIG'), 'config.json'))
            p('verified.txt').write_text(immutable + '\n', encoding='utf-8')
            print('Approved manifest copied and verified:', immutable)
    finally:
        # Only remove local tags owned by this job; never prune the daemon.
        subprocess.run(['docker', 'image', 'rm', *present], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    main()
