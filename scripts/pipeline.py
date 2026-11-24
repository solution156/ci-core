#!/usr/bin/env python3
"""Build giữ nguyên Dockerfile; auto-patch chỉ áp dụng OS packages có bản vá."""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import re
import tempfile
from catalog import catalog, one, ref, run, env, require, document, write, fail, bootstrap_target, checked_path

PROXIES = ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy')


def path(name, filename):
    p = pathlib.Path('out') / name / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def build_arguments():
    args = []
    for var in PROXIES:
        if os.environ.get(var):
            args += ['--build-arg', var]  # Docker BuildKit tự ẩn proxy args chuẩn.
    return args


def validate(_):
    rows = catalog(bootstrap=bootstrap_target())
    print('Validated', len(rows), 'image entries:')
    for row in rows:
        print(f'  {row["id"]:18} {row["version"]:12} enabled={row["enabled"]} shared={row["depends_on"]}')


def build(args):
    row = one(require('IMAGE_ID'))
    fast = args.command == 'smoke'
    if not fast and env('CI_COMMIT_REF_PROTECTED') != 'true':
        fail('Build push requires protected ref')
    tag = ('smoke-p' + require('ROOT_PIPELINE_ID')
           if fast else require('IMAGE_CANDIDATE_TAG'))
    reference = ref(row, tag)
    command = ['docker', 'buildx', 'build', '--pull', '--progress=plain', '--platform', row['platform'],
               '-f', row['dockerfile'], '-t', reference,
               '--label', 'org.opencontainers.image.title=' + row['repository'],
               '--label', 'org.opencontainers.image.source=' + env('CI_PROJECT_URL'),
               '--label', 'org.opencontainers.image.revision=' + env('CI_COMMIT_SHA'),
               '--label', 'org.opencontainers.image.version=' + row['version']]
    metadata_file = path(row['id'], 'build-metadata.json')
    if fast:
        command += ['--load']
    else:
        # Inline cache works with the default Docker Buildx driver. The previous
        # stable policy tag is imported as a registry cache source when present;
        # a missing tag is treated by BuildKit as a cache miss, not a build error.
        cache = ref(row, require('IMAGE_FINAL_TAG'))
        command += [
            '--push',
            '--cache-from', 'type=registry,ref=' + cache,
            '--cache-to', 'type=inline',
            '--provenance=mode=max', '--sbom=true',
            '--metadata-file', str(metadata_file),
        ]
    command += build_arguments() + [row['context']]
    run(command)
    if fast:
        runtime_check(row, reference)
        write(path(row['id'], 'smoke.json'), {'id': row['id'], 'result': 'pass', 'pushed': False})
        print('FAST local build/runtime OK; không push:', row['id'])
        return
    immutable = metadata_digest(reference, metadata_file)
    path(row['id'], 'built.txt').write_text(immutable + '\n', encoding='utf-8')
    write(path(row['id'], 'build.json'), {
        'reference': immutable,
        'id': row['id'], 'version': row['version'], 'commit': require('CI_COMMIT_SHA'),
        'candidate': reference, 'dockerfile': row['dockerfile'], 'platform': row['platform'],
        'root_pipeline': require('ROOT_PIPELINE_ID'),
    })


def metadata_digest(reference, metadata_file):
    metadata = document(metadata_file)
    digest = metadata.get('containerimage.digest', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
        fail('BuildKit metadata thiếu containerimage.digest hợp lệ')
    return reference.rsplit(':', 1)[0] + '@' + digest


def pushed_digest(reference):
    immutable = run(['docker', 'image', 'inspect', '--format', '{{index .RepoDigests 0}}', reference], capture=True)
    if not re.fullmatch(re.escape(reference.rsplit(':', 1)[0]) + r'@sha256:[a-f0-9]{64}', immutable):
        fail('Docker push không trả digest hợp lệ')
    return immutable


def runtime_check(row, reference):
    script = 'set -e; test "$(id -u)" = 1000; test -d /dockerstartup; test -d "$HOME"'
    run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', '/bin/bash', reference, '-lc', script])
    if row.get('runtime_check'):
        # Read a reviewed repository script and stream via stdin; no host mounts.
        with checked_path(row['runtime_check']).open('rb') as source:
            import subprocess
            subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none', '--entrypoint', '/bin/bash', reference, '-s'], stdin=source, check=True)


def lock(_args):
    name = require('IMAGE_ID')
    if env('WORKSPACE_REF_KIND') != 'bootstrap' or env('PARENT_PIPELINE_SOURCE') != 'web':
        fail('Lock resolve chỉ qua bootstrap child từ Run pipeline')
    rows = {r['id']: r for r in catalog(bootstrap=name)}
    if name not in rows or 'extension_lock' not in rows[name]:
        fail('Image chưa khai báo extension_lock')
    row = rows[name]
    local = 'sdwf-lock-' + require('ROOT_PIPELINE_ID') + '-' + name
    run(['docker', 'buildx', 'build', '--load', '--pull', '--progress=plain', '--platform', row['platform'],
         '--build-arg', 'EXTENSION_MODE=resolve', '-f', row['dockerfile'], '-t', local,
         *build_arguments(), row['context']])
    container = run(['docker', 'create', local], capture=True)
    if not re.fullmatch(r'[a-f0-9]{12,64}', container):
        fail('Docker create trả container ID sai')
    try:
        target = path(name, 'extensions.lock')
        run(['docker', 'cp', container + ':' + row['extension_lock']['generated'], str(target)])
        if not target.is_file() or not target.stat().st_size:
            fail('Bootstrap không xuất được lockfile')
    finally:
        run(['docker', 'rm', container])
    print('Download verified lock artifact, review/commit it, then enable the image.')


def patch_candidates(report):
    severities = {v.strip().upper() for v in env('TRIVY_PATCH_SEVERITY', 'HIGH,CRITICAL').split(',')}
    if not severities or not severities <= {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}:
        fail('TRIVY_PATCH_SEVERITY không hợp lệ')
    excluded = set(env('PATCH_PACKAGE_EXCLUDE').split())
    packages, skipped = set(), set()
    for block in report.get('Results') or []:
        if block.get('Class') != 'os-pkgs' or block.get('Type') not in ('ubuntu', 'debian'):
            continue
        for vuln in block.get('Vulnerabilities') or []:
            pkg = vuln.get('PkgName', '')
            if (vuln.get('Severity', '').upper() in severities and vuln.get('FixedVersion')
                    and re.fullmatch(r'[a-z0-9][a-z0-9+.:_-]*', pkg)):
                (skipped if pkg in excluded else packages).add(pkg)
    return sorted(packages), sorted(skipped)


def patch(args):
    row = one(require('IMAGE_ID'))
    name = row['id']
    info = document(path(name, 'build.json'))
    candidate = ref(row, require('IMAGE_CANDIDATE_TAG'))
    if info.get('candidate') != candidate or info.get('commit') != require('CI_COMMIT_SHA'):
        fail(f'{name}: build evidence không khớp')
    scan_file = path(name, 'scan.json')
    if not scan_file.is_file():
        fail(f'{name}: thiếu báo cáo Trivy scan ban đầu')
    findings = document(scan_file)
    packages, skipped = patch_candidates(findings)
    immutable = info.get('reference', '')
    if not re.fullmatch(re.escape(candidate.rsplit(':', 1)[0]) + r'@sha256:[a-f0-9]{64}', immutable):
        fail('Build artifact thiếu pinned digest')
    if env('CI_COMMIT_REF_PROTECTED') != 'true':
        fail('Patch push requires protected ref')
    status = 'no-applicable-os-fixes'
    final_reference = immutable
    if packages and env('AUTO_PATCH_OS', 'true').lower() == 'true':
        run(['docker', 'pull', immutable])
        user = run(['docker', 'image', 'inspect', '--format', '{{.Config.User}}', immutable], capture=True)
        if not re.fullmatch(r'[A-Za-z_0-9:.-]*', user):
            fail(f'{name}: user từ Docker inspect không an toàn')
        instructions = ['FROM ' + immutable, 'USER root', 'ENV DEBIAN_FRONTEND=noninteractive',
                        'RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade '
                        + ' '.join(packages) + ' && rm -rf /var/lib/apt/lists/*']
        if user:
            instructions.append('USER ' + user)
        with tempfile.TemporaryDirectory(prefix='sdwf-patch-') as tmp:
            pathlib.Path(tmp, 'Dockerfile').write_text('\n'.join(instructions) + '\n', encoding='utf-8')
            run(['docker', 'build', '--platform', row['platform'], '--progress=plain', '--pull=false',
                 '-f', f'{tmp}/Dockerfile', '-t', candidate, *build_arguments(), tmp])
        run(['docker', 'push', candidate])
        final_reference = pushed_digest(candidate)
        status = 'patched'
    elif packages:
        status = 'patch-disabled'
    write(path(name, 'patch.json'), {
        'id': name, 'candidate': candidate, 'status': status, 'reference': final_reference,
        'upgraded_packages': packages if status == 'patched' else [],
        'available_packages': packages, 'excluded_packages': skipped,
    })


def runtime(_args):
    row = one(require('IMAGE_ID'))
    name = row['id']
    immutable_file = path(name, 'verified.txt')
    if not immutable_file.is_file():
        fail(f'{name}: thiếu verified digest từ Harbor')
    immutable = immutable_file.read_text(encoding='utf-8').strip()
    if not re.fullmatch(re.escape(ref(row, require('IMAGE_CANDIDATE_TAG')).rsplit(':', 1)[0]) +
                        r'@sha256:[a-f0-9]{64}', immutable):
        fail(f'{name}: digest tham chiếu không hợp lệ')
    run(['docker', 'pull', immutable])
    runtime_check(row, immutable)
    write(path(name, 'runtime.json'), {'id': name, 'reference': immutable, 'result': 'pass'})


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('command', choices=('validate', 'smoke', 'build', 'patch', 'runtime', 'lock'))
    cli.add_argument('--dry-run', action='store_true', help='Show intent only; no Docker/network/file mutations')
    args = cli.parse_args()
    if args.dry_run:
        print('DRY-RUN:', args.command, 'image=' + env('IMAGE_ID'), '(no commands executed)')
        return
    try:
        {'validate': validate, 'smoke': build, 'build': build, 'patch': patch, 'runtime': runtime, 'lock': lock}[args.command](args)
    except (OSError, ValueError, KeyError) as exc:
        fail(str(exc))


if __name__ == '__main__':
    main()
