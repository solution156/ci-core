#!/usr/bin/env python3
"""Security evidence, SLSA provenance predicate, GitLab release cho từng image."""
from __future__ import annotations
import argparse
import datetime
import json
import pathlib
import urllib.error
import urllib.request
import urllib.parse
from catalog import one, env, require, ref, document, write, fail, security_policy_evidence


def file(name, part):
    return pathlib.Path('out') / name / part


def evidence(_args):
    name = require('IMAGE_ID')
    row = one(name)
    candidate = ref(row, require('IMAGE_CANDIDATE_TAG'))
    immutable = file(name, 'verified.txt').read_text(encoding='utf-8').strip()
    if not immutable.startswith(candidate.rsplit(':', 1)[0] + '@sha256:'):
        fail('Evidence digest khác candidate reference')
    build = document(file(name, 'build.json'))
    patch = document(file(name, 'patch.json'))
    runtime = document(file(name, 'runtime.json'))
    if (build.get('candidate') != candidate or patch.get('candidate') != candidate or
            runtime.get('reference') != immutable or runtime.get('result') != 'pass'):
        fail('Build/patch/runtime không khớp immutable digest')
    for part in ('scan.json', 'verify.json', 'verify-policy.json', 'sbom.cdx.json'):
        if not file(name, part).is_file() or not file(name, part).stat().st_size:
            fail(f'Thiếu evidence: {part}')
        document(file(name, part))
    gate_policy = security_policy_evidence(row)
    expected_gate = {'image_id': name, 'policy': gate_policy, 'result': 'pass', 'findings': []}
    if document(file(name, 'verify-policy.json')) != expected_gate:
        fail('Security gate result không khớp catalog hoặc VEX source digest')
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    core_source = require('CI_PROJECT_URL')
    commit = require('CI_COMMIT_SHA')
    root_id = require('ROOT_PIPELINE_ID')
    manifest = {
        'image_id': name, 'image_version': row['version'], 'reference': immutable,
        'git_sha': commit, 'git_tag': env('CI_COMMIT_TAG'), 'git_branch': env('CI_COMMIT_BRANCH'),
        'root_pipeline_id': root_id, 'child_pipeline_id': require('CI_PIPELINE_ID'),
        'pipeline_kind': require('WORKSPACE_REF_KIND'), 'generated_at': now,
        'scan_severity': require('TRIVY_SCAN_SEVERITY'),
        'gate_severity': gate_policy['severity'],
        'gate_policy': gate_policy,
    }
    write(file(name, 'evidence.json'), manifest)
    # SLSA v1 predicate, Cosign ghép predicate vào in-toto statement với subject digest.
    provenance = {
        'buildDefinition': {
            'buildType': core_source + '/-/blob/' + commit + '/.gitlab-ci.yml',
            'externalParameters': {
                'source': {'uri': core_source, 'commit': commit},
                'imageId': name, 'version': row['version'],
                'dockerfile': build.get('dockerfile'), 'context': build.get('context'),
                'platform': build.get('platform'), 'target': build.get('target'),
                'buildArgs': build.get('build_args', {}), 'candidate': candidate,
            },
            'internalParameters': {'rootPipelineId': root_id},
            'resolvedDependencies': [{'uri': 'git+' + core_source,
                                      'digest': {'gitCommit': commit}}],
        },
        'runDetails': {
            'builder': {'id': core_source + '/-/pipelines/' + root_id},
            'metadata': {'invocationId': env('CI_PIPELINE_URL'), 'finishedOn': now},
        },
    }
    write(file(name, 'provenance.json'), provenance)
    # Only VEX documents explicitly named by the catalog policy are emitted.
    statements = []
    for source in gate_policy['vex_sources']:
        src = document(source)
        statements.extend(src['statements'])
    if statements:
        write(file(name, 'vex.openvex.json'), {
            '@context': 'https://openvex.dev/ns/v0.2.0',
            '@id': env('CI_PIPELINE_URL') + '/openvex/' + name,
            'author': env('CI_PROJECT_PATH'), 'timestamp': now,
            'version': 1, 'statements': statements,
        })
    summary = [f'# Phát hành {name} v{row["version"]}', '',
               f'- Image digest: `{immutable}`', f'- Commit: `{commit}`',
               f'- Parent pipeline: `{root_id}`', f'- Git ref: `{env("CI_COMMIT_TAG") or env("CI_COMMIT_BRANCH")}`',
               f'- Gate: severity=`{gate_policy["severity"]}`, pkg_types=`{gate_policy["pkg_types"]}`, '
               f'ignore_unfixed=`{str(gate_policy["ignore_unfixed"]).lower()}`',
               f'- VEX source digests: `{gate_policy["vex_source_digests"]}`',
               f'- OS patch: `{patch["status"]}`',
               '- Đã kiểm thử container dưới USER 1000 và các thư mục Kasm cơ bản.',
               '- Kết quả kiểm thử này **không thay thế** UAT trình duyệt/GUI thực tế.', '']
    file(name, 'summary.md').write_text('\n'.join(summary), encoding='utf-8')
    print('Evidence sẵn sàng cho Cosign:', immutable)


def publish(_args):
    name = require('IMAGE_ID')
    row = one(name)
    tag = require('CI_COMMIT_TAG')
    if (tag not in (f'{name}/v{row["version"]}', f'release/{name}/v{row["version"]}') or
            require('WORKSPACE_REF_KIND') != 'release' or env('CI_COMMIT_REF_PROTECTED') != 'true'):
        fail('GitLab Release chỉ cho protected tag image đã được xác thực')
    promotion = document(file(name, 'promotion.json'))
    if promotion.get('image_id') != name or promotion.get('promoted') != ref(row, row['version']):
        fail('Missing/mismatched Harbor promotion')
    evidence_json = document(file(name, 'evidence.json'))
    if evidence_json.get('reference') != promotion.get('reference'):
        fail('Digest promoted khác digest evidence')
    api = require('CI_API_V4_URL').rstrip('/')
    project = require('CI_PROJECT_ID')
    body = {
        'name': f'{name} v{row["version"]}', 'tag_name': tag,
        'description': file(name, 'summary.md').read_text(encoding='utf-8') +
                       f'\nHarbor: `{promotion["promoted"]}`\n',
        'ref': require('CI_COMMIT_SHA'),
    }
    url = f'{api}/projects/{urllib.parse.quote(project, safe="")}/releases'
    target = url + '/' + urllib.parse.quote(tag, safe='')
    def read_release():
        request = urllib.request.Request(target, headers={'JOB-TOKEN': require('CI_JOB_TOKEN')})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            fail(f'Releases GET HTTP {exc.code}')
    try:
        existing = read_release()
        if existing is None:
            req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), method='POST',
                                         headers={'JOB-TOKEN': require('CI_JOB_TOKEN'), 'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=30) as result:
                if result.status != 201:
                    fail(f'Unexpected Releases API status {result.status}')
            existing = read_release()
        if not existing or existing.get('tag_name') != tag or existing.get('commit', {}).get('id') != require('CI_COMMIT_SHA'):
            fail('GitLab Release read-back không khớp tag/commit')
    except urllib.error.HTTPError as exc:
        fail(f'Releases API HTTP {exc.code}')
    except urllib.error.URLError as exc:
        fail(f'Releases API failure: {exc.reason}')
    print('GitLab release verified:', tag)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('command', choices=('evidence', 'publish'))
    cli.add_argument('--dry-run', action='store_true', help='No API calls or file writes')
    args = cli.parse_args()
    if args.dry_run:
        print('DRY-RUN Release', args.command, 'image=' + env('IMAGE_ID'))
        return
    {'evidence': evidence, 'publish': publish}[args.command](args)


if __name__ == '__main__':
    main()
