#!/usr/bin/env python3
"""Harbor v2 API: lock candidate digest and promote only verified artifacts.

Promote preflights every selected image before changing any tag. Harbor has no
atomic multi-repository transaction; the release is not published if a call fails.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from catalog import one, ref, document, write, require, env, fail as catalog_fail


def fail(message):
    raise SystemExit('ERROR: ' + message)


def required(key):
    value = os.environ.get(key, '').strip()
    if not value:
        fail(f'{key} is required')
    return value


class Harbor:
    def __init__(self):
        self.registry = required('HARBOR_REGISTRY')
        self.project = required('HARBOR_PROJECT')
        self.auth = base64.b64encode((required('HARBOR_USER') + ':' + required('HARBOR_PASSWORD')).encode()).decode()
        scheme = os.environ.get('HARBOR_SCHEME', 'https')
        if scheme not in ('http', 'https'):
            fail('Invalid HARBOR_SCHEME')
        self.base = f'{scheme}://{self.registry}/api/v2.0'
        if os.environ.get('HARBOR_TLS_VERIFY', 'true').lower() != 'true':
            fail('HARBOR_TLS_VERIFY=false is forbidden for release promotion; install the trusted CA instead')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    @staticmethod
    def encoded(repo):
        return urllib.parse.quote(urllib.parse.quote(repo, safe=''), safe='')

    def path(self, repo, artifact=None):
        result = f'/projects/{urllib.parse.quote(self.project, safe="")}/repositories/{self.encoded(repo)}/artifacts'
        return result if artifact is None else result + '/' + urllib.parse.quote(artifact, safe='')

    def request(self, method, path, document=None, missing_ok=False):
        body = json.dumps(document).encode() if document is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method)
        req.add_header('Authorization', 'Basic ' + self.auth)
        req.add_header('Accept', 'application/json')
        if body is not None:
            req.add_header('Content-Type', 'application/json')
        try:
            with self.opener.open(req, timeout=45) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            fail(f'Harbor {method} {path}: HTTP {error.code}: {error.read().decode(errors="replace")[:500]}')
        except urllib.error.URLError as error:
            fail(f'Harbor request failed: {error.reason}')

    def digest(self, repo, tag):
        result = self.request('GET', self.path(repo, tag), missing_ok=True)
        if result is None:
            return None
        digest = result.get('digest')
        if not digest or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            fail(f'Invalid digest returned by Harbor for {repo}:{tag}')
        return digest

    def tag(self, repo, digest, target):
        self.request('POST', self.path(repo, digest) + '/tags', {'name': target})

    def untag(self, repo, digest, tag):
        self.request('DELETE', self.path(repo, digest) + '/tags/' + urllib.parse.quote(tag, safe=''))



def file(name, part):
    return pathlib.Path('out') / name / part


def expected(name):
    row = one(name)
    return row, ref(row, required('IMAGE_CANDIDATE_TAG'))


def snapshot(_args):
    name = required('IMAGE_ID')
    row, candidate = expected(name)
    build = document(file(name, 'build.json'))
    if build.get('candidate') != candidate:
        fail('Build artifact không khớp candidate ref')
    report = document(file(name, 'patch.json'))
    if report.get('candidate') != candidate:
        fail('Patch evidence không khớp candidate ref')
    harbor = Harbor()
    digest = harbor.digest(row['repository'], required('IMAGE_CANDIDATE_TAG'))
    if digest is None:
        fail('Candidate tag không tồn tại trên Harbor')
    immutable = candidate.rsplit(':', 1)[0] + '@' + digest
    if report.get('reference') != immutable:
        fail('Candidate đã đổi sau patch push; từ chối khóa digest khác')
    file(name, 'verified.txt').write_text(immutable + '\n', encoding='utf-8')
    print('Locked post-patch digest:', immutable)


def assert_current_branch_tip():
    branch = required('CI_COMMIT_BRANCH')
    expected_sha = required('CI_COMMIT_SHA')
    api = required('CI_API_V4_URL').rstrip('/')
    project = required('CI_PROJECT_ID')
    token = required('CI_JOB_TOKEN')
    url = (f'{api}/projects/{urllib.parse.quote(project, safe="")}/repository/branches?'
           + urllib.parse.urlencode({'search': '^' + re.escape(branch) + '$', 'per_page': 100}))
    req = urllib.request.Request(url, headers={'JOB-TOKEN': token})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            branches = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError) as error:
        fail(f'Không thể xác nhận branch tip: {error}')
    matches = [b for b in branches if b.get('name') == branch]
    if len(matches) != 1 or matches[0].get('commit', {}).get('id') != expected_sha:
        fail(f'{branch} đã thay đổi: từ chối promote pipeline cũ')


def ensure_verified(name, immutable):
    if file(name, 'verified.txt').read_text(encoding='utf-8').strip() != immutable:
        fail('Verified artifact không khớp')
    if file(name, 'signed.txt').read_text(encoding='utf-8').strip() != immutable:
        fail('Cosign signature marker không khớp immutable digest')
    runtime = document(file(name, 'runtime.json'))
    if runtime != {'id': name, 'reference': immutable, 'result': 'pass'}:
        fail('Runtime gate không đạt')
    checked = document(file(name, 'verify.json'))
    severities = {x.strip().upper() for x in required('TRIVY_GATE_SEVERITY').split(',')}
    if not severities or not severities <= {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}:
        fail('TRIVY_GATE_SEVERITY không hợp lệ')
    for block in checked.get('Results') or []:
        for vulnerability in block.get('Vulnerabilities') or []:
            if vulnerability.get('Severity', '').upper() in severities:
                fail(f'{name} vẫn còn CVE {vulnerability.get("VulnerabilityID")}')
    for part in ('scan.json', 'patch.json', 'sbom.cdx.json', 'build.json',
                 'evidence.json', 'provenance.json', 'summary.md'):
        if not file(name, part).is_file() or file(name, part).stat().st_size == 0:
            fail(f'Thiếu security evidence: {part}')
    evidence = document(file(name, 'evidence.json'))
    if evidence.get('reference') != immutable or evidence.get('image_id') != name:
        fail('Evidence JSON khác digest được ký')


def promote(_args):
    name = required('IMAGE_ID')
    row, candidate = expected(name)
    final = required('IMAGE_FINAL_TAG')
    kind = required('WORKSPACE_REF_KIND')
    if kind not in ('main', 'rc', 'release'):
        fail('Ref kind không có quyền promote')
    if env('CI_COMMIT_REF_PROTECTED') != 'true':
        fail('Chỉ protected ref được promote')
    expected_final = (row['version'] + '-dev' if kind == 'main' else
                      row['version'] + '-rc' if kind == 'rc' else row['version'])
    if final != expected_final:
        fail('Final tag không khớp chính sách per-image')
    if kind in ('main', 'rc'):
        assert_current_branch_tip()
    if kind == 'release' and env('CI_COMMIT_TAG') not in (f'{name}/v{row["version"]}', f'release/{name}/v{row["version"]}'):
        fail('Immutable release phải khớp Git tag của image')
    expected_candidate = ref(row, required('IMAGE_CANDIDATE_TAG'))
    if candidate != expected_candidate:
        fail('Candidate không khớp')
    immutable = file(name, 'verified.txt').read_text(encoding='utf-8').strip()
    if not re.fullmatch(re.escape(candidate.rsplit(':', 1)[0]) + r'@sha256:[a-f0-9]{64}', immutable):
        fail('Digest được duyệt không hợp lệ')
    ensure_verified(name, immutable)
    harbor = Harbor()
    digest = immutable.rsplit('@', 1)[1]
    if harbor.digest(row['repository'], required('IMAGE_CANDIDATE_TAG')) != digest:
        fail('Candidate digest đã thay đổi sau khi scan: từ chối promote')
    previous = harbor.digest(row['repository'], final)
    if previous and previous != digest and kind == 'release':
        fail(f'Immutable release {final} đã tồn tại với digest khác')
    if previous != digest:
        if previous:
            harbor.untag(row['repository'], previous, final)
        harbor.tag(row['repository'], digest, final)
    if harbor.digest(row['repository'], final) != digest:
        fail('Harbor tag verification failed')
    output = {'image_id': name, 'candidate': candidate, 'reference': immutable,
              'promoted': ref(row, final), 'digest': digest}
    write(file(name, 'promotion.json'), output)
    print('Promotion OK:', output['promoted'], digest)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('command', choices=('snapshot', 'promote'))
    cli.add_argument('--dry-run', action='store_true', help='No API calls or file writes')
    args = cli.parse_args()
    if args.dry_run:
        print('DRY-RUN Harbor', args.command, 'image=' + env('IMAGE_ID'))
        return
    {'snapshot': snapshot, 'promote': promote}[args.command](args)


if __name__ == '__main__':
    main()
