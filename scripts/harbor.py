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
from catalog import (one, ref, document, write, require, env, fail as catalog_fail,
                     security_gate, security_policy_evidence)


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


def selected_candidate(candidate, report):
    expected_ref = candidate
    if report.get('status') == 'patched' and report.get('transport') != 'local-archive':
        expected_ref += '-patched'
    if report.get('candidate') != candidate or report.get('final_candidate') != expected_ref:
        fail('Patch evidence không khớp candidate ref')
    return expected_ref


def snapshot(_args):
    name = required('IMAGE_ID')
    row, candidate = expected(name)
    build = document(file(name, 'build.json'))
    if build.get('candidate') != candidate:
        fail('Build artifact không khớp candidate ref')
    report = document(file(name, 'patch.json'))
    final_candidate = selected_candidate(candidate, report)
    if report.get('build_reference') != build.get('reference'):
        fail('Patch build digest không khớp build evidence')
    harbor = Harbor()
    digest = harbor.digest(row['repository'], final_candidate.rsplit(':', 1)[1])
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


# Gate policy comes from the catalog via planner job variables. Default is strict:
# all package classes, unfixed findings included. Only an explicit per-image
# exception in images.json may relax it.
PKGS_TO_CLASS = {'os': 'os-pkgs', 'library': 'lang-pkgs'}


def gate_findings(report, severities, pkg_types='os,library', ignore_unfixed=False):
    """Return gated CVE IDs using the image's effective Trivy gate policy."""
    classes = {PKGS_TO_CLASS[p.strip()] for p in pkg_types.split(',') if p.strip() in PKGS_TO_CLASS}
    findings = []
    for block in report.get('Results') or []:
        if block.get('Class') not in classes:
            continue
        for vulnerability in block.get('Vulnerabilities') or []:
            if vulnerability.get('Severity', '').upper() not in severities:
                continue
            if ignore_unfixed and not vulnerability.get('FixedVersion'):
                continue
            findings.append(vulnerability.get('VulnerabilityID'))
    return findings


def gate_policy(row):
    """The catalog is the only source of security-gate policy."""
    return security_gate(row)


def report_findings(name, policy):
    checked = document(file(name, 'verify.json'))
    severities = set(policy['severity'].split(','))
    return gate_findings(checked, severities, policy['pkg_types'], policy['ignore_unfixed'])


def check_gate_report(name, policy):
    gated = report_findings(name, policy)
    if gated:
        fail(f'{name} vẫn còn CVE {gated[0]}')


def gate(_args):
    name = required('IMAGE_ID')
    row = one(name)
    policy = gate_policy(row)
    gated = report_findings(name, policy)
    result = {'image_id': name, 'policy': security_policy_evidence(row),
              'result': 'fail' if gated else 'pass', 'findings': gated}
    write(file(name, 'verify-policy.json'), result)
    if gated:
        fail(f'{name} vẫn còn CVE {gated[0]}')
    print('Security gate OK:', name, policy['severity'], policy['pkg_types'])


def ensure_verified(name, immutable):
    if file(name, 'verified.txt').read_text(encoding='utf-8').strip() != immutable:
        fail('Verified artifact không khớp')
    if file(name, 'signed.txt').read_text(encoding='utf-8').strip() != immutable:
        fail('Cosign signature marker không khớp immutable digest')
    runtime = document(file(name, 'runtime.json'))
    if runtime != {'id': name, 'reference': immutable, 'result': 'pass'}:
        fail('Runtime gate không đạt')
    row = one(name)
    policy = gate_policy(row)
    check_gate_report(name, policy)
    expected_policy = {'image_id': name, 'policy': security_policy_evidence(row),
                       'result': 'pass', 'findings': []}
    if document(file(name, 'verify-policy.json')) != expected_policy:
        fail('Security gate artifact không khớp images.json hoặc VEX source digest')
    for part in ('scan.json', 'patch.json', 'sbom.cdx.json', 'build.json',
                 'evidence.json', 'provenance.json', 'summary.md'):
        if not file(name, part).is_file() or file(name, part).stat().st_size == 0:
            fail(f'Thiếu security evidence: {part}')
    evidence = document(file(name, 'evidence.json'))
    if evidence.get('reference') != immutable or evidence.get('image_id') != name:
        fail('Evidence JSON khác digest được ký')
    if evidence.get('gate_policy') != expected_policy['policy']:
        fail('Evidence gate policy không khớp catalog')


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
    patch = document(file(name, 'patch.json'))
    final_candidate = selected_candidate(candidate, patch)
    if patch.get('reference') != immutable or harbor.digest(row['repository'], final_candidate.rsplit(':', 1)[1]) != digest:
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
    output = {'image_id': name, 'candidate': candidate, 'final_candidate': final_candidate, 'reference': immutable,
              'promoted': ref(row, final), 'digest': digest}
    write(file(name, 'promotion.json'), output)
    print('Promotion OK:', output['promoted'], digest)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('command', choices=('snapshot', 'gate', 'promote'))
    cli.add_argument('--dry-run', action='store_true', help='No API calls or file writes')
    args = cli.parse_args()
    if args.dry_run:
        print('DRY-RUN Harbor', args.command, 'image=' + env('IMAGE_ID'))
        return
    {'snapshot': snapshot, 'gate': gate, 'promote': promote}[args.command](args)


if __name__ == '__main__':
    main()
