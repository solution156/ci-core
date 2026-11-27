#!/usr/bin/env python3
"""Danh mục image, kiểm tra source và xác định chính xác image cần build.

Chỉ dùng thư viện chuẩn Python. images.json thuộc sở hữu repo Workspace Images.
"""
from __future__ import annotations
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess

ROOT = pathlib.Path.cwd()
ID = re.compile(r'[a-z0-9]+(?:[._-][a-z0-9]+)*\Z')
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
RELEASE_TAG = re.compile(r'(?:release/)?([a-z0-9]+(?:[._-][a-z0-9]+)*)/v(\d+\.\d+\.\d+)\Z')
RELEASE_BRANCH = re.compile(r'release/([a-z0-9]+(?:[._-][a-z0-9]+)*)/v(\d+\.\d+\.\d+)\Z')
DEV_BRANCH = re.compile(r'(feature|bugfix|hotfix)/[a-zA-Z0-9][a-zA-Z0-9._/-]*\Z')
REGISTRY = re.compile(r'[a-zA-Z0-9._:-]+\Z')


def fail(message):
    raise SystemExit('ERROR: ' + message)


def env(key, default=''):
    return os.environ.get(key, default).strip()


def require(key):
    value = env(key)
    if not value:
        fail(f'Thiếu biến bắt buộc {key}')
    return value


def docker_config_path():
    root = pathlib.Path(require('CI_PROJECT_DIR')).resolve()
    path = pathlib.Path(env('DOCKER_CONFIG', str(root / '.docker-job'))).resolve()
    if path != root / '.docker-job':
        fail('DOCKER_CONFIG phải là CI_PROJECT_DIR/.docker-job')
    return path


def job_builder_name():
    job_id = require('CI_JOB_ID')
    if not re.fullmatch(r'[0-9]+', job_id):
        fail('CI_JOB_ID không hợp lệ để tạo Buildx builder riêng')
    return 'workspace-ci-' + job_id


def document(path):
    return json.loads(pathlib.Path(path).read_text(encoding='utf-8'))


def write(path, obj):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def checked_path(value):
    if not isinstance(value, str) or not value or pathlib.PurePosixPath(value).is_absolute() or '..' in pathlib.PurePosixPath(value).parts:
        fail('Đường dẫn catalog không an toàn')
    path = ROOT / value
    if not path.is_file() or not path.resolve().is_relative_to(ROOT.resolve()):
        fail(f'File catalog thiếu/không an toàn: {value}')
    return path


def lock_config(row, strict=True):
    config = row.get('extension_lock')
    if config is None:
        return True
    if not isinstance(config, dict) or set(config) != {'manifest', 'lock', 'generated'}:
        fail(f'{row["id"]}: extension_lock cần manifest, lock, generated')
    manifest = checked_path(config['manifest'])
    lock = checked_path(config['lock'])
    if not isinstance(config['generated'], str) or not config['generated'].startswith('/opt/') or '..' in pathlib.PurePosixPath(config['generated']).parts:
        fail('extension_lock.generated không an toàn')
    def entries(path):
        return [s.split('#', 1)[0].strip() for s in path.read_text(encoding='utf-8').splitlines()
                if s.split('#', 1)[0].strip()]
    wanted = entries(manifest)
    if not wanted or any(not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', s) for s in wanted) or len(set(s.lower() for s in wanted)) != len(wanted):
        fail(f'{row["id"]}: extension manifest không hợp lệ')
    if not row['enabled']:
        return True
    locked = entries(lock)
    pins = {}
    valid = True
    for spec in locked:
        match = re.fullmatch(r'([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)@(\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?)', spec)
        if not match or match[1].lower() in pins:
            valid = False
            break
        pins[match[1].lower()] = match[2]
    valid = valid and set(pins) == {s.lower() for s in wanted}
    if not valid and strict:
        fail(f'{row["id"]}: extensions.lock không hợp lệ; chạy FAST trên branch, tải và commit lock artifact')
    return valid


SECURITY_GATE_FIELDS = {'severity', 'pkg_types', 'ignore_unfixed', 'vex_sources', 'justification', 'review_by'}
PKG_CLASSES = {'os': 'os-pkgs', 'library': 'lang-pkgs'}
SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}
WEAKEST_SECURITY_POLICY = {'severity': {'CRITICAL'}, 'pkg_types': {'os', 'library'}, 'ignore_unfixed': False}
VEX_FILE = re.compile(r'vex/[a-z0-9]+(?:[._-][a-z0-9]+)*/[A-Za-z0-9][A-Za-z0-9._-]*\.openvex\.json\Z')


def security_gate(row):
    """Validated catalog-owned Trivy gate policy; strict by default."""
    raw = row.get('security_gate') or {}
    if not isinstance(raw, dict) or not set(raw) <= SECURITY_GATE_FIELDS:
        fail(f'{row["id"]}: security_gate fields không hợp lệ')
    severity = raw.get('severity', 'CRITICAL')
    pkg_types = raw.get('pkg_types', 'os,library')
    ignore_unfixed = raw.get('ignore_unfixed', False)
    sources = raw.get('vex_sources', [])
    if not isinstance(severity, str) or not severity:
        fail(f'{row["id"]}: security_gate.severity không hợp lệ')
    severity_parts = [part.strip().upper() for part in severity.split(',')]
    if any(part not in SEVERITIES for part in severity_parts) or len(set(severity_parts)) != len(severity_parts):
        fail(f'{row["id"]}: security_gate.severity không hợp lệ')
    severity_parts = sorted(severity_parts, key=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].index)
    if not isinstance(pkg_types, str) or not pkg_types:
        fail(f'{row["id"]}: security_gate.pkg_types không hợp lệ')
    parts = [part.strip() for part in pkg_types.split(',')]
    if not parts or any(part not in PKG_CLASSES for part in parts) or len(set(parts)) != len(parts):
        fail(f'{row["id"]}: security_gate.pkg_types chỉ nhận os, library')
    if type(ignore_unfixed) is not bool:
        fail(f'{row["id"]}: security_gate.ignore_unfixed phải là boolean')
    if not isinstance(sources, list) or any(not isinstance(source, str) or not VEX_FILE.fullmatch(source)
                                               or not source.startswith(f'vex/{row["id"]}/') for source in sources):
        fail(f'{row["id"]}: security_gate.vex_sources chỉ nhận file OpenVEX trong vex/{row["id"]}/')
    if len(sources) != len(set(sources)):
        fail(f'{row["id"]}: security_gate.vex_sources bị trùng')
    vex_dir = ROOT / 'vex' / row['id']
    present = {p.relative_to(ROOT).as_posix() for p in vex_dir.rglob('*.openvex.json')} if vex_dir.is_dir() else set()
    if present != set(sources):
        fail(f'{row["id"]}: VEX sources phải khai báo tường minh, không khai báo={sorted(present-set(sources))}, thiếu={sorted(set(sources)-present)}')
    for source in sources:
        vex = document(checked_path(source))
        statements = vex.get('statements')
        if not str(vex.get('@context', '')).startswith('https://openvex.dev/ns/') or not isinstance(statements, list) or not statements:
            fail(f'{row["id"]}: OpenVEX không hợp lệ: {source}')
        for statement in statements:
            if (not isinstance(statement, dict) or not statement.get('vulnerability') or
                    statement.get('status') not in {'not_affected', 'affected', 'fixed', 'under_investigation'} or
                    not statement.get('products')):
                fail(f'{row["id"]}: OpenVEX statement không hợp lệ: {source}')
            if statement['status'] == 'not_affected' and not (statement.get('justification') or statement.get('impact_statement')):
                fail(f'{row["id"]}: not_affected thiếu justification: {source}')
    justification = raw.get('justification', '')
    review_by = raw.get('review_by', '')
    weaker = (not WEAKEST_SECURITY_POLICY['severity'] <= set(severity_parts) or
              set(parts) != WEAKEST_SECURITY_POLICY['pkg_types'] or ignore_unfixed or bool(sources))
    if weaker:
        if not isinstance(justification, str) or len(justification.strip()) < 20:
            fail(f'{row["id"]}: ngoại lệ security_gate cần justification (tối thiểu 20 ký tự)')
        try:
            review_date = datetime.date.fromisoformat(review_by)
        except (TypeError, ValueError):
            fail(f'{row["id"]}: ngoại lệ security_gate cần review_by dạng YYYY-MM-DD')
        if review_date < datetime.date.today():
            fail(f'{row["id"]}: security_gate exception đã quá hạn review')
    elif justification or review_by:
        if not isinstance(justification, str) or not isinstance(review_by, str):
            fail(f'{row["id"]}: security_gate justification/review_by không hợp lệ')
    return {'severity': ','.join(severity_parts), 'pkg_types': ','.join(parts),
            'ignore_unfixed': ignore_unfixed, 'vex_sources': sorted(sources),
            'justification': justification, 'review_by': review_by}


def security_policy_evidence(row):
    policy = security_gate(row)
    sources = []
    for source in policy['vex_sources']:
        digest = hashlib.sha256(checked_path(source).read_bytes()).hexdigest()
        sources.append({'path': source, 'sha256': 'sha256:' + digest})
    return {**policy, 'vex_source_digests': sources}


BUILD_FIELDS = {'context', 'dockerfile', 'platform', 'args', 'target'}
BUILD_ARG_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
BUILD_TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
BUILD_PLATFORM = re.compile(r'[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9_.-]+)?\Z')
SECRET_BUILD_ARG = re.compile(r'(?:PASS(?:WORD)?|SECRET|TOKEN|CREDENTIAL|PRIVATE|API[_-]?KEY|AUTH)', re.I)
PIPELINE_BUILD_ARGS = {'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'EXTENSION_MODE'}


def build_config(row):
    """Validated per-image build settings; legacy catalog fields remain defaults."""
    raw = row.get('build', {})
    if not isinstance(raw, dict) or not set(raw) <= BUILD_FIELDS:
        fail(f'{row.get("id", "image")}: build chỉ nhận {sorted(BUILD_FIELDS)}')
    context = raw.get('context', row.get('context', '.'))
    dockerfile = raw.get('dockerfile', row.get('dockerfile', f'images/{row.get("id", "")}/Dockerfile'))
    platform = raw.get('platform', row.get('platform', 'linux/amd64'))
    target = raw.get('target', '')
    args = raw.get('args', {})
    context = pathlib.PurePosixPath(context).as_posix() if isinstance(context, str) else context
    dockerfile = pathlib.PurePosixPath(dockerfile).as_posix() if isinstance(dockerfile, str) else dockerfile
    for label, value in (('context', context), ('dockerfile', dockerfile)):
        path = pathlib.PurePosixPath(value) if isinstance(value, str) else None
        if (path is None or not value or path.is_absolute() or '..' in path.parts or
                any(part in ('', '.') for part in path.parts if part != '.')):
            fail(f'{row.get("id", "image")}: build.{label} không an toàn')
    if context != '.':
        context_dir = ROOT / context
        if not context_dir.is_dir() or not context_dir.resolve().is_relative_to(ROOT.resolve()):
            fail(f'{row.get("id", "image")}: build.context thiếu hoặc vượt repo')
    if not isinstance(platform, str) or not BUILD_PLATFORM.fullmatch(platform):
        fail(f'{row.get("id", "image")}: build.platform không hợp lệ')
    if target and (not isinstance(target, str) or not BUILD_TARGET.fullmatch(target)):
        fail(f'{row.get("id", "image")}: build.target không hợp lệ')
    if not isinstance(args, dict):
        fail(f'{row.get("id", "image")}: build.args phải là object')
    normalized_args = {}
    for key, value in args.items():
        if not isinstance(key, str) or not BUILD_ARG_NAME.fullmatch(key):
            fail(f'{row.get("id", "image")}: tên build arg không hợp lệ')
        if key in PIPELINE_BUILD_ARGS or SECRET_BUILD_ARG.search(key):
            fail(f'{row.get("id", "image")}: build arg {key} có thể chứa secret hoặc do pipeline quản lý')
        if not isinstance(value, (str, int, float, bool)) or isinstance(value, (dict, list)):
            fail(f'{row.get("id", "image")}: build arg {key} phải là giá trị scalar')
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        if any(ord(char) < 32 for char in rendered):
            fail(f'{row.get("id", "image")}: build arg {key} chứa ký tự điều khiển')
        normalized_args[key] = rendered
    return {'context': context, 'dockerfile': dockerfile, 'platform': platform,
            'args': normalized_args, 'target': target}


def runtime_config(row):
    raw = row.get('runtime', {})
    if not isinstance(raw, dict) or not set(raw) <= {'uid', 'shell', 'require_kasm'}:
        fail('runtime chỉ nhận uid, shell và require_kasm')
    uid, shell, kasm = raw.get('uid', 1000), raw.get('shell', '/bin/bash'), raw.get('require_kasm', True)
    if type(uid) is not int or not 0 <= uid <= 2147483647:
        fail('runtime.uid phải là UID hợp lệ (0 = root)')
    if shell not in ('/bin/sh', '/bin/bash') or type(kasm) is not bool:
        fail('runtime.shell hoặc runtime.require_kasm không hợp lệ')
    return uid, shell, kasm


def catalog(strict_locks=True):
    source = document('images.json')
    if source.get('schema_version') != 2 or not isinstance(source.get('images'), list):
        fail('images.json phải có schema_version=2 và mảng images')
    ids, repositories, result = set(), set(), []
    root = ROOT.resolve()
    for row in source['images']:
        if not isinstance(row, dict):
            fail('Mỗi image phải là object')
        name, repo, version = row.get('id'), row.get('repository'), row.get('version')
        if not isinstance(name, str) or not ID.fullmatch(name) or not isinstance(repo, str) or not ID.fullmatch(repo):
            fail(f'ID hoặc repository không hợp lệ: {name}/{repo}')
        if name in ids or repo in repositories:
            fail(f'Trùng ID/repository: {name}/{repo}')
        ids.add(name); repositories.add(repo)
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            fail(f'{name}: version phải dạng X.Y.Z độc lập cho image')
        if type(row.get('enabled')) is not bool:
            fail(f'{name}: enabled phải là boolean')
        build = build_config(row)
        context_dir = (ROOT / build['context']).resolve()
        dockerfile = (context_dir / build['dockerfile']).resolve()
        if not context_dir.is_dir() or not context_dir.is_relative_to(root):
            fail(f'{name}: build.context thiếu hoặc vượt repo')
        if not dockerfile.is_file() or not dockerfile.is_relative_to(context_dir):
            fail(f'{name}: Dockerfile thiếu hoặc nằm ngoài build context')
        lines = dockerfile.read_text(encoding="utf-8").replace(chr(92) + chr(10), " " ).splitlines()
        # Không kiểm tra USER ở catalog: custom image có thể dùng USER root.
        # Mọi kiểm tra runtime được thực hiện SAU KHI BUILD bởi runtime_check().
        if not any(x.startswith('FROM ') for x in lines):
            fail(f'{name}: Dockerfile thiếu FROM')
        stage_names = []
        for line in lines:
            if line.startswith('FROM '):
                match = re.search(r'\s+AS\s+([A-Za-z0-9_.-]+)\s*$', line, re.I)
                if match:
                    stage_names.append(match[1].lower())
        if build['target']:
            target = build['target'].lower()
            numeric_target = target.isdigit() and int(target) < len([line for line in lines if line.startswith('FROM ')])
            if target not in stage_names and not numeric_target:
                fail(f'{name}: build.target không tồn tại trong Dockerfile')
        for line in lines:
            if not line.startswith('COPY '):
                continue
            args = shlex.split(line)[1:]
            if any(x.startswith('--from=') for x in args):
                continue
            src = [x for x in args if not x.startswith('--')][:-1]
            if not src:
                fail(f'{name}: COPY không hợp lệ: {line}')
            for item in src:
                p = context_dir / item
                if pathlib.PurePosixPath(item).is_absolute() or '..' in pathlib.PurePosixPath(item).parts:
                    fail(f'{name}: nguồn COPY không an toàn: {item}')
                # File có thể do CI tạo trước build (cert local, file từ secret).
                # Kiểm tra tồn tại để biết sớm, nhưng KHÔNG chặn: build sẽ fail
                # nếu file thực sự cần thiết không xuất hiện.
                if p.exists() and not p.resolve().is_relative_to(context_dir):
                    fail(f'{name}: nguồn COPY vượt build context: {item}')
        deps = row.get('depends_on')
        if not isinstance(deps, list) or any(not isinstance(d, str) or not d.startswith('shared/') or '..' in pathlib.PurePosixPath(d).parts or not (ROOT / d).is_file() for d in deps):
            fail(f'{name}: depends_on phải tham chiếu tài nguyên shared/ hợp lệ')
        if len(deps) != len(set(deps)):
            fail(f'{name}: depends_on bị trùng')
        if build['context'] != '.' and deps:
            fail(f'{name}: depends_on shared/ yêu cầu build.context là repo root')
        shared_copy = set()
        for line in lines:
            if not line.startswith('COPY '):
                continue
            args = shlex.split(line)[1:]
            if any(x.startswith('--from=') for x in args):
                continue
            shared_copy.update(x for x in [p for p in args if not p.startswith('--')][:-1]
                               if x.startswith('shared/'))
        if shared_copy and build['context'] != '.':
            fail(f'{name}: COPY shared/ yêu cầu build.context là repo root')
        if not shared_copy <= set(deps):
            fail(f'{name}: Dockerfile COPY shared chưa có depends_on: {sorted(shared_copy - set(deps))}')
        lock_config(row, strict=strict_locks)
        security_gate(row)
        if 'runtime_check' in row:
            checked_path(row['runtime_check'])
        result.append(row)
    if not result or not any(x['enabled'] for x in result):
        fail('Danh mục không có image đang bật')
    referenced = {p for row in result for p in row['depends_on']}
    actual = {p.as_posix() for p in pathlib.Path('shared').rglob('*') if p.is_file()}
    if actual != referenced:
        fail(f'Có tài nguyên shared chưa được khai báo hoặc thiếu: {sorted(actual ^ referenced)}')
    return result


def one(name, strict_locks=True):
    rows = {r['id']: r for r in catalog(strict_locks=strict_locks)}
    if name not in rows or not rows[name]['enabled']:
        fail(f'Image không tồn tại hoặc chưa enable: {name}')
    return rows[name]


def ref(row, tag):
    host = require('HARBOR_REGISTRY')
    project = require('HARBOR_PROJECT')
    if not REGISTRY.fullmatch(host) or not re.fullmatch(r'[a-z0-9]+(?:[a-z0-9._/-]*[a-z0-9])?', project) or '..' in project:
        fail('HARBOR_REGISTRY/HARBOR_PROJECT không hợp lệ')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag):
        fail(f'OCI tag không hợp lệ: {tag}')
    return f'{host}/{project}/{row["repository"]}:{tag}'


def run(cmd, capture=False):
    display = []
    redact_next = False
    for item in cmd:
        if redact_next:
            # Proxy values travel as "env.<VAR>=<value>" driver opts and may
            # contain credentials. network=<mode> is safe and needed for debug.
            key = item.split('=', 1)[0].strip('"') if '=' in item else item
            if key.startswith('env.'):
                display.append(key + '=[REDACTED]')
            else:
                display.append(item)
            redact_next = False
        else:
            display.append(item)
            redact_next = item == '--driver-opt'
    print('+', ' '.join(shlex.quote(p) for p in display), flush=True)
    if capture:
        return subprocess.check_output(cmd, text=True).strip()
    subprocess.run(cmd, check=True)
    return ''


def base_changes():
    """Return file paths; None means no reliable diff base for the first commit."""
    base = env('CI_MERGE_REQUEST_DIFF_BASE_SHA') or env('CI_COMMIT_BEFORE_SHA')
    if not base or set(base) == {'0'}:
        # First push to a new branch with a parent commit still has an exact local diff.
        try:
            subprocess.run(['git', 'rev-parse', 'HEAD^'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True)
            base = 'HEAD^'
        except subprocess.CalledProcessError:
            return None, None
    try:
        files = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', '-z', '--diff-filter=ACMRD', base, 'HEAD'], text=True, stderr=subprocess.PIPE).split('\0')
        return base, [p for p in files if p]
    except subprocess.CalledProcessError:
        fail(f'Không đọc được git diff từ {base}: cần GIT_DEPTH=0; không tự chọn tất cả')


def changed_images(rows):
    base, files = base_changes()
    if files is None:
        print('Commit đầu tiên/không có diff base: KHÔNG tự chạy FULL; dùng manual IMAGE_SELECTION')
        return [], 'initial-commit'
    changed = set(files)
    # Danh mục có thể sửa version/enable của đúng một image.
    if 'images.json' in changed:
        try:
            before = json.loads(subprocess.check_output(['git', 'show', f'{base}:images.json'], text=True))
            old = {r['id']: r for r in before.get('images', [])}
        except (subprocess.CalledProcessError, ValueError, KeyError):
            old = {}
        for row in rows:
            if old.get(row['id']) != row:
                changed.add(f'images/{row["id"]}/.inventory-changed')
    selected = []
    for row in rows:
        if not row['enabled']:
            continue
        folder = f'images/{row["id"]}/'
        build = build_config(row)
        context_prefix = build['context'].rstrip('/') + '/' if build['context'] != '.' else None
        context_changed = context_prefix and any(p.startswith(context_prefix) for p in changed)
        dockerfile_path = (build['dockerfile'] if build['context'] == '.' else
                           build['context'].rstrip('/') + '/' + build['dockerfile'])
        if (any(p.startswith(folder) or p.startswith(f'vex/{row["id"]}/') for p in changed)
                or context_changed or dockerfile_path in changed
                or any(dep in changed for dep in row['depends_on'])):
            selected.append(row['id'])
    shared = {p for p in changed if p.startswith('shared/')}
    handled = {p for row in rows if row['enabled'] for p in row['depends_on']}
    if shared - handled:
        fail(f'Shared files thay đổi nhưng không có enabled image phụ thuộc: {sorted(shared - handled)}')
    if '.dockerignore' in changed:
        selected = [row['id'] for row in rows if row['enabled']]
    return selected, 'git-diff'


def pipeline_mode():
    prefix = 'PARENT_' if env('CI_PIPELINE_SOURCE') == 'parent_pipeline' else 'CI_'
    branch, tag, src = (env(prefix + key) for key in ('COMMIT_BRANCH', 'COMMIT_TAG', 'PIPELINE_SOURCE'))
    protected = env(prefix + ('REF_PROTECTED' if prefix == 'PARENT_' else 'COMMIT_REF_PROTECTED')) == 'true'
    if src == 'merge_request_event':
        mode = 'fast'
    elif tag and src == 'push' and protected and RELEASE_TAG.fullmatch(tag):
        mode = 'release'
    elif not tag and src in ('push', 'web') and protected and (branch == 'main' or RELEASE_BRANCH.fullmatch(branch)):
        mode = 'full'
    elif not tag and src in ('push', 'web') and DEV_BRANCH.fullmatch(branch):
        mode = 'fast'
    else:
        fail('Pipeline source/ref không được hỗ trợ hoặc chưa được bảo vệ')
    if env('PIPELINE_KIND') not in ('', mode):
        fail('PIPELINE_KIND không khớp source/ref')
    return mode


def plan():
    mode = pipeline_mode()
    rows = catalog(strict_locks=mode != 'fast')
    index = {x['id']: x for x in rows}
    branch, tag, src = env('CI_COMMIT_BRANCH'), env('CI_COMMIT_TAG'), env('CI_PIPELINE_SOURCE')
    protected = env('CI_COMMIT_REF_PROTECTED') == 'true'
    ref_kind = ''
    if mode != 'fast' and not protected:
        fail('FULL/RELEASE yêu cầu protected Git ref')
    release = RELEASE_TAG.fullmatch(tag) if tag else None
    release_branch = RELEASE_BRANCH.fullmatch(branch) if branch else None
    if mode == 'release':
        if src != 'push' or not release:
            fail('Chỉ Git tag <image>/vX.Y.Z mới được phát hành')
        selected = [release.group(1)]
        ref_kind = 'release'
        requested_version = release.group(2)
    elif mode == 'full':
        if branch == 'main' and src in ('push', 'web'):
            ref_kind = 'main'
        elif release_branch and src in ('push', 'web'):
            ref_kind = 'rc'
        else:
            fail('FULL chỉ hỗ trợ main hoặc release/<image>/vX.Y.Z')
        if release_branch:
            selected = [release_branch.group(1)]
            requested_version = release_branch.group(2)
        else:
            selected = []
            requested_version = None
    else:
        if not (src == 'merge_request_event' or (DEV_BRANCH.fullmatch(branch) and src in ('push', 'web'))):
            fail('FAST chỉ áp dụng branch phát triển hoặc Merge Request')
        ref_kind = 'fast'
        selected = []
        requested_version = None
    override = env('IMAGE_SELECTION', 'auto')
    if override != 'auto':
        if src != 'web' or tag or release_branch:
            fail('IMAGE_SELECTION chỉ được override qua Run pipeline trên branch FAST hoặc dùng all trên main')
        if ref_kind == 'main' and override != 'all':
            fail('Protected main phải chạy toàn bộ image enabled; dùng IMAGE_SELECTION=auto hoặc all')
        if override == 'all':
            selected = [r['id'] for r in rows if r['enabled']]
        else:
            selected = [x.strip() for x in override.split(',')]
            if not selected or any(not ID.fullmatch(x) for x in selected) or len(set(selected)) != len(selected):
                fail('IMAGE_SELECTION phải là auto, all hoặc ID phân cách dấu phẩy không trùng')
        reason = 'manual-selection'
    elif mode == 'release' or release_branch:
        reason = 'image-specific-release-ref'
    elif mode == 'full':
        selected = [r['id'] for r in rows if r['enabled']]
        reason = 'all-enabled-main'
    else:
        selected, reason = changed_images(rows)
    if len(selected) != len(set(selected)):
        fail('Danh sách image bị trùng')
    root_pipeline = require('CI_PIPELINE_ID')
    if not root_pipeline.isdigit():
        fail('CI_PIPELINE_ID phải là số')
    short_sha = require('CI_COMMIT_SHA')[:12]
    if not re.fullmatch(r'[a-f0-9]{12}', short_sha):
        fail('CI_COMMIT_SHA không hợp lệ')
    details = []
    for name in selected:
        if name not in index or not index[name]['enabled']:
            fail(f'Không thể chọn image bị vô hiệu hóa/không tồn tại: {name}')
        row = index[name]
        if requested_version is not None and requested_version != row['version']:
            fail(f'{name}: ref yêu cầu v{requested_version} nhưng images.json ghi {row["version"]}')
        # Build to a unique candidate tag so concurrent pipelines cannot overwrite
        # the digest being scanned/signed. Promotion creates the stable policy tag.
        candidate = f'ci-p{root_pipeline}-{short_sha}'
        final = (f"{row['version']}-dev" if ref_kind == 'main' else
                 f"{row['version']}-rc" if ref_kind == 'rc' else
                 row['version'] if ref_kind == 'release' else '')
        # Ensure source-controlled release repo cannot silently change the target name.
        ref(row, candidate)
        if final:
            ref(row, final)
        details.append({'id': name, 'repository': row['repository'], 'version': row['version'],
                        'candidate_tag': candidate, 'final_tag': final})
    return {'mode': mode, 'ref_kind': ref_kind, 'source': src, 'ref': tag or branch,
            'commit': require('CI_COMMIT_SHA'), 'pipeline_id': root_pipeline,
            'reason': reason, 'images': details}
