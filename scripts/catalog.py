#!/usr/bin/env python3
"""Danh mục image, kiểm tra source và xác định chính xác image cần build.

Chỉ dùng thư viện chuẩn Python. images.json thuộc sở hữu repo Workspace Images.
"""
from __future__ import annotations
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
        if row.get('context') != '.' or row.get('dockerfile') != f'images/{name}/Dockerfile':
            fail(f'{name}: context phải là . và Dockerfile images/{name}/Dockerfile')
        if row.get('platform') != 'linux/amd64':
            fail(f'{name}: chỉ hỗ trợ linux/amd64 đã được cấu hình trong source gốc')
        dockerfile = ROOT / row['dockerfile']
        if not dockerfile.is_file() or not dockerfile.resolve().is_relative_to(root):
            fail(f'{name}: Dockerfile không tồn tại hoặc vượt thư mục repo')
        lines = re.sub(r'\\\s*\n\s*', ' ', dockerfile.read_text(encoding='utf-8')).splitlines()
        users = [x.strip() for x in lines if x.startswith('USER ')]
        if not any(x.startswith('FROM ') for x in lines) or not users or users[-1] != 'USER 1000':
            fail(f'{name}: Dockerfile thiếu FROM hoặc USER 1000 cuối')
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
                p = ROOT / item
                if pathlib.PurePosixPath(item).is_absolute() or '..' in pathlib.PurePosixPath(item).parts or not p.exists() or not p.resolve().is_relative_to(root):
                    fail(f'{name}: nguồn COPY không an toàn/không tồn tại: {item}')
        deps = row.get('depends_on')
        if not isinstance(deps, list) or any(not isinstance(d, str) or not d.startswith('shared/') or '..' in pathlib.PurePosixPath(d).parts or not (ROOT / d).is_file() for d in deps):
            fail(f'{name}: depends_on phải tham chiếu tài nguyên shared/ hợp lệ')
        if len(deps) != len(set(deps)):
            fail(f'{name}: depends_on bị trùng')
        shared_copy = set()
        for line in lines:
            if not line.startswith('COPY '):
                continue
            args = shlex.split(line)[1:]
            if any(x.startswith('--from=') for x in args):
                continue
            shared_copy.update(x for x in [p for p in args if not p.startswith('--')][:-1]
                               if x.startswith('shared/'))
        if not shared_copy <= set(deps):
            fail(f'{name}: Dockerfile COPY shared chưa có depends_on: {sorted(shared_copy - set(deps))}')
        lock_config(row, strict=strict_locks)
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
            key = item.split('=', 1)[0].strip('"') if '=' in item else item
            display.append(key + '=[REDACTED]')
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
        if (any(p.startswith(folder) or p.startswith(f'vex/{row["id"]}/') for p in changed)
                or any(dep in changed for dep in row['depends_on'])):
            selected.append(row['id'])
    shared = {p for p in changed if p.startswith('shared/')}
    handled = {p for row in rows if row['enabled'] for p in row['depends_on']}
    if shared - handled:
        fail(f'Shared files thay đổi nhưng không có enabled image phụ thuộc: {sorted(shared - handled)}')
    if '.dockerignore' in changed:
        selected = [row['id'] for row in rows if row['enabled']]
    return selected, 'git-diff'


def plan():
    mode = require('PIPELINE_KIND')
    if mode not in ('fast', 'full', 'release'):
        fail(f'PIPELINE_KIND không hợp lệ: {mode}')
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
            fail('IMAGE_SELECTION chỉ được override qua Run pipeline trên main hoặc branch FAST')
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
