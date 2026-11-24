#!/usr/bin/env python3
"""Job-scoped Docker credentials; no secret values are logged or artifacted."""
import argparse
import base64
import json
import os
import shutil
from catalog import docker_config_path, env, fail, job_builder_name, require, run


def auth_path():
    return docker_config_path()


def cleanup_builder(path):
    marker = path / 'buildx-builder'
    if not marker.exists():
        return
    name = marker.read_text(encoding='utf-8').strip()
    if name != job_builder_name():
        fail('Buildx builder marker không thuộc job hiện tại')
    builders = run(['docker', 'buildx', 'ls', '--format', '{{.Name}}'], capture=True).splitlines()
    if name in builders:
        run(['docker', 'buildx', 'rm', '--force', name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['docker-auth', 'cleanup-auth'])
    args = parser.parse_args()
    path = auth_path()
    if args.command == 'cleanup-auth':
        try:
            cleanup_builder(path)
        except (Exception, SystemExit):
            # Remove credentials even if the daemon cannot remove its builder.
            (path / 'config.json').unlink(missing_ok=True)
            raise
        (path / 'config.json').unlink(missing_ok=True)
        if path.exists():
            shutil.rmtree(path)
        return
    registry = require('HARBOR_REGISTRY')
    # Never put push credentials into FAST/bootstrap Docker config.
    if env('WORKSPACE_REF_KIND') in ('fast', 'bootstrap'):
        user, password = env('HARBOR_PULL_USER'), env('HARBOR_PULL_PASSWORD')
        config = {'auths': {}}
        if user and password:
            config['auths'][registry] = {'auth': base64.b64encode(f'{user}:{password}'.encode()).decode()}
    else:
        if env('CI_COMMIT_REF_PROTECTED') != 'true':
            fail('Publish credentials require protected ref')
        raw = env('DOCKER_AUTH_CONFIG')
        if raw:
            try:
                config = json.loads(raw)
            except ValueError:
                fail('DOCKER_AUTH_CONFIG phải là JSON, không phải base64 toàn document')
            if not isinstance(config, dict) or not isinstance(config.get('auths'), dict):
                fail('DOCKER_AUTH_CONFIG thiếu object auths')
        else:
            auth = base64.b64encode((require('HARBOR_USER') + ':' + require('HARBOR_PASSWORD')).encode()).decode()
            config = {'auths': {registry: {'auth': auth}}}
    path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path / 'config.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(config, output)
    print('Job-scoped Docker auth configured (values hidden).')


if __name__ == '__main__':
    main()
