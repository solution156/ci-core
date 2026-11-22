#!/usr/bin/env python3
"""Job-scoped Docker credentials; no secret values are logged or artifacted."""
import argparse
import base64
import json
import os
from pathlib import Path
from catalog import env, fail, require


def auth_path():
    root = Path(require('CI_PROJECT_DIR')).resolve()
    path = Path(env('DOCKER_CONFIG', str(root / '.docker-job'))).resolve()
    if path != root / '.docker-job':
        fail('DOCKER_CONFIG phải là CI_PROJECT_DIR/.docker-job')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['docker-auth', 'cleanup-auth'])
    args = parser.parse_args()
    path = auth_path()
    if args.command == 'cleanup-auth':
        (path / 'config.json').unlink(missing_ok=True)
        if path.exists():
            path.rmdir()
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
