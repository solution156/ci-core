#!/usr/bin/env python3
"""Verify a released digest against independently provisioned deployment policy."""
import argparse
import base64
import binascii
import json
import pathlib
import re
import subprocess

PREDICATE = 'https://slsa.dev/provenance/v1'


def matches(statement, args, digest):
    definition = statement['predicate']['buildDefinition']
    source = definition['externalParameters']['source']
    internal = definition['internalParameters']
    gate = internal['vulnerabilityGate']
    return (statement['predicateType'] == PREDICATE
            and any(s['digest'].get('sha256') == digest for s in statement['subject'])
            and source == {'uri': args.source, 'commit': args.commit}
            and statement['predicate']['runDetails']['builder']['id'].startswith(args.source + '/-/pipelines/')
            and internal['engineCommit'] == args.engine_commit
            and gate['result'] == 'pass' and gate['findings'] == [] and gate['reference'] == args.reference
            and re.fullmatch(r'[a-f0-9]{64}', gate['report_sha256']) is not None)


def verify(args):
    if not re.fullmatch(re.escape(args.repository) + r'@sha256:[a-f0-9]{64}', args.reference):
        raise ValueError('image must match the allowed repository and use a SHA-256 digest')
    if any(not re.fullmatch(r'[a-f0-9]{40}', value) for value in (args.commit, args.engine_commit)):
        raise ValueError('expected source and engine commits must be full SHAs')
    flags = ['--key', str(args.key)]
    if args.allow_no_transparency_log:
        flags.append('--insecure-ignore-tlog')
    subprocess.run(['cosign', 'verify', *flags, args.reference], check=True, stdout=subprocess.DEVNULL)
    output = subprocess.check_output(['cosign', 'verify-attestation', *flags, '--type', 'slsaprovenance1', args.reference])
    for line in output.splitlines():
        try:
            payload = json.loads(line)['payload']
            statement = json.loads(base64.b64decode(payload, validate=True))
            if matches(statement, args, args.reference.rsplit(':', 1)[1]):
                return
        except (ValueError, TypeError, KeyError, AttributeError, binascii.Error):
            continue
    raise ValueError('no verified provenance matches the deployment policy')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('reference')
    for option in ('repository', 'source', 'commit', 'engine-commit'):
        p.add_argument('--' + option, required=True)
    p.add_argument('--key', required=True, type=pathlib.Path)
    p.add_argument('--allow-no-transparency-log', action='store_true')
    args = p.parse_args()
    try:
        verify(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        p.exit(1, f'Image verification failed: {exc}\n')
    print(args.reference)


if __name__ == '__main__':
    main()
