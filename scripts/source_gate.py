#!/usr/bin/env python3
"""Evaluate unfiltered Trivy source findings without exporting secret values."""
import pathlib
import subprocess
import tempfile

from catalog import build_config, catalog, document, fail, pipeline_mode, source_scan_exceptions, write
from scanner_env import scanner_env


def evaluate(report, exceptions, expected):
    if (not isinstance(report, dict) or report.get('SchemaVersion') != 2
            or report.get('ArtifactType') != 'filesystem' or report.get('ArtifactName') != '.'
            or not isinstance(report.get('Results'), list)):
        raise ValueError('invalid Trivy source report')
    approved = {(item['rule_id'], target): item for item in exceptions for target in item['targets']}
    covered, blocked, applied = set(), [], []
    for result in report['Results']:
        if not isinstance(result, dict) or not isinstance(result.get('Target'), str) or not result['Target']:
            raise ValueError('invalid Trivy source target')
        target = pathlib.PurePosixPath(result['Target']).as_posix()
        if result.get('Class') == 'config' and result.get('Type') == 'dockerfile':
            covered.add(target)
        for key, field in (('Misconfigurations', 'ID'), ('Secrets', 'RuleID')):
            findings = result.get(key, [])
            if not isinstance(findings, list):
                raise ValueError('invalid Trivy source findings')
            for finding in findings:
                if (not isinstance(finding, dict) or not isinstance(finding.get(field), str)
                        or not finding[field] or finding.get('Severity') not in {'HIGH', 'CRITICAL'}
                        or (key == 'Misconfigurations' and finding.get('Status') != 'FAIL')):
                    raise ValueError('invalid Trivy source finding')
                entry = {'kind': key, 'target': target, 'rule_id': finding[field], 'severity': finding['Severity']}
                waiver = approved.get((finding[field], target)) if key == 'Misconfigurations' else None
                if waiver:
                    applied.append({**entry, 'justification': waiver['justification'], 'review_by': waiver['review_by']})
                else:
                    blocked.append(entry)
    if missing := expected - covered:
        raise ValueError('missing Dockerfile coverage: ' + ', '.join(sorted(missing)))
    return {'result': 'fail' if blocked else 'pass', 'blocking': blocked, 'exceptions_applied': applied,
            'dockerfiles_checked': sorted(covered)}


def main():
    output = 'reports/source-policy.json'
    try:
        rows = catalog(strict_locks=pipeline_mode() != 'fast')
        expected = {(pathlib.PurePosixPath(cfg['context']) / cfg['dockerfile']).as_posix()
                    for row in rows if row['enabled'] for cfg in [build_config(row)]}
        exceptions = source_scan_exceptions(rows)
        with tempfile.TemporaryDirectory(prefix='trivy-source-') as temp:
            raw = pathlib.Path(temp) / 'report.json'
            secret_config = raw.with_name('secret.yaml')
            secret_config.write_text('{}\n', encoding='utf-8')
            subprocess.run(['trivy', '--config', '/dev/null', 'fs', '--scanners', 'secret,misconfig',
                            '--ignore-policy=', '--secret-config', str(secret_config),
                            '--severity', 'HIGH,CRITICAL', '--ignorefile', '/dev/null', '--exit-code', '0',
                            '--format', 'json', '--output', str(raw), '--skip-dirs', '.ci-tools', '.'],
                           check=True, env=scanner_env())
            decision = evaluate(document(raw), exceptions, expected)
    except (OSError, ValueError, subprocess.CalledProcessError):
        write(output, {'result': 'error', 'reason': 'scan, report schema or Dockerfile coverage validation failed'})
        return fail('Source scan/report validation failed; verify scanner and Dockerfile coverage')
    write(output, decision)
    if decision['blocking']:
        fail('Source security findings blocked the pipeline; inspect reports/source-policy.json')


if __name__ == '__main__':
    main()
