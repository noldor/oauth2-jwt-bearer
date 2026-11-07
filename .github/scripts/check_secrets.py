"""Scan publishable current/index bytes and an optional complete local Git ref.

The reviewed Betterleaks binary is supplied by explicit setup. The scanner runs
without network access in the already-built package Docker image.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BINARY_SHA256 = 'd9deb306c80b489512bbca87c39bf4b5f529ce1ab43cd8e0aa444c603085db7e'
CONFIG = ROOT / '.github/betterleaks.toml'


def git(*arguments):
    result = subprocess.run(
        ['git', '--literal-pathspecs', '--no-replace-objects', '--no-lazy-fetch',
         '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', *arguments],
        cwd=ROOT, capture_output=True, timeout=30,
        env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent',
             'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
             'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'},
    )
    if result.returncode:
        raise RuntimeError('Git scope verification failed.')
    return result.stdout


def put(snapshot, image, name, data):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or '.git' in relative.parts or relative.name in ('.betterleaksignore', '.gitleaksignore'):
        raise RuntimeError('Unsupported source path.')
    if len(data) > 2 * 1024 * 1024 or b'\0' in data:
        raise RuntimeError('Unsupported binary or oversized source.')
    data.decode('utf-8')
    path = snapshot / image / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def snapshot_current(destination):
    count = 0
    for row in git('ls-files', '--stage', '-z').split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, object_id, stage = metadata.decode().split()
        if mode not in ('100644', '100755') or stage != '0':
            raise RuntimeError('Unsupported index entry.')
        put(destination, 'index', os.fsdecode(name), git('cat-file', 'blob', object_id))
        count += 1
    names = git('ls-files', '--cached', '--others', '--exclude-standard', '-z')
    for name in set(filter(None, names.split(b'\0'))):
        relative = Path(os.fsdecode(name))
        path = ROOT / relative
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != ROOT.parent):
            raise RuntimeError('Symbolic links are outside the scan profile.')
        if not path.exists():
            continue  # A staged version, if any, was scanned above.
        if not path.is_file():
            raise RuntimeError('Unsupported source entry.')
        put(destination, 'worktree', str(relative), path.read_bytes())
        count += 1
    if not count:
        raise RuntimeError('Empty secret-scan scope.')
    return count


def scan(binary, image, source, output, mode='dir', ref=None):
    output.mkdir(mode=0o700)
    command = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
               '--cpus=1', '--memory=256m', '--pids-limit=64',
               '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,size=32m',
               '-e', 'HOME=/tmp', '-e', 'GIT_CONFIG_NOSYSTEM=1',
               '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_NO_REPLACE_OBJECTS=1',
               '-e', 'GIT_NO_LAZY_FETCH=1',
               '-v', f'{binary}:/scanner:ro', '-v', f'{CONFIG}:/configuration.toml:ro',
               '-v', f'{source}:/source:ro', '-v', f'{output}:/output',
               '-w', '/source', '--entrypoint', '/scanner', image, mode, '/source',
               '--config=/configuration.toml', '--redact=100', '--validation=false',
               '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--exit-code=2',
               '--report-format=json', '--report-path=/output/report.json', '--timeout=90']
    if ref:
        command += [f'--log-opts={ref} --full-history --diff-filter=AMCRT --no-renames --diff-merges=first-parent']
    result = subprocess.run(command, capture_output=True, timeout=100)
    (output / 'scanner.stdout').write_bytes(result.stdout)
    (output / 'scanner.stderr').write_bytes(result.stderr)
    report_path = output / 'report.json'
    if not report_path.exists():
        raise RuntimeError('Secret scanner did not produce a report; see private artifacts.')
    report = json.loads(report_path.read_text())
    if not isinstance(report, list) or result.returncode not in (0, 2):
        raise RuntimeError('Secret scanner did not complete; see private artifacts.')
    diagnostics = result.stderr.decode(errors='replace')
    warnings = [line for line in diagnostics.splitlines() if re.search(r'\b(WRN|ERR|FTL)\b', line)]
    if any(not re.search(r'\bWRN leaks found: \d+\s*$', line) for line in warnings):
        raise RuntimeError('Secret scan reported incomplete coverage; see private artifacts.')
    if bool(report) != (result.returncode == 2):
        raise RuntimeError('Secret scanner status/report mismatch.')
    return [{'rule': item['RuleID'], 'path': item['File'], 'line': item['StartLine'],
             'commit': item.get('Commit', '')} for item in report]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image', default='noldors-oauth2-jwt-bearer:dev')
    parser.add_argument('--history-ref')
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != BINARY_SHA256:
        raise RuntimeError('Betterleaks 1.10.0 binary checksum mismatch.')
    for name in ('.betterleaksignore', '.gitleaksignore'):
        if (ROOT / name).exists():
            raise RuntimeError('Unreviewed suppression input.')
    with tempfile.TemporaryDirectory(prefix='jwt-bearer-secrets-source-') as temporary:
        source = Path(temporary)
        output = Path(tempfile.mkdtemp(prefix='jwt-bearer-secrets-report-'))
        source.chmod(0o700)
        count = snapshot_current(source)
        findings = scan(binary, options.image, source, output / 'current')
        if options.history_ref:
            if git('rev-parse', '--is-shallow-repository').strip() != b'false':
                raise RuntimeError('Complete history is required.')
            if options.history_ref.startswith('-'):
                raise RuntimeError('Invalid history ref.')
            ref = git('rev-parse', '--verify', options.history_ref + '^{commit}').decode().strip()
            if not re.fullmatch('[a-f0-9]{40,64}', ref):
                raise RuntimeError('Invalid resolved history ref.')
            findings += scan(binary, options.image, ROOT, output / 'history', mode='git', ref=ref)
        print(json.dumps({'outcome': 'findings' if findings else 'clean',
                          'tool': 'Betterleaks 1.10.0', 'currentImages': count,
                          'history': options.history_ref, 'findings': findings,
                          'privateArtifacts': str(output)}))
        return 1 if findings else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'outcome': 'incomplete', 'reason': str(error)}))
        raise SystemExit(2)
