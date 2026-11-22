"""Repeatable commands with machine-readable evidence for the coursework."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def audit():
    from core import CMS
    with tempfile.TemporaryDirectory() as folder:
        cms = CMS(ROOT, db_path=Path(folder) / 'fresh.sqlite3')
        try:
            cms.migrate()
            schemas = {}
            for path in sorted((ROOT / 'schemas').glob('*.json')):
                schema = json.loads(path.read_text(encoding='utf-8'))
                assert schema['label'] and isinstance(schema['fields'], dict)
                assert all(v.get('type') in {'text', 'integer', 'url', 'date'} for v in schema['fields'].values())
                schemas[path.stem] = list(schema['fields'])
            return {'schemas': schemas, 'fresh_migration': 'passed', 'types': len(schemas)}
        finally:
            cms.close()


def release_check():
    result = subprocess.run([sys.executable, str(ROOT / 'tools' / 'check.py')], cwd=ROOT,
                            capture_output=True, text=True, encoding='utf-8', errors='replace', check=False)
    output = result.stdout + result.stderr
    if result.returncode:
        raise RuntimeError(output)
    required = ['CHANGELOG.md', 'README.md', 'VERSION', 'AGENTS.md']
    for filename in required:
        if not (ROOT / filename).is_file():
            raise RuntimeError('Missing release file: ' + filename)
    return {'version': (ROOT / 'VERSION').read_text().strip(), 'content': audit(),
            'checks': output, 'required_files': required}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['content-audit', 'release-check'])
    args = parser.parse_args()
    started = time.perf_counter()
    timestamp = datetime.now(timezone.utc).isoformat()
    status = 'passed'
    try:
        detail = audit() if args.command == 'content-audit' else release_check()
    except (AssertionError, KeyError, OSError, RuntimeError, ValueError) as error:
        status, detail = 'failed', {'error': str(error)}
    record = {'timestamp_utc': timestamp, 'command': args.command, 'status': status,
              'elapsed_seconds': round(time.perf_counter() - started, 3), 'detail': detail}
    destination = ROOT / 'evidence' / 'commands'
    destination.mkdir(parents=True, exist_ok=True)
    filename = str(time.time_ns()) + '-' + args.command + '.json'
    (destination / filename).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    print(args.command, status, 'evidence/commands/' + filename)
    if status == 'failed':
        print(detail['error'])
    return 0 if status == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
