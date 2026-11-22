"""Small fail-closed project tool boundary. This is not an OS sandbox."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((Path(__file__).with_name('permissions.json')).read_text(encoding='utf-8'))


def read_project(relative):
    """Read a public project file without following a path out of the root."""
    requested = Path(relative)
    target = (ROOT / requested).resolve()
    if requested.is_absolute() or not target.is_relative_to(ROOT):
        raise PermissionError('outside-project')
    parts = requested.parts + target.relative_to(ROOT).parts
    if any(part.casefold() == '.env' or part.casefold().startswith('.env.') for part in parts):
        raise PermissionError('read-secrets')
    return target.read_text(encoding='utf-8')


def execute(action):
    """No shell strings, arbitrary argv or execution outside the allowlist."""
    if action not in POLICY['execute']:
        raise PermissionError('Action is not allowlisted')
    return subprocess.run([sys.executable, str(ROOT / 'harness' / 'commands.py'), action],
                          cwd=ROOT, check=False).returncode


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise PermissionError('Usage: guard.py read PATH | run ACTION')
        if sys.argv[1] == 'read':
            print(read_project(sys.argv[2]))
        elif sys.argv[1] == 'run':
            sys.exit(execute(sys.argv[2]))
        else:
            raise PermissionError('Unknown operation')
    except (PermissionError, OSError) as error:
        print('DENIED:', error, file=sys.stderr)
        sys.exit(2)
