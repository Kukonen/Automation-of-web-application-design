"""Project lint and tests, executable with only the Python standard library."""
from pathlib import Path
import ast
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def lint():
    problems = []
    for path in ROOT.rglob('*.py'):
        if any(part in {'.venv', 'tmp', 'data', '__pycache__'} for part in path.relative_to(ROOT).parts):
            continue
        source = path.read_text(encoding='utf-8-sig')
        for number, line in enumerate(source.splitlines(), 1):
            if line.rstrip() != line:
                problems.append(f'{path.relative_to(ROOT)}:{number}: trailing whitespace')
            if '\t' in line[:len(line) - len(line.lstrip())]:
                problems.append(f'{path.relative_to(ROOT)}:{number}: tab indentation')
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            problems.append(str(error))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                problems.append(f'{path.name}:{node.lineno}: bare except')
            if isinstance(node, ast.ImportFrom) and any(v.name == '*' for v in node.names):
                problems.append(f'{path.name}:{node.lineno}: wildcard import')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec'}:
                problems.append(f'{path.name}:{node.lineno}: dynamic code execution')
            if isinstance(node, ast.Call) and any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                                                   and k.value.value is True for k in node.keywords):
                problems.append(f'{path.name}:{node.lineno}: shell execution')
    for problem in problems:
        print(problem)
    print(f'Project lint: {len(problems)} issue(s)')
    return not problems


if __name__ == '__main__':
    if not lint():
        sys.exit(1)
    sys.exit(subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                            cwd=ROOT, check=False).returncode)
