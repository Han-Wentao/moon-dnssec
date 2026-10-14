"""Reproduce conservative production line and commit evidence without secrets."""
from pathlib import Path
import json
import subprocess

root = Path(__file__).resolve().parents[1]
files = sorted(p for p in root.glob('*.mbt') if not p.name.endswith(('_test.mbt', '_wbtest.mbt')))
rows = []
for path in files:
    lines = path.read_text(encoding='utf-8').splitlines()
    substantive = sum(bool(line.strip()) and not line.lstrip().startswith('//') for line in lines)
    rows.append({'file': path.name, 'physical_lines': len(lines), 'nonblank_noncomment_lines': substantive})
commits = subprocess.check_output(['git', 'log', '--reverse', '--format=%H|%s'], cwd=root).decode('utf-8').splitlines()
print(json.dumps({'production_files': rows, 'physical_lines': sum(r['physical_lines'] for r in rows), 'nonblank_noncomment_lines': sum(r['nonblank_noncomment_lines'] for r in rows), 'commits': commits}, indent=2))
