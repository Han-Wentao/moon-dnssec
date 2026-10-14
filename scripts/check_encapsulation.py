"""Negative external-package checks for unforgeable authentication objects."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
probe = root / 'contract_guard'
if probe.exists():
    raise SystemExit('Refusing to replace an existing contract probe directory')
probe.mkdir()
try:
    (probe / 'moon.pkg').write_text('import { "Han-Wentao/moon-dnssec" @dns }\n', encoding='utf-8')
    cases = [
        ('pub fn attack(x : @dns.AuthenticatedSet) -> Unit { x.records.clear() }', 'has no field records'),
        ('pub fn attack(x : @dns.TrustedKeys) -> Unit { x.keys.clear() }', 'has no field keys'),
        ('pub fn attack(x : @dns.Name) -> Unit { x.labels.clear() }', 'has no field labels'),
        ('pub fn attack(zone : @dns.Name) -> @dns.AuthenticatedSet { { records: [], zone, verified_at: 0U, lifetime: 100U, wildcard: false } }', 'Cannot create values'),
    ]
    for source, diagnostic in cases:
        (probe / 'attack.mbt').write_text(source + '\n', encoding='utf-8')
        checked = subprocess.run(['moon', 'check', '--deny-warn'], cwd=root, capture_output=True)
        output = (checked.stdout + checked.stderr).decode('utf-8', errors='replace')
        if checked.returncode == 0 or diagnostic not in output:
            raise SystemExit('Encapsulation negative check did not fail as expected')
    print('PASS: four external construction/mutation attacks are rejected')
finally:
    # Delete only the two files created by this probe; never recursively delete.
    (probe / 'attack.mbt').unlink(missing_ok=True)
    (probe / 'moon.pkg').unlink(missing_ok=True)
    probe.rmdir()
