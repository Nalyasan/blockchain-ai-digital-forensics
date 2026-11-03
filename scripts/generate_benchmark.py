"""Run existing R1-R4 synthetic regression fixtures; never report as real accuracy."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--out',
        type=str,
        default=None,
        help='Output directory (defaults to temporary directory synthetic-<uuid>)',
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if args.out:
        out = Path(args.out).resolve()
    else:
        out = Path(tempfile.gettempdir()) / ('synthetic-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, '-m', 'pytest', 'tests/test_rules.py', '-q',
        '--junitxml=' + str(out / 'junit.xml'),
        '--basetemp=' + str(out / 'temp'),
    ]
    run = subprocess.run(
        cmd, cwd=root, text=True, encoding='utf-8', errors='replace', capture_output=True
    )
    (out / 'test.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    (out / 'summary.json').write_text(
        json.dumps({
            'synthetic': True,
            'kind': 'existing rule regression fixtures',
            'exit_code': run.returncode,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'real_world_precision': None,
            'real_world_recall': None,
        }, indent=2),
        encoding='utf-8',
    )
    print(run.stdout)
    print(out)
    return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
