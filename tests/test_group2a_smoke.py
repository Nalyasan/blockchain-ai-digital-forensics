"""Real local Anvil integration. A missing tool or failed smoke is a test failure."""
import json
import os
from pathlib import Path
import subprocess
import sys


def test_real_anvil_collector_export_integrity():
    script = Path(__file__).resolve().parents[1]/'scripts/run_p3_group2a_smoke.py'
    result = subprocess.run([sys.executable, str(script)], capture_output=True,
                            encoding='utf-8', errors='replace', timeout=240)
    if os.environ.get('P3_2A_EVIDENCE_DIR'):
        Path(os.environ['P3_2A_EVIDENCE_DIR'], 'group2a-smoke.json').write_text(result.stdout, encoding='utf-8')
    assert result.returncode == 0, result.stdout
    data = json.loads(result.stdout)
    assert data['status'] == 'PASS'
    assert len(data['checks']) == 7 and all(c['status'] == 'PASS' for c in data['checks'])
    assert data['chain_id'] == 31337 and data['public_rpc_used'] is False
