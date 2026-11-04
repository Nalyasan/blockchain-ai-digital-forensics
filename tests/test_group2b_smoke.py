import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def test_B08_C03_C10_C12_real_group2b_smoke(tmp_path):
    root=Path(__file__).resolve().parents[1]
    evidence_dir=os.environ.get('P3_2B_EVIDENCE_DIR')
    parent=Path(evidence_dir) if evidence_dir else (tmp_path/'2b_evidence')
    parent.mkdir(parents=True, exist_ok=True)
    output=parent/('anvil-2b-'+uuid.uuid4().hex)
    cmd=[sys.executable,str(root/'scripts/run_evidence_export_smoke.py'),'--output-dir',str(output)]
    roots_env=os.environ.get('P3_PROTECTED_ROOTS','["forensics", "contracts"]')
    for path in json.loads(roots_env):cmd+=['--protected-root',path]
    result=subprocess.run(cmd,capture_output=True,encoding='utf-8',errors='replace',timeout=240)
    # Script stdout contains only the allowlisted report, never tool diagnostics.
    smoke_json=parent/'group2b-smoke.json'
    exit_json=parent/'group2b-exit.json'
    if smoke_json.exists(): smoke_json.unlink()
    if exit_json.exists(): exit_json.unlink()
    smoke_json.write_text(result.stdout,encoding='utf-8')
    exit_json.write_text(json.dumps({'exit_code':result.returncode}),encoding='utf-8')
    assert result.returncode==0,f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    data=json.loads(result.stdout)
    assert data['status']=='PASS' and len(data['checks'])==9
    assert all(c['status']=='PASS' for c in data['checks'])
    assert data['chain_id']==31337 and data['public_rpc_used'] is False
