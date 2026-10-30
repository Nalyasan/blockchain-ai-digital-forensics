import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def test_B08_C03_C10_C12_real_group2b_smoke():
    root=Path(__file__).resolve().parents[1]
    parent=Path(os.environ['P3_2B_EVIDENCE_DIR'])
    output=parent/('anvil-2b-'+uuid.uuid4().hex)
    cmd=[sys.executable,str(root/'scripts/run_p3_group2b_smoke.py'),'--output-dir',str(output)]
    for path in json.loads(os.environ['P3_PROTECTED_ROOTS']):cmd+=['--protected-root',path]
    result=subprocess.run(cmd,capture_output=True,encoding='utf-8',errors='replace',timeout=240)
    # Script stdout contains only the allowlisted report, never tool diagnostics.
    with (parent/'group2b-smoke.json').open('x',encoding='utf-8') as f:f.write(result.stdout)
    with (parent/'group2b-exit.json').open('x',encoding='utf-8') as f:json.dump({'exit_code':result.returncode},f)
    assert result.returncode==0,result.stdout
    data=json.loads(result.stdout)
    assert data['status']=='PASS' and len(data['checks'])==9
    assert all(c['status']=='PASS' for c in data['checks'])
    assert data['chain_id']==31337 and data['public_rpc_used'] is False
