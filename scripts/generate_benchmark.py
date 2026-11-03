"""Run existing R1-R4 synthetic regression fixtures; never report as real accuracy."""
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone
import uuid

def main():
    root=Path(__file__).resolve().parents[1]
    out=root/'run-output'/('synthetic-'+uuid.uuid4().hex[:8]);out.mkdir(parents=True)
    cmd=[sys.executable,'-m','pytest','tests/test_rules.py','-q',
         '--junitxml='+str(out/'junit.xml'),'--basetemp='+str(out/'temp')]
    run=subprocess.run(cmd,cwd=root,text=True,encoding='utf-8',errors='replace',capture_output=True)
    (out/'test.log').write_text(run.stdout+run.stderr,encoding='utf-8')
    (out/'summary.json').write_text(json.dumps({'synthetic':True,'kind':'existing rule regression fixtures',
        'exit_code':run.returncode,'generated_at':datetime.now(timezone.utc).isoformat(),
        'real_world_precision':None,'real_world_recall':None},indent=2),encoding='utf-8')
    print(run.stdout);print(out)
    return run.returncode

if __name__=='__main__': raise SystemExit(main())
