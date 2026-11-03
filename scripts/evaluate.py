"""Read-only evaluation of explicitly labeled transaction/address-window units."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensics.evaluation import evaluate_database

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', required=True)
    p.add_argument('--labels', required=True)
    p.add_argument('--calibration', nargs=2, type=int, required=True)
    p.add_argument('--test', nargs=2, type=int, required=True)
    p.add_argument('--chain-id', type=int, default=1)
    p.add_argument('--bucket-size', type=int, default=900)
    p.add_argument('--out', required=True)
    a=p.parse_args(); db=Path(a.db).resolve(); labels=Path(a.labels)
    with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:
        c.execute('PRAGMA query_only=ON')
        report=evaluate_database(c,json.loads(labels.read_text(encoding='utf-8-sig')),a.calibration,a.test,
                                 chain_id=a.chain_id,bucket_size=a.bucket_size)
    report.update(database_sha256=hashlib.sha256(db.read_bytes()).hexdigest(),
                  labels_sha256=hashlib.sha256(labels.read_bytes()).hexdigest(),
                  generated_at=datetime.now(timezone.utc).isoformat())
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    print(out)

if __name__=='__main__': main()
