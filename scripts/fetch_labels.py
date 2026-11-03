"""Validate/import a cited label JSON, optionally fetched from an explicit HTTPS URL.

Does not manufacture labels from blacklist absence or download blockchain state.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensics.evaluation import validate_labels

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',help='Local JSON or explicit https:// URL')
    p.add_argument('--out',required=True)
    args=p.parse_args()
    if args.source.startswith('https://'):
        with urllib.request.urlopen(args.source,timeout=30) as response:
            raw=response.read(10_000_001)
        if len(raw)>10_000_000: raise ValueError('LABEL_DOCUMENT_TOO_LARGE')
    else: raw=Path(args.source).read_bytes()
    doc=validate_labels(json.loads(raw.decode('utf-8-sig')))
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with Path(args.out).open('x',encoding='utf-8') as f: json.dump(doc,f,indent=2,ensure_ascii=False)
    print(f'Validated {len(doc["labels"])} explicit labels; synthetic={doc["synthetic"]}')

if __name__=='__main__': main()
