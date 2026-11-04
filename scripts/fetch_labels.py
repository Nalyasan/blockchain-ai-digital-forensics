"""Validate/import a cited label JSON, optionally fetched from an explicit HTTPS URL.

Does not manufacture labels from blacklist absence or download blockchain state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensics.evaluation import validate_labels
from forensics.paths import PROJECT_ROOT


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', help='Local JSON filepath or explicit https:// URL')
    p.add_argument('--out', required=True, help='Output JSON path')
    args = p.parse_args(argv)

    raw = None
    is_url = args.source.startswith('https://') or args.source.startswith('http://')

    if is_url:
        cache_dir = PROJECT_ROOT / 'scratch' / 'dataset_cache'
        cache_dir.mkdir(parents=True, exist_ok=True)
        url_hash = hashlib.sha256(args.source.encode('utf-8')).hexdigest()[:12]
        url_name = Path(urlparse(args.source).path).name or f'labels_{url_hash}.json'
        cached_file = cache_dir / url_name

        offline_requested = (
            os.environ.get('FORENSICS_OFFLINE') == '1'
            or os.environ.get('AI_PROVIDER') == 'none'
        )

        if offline_requested:
            if cached_file.exists():
                raw = cached_file.read_bytes()
            else:
                print(f"OFFLINE: Network fetch blocked for {args.source} and no cache at {cached_file}", file=sys.stderr)
                return 1
        else:
            try:
                req = urllib.request.Request(args.source, headers={'User-Agent': 'ForensicsBenchmark/1.0'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise ValueError('LABEL_DOCUMENT_TOO_LARGE')
                try:
                    cached_file.write_bytes(raw)
                except Exception:
                    pass
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if cached_file.exists():
                    raw = cached_file.read_bytes()
                else:
                    print(f"ERROR: Could not fetch URL {args.source}: {e}", file=sys.stderr)
                    return 1
    else:
        src = Path(args.source)
        if not src.exists():
            print(f"ERROR: Local source file not found: {src}", file=sys.stderr)
            return 1
        raw = src.read_bytes()

    if raw is None:
        print("ERROR: No label content loaded", file=sys.stderr)
        return 1

    doc = validate_labels(json.loads(raw.decode('utf-8-sig')))
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print(f'Validated {len(doc["labels"])} explicit labels; synthetic={doc["synthetic"]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
