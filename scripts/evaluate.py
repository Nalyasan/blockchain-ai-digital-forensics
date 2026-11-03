"""Read-only evaluation of explicitly labeled transaction/address-window units.

Supports modes:
- incident: Replay real incident block windows (Euler DAI, Curve alETH)
- sepolia: Live testnet alert sampling with Wilson 95% CI precision estimation
- benchmark: Synthetic regression evaluation (synthetic=true)
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forensics.evaluation import evaluate_database, wilson_review, validate_labels
from forensics.paths import REAL_P4_DB, PROJECT_ROOT


# Authoritative incident boundary defaults from P4_08_ACCEPTANCE_REPORT.md
INCIDENT_BOUNDS = {
    'euler': {
        'calibration': (16816000, 16817989),
        'test': (16817990, 16818110),
        'chain_id': 1,
        'exploits': [
            '0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d',
            '0x71a908be0bef6174bccc3d493becdfd28395d78898e355d451cb52f7bac38617',
            '0x62bd3d31a7b75c098ccf28bc4d4af8c4a191b4b9e451fab4232258079e8b18c4',
            '0x465a6780145f1efe3ab52f94c006065575712d2003d83d85481f3d110ed131d9',
            '0x3097830e9921e4063d334acb82f6a79374f76f0b1a8f857e89b89bc58df1f311',
            '0x47ac3527d02e6b9631c77fad1cdee7bfa77a8a7bfd4880dccbda5146ace4088f',
        ],
        'exploiter_addrs': [
            '0xb66cd966670d962c227b3eabe3052902425a292a',
        ],
        'source_url': 'https://github.com/euler-xyz/euler-incident-2023',
        'accessed_at': '2023-03-14T00:00:00Z',
    },
    'curve': {
        'calibration': (17700000, 17806699),
        'test': (17806700, 17806830),
        'chain_id': 1,
        'exploits': [
            '0xb676d789bb8b66a08105c844a49c2bcffb400e5c1cfabd4bc30cca4bff3c9801',
        ],
        'exploiter_addrs': [
            '0x6ec2136e090e9d6d5bf63673c683b5f7e7502bfa',
        ],
        'source_url': 'https://curve.fi/postmortem-2023-07-30',
        'accessed_at': '2023-08-01T00:00:00Z',
    },
}


def build_default_incident_labels(incident_key: str, conn: sqlite3.Connection, test_window: tuple[int, int], bucket_size: int = 900) -> dict:
    cfg = INCIDENT_BOUNDS.get(incident_key, INCIDENT_BOUNDS['euler'])
    labels_list = []
    
    # 1. tx_unit labels
    db_txs = {
        r[0].lower()
        for r in conn.execute(
            'SELECT DISTINCT tx_hash FROM asset_transfers WHERE block_number BETWEEN ? AND ?',
            test_window,
        ).fetchall()
    }
    for tx in cfg['exploits']:
        tx_lower = tx.lower()
        if tx_lower in db_txs:
            labels_list.append({
                'unit_type': 'tx_unit',
                'unit_key': tx_lower,
                'positive': True,
                'source_url': cfg['source_url'],
                'accessed_at': cfg['accessed_at'],
            })
            
    # 2. address_window_unit labels from exploit transactions in test window
    exploit_q = ','.join('?' for _ in cfg['exploits'])
    rows = conn.execute(
        f'SELECT DISTINCT from_addr, to_addr, block_timestamp FROM asset_transfers '
        f'WHERE lower(tx_hash) IN ({exploit_q}) AND block_number BETWEEN ? AND ?',
        (*[tx.lower() for tx in cfg['exploits']], test_window[0], test_window[1]),
    ).fetchall()

    seen_aw = set()
    for from_addr, to_addr, stamp in rows:
        bucket = stamp // bucket_size
        for a in (from_addr, to_addr):
            if a and a != '0x0000000000000000000000000000000000000000':
                key = f'{a.lower()}:{bucket}'
                if key not in seen_aw:
                    seen_aw.add(key)
                    labels_list.append({
                        'unit_type': 'address_window_unit',
                        'unit_key': key,
                        'positive': True,
                        'source_url': cfg['source_url'],
                        'accessed_at': cfg['accessed_at'],
                    })

    if not labels_list and db_txs:
        first_tx = next(iter(db_txs))
        labels_list.append({
            'unit_type': 'tx_unit',
            'unit_key': first_tx,
            'positive': False,
            'source_url': cfg['source_url'],
            'accessed_at': cfg['accessed_at'],
        })

    return {
        'schema_version': 1,
        'synthetic': False,
        'labels': labels_list,
    }


def write_csv_summary(report: dict, csv_path: Path):
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['unit_type', 'rule', 'TP', 'FP', 'TN', 'FN', 'precision', 'recall', 'fpr', 'f1'])
        units = report.get('units', {})
        for unit_name, unit_data in units.items():
            if not isinstance(unit_data, dict):
                continue
            metrics = unit_data.get('metrics') or {}
            for rule_name, m in metrics.items():
                if isinstance(m, dict):
                    writer.writerow([
                        unit_name,
                        rule_name,
                        m.get('TP', ''),
                        m.get('FP', ''),
                        m.get('TN', ''),
                        m.get('FN', ''),
                        m.get('precision', ''),
                        m.get('recall', ''),
                        m.get('fpr', ''),
                        m.get('f1', ''),
                    ])


def parse_args(args=None):
    p = argparse.ArgumentParser(description=__doc__)
    # Interface Contract arguments
    p.add_argument('--mode', choices=['incident', 'sepolia', 'benchmark'], default='incident',
                   help='Evaluation mode: incident (real replay), sepolia (live sample review), benchmark (synthetic)')
    p.add_argument('--data', '--db', dest='data', default=None,
                   help='Path to SQLite database (defaults to data/real_p4.db)')
    p.add_argument('--unit', choices=['tx_unit', 'address_window_unit', 'all'], default='all',
                   help='Evaluation unit filter (default: all)')
    p.add_argument('--output', '--out', dest='output', required=True,
                   help='Output directory or JSON filepath')
    # Incident-specific / backward-compatible arguments
    p.add_argument('--labels', default=None,
                   help='Path to ground truth labels JSON file')
    p.add_argument('--incident', choices=['euler', 'curve'], default=None,
                   help='Specific incident target for defaults (euler or curve)')
    p.add_argument('--calibration', nargs=2, type=int, default=None,
                   help='Calibration window block bounds [start, end]')
    p.add_argument('--test', nargs=2, type=int, default=None,
                   help='Test window block bounds [start, end]')
    p.add_argument('--chain-id', type=int, default=1,
                   help='EVM Chain ID (default: 1)')
    p.add_argument('--bucket-size', type=int, default=900,
                   help='Address window bucket size in seconds (default: 900)')
    p.add_argument('--seed', type=int, default=42,
                   help='Random seed for Sepolia review sampling (default: 42)')
    return p.parse_args(args)


def main(argv=None):
    args = parse_args(argv)

    # Resolve database path
    if args.data:
        db_path = Path(args.data).resolve()
    else:
        db_path = REAL_P4_DB.resolve()

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    report = None
    labels_sha256 = None

    if args.mode == 'incident':
        with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as conn:
            conn.execute('PRAGMA query_only=ON')

            # Determine incident if bounds omitted
            incident_key = args.incident
            if not incident_key:
                row = conn.execute('SELECT min(block_number), max(block_number) FROM asset_transfers').fetchone()
                if row and row[0] is not None and row[0] >= 17000000:
                    incident_key = 'curve'
                else:
                    incident_key = 'euler'

            cfg = INCIDENT_BOUNDS.get(incident_key, INCIDENT_BOUNDS['euler'])
            cal_window = tuple(args.calibration) if args.calibration else cfg['calibration']
            test_window = tuple(args.test) if args.test else cfg['test']

            if args.labels:
                labels_file = Path(args.labels).resolve()
                labels_doc = json.loads(labels_file.read_text(encoding='utf-8-sig'))
                labels_sha256 = hashlib.sha256(labels_file.read_bytes()).hexdigest()
            else:
                labels_doc = build_default_incident_labels(
                    incident_key, conn, test_window, bucket_size=args.bucket_size
                )

            report = evaluate_database(
                conn,
                labels_doc,
                cal_window,
                test_window,
                chain_id=args.chain_id,
                bucket_size=args.bucket_size,
                unit_filter=args.unit,
            )
            report['incident'] = incident_key

    elif args.mode == 'sepolia':
        with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as conn:
            conn.execute('PRAGMA query_only=ON')
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            reviewed_total = 0
            reviewed_tp = 0
            if 'reviews' in tables:
                cols = {r[1].lower() for r in conn.execute('PRAGMA table_info(reviews)').fetchall()}
                reviewed_total = conn.execute('SELECT count(*) FROM reviews').fetchone()[0]
                if 'verdict' in cols:
                    reviewed_tp = conn.execute(
                        "SELECT count(*) FROM reviews WHERE upper(verdict) IN ('TP', 'TRUE_POSITIVE', '1', 'POSITIVE')"
                    ).fetchone()[0]
                elif 'positive' in cols:
                    reviewed_tp = conn.execute('SELECT count(*) FROM reviews WHERE positive=1').fetchone()[0]

            wilson_res = wilson_review(reviewed_tp, reviewed_total)
            report = {
                'mode': 'sepolia',
                'synthetic': False,
                'chain_id': args.chain_id,
                'database_sha256': hashlib.sha256(db_path.read_bytes()).hexdigest(),
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'review_sample': wilson_res,
                'units': {
                    'tx_unit': {
                        'status': 'REVIEW_SAMPLE_ESTIMATE',
                        'cohort_size': reviewed_total,
                        'labeled': reviewed_total,
                        'unknown': 'N/A: Ground truth absent under Open World Assumption',
                        'metrics': {
                            'union': {
                                'TP': wilson_res['true_positive'],
                                'FP': wilson_res['reviewed'] - wilson_res['true_positive'],
                                'TN': 'N/A: Ground truth absent under Open World Assumption',
                                'FN': 'N/A: Ground truth absent under Open World Assumption',
                                'precision': wilson_res['estimated_precision'],
                                'recall': 'N/A: Ground truth absent under Open World Assumption',
                                'fpr': 'N/A: Ground truth absent under Open World Assumption',
                                'f1': 'N/A: Ground truth absent under Open World Assumption',
                                'wilson_95': wilson_res['wilson_95'],
                            }
                        }
                    }
                }
            }
            if args.unit == 'address_window_unit':
                report['units'] = {}

    elif args.mode == 'benchmark':
        if args.labels and args.calibration and args.test:
            labels_file = Path(args.labels).resolve()
            labels_doc = json.loads(labels_file.read_text(encoding='utf-8-sig'))
            labels_sha256 = hashlib.sha256(labels_file.read_bytes()).hexdigest()
            with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as conn:
                conn.execute('PRAGMA query_only=ON')
                report = evaluate_database(
                    conn,
                    labels_doc,
                    tuple(args.calibration),
                    tuple(args.test),
                    chain_id=args.chain_id,
                    bucket_size=args.bucket_size,
                    unit_filter=args.unit,
                )
        else:
            report = {
                'mode': 'benchmark',
                'synthetic': True,
                'chain_id': args.chain_id,
                'real_world_precision': None,
                'real_world_recall': None,
                'units': {},
            }

    report.update(
        mode=args.mode,
        database_sha256=hashlib.sha256(db_path.read_bytes()).hexdigest(),
        labels_sha256=labels_sha256,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    out_arg = Path(args.output).resolve()
    if out_arg.suffix.lower() == '.json':
        out_dir = out_arg.parent
        json_path = out_arg
        csv_path = out_dir / (out_arg.stem + '.csv')
    else:
        out_dir = out_arg
        json_path = out_dir / 'summary.json'
        csv_path = out_dir / 'summary.csv'

    out_dir.mkdir(parents=True, exist_ok=True)
    with json_path.open('w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    write_csv_summary(report, csv_path)
    print(f"Generated: {json_path} and {csv_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
