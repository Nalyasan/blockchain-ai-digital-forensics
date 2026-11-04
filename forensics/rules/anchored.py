"""P4 reads P3 evidence and custody context, preserving verification status.

Run with python -m forensics.rules.anchored --help. No wallet, signing,
canonical DB writes, or custody mutations are performed by this entrypoint.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sqlite3

from forensics import onchain
from forensics.rules.engine import RuleEngine


class AnchoredEvidenceError(ValueError):
    """The P3 verification or the package binding did not pass."""


TRANSFER_COLUMNS = (
    'transfer_id', 'chain_id', 'block_number', 'block_hash', 'block_timestamp',
    'tx_hash', 'log_index', 'asset_id', 'from_addr', 'to_addr', 'amount_raw', 'synthetic',
)
INTEGER_COLUMNS = {'transfer_id', 'chain_id', 'block_number', 'block_timestamp', 'log_index', 'synthetic'}


def _snapshot(manifest_path, require_verified=False):
    path = Path(manifest_path).resolve()
    if path.is_dir():
        path = path / 'manifest.json'
    raw = path.read_bytes()
    manifest = json.loads(raw)
    contents = {}
    mismatches = []
    for name in ('asset_transfers.csv', 'raw_blocks.jsonl'):
        entries = [f for f in manifest['files'] if f['path'] == name]
        if len(entries) != 1:
            raise AnchoredEvidenceError('PACKAGE_INPUT_MISSING')
        file = path.parent / name
        if file.is_symlink() or file.resolve().parent != path.parent:
            raise AnchoredEvidenceError('PACKAGE_PATH_INVALID')
        data = file.read_bytes()
        entry = entries[0]
        if len(data) != entry['size_bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            mismatches.append(name)
            if require_verified:
                raise AnchoredEvidenceError('PACKAGE_CONTENT_MISMATCH')
        contents[name] = data
    return path, manifest, hashlib.sha256(raw).hexdigest(), contents, mismatches


def read_custody(db_path, manifest_hash, chain_id, contract):
    """Read local P3 records bound by manifest+chain+contract; no trust upgrade."""
    result = {'status': 'NOT_SUPPLIED', 'source': 'LOCAL_P3_RECORDS_NOT_REVERIFIED', 'events': []}
    if not db_path:
        return result
    if chain_id is None or not contract:
        return {**result, 'status': 'CONTEXT_REQUIRED'}
    try:
        with sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA query_only=ON')
            rows = conn.execute(
                "SELECT c.* FROM custody_events c JOIN anchor_links a ON "
                "c.evidence_id=a.evidence_id AND c.chain_id=a.chain_id "
                "AND lower(c.contract_address)=lower(a.contract_address) "
                "WHERE lower(a.manifest_sha256)=? AND a.chain_id=? "
                "AND lower(a.contract_address)=? ORDER BY c.block_number,c.recorded_at,c.event_id",
                (manifest_hash.lower(), chain_id, contract.lower())).fetchall()
            return {**result, 'status': 'LOADED' if rows else 'NO_RECORDS', 'events': [dict(r) for r in rows]}
    except (OSError, sqlite3.Error, ValueError):
        return {**result, 'status': 'UNAVAILABLE'}


def analyze_anchored_package(manifest_path, *, contract_address=None, rpc_url=None,
                             anchor_chain_id=None, test_start_block=None, test_end_block=None,
                             cal_start_block=None, cal_end_block=None,
                             evidence_id=None, rules=None, token_thresholds=None,
                             require_verified=False, custody_db=None):
    """Verify P3, then run R1-R4 on a private in-memory copy of anchored bytes.

    Anchor chain (e.g. Anvil/Sepolia) and evidence source chain are distinct.
    A package must cover both requested calibration and analysis windows.
    Unverified readable input continues with explicit warning; strict mode is optional.
    """
    path, manifest, digest, contents, mismatches = _snapshot(manifest_path, require_verified)
    bounds = manifest['block_range']
    start, end = bounds['start_block'], bounds['end_block']
    test_start_block = start if test_start_block is None else test_start_block
    test_end_block = end if test_end_block is None else test_end_block
    windows = [(test_start_block, test_end_block)]
    if cal_start_block is not None or cal_end_block is not None:
        windows.append((cal_start_block, cal_end_block))
    for low, high in windows:
        if type(low) is not int or type(high) is not int or not start <= low <= high <= end:
            raise AnchoredEvidenceError('WINDOW_OUTSIDE_ANCHORED_PACKAGE')
    if cal_end_block is not None and cal_end_block >= test_start_block:
        raise AnchoredEvidenceError('CALIBRATION_MUST_PRECEDE_TEST')

    # Existing P3 verifier checks package integrity, Git provenance, RPC chain,
    # registry state, registration event and receipt. Never trust a stored flag.
    verified = onchain.OnchainVerification('ERROR', 'ANCHOR_CONTEXT_NOT_SUPPLIED', {})
    if contract_address and rpc_url and anchor_chain_id is not None:
        try:
            verified = onchain.verify_onchain_evidence(
                path, contract_address, evidence_id=evidence_id,
                rpc_url=rpc_url, anchor_chain_id=anchor_chain_id)
        except Exception:
            verified = onchain.OnchainVerification('ERROR', 'P3_UNAVAILABLE', {})
    status = 'NOT_VERIFIED'
    reason = verified.reason_code
    if verified.status == 'MATCH':
        if verified.details.get('manifest_sha256') != digest:
            status, reason = 'MISMATCH', 'PACKAGE_CHANGED_DURING_VERIFICATION'
        elif verified.details.get('source_chain_id') != manifest['chain_id']:
            status, reason = 'MISMATCH', 'SOURCE_CHAIN_MISMATCH'
        else:
            status = 'VERIFIED'
    elif verified.status == 'MISMATCH':
        status = 'MISMATCH'
    if mismatches:
        status, reason = 'MISMATCH', 'PACKAGE_CONTENT_MISMATCH'
    if require_verified and status != 'VERIFIED':
        raise AnchoredEvidenceError('P3_' + status + ':' + reason)
    verification = {**verified.details, 'status': status, 'reason_code': reason,
                    'scope': 'P3_PACKAGE_INPUT', 'analyzed_manifest_sha256': digest,
                    'content_mismatches': mismatches,
                    'input_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}}
    custody = read_custody(custody_db, digest, anchor_chain_id, contract_address)

    # Analyze captured bytes, not mutable files or an unrelated source database.
    conn = sqlite3.connect(':memory:')
    try:
        conn.execute('CREATE TABLE blocks (chain_id INTEGER, hash TEXT, status TEXT, PRIMARY KEY(chain_id,hash))')
        declarations = ','.join(f'{c} {"INTEGER" if c in INTEGER_COLUMNS else "TEXT"}' for c in TRANSFER_COLUMNS)
        conn.execute('CREATE TABLE asset_transfers (' + declarations + ')')
        for line in contents['raw_blocks.jsonl'].decode('utf-8').splitlines():
            row = json.loads(line)
            conn.execute('INSERT INTO blocks VALUES (?,?,?)', (row['chain_id'], row['hash'], row['status']))
        reader = csv.DictReader(io.StringIO(contents['asset_transfers.csv'].decode('utf-8')))
        if reader.fieldnames != list(TRANSFER_COLUMNS):
            raise AnchoredEvidenceError('TRANSFER_SCHEMA_UNSUPPORTED')
        for row in reader:
            values = [int(row[c]) if c in INTEGER_COLUMNS else row[c] for c in TRANSFER_COLUMNS]
            conn.execute('INSERT INTO asset_transfers VALUES (' + ','.join('?' for _ in values) + ')', values)
        conn.commit()
        conn.execute('PRAGMA query_only=ON')
        with RuleEngine(conn, chain_id=manifest['chain_id'], token_thresholds=token_thresholds) as engine:
            alerts = engine.run(test_start_block=test_start_block, test_end_block=test_end_block,
                                cal_start_block=cal_start_block, cal_end_block=cal_end_block,
                                rules=rules, persist=False)
        return {
            'verification': verification, 'custody': custody,
            'analysis_status': 'COMPLETED' if status == 'VERIFIED' else 'COMPLETED_WITH_WARNING',
            'case_id': manifest['case_id'], 'source_chain_id': manifest['chain_id'],
            'test_window': [test_start_block, test_end_block],
            'calibration_window': None if cal_start_block is None else [cal_start_block, cal_end_block],
            'total_alerts': len(alerts), 'alerts': [{**a.to_dict(), 'p3_verification_status': status, 'p3_manifest_sha256': digest} for a in alerts],
        }
    finally:
        conn.close()


def cli_analyze_p3(args):
    """P3 input mode of the existing P4 analyze command; JSON preserves context."""
    try:
        if args.format == 'csv':
            raise AnchoredEvidenceError('P3_CONTEXT_REQUIRES_JSON')
        thresholds = None
        if args.token_thresholds:
            value = args.token_thresholds
            thresholds = json.loads(Path(value).read_text() if Path(value).is_file() else value)
        report = analyze_anchored_package(
            args.p3_manifest, contract_address=args.p3_contract,
            rpc_url=args.p3_rpc_url, anchor_chain_id=args.p3_anchor_chain_id,
            custody_db=args.p3_custody_db, require_verified=args.p3_require_verified,
            test_start_block=args.start_block, test_end_block=args.end_block,
            cal_start_block=args.cal_start_block, cal_end_block=args.cal_end_block,
            rules=args.rules, token_thresholds=thresholds)
        payload = json.dumps(report, ensure_ascii=False, indent=2)
        if args.out:
            # Never overwrite input evidence or an existing report.
            with Path(args.out).open('x', encoding='utf-8') as target:
                target.write(payload)
        else:
            print(payload)
        return 0
    except Exception:
        print(json.dumps({'error': 'P3_P4_ANALYSIS_REJECTED', 'verification': {'status': 'NOT_VERIFIED'}}))
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--contract')
    parser.add_argument('--rpc-url', help='Explicit read-only P3 verification endpoint')
    parser.add_argument('--anchor-chain-id', type=int)
    parser.add_argument('--require-verified', action='store_true')
    parser.add_argument('--custody-db')
    parser.add_argument('--evidence-id', type=int)
    parser.add_argument('--test', required=True, nargs=2, type=int, metavar=('START', 'END'))
    parser.add_argument('--calibration', nargs=2, type=int, metavar=('START', 'END'))
    parser.add_argument('--rules', nargs='+', choices=['large_transfer', 'high_frequency', 'fan_in_out', 'rapid_pass_through'])
    args = parser.parse_args(argv)
    try:
        report = analyze_anchored_package(
            args.manifest, contract_address=args.contract, rpc_url=args.rpc_url,
            anchor_chain_id=args.anchor_chain_id, evidence_id=args.evidence_id,
            test_start_block=args.test[0], test_end_block=args.test[1],
            cal_start_block=args.calibration[0] if args.calibration else None,
            cal_end_block=args.calibration[1] if args.calibration else None, rules=args.rules,
            require_verified=args.require_verified, custody_db=args.custody_db)
    except Exception:
        # Do not expose RPC credentials, tool output or evidence contents.
        print(json.dumps({'verification': {'status': 'NOT_VERIFIED'}, 'error': 'P3_P4_ANALYSIS_REJECTED'}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
