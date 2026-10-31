"""Snapshot export 1.1, verified staging and platform-specific no-clobber publish."""
import contextlib
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import uuid

from forensics.evidence_identity import case_id_digest, canonical_storage_uri
from forensics.integrity import (BASE_FILES, InvalidPackage, Reason, _no_link, need,
                                package_digest, quantity, raw_hash, verify_package, validate_receipt)
from forensics.provenance import get_git_state


class ExportPolicyError(ValueError):
    """Only fixed, application-owned messages may cross the CLI boundary."""


def publish_no_replace(staging, target):
    """No check-then-overwriting-rename fallback is permitted."""
    if os.name == 'nt':
        os.rename(staging, target)  # Windows fails even for an existing empty directory.
    elif os.name == 'posix':
        import ctypes
        import errno
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, 'renameat2', None)
        if rename is None:
            raise RuntimeError('NO_CLOBBER_UNSUPPORTED')
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1):
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError('DESTINATION_EXISTS')
            raise RuntimeError('PUBLISH_FAILED')
    else:
        raise RuntimeError('NO_CLOBBER_UNSUPPORTED')


def select_audits(rows, chain, blocks, start, end, db_chains):
    selected, excluded = [], 0
    block_keys = {(b['number'], b['hash']) for b in blocks}
    numbers = {b['number'] for b in blocks}
    hashes = {b['hash'] for b in blocks}
    for row in rows:
        meta = json.loads(row['metadata']) if row['metadata'] else {}
        need(isinstance(meta, dict))
        ref = row['object_ref'] or ''
        scoped = (type(meta['chain_id']) is int and meta['chain_id'] == chain) if 'chain_id' in meta else (
            len(db_chains) == 1 and chain in db_chains)
        linked = False
        if match := re.fullmatch(r'block:(\d+)', ref):
            n = int(match[1])
            linked = scoped and ((n, meta.get('hash')) in block_keys if 'hash' in meta else n in numbers)
        elif match := re.fullmatch(r'range:(\d+)-(\d+)', ref):
            a, b = map(int, match.groups())
            linked = scoped and a <= b and max(a, start) <= min(b, end)
        elif match := re.fullmatch(r'chain:(\d+)', ref):
            linked = int(match[1]) == chain and ('chain_id' not in meta or scoped)
        elif match := re.fullmatch(r'block:(0x[0-9a-fA-F]{64})', ref):
            linked = match[1] in hashes and type(meta.get('chain_id')) is int and meta['chain_id'] == chain
        if not linked:
            excluded += 1
            continue
        # Diagnostic free text may contain provider URLs. Export only structured
        # linkage metadata; never echo error strings, tokens or shell arguments.
        safe = {}
        for key, value in meta.items():
            if key in ('hash', 'block_hash') and isinstance(value, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', value):
                safe[key] = value
            elif key in ('chain_id', 'common_ancestor', 'confirmations') and type(value) is int:
                safe[key] = value
            elif key == 'watch' and type(value) is bool:
                safe[key] = value
            elif key == 'version' and isinstance(value, str) and re.fullmatch(r'[0-9.]+', value):
                safe[key] = value
        selected.append({'id': row['id'], 'ts': row['ts'], 'action': row['action'],
                         'object_ref': ref, 'metadata': safe,
                         'metadata_fields_omitted': len(meta) - len(safe)})
    return selected, excluded


def _snapshot(conn, chain_id, start, end):
    rows = conn.execute('SELECT * FROM blocks WHERE number BETWEEN ? AND ? ORDER BY chain_id,number,status,hash', (start, end)).fetchall()
    chains = {r['chain_id'] for r in rows}
    if chain_id is None:
        if len(chains) != 1:
            raise ExportPolicyError('SOURCE_CHAIN_REQUIRED: chọn --chain-id cho một source chain')
        chain_id = next(iter(chains))
    need(type(chain_id) is int and chain_id >= 0 and chain_id in chains)
    rows = [dict(r) for r in rows if r['chain_id'] == chain_id]
    synthetics = {b['synthetic'] for b in rows}
    if len(synthetics) != 1 or not synthetics.issubset({0, 1}):
        raise ExportPolicyError('Không được trộn lẫn dữ liệu synthetic')
    for row in rows:
        row['raw_json'] = json.loads(row['raw_json'])
    canonical = [b for b in rows if b['status'] == 'canonical']
    need(bool(canonical), Reason.INCOMPLETE)
    txs, receipts, transfers, db_logs = [], [], [], []
    for block in canonical:
        args = (chain_id, block['hash'])
        txs.extend(dict(r) for r in conn.execute('SELECT * FROM transactions WHERE chain_id=? AND block_hash=? ORDER BY tx_index,tx_hash', args))
        for r in conn.execute('SELECT * FROM receipts WHERE chain_id=? AND block_hash=? ORDER BY tx_hash', args):
            record = dict(r)
            record['raw_json'] = json.loads(record['raw_json'])
            receipts.append(record)
        transfers.extend(dict(r) for r in conn.execute('SELECT * FROM asset_transfers WHERE chain_id=? AND block_hash=? ORDER BY tx_hash,log_index,transfer_id', args))
        db_logs.extend(dict(r) for r in conn.execute('SELECT * FROM logs WHERE chain_id=? AND block_hash=? ORDER BY log_index', args))
    raw_txs = {(b['hash'], t['hash']): t for b in canonical for t in b['raw_json']['transactions']}
    need(len(raw_txs) == len(txs) and {(t['block_hash'], t['tx_hash']) for t in txs} == set(raw_txs), Reason.INCOMPLETE)
    for tx in txs:
        raw = json.loads(tx['raw_json'])
        need(raw_hash(raw) == tx['raw_sha256'] and raw == raw_txs[(tx['block_hash'], tx['tx_hash'])])
        for column, key in [('from_addr', 'from'), ('to_addr', 'to'), ('input', 'input')]:
            need(tx[column] == raw.get(key))
        for column, key in [('block_number', 'blockNumber'), ('tx_index', 'transactionIndex'), ('nonce', 'nonce'), ('value_raw', 'value')]:
            need(quantity(tx[column]) == quantity(raw[key]))
    tx_lookup = {(t['block_hash'], t['tx_hash']): t for t in txs}
    raw_logs, output_receipts = {}, []
    for receipt in receipts:
        raw = receipt['raw_json']
        need(raw_hash(raw) == receipt['raw_sha256'])
        validate_receipt(raw, raw_txs[(receipt['block_hash'], receipt['tx_hash'])])
        need(isinstance(raw.get('logs'), list), Reason.INCOMPLETE)
        need(quantity(raw['status']) == receipt['status'] and quantity(raw['gasUsed']) == receipt['gas_used'])
        need(raw.get('contractAddress') == receipt['contract_address'])
        tx = tx_lookup[(receipt['block_hash'], receipt['tx_hash'])]
        output_receipts.append({'chain_id': chain_id, 'block_hash': receipt['block_hash'],
            'block_number': tx['block_number'], 'tx_hash': receipt['tx_hash'], 'tx_index': tx['tx_index'],
            'raw_sha256': receipt['raw_sha256'], 'raw_json': raw})
        for log in raw['logs']:
            key = (receipt['block_hash'], quantity(log['logIndex']))
            need(key not in raw_logs)
            raw_logs[key] = log
    need(len(db_logs) == len(raw_logs))
    for log in db_logs:
        raw = json.loads(log['raw_json'])
        need(raw == raw_logs[(log['block_hash'], log['log_index'])])
        need(log['tx_hash'] == raw['transactionHash'] and log['address'] == raw['address'])
        need(json.loads(log['topics']) == raw['topics'] and log['data'] == raw['data'])
    observed = conn.execute("SELECT MAX(number) FROM blocks WHERE chain_id=? AND status='canonical'", (chain_id,)).fetchone()[0]
    runs = conn.execute('SELECT * FROM collector_runs WHERE chain_id=? AND start_block<=? AND end_block>=? ORDER BY started_at,run_id',
                        (chain_id, end, start)).fetchall()
    labels = sorted({r['rpc_label'] for r in runs if r['rpc_label']})
    label = labels[0] if len(labels) == 1 else 'multiple-recorded-sources' if labels else 'unknown'
    # A provider URL is never a safe rpc_label.
    if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', label):
        label = 'redacted-source-label'
    all_audits = conn.execute('SELECT * FROM audit_events ORDER BY id').fetchall()
    db_chains = {r[0] for r in conn.execute('SELECT DISTINCT chain_id FROM blocks')}
    audits, excluded = select_audits(all_audits, chain_id, rows, start, end, db_chains)
    return chain_id, rows, canonical, txs, output_receipts, transfers, audits, excluded, observed, label


def export_package(case_id, start_block, end_block, out_dir=None, db_path=None,
                   operator=None, allow_gaps=False, require_final=False, chain_id=None):
    from forensics import evidence as ev
    from forensics.schemas import init_db
    try:
        ev.validate_case_id(case_id)
    except ValueError:
        raise ValueError('INVALID_CASE_ID') from None
    need(type(start_block) is int and type(end_block) is int and 0 <= start_block <= end_block)
    git = get_git_state()
    if git.state == 'UNKNOWN':
        raise RuntimeError('GIT_UNKNOWN')
    db_file = Path(db_path or os.environ.get('DB_PATH', 'data/forensics.db')).absolute()
    if not db_file.is_file():
        raise RuntimeError('DATABASE_UNAVAILABLE')
    target = Path(out_dir or Path('evidence') / case_id).absolute()
    if os.path.lexists(target):
        raise FileExistsError('DESTINATION_EXISTS')
    stage = None
    try:
        # Validate all existing ancestors before creating directories/staging.
        for parent in reversed(target.parents):
            if os.path.lexists(parent):
                _no_link(parent)
        target.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.closing(sqlite3.connect(db_file.as_uri() + '?mode=ro', uri=True, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute('BEGIN')
            data = _snapshot(conn, chain_id, start_block, end_block)
            chain, blocks, canonical, txs, receipts, transfers, audits, excluded, head, label = data
            conn.execute('ROLLBACK')
        synthetics = {b['synthetic'] for b in blocks}
        if len(synthetics) != 1 or not synthetics.issubset({0, 1}):
            raise ExportPolicyError('Không được trộn lẫn dữ liệu synthetic')
        synthetic = bool(next(iter(synthetics)))
        numbers = sorted(b['number'] for b in canonical)
        gaps, last = [], start_block
        for number in numbers:
            if number > last:
                gaps.append([last, number-1])
            last = number+1
        if last <= end_block:
            gaps.append([last, end_block])
        if gaps and not allow_gaps:
            raise ExportPolicyError('Phát hiện block bị thiếu (gaps); cần --allow-gaps')
        confirmations = int(os.environ.get('CONFIRMATIONS', '2'))
        need(confirmations >= 0)
        unfinalized = [n for n in numbers if n >= head-confirmations+1]
        if unfinalized and require_final:
            raise ExportPolicyError('Khoảng block chưa finalize; --require-final từ chối')
        stage = Path(tempfile.mkdtemp(prefix='.evidence-stage-', dir=target.parent))
        def write_jsonl(name, records):
            with (stage / name).open('w', encoding='utf-8', newline='\n') as out:
                for row in records:
                    out.write(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n')
        write_jsonl('raw_blocks.jsonl', blocks)
        write_jsonl('raw_receipts.jsonl', sorted(receipts, key=lambda r: (r['block_number'], r['tx_index'], r['tx_hash'])))
        write_jsonl('audit_events.jsonl', audits)
        timestamps = {(b['chain_id'], b['hash']): b['block_time_utc'] for b in canonical}
        timeline = []
        for b in canonical:
            timeline.append([b['block_time_utc'], b['number'], 'BLOCK', '', '', '', '', '', 'canonical'])
        for tx in txs:
            timeline.append([timestamps[(chain, tx['block_hash'])], tx['block_number'], 'TX', tx['tx_hash'],
                             tx['from_addr'] or '', tx['to_addr'] or '', 'NATIVE', tx['value_raw'], 'mined'])
        for t in transfers:
            timeline.append([timestamps[(chain, t['block_hash'])], t['block_number'], 'TRANSFER', t['tx_hash'],
                             t['from_addr'] or '', t['to_addr'] or '', t['asset_id'], t['amount_raw'], 'success'])
        timeline.sort(key=lambda r: tuple(str(v) for v in r))
        with (stage / 'timeline.csv').open('w', encoding='utf-8', newline='') as out:
            writer = csv.writer(out, lineterminator='\n')
            writer.writerow(['timestamp_utc', 'block_number', 'event_type', 'tx_hash', 'from_addr', 'to_addr', 'asset_id', 'amount_raw', 'status'])
            writer.writerows(timeline)
        columns = ['transfer_id', 'chain_id', 'block_number', 'block_hash', 'block_timestamp', 'tx_hash',
                   'log_index', 'asset_id', 'from_addr', 'to_addr', 'amount_raw', 'synthetic']
        with (stage / 'asset_transfers.csv').open('w', encoding='utf-8', newline='') as out:
            writer = csv.DictWriter(out, fieldnames=columns, lineterminator='\n')
            writer.writeheader()
            writer.writerows(transfers)
        files = [{'path': name, 'size_bytes': (stage/name).stat().st_size,
                  'sha256': ev.compute_file_sha256(str(stage/name))} for name in sorted(BASE_FILES | {'raw_receipts.jsonl'})]
        config = ev.sanitize_config({'RPC_LABEL': label, 'RPC_SYNTHETIC': synthetic, 'commit_hash': git.head})
        m = {'manifest_version': '1.1.0', 'case_id': case_id, 'exported_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
             'operator': ev.get_operator(operator), 'chain_id': chain, 'source_chain_id': chain, 'rpc_label': label,
             'synthetic': synthetic, 'block_range': {'start_block': start_block, 'end_block': end_block},
             'block_timestamps_utc': {'start': min(b['block_time_utc'] for b in blocks), 'end': max(b['block_time_utc'] for b in blocks)},
             'software': {'version': ev.__version__, 'commit_hash': git.head, 'working_tree_dirty': git.state == 'DIRTY'},
             'sanitized_config': config, 'export_commit': git.head, 'git_state': git.state,
             'working_tree_dirty': git.state == 'DIRTY', 'coverage': 'FULL',
             'finalization': {'confirmations': confirmations, 'observed_head': head, 'basis': 'collected-canonical-head-confirmations',
                              'is_finalized': not unfinalized, 'unfinalized_blocks_count': len(unfinalized), 'unfinalized_blocks': unfinalized},
             'counts': {'total_blocks': len(blocks), 'canonical_blocks': len(canonical), 'orphaned_blocks': len(blocks)-len(canonical),
                        'transactions': len(txs), 'asset_transfers': len(transfers), 'audit_events': len(audits), 'receipts': len(receipts)},
             'audit_selection': {'excluded_unlinked': excluded, 'rule': 'exact-reference-v1'},
             'integrity_checks': {'verify_local': {'status': 'PASSED', 'mismatches': 0},
                                  'verify_derived': {'status': 'PASSED', 'mismatches': 0},
                                  'gaps': gaps, 'gaps_count': sum(b-a+1 for a,b in gaps)},
             'export_policy': {'allow_gaps': bool(allow_gaps), 'require_final': bool(require_final)},
             'package_digest': package_digest(files), 'files': files}
        manifest_bytes = (json.dumps(m, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
        (stage/'manifest.json').write_bytes(manifest_bytes)
        checked = verify_package(stage)
        if checked.status != 'VALID' or checked.coverage != 'FULL':
            raise InvalidPackage(checked.reason_code)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        need(checked.manifest_sha256 == manifest_hash)
        publish_no_replace(stage, target)
        stage = None
        # Append-only, including identical manifest bytes exported to distinct destinations.
        export_id = f'exp-{case_id}-{manifest_hash[:12]}-{uuid.uuid4().hex[:12]}'
        case_dig = case_id_digest(case_id)
        storage_uri = canonical_storage_uri(case_dig, manifest_hash)
        with contextlib.closing(init_db(str(db_file))) as conn:
            with conn:
                conn.execute('INSERT INTO evidence_exports(export_id,case_id,manifest_path,manifest_sha256,storage_uri,created_at,operator,onchain_evidence_id) VALUES(?,?,?,?,?,?,?,NULL)',
                             (export_id, case_id, 'manifest.json', manifest_hash, storage_uri, m['exported_at'], m['operator']))
        return m
    except FileExistsError:
        raise FileExistsError('DESTINATION_EXISTS') from None
    except (InvalidPackage, ExportPolicyError, RuntimeError):
        raise
    except (OSError, sqlite3.Error):
        raise RuntimeError('EXPORT_IO_OR_DB_ERROR: published package, if present, is retained') from None
    except (ValueError, KeyError, TypeError, IndexError):
        raise ValueError('EXPORT_INVALID_OR_INCOMPLETE_DATA') from None
    finally:
        if stage is not None and stage.exists():
            # Delete only our resolved, uniquely-created staging child, never the target.
            if stage.resolve().parent != target.parent.resolve() or not stage.name.startswith('.evidence-stage-'):
                raise RuntimeError('STAGING_CLEANUP_REFUSED')
            shutil.rmtree(stage)
