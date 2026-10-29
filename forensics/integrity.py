"""Shared evidence verification. Local consistency is not independent chain truth."""
import csv
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

BASE_FILES = {'raw_blocks.jsonl', 'timeline.csv', 'asset_transfers.csv', 'audit_events.jsonl'}
HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_FILES = 4096


class Reason(str, Enum):
    OK = 'OK'
    SCHEMA = 'SCHEMA_INVALID'
    VERSION = 'UNSUPPORTED_VERSION'
    PATH = 'UNSAFE_PATH'
    DUPLICATE = 'DUPLICATE_PATH'
    MISSING = 'MISSING_FILE'
    EXTRA = 'EXTRA_FILE'
    HASH = 'HASH_MISMATCH'
    SIZE = 'SIZE_MISMATCH'
    DIGEST = 'PACKAGE_DIGEST_MISMATCH'
    SEMANTIC = 'SEMANTIC_MISMATCH'
    SYNTHETIC = 'SYNTHETIC_MISMATCH'
    SOURCE_LABEL = 'SOURCE_LABEL_MISMATCH'
    INCOMPLETE = 'INCOMPLETE_RAW_DATA'
    DB = 'DB_MANIFEST_MISMATCH'
    IO = 'IO_ERROR'
    RESOURCE = 'RESOURCE_LIMIT'
    UNSTABLE = 'PACKAGE_UNSTABLE'


@dataclass
class VerifyResult:
    status: str
    reason_code: Reason
    coverage: str = 'LIMITED'
    manifest_sha256: str | None = None
    manifest_version: str | None = None
    details: dict = field(default_factory=dict)


class InvalidPackage(ValueError):
    def __init__(self, code=Reason.SEMANTIC):
        self.code = code
        super().__init__(code.value)


class VerificationError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code.value)


def need(condition, code=Reason.SEMANTIC):
    if not condition:
        raise InvalidPackage(code)


def integer(value):
    return type(value) is int and value >= 0


def raw_hash(value):
    # Exact Collector convention, intentionally different from file-byte hashing.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def package_digest(files):
    # Preserve P2's sorted [path, sha256] convention, including ensure_ascii=False.
    items = [[f['path'], f['sha256']] for f in sorted(files, key=lambda f: f['path'])]
    return hashlib.sha256(json.dumps(items, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def normalized_path(value):
    need(isinstance(value, str) and bool(value), Reason.PATH)
    value = value.replace('\\', '/')
    parts = value.split('/')
    for part in parts:
        need(part not in ('', '.', '..') and part == part.rstrip(' .'), Reason.PATH)
        need(not any(ord(c) < 32 or c in '<>:"|?*' for c in part), Reason.PATH)
        device = part.split('.')[0].upper()
        need(not re.fullmatch(r'CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³]', device), Reason.PATH)
    return '/'.join(parts)


def _metadata(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _no_link(path):
    s = path.lstat()
    need(not stat.S_ISLNK(s.st_mode) and not (getattr(s, 'st_file_attributes', 0) & 0x400), Reason.PATH)
    return s


def safe_path(root, relative):
    normalized = normalized_path(relative)
    current = root
    _no_link(current)
    for part in normalized.split('/'):
        current = current / part
        _no_link(current)
    need(current.resolve().is_relative_to(root.resolve()), Reason.PATH)
    return current


def inventory(root):
    files = {}
    def walk(directory):
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                rel = path.relative_to(root).as_posix()
                normalized_path(rel)
                s = _no_link(path)
                if stat.S_ISDIR(s.st_mode):
                    walk(path)
                else:
                    need(stat.S_ISREG(s.st_mode), Reason.PATH)
                    files[rel] = _metadata(s)
                    if len(files) > MAX_FILES:
                        raise VerificationError(Reason.RESOURCE)
    walk(root)
    return files


def read_stable(path, limit=MAX_FILE_BYTES):
    before = _metadata(_no_link(path))
    if before[2] > limit:
        raise VerificationError(Reason.RESOURCE)
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    digest, chunks, length = hashlib.sha256(), [], 0
    with os.fdopen(fd, 'rb') as stream:
        opened = _metadata(os.fstat(stream.fileno()))
        # CPython/Windows lstat and fstat can expose different ctime semantics.
        # Compare identity/size/mtime across APIs, and full metadata within each.
        cross_api_match = opened[:4] == before[:4] if os.name == 'nt' else opened == before
        if not cross_api_match:
            raise VerificationError(Reason.UNSTABLE)
        while chunk := stream.read(65536):
            length += len(chunk)
            if length > limit:
                raise VerificationError(Reason.RESOURCE)
            digest.update(chunk)
            chunks.append(chunk)
        after_fd = _metadata(os.fstat(stream.fileno()))
    if opened != after_fd or before != _metadata(_no_link(path)):
        raise VerificationError(Reason.UNSTABLE)
    return b''.join(chunks), digest.hexdigest()


def _object(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result, Reason.SCHEMA)
        result[k] = v
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(InvalidPackage(Reason.SCHEMA)))


def jsonl(raw):
    rows = []
    for line in raw.decode('utf-8').splitlines():
        need(bool(line.strip()), Reason.SCHEMA)
        row = parse_json(line)
        need(isinstance(row, dict), Reason.SCHEMA)
        rows.append(row)
    return rows


def csv_rows(raw):
    stream = io.StringIO(raw.decode('utf-8'), newline='')
    reader = csv.DictReader(stream, strict=True)
    need(reader.fieldnames is not None and len(reader.fieldnames) == len(set(reader.fieldnames)), Reason.SCHEMA)
    rows = list(reader)
    need(all(None not in row and None not in row.values() for row in rows), Reason.SCHEMA)
    return rows


def quantity(value):
    need(type(value) in (str, int))
    n = int(value, 16) if isinstance(value, str) and value.startswith('0x') else int(value)
    need(n >= 0)
    return n


def validate_records(manifest, blocks, receipts, transfers, timeline, audits):
    """Validate complete 1.1 data; called on the SAME bytes that were hashed."""
    from collector import extract_transfers, ERC20_TRANSFER_TOPIC0
    chain = manifest['source_chain_id']
    need(integer(chain) and chain == manifest['chain_id'])
    start, end = manifest['block_range']['start_block'], manifest['block_range']['end_block']
    need(integer(start) and integer(end) and start <= end)
    block_map, canonical, tx_map = {}, {}, {}
    for block in blocks:
        raw = block['raw_json']
        need(isinstance(raw, dict) and raw_hash(raw) == block['raw_sha256'])
        need(integer(block['chain_id']) and block['chain_id'] == chain and block['hash'] == raw['hash'])
        number = quantity(raw['number'])
        need(integer(block['number']) and start <= number <= end and number == block['number'])
        need(block['parent_hash'] == raw['parentHash'] and block['block_timestamp'] == quantity(raw['timestamp']))
        need(block['block_time_utc'] == datetime.fromtimestamp(quantity(raw['timestamp']), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        need(block['status'] in ('canonical', 'orphaned') and type(block['synthetic']) is int
             and block['synthetic'] in (0, 1) and bool(block['synthetic']) == manifest['synthetic'])
        key = (chain, block['hash'])
        need(key not in block_map)
        block_map[key] = block
        need(isinstance(raw['transactions'], list))
        if block['status'] != 'canonical':
            continue
        need(number not in canonical)
        canonical[number] = block
        indices = set()
        for tx in raw['transactions']:
            need(isinstance(tx, dict))
            index = quantity(tx['transactionIndex'])
            need(tx['blockHash'] == block['hash'] and quantity(tx['blockNumber']) == number and index not in indices)
            indices.add(index)
            key = (chain, block['hash'], tx['hash'])
            need(key not in tx_map)
            tx_map[key] = tx
        need(indices == set(range(len(raw['transactions']))))
    need(bool(canonical), Reason.INCOMPLETE)
    previous = None
    for number, block in sorted(canonical.items()):
        if previous and number == previous['number'] + 1:
            need(block['parent_hash'] == previous['hash'])
        previous = block
    receipt_map, log_keys = {}, set()
    for item in receipts:
        need(all(integer(item.get(k)) for k in ('chain_id', 'block_number', 'tx_index')), Reason.SCHEMA)
        key = (item['chain_id'], item['block_hash'], item['tx_hash'])
        need(key in tx_map and key not in receipt_map)
        raw, tx = item['raw_json'], tx_map[key]
        need(isinstance(raw, dict) and raw_hash(raw) == item['raw_sha256'])
        need(all(k in raw for k in ('transactionHash', 'blockHash', 'blockNumber', 'transactionIndex', 'status', 'logs')), Reason.INCOMPLETE)
        need(raw['transactionHash'] == key[2] and raw['blockHash'] == key[1])
        need(quantity(raw['blockNumber']) == item['block_number'] == quantity(tx['blockNumber']))
        need(quantity(raw['transactionIndex']) == item['tx_index'] == quantity(tx['transactionIndex']))
        need(quantity(raw['status']) in (0, 1) and isinstance(raw['logs'], list))
        if quantity(raw['status']) == 0:
            need(not raw['logs'])
        if tx.get('to') is None and quantity(tx['value']) > 0 and quantity(raw['status']) == 1:
            need(isinstance(raw.get('contractAddress'), str) and bool(raw['contractAddress']), Reason.INCOMPLETE)
        for log in raw['logs']:
            need(isinstance(log, dict) and all(k in log for k in ('address', 'topics', 'data', 'logIndex',
                 'blockHash', 'blockNumber', 'transactionHash', 'transactionIndex')), Reason.INCOMPLETE)
            need(log['blockHash'] == key[1] and log['transactionHash'] == key[2])
            need(quantity(log['blockNumber']) == item['block_number'] and quantity(log['transactionIndex']) == item['tx_index'])
            need(log.get('removed', False) is False and isinstance(log['topics'], list))
            need(re.fullmatch(r'0x[0-9a-fA-F]{40}', log['address']) is not None)
            need(all(isinstance(t, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', t) for t in log['topics']))
            need(isinstance(log['data'], str) and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', log['data']))
            if len(log['topics']) == 3 and log['topics'][0].lower() == ERC20_TRANSFER_TOPIC0:
                need(len(log['data']) == 66)
            lk = (key[0], key[1], quantity(log['logIndex']))
            need(lk not in log_keys)
            log_keys.add(lk)
        receipt_map[key] = raw
    need(set(receipt_map) == set(tx_map), Reason.INCOMPLETE)
    fields = ('chain_id', 'block_number', 'block_hash', 'block_timestamp', 'tx_hash', 'log_index',
              'asset_id', 'from_addr', 'to_addr', 'amount_raw', 'synthetic')
    def transfer_tuple(row):
        return tuple(str(row[k]).lower() for k in fields)
    expected = []
    for block in canonical.values():
        rcs = {k[2].lower(): r for k, r in receipt_map.items() if k[:2] == (chain, block['hash'])}
        expected.extend(extract_transfers(chain, block['raw_json'], rcs, block['synthetic']))
    need(sorted(map(transfer_tuple, expected)) == sorted(map(transfer_tuple, transfers)))
    # Compare canonical timeline content, including counts, not just file hashes.
    wanted = []
    for block in canonical.values():
        ts, n = block['block_time_utc'], str(block['number'])
        wanted.append((ts, n, 'BLOCK', '', '', '', '', '', 'canonical'))
        for tx in block['raw_json']['transactions']:
            wanted.append((ts, n, 'TX', tx['hash'], tx['from'] or '', tx['to'] or '',
                           'NATIVE', str(quantity(tx['value'])), 'mined'))
    for t in expected:
        b = block_map[(chain, t['block_hash'])]
        wanted.append((b['block_time_utc'], str(t['block_number']), 'TRANSFER', t['tx_hash'],
                       t['from_addr'], t['to_addr'], t['asset_id'], t['amount_raw'], 'success'))
    columns = ('timestamp_utc', 'block_number', 'event_type', 'tx_hash', 'from_addr', 'to_addr', 'asset_id', 'amount_raw', 'status')
    need(sorted(wanted) == sorted(tuple(row[k] for k in columns) for row in timeline))
    counts = manifest['counts']
    for k, actual in {'total_blocks': len(blocks), 'canonical_blocks': len(canonical),
                      'orphaned_blocks': len(blocks) - len(canonical), 'transactions': len(tx_map),
                      'asset_transfers': len(transfers), 'audit_events': len(audits), 'receipts': len(receipts)}.items():
        need(type(counts.get(k)) is int and counts[k] == actual)
    gaps, last = [], start
    for number in sorted(canonical):
        if number > last:
            gaps.append([last, number - 1])
        last = number + 1
    if last <= end:
        gaps.append([last, end])
    integrity = manifest['integrity_checks']
    need(integrity['gaps'] == gaps and type(integrity['gaps_count']) is int
         and integrity['gaps_count'] == sum(b-a+1 for a, b in gaps))
    for k in ('verify_local', 'verify_derived'):
        need(integrity[k]['status'] == 'PASSED' and type(integrity[k]['mismatches']) is int and integrity[k]['mismatches'] == 0)
    final = manifest['finalization']
    need(integer(final['confirmations']) and integer(final['observed_head']))
    need(final['observed_head'] >= max(canonical))
    threshold = final['observed_head'] - final['confirmations'] + 1
    unfinalized = [n for n in sorted(canonical) if n >= threshold]
    need(final['unfinalized_blocks'] == unfinalized and final['unfinalized_blocks_count'] == len(unfinalized))
    need(type(final['is_finalized']) is bool and final['is_finalized'] == (not unfinalized))
    return {'gaps_count': integrity['gaps_count'], 'is_finalized': final['is_finalized'],
            'canonical_blocks': len(canonical)}


def verify_package(manifest_path_or_dir, db_path=None):
    digest = version = None
    initial = None
    coverage = 'LIMITED'
    try:
        given = Path(manifest_path_or_dir).absolute()
        # Refuse reparse ancestors too, before opening manifest or payload files.
        for parent in reversed(given.parents):
            _no_link(parent)
        _no_link(given)
        root = given if given.is_dir() else given.parent
        need(given.is_dir() or given.name == 'manifest.json', Reason.PATH)
        manifest_file = safe_path(root, 'manifest.json')
        initial = inventory(root)
        raw, digest = read_stable(manifest_file, 1024 * 1024)
        m = parse_json(raw.decode('utf-8'))
        need(isinstance(m, dict), Reason.SCHEMA)
        supplied_version = m.get('manifest_version')
        if supplied_version not in ('1.0.0', '1.1.0'):
            if supplied_version is None or not isinstance(supplied_version, str):
                raise InvalidPackage(Reason.SCHEMA)
            raise VerificationError(Reason.VERSION)
        version = supplied_version  # Never echo arbitrary unsupported-version text.
        files = m.get('files')
        need(isinstance(files, list) and bool(files), Reason.SCHEMA)
        normalized, paths = {}, {}
        for item in files:
            need(isinstance(item, dict), Reason.SCHEMA)
            name = normalized_path(item.get('path'))
            key = name.casefold()  # Conservative, deterministic across platforms.
            need(key not in normalized and key != 'manifest.json', Reason.DUPLICATE)
            normalized[key] = name
            paths[name] = item
        for item in files:
            need(integer(item.get('size_bytes')) and isinstance(item.get('sha256'), str)
                 and HEX64.fullmatch(item['sha256']), Reason.SCHEMA)
        required = BASE_FILES | ({'raw_receipts.jsonl'} if version == '1.1.0' else set())
        need(required.issubset(paths), Reason.SCHEMA)
        for name, kind in {'case_id': str, 'chain_id': int, 'synthetic': bool, 'block_range': dict,
                           'exported_at': str, 'operator': str, 'rpc_label': str, 'block_timestamps_utc': dict,
                           'software': dict, 'counts': dict, 'integrity_checks': dict, 'finalization': dict,
                           'sanitized_config': dict}.items():
            need(type(m.get(name)) is kind, Reason.SCHEMA)
        need(integer(m['chain_id']) and all(integer(m['block_range'].get(k)) for k in ('start_block', 'end_block')),
             Reason.SCHEMA)
        need(m['block_range']['start_block'] <= m['block_range']['end_block'], Reason.SCHEMA)
        need(isinstance(m.get('package_digest'), str) and HEX64.fullmatch(m['package_digest']), Reason.SCHEMA)
        need(package_digest(files) == m['package_digest'], Reason.DIGEST)
        cfg = m['sanitized_config']
        need(type(cfg.get('RPC_SYNTHETIC')) is bool and cfg['RPC_SYNTHETIC'] == m['synthetic'], Reason.SYNTHETIC)
        need(cfg.get('RPC_LABEL') == m.get('rpc_label'), Reason.SOURCE_LABEL)
        if version == '1.1.0':
            need(m.get('coverage') == 'FULL' and m.get('git_state') in ('CLEAN', 'DIRTY'), Reason.SCHEMA)
            need(type(m.get('working_tree_dirty')) is bool and m['working_tree_dirty'] == (m['git_state'] == 'DIRTY'), Reason.SCHEMA)
            need(isinstance(m.get('export_commit'), str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', m['export_commit']), Reason.SCHEMA)
            need(m['software'].get('commit_hash') == m['export_commit'] and
                 m['software'].get('working_tree_dirty') is m['working_tree_dirty'], Reason.SCHEMA)
        issues, content = [], {}
        if set(paths) - set(initial):
            issues.append(Reason.MISSING)
        if set(initial) - set(paths) - {'manifest.json'}:
            issues.append(Reason.EXTRA)
        total = 0
        for name, item in paths.items():
            if name not in initial:
                continue
            try:
                payload, file_hash = read_stable(safe_path(root, name))
            except FileNotFoundError:
                raise VerificationError(Reason.UNSTABLE) from None
            total += len(payload)
            if total > MAX_PACKAGE_BYTES:
                raise VerificationError(Reason.RESOURCE)
            if len(payload) != item['size_bytes']:
                issues.append(Reason.SIZE)
            if file_hash.lower() != item['sha256'].lower():
                issues.append(Reason.HASH)
            content[name] = payload
        if db_path is not None:
            # Read-only DB access: never create/migrate a missing database.
            uri = Path(db_path).absolute().as_uri() + '?mode=ro'
            with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
                row = conn.execute('SELECT 1 FROM evidence_exports WHERE case_id=? AND lower(manifest_sha256)=?',
                                   (m['case_id'], digest)).fetchone()
                if not row:
                    issues.append(Reason.DB)
        details = {}
        if not issues and version == '1.1.0':
            details = validate_records(m, jsonl(content['raw_blocks.jsonl']), jsonl(content['raw_receipts.jsonl']),
                                       csv_rows(content['asset_transfers.csv']), csv_rows(content['timeline.csv']),
                                       jsonl(content['audit_events.jsonl']))
            coverage = 'FULL'
        if inventory(root) != initial:
            raise VerificationError(Reason.UNSTABLE)
        if issues:
            return VerifyResult('INVALID', issues[0], 'LIMITED', digest, version,
                                {'violations': list(dict.fromkeys(c.value for c in issues))})
        return VerifyResult('VALID', Reason.OK, coverage, digest, version, details)
    except InvalidPackage as exc:
        return VerifyResult('INVALID', exc.code, 'LIMITED', digest, version)
    except VerificationError as exc:
        return VerifyResult('ERROR', exc.code, 'LIMITED', digest, version)
    except FileNotFoundError:
        return VerifyResult('ERROR' if initial is not None else 'INVALID',
                            Reason.UNSTABLE if initial is not None else Reason.MISSING, 'LIMITED', digest, version)
    except (OSError, sqlite3.Error):
        return VerifyResult('ERROR', Reason.IO, 'LIMITED', digest, version)
    except (MemoryError, RecursionError):
        return VerifyResult('ERROR', Reason.RESOURCE, 'LIMITED', digest, version)
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, UnicodeError, csv.Error):
        return VerifyResult('INVALID', Reason.SCHEMA, 'LIMITED', digest, version)
