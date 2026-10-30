"""Phase 2A security tests. Red cases exercise existing APIs, not missing APIs."""
import contextlib
import hashlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest

from forensics import evidence as ev
from test_evidence_p2 import populate_sample_db


@pytest.fixture
def sample(tmp_path):
    db = tmp_path / 'sample.db'
    populate_sample_db(str(db), 3)
    # Complete RPC identity metadata, previously omitted by the old P2 fixture.
    with contextlib.closing(sqlite3.connect(db)) as conn:
        for tx, block, raw in conn.execute('SELECT tx_hash, block_hash, raw_json FROM receipts').fetchall():
            receipt = json.loads(raw)
            number = conn.execute('SELECT block_number FROM transactions WHERE tx_hash=?', (tx,)).fetchone()[0]
            receipt.update(blockNumber=hex(number), transactionIndex='0x0', contractAddress=None)
            conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=? WHERE tx_hash=? AND block_hash=?',
                         (json.dumps(receipt), ev.sha(receipt), tx, block))
        conn.commit()
    return db


def exported(tmp_path, db):
    pkg = tmp_path / 'package'
    ev.export_evidence('test-2a', 0, 2, str(pkg), str(db))
    return pkg


def rewrite(pkg, change):
    path = pkg / 'manifest.json'
    m = json.loads(path.read_text(encoding='utf-8'))
    change(m)
    path.write_text(json.dumps(m), encoding='utf-8')


def test_red_missing_file_hash_rejected(tmp_path, sample):
    pkg = exported(tmp_path, sample)
    rewrite(pkg, lambda m: (m.pop('package_digest'), m['files'][0].pop('sha256')))
    assert ev.verify_manifest(str(pkg))[0] is False


def test_red_duplicate_path_rejected(tmp_path, sample):
    pkg = exported(tmp_path, sample)
    def duplicate(m):
        m['files'].append(dict(m['files'][0]))
        m['package_digest'] = hashlib.sha256(json.dumps(
            [[f['path'], f['sha256']] for f in sorted(m['files'], key=lambda f: f['path'])],
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    rewrite(pkg, duplicate)
    assert ev.verify_manifest(str(pkg))[0] is False


def test_red_unsupported_version_not_valid(tmp_path, sample):
    pkg = exported(tmp_path, sample)
    rewrite(pkg, lambda m: m.update(manifest_version='99.0.0'))
    assert ev.verify_manifest(str(pkg))[0] is False


def test_red_nested_manifest_is_extra(tmp_path, sample):
    pkg = exported(tmp_path, sample)
    (pkg / 'nested').mkdir()
    (pkg / 'nested/manifest.json').write_text('{}')
    assert ev.verify_manifest(str(pkg))[0] is False


@pytest.mark.parametrize('corruption', ['raw_hash', 'derived', 'receipt_missing'])
def test_red_export_failed_integrity_rejected(tmp_path, sample, corruption):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        if corruption == 'raw_hash':
            conn.execute("UPDATE receipts SET raw_sha256='bad'")
        elif corruption == 'derived':
            conn.execute("UPDATE asset_transfers SET amount_raw='999'")
        else:
            conn.execute('DELETE FROM receipts')
        conn.commit()
    with pytest.raises((ValueError, RuntimeError)):
        exported(tmp_path, sample)
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0] == 0


def test_red_existing_destination_rejected(tmp_path, sample):
    pkg = exported(tmp_path, sample)
    original = (pkg / 'manifest.json').read_bytes()
    with pytest.raises((ValueError, RuntimeError, FileExistsError)):
        ev.export_evidence('different-case', 0, 2, str(pkg), str(sample))
    assert (pkg / 'manifest.json').read_bytes() == original


def test_red_export_records_are_append_only(tmp_path, sample):
    exported(tmp_path, sample)
    ev.export_evidence('test-2a', 0, 2, str(tmp_path / 'second'), str(sample), operator='second')
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0] == 2


def test_red_git_error_is_not_clean(monkeypatch):
    monkeypatch.setattr(ev.subprocess, 'run', Mock(side_effect=OSError('synthetic-error')))
    with pytest.raises(RuntimeError):
        ev.is_working_tree_dirty()


def rehash(pkg):
    from forensics.integrity import package_digest
    def update(m):
        for f in m['files']:
            data = (pkg / f['path']).read_bytes()
            f.update(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        m['package_digest'] = package_digest(m['files'])
    rewrite(pkg, update)


@pytest.mark.parametrize('mutation,expected', [
    ('bool_size', 'INVALID'), ('negative_size', 'INVALID'), ('bad_hash', 'INVALID'),
    ('empty_files', 'INVALID'), ('digest_missing', 'INVALID'), ('digest_wrong', 'INVALID'),
    ('version', 'ERROR'), ('counts', 'INVALID'), ('synthetic_type', 'INVALID'),
    ('chain', 'INVALID'), ('provenance', 'INVALID')])
def test_manifest_schema_and_semantics(tmp_path, sample, mutation, expected):
    from forensics.integrity import verify_package
    pkg = exported(tmp_path, sample)
    def change(m):
        if mutation == 'bool_size': m['files'][0]['size_bytes'] = True
        if mutation == 'negative_size': m['files'][0]['size_bytes'] = -1
        if mutation == 'bad_hash': m['files'][0]['sha256'] = 'abc'
        if mutation == 'empty_files': m['files'] = []
        if mutation == 'digest_missing': m.pop('package_digest')
        if mutation == 'digest_wrong': m['package_digest'] = 'a'*64
        if mutation == 'version': m['manifest_version'] = '2.0.0'
        if mutation == 'counts': m['counts']['transactions'] += 1
        if mutation == 'synthetic_type': m['synthetic'] = 'false'
        if mutation == 'chain': m['source_chain_id'] = 1
        if mutation == 'provenance': m['export_commit'] = 'not-a-commit'
    rewrite(pkg, change)
    assert verify_package(pkg).status == expected


@pytest.mark.parametrize('path', ['/absolute', '../outside', 'C:secret', 'C:/secret',
    '//server/share', 'file:stream', 'NUL', 'con.txt', 'COM1.json', 'LPT¹',
    'trailing.', 'trailing ', 'x/../y', 'x//y', './raw_blocks.jsonl', 'x\x00y'])
def test_path_security_before_open(tmp_path, sample, monkeypatch, path):
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    rewrite(pkg, lambda m: m['files'].append({'path': path, 'size_bytes': 0, 'sha256': 'a'*64}))
    real = core.read_stable
    opened = []
    def record(p, *args):
        opened.append(Path(p).name)
        return real(p, *args)
    monkeypatch.setattr(core, 'read_stable', record)
    result = core.verify_package(pkg)
    assert result.status == 'INVALID' and result.reason_code == core.Reason.PATH
    assert opened == ['manifest.json']


@pytest.mark.parametrize('alias', ['RAW_BLOCKS.JSONL', 'raw_blocks.jsonl'])
def test_duplicate_alias(tmp_path, sample, alias):
    from forensics.integrity import verify_package, Reason
    pkg = exported(tmp_path, sample)
    rewrite(pkg, lambda m: m['files'].append({'path': alias, 'size_bytes': 0, 'sha256': 'a'*64}))
    assert verify_package(pkg).reason_code == Reason.DUPLICATE


def test_reparse_escape_not_read(tmp_path, sample, monkeypatch):
    import os
    import subprocess
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret.txt').write_text('synthetic-secret')
    link = pkg / 'escape'
    try:
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            assert os.name == 'nt'
            result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)], capture_output=True)
            assert result.returncode == 0, 'Cannot exercise reparse test'
        opened = []
        real = core.read_stable
        def record(p, *a):
            opened.append(Path(p).resolve())
            return real(p, *a)
        monkeypatch.setattr(core, 'read_stable', record)
        result = core.verify_package(pkg)
        assert result.status == 'INVALID' and result.reason_code == core.Reason.PATH
        assert not any(p.is_relative_to(outside) for p in opened)
    finally:
        if os.path.lexists(link):
            if link.is_symlink(): link.unlink()
            else: os.rmdir(link)


def test_legacy_limited_without_mutation():
    from forensics.integrity import verify_package
    pkg = Path(__file__).resolve().parents[1] / 'results/p2/case-anvil-p1-001'
    before = {p.name: p.read_bytes() for p in pkg.iterdir() if p.is_file()}
    result = verify_package(pkg)
    assert result.status == 'VALID' and result.coverage == 'LIMITED'
    assert before == {p.name: p.read_bytes() for p in pkg.iterdir() if p.is_file()}


@pytest.mark.parametrize('failure', ['io', 'unstable', 'resource'])
def test_verifier_operational_errors_are_not_mismatch(tmp_path, sample, monkeypatch, failure):
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    if failure == 'io':
        monkeypatch.setattr(core.os, 'open', Mock(side_effect=PermissionError('fake-token-in-path')))
        expected = core.Reason.IO
    elif failure == 'resource':
        monkeypatch.setattr(core, 'MAX_PACKAGE_BYTES', 1)
        expected = core.Reason.RESOURCE
    else:
        original = core.read_stable
        def changing(p, *a):
            result = original(p, *a)
            if Path(p).name == 'raw_blocks.jsonl':
                with Path(p).open('ab') as out: out.write(b' ')
            return result
        monkeypatch.setattr(core, 'read_stable', changing)
        expected = core.Reason.UNSTABLE
    result = core.verify_package(pkg)
    assert result.status == 'ERROR' and result.reason_code == expected
    assert 'fake-token-in-path' not in repr(result)


def test_changed_handle_metadata_rejected(tmp_path, sample, monkeypatch):
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    original, count = core.os.fstat, 0
    def changed(fd):
        nonlocal count
        count += 1
        value = original(fd)
        if count == 2:
            return type('ChangedStat', (), dict(st_dev=value.st_dev, st_ino=value.st_ino,
                st_size=value.st_size+1, st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns))()
        return value
    monkeypatch.setattr(core.os, 'fstat', changed)
    assert core.verify_package(pkg).reason_code == core.Reason.UNSTABLE


@pytest.mark.parametrize('kind', ['receipt_relation', 'parent', 'derived', 'receipt_missing_fields'])
def test_rehashed_semantic_tampering_rejected(tmp_path, sample, kind):
    from forensics.integrity import verify_package
    pkg = exported(tmp_path, sample)
    if kind == 'derived':
        path = pkg/'asset_transfers.csv'
        path.write_text(path.read_text().replace('1000000000000000000', '999999'), encoding='utf-8', newline='\n')
    else:
        path = pkg/('raw_blocks.jsonl' if kind == 'parent' else 'raw_receipts.jsonl')
        records = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        record = records[1]
        if kind == 'parent':
            record['parent_hash'] = record['raw_json']['parentHash'] = '0x'+'f'*64
        elif kind == 'receipt_relation':
            record['raw_json']['transactionHash'] = '0x'+'f'*64
        else:
            record['raw_json'].pop('logs')
        record['raw_sha256'] = ev.sha(record['raw_json'])
        path.write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8', newline='\n')
    rehash(pkg)
    assert verify_package(pkg).status == 'INVALID'


def test_publish_race_keeps_destination(tmp_path, sample, monkeypatch):
    from forensics import exporter
    original = exporter.publish_no_replace
    def raced(stage, target):
        target.mkdir()
        (target/'sentinel').write_text('existing')
        original(stage, target)
    monkeypatch.setattr(exporter, 'publish_no_replace', raced)
    with pytest.raises(FileExistsError): exported(tmp_path, sample)
    assert (tmp_path/'package/sentinel').read_text() == 'existing'
    assert list((tmp_path/'package').iterdir()) == [tmp_path/'package/sentinel']
    assert not list(tmp_path.glob('.evidence-stage-*'))


def test_failed_staging_does_not_publish(tmp_path, sample, monkeypatch):
    from forensics import exporter, integrity
    monkeypatch.setattr(exporter, 'verify_package', lambda _: integrity.VerifyResult('INVALID', integrity.Reason.HASH))
    with pytest.raises(ValueError): exported(tmp_path, sample)
    assert not (tmp_path/'package').exists()
    assert not list(tmp_path.glob('.evidence-stage-*'))


def test_failed_insert_retains_published_package(tmp_path, sample, monkeypatch):
    from forensics import schemas, integrity
    monkeypatch.setattr(schemas, 'init_db', Mock(side_effect=sqlite3.OperationalError('fake-db-password')))
    with pytest.raises(RuntimeError) as error: exported(tmp_path, sample)
    assert 'fake-db-password' not in str(error.value)
    assert integrity.verify_package(tmp_path/'package').status == 'VALID'
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0] == 0


def test_source_chain_selector_and_orphans(tmp_path, sample):
    from forensics.integrity import verify_package
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        # An orphan branch with retained historical raw evidence and tx rows.
        b = list(conn.execute('SELECT * FROM blocks WHERE number=1').fetchone())
        old = b[2]; b[2] = '0x'+'e'*64; b[8] = 'orphaned'
        raw = json.loads(b[9]); raw['hash'] = b[2]
        for t in raw['transactions']: t['blockHash'] = b[2]
        b[9], b[10] = json.dumps(raw), ev.sha(raw)
        conn.execute('INSERT INTO blocks VALUES('+','.join('?'*len(b))+')', b)
        t = list(conn.execute('SELECT * FROM transactions WHERE block_hash=?', (old,)).fetchone())
        t[2] = b[2]; conn.execute('INSERT INTO transactions VALUES('+','.join('?'*len(t))+')', t)
        other = b.copy(); other[0] = 1
        conn.execute('INSERT INTO blocks VALUES('+','.join('?'*len(other))+')', other)
        conn.commit()
    with pytest.raises(ValueError): exported(tmp_path, sample)
    m = ev.export_evidence('selected', 0, 2, str(tmp_path/'selected'), str(sample), chain_id=31337)
    assert m['counts']['transactions'] == 3 and m['counts']['orphaned_blocks'] == 1
    assert verify_package(tmp_path/'selected').coverage == 'FULL'


def test_audit_exact_selection_and_redaction(tmp_path, sample):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        for ref in ('block:10', 'block:100', 'loop', 'range:10-20', 'chain:1'):
            conn.execute('INSERT INTO audit_events(action,object_ref,metadata) VALUES(?,?,?)',
                         ('COLLECT_REORG', ref, json.dumps({'password': 'synthetic-password', 'error': 'https://fake/token'})))
        conn.commit()
    pkg = exported(tmp_path, sample)
    data = (pkg/'audit_events.jsonl').read_text(encoding='utf-8')
    assert len(data.splitlines()) == 3 and 'block:10' not in data and 'synthetic-password' not in data
    assert json.loads((pkg/'manifest.json').read_text())['audit_selection']['excluded_unlinked'] == 5


def test_snapshot_reads_remain_consistent(tmp_path, sample, monkeypatch):
    from forensics import exporter
    with contextlib.closing(sqlite3.connect(sample)) as conn: conn.execute('PRAGMA journal_mode=WAL')
    original = exporter._snapshot
    changed = False
    def snapshot(conn, *args):
        def trace(statement):
            nonlocal changed
            if 'SELECT * FROM receipts' in statement and not changed:
                with contextlib.closing(sqlite3.connect(sample)) as writer:
                    writer.execute("UPDATE asset_transfers SET amount_raw='777'")
                    writer.commit()
                changed = True
        conn.set_trace_callback(trace)
        return original(conn, *args)
    monkeypatch.setattr(exporter, '_snapshot', snapshot)
    pkg = exported(tmp_path, sample)
    assert changed and '777' not in (pkg/'asset_transfers.csv').read_text()


@pytest.mark.parametrize('mode,exit_code,coverage', [('full',0,'FULL'),('legacy',0,'LIMITED'),('bad',1,'LIMITED'),('version',2,'LIMITED')])
def test_cli_status_and_coverage(tmp_path, sample, mode, exit_code, coverage):
    import os, subprocess, sys
    pkg = exported(tmp_path, sample)
    if mode == 'legacy':
        rewrite(pkg, lambda m: (m.update(manifest_version='1.0.0'), m.update(files=[f for f in m['files'] if f['path'] != 'raw_receipts.jsonl'])))
        (pkg/'raw_receipts.jsonl').unlink()
        rehash(pkg)
    if mode == 'bad': (pkg/'timeline.csv').write_bytes(b'broken')
    if mode == 'version': rewrite(pkg, lambda m: m.update(manifest_version='future'))
    env = {k:v for k,v in os.environ.items() if k.upper() in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP','USERPROFILE')}
    env.update(PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONUTF8='1')
    p = subprocess.run([sys.executable,'-m','forensics.cli','verify-manifest',str(pkg)],cwd=tmp_path,
                       env=env,capture_output=True,encoding='utf-8')
    assert p.returncode == exit_code and 'coverage='+coverage in p.stdout


def test_canaries_never_echo_in_verifier_errors(tmp_path, sample, monkeypatch, capsys, caplog):
    from forensics import integrity
    pkg = exported(tmp_path, sample)
    canaries = ['a1'*32, '0x'+'b2'*32, 'fake-password-canary',
                'alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima',
                'https://provider.invalid/fake-token-canary']
    monkeypatch.setattr(integrity.os, 'open', Mock(side_effect=OSError(' '.join(canaries))))
    result = integrity.verify_package(pkg)
    captured = capsys.readouterr()
    visible = repr(result) + captured.out + captured.err + caplog.text
    assert result.status == 'ERROR'
    assert all(secret not in visible for secret in canaries)


@pytest.mark.parametrize('mode', ['filtered_receipt', 'transaction_hash', 'missing_db_log'])
def test_incomplete_or_inconsistent_raw_export_rejected(tmp_path, sample, mode):
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        if mode == 'filtered_receipt':
            raw = {'status': '0x1'}
            conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=?', (json.dumps(raw), ev.sha(raw)))
        elif mode == 'transaction_hash':
            conn.execute("UPDATE transactions SET raw_sha256='bad'")
        else:
            tx, block, raw_text = conn.execute('SELECT tx_hash,block_hash,raw_json FROM receipts LIMIT 1').fetchone()
            raw = json.loads(raw_text)
            raw['logs'] = [{'address':'0x'+'1'*40, 'topics':[], 'data':'0x', 'logIndex':'0x0',
                'blockNumber':raw['blockNumber'], 'transactionIndex':'0x0', 'blockHash':block, 'transactionHash':tx}]
            conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=? WHERE tx_hash=?',
                         (json.dumps(raw), ev.sha(raw), tx))
        conn.commit()
    with pytest.raises((ValueError, RuntimeError)): exported(tmp_path, sample)
    assert not (tmp_path/'package').exists()


def test_consistent_raw_and_hash_edit_is_not_independent_authenticity(tmp_path, sample):
    from forensics.integrity import verify_package
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        for tx, text in conn.execute('SELECT tx_hash,raw_json FROM receipts').fetchall():
            raw = json.loads(text); raw['gasUsed'] = raw['cumulativeGasUsed'] = '0x5209'
            conn.execute('UPDATE receipts SET raw_json=?,raw_sha256=?,gas_used=21001 WHERE tx_hash=?',
                         (json.dumps(raw), ev.sha(raw), tx))
        conn.commit()
    # No independent RPC anchor exists here. Consistency is not chain truth.
    assert verify_package(exported(tmp_path, sample)).status == 'VALID'


def test_manifest_bytes_read_once_and_hash_matches(tmp_path, sample, monkeypatch):
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    real, reads = core.read_stable, []
    def record(path, *args):
        reads.append(Path(path).name)
        return real(path, *args)
    monkeypatch.setattr(core, 'read_stable', record)
    result = core.verify_package(pkg)
    assert result.status == 'VALID' and reads.count('manifest.json') == 1
    assert result.manifest_sha256 == hashlib.sha256((pkg/'manifest.json').read_bytes()).hexdigest()


def test_deleted_after_inventory_is_unstable(tmp_path, sample, monkeypatch):
    from forensics import integrity as core
    pkg = exported(tmp_path, sample)
    real = core.read_stable
    def remove(path, *args):
        if Path(path).name == 'raw_blocks.jsonl': Path(path).unlink()
        return real(path, *args)
    monkeypatch.setattr(core, 'read_stable', remove)
    result = core.verify_package(pkg)
    assert result.status == 'ERROR' and result.reason_code == core.Reason.UNSTABLE


def test_unknown_version_does_not_echo_arbitrary_text(tmp_path, sample):
    from forensics.integrity import verify_package
    pkg = exported(tmp_path, sample)
    rewrite(pkg, lambda m: m.update(manifest_version='fake-secret-version'))
    result = verify_package(pkg)
    assert result.status == 'ERROR' and 'fake-secret-version' not in repr(result)


@pytest.mark.parametrize('failure', ['empty_destination', 'publish_io'])
def test_publish_failure_preserves_destination_and_db(tmp_path, sample, monkeypatch, failure):
    from forensics import exporter
    if failure == 'empty_destination':
        (tmp_path/'package').mkdir()
        expected = FileExistsError
    else:
        monkeypatch.setattr(exporter, 'publish_no_replace', Mock(side_effect=OSError('fake-publish-token')))
        expected = RuntimeError
    with pytest.raises(expected) as error: exported(tmp_path, sample)
    assert 'fake-publish-token' not in str(error.value)
    assert not list(tmp_path.glob('.evidence-stage-*'))
    if failure == 'empty_destination': assert list((tmp_path/'package').iterdir()) == []
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        assert conn.execute('SELECT COUNT(*) FROM evidence_exports').fetchone()[0] == 0


def test_determinism_and_export_id_contains_manifest_hash(tmp_path, sample):
    first = exported(tmp_path, sample)
    second = tmp_path/'second'
    ev.export_evidence('test-2a', 0, 2, str(second), str(sample))
    manifests = [json.loads((p/'manifest.json').read_text(encoding='utf-8')) for p in (first, second)]
    assert manifests[0]['package_digest'] == manifests[1]['package_digest']
    for file in manifests[0]['files']:
        assert (first/file['path']).read_bytes() == (second/file['path']).read_bytes()
    with contextlib.closing(sqlite3.connect(sample)) as conn:
        rows = conn.execute('SELECT export_id,manifest_sha256 FROM evidence_exports').fetchall()
    assert len(rows) == 2 and len({r[0] for r in rows}) == 2
    assert all(r[0].startswith('exp-test-2a-'+r[1][:12]+'-') for r in rows)


@pytest.mark.parametrize('git_mode', ['CLEAN', 'DIRTY', 'UNKNOWN'])
def test_export_real_git_policy(tmp_path, sample, monkeypatch, git_mode):
    from forensics import provenance
    from test_provenance_2a import command, commit
    repo = tmp_path/'git-root'; repo.mkdir()
    if git_mode != 'UNKNOWN':
        command(repo, 'init', '-q')
        (repo/'source.py').write_text('source')
        commit(repo, 'isolated source')
        if git_mode == 'DIRTY': (repo/'source.py').write_text('changed')
    monkeypatch.setattr(provenance, '__file__', str(repo/'forensics/provenance.py'))
    if git_mode == 'UNKNOWN':
        with pytest.raises(RuntimeError, match='GIT_UNKNOWN'): exported(tmp_path, sample)
        assert not (tmp_path/'package').exists()
    else:
        pkg = exported(tmp_path, sample)
        m = json.loads((pkg/'manifest.json').read_text(encoding='utf-8'))
        assert m['git_state'] == git_mode and m['working_tree_dirty'] == (git_mode == 'DIRTY')


def test_export_cli_errors_hide_all_canary_classes(tmp_path, sample, monkeypatch, capsys):
    from forensics import cli
    canaries = ['ab'*32, '0x'+'cd'*32, 'fake-password-canary',
        'alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima',
        'https://provider.invalid/fake-api-token']
    monkeypatch.setattr(cli, 'export_evidence', Mock(side_effect=PermissionError(' '.join(canaries))))
    args = cli.build_parser().parse_args(['export-evidence','--case-id','safe','--start-block','0',
                                         '--end-block','2','--db',str(sample)])
    assert cli.cli_export_evidence(args) == 1
    captured = capsys.readouterr()
    assert all(s not in captured.out+captured.err for s in canaries)


def test_audit_explicit_chain_overrides_legacy_inference():
    from forensics.exporter import select_audits
    block_hash = '0x'+'1'*64
    block = {'number':1, 'hash':block_hash}
    def row(ref, metadata):
        return {'id':1, 'ts':'safe', 'action':'COLLECT_BLOCK', 'object_ref':ref, 'metadata':json.dumps(metadata)}
    for db_chains in ({31337}, {31337, 1}):
        for ref in ('block:1','range:0-2','chain:31337'):
            selected, excluded = select_audits([row(ref, {'hash':block_hash, 'chain_id':1})],
                                                31337,[block],0,2,db_chains)
            assert selected == [] and excluded == 1
    selected, excluded = select_audits([row('block:1', {'hash':block_hash})],31337,[block],0,2,{31337,1})
    assert selected == [] and excluded == 1
    selected, excluded = select_audits([row('block:'+block_hash, {'chain_id':31337})],31337,[block],0,2,{31337,1})
    assert len(selected) == 1 and excluded == 0
