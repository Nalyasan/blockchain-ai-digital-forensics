"""Bridge tests use synthetic package bytes and a stubbed P3 boundary, no RPC."""
import csv
import hashlib
import io
import json

import pytest

from forensics.rules import anchored
from forensics.onchain import OnchainVerification


@pytest.fixture
def package(tmp_path, monkeypatch):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(anchored.TRANSFER_COLUMNS)
    writer.writerow([1, 1, 2, '0xblock', 1700000000, '0xtx', -1, 'NATIVE',
                     '0x' + 'a' * 40, '0x' + 'b' * 40, str(20 * 10**18), 1])
    payloads = {'asset_transfers.csv': stream.getvalue().encode(),
                'raw_blocks.jsonl': json.dumps({'chain_id': 1, 'hash': '0xblock', 'status': 'canonical'}).encode()}
    manifest = {'chain_id': 1, 'case_id': 'bridge-test', 'block_range': {'start_block': 0, 'end_block': 3},
                'files': []}
    for name, data in payloads.items():
        (tmp_path / name).write_bytes(data)
        manifest['files'].append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)})
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest), encoding='utf-8')
    verification = OnchainVerification('MATCH', 'OK', {
        'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'source_chain_id': 1, 'anchor_chain_id': 31337, 'evidence_id': 7,
    })
    monkeypatch.setattr(anchored.onchain, 'verify_onchain_evidence', lambda *a, **k: verification)
    return path, verification


def run(path, **kwargs):
    options = dict(contract_address='0x' + 'c' * 40, rpc_url='http://127.0.0.1:8545',
                   anchor_chain_id=31337, test_start_block=2, test_end_block=3, require_verified=True)
    options.update(kwargs)
    return anchored.analyze_anchored_package(path, **options)


def test_verified_package_runs_real_rules_without_changing_files(package):
    path, _ = package
    before = {p.name: p.read_bytes() for p in path.parent.iterdir()}
    report = run(path)
    assert report['verification']['status'] == 'VERIFIED'
    assert report['source_chain_id'] == 1  # distinct from anchor 31337
    assert any(a['rule_id'] == 'large_transfer' for a in report['alerts'])
    assert before == {p.name: p.read_bytes() for p in path.parent.iterdir()}


@pytest.mark.parametrize('status,reason', [('MISMATCH', 'REGISTRY_MISMATCH'), ('MISMATCH', 'EVIDENCE_NOT_FOUND'), ('ERROR', 'RPC_QUERY_FAILED')])
def test_p3_failure_prevents_any_rule_execution(package, monkeypatch, status, reason):
    path, verification = package
    verification.status, verification.reason_code = status, reason
    monkeypatch.setattr(anchored, 'RuleEngine', lambda *a, **k: pytest.fail('P4 must not run'))
    with pytest.raises(anchored.AnchoredEvidenceError, match='P3_'):
        run(path)


def test_tampered_transfer_rejected_before_rpc(package, monkeypatch):
    path, _ = package
    with (path.parent / 'asset_transfers.csv').open('ab') as f:
        f.write(b'tampered')
    monkeypatch.setattr(anchored.onchain, 'verify_onchain_evidence', lambda *a, **k: pytest.fail('No RPC'))
    with pytest.raises(anchored.AnchoredEvidenceError, match='CONTENT_MISMATCH'):
        run(path)


def test_package_changed_at_p3_boundary_rejected(package):
    path, verification = package
    verification.details['manifest_sha256'] = '0' * 64
    with pytest.raises(anchored.AnchoredEvidenceError, match='CHANGED_DURING'):
        run(path)


def test_source_chain_mismatch(package):
    path, verification = package
    verification.details['source_chain_id'] = 31337
    with pytest.raises(anchored.AnchoredEvidenceError, match='SOURCE_CHAIN'):
        run(path)


@pytest.mark.parametrize('options', [dict(test_end_block=4), dict(cal_start_block=-1, cal_end_block=1), dict(cal_start_block=0), dict(cal_start_block=0, cal_end_block=2)])
def test_windows_fail_closed(package, options):
    with pytest.raises(anchored.AnchoredEvidenceError):
        run(package[0], **options)


def test_calibration_reads_verified_package(package):
    assert run(package[0], cal_start_block=0, cal_end_block=1)['total_alerts'] >= 1


def test_files_changed_after_verification_cannot_change_analysis(package, monkeypatch):
    path, verified = package
    def boundary(*a, **k):
        (path.parent / 'asset_transfers.csv').write_text('changed after snapshot', encoding='utf-8')
        return verified
    monkeypatch.setattr(anchored.onchain, 'verify_onchain_evidence', boundary)
    assert run(path)['total_alerts'] >= 1  # uses authenticated captured bytes


def test_real_p3_rejects_invalid_package_without_rpc(tmp_path, monkeypatch):
    # Restore real verifier by importing it outside fixture monkeypatch lifetime.
    path = tmp_path / 'manifest.json'
    path.write_text('{}')
    monkeypatch.setattr(anchored.onchain, 'rpc_read', lambda *a, **k: pytest.fail('No RPC'))
    result = anchored.onchain.verify_onchain_evidence(path, '0x' + 'c' * 40, anchor_chain_id=31337)
    assert result.status != 'MATCH'


def test_cli_rejects_missing_package_without_secret_leak(capsys):
    code = anchored.main(['--manifest', 'missing-evidence.json', '--contract', 'bad',
                         '--rpc-url', 'https://secret.invalid/key', '--anchor-chain-id', '31337', '--test', '1', '2'])
    output = capsys.readouterr().out
    assert code == 1 and 'NOT_VERIFIED' in output and 'secret' not in output
