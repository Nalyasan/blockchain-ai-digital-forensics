import json
import sqlite3
from forensics.rules.anchored import read_custody
from test_p4_anchored_package import package, run


def test_unavailable_p3_continues(package):
    path, verification = package
    verification.status = 'ERROR'
    verification.reason_code = 'RPC_QUERY_FAILED'
    result = run(path, require_verified=False)
    assert result['analysis_status'] == 'COMPLETED_WITH_WARNING'
    assert result['verification']['status'] == 'NOT_VERIFIED'
    assert result['total_alerts'] > 0


def test_mismatch_continues_with_marked_alerts(package):
    path, verification = package
    verification.status = 'MISMATCH'
    result = run(path, require_verified=False)
    assert result['verification']['status'] == 'MISMATCH'
    assert all(a['p3_verification_status'] == 'MISMATCH' for a in result['alerts'])


def test_custody_bound_to_manifest_chain_contract(tmp_path):
    db = tmp_path / 'custody.db'
    with sqlite3.connect(db) as c:
        c.executescript("CREATE TABLE anchor_links(chain_id,contract_address,manifest_sha256,evidence_id); CREATE TABLE custody_events(event_id,evidence_id,chain_id,contract_address,block_number,recorded_at);")
        c.execute("INSERT INTO anchor_links VALUES(31337,'0xabc','digest',7)")
        c.execute("INSERT INTO custody_events VALUES('evt',7,31337,'0xabc',1,'now')")
    original = db.read_bytes()
    assert len(read_custody(db, 'digest', 31337, '0xabc')['events']) == 1
    assert read_custody(db, 'other', 31337, '0xabc')['events'] == []
    assert read_custody(db, 'digest', 1, '0xabc')['events'] == []
    assert db.read_bytes() == original


def test_existing_analyze_routes_p3(package, capsys):
    from forensics.cli import build_parser
    args = build_parser().parse_args(['analyze', '--p3-manifest', str(package[0]), '--start-block', '2', '--end-block', '3'])
    assert args.func(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['verification']['status'] == 'NOT_VERIFIED'
    assert result['total_alerts'] > 0
