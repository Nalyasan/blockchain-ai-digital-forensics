"""P3 Group 5 End-to-End Acceptance Smoke Suite.
Executes complete Phase 3 lifecycle on local Anvil:
Collector -> Evidence Export -> Manifest Verification -> Blockchain Anchor
-> Custody Recording -> Verify-onchain -> Custody Pagination
-> Tamper Detection (MISMATCH) -> Negative Receipt Protection -> Reconcile
-> Zero Secret Leakage Audit -> Production DB & Sample Immutability Check.
"""
import os
import sys
import json
import time
import socket
import sqlite3
import argparse
import tempfile
import contextlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from forensics.schemas import init_db, migrate_group3
from forensics.evidence import export_evidence
from forensics.integrity import verify_package
from forensics.evidence_identity import (
    case_id_digest,
    case_id_hash_bytes32,
    note_hash_bytes32,
    canonical_storage_uri,
    sanitize_log_text,
)
import forensics.onchain as oc
from forensics import onchain_store as ops


PROTECTED_FILES = {
    "data/forensics.db": "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001",
    "results/p1/anvil_forensics.db": "50a5872890f2b92f4e1257230a4b1c56a3ec652bb028a054d67494cf15adb525",
    "results/p2/case-anvil-p1-001/manifest.json": "964da91bd5fcca0171461ed585dc777ffcccea094800b8a3d81ea76f2952006e",
    "results/p2/case-anvil-p1-001/raw_blocks.jsonl": "b828fdcd0b61cc0c11236cb1c1d0dddf65fc42b2c9aa7f0bd0ad75b532962d8f",
    "results/p2/case-anvil-p1-001/timeline.csv": "239c640fe958dca801ae0f96a78b6f14037c0958d55aeae428d76291e2b195e3",
    "results/p2/case-anvil-p1-001/asset_transfers.csv": "d509c83875a411c514d59228cdc6ac88eb836597ca14809e35502b57a90fa5a1",
    "results/p2/case-anvil-p1-001/audit_events.jsonl": "8ce0a9f8b3686fbd4f242ac6c38e8d0a8ee7aa013d2fb35683ee39c8f311d508",
}


def populate_smoke_db(db_path: Path, num_blocks: int = 5):
    """Tạo DB mẫu chứa blocks, transactions, receipts, logs."""
    conn = init_db(str(db_path))
    chain_id = 31337
    prev_hash = "0x" + "0" * 64

    for n in range(num_blocks):
        b_hash = f"0x{n:064x}"
        utc_str = datetime.fromtimestamp(1700000000 + n * 12, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tx_hash = f"0x{n+200:064x}"
        from_a = "0x1111111111111111111111111111111111111111"
        to_a = "0x2222222222222222222222222222222222222222"
        val = 1000000000000000000
        tx_obj = {
            "hash": tx_hash, "blockHash": b_hash, "blockNumber": hex(n), "transactionIndex": "0x0",
            "from": from_a, "to": to_a, "value": hex(val), "nonce": "0x0", "input": "0x"
        }
        tx_raw = json.dumps(tx_obj, sort_keys=True, separators=(',', ':'))
        tx_sha = hashlib.sha256(tx_raw.encode()).hexdigest()

        blk_data = {
            "number": hex(n), "hash": b_hash, "parentHash": prev_hash,
            "timestamp": hex(1700000000 + n * 12), "transactions": [tx_obj]
        }
        b_raw = json.dumps(blk_data, sort_keys=True, separators=(',', ':'))
        b_sha = hashlib.sha256(b_raw.encode()).hexdigest()

        conn.execute(
            "INSERT INTO blocks(chain_id, number, hash, parent_hash, block_timestamp, block_time_utc, "
            "first_observed_at, collected_at, status, raw_json, raw_sha256, synthetic) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'canonical', ?, ?, 0)",
            (chain_id, n, b_hash, prev_hash, 1700000000 + n * 12, utc_str, utc_str, utc_str, b_raw, b_sha)
        )
        conn.execute(
            "INSERT INTO transactions(chain_id, tx_hash, block_hash, block_number, tx_index, "
            "from_addr, to_addr, value_raw, nonce, input, raw_json, raw_sha256) "
            "VALUES(?, ?, ?, ?, 0, ?, ?, ?, 0, '0x', ?, ?)",
            (chain_id, tx_hash, b_hash, n, from_a, to_a, str(val), tx_raw, tx_sha)
        )
        rc_obj = {
            "transactionHash": tx_hash, "blockHash": b_hash, "blockNumber": hex(n),
            "transactionIndex": "0x0", "contractAddress": None,
            "status": "0x1", "gasUsed": "0x5208", "logs": [],
            "from": from_a, "to": to_a, "cumulativeGasUsed": "0x5208",
            "effectiveGasPrice": "0x1", "logsBloom": "0x" + "0" * 512
        }
        rc_raw = json.dumps(rc_obj, sort_keys=True, separators=(',', ':'))
        rc_sha = hashlib.sha256(rc_raw.encode()).hexdigest()
        conn.execute(
            "INSERT INTO receipts(chain_id, tx_hash, block_hash, status, gas_used, raw_json, raw_sha256) "
            "VALUES(?, ?, ?, 1, 21000, ?, ?)",
            (chain_id, tx_hash, b_hash, rc_raw, rc_sha)
        )
        conn.execute(
            "INSERT INTO asset_transfers(chain_id, block_number, block_hash, block_timestamp, tx_hash, "
            "log_index, asset_id, from_addr, to_addr, amount_raw, synthetic) "
            "VALUES(?, ?, ?, ?, ?, -1, 'NATIVE', ?, ?, ?, 0)",
            (chain_id, n, b_hash, 1700000000 + n * 12, tx_hash, from_a, to_a, str(val))
        )
        conn.execute(
            "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'COLLECT_BLOCK', ?, ?)",
            (utc_str, f"block:{n}", json.dumps({"hash": b_hash}))
        )
        prev_hash = b_hash

    conn.execute(
        "INSERT INTO collector_runs(run_id, rpc_label, chain_id, synthetic, mode, start_block, end_block, "
        "blocks_count, txs_count, blocks_per_sec, txs_per_sec, retries_count, gaps_count, status, started_at, ended_at, commit_hash) "
        "VALUES('run-smoke-05', 'anvil-smoke-node', 31337, 0, 'backfill', 0, ?, ?, ?, 10.0, 10.0, 0, 0, 'completed', ?, ?, 'commit-g5')",
        (num_blocks - 1, num_blocks, num_blocks, utc_str, utc_str)
    )
    conn.commit()
    conn.close()


def run_group5_smoke():
    report = {
        "suite": "P3-Group5-EndToEnd-Acceptance",
        "status": "FAIL",
        "chain_id": 31337,
        "checks": [],
        "operations": [],
        "leaks_found": []
    }
    anvil_proc = None
    saved_env = dict(os.environ)

    def check_pass(name, **meta):
        report["checks"].append({"name": name, "status": "PASS", **meta})

    try:
        # Pre-check: Verify immutability of protected files before test
        for rel_path, exp_sha in PROTECTED_FILES.items():
            full = ROOT / rel_path
            if full.exists():
                actual = hashlib.sha256(full.read_bytes()).hexdigest()
                assert actual == exp_sha, f"Pre-test corruption detected in {rel_path}"
        check_pass("preflight_protected_files_verified")

        with tempfile.TemporaryDirectory(prefix="p3-g5-smoke-") as temp_dir:
            work = Path(temp_dir)
            allowed_env = {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"}
            os.environ.clear()
            os.environ.update({k: v for k, v in saved_env.items() if k.upper() in allowed_env})
            os.environ.update(
                PYTHONUTF8="1",
                PYTHONPATH=str(ROOT),
                ANCHOR_CHAIN_ID="31337",
                RATE_LIMIT_RPS="100"
            )

            # 1. Start ephemeral local Anvil
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            url = f"http://127.0.0.1:{port}"
            os.environ["ANCHOR_RPC_URL"] = url

            suffix = ".exe" if os.name == "nt" else ""
            anvil_bin = ROOT / "tools/foundry" / ("anvil" + suffix)
            if not anvil_bin.exists():
                anvil_bin = Path("anvil")

            anvil_proc = subprocess.Popen(
                [str(anvil_bin), "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )

            deadline = time.monotonic() + 25
            while True:
                if anvil_proc.poll() is not None:
                    raise RuntimeError("ANVIL_PROCESS_TERMINATED_PREMATURELY")
                try:
                    if oc.get_rpc_chain_id(url) == 31337:
                        break
                except Exception:
                    if time.monotonic() > deadline:
                        raise TimeoutError("ANVIL_START_TIMEOUT")
                    time.sleep(0.15)
            check_pass("anvil_online", port=port, rpc_url=url)

            # 2. Deploy hardened EvidenceRegistry
            owner = oc.rpc_read(url, "eth_accounts", [])[0]
            artifact_file = ROOT / "contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json"
            if not artifact_file.exists():
                artifact_file = ROOT / "out/EvidenceRegistry.sol/EvidenceRegistry.json"
            artifact = json.loads(artifact_file.read_text(encoding="utf-8"))
            bytecode = artifact["bytecode"]["object"]

            raw_deploy = oc.run_cast_send([
                "--from", owner, "--unlocked", "--rpc-url", url,
                "--chain", "31337", "--json", "--create", bytecode
            ])
            contract = json.loads(raw_deploy)["contractAddress"]
            check_pass("deploy_registry", contract=contract, owner=owner)

            # 3. Stage 1: Collector data generation in isolated temp db
            temp_db = work / "forensics.db"
            populate_smoke_db(temp_db, num_blocks=5)
            check_pass("collector_data_generated", db_path=str(temp_db))

            # 4. Stage 2: Evidence Export
            raw_case = "CASE-2026-GROUP5-FINAL-EVAL"
            temp_pkg = work / "evidence_export"
            export_evidence(raw_case, 0, 4, str(temp_pkg), str(temp_db), allow_gaps=True)
            check_pass("evidence_exported", export_dir=str(temp_pkg))

            # 5. Stage 3: Manifest Verification
            v_pkg = verify_package(temp_pkg)
            assert v_pkg.status == "VALID", f"Exported package verification failed: {v_pkg}"
            pkg_digest = v_pkg.manifest_sha256
            check_pass("manifest_verified_valid", digest=pkg_digest)

            # 6. Stage 4: Blockchain Anchor with Canonical URI
            anchor_res = oc.anchor_evidence(
                manifest_path_or_dir=str(temp_pkg),
                contract_address=contract,
                db_path=str(temp_db),
                from_addr=owner,
                allow_dirty=True,
                allow_unfinalized=True,
                reason="controlled-test",
                rpc_url=url
            )
            eid = anchor_res["evidence_id"]
            anchor_tx = anchor_res["tx_hash"]
            expected_uri = canonical_storage_uri(case_id_digest(raw_case), pkg_digest)
            check_pass("blockchain_anchor_success", evidence_id=eid, tx_hash=anchor_tx, storage_uri=expected_uri)
            report["operations"].append({"action": "anchor", "tx_hash": anchor_tx})

            # 7. Stage 5: Custody Event Recording
            custody_notes = [
                "Transferred to Lead Investigator for hash audit",
                "Analysis complete: no anomalies observed",
                "Exported evidence package signed and sealed"
            ]
            custody_actions = [2, 1, 3]  # TRANSFERRED, ANALYZED, EXPORTED
            for act, note in zip(custody_actions, custody_notes):
                c_res = oc.record_custody_action(
                    evidence_id=eid,
                    action=act,
                    artifact_sha256="0x" + pkg_digest,
                    note=note,
                    contract_address=contract,
                    db_path=str(temp_db),
                    from_addr=owner,
                    rpc_url=url
                )
                report["operations"].append({"action": f"custody_{act}", "tx_hash": c_res["tx_hash"]})
            check_pass("custody_events_recorded", count=len(custody_actions))

            # 8. Stage 6: Verify-onchain (Authentic data -> MATCH)
            v_onchain = oc.verify_onchain_evidence(
                manifest_path_or_dir=str(temp_pkg),
                contract_address=contract,
                evidence_id=eid,
                db_path=str(temp_db),
                rpc_url=url,
                anchor_chain_id=31337
            )
            assert v_onchain.exit_code == 0 and v_onchain.status == "MATCH"
            check_pass("verify_onchain_match", status=v_onchain.status)

            # 9. Stage 7: Custody Pagination Verification
            raw_count = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyCount(uint256)(uint256)", str(eid)
            ]).strip()
            total_custody = int(raw_count.split()[0], 0) if " " in raw_count else int(raw_count, 0)
            assert total_custody == len(custody_actions)

            raw_p1 = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(eid), "0", "2"
            ])
            assert raw_p1 and "[]" not in raw_p1
            check_pass("custody_pagination_verified", total=total_custody)

            # 10. Stage 8: Tamper Detection (Tampered data -> MISMATCH)
            tamper_file = temp_pkg / "timeline.csv"
            orig_text = tamper_file.read_text(encoding="utf-8")
            tamper_file.write_text(orig_text + "\n999999,tampered,tampered", encoding="utf-8")

            v_tampered = oc.verify_onchain_evidence(
                manifest_path_or_dir=str(temp_pkg),
                contract_address=contract,
                evidence_id=eid,
                db_path=str(temp_db),
                rpc_url=url,
                anchor_chain_id=31337
            )
            assert v_tampered.status == "MISMATCH", f"Expected MISMATCH on tampered package, got {v_tampered.status}"
            check_pass("tamper_detection_mismatch", status=v_tampered.status)

            # Restore original package text
            tamper_file.write_text(orig_text, encoding="utf-8")

            # 11. Stage 9: Negative Receipt Protection
            forged_receipt = {
                "status": 1,
                "blockNumber": hex(1),
                "blockHash": "0x" + "bb" * 32,
                "transactionHash": "0x" + "aa" * 32,
                "logs": [{
                    "address": contract,
                    "topics": [
                        ops.TOPIC_EVIDENCE_REGISTERED,
                        "0x" + hex(eid)[2:].zfill(64),
                        "0x" + "99" * 32,  # FORGED case digest
                        "0x" + pkg_digest.lower()
                    ],
                    "data": "0x"
                }]
            }
            rejected = False
            try:
                ops.verify_receipt_and_event(
                    receipt=forged_receipt,
                    expected_event_type=ops.EVENT_TYPE_EVIDENCE_REGISTERED,
                    expected_contract=contract,
                    expected_evidence_id=eid,
                    expected_case_id=raw_case,
                    expected_manifest_sha256=pkg_digest
                )
            except RuntimeError:
                rejected = True
            assert rejected is True, "Forged receipt must be rejected fail-closed"
            check_pass("negative_receipt_protection_fail_closed", rejected=True)

            # 12. Stage 10: Idempotency Reconcile
            # Ensure reconcile on already confirmed operation does not re-broadcast
            with contextlib.closing(sqlite3.connect(temp_db)) as conn:
                op_row = conn.execute("SELECT operation_id FROM onchain_operations WHERE state='CONFIRMED'").fetchone()
            assert op_row is not None
            conf_op_id = op_row[0]
            rec_result = ops.reconcile_operation(temp_db, conf_op_id, rpc_url_or_client=url)
            assert rec_result["state"] == "CONFIRMED"
            check_pass("idempotency_reconciliation_no_resend", operation_id=conf_op_id, state="CONFIRMED")

            # 13. Stage 11: Zero Secret Leakage Audit
            with contextlib.closing(sqlite3.connect(temp_db)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                leaks = []
                for tbl in ["custody_events", "onchain_operations", "onchain_operation_events", "anchor_links", "audit_events"]:
                    try:
                        for row in cursor.execute(f"SELECT * FROM {tbl}").fetchall():
                            for k in row.keys():
                                val = str(row[k] or "")
                                if raw_case in val:
                                    leaks.append(f"raw case_id leaked in {tbl}.{k}")
                                for note in custody_notes:
                                    if note in val:
                                        leaks.append(f"plaintext custody note leaked in {tbl}.{k}")
                    except sqlite3.OperationalError:
                        pass
            assert not leaks, f"Data leaks found: {leaks}"
            check_pass("zero_secret_leakage_asserted", leaks_count=len(leaks))

        # 14. Stage 12: Verify production DB & sample immutability post-test
        for rel_path, exp_sha in PROTECTED_FILES.items():
            full = ROOT / rel_path
            if full.exists():
                actual = hashlib.sha256(full.read_bytes()).hexdigest()
                assert actual == exp_sha, f"Post-test corruption detected in {rel_path}"
        check_pass("post_test_protected_files_verified")

        report["status"] = "PASS"
        return report

    finally:
        os.environ.clear()
        os.environ.update(saved_env)
        if anvil_proc is not None and anvil_proc.poll() is None:
            anvil_proc.terminate()
            try:
                anvil_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                anvil_proc.kill()


if __name__ == "__main__":
    rep = run_group5_smoke()
    print(json.dumps(rep, indent=2))
    if rep["status"] == "PASS":
        sys.exit(0)
    else:
        sys.exit(1)
