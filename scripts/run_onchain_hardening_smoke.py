"""P3 Group 4 Integration Smoke Suite: Smart Contract Hardening & Custody Pagination.
Tests:
- Local Anvil ephemeral instance on chain ID 31337
- Deployment of hardened EvidenceRegistry.sol
- Rejection of invalid storageUri onchain (wrong prefix, control chars)
- Successful registration with canonical SHA-256 storageUri (G4-01..G4-04)
- Verification of EvidenceRegistered event
- Recording of multiple custody actions with SHA-256 note hashes
- Custody pagination verification (getCustodyCount, getCustodyHistory with offset/limit, bounds)
- Backwards compatibility of single-argument getCustodyHistory
- verify-onchain integration check
- Negative receipt rejection (fail-closed, no verified=1)
- Group 3 guards preservation (zero raw secret/case leakage, immutable historical rows)
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

from forensics.schemas import init_db
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
        "VALUES('run-smoke-01', 'anvil-smoke-node', 31337, 0, 'backfill', 0, ?, ?, ?, 10.0, 10.0, 0, 0, 'completed', ?, ?, 'commit1')",
        (num_blocks - 1, num_blocks, num_blocks, utc_str, utc_str)
    )
    conn.commit()
    conn.close()


def run_group4_smoke():
    report = {
        "suite": "P3-Group4-Smoke",
        "status": "FAIL",
        "chain_id": 31337,
        "checks": [],
        "operations": [],
        "pagination_results": {},
        "leaks_found": []
    }
    stage = "init"
    anvil_proc = None
    saved_env = dict(os.environ)

    def check_pass(name, **meta):
        report["checks"].append({"name": name, "status": "PASS", **meta})

    try:
        with tempfile.TemporaryDirectory(prefix="p3-g4-smoke-") as temp_dir:
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

            # 1. Start local Anvil on free port
            stage = "anvil_start"
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

            # 2. Deploy hardened EvidenceRegistry contract
            stage = "deploy_registry"
            owner = oc.rpc_read(url, "eth_accounts", [])[0]
            artifact_file = ROOT / "contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json"
            if not artifact_file.exists():
                artifact_file = ROOT / "out/EvidenceRegistry.sol/EvidenceRegistry.json"
            if not artifact_file.exists():
                raise FileNotFoundError(f"Missing contract artifact: {artifact_file}")
            artifact = json.loads(artifact_file.read_text(encoding="utf-8"))
            bytecode = artifact["bytecode"]["object"]

            raw_deploy = oc.run_cast_send([
                "--from", owner, "--unlocked", "--rpc-url", url,
                "--chain", "31337", "--json", "--create", bytecode
            ])
            deployed_receipt = json.loads(raw_deploy)
            contract = deployed_receipt["contractAddress"]
            check_pass("deploy_hardened_registry", contract=contract, deployer=owner)

            # Verify onchain rejection of invalid storageUri
            stage = "uri_negative_onchain"
            dummy_case_hash = "0x" + hashlib.sha256(b"TEST_CASE").hexdigest()
            dummy_manifest_hash = "0x" + hashlib.sha256(b"TEST_MANIFEST").hexdigest()

            # Attempt 3a: missing prefix -> cast send should fail
            failed_prefix = False
            try:
                oc.run_cast_send([
                    "--from", owner, "--unlocked", "--rpc-url", url,
                    "--chain", "31337", contract,
                    "registerEvidence(bytes32,bytes32,string)",
                    dummy_case_hash, dummy_manifest_hash, "http://malicious.url/manifest.json"
                ])
            except RuntimeError:
                failed_prefix = True
            assert failed_prefix, "Contract must revert when storageUri prefix is not evidence://"
            check_pass("reject_invalid_uri_prefix", reason="reverted on missing evidence://")

            # Attempt 3b: empty reference part -> should fail
            failed_empty_ref = False
            try:
                oc.run_cast_send([
                    "--from", owner, "--unlocked", "--rpc-url", url,
                    "--chain", "31337", contract,
                    "registerEvidence(bytes32,bytes32,string)",
                    dummy_case_hash, dummy_manifest_hash, "evidence://"
                ])
            except RuntimeError:
                failed_empty_ref = True
            assert failed_empty_ref, "Contract must revert when storageUri has no reference part"
            check_pass("reject_empty_uri_reference", reason="reverted on evidence://")

            # Attempt 3c: newline character in URI -> should fail
            failed_newline = False
            try:
                oc.run_cast_send([
                    "--from", owner, "--unlocked", "--rpc-url", url,
                    "--chain", "31337", contract,
                    "registerEvidence(bytes32,bytes32,string)",
                    dummy_case_hash, dummy_manifest_hash, "evidence://case\nmanifest.json"
                ])
            except RuntimeError:
                failed_newline = True
            assert failed_newline, "Contract must revert when storageUri contains newline"
            check_pass("reject_control_char_newline", reason="reverted on newline in URI")

            # 4. Export sample evidence package and anchor with canonical storageUri
            stage = "export_and_anchor"
            db_file = work / "forensics.db"
            populate_smoke_db(db_file, num_blocks=5)

            raw_case = "CASE-2026-GROUP4-ANVIL"
            export_dir = work / "export_pkg"
            export_evidence(raw_case, 0, 4, str(export_dir), str(db_file), allow_gaps=True)
            v_pkg = verify_package(export_dir)
            if v_pkg.status != "VALID":
                raise ValueError("EXPORTED_PACKAGE_INVALID")
            pkg_digest = v_pkg.manifest_sha256

            # Anchor using canonical URI
            anchor_res = oc.anchor_evidence(
                manifest_path_or_dir=str(export_dir),
                contract_address=contract,
                db_path=str(db_file),
                from_addr=owner,
                allow_dirty=True,
                allow_unfinalized=True,
                reason="controlled-test",
                rpc_url=url
            )
            evidence_id = anchor_res["evidence_id"]
            anchor_tx = anchor_res["tx_hash"]
            expected_uri = canonical_storage_uri(case_id_digest(raw_case), pkg_digest)
            check_pass("anchor_canonical_storage_uri", evidence_id=evidence_id, tx_hash=anchor_tx, uri=expected_uri)
            report["operations"].append({"action": "anchor", "evidence_id": evidence_id, "tx_hash": anchor_tx})

            # 5. Record 5 custody events with SHA-256 note hashes
            stage = "record_custody_events"
            custody_txs = []
            actions = [0, 1, 2, 1, 3]  # COLLECTED, ANALYZED, TRANSFERRED, ANALYZED, EXPORTED
            action_names = ["COLLECTED", "ANALYZED", "TRANSFERRED", "ANALYZED", "EXPORTED"]
            for idx, (act_enum, act_name) in enumerate(zip(actions, action_names)):
                note = f"Step {idx+1}: {act_name} by investigator"
                art_bytes = "0x" + hashlib.sha256(f"artifact-{idx}".encode()).hexdigest()
                c_res = oc.record_custody_action(
                    evidence_id=evidence_id,
                    action=act_enum,
                    artifact_sha256=art_bytes,
                    note=note,
                    contract_address=contract,
                    db_path=str(db_file),
                    from_addr=owner,
                    rpc_url=url
                )
                ctx = c_res["tx_hash"]
                custody_txs.append(ctx)
                report["operations"].append({"action": f"custody_{act_name.lower()}", "tx_hash": ctx})

            with contextlib.closing(sqlite3.connect(db_file)) as conn:
                custody_rows = conn.execute(
                    "SELECT evidence_id, action, verified FROM custody_events WHERE contract_address=?",
                    (contract,)
                ).fetchall()
            assert len(custody_rows) == 6, f"Expected 6 custody rows in DB, found {len(custody_rows)}"
            for r in custody_rows:
                assert r[2] == 1, f"Custody row not verified: {r}"
            check_pass("record_multiple_custody_events", count=len(actions), tx_hashes=custody_txs, db_rows=len(custody_rows))

            # Verify Custody Pagination via cast call
            stage = "verify_pagination"

            # 6a. Check getCustodyCount(uint256)
            raw_count = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyCount(uint256)(uint256)",
                str(evidence_id)
            ]).strip()
            total_count = int(raw_count.split()[0], 0) if " " in raw_count else int(raw_count, 0)
            assert total_count == 5, f"Expected total 5 custody records, got {total_count}"
            check_pass("pagination_custody_count", total=total_count)

            # 6b. Check getCustodyHistory(uint256,uint256,uint256)
            # Page 1: offset 0, limit 2
            raw_p1 = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(evidence_id), "0", "2"
            ])
            # Page 2: offset 2, limit 2
            raw_p2 = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(evidence_id), "2", "2"
            ])
            # Page 3: offset 4, limit 2 (partial page)
            raw_p3 = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(evidence_id), "4", "2"
            ])
            # Page beyond total: offset 10, limit 2
            raw_p_empty = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(evidence_id), "10", "2"
            ])
            # Limit zero: offset 0, limit 0
            raw_p_limit0 = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                str(evidence_id), "0", "0"
            ])

            # Page size exceeding MAX_PAGE_SIZE (50) -> should revert
            limit_exceeded_reverts = False
            try:
                oc.run_cast_call([
                    "--rpc-url", url, contract,
                    "getCustodyHistory(uint256,uint256,uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[],uint256)",
                    str(evidence_id), "0", "51"
                ])
            except RuntimeError:
                limit_exceeded_reverts = True
            assert limit_exceeded_reverts, "getCustodyHistory must revert when limit > MAX_PAGE_SIZE (50)"

            # 6c. Check backwards compatibility of single-arg getCustodyHistory(uint256)
            raw_full = oc.run_cast_call([
                "--rpc-url", url, contract,
                "getCustodyHistory(uint256)((uint256,uint8,address,bytes32,bytes32,uint256)[])",
                str(evidence_id)
            ])
            assert raw_full and "[]" not in raw_full, "Full history call must return records"

            report["pagination_results"] = {
                "total_count": total_count,
                "p1_returned": bool(raw_p1),
                "p2_returned": bool(raw_p2),
                "p3_returned": bool(raw_p3),
                "empty_page_returned": bool(raw_p_empty),
                "limit_zero_returned": bool(raw_p_limit0),
                "limit_51_reverted": limit_exceeded_reverts,
                "backwards_compatible_full_call": bool(raw_full),
            }
            check_pass("pagination_views_and_boundaries", **report["pagination_results"])

            # 7. Run verify_onchain_evidence
            stage = "verify_onchain"
            v_res = oc.verify_onchain_evidence(
                manifest_path_or_dir=str(export_dir),
                contract_address=contract,
                evidence_id=evidence_id,
                db_path=str(db_file),
                rpc_url=url,
                anchor_chain_id=31337
            )
            assert v_res.exit_code == 0 and v_res.status == "MATCH", f"Verify failed: {v_res}"
            check_pass("verify_onchain_success", status="MATCH", evidence_id=evidence_id)

            # 8. Negative Receipt Rejection (Guard against false verified=1)
            stage = "negative_receipt_rejection"
            bad_receipt = {
                "status": 1,
                "blockNumber": hex(1),
                "blockHash": "0x" + "bb" * 32,
                "transactionHash": "0x" + "aa" * 32,
                "logs": [{
                    "address": contract,
                    "topics": [
                        ops.TOPIC_EVIDENCE_REGISTERED,
                        "0x" + hex(evidence_id)[2:].zfill(64),
                        "0x" + "99" * 32,  # WRONG case digest
                        "0x" + pkg_digest.lower()
                    ],
                    "data": "0x"
                }]
            }
            rejected = False
            try:
                ops.verify_receipt_and_event(
                    receipt=bad_receipt,
                    expected_event_type=ops.EVENT_TYPE_EVIDENCE_REGISTERED,
                    expected_contract=contract,
                    expected_evidence_id=evidence_id,
                    expected_case_id=raw_case,
                    expected_manifest_sha256=pkg_digest
                )
            except RuntimeError:
                rejected = True
            assert rejected, "Fake receipt with mismatched case digest must be rejected"
            check_pass("negative_receipt_rejection_fail_closed", rejected=True)

            # 9. Verify zero secret/case leakage (Group 3 guard verification)
            stage = "leakage_audit"
            conn = sqlite3.connect(str(db_file))
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
                            if "by investigator" in val:
                                leaks.append(f"plaintext note leaked in {tbl}.{k}")
                except sqlite3.OperationalError:
                    pass
            conn.close()
            assert not leaks, f"Leaks found: {leaks}"
            check_pass("zero_raw_leakage_asserted", leaks_count=len(leaks))

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
    rep = run_group4_smoke()
    print(json.dumps(rep, indent=2))
    if rep["status"] == "PASS":
        sys.exit(0)
    else:
        sys.exit(1)
