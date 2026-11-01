"""P3 Group 3 Integration Smoke Suite: Local Anvil End-to-End Verification.
Tests:
- Canonical SHA-256 case_id digest & canonical storage URI
- SHA-256 note_hash in CustodyRecorded
- Read-only onchain verification & CLI integration
- Read-only reconciliation via onchain_store and CLI
- Multi-manifest anchor_links tracking
- Fail-closed idempotency on duplicate send attempts
- Zero leakage of raw case_id or secret note into SQLite DB or logs
"""
import os
import sys
import json
import time
import shutil
import socket
import sqlite3
import argparse
import tempfile
import contextlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

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
        import hashlib
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


def run_smoke():
    report = {
        "suite": "P3-Group3-Smoke",
        "status": "FAIL",
        "chain_id": 31337,
        "checks": [],
        "operations": [],
        "leaks_found": []
    }
    stage = "init"
    anvil_proc = None
    saved_env = dict(os.environ)

    def check_pass(name, **meta):
        report["checks"].append({"name": name, "status": "PASS", **meta})

    try:
        with tempfile.TemporaryDirectory(prefix="p3-g3-smoke-") as temp_dir:
            work = Path(temp_dir)
            allowed_env = {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "FORENSICS_TRUSTED_REPOSITORY"}
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

            # 2. Deploy EvidenceRegistry contract
            stage = "deploy_registry"
            owner = oc.rpc_read(url, "eth_accounts", [])[0]
            artifact_file = ROOT / "contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json"
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
            check_pass("deploy_evidence_registry", contract=contract, deployer=owner)

            # 3. Create sample SQLite DB and export two packages
            stage = "export_packages"
            db_file = work / "forensics.db"
            populate_smoke_db(db_file, num_blocks=5)

            case_raw_id = "CASE-FORENSICS-2026-GROUP3-ALPHA"
            pkg1 = work / "package1"
            pkg2 = work / "package2"

            export_evidence(case_raw_id, 0, 2, str(pkg1), str(db_file), allow_gaps=True)
            export_evidence(case_raw_id, 0, 4, str(pkg2), str(db_file), allow_gaps=True)

            v1 = verify_package(pkg1)
            v2 = verify_package(pkg2)
            if v1.status != "VALID" or v2.status != "VALID":
                raise ValueError("PACKAGE_EXPORT_INVALID")
            check_pass("export_dual_manifest_packages", pkg1_digest=v1.manifest_sha256, pkg2_digest=v2.manifest_sha256)

            # 4. Step 1: Anchor evidence 1 with canonical SHA-256 case_id and canonical URI
            stage = "anchor_evidence_1"
            anchor1 = oc.anchor_evidence(
                manifest_path_or_dir=str(pkg1),
                contract_address=contract,
                db_path=str(db_file),
                from_addr=owner,
                allow_dirty=True,
                allow_unfinalized=True,
                reason="controlled-test",
                rpc_url=url
            )
            eid1 = anchor1["evidence_id"]
            tx1 = anchor1["tx_hash"]
            report["operations"].append({"action": "anchor_1", "evidence_id": eid1, "tx_hash": tx1})

            # Verify receipt & event
            receipt1 = oc.get_transaction_receipt(tx1, url)
            event1 = receipt1["logs"][0]
            if event1["topics"][0].lower() != oc.TOPIC_EVIDENCE_REGISTERED.lower():
                raise AssertionError("TOPIC_EVIDENCE_REGISTERED_MISMATCH")

            expected_case_b32 = case_id_hash_bytes32(case_raw_id).lower()
            if event1["topics"][2].lower() != expected_case_b32:
                raise AssertionError(f"EVENT_CASE_HASH_MISMATCH: expected {expected_case_b32}, got {event1['topics'][2]}")

            expected_uri1 = canonical_storage_uri(case_id_digest(case_raw_id), v1.manifest_sha256)
            check_pass("anchor_evidence_1_canonical_identity", evidence_id=eid1, tx_hash=tx1, uri=expected_uri1)

            # 5. Step 2: Anchor evidence 2 (same case ID, second manifest) -> Multi-manifest anchor_links
            stage = "anchor_evidence_2_multi_manifest"
            anchor2 = oc.anchor_evidence(
                manifest_path_or_dir=str(pkg2),
                contract_address=contract,
                db_path=str(db_file),
                from_addr=owner,
                allow_dirty=True,
                allow_unfinalized=True,
                reason="controlled-test",
                rpc_url=url
            )
            eid2 = anchor2["evidence_id"]
            tx2 = anchor2["tx_hash"]
            report["operations"].append({"action": "anchor_2", "evidence_id": eid2, "tx_hash": tx2})

            # Assert multi-manifest anchor_links in SQLite
            with contextlib.closing(sqlite3.connect(db_file)) as conn:
                links = conn.execute(
                    "SELECT evidence_id, manifest_sha256 FROM anchor_links WHERE contract_address=?",
                    (contract,)
                ).fetchall()
                cases = conn.execute(
                    "SELECT evidence_id, case_id FROM custody_events WHERE case_id=?",
                    (case_id_digest(case_raw_id),)
                ).fetchall()
            if len(links) < 2 or len(cases) < 2:
                raise AssertionError(f"MULTI_MANIFEST_ANCHOR_LINKS_MISSING: links={links}, cases={cases}")
            check_pass("multi_manifest_anchor_links_created", row_count=len(links))

            # 6. Step 3: Record custody with secret note -> verify SHA-256 note_hash
            stage = "record_custody"
            secret_note = "CONFIDENTIAL_CHAIN_CUSTODY_TRANSFER_TO_INVESTIGATOR_8829"
            custody_res = oc.record_custody_action(
                evidence_id=eid1,
                action=1,  # ANALYZED
                artifact_sha256="0x" + v1.manifest_sha256,
                note=secret_note,
                contract_address=contract,
                db_path=str(db_file),
                from_addr=owner,
                rpc_url=url
            )
            ctx = custody_res["tx_hash"]
            report["operations"].append({"action": "custody", "evidence_id": eid1, "tx_hash": ctx})

            # Verify custody receipt
            receipt_c = oc.get_transaction_receipt(ctx, url)
            event_c = receipt_c["logs"][0]
            if event_c["topics"][0].lower() != oc.TOPIC_CUSTODY_RECORDED.lower():
                raise AssertionError("TOPIC_CUSTODY_RECORDED_MISMATCH")

            expected_note_b32 = note_hash_bytes32(secret_note).lower()
            # Topic 4 is noteHash in CustodyRecorded(uint256 indexed, uint8 indexed, address indexed, bytes32 artifactSha256, bytes32 noteHash)
            # Check data bytes for artifactSha256 and noteHash
            c_data = bytes.fromhex(event_c["data"][2:])
            c_note_b32 = "0x" + c_data[32:64].hex().lower()
            if c_note_b32 != expected_note_b32:
                raise AssertionError(f"EVENT_NOTE_HASH_MISMATCH: expected {expected_note_b32}, got {c_note_b32}")

            with contextlib.closing(sqlite3.connect(db_file)) as conn:
                custody_row = conn.execute(
                    "SELECT verified, note_hash, actor_address FROM custody_events WHERE tx_hash=?",
                    (ctx,)
                ).fetchone()
            if not custody_row or custody_row[0] != 1 or custody_row[1].lower() != expected_note_b32.removeprefix("0x"):
                raise AssertionError(f"CUSTODY_DB_ROW_INVALID: {custody_row}")
            check_pass("record_custody_sha256_note_hash", tx_hash=ctx, verified=custody_row[0])

            # 7. Step 4: Verify on-chain (Python & CLI)
            stage = "verify_onchain"
            verify_res = oc.verify_onchain_evidence(
                manifest_path_or_dir=str(pkg1),
                contract_address=contract,
                evidence_id=eid1,
                db_path=str(db_file),
                rpc_url=url,
                anchor_chain_id=31337
            )
            if verify_res.exit_code != 0:
                raise AssertionError(f"ONCHAIN_VERIFY_FAILED: {verify_res.status} {verify_res.reason_code}")

            cli_verify = subprocess.run(
                [sys.executable, "-m", "forensics.cli", "verify-onchain", str(pkg1),
                 "--contract", contract, "--evidence-id", str(eid1), "--rpc-url", url,
                 "--anchor-chain-id", "31337", "--db", str(db_file)],
                capture_output=True, text=True, timeout=30
            )
            if cli_verify.returncode != 0 or "MATCH: OK" not in cli_verify.stdout:
                raise AssertionError(f"CLI_VERIFY_ONCHAIN_FAILED: code={cli_verify.returncode}, out={cli_verify.stdout}")
            check_pass("verify_onchain_python_and_cli", status=verify_res.status, code=verify_res.reason_code)

            # 8. Step 5: Read-only reconcile (Python & CLI)
            stage = "reconcile"
            op1_id = anchor1.get("operation_id")
            if op1_id:
                reconcile_res = ops.reconcile_operation(str(db_file), op1_id, rpc_url_or_client=url)
                if not reconcile_res.get("reconciled") or reconcile_res.get("state") != "CONFIRMED":
                    raise AssertionError(f"RECONCILE_FAILED: {reconcile_res}")

                cli_rec = subprocess.run(
                    [sys.executable, "-m", "forensics.cli", "reconcile", "--operation-id", op1_id,
                     "--db", str(db_file), "--rpc-url", url],
                    capture_output=True, text=True, timeout=30
                )
                if cli_rec.returncode != 0 or '"CONFIRMED"' not in cli_rec.stdout:
                    raise AssertionError(f"CLI_RECONCILE_FAILED: code={cli_rec.returncode}, out={cli_rec.stdout}")
                check_pass("read_only_reconciliation", operation_id=op1_id, state="CONFIRMED")

            # 9. Step 6: Fail-closed idempotency refusal on re-send
            stage = "idempotency_refusal"
            nonce_before = oc.rpc_read(url, "eth_getTransactionCount", [owner, "latest"])
            re_send_failed = False
            try:
                oc.anchor_evidence(
                    manifest_path_or_dir=str(pkg1),
                    contract_address=contract,
                    db_path=str(db_file),
                    from_addr=owner,
                    allow_dirty=True,
                    allow_unfinalized=True,
                    reason="controlled-test",
                    rpc_url=url
                )
            except (ValueError, RuntimeError) as e:
                re_send_failed = True

            nonce_after = oc.rpc_read(url, "eth_getTransactionCount", [owner, "latest"])
            if not re_send_failed or nonce_after != nonce_before:
                raise AssertionError(f"IDEMPOTENCY_BREACH: re_send_failed={re_send_failed}, nonce_delta={nonce_after - nonce_before}")
            check_pass("fail_closed_idempotency_no_broadcast", nonce_unchanged=True)

            # 10. Step 7: Leak scan - Assert zero raw case_id or secret note in on-chain tables, audit events, or event logs
            stage = "zero_leak_scan"
            leaks = []
            with contextlib.closing(sqlite3.connect(db_file)) as conn:
                # 1. Secret note must NEVER appear anywhere in the entire database
                full_db = "\n".join(conn.iterdump())
                if secret_note in full_db:
                    leaks.append("LEAK_NOTE_IN_FULL_DB")

                # 2. Raw case_id must NEVER appear in Group 3 on-chain tables
                for tbl in ("custody_events", "onchain_operations", "onchain_operation_events", "anchor_links"):
                    rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                    dump_tbl = json.dumps(rows)
                    if case_raw_id in dump_tbl:
                        leaks.append(f"LEAK_CASE_ID_IN_{tbl.upper()}")

                # 3. Raw case_id must NEVER appear in onchain audit events
                onchain_audits = conn.execute(
                    "SELECT action, object_ref, metadata FROM audit_events WHERE action IN ('ANCHOR_PREFLIGHT', 'ANCHOR_EVIDENCE', 'RECORD_CUSTODY')"
                ).fetchall()
                for action, obj_ref, meta in onchain_audits:
                    if case_raw_id in obj_ref or case_raw_id in meta:
                        leaks.append(f"LEAK_CASE_ID_IN_AUDIT_{action}")

            # 4. Check on-chain receipts & event logs for leaks
            for op in report["operations"]:
                tx_h = op.get("tx_hash")
                if tx_h:
                    rcpt_dump = json.dumps(oc.get_transaction_receipt(tx_h, url))
                    if case_raw_id in rcpt_dump:
                        leaks.append(f"LEAK_CASE_ID_IN_RECEIPT_{tx_h}")
                    if secret_note in rcpt_dump:
                        leaks.append(f"LEAK_NOTE_IN_RECEIPT_{tx_h}")

            if leaks:
                report["leaks_found"] = leaks
                raise AssertionError(f"ZERO_LEAK_VIOLATION: {leaks}")
            check_pass("zero_raw_data_leakage_asserted", scanned_tables=["custody_events", "onchain_operations", "onchain_operation_events", "anchor_links", "audit_events", "receipts"])

            report["status"] = "PASS"
    except Exception as exc:
        import traceback
        report["failure"] = {
            "stage": stage,
            "error_type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc()
        }
    finally:
        if anvil_proc is not None and anvil_proc.poll() is None:
            anvil_proc.terminate()
            try:
                anvil_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                anvil_proc.kill()
                anvil_proc.wait(timeout=5)
        os.environ.clear()
        os.environ.update(saved_env)

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P3 Group 3 Smoke Integration Test")
    parser.add_argument("--output-dir", default=None, help="Optional output directory for smoke.json report")
    args = parser.parse_args()

    result = run_smoke()
    report_json = json.dumps(result, indent=2)
    print(report_json)

    if args.output_dir:
        out_p = Path(args.output_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        (out_p / "p3_group3_smoke.json").write_text(report_json, encoding="utf-8")

    sys.exit(0 if result["status"] == "PASS" else 1)
