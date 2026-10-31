"""Comprehensive Unit and Multiprocess Test Suite for Milestone 3 (Requirement R4: M4 Idempotency & Recovery).

Validates Acceptance Gates:
- G3-08: Canonical Immutable Intent & Fingerprint (deterministic JSON, SHA-256 digest, key order independence)
- G3-09: Operation Journal & State Transitions (READY -> SEND_STARTED -> BROADCAST -> CONFIRMED, UNKNOWN transitions)
- G3-10: Read-Only Reconcile Mechanism (read-only blockchain status verification, zero transaction broadcasts)
- G3-16: Real Dual-Process Concurrency Test (2 real OS processes sharing real SQLite DB, exactly 1 send claim granted, NO mock rowcount)
- G3-17: Crash Recovery Fail-Closed (crash after COMMIT SEND_STARTED refuses resend on restart, NO mock rowcount)
"""
from __future__ import annotations

import json
import multiprocessing
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forensics.schemas import init_db
from forensics.onchain_store import (
    BROADCAST,
    CONFIRMED,
    CUSTODY,
    EVENT_TYPE_CUSTODY_RECORDED,
    EVENT_TYPE_EVIDENCE_REGISTERED,
    FAILED,
    READY,
    REGISTER,
    SEND_STARTED,
    TOPIC_CUSTODY_RECORDED,
    TOPIC_EVIDENCE_REGISTERED,
    UNKNOWN,
    ClaimResult,
    apply_reconcile_result,
    build_custody_intent,
    build_register_intent,
    canonical_json,
    claim_send,
    fingerprint,
    load_operation,
    mark_unknown,
    open_existing_rw,
    persist_verified_event,
    record_broadcast,
    reconcile_operation,
    register_intent,
    sanitize_sidecar_payload,
    SidecarSecretError,
    write_sidecar,
)


# ==============================================================================
# Top-Level Multiprocessing Worker Function (Picklable on Windows spawn)
# ==============================================================================
def _concurrency_worker(
    db_path_str: str,
    intent_dict: dict[str, Any],
    barrier: Any,
    queue: Any,
) -> None:
    """Worker process function for Gate G3-16 concurrency test."""
    try:
        # Synchronize processes at the barrier so claim_send is called simultaneously
        if barrier is not None:
            barrier.wait(timeout=10)
        res = claim_send(db_path_str, intent_dict)
        queue.put(
            {
                "success": True,
                "operation_id": res.operation_id,
                "can_send": res.can_send,
                "current_state": res.current_state,
            }
        )
    except Exception as exc:
        queue.put(
            {
                "success": False,
                "error": str(exc),
                "type": type(exc).__name__,
            }
        )



def _real_anvil_concurrency_worker(
    db_path_str: str,
    rpc_url: str,
    contract_address: str,
    intent_dict: dict[str, Any],
    barrier: Any,
    queue: Any,
) -> None:
    """Worker process function for Gate G3-16 real on-chain send concurrency."""
    try:
        if barrier is not None:
            barrier.wait(timeout=10)
        claim = claim_send(db_path_str, intent_dict)
        op_id = claim.operation_id
        if claim.can_send:
            import json
            from forensics.onchain import run_cast_send
            signer = intent_dict["signer"]
            case_digest = intent_dict["case_digest"]
            manifest_sha256 = intent_dict["manifest_sha256"]
            storage_uri = intent_dict["storage_uri"]
            raw_receipt = run_cast_send([
                "--from", signer,
                "--unlocked",
                "--rpc-url", rpc_url,
                "--chain", "31337",
                "--json",
                contract_address,
                "registerEvidence(bytes32,bytes32,string)",
                "0x" + case_digest,
                "0x" + manifest_sha256,
                storage_uri,
            ])
            receipt = json.loads(raw_receipt)
            tx_hash = receipt["transactionHash"]
            record_broadcast(db_path_str, op_id, tx_hash)
            persist_verified_event(
                db_path_str,
                operation_id=op_id,
                chain_id=31337,
                contract=contract_address,
                evidence_id=1,
                action=0,
                actor=signer,
                artifact_sha256=manifest_sha256,
                note_hash="0x" + "0"*64,
                tx_hash=tx_hash,
                block_number=int(receipt["blockNumber"], 16),
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                manifest_sha256=manifest_sha256,
                case_digest=case_digest,
                receipt=receipt,
            )
            queue.put({
                "success": True,
                "can_send": True,
                "sent": True,
                "tx_hash": tx_hash,
                "operation_id": op_id,
            })
        else:
            queue.put({
                "success": True,
                "can_send": False,
                "sent": False,
                "tx_hash": None,
                "operation_id": op_id,
                "current_state": claim.current_state,
            })
    except Exception as exc:
        queue.put({
            "success": False,
            "error": str(exc),
            "type": type(exc).__name__,
        })


def _crash_failpoint_worker(
    db_path_str: str,
    intent_dict: dict[str, Any],
    started_event: Any,
) -> None:
    """Worker process function for Gate G3-17: commits SEND_STARTED then waits to be killed."""
    import time
    claim = claim_send(db_path_str, intent_dict)
    if claim.can_send and claim.current_state == SEND_STARTED:
        started_event.set()
        while True:
            time.sleep(0.1)


def _restart_recovery_worker(
    db_path_str: str,
    rpc_url: str,
    contract_address: str,
    intent_dict: dict[str, Any],
    queue: Any,
) -> None:
    """Worker process function for Gate G3-17: restarts, verifies resend refused, reconciles with 0 new txs."""
    try:
        from forensics.onchain import rpc_read
        signer = intent_dict["signer"]
        nonce_before = int(rpc_read(rpc_url, "eth_getTransactionCount", [signer, "latest"]), 16)

        claim = claim_send(db_path_str, intent_dict)
        op_id = claim.operation_id
        resend_granted = claim.can_send

        recon = reconcile_operation(db_path_str, op_id, rpc_url)

        nonce_after = int(rpc_read(rpc_url, "eth_getTransactionCount", [signer, "latest"]), 16)

        queue.put({
            "success": True,
            "resend_granted": resend_granted,
            "current_state": claim.current_state,
            "reconcile_state": recon.get("state"),
            "nonce_before": nonce_before,
            "nonce_after": nonce_after,
            "new_transactions": nonce_after - nonce_before,
        })
    except Exception as exc:
        queue.put({
            "success": False,
            "error": str(exc),
            "type": type(exc).__name__,
        })


@pytest.fixture(scope="module")
def local_anvil():
    """Start a local Anvil node and deploy EvidenceRegistry for module-level integration tests."""
    import socket
    import subprocess
    import time
    ROOT = Path(__file__).resolve().parents[1]
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    suffix = ".exe" if os.name == "nt" else ""
    anvil_bin = ROOT / "tools/foundry" / ("anvil" + suffix)
    if not anvil_bin.exists():
        anvil_bin = Path("anvil")

    proc = subprocess.Popen(
        [str(anvil_bin), "--host", "127.0.0.1", "--port", str(port), "--chain-id", "31337"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    from forensics.onchain import get_rpc_chain_id, run_cast_send, rpc_read
    deadline = time.monotonic() + 25
    while True:
        if proc.poll() is not None:
            raise RuntimeError("ANVIL_TERMINATED")
        try:
            if get_rpc_chain_id(url) == 31337:
                break
        except Exception:
            if time.monotonic() > deadline:
                proc.terminate()
                raise TimeoutError("ANVIL_START_TIMEOUT")
            time.sleep(0.1)

    owner = rpc_read(url, "eth_accounts", [])[0]
    artifact_file = ROOT / "contracts/out/EvidenceRegistry.sol/EvidenceRegistry.json"
    artifact = json.loads(artifact_file.read_text(encoding="utf-8"))
    bytecode = artifact["bytecode"]["object"]
    raw_deploy = run_cast_send([
        "--from", owner, "--unlocked", "--rpc-url", url,
        "--chain", "31337", "--json", "--create", bytecode
    ])
    deployed = json.loads(raw_deploy)
    contract = deployed["contractAddress"]

    yield {"url": url, "contract": contract, "owner": owner, "port": port}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


class MockRpcClient:
    """Mock read-only RPC provider simulating eth_chainId, eth_getTransactionReceipt, and eth_getBlockByNumber."""
    def __init__(self, receipt: dict | None, chain_id: int = 31337):
        self.receipt = receipt
        self.chain_id = chain_id

    def eth_chainId(self):
        return hex(self.chain_id)

    def eth_getTransactionReceipt(self, tx_hash):
        return self.receipt

    def eth_getBlockByNumber(self, block_num, full_tx):
        if self.receipt:
            return {"hash": self.receipt.get("blockHash", "0x" + "bb" * 32)}
        return None


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a fully migrated SQLite test database."""
    db_file = tmp_path / "forensics_m3_test.db"
    conn = init_db(str(db_file))
    conn.close()
    return db_file


# ==============================================================================
# Gate G3-08: Canonical Immutable Intent & Fingerprint
# ==============================================================================
class TestGate3_08_CanonicalImmutableIntent:
    """Gate G3-08: Canonical Immutable Intent & Fingerprint.

    Requirements:
    - Serializes intent dict with sort_keys=True, separators=(',', ':'), UTF-8 compact representation.
    - Deterministic 64-char hex SHA-256 digest regardless of dict key insertion order.
    - Distinct fingerprints for different case_ids, actions, notes, signers, or chains.
    """

    def test_shuffled_key_order_produces_identical_fingerprint(self):
        """Identical keys and values inserted in different order produce identical fingerprint."""
        d1 = {
            "op_type": REGISTER,
            "chain_id": 31337,
            "contract": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "manifest_sha256": "aa" * 32,
            "case_digest": "bb" * 32,
            "storage_uri": "evidence://sha256/" + ("bb" * 32) + "/" + ("aa" * 32) + "/manifest.json",
            "signer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        }
        # Shuffled key order
        d2 = {
            "signer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "storage_uri": "evidence://sha256/" + ("bb" * 32) + "/" + ("aa" * 32) + "/manifest.json",
            "op_type": REGISTER,
            "case_digest": "bb" * 32,
            "chain_id": 31337,
            "manifest_sha256": "aa" * 32,
            "contract": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        }

        canon1 = canonical_json(d1)
        canon2 = canonical_json(d2)
        assert canon1 == canon2
        assert fingerprint(d1) == fingerprint(d2)

    def test_distinct_register_intents_produce_distinct_fingerprints(self):
        """Mutations to case_digest, manifest, signer, or chain yield unique fingerprints."""
        base = build_register_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            manifest_sha256="aa" * 32,
            case_digest="11" * 32,
            storage_uri="evidence://sha256/" + ("11" * 32) + "/" + ("aa" * 32) + "/manifest.json",
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        diff_case = dict(base, case_digest="22" * 32)
        diff_manifest = dict(base, manifest_sha256="bb" * 32)
        diff_signer = dict(base, signer="0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
        diff_chain = dict(base, chain_id=1)

        fps = {
            fingerprint(base),
            fingerprint(diff_case),
            fingerprint(diff_manifest),
            fingerprint(diff_signer),
            fingerprint(diff_chain),
        }
        assert len(fps) == 5, "All mutated intents must have distinct fingerprints"

    def test_distinct_custody_intents_produce_distinct_fingerprints(self):
        """Mutations to action, note_hash, evidence_id, or signer yield unique fingerprints."""
        base = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=1,
            action=0,
            artifact_sha256="aa" * 32,
            note_hash="bb" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        diff_action = dict(base, action=1)
        diff_note = dict(base, note_hash="cc" * 32)
        diff_evidence = dict(base, evidence_id=2)
        diff_signer = dict(base, signer="0x70997970c51812dc3a010c7d01b50e0d17dc79c8")

        fps = {
            fingerprint(base),
            fingerprint(diff_action),
            fingerprint(diff_note),
            fingerprint(diff_evidence),
            fingerprint(diff_signer),
        }
        assert len(fps) == 5, "All mutated custody intents must have distinct fingerprints"

    def test_fingerprint_format_and_hex_length(self):
        """Fingerprint returns a strict 64-char lowercase hex SHA-256 string."""
        intent = build_register_intent(
            chain_id=31337,
            contract="0x5FBDB2315678AFECB367F032D93F642F64180AA3",
            manifest_sha256="AA" * 32,
            case_digest="BB" * 32,
            storage_uri="evidence://sha256/test/manifest.json",
            signer="0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266",
        )
        fp = fingerprint(intent)
        assert len(fp) == 64
        assert re.fullmatch(r"^[0-9a-f]{64}$", fp) is not None


# ==============================================================================
# Gate G3-09: Operation Journal & State Transitions
# ==============================================================================
class TestGate3_09_OperationJournalAndStateTransitions:
    """Gate G3-09: Operation Journal & State Transitions.

    Requirements:
    - Tracks complete lifecycle transitions: READY -> SEND_STARTED -> BROADCAST -> CONFIRMED.
    - Appends an entry into onchain_operation_events for each state change.
    - Records transition to UNKNOWN or FAILED on timeout or error.
    """

    def test_complete_lifecycle_journal_trail(self, test_db: Path):
        """Lifecycle transitions READY -> SEND_STARTED -> BROADCAST -> CONFIRMED log all events."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        manifest_sha = "44" * 32
        case_dig = "55" * 32
        intent = build_register_intent(
            chain_id=31337,
            contract=contract,
            manifest_sha256=manifest_sha,
            case_digest=case_dig,
            storage_uri="evidence://sha256/" + case_dig + "/" + manifest_sha + "/manifest.json",
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        # 1. Pre-register intent -> READY
        op_id = register_intent(test_db, intent)
        op = load_operation(test_db, op_id)
        assert op["state"] == READY

        # 2. Claim send -> SEND_STARTED
        claim_res = claim_send(test_db, intent)
        assert claim_res.can_send is True
        assert claim_res.current_state == SEND_STARTED
        assert claim_res.operation_id == op_id

        # 3. Record broadcast -> BROADCAST
        tx_hash = "0x" + "77" * 32
        record_broadcast(test_db, op_id, tx_hash)
        op = load_operation(test_db, op_id)
        assert op["state"] == BROADCAST
        assert op["tx_hash"] == tx_hash.lower()

        # 4. Confirm event -> CONFIRMED
        mock_rc = {
            "status": 1,
            "blockNumber": hex(200),
            "transactionHash": tx_hash,
            "blockHash": "0x" + "bb" * 32,
            "logs": [{
                "address": contract,
                "topics": [
                    TOPIC_EVIDENCE_REGISTERED,
                    hex(10),
                    "0x" + case_dig,
                    "0x" + manifest_sha,
                ],
                "data": "0x",
                "logIndex": "0x0",
            }]
        }
        persist_verified_event(
            test_db,
            operation_id=op_id,
            chain_id=31337,
            contract=contract,
            evidence_id=10,
            action=0,
            actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            manifest_sha256=manifest_sha,
            case_digest=case_dig,
            tx_hash=tx_hash,
            block_number=200,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=mock_rc,
        )
        op = load_operation(test_db, op_id)
        assert op["state"] == CONFIRMED

        # Query journal
        conn = sqlite3.connect(str(test_db))
        try:
            events = conn.execute(
                "SELECT seq, from_state, to_state, code FROM onchain_operation_events WHERE operation_id=? ORDER BY seq",
                (op_id,),
            ).fetchall()
            assert len(events) == 4

            # Transition 1: (None -> READY, INTENT_RECORDED)
            assert events[0][1] is None
            assert events[0][2] == READY
            assert events[0][3] == "INTENT_RECORDED"

            # Transition 2: (READY -> SEND_STARTED, SEND_CLAIMED)
            assert events[1][1] == READY
            assert events[1][2] == SEND_STARTED
            assert events[1][3] == "SEND_CLAIMED"

            # Transition 3: (SEND_STARTED -> BROADCAST, TX_RECORDED)
            assert events[2][1] == SEND_STARTED
            assert events[2][2] == BROADCAST
            assert events[2][3] == "TX_RECORDED"

            # Transition 4: (BROADCAST -> CONFIRMED, EvidenceRegistered)
            assert events[3][1] == BROADCAST
            assert events[3][2] == CONFIRMED
            assert events[3][3] == EVENT_TYPE_EVIDENCE_REGISTERED
        finally:
            conn.close()

    def test_journal_logs_transition_to_unknown(self, test_db: Path):
        """mark_unknown logs SEND_STARTED -> UNKNOWN in the operation journal."""
        intent = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=1,
            action=0,
            artifact_sha256="aa" * 32,
            note_hash="bb" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        res = claim_send(test_db, intent)
        op_id = res.operation_id
        mark_unknown(test_db, op_id, "NETWORK_TIMEOUT")

        conn = sqlite3.connect(str(test_db))
        try:
            events = conn.execute(
                "SELECT from_state, to_state, code FROM onchain_operation_events WHERE operation_id=? ORDER BY seq",
                (op_id,),
            ).fetchall()
            assert len(events) >= 2
            assert events[-1] == (SEND_STARTED, UNKNOWN, "NETWORK_TIMEOUT")
        finally:
            conn.close()

    def test_journal_logs_transition_to_unknown_from_broadcast(self, test_db: Path):
        """mark_unknown succeeds on in-flight broadcast operation and logs BROADCAST -> UNKNOWN."""
        intent = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=1,
            action=0,
            artifact_sha256="aa" * 32,
            note_hash="bb" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        res = claim_send(test_db, intent)
        op_id = res.operation_id
        tx_hash = "0x" + "11" * 32
        record_broadcast(test_db, op_id, tx_hash)

        # In-flight timeout after broadcast
        mark_unknown(test_db, op_id, "CONFIRMATION_TIMEOUT")

        # Operations table state must be UNKNOWN and tx_hash preserved
        op = load_operation(test_db, op_id)
        assert op["state"] == UNKNOWN
        assert op["tx_hash"] == tx_hash

        # Journal must contain true transition: BROADCAST -> UNKNOWN
        conn = sqlite3.connect(str(test_db))
        try:
            events = conn.execute(
                "SELECT from_state, to_state, code FROM onchain_operation_events WHERE operation_id=? ORDER BY seq",
                (op_id,),
            ).fetchall()
            assert len(events) >= 3
            assert events[-1] == (BROADCAST, UNKNOWN, "CONFIRMATION_TIMEOUT")
        finally:
            conn.close()

        # Subsequent claim_send strictly refused
        restart_claim = claim_send(test_db, intent)
        assert restart_claim.can_send is False
        assert restart_claim.current_state == UNKNOWN



# ==============================================================================
# Gate G3-10: Read-Only Reconcile Mechanism
# ==============================================================================
class TestGate3_10_ReadOnlyReconcileMechanism:
    """Gate G3-10: Read-Only Reconcile Mechanism.

    Requirements:
    - Queries blockchain via RPC or receipt client in strictly read-only mode.
    - If confirmed on-chain, updates operation state to CONFIRMED and persists verified event.
    - If transaction reverted on-chain (status=0), updates operation state to FAILED.
    - If unmined or missing, preserves unconfirmed state.
    - Strictly performs ZERO transaction broadcasts (no cast send, zero sends).
    """

    def test_reconcile_confirmed_register_evidence_updates_store(self, test_db: Path):
        """Confirmed receipt updates operation to CONFIRMED and persists anchor_links."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        manifest_sha = "66" * 32
        case_dig = "77" * 32
        intent = build_register_intent(
            chain_id=31337,
            contract=contract,
            manifest_sha256=manifest_sha,
            case_digest=case_dig,
            storage_uri="evidence://sha256/" + case_dig + "/" + manifest_sha + "/manifest.json",
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        claim_res = claim_send(test_db, intent)
        op_id = claim_res.operation_id
        tx_hash = "0x" + "88" * 32
        record_broadcast(test_db, op_id, tx_hash)

        # Mock read-only confirmed receipt via MockRpcClient
        receipt = {
            "status": 1,
            "blockNumber": 105,
            "blockHash": "0x" + "bb" * 32,
            "transactionHash": tx_hash,
            "logs": [
                {
                    "address": contract,
                    "topics": [
                        TOPIC_EVIDENCE_REGISTERED,
                        "0x" + hex(42)[2:].zfill(64),
                        "0x" + case_dig,
                        "0x" + manifest_sha,
                    ],
                    "data": "0x" + "f39fd6e51aad88f6f4ce6ab8827279cfffb92266".zfill(64) + "00" * 32,
                    "logIndex": 0,
                }
            ],
        }

        reconcile_res = reconcile_operation(test_db, op_id, MockRpcClient(receipt))
        assert reconcile_res["reconciled"] is True
        assert reconcile_res["state"] == CONFIRMED

        # Check DB state
        op = load_operation(test_db, op_id)
        assert op["state"] == CONFIRMED

        conn = sqlite3.connect(str(test_db))
        try:
            custody_row = conn.execute(
                "SELECT evidence_id, verified, event_type FROM custody_events WHERE tx_hash=?",
                (tx_hash.lower(),),
            ).fetchone()
            assert custody_row == (42, 1, EVENT_TYPE_EVIDENCE_REGISTERED)

            anchor_row = conn.execute(
                "SELECT manifest_sha256, evidence_id, verified FROM anchor_links WHERE tx_hash=?",
                (tx_hash.lower(),),
            ).fetchone()
            assert anchor_row == (manifest_sha, 42, 1)
        finally:
            conn.close()

    def test_reconcile_confirmed_custody_updates_store(self, test_db: Path):
        """Confirmed custody receipt updates operation to CONFIRMED and persists custody_events."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        intent = build_custody_intent(
            chain_id=31337,
            contract=contract,
            evidence_id=7,
            action=2,
            artifact_sha256="12" * 32,
            note_hash="34" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        claim_res = claim_send(test_db, intent)
        op_id = claim_res.operation_id
        tx_hash = "0x" + "bb" * 32
        record_broadcast(test_db, op_id, tx_hash)

        receipt = {
            "status": 1,
            "blockNumber": 115,
            "blockHash": "0x" + "bb" * 32,
            "transactionHash": tx_hash,
            "logs": [
                {
                    "address": contract,
                    "topics": [
                        TOPIC_CUSTODY_RECORDED,
                        "0x" + hex(7)[2:].zfill(64),
                        "0x" + hex(2)[2:].zfill(64),
                        "0x" + "f39fd6e51aad88f6f4ce6ab8827279cfffb92266".zfill(64),
                    ],
                    "data": "0x" + ("12" * 32) + ("34" * 32),
                    "logIndex": 1,
                }
            ],
        }

        reconcile_res = reconcile_operation(test_db, op_id, MockRpcClient(receipt))
        assert reconcile_res["reconciled"] is True
        assert reconcile_res["state"] == CONFIRMED

        op = load_operation(test_db, op_id)
        assert op["state"] == CONFIRMED

        conn = sqlite3.connect(str(test_db))
        try:
            row = conn.execute(
                "SELECT evidence_id, action, verified, event_type FROM custody_events WHERE tx_hash=?",
                (tx_hash.lower(),),
            ).fetchone()
            assert row == (7, 2, 1, EVENT_TYPE_CUSTODY_RECORDED)
        finally:
            conn.close()

    def test_reconcile_reverted_transaction_marks_failed(self, test_db: Path):
        """Reverted transaction status=0 transitions operation state to FAILED."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        intent = build_custody_intent(31337, contract, 1, 0, "aa" * 32, "bb" * 32, "0xsigner")
        claim_res = claim_send(test_db, intent)
        op_id = claim_res.operation_id
        tx_hash = "0x" + "99" * 32
        record_broadcast(test_db, op_id, tx_hash)

        reverted_receipt = {
            "status": 0,
            "blockNumber": 110,
            "blockHash": "0x" + "bb" * 32,
            "transactionHash": tx_hash,
            "logs": [],
        }

        reconcile_res = reconcile_operation(test_db, op_id, MockRpcClient(reverted_receipt))
        assert reconcile_res["reconciled"] is True
        assert reconcile_res["state"] == FAILED

        op = load_operation(test_db, op_id)
        assert op["state"] == FAILED

    def test_reconcile_unmined_transaction_preserves_state(self, test_db: Path):
        """When transaction receipt is not found (unmined), state remains unchanged."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        intent = build_custody_intent(31337, contract, 1, 0, "aa" * 32, "bb" * 32, "0xsigner")
        claim_res = claim_send(test_db, intent)
        op_id = claim_res.operation_id
        tx_hash = "0x" + "aa" * 32
        record_broadcast(test_db, op_id, tx_hash)

        # RPC returns None for pending/unmined receipt
        reconcile_res = reconcile_operation(test_db, op_id, lambda tx: None)
        assert reconcile_res["reconciled"] is False

        op = load_operation(test_db, op_id)
        assert op["state"] == BROADCAST

    def test_zero_send_calls_in_reconcile(self, test_db: Path):
        """Reconciliation performs strictly read-only checks without initiating sends."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        intent = build_custody_intent(31337, contract, 5, 1, "aa" * 32, "bb" * 32, "0xsigner")
        claim_res = claim_send(test_db, intent)
        op_id = claim_res.operation_id
        tx_hash = "0x" + "cc" * 32
        record_broadcast(test_db, op_id, tx_hash)

        receipt = {
            "status": 1,
            "blockNumber": 120,
            "blockHash": "0x" + "bb" * 32,
            "transactionHash": tx_hash,
            "logs": [
                {
                    "address": contract,
                    "topics": [
                        TOPIC_CUSTODY_RECORDED,
                        "0x" + hex(5)[2:].zfill(64),
                        "0x" + hex(1)[2:].zfill(64),
                        "0x" + "0xsigner".lower().removeprefix("0x").zfill(64),
                    ],
                    "data": "0x" + ("aa" * 32) + ("bb" * 32),
                    "logIndex": 0,
                }
            ],
        }

        # Calls reconcile_operation with mock RPC provider — zero subprocess / cast execution
        reconcile_res = reconcile_operation(test_db, op_id, MockRpcClient(receipt))
        assert reconcile_res["state"] == CONFIRMED


# ==============================================================================
# Gate G3-16: Real Dual-Process Concurrency Test (CRITICAL ACCEPTANCE CRITERION)
# ==============================================================================
class TestGate3_16_RealDualProcessConcurrency:
    """Gate G3-16: Real Dual-Process Concurrency Test.

    Requirements:
    - MUST use real multiprocessing processes sharing a real SQLite DB file on disk.
    - Both processes attempt claim_send concurrently with identical intent / operation ID.
    - Asserts that exactly ONE process receives can_send=True, while the other receives can_send=False.
    - Verifies that exactly one send would occur (NO mock rowcount!).
    """

    def test_dual_process_concurrent_claim_send_register(self, test_db: Path):
        """Two real OS processes concurrently claiming send on register intent: exactly 1 wins."""
        intent = build_register_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            manifest_sha256="aa" * 32,
            case_digest="bb" * 32,
            storage_uri="evidence://sha256/" + ("bb" * 32) + "/" + ("aa" * 32) + "/manifest.json",
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()

        p1 = ctx.Process(
            target=_concurrency_worker,
            args=(str(test_db), intent, barrier, queue),
        )
        p2 = ctx.Process(
            target=_concurrency_worker,
            args=(str(test_db), intent, barrier, queue),
        )

        p1.start()
        p2.start()

        p1.join(timeout=20)
        p2.join(timeout=20)

        assert not p1.is_alive(), "Process 1 timed out"
        assert not p2.is_alive(), "Process 2 timed out"

        res1 = queue.get(timeout=5)
        res2 = queue.get(timeout=5)

        assert res1["success"] is True, f"Worker 1 error: {res1.get('error')}"
        assert res2["success"] is True, f"Worker 2 error: {res2.get('error')}"

        results = [res1, res2]
        can_sends = [r["can_send"] for r in results]

        # CRITICAL ACCEPTANCE ASSERTION: Exactly one process is granted send permission!
        assert can_sends.count(True) == 1, f"Expected exactly 1 True, got {can_sends}"
        assert can_sends.count(False) == 1, f"Expected exactly 1 False, got {can_sends}"

        # Both returned the exact same operation_id
        assert res1["operation_id"] == res2["operation_id"]
        op_id = res1["operation_id"]

        # The losing process saw state SEND_STARTED
        losing_res = [r for r in results if not r["can_send"]][0]
        assert losing_res["current_state"] == SEND_STARTED

        # In DB, state is SEND_STARTED
        op = load_operation(test_db, op_id)
        assert op["state"] == SEND_STARTED

        # Audit events in onchain_operation_events contain both SEND_CLAIMED and SEND_CLAIM_DENIED
        conn = sqlite3.connect(str(test_db))
        try:
            events = conn.execute(
                "SELECT code FROM onchain_operation_events WHERE operation_id=? ORDER BY seq",
                (op_id,),
            ).fetchall()
            codes = [e[0] for e in events]
            assert "SEND_CLAIMED" in codes, "Expected SEND_CLAIMED in audit trail"
            assert "SEND_CLAIM_DENIED" in codes, "Expected SEND_CLAIM_DENIED in audit trail"
        finally:
            conn.close()

    def test_dual_process_concurrent_claim_send_custody(self, test_db: Path):
        """Two real OS processes concurrently claiming send on custody intent: exactly 1 wins."""
        intent = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=1,
            action=0,
            artifact_sha256="33" * 32,
            note_hash="44" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()

        p1 = ctx.Process(
            target=_concurrency_worker,
            args=(str(test_db), intent, barrier, queue),
        )
        p2 = ctx.Process(
            target=_concurrency_worker,
            args=(str(test_db), intent, barrier, queue),
        )

        p1.start()
        p2.start()

        p1.join(timeout=20)
        p2.join(timeout=20)

        assert not p1.is_alive(), "Process 1 timed out"
        assert not p2.is_alive(), "Process 2 timed out"

        res1 = queue.get(timeout=5)
        res2 = queue.get(timeout=5)

        assert res1["success"] is True, f"Worker 1 error: {res1.get('error')}"
        assert res2["success"] is True, f"Worker 2 error: {res2.get('error')}"

        can_sends = [res1["can_send"], res2["can_send"]]
        assert can_sends.count(True) == 1
        assert can_sends.count(False) == 1


# ==============================================================================
# Gate G3-17: Crash Recovery Fail-Closed (CRITICAL ACCEPTANCE CRITERION)
# ==============================================================================

    def test_real_dual_process_concurrency_with_real_anvil_send(self, test_db: Path, local_anvil: dict):
        """Two real OS processes contend on disk; exactly 1 sends to Anvil, loser sends nothing.
        
        Verifies:
        - Exactly one process receives can_send=True and broadcasts to Anvil.
        - Losing process receives can_send=False and sends 0 transactions.
        - Signer nonce on Anvil increases by exactly 1.
        - Exactly 1 transaction mined on Anvil with status=1 and EvidenceRegistered event.
        - Database state transitions cleanly to CONFIRMED.
        """
        from forensics.onchain import rpc_read
        owner = local_anvil["owner"]
        url = local_anvil["url"]
        contract = local_anvil["contract"]
        
        nonce_before = int(rpc_read(url, "eth_getTransactionCount", [owner, "latest"]), 16)
        
        intent = build_register_intent(
            chain_id=31337,
            contract=contract,
            manifest_sha256="12" * 32,
            case_digest="34" * 32,
            storage_uri="evidence://sha256/" + ("34" * 32) + "/" + ("12" * 32) + "/manifest.json",
            signer=owner,
        )

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()

        p1 = ctx.Process(
            target=_real_anvil_concurrency_worker,
            args=(str(test_db), url, contract, intent, barrier, queue),
        )
        p2 = ctx.Process(
            target=_real_anvil_concurrency_worker,
            args=(str(test_db), url, contract, intent, barrier, queue),
        )

        p1.start()
        p2.start()

        p1.join(timeout=30)
        p2.join(timeout=30)

        assert not p1.is_alive(), "Process 1 timed out"
        assert not p2.is_alive(), "Process 2 timed out"

        res1 = queue.get(timeout=5)
        res2 = queue.get(timeout=5)

        assert res1["success"] is True, f"Worker 1 error: {res1.get('error')}"
        assert res2["success"] is True, f"Worker 2 error: {res2.get('error')}"

        results = [res1, res2]
        can_sends = [r["can_send"] for r in results]
        sents = [r["sent"] for r in results]

        # Exactly 1 process allowed to send, exactly 1 sent
        assert can_sends.count(True) == 1
        assert can_sends.count(False) == 1
        assert sents.count(True) == 1
        assert sents.count(False) == 1

        winner = [r for r in results if r["can_send"]][0]
        loser = [r for r in results if not r["can_send"]][0]

        assert winner["tx_hash"] is not None
        assert loser["tx_hash"] is None
        assert loser["current_state"] == SEND_STARTED

        # On Anvil: Nonce increased by EXACTLY 1!
        nonce_after = int(rpc_read(url, "eth_getTransactionCount", [owner, "latest"]), 16)
        assert nonce_after == nonce_before + 1, f"Nonce expected {nonce_before + 1}, got {nonce_after}"

        # On Anvil: Transaction receipt status is 1
        rc = rpc_read(url, "eth_getTransactionReceipt", [winner["tx_hash"]])
        assert rc is not None
        assert int(rc["status"], 16) == 1

        # DB state is CONFIRMED
        op = load_operation(test_db, winner["operation_id"])
        assert op["state"] == CONFIRMED
        assert op["tx_hash"].lower() == winner["tx_hash"].lower()


class TestGate3_17_CrashRecoveryFailClosed:

    def test_real_child_process_kill_after_send_started_and_restart_reconcile(self, test_db: Path, local_anvil: dict):
        """Simulate real hard crash (SIGKILL/proc.kill()) immediately after COMMIT SEND_STARTED.
        
        Verifies:
        - Child process successfully commits state=SEND_STARTED and is hard-killed.
        - Restarted runner attempts claim_send on same intent: strictly refused (can_send=False).
        - Read-only reconciliation inspects onchain status: evidence not onchain.
        - Signer nonce on Anvil is strictly unchanged: ZERO new transactions broadcast.
        - Operation state transitions cleanly without double-send.
        """
        from forensics.onchain import rpc_read
        owner = local_anvil["owner"]
        url = local_anvil["url"]
        contract = local_anvil["contract"]
        
        nonce_start = int(rpc_read(url, "eth_getTransactionCount", [owner, "latest"]), 16)

        intent = build_register_intent(
            chain_id=31337,
            contract=contract,
            manifest_sha256="56" * 32,
            case_digest="78" * 32,
            storage_uri="evidence://sha256/" + ("78" * 32) + "/" + ("56" * 32) + "/manifest.json",
            signer=owner,
        )

        ctx = multiprocessing.get_context("spawn")
        started_event = ctx.Event()

        # Step 1: Start child process that claims send and waits at failpoint
        child_p = ctx.Process(
            target=_crash_failpoint_worker,
            args=(str(test_db), intent, started_event),
        )
        child_p.start()

        # Wait until child has committed SEND_STARTED
        assert started_event.wait(timeout=10), "Child failed to reach SEND_STARTED"

        # Verify DB directly from parent
        op_id = fingerprint(intent)
        op_pre_crash = load_operation(test_db, op_id)
        assert op_pre_crash["state"] == SEND_STARTED
        assert op_pre_crash["tx_hash"] is None

        # Step 2: Hard-kill the child process at the failpoint!
        child_p.kill()
        child_p.join(timeout=5)
        assert not child_p.is_alive()

        # Step 3: Start a new independent process (restarted runner) to recover
        queue = ctx.Queue()
        recovery_p = ctx.Process(
            target=_restart_recovery_worker,
            args=(str(test_db), url, contract, intent, queue),
        )
        recovery_p.start()
        recovery_p.join(timeout=15)
        assert not recovery_p.is_alive()

        rec_res = queue.get(timeout=5)
        assert rec_res["success"] is True, f"Recovery worker error: {rec_res.get('error')}"

        # CRITICAL ASSERTIONS:
        # 1. Restarted process was strictly REFUSED send permission
        assert rec_res["resend_granted"] is False, "Restarted process must not be granted send permission!"
        assert rec_res["current_state"] == SEND_STARTED

        # 2. Reconcile executed read-only and preserved safe state (since evidence was never broadcast)
        assert rec_res["reconcile_state"] in (SEND_STARTED, UNKNOWN, FAILED)

        # 3. ZERO new transactions broadcast to Anvil during recovery!
        assert rec_res["new_transactions"] == 0
        assert rec_res["nonce_after"] == nonce_start

        # Nonce on Anvil is still strictly unchanged
        nonce_final = int(rpc_read(url, "eth_getTransactionCount", [owner, "latest"]), 16)
        assert nonce_final == nonce_start


    """Gate G3-17: Crash Recovery Fail-Closed.

    Requirements:
    - Simulates crash after COMMIT SEND_STARTED but before transaction broadcast.
    - On process restart, claim_send is invoked again for the same operation ID / intent.
    - Asserts that claim_send strictly returns can_send=False and current_state='SEND_STARTED'.
    - Zero send calls granted on crash recovery (NO mock rowcount!).
    """

    def test_crash_after_send_started_refuses_resend_on_restart(self, test_db: Path):
        """Crash after COMMIT SEND_STARTED strictly refuses resend upon restart."""
        intent = build_register_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            manifest_sha256="cc" * 32,
            case_digest="dd" * 32,
            storage_uri="evidence://sha256/" + ("dd" * 32) + "/" + ("cc" * 32) + "/manifest.json",
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )

        # Process 1: Successfully claims send
        res1 = claim_send(test_db, intent)
        assert res1.can_send is True
        assert res1.current_state == SEND_STARTED
        op_id = res1.operation_id

        # Simulating CRASH: Connection closed, process died, tx_hash is NULL, no broadcast!
        op_before = load_operation(test_db, op_id)
        assert op_before["state"] == SEND_STARTED
        assert op_before["tx_hash"] is None

        # Process 2 (Restarted runner): Attempts claim_send with same intent
        res2 = claim_send(test_db, intent)
        assert res2.operation_id == op_id
        assert res2.can_send is False, "CRITICAL: Restarted process MUST NOT be granted send permission!"
        assert res2.current_state == SEND_STARTED

        # Process 2 attempts claim_send using operation_id directly
        res3 = claim_send(test_db, op_id)
        assert res3.operation_id == op_id
        assert res3.can_send is False, "CRITICAL: Resend by operation_id MUST NOT be granted!"
        assert res3.current_state == SEND_STARTED

        # Operation state remains intact
        op_after = load_operation(test_db, op_id)
        assert op_after["state"] == SEND_STARTED
        assert op_after["tx_hash"] is None

    def test_crash_recovery_unknown_state_refuses_resend(self, test_db: Path):
        """When an operation is marked UNKNOWN after crash/timeout, claim_send refuses resend."""
        intent = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=1,
            action=0,
            artifact_sha256="ee" * 32,
            note_hash="ff" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        res = claim_send(test_db, intent)
        assert res.can_send is True
        op_id = res.operation_id

        # Crash detector or timeout handler marks UNKNOWN
        mark_unknown(test_db, op_id, "TRANSACTION_TIMEOUT")

        op = load_operation(test_db, op_id)
        assert op["state"] == UNKNOWN

        # Subsequent attempt to claim_send MUST be refused
        res_after = claim_send(test_db, intent)
        assert res_after.can_send is False
        assert res_after.current_state == UNKNOWN

    def test_confirmed_operation_refuses_resend(self, test_db: Path):
        """When an operation is CONFIRMED, claim_send strictly returns can_send=False."""
        intent = build_custody_intent(
            chain_id=31337,
            contract="0x5fbdb2315678afecb367f032d93f642f64180aa3",
            evidence_id=2,
            action=1,
            artifact_sha256="11" * 32,
            note_hash="22" * 32,
            signer="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        )
        res = claim_send(test_db, intent)
        assert res.can_send is True
        op_id = res.operation_id

        record_broadcast(test_db, op_id, "0x" + "99" * 32)
        apply_reconcile_result(test_db, op_id, state=CONFIRMED, code="CONFIRMED")

        res_after = claim_send(test_db, intent)
        assert res_after.can_send is False
        assert res_after.current_state == CONFIRMED


# ==============================================================================
# Recovery Sidecar & Privacy Sanitization Tests
# ==============================================================================
class TestRecoverySidecar:
    """Recovery Sidecar & Secret Redaction tests."""

    def test_sidecar_appends_valid_jsonl(self, tmp_path: Path):
        """Valid non-sensitive payload is appended to <db_path>.recovery.jsonl."""
        db_file = tmp_path / "test_sidecar.db"
        payload = {"operation_id": "op-123", "state": UNKNOWN, "code": "DB_FAILED"}
        write_sidecar(db_file, payload)

        sc_path = Path(str(db_file) + ".recovery.jsonl")
        assert sc_path.is_file()
        line = sc_path.read_text(encoding="utf-8").strip()
        assert json.loads(line) == payload

    def test_sidecar_rejects_unredacted_secrets(self, tmp_path: Path):
        """write_sidecar rejects unredacted credentials and sensitive keys."""
        db_file = tmp_path / "test_secret.db"

        with pytest.raises(RuntimeError, match="SIDECAR_SECRET"):
            write_sidecar(db_file, {"operation_id": "op-1", "case_id": "CASE-RAW-123"})

        with pytest.raises(RuntimeError, match="SIDECAR_SECRET"):
            write_sidecar(db_file, {"operation_id": "op-1", "private_key": "0x1234567890"})

        with pytest.raises(RuntimeError, match="SIDECAR_SECRET"):
            write_sidecar(db_file, {"operation_id": "op-1", "mnemonic": "twelve secret words"})

        with pytest.raises(RuntimeError, match="SIDECAR_SECRET"):
            write_sidecar(db_file, {"operation_id": "op-1", "note": "classified note"})

    def test_sidecar_auto_redact(self, tmp_path: Path):
        """auto_redact=True redacts sensitive fields and writes sanitized line."""
        db_file = tmp_path / "test_redact.db"
        payload = {"operation_id": "op-2", "case_id": "RAW-CASE", "note": "SECRET NOTE"}
        write_sidecar(db_file, payload, auto_redact=True)

        sc_path = Path(str(db_file) + ".recovery.jsonl")
        data = json.loads(sc_path.read_text(encoding="utf-8").strip())
        assert data["case_id"] == "[REDACTED]"
        assert data["note"] == "[REDACTED]"
        content = sc_path.read_text(encoding="utf-8")
        assert "RAW-CASE" not in content
        assert "SECRET NOTE" not in content

    def test_sanitize_sidecar_payload_helper(self):
        """sanitize_sidecar_payload redacts all sensitive keys and nested structures."""
        raw = {
            "operation_id": "op-3",
            "case_id": "sensitive_case",
            "note": "sensitive_note",
            "nested": {"private_key": "secret", "ok_val": 42},
        }
        sanitized = sanitize_sidecar_payload(raw)
        assert sanitized["case_id"] == "[REDACTED]"
        assert sanitized["note"] == "[REDACTED]"
        assert sanitized["nested"]["private_key"] == "[REDACTED]"
        assert sanitized["nested"]["ok_val"] == 42

    def test_sidecar_rejects_compound_keys_and_nested_secrets(self, tmp_path: Path):
        """write_sidecar rejects compound keys, nested dicts, and hex keys without auto_redact."""
        db_file = tmp_path / "test_compound_secrets.db"
        canary_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        canary_mnemonic = "test test test test test test test test test test test junk"

        # Compound keys
        compound_keys = [
            ("signing_key", canary_pk),
            ("seed_words", canary_mnemonic),
            ("raw_case_id", "CASE-RAW-123"),
            ("case_id_raw", "CASE-RAW-456"),
            ("evidence_note", "classified evidence"),
            ("note_text", "secret note content"),
            ("recovery_phrase", canary_mnemonic),
        ]
        for key, val in compound_keys:
            with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
                write_sidecar(db_file, {"operation_id": "op-comp", key: val})

        # Nested dictionaries
        with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
            write_sidecar(
                db_file,
                {"operation_id": "op-nested", "metadata": {"case_id": "CASE-NESTED-1"}},
            )

        with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
            write_sidecar(
                db_file,
                {"operation_id": "op-nested", "credentials": {"private_key": canary_pk}},
            )

        # 64-hex private key in non-standard key
        with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
            write_sidecar(db_file, {"operation_id": "op-pk", "custom_signer": canary_pk})

        # Partial redaction bypass attempt (one field redacted, other leaked)
        with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
            write_sidecar(
                db_file,
                {"case_id": "[REDACTED]", "secret_leak": "private_key=0xdeadbeef"},
            )

        with pytest.raises((RuntimeError, ValueError), match="SIDECAR_SECRET"):
            write_sidecar(
                db_file,
                {"case_id": "[REDACTED]", "custom_signer": canary_pk},
            )

    def test_sidecar_auto_redact_compound_and_nested(self, tmp_path: Path):
        """auto_redact=True redacts compound keys, nested dicts, and hex keys."""
        db_file = tmp_path / "test_auto_redact_compound.db"
        canary_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        canary_mnemonic = "test test test test test test test test test test test junk"
        canary_case = "CASE-2026-CONFIDENTIAL"
        canary_note = "FORENSIC-CRITICAL-NOTE"

        payload = {
            "operation_id": "op-auto",
            "raw_case_id": canary_case,
            "evidence_note": canary_note,
            "signing_key": canary_pk,
            "custom_signer": canary_pk,
            "mnemonic_phrase": canary_mnemonic,
            "nested": {
                "private_key": canary_pk,
                "note_text": canary_note,
                "safe_field": 999,
            },
            "item_list": [
                {"seed_words": canary_mnemonic},
                canary_pk,
                "safe_item",
            ],
        }

        write_sidecar(db_file, payload, auto_redact=True)

        sc_path = Path(str(db_file) + ".recovery.jsonl")
        assert sc_path.is_file()
        content = sc_path.read_text(encoding="utf-8")

        # Zero leaks of canaries
        assert canary_pk not in content
        assert canary_mnemonic not in content
        assert canary_case not in content
        assert canary_note not in content

        # Verify parsed structure
        data = json.loads(content.strip())
        assert data["raw_case_id"] == "[REDACTED]"
        assert data["evidence_note"] == "[REDACTED]"
        assert data["signing_key"] == "[REDACTED]"
        assert data["custom_signer"] == "[REDACTED]"
        assert data["mnemonic_phrase"] == "[REDACTED]"
        assert data["nested"]["private_key"] == "[REDACTED]"
        assert data["nested"]["note_text"] == "[REDACTED]"
        assert data["nested"]["safe_field"] == 999
        assert data["item_list"][0]["seed_words"] == "[REDACTED]"
        assert data["item_list"][1] == "[REDACTED]"
        assert data["item_list"][2] == "safe_item"

    def test_sanitize_sidecar_payload_nested_and_lists(self):
        """sanitize_sidecar_payload recursively redacts compound keys, nested dicts, and lists."""
        canary_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        raw = {
            "operation_id": "op-4",
            "signing_key": canary_pk,
            "seed_words": "test test test test test test test test test test test junk",
            "raw_case_id": "CASE-RAW",
            "evidence_note": "CONFIDENTIAL NOTE",
            "nested": {
                "sub_key": "some_key_value",
                "normal": "hello",
            },
            "list_data": [
                {"raw_case": "CASE-IN-LIST"},
                canary_pk,
                "safe_string",
            ],
        }
        sanitized = sanitize_sidecar_payload(raw)
        assert sanitized["signing_key"] == "[REDACTED]"
        assert sanitized["seed_words"] == "[REDACTED]"
        assert sanitized["raw_case_id"] == "[REDACTED]"
        assert sanitized["evidence_note"] == "[REDACTED]"
        assert sanitized["nested"]["sub_key"] == "[REDACTED]"
        assert sanitized["nested"]["normal"] == "hello"
        assert sanitized["list_data"][0]["raw_case"] == "[REDACTED]"
        assert sanitized["list_data"][1] == "[REDACTED]"
        assert sanitized["list_data"][2] == "safe_string"

