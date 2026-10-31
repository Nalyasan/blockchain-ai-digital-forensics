"""Targeted RED/GREEN tests for BLOCKER 1 (False verified/confirmed) and BLOCKER 2 (SQLite migration atomicity)."""

import hashlib
import inspect
import json
import sqlite3
import urllib.error
from pathlib import Path
from typing import Any
import pytest

from forensics.onchain_store import (
    EVENT_TYPE_CUSTODY_RECORDED,
    EVENT_TYPE_EVIDENCE_REGISTERED,
    TOPIC_CUSTODY_RECORDED,
    TOPIC_EVIDENCE_REGISTERED,
    get_event_topic,
    make_event_id,
    persist_verified_event,
    reconcile_operation,
    verify_receipt_and_event,
    load_operation,
    READY,
    SEND_STARTED,
    CONFIRMED,
)
from forensics.schemas import (
    GROUP3_TABLES,
    group3_schema_present,
    migrate_group3,
)


def _make_full_valid_receipt(
    contract: str,
    tx_hash: str,
    block_number: int = 100,
    block_hash: str = "0x" + "bb" * 32,
    event_type: str = EVENT_TYPE_EVIDENCE_REGISTERED,
    log_index: int = 0,
    evidence_id: int = 1,
    case_digest: str = "0x" + "11" * 32,
    manifest_sha256: str = "0x" + "22" * 32,
    actor: str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    action: int = 0,
) -> dict[str, Any]:
    """Helper creating a 100% ABI-compliant receipt."""
    if event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
        topics = [
            TOPIC_EVIDENCE_REGISTERED,
            "0x" + hex(evidence_id)[2:].zfill(64),
            "0x" + case_digest.lower().removeprefix("0x").zfill(64),
            "0x" + manifest_sha256.lower().removeprefix("0x").zfill(64),
        ]
        data = "0x" + actor.lower().removeprefix("0x").zfill(64) + "00" * 32
    else:
        topics = [
            TOPIC_CUSTODY_RECORDED,
            "0x" + hex(evidence_id)[2:].zfill(64),
            "0x" + hex(action)[2:].zfill(64),
            "0x" + actor.lower().removeprefix("0x").zfill(64),
        ]
        data = "0x" + ("33" * 32) + ("44" * 32)

    return {
        "status": 1,
        "blockNumber": hex(block_number),
        "blockHash": block_hash,
        "transactionHash": tx_hash,
        "logs": [
            {
                "address": contract,
                "logIndex": log_index,
                "topics": topics,
                "data": data,
            }
        ],
    }


# ==============================================================================
# BLOCKER 1: Receipt validation & Reconcile hardening
# ==============================================================================

class TestBlocker1_ReceiptValidationHardening:
    """Tests enforcing ABI compliance, field presence, and context matching."""

    def test_verify_receipt_rejects_missing_transaction_hash(self):
        """Receipt without transactionHash must be strictly rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, "0xvalidhash")
        del rec["transactionHash"]

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*transactionHash"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_missing_block_hash(self):
        """Receipt without blockHash must be strictly rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, "0xvalidhash")
        del rec["blockHash"]

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*blockHash"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_evidence_registered_incomplete_topics(self):
        """EvidenceRegistered with fewer than 4 topics violates ABI and must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, "0xvalidhash")
        # Only topic0 provided
        rec["logs"][0]["topics"] = [TOPIC_EVIDENCE_REGISTERED]

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*ABI violation.*topics"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_custody_recorded_incomplete_topics(self):
        """CustodyRecorded with fewer than 4 topics violates ABI and must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, "0xvalidhash", event_type=EVENT_TYPE_CUSTODY_RECORDED)
        # Only topic0 and topic1 provided
        rec["logs"][0]["topics"] = [TOPIC_CUSTODY_RECORDED, "0x" + "01".zfill(64)]

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*ABI violation.*topics"):
            verify_receipt_and_event(rec, EVENT_TYPE_CUSTODY_RECORDED, contract)

    def test_verify_receipt_rejects_missing_log_index(self):
        """Log missing logIndex must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, "0xvalidhash")
        del rec["logs"][0]["logIndex"]

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*logIndex"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_emitter_mismatch(self):
        """Log from a different contract address must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt("0x9999999999999999999999999999999999999999", "0xvalidhash")

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*contract address mismatch"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_payload_context_mismatch(self):
        """Receipt payload topics differing from expected intent context must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(
            contract,
            "0xvalidhash",
            case_digest="0x" + "aa" * 32,
            manifest_sha256="0x" + "bb" * 32,
        )

        # Expected case_digest is different
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: case_digest mismatch"):
            verify_receipt_and_event(
                rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                expected_case_digest="0x" + "cc" * 32,
            )


class TestBlocker1_ReconcileRpcEnforcement:
    """Tests ensuring reconcile_operation requires an RPC endpoint and does not accept direct receipt dicts."""

    def test_reconcile_operation_rejects_mapping_receipt(self, tmp_path: Path):
        """Passing a raw receipt dictionary to reconcile_operation must be strictly rejected."""
        db_file = tmp_path / "test_reconcile.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)
        op_id = "op123"
        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp1', '{}', 'SEND_STARTED', 31337, '0xcontract', '0xsigner', '0xtx1', 'now', 'now')",
            (op_id,)
        )
        conn.commit()
        conn.close()

        dummy_receipt = {"status": 1, "blockNumber": 100}
        with pytest.raises(ValueError, match="RECONCILE_FAILED.*cannot be a.*receipt dictionary"):
            reconcile_operation(db_file, op_id, dummy_receipt)

    def test_reconcile_operation_rpc_error_handling(self, tmp_path: Path):
        """RPC connection error transitions to error and does NOT mark CONFIRMED."""
        db_file = tmp_path / "test_reconcile_err.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)
        op_id = "op_err"
        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp_err', '{}', 'SEND_STARTED', 31337, '0xcontract', '0xsigner', '0xtx_err', 'now', 'now')",
            (op_id,)
        )
        conn.commit()
        conn.close()

        # Connect to a non-existent port
        res = reconcile_operation(db_file, op_id, "http://127.0.0.1:59999")
        assert res["reconciled"] is False
        assert "RPC_ERROR" in res.get("error", "")

        # State in DB must still be SEND_STARTED
        op = load_operation(db_file, op_id)
        assert op["state"] == "SEND_STARTED"


# ==============================================================================
# BLOCKER 2: SQLite Migration Atomicity
# ==============================================================================

class TestBlocker2_MigrationAtomicity:
    """Tests ensuring migrate_group3 does not use executescript and is truly atomic."""

    def test_migrate_group3_does_not_use_executescript(self):
        """AST/bytecode check: migrate_group3 must NEVER call executescript."""
        source = inspect.getsource(migrate_group3)
        assert ".executescript(" not in source, "migrate_group3 must not call executescript because it issues an implicit commit!"

    def test_migrate_group3_atomic_rollback_on_unique_index_failure(self, tmp_path: Path):
        """When CREATE UNIQUE INDEX fails due to duplicate rows, rollback leaves 0 Group 3 tables/columns."""
        db_file = tmp_path / "atomic_mig_test.db"
        conn = sqlite3.connect(str(db_file))
        # Create legacy schema
        conn.execute(
            "CREATE TABLE custody_events(chain_id INT, contract_address TEXT, tx_hash TEXT, log_index INT, action TEXT)"
        )
        # Insert duplicate rows with identical (chain_id, contract_address, tx_hash, log_index)
        conn.execute("INSERT INTO custody_events VALUES(31337, '0xcontract', '0xhash1', 0, 'collect')")
        conn.execute("INSERT INTO custody_events VALUES(31337, '0xcontract', '0xhash1', 0, 'collect')")
        conn.commit()

        # migrate_group3 must attempt to create unique index and fail due to duplicates
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)):
            migrate_group3(conn)

        # Assert clean rollback: Group 3 tables MUST NOT exist!
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        assert "anchor_links" not in tables, "anchor_links must have been rolled back!"
        assert "onchain_operations" not in tables, "onchain_operations must have been rolled back!"
        assert "onchain_operation_events" not in tables, "onchain_operation_events must have been rolled back!"

        # Custody events must still have original rows intact
        rows = cur.execute("SELECT COUNT(*) FROM custody_events").fetchone()[0]
        assert rows == 2
        conn.close()

    def test_migrate_group3_wal_mode_and_rerun_idempotency(self, tmp_path: Path):
        """migrate_group3 works smoothly in WAL mode and re-running is completely idempotent."""
        db_file = tmp_path / "wal_idempotent_test.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE custody_events(chain_id INT, contract_address TEXT, tx_hash TEXT, action TEXT)")
        conn.execute("INSERT INTO custody_events VALUES(31337, '0xcontract', '0xhash1', 'collect')")
        conn.commit()

        # Run 1
        migrate_group3(conn)
        assert group3_schema_present(conn)

        # Run 2 (idempotency check)
        migrate_group3(conn)
        assert group3_schema_present(conn)

        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        conn.close()

