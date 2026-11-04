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
    tx_hash: str = "0x" + "aa" * 32,
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
    tx_clean = tx_hash.lower().removeprefix("0x")
    tx_normalized = "0x" + (tx_clean if len(tx_clean) == 64 and all(c in "0123456789abcdef" for c in tx_clean) else hashlib.sha256(tx_hash.encode()).hexdigest())

    bh_clean = block_hash.lower().removeprefix("0x")
    bh_normalized = "0x" + (bh_clean if len(bh_clean) == 64 and all(c in "0123456789abcdef" for c in bh_clean) else hashlib.sha256(block_hash.encode()).hexdigest())

    if event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
        topics = [
            TOPIC_EVIDENCE_REGISTERED,
            "0x" + hex(evidence_id)[2:].zfill(64),
            "0x" + case_digest.lower().removeprefix("0x").zfill(64),
            "0x" + manifest_sha256.lower().removeprefix("0x").zfill(64),
        ]
        uri = f"evidence://sha256/{case_digest.lower().removeprefix('0x')}/{manifest_sha256.lower().removeprefix('0x')}/manifest.json"
        raw_uri = uri.encode("utf-8")
        pad_len = (-len(raw_uri)) % 32
        data = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_uri))[2:].zfill(64)
            + raw_uri.hex()
            + "00" * pad_len
        )
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
        "blockHash": bh_normalized,
        "transactionHash": tx_normalized,
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


# ==============================================================================
# AUDIT FINDINGS: Targeted RED tests
# ==============================================================================

class TestFinding1_EventDataAndHashValidation:
    """Finding 1 — G3-03: Incomplete ABI event data accepted & bytes32 hex validation."""

    def test_verify_receipt_rejects_non_32byte_tx_hash(self):
        """Receipt transactionHash must be exactly 32 bytes (66 hex chars)."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract)
        rec["transactionHash"] = "0x1234"  # too short

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*transactionHash.*32-byte hex"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_non_hex_tx_hash(self):
        """Receipt transactionHash with invalid hex chars must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract)
        rec["transactionHash"] = "0x" + "g" * 64

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*transactionHash.*32-byte hex"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_non_32byte_block_hash(self):
        """Receipt blockHash must be exactly 32 bytes (66 hex chars)."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract)
        rec["blockHash"] = "0x1234"  # too short

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*blockHash.*32-byte hex"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_evidence_registered_empty_data(self):
        """EvidenceRegistered with data='0x' violates ABI and must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_EVIDENCE_REGISTERED)
        rec["logs"][0]["data"] = "0x"

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*EvidenceRegistered.*data payload ABI violation"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_evidence_registered_short_data(self):
        """EvidenceRegistered with data shorter than 96 bytes violates ABI."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_EVIDENCE_REGISTERED)
        rec["logs"][0]["data"] = "0x" + "11" * 32  # only 32 bytes

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*EvidenceRegistered.*data payload ABI violation"):
            verify_receipt_and_event(rec, EVENT_TYPE_EVIDENCE_REGISTERED, contract)

    def test_verify_receipt_rejects_custody_recorded_empty_data(self):
        """CustodyRecorded with data='0x' violates ABI and must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_CUSTODY_RECORDED)
        rec["logs"][0]["data"] = "0x"

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*CustodyRecorded.*data payload ABI violation"):
            verify_receipt_and_event(rec, EVENT_TYPE_CUSTODY_RECORDED, contract)

    def test_verify_receipt_rejects_custody_recorded_wrong_data_length(self):
        """CustodyRecorded with data not exactly 64 bytes (130 hex chars) must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_CUSTODY_RECORDED)
        rec["logs"][0]["data"] = "0x" + "33" * 32  # 32 bytes instead of 64 bytes

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*CustodyRecorded.*data payload ABI violation"):
            verify_receipt_and_event(rec, EVENT_TYPE_CUSTODY_RECORDED, contract)

    def test_persist_verified_event_refuses_verified_1_when_evidence_data_empty(self, tmp_path: Path):
        """persist_verified_event must NOT write verified=1 when EvidenceRegistered data='0x'."""
        db_file = tmp_path / "test_persist_empty_data.db"
        from forensics.schemas import init_db
        conn = init_db(str(db_file))
        conn.close()

        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_EVIDENCE_REGISTERED)
        rec["logs"][0]["data"] = "0x"

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED"):
            persist_verified_event(
                db_file,
                operation_id="op_empty_ev",
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                action=0,
                actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                artifact_sha256="22" * 32,
                note_hash="44" * 32,
                tx_hash=rec["transactionHash"],
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                manifest_sha256="22" * 32,
                case_digest="11" * 32,
                receipt=rec,
            )

        # Confirm zero verified rows written
        conn = sqlite3.connect(str(db_file))
        rows = conn.execute("SELECT COUNT(*) FROM anchor_links").fetchone()[0]
        assert rows == 0
        conn.close()

    def test_persist_verified_event_refuses_verified_1_when_custody_data_empty(self, tmp_path: Path):
        """persist_verified_event must NOT write verified=1 when CustodyRecorded data='0x'."""
        db_file = tmp_path / "test_persist_empty_custody.db"
        from forensics.schemas import init_db
        conn = init_db(str(db_file))
        conn.close()

        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        rec = _make_full_valid_receipt(contract, event_type=EVENT_TYPE_CUSTODY_RECORDED)
        rec["logs"][0]["data"] = "0x"

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED"):
            persist_verified_event(
                db_file,
                operation_id="op_empty_custody",
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                action=1,
                actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                artifact_sha256="33" * 32,
                note_hash="44" * 32,
                tx_hash=rec["transactionHash"],
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_CUSTODY_RECORDED,
                receipt=rec,
            )

        conn = sqlite3.connect(str(db_file))
        rows = conn.execute("SELECT COUNT(*) FROM custody_events WHERE verified=1").fetchone()[0]
        assert rows == 0
        conn.close()


class TestFinding2_ReconcileCanonicalBlock:
    """Finding 2 — G3-10: Missing canonical block accepted."""

    def test_reconcile_operation_rejects_null_block_lookup(self, tmp_path: Path):
        """reconcile_operation must remain UNKNOWN when block lookup returns None."""
        db_file = tmp_path / "test_reconcile_null_block.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)
        op_id = "op_null_block"
        tx_hash = "0x" + "aa" * 32
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp_null_b', '{}', 'SEND_STARTED', 31337, ?, '0xsigner', ?, 'now', 'now')",
            (op_id, contract, tx_hash),
        )
        conn.commit()
        conn.close()

        rec = _make_full_valid_receipt(contract, tx_hash=tx_hash)

        class NullBlockRpcClient:
            def eth_chainId(self):
                return 31337
            def eth_getTransactionReceipt(self, _tx):
                return rec
            def eth_getBlockByNumber(self, _bn, _full):
                return None

        res = reconcile_operation(db_file, op_id, NullBlockRpcClient())
        assert res["reconciled"] is False
        assert res.get("reason") == "CANONICAL_BLOCK_NOT_FOUND"

        op = load_operation(db_file, op_id)
        assert op["state"] == "SEND_STARTED"

    def test_reconcile_operation_rejects_rpc_client_missing_block_method(self, tmp_path: Path):
        """reconcile_operation must remain UNKNOWN when RPC client lacks block verification method."""
        db_file = tmp_path / "test_reconcile_no_block_method.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)
        op_id = "op_no_method"
        tx_hash = "0x" + "aa" * 32
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp_no_method', '{}', 'SEND_STARTED', 31337, ?, '0xsigner', ?, 'now', 'now')",
            (op_id, contract, tx_hash),
        )
        conn.commit()
        conn.close()

        rec = _make_full_valid_receipt(contract, tx_hash=tx_hash)

        class NoBlockMethodRpcClient:
            def eth_chainId(self):
                return 31337
            def eth_getTransactionReceipt(self, _tx):
                return rec

        res = reconcile_operation(db_file, op_id, NoBlockMethodRpcClient())
        assert res["reconciled"] is False
        assert res.get("reason") == "RPC_BLOCK_VERIFICATION_UNSUPPORTED"

        op = load_operation(db_file, op_id)
        assert op["state"] == "SEND_STARTED"

    def test_reconcile_operation_rejects_reorg_block_hash_mismatch(self, tmp_path: Path):
        """reconcile_operation must reject receipt when block hash does not match (reorg)."""
        db_file = tmp_path / "test_reconcile_reorg.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)
        op_id = "op_reorg"
        tx_hash = "0x" + "aa" * 32
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp_reorg', '{}', 'SEND_STARTED', 31337, ?, '0xsigner', ?, 'now', 'now')",
            (op_id, contract, tx_hash),
        )
        conn.commit()
        conn.close()

        rec = _make_full_valid_receipt(contract, tx_hash=tx_hash, block_hash="0x" + "bb" * 32)

        class ReorgRpcClient:
            def eth_chainId(self):
                return 31337
            def eth_getTransactionReceipt(self, _tx):
                return rec
            def eth_getBlockByNumber(self, _bn, _full):
                return {"hash": "0x" + "99" * 32}  # Mismatched hash

        res = reconcile_operation(db_file, op_id, ReorgRpcClient())
        assert res["reconciled"] is False
        assert res.get("reason") == "NON_CANONICAL_BLOCK_OR_REORG"

        op = load_operation(db_file, op_id)
        assert op["state"] == "SEND_STARTED"


class TestFinding3_PreSendNoAutoMigration:
    """Finding 3 — G3-04: Unauthorized automatic migration."""

    def test_pre_send_unmigrated_db_fails_closed_without_modifying_schema(self, tmp_path: Path):
        """pre_send_db_check on unmigrated DB must fail-closed and leave schema untouched."""
        from forensics.onchain_store import pre_send_db_check
        db_file = tmp_path / "unmigrated_presend.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE dummy_table(id INT)")
        conn.commit()
        conn.close()

        # Must raise GROUP3_SCHEMA_MISSING
        with pytest.raises(RuntimeError, match="GROUP3_SCHEMA_MISSING"):
            pre_send_db_check(db_file, migrate=False)

        # Assert schema was NOT modified
        conn = sqlite3.connect(str(db_file))
        assert not group3_schema_present(conn)
        conn.close()

    def test_record_custody_action_fails_closed_on_unmigrated_db(self, tmp_path: Path, monkeypatch):
        """record_custody_action on unmigrated DB must fail-closed with zero send and zero schema modification."""
        import forensics.onchain as oc
        db_file = tmp_path / "unmigrated_custody.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE dummy_table(id INT)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(oc, "prepare_write", lambda *a, **k: ("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", 31337))

        with pytest.raises(RuntimeError, match="GROUP3_SCHEMA_MISSING"):
            oc.record_custody_action(
                evidence_id=1,
                action=0,
                artifact_sha256="0x" + "11" * 32,
                note="test note",
                contract_address="0x5fbdb2315678afecb367f032d93f642f64180aa3",
                db_path=str(db_file),
            )

        conn = sqlite3.connect(str(db_file))
        assert not group3_schema_present(conn)
        conn.close()

    def test_anchor_evidence_fails_closed_on_unmigrated_db(self, tmp_path: Path, monkeypatch):
        """anchor_evidence on unmigrated DB must fail-closed before send and not mutate schema."""
        import forensics.onchain as oc
        from forensics.evidence import export_evidence
        from test_evidence_package import populate_sample_db

        # Create temporary valid package
        pkg_dir = tmp_path / "pkg"
        db_src = tmp_path / "src.db"
        populate_sample_db(str(db_src), 2)
        export_evidence("test-case", 0, 1, str(pkg_dir), str(db_src))

        # Target DB is unmigrated
        target_db = tmp_path / "target_unmigrated.db"
        conn = sqlite3.connect(str(target_db))
        conn.execute("CREATE TABLE dummy_table(id INT)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(oc, "is_working_tree_dirty", lambda: False)
        monkeypatch.setattr(oc, "get_rpc_chain_id", lambda url: 31337)
        monkeypatch.setattr(oc, "prepare_write", lambda *a, **k: ("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", 31337))

        with pytest.raises(RuntimeError, match="GROUP3_SCHEMA_MISSING"):
            oc.anchor_evidence(
                str(pkg_dir / "manifest.json"),
                contract_address="0x5fbdb2315678afecb367f032d93f642f64180aa3",
                db_path=str(target_db),
                reason="controlled-test",
                allow_dirty=True,
                allow_unfinalized=True,
            )

        conn = sqlite3.connect(str(target_db))
        assert not group3_schema_present(conn)
        conn.close()

    def test_cli_migrate_db_explicitly_migrates_database(self, tmp_path: Path):
        """cli_migrate_db explicitly upgrades an unmigrated DB to Group 3 schema."""
        from forensics.cli import build_parser
        from forensics.onchain_store import pre_send_db_check
        db_file = tmp_path / "explicit_migration.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE blocks(block_number INT, hash TEXT)")
        conn.commit()
        conn.close()

        parser = build_parser()
        args = parser.parse_args(["migrate-db", "--db", str(db_file)])
        exit_code = args.func(args)
        assert exit_code == 0

        conn = sqlite3.connect(str(db_file))
        assert group3_schema_present(conn)
        conn.close()

        # Subsequent pre-send check succeeds
        pre_send_db_check(db_file, migrate=False)


class TestFindingA_StorageUriStrictValidation:
    """Finding A — G3-03 / G3-10: Event storage URI strict validation, decoding, and profile enforcement."""

    def test_verify_receipt_rejects_single_byte_uri_mismatch(self):
        """Mutating a single byte in storageUri (e.g. 'e' -> 'X') must be strictly rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        cd = "11" * 32
        ms = "22" * 32
        rec = _make_full_valid_receipt(contract, case_digest="0x" + cd, manifest_sha256="0x" + ms)

        # Mutate the first byte of URI from 'e' to 'X'
        valid_uri = f"evidence://sha256/{cd}/{ms}/manifest.json"
        tampered_uri = "X" + valid_uri[1:]
        raw_tampered = tampered_uri.encode("utf-8")
        pad_len = (-len(raw_tampered)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        tampered_data = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_tampered))[2:].zfill(64)
            + raw_tampered.hex()
            + "00" * pad_len
        )
        rec["logs"][0]["data"] = tampered_data

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*storageUri"):
            verify_receipt_and_event(
                rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                expected_case_digest="0x" + cd,
                expected_manifest_sha256="0x" + ms,
            )

    def test_verify_receipt_rejects_uri_manifest_mismatch(self):
        """Storage URI pointing to a different manifest hash than indexed topic3 must fail."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        cd = "11" * 32
        ms = "22" * 32
        wrong_ms = "33" * 32
        rec = _make_full_valid_receipt(contract, case_digest="0x" + cd, manifest_sha256="0x" + ms)

        wrong_uri = f"evidence://sha256/{cd}/{wrong_ms}/manifest.json"
        raw_wrong = wrong_uri.encode("utf-8")
        pad_len = (-len(raw_wrong)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        rec["logs"][0]["data"] = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_wrong))[2:].zfill(64)
            + raw_wrong.hex()
            + "00" * pad_len
        )

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*(storageUri|manifestSha256)"):
            verify_receipt_and_event(
                rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                expected_case_digest="0x" + cd,
                expected_manifest_sha256="0x" + ms,
            )

    def test_verify_receipt_rejects_uri_case_digest_mismatch(self):
        """Storage URI pointing to a different case digest than indexed topic2 must fail."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        cd = "11" * 32
        ms = "22" * 32
        wrong_cd = "44" * 32
        rec = _make_full_valid_receipt(contract, case_digest="0x" + cd, manifest_sha256="0x" + ms)

        wrong_uri = f"evidence://sha256/{wrong_cd}/{ms}/manifest.json"
        raw_wrong = wrong_uri.encode("utf-8")
        pad_len = (-len(raw_wrong)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        rec["logs"][0]["data"] = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_wrong))[2:].zfill(64)
            + raw_wrong.hex()
            + "00" * pad_len
        )

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*(storageUri|case_digest)"):
            verify_receipt_and_event(
                rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                expected_case_digest="0x" + cd,
                expected_manifest_sha256="0x" + ms,
            )

    def test_verify_receipt_rejects_nonzero_padding_in_uri(self):
        """Non-zero byte in storageUri ABI padding area must be strictly rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        cd = "11" * 32
        ms = "22" * 32
        rec = _make_full_valid_receipt(contract, case_digest="0x" + cd, manifest_sha256="0x" + ms)

        uri = f"evidence://sha256/{cd}/{ms}/manifest.json"
        raw_uri = uri.encode("utf-8")
        pad_len = (-len(raw_uri)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        # Corrupt the padding by placing 'ff' in it
        corrupted_pad = "00" * (pad_len - 1) + "ff"
        rec["logs"][0]["data"] = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_uri))[2:].zfill(64)
            + raw_uri.hex()
            + corrupted_pad
        )

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: non-zero padding in storageUri ABI data"):
            verify_receipt_and_event(
                rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                expected_case_digest="0x" + cd,
                expected_manifest_sha256="0x" + ms,
            )

    def test_verify_receipt_rejects_mixed_legacy_canonical_profiles(self):
        """Mixed profile checks: legacy URI in canonical mode or canonical URI in legacy mode must be rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        case_raw = "CASE-LEGACY-01"
        from forensics.evidence_identity import string_to_bytes32_hex
        legacy_case_b32 = string_to_bytes32_hex(case_raw)
        ms = "22" * 32

        # 1. Canonical mode (legacy_case_encoding=False) receiving a legacy URI
        legacy_uri = f"evidence://{case_raw}/manifest.json"
        raw_leg = legacy_uri.encode("utf-8")
        pad_leg = (-len(raw_leg)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        rec_legacy_payload = {
            "status": 1,
            "blockNumber": 100,
            "blockHash": "0x" + "bb" * 32,
            "transactionHash": "0x" + "aa" * 32,
            "logs": [
                {
                    "address": contract,
                    "logIndex": 0,
                    "topics": [
                        TOPIC_EVIDENCE_REGISTERED,
                        "0x" + "01".zfill(64),
                        legacy_case_b32,
                        "0x" + ms,
                    ],
                    "data": (
                        "0x"
                        + actor.lower().removeprefix("0x")[-40:].zfill(64)
                        + hex(64)[2:].zfill(64)
                        + hex(len(raw_leg))[2:].zfill(64)
                        + raw_leg.hex()
                        + "00" * pad_leg
                    ),
                }
            ],
        }

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: legacy storageUri in canonical mode"):
            verify_receipt_and_event(
                rec_legacy_payload,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                legacy_case_encoding=False,
            )

        # 2. Legacy mode (legacy_case_encoding=True) receiving a canonical URI
        canonical_rec = _make_full_valid_receipt(contract, case_digest="0x" + "11" * 32, manifest_sha256="0x" + ms)
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: canonical storageUri in legacy mode"):
            verify_receipt_and_event(
                canonical_rec,
                EVENT_TYPE_EVIDENCE_REGISTERED,
                contract,
                legacy_case_encoding=True,
                expected_case_id=case_raw,
            )

    def test_reconcile_operation_preserves_unknown_on_uri_mismatch(self, tmp_path: Path):
        """When on-chain event contains mismatched storageUri, reconcile returns false and keeps operation UNKNOWN."""
        db_file = tmp_path / "reconcile_uri_mismatch.db"
        conn = sqlite3.connect(str(db_file))
        migrate_group3(conn)

        op_id = "op_uri_test"
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0x" + "ee" * 32
        cd = "11" * 32
        ms = "22" * 32

        from forensics.evidence_identity import canonical_storage_uri
        expected_uri = canonical_storage_uri(cd, ms)

        intent = {
            "op_type": "REGISTER_EVIDENCE",
            "chain_id": 31337,
            "contract": contract,
            "manifest_sha256": ms,
            "case_digest": cd,
            "storage_uri": expected_uri,
            "signer": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        }

        conn.execute(
            "INSERT INTO onchain_operations(operation_id, op_type, fingerprint, intent_canonical, state, chain_id, contract_address, signer, tx_hash, created_at, updated_at) "
            "VALUES(?, 'REGISTER_EVIDENCE', 'fp_uri_test', ?, 'UNKNOWN', 31337, ?, '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266', ?, 'now', 'now')",
            (op_id, json.dumps(intent), contract, tx_hash),
        )
        conn.commit()
        conn.close()

        # Receipt with single byte altered in URI ("e" -> "X")
        rec = _make_full_valid_receipt(contract, tx_hash=tx_hash, case_digest="0x" + cd, manifest_sha256="0x" + ms)
        tampered_uri = "X" + expected_uri[1:]
        raw_tampered = tampered_uri.encode("utf-8")
        pad_len = (-len(raw_tampered)) % 32
        actor = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        rec["logs"][0]["data"] = (
            "0x"
            + actor.lower().removeprefix("0x")[-40:].zfill(64)
            + hex(64)[2:].zfill(64)
            + hex(len(raw_tampered))[2:].zfill(64)
            + raw_tampered.hex()
            + "00" * pad_len
        )

        class MockRpcClient:
            def eth_chainId(self):
                return 31337
            def eth_getTransactionReceipt(self, _tx):
                return rec
            def eth_getBlockByNumber(self, _bn, _full):
                return {"hash": rec["blockHash"]}

        res = reconcile_operation(db_file, op_id, MockRpcClient())
        assert res["reconciled"] is False
        assert "storageUri" in res.get("error", "")

        # Crucial: operation state in DB must REMAIN UNKNOWN, never CONFIRMED!
        op = load_operation(db_file, op_id)
        assert op["state"] == "UNKNOWN"

        # Crucial: anchor_links must contain ZERO rows
        conn = sqlite3.connect(str(db_file))
        assert conn.execute("SELECT COUNT(*) FROM anchor_links").fetchone()[0] == 0
        conn.close()


class TestFindingB_ExporterPreservesLegacySchema:
    """Finding B — G3-04: Standard evidence export must never implicitly migrate legacy database."""

    def test_export_evidence_on_legacy_db_preserves_schema_untouched(self, tmp_path: Path):
        """Exporting evidence on a pre-existing legacy SQLite DB must succeed without creating Group 3 tables."""
        from forensics.evidence import export_evidence
        from test_evidence_package import populate_sample_db
        from forensics.schemas import rollback_group3

        legacy_db = tmp_path / "existing_legacy.db"
        populate_sample_db(str(legacy_db), 3)

        # Roll back Group 3 additions to produce an authentic Phase 2 legacy database with historical data
        conn = sqlite3.connect(str(legacy_db))
        rollback_group3(conn)
        conn.commit()

        # Verify initial legacy state: Group 3 schema is NOT present
        assert not group3_schema_present(conn)
        tables_before = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for t in GROUP3_TABLES:
            assert t not in tables_before
        custody_cols_before = {row[1] for row in conn.execute("PRAGMA table_info(custody_events)").fetchall()}
        assert "log_index" not in custody_cols_before
        assert "event_type" not in custody_cols_before
        conn.close()

        # Perform standard evidence export
        pkg_dir = tmp_path / "exported_legacy_pkg"
        manifest = export_evidence("CASE-LEGACY-01", 0, 2, out_dir=str(pkg_dir), db_path=str(legacy_db), allow_gaps=True)
        assert manifest["case_id"] == "CASE-LEGACY-01"

        # Verify post-export state on legacy DB: MUST REMAIN UNMIGRATED
        conn = sqlite3.connect(str(legacy_db))
        assert not group3_schema_present(conn)
        tables_after = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for t in GROUP3_TABLES:
            assert t not in tables_after, f"Group 3 table {t} was improperly created during export!"

        custody_cols_after = {row[1] for row in conn.execute("PRAGMA table_info(custody_events)").fetchall()}
        assert "log_index" not in custody_cols_after
        assert "event_type" not in custody_cols_after

        index_names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
        assert "idx_custody_event_identity" not in index_names

        # Verify export was properly recorded in evidence_exports table with canonical storage URI
        export_row = conn.execute("SELECT case_id, storage_uri, manifest_sha256 FROM evidence_exports").fetchone()
        assert export_row is not None
        assert export_row[0] == "CASE-LEGACY-01"
        assert export_row[1].startswith("evidence://sha256/")
        conn.close()

    def test_init_db_on_existing_db_preserves_legacy_schema(self, tmp_path: Path):
        """init_db called on an existing legacy DB does not auto-migrate Group 3 unless explicitly requested."""
        from forensics.schemas import init_db, SCHEMA
        db_file = tmp_path / "legacy_existing_manual.db"
        conn = sqlite3.connect(str(db_file))
        conn.executescript(SCHEMA)
        conn.commit()
        assert not group3_schema_present(conn)
        conn.close()

        # Opening existing DB with init_db() default preserves legacy schema
        conn = init_db(str(db_file))
        assert not group3_schema_present(conn)
        conn.close()

        # Opening with explicit migrate_group3_schema=True migrates
        conn = init_db(str(db_file), migrate_group3_schema=True)
        assert group3_schema_present(conn)
        conn.close()


class TestFindingC_CanonicalCustodyNoteHash:
    """Finding C — G3-03 / G3-05 / G3-07 / G3-10: Canonical Custody NoteHash Verification.

    Guarantees:
    1. Canonical profile requires 100% exact bytes32 equality between on-chain noteHash and expected SHA-256.
    2. Zero implicit plaintext/zero-padding fallback permitted in canonical mode.
    3. Legacy profile (legacy_case_encoding=True) accepts valid UTF-8 zero-padded plaintext <= 32 bytes
       matching expected SHA-256, but rejects if SHA-256 does not match.
    4. persist_verified_event and reconcile_operation strictly fail-closed on plaintext-padded note in canonical mode.
    5. verify_custody_receipt enforces exact equality when legacy_case_encoding=False.
    """

    CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    SIGNER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    PLAINTEXT_NOTE = "private-demo"

    def _make_custody_receipt(
        self,
        note_hash_hex: str,
        artifact_sha256_hex: str = "33" * 32,
        action: int = 1,
        evidence_id: int = 1,
        tx_hash: str = "0x" + "aa" * 32,
        block_hash: str = "0x" + "bb" * 32,
        block_number: int = 100,
        log_index: int = 0,
    ) -> dict[str, Any]:
        """Create an ABI-compliant CustodyRecorded receipt with specified note_hash in data."""
        art_clean = artifact_sha256_hex.lower().removeprefix("0x")
        nh_clean = note_hash_hex.lower().removeprefix("0x")
        tx_norm = tx_hash if tx_hash.startswith("0x") else "0x" + tx_hash
        bh_norm = block_hash if block_hash.startswith("0x") else "0x" + block_hash
        return {
            "status": 1,
            "blockNumber": hex(block_number),
            "blockHash": bh_norm,
            "transactionHash": tx_norm,
            "transactionIndex": 0,
            "logs": [
                {
                    "address": self.CONTRACT,
                    "logIndex": log_index,
                    "transactionIndex": 0,
                    "transactionHash": tx_norm,
                    "blockNumber": hex(block_number),
                    "blockHash": bh_norm,
                    "topics": [
                        TOPIC_CUSTODY_RECORDED,
                        "0x" + hex(evidence_id)[2:].zfill(64),
                        "0x" + hex(action)[2:].zfill(64),
                        "0x" + self.SIGNER.lower().removeprefix("0x")[-40:].zfill(64),
                    ],
                    "data": "0x" + art_clean.zfill(64) + nh_clean.zfill(64),
                }
            ],
        }

    def test_canonical_verification_rejects_plaintext_padded_note_hash(self):
        """Canonical verification (legacy_case_encoding=False) MUST reject zero-padded plaintext noteHash."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8

        # Note on-chain is zero-padded plaintext UTF-8 "private-demo"
        padded_nh = string_to_bytes32_hex(self.PLAINTEXT_NOTE)
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)

        receipt = self._make_custody_receipt(note_hash_hex=padded_nh)

        # In canonical mode, must fail-closed with RuntimeError
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: noteHash mismatch in CustodyRecorded log"):
            verify_receipt_and_event(
                receipt,
                expected_event_type=EVENT_TYPE_CUSTODY_RECORDED,
                expected_contract=self.CONTRACT,
                expected_actor=self.SIGNER,
                expected_evidence_id=1,
                expected_action=1,
                expected_artifact_sha256="33" * 32,
                expected_note_hash=expected_nh,
                legacy_case_encoding=False,
            )

    def test_canonical_verification_accepts_correct_sha256_note_hash(self):
        """Canonical verification MUST accept exact bytes32 SHA-256 noteHash."""
        from forensics.evidence_identity import sha256_utf8

        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        receipt = self._make_custody_receipt(note_hash_hex=expected_nh)

        matched = verify_receipt_and_event(
            receipt,
            expected_event_type=EVENT_TYPE_CUSTODY_RECORDED,
            expected_contract=self.CONTRACT,
            expected_actor=self.SIGNER,
            expected_evidence_id=1,
            expected_action=1,
            expected_artifact_sha256="33" * 32,
            expected_note_hash=expected_nh,
            legacy_case_encoding=False,
        )
        assert matched is not None
        assert matched["topics"][0].lower() == TOPIC_CUSTODY_RECORDED.lower()

    def test_canonical_verification_rejects_wrong_sha256_note_hash(self):
        """Canonical verification MUST reject wrong SHA-256 noteHash."""
        from forensics.evidence_identity import sha256_utf8

        wrong_nh = sha256_utf8("completely-different-note")
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        receipt = self._make_custody_receipt(note_hash_hex=wrong_nh)

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: noteHash mismatch in CustodyRecorded log"):
            verify_receipt_and_event(
                receipt,
                expected_event_type=EVENT_TYPE_CUSTODY_RECORDED,
                expected_contract=self.CONTRACT,
                expected_actor=self.SIGNER,
                expected_evidence_id=1,
                expected_action=1,
                expected_artifact_sha256="33" * 32,
                expected_note_hash=expected_nh,
                legacy_case_encoding=False,
            )

    def test_persist_verified_event_refuses_verified_1_for_plaintext_padded_note_in_canonical_mode(self, tmp_path: Path):
        """persist_verified_event must refuse to write verified=1 when noteHash is plaintext-padded in canonical mode."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8
        from forensics.schemas import init_db

        db_file = tmp_path / "test_persist_custody.db"
        init_db(str(db_file), migrate_group3_schema=True)

        padded_nh = string_to_bytes32_hex(self.PLAINTEXT_NOTE)
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        tx_hash = "0x" + "aa" * 32
        receipt = self._make_custody_receipt(note_hash_hex=padded_nh, tx_hash=tx_hash)

        # Attempt to persist with canonical profile (legacy_case_encoding=False)
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: noteHash mismatch in CustodyRecorded log"):
            persist_verified_event(
                db_file,
                operation_id="op-test-custody-1",
                chain_id=31337,
                contract=self.CONTRACT,
                evidence_id=1,
                action=1,
                actor=self.SIGNER,
                artifact_sha256="33" * 32,
                note_hash=expected_nh,
                tx_hash=tx_hash,
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_CUSTODY_RECORDED,
                receipt=receipt,
                legacy_case_encoding=False,
            )

        # Assert database contains ZERO verified custody records
        conn = sqlite3.connect(str(db_file))
        assert conn.execute("SELECT COUNT(*) FROM custody_events WHERE verified = 1").fetchone()[0] == 0
        conn.close()

    def test_reconcile_custody_preserves_unknown_for_plaintext_padded_note_in_canonical_mode(self, tmp_path: Path, monkeypatch):
        """reconcile_operation for custody in canonical mode preserves UNKNOWN when on-chain noteHash is plaintext-padded."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8
        from forensics.schemas import init_db
        from forensics.onchain_store import custody_intent, claim_send, mark_unknown

        db_file = tmp_path / "test_reconcile_custody.db"
        init_db(str(db_file), migrate_group3_schema=True)

        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        tx_hash = "0x" + "aa" * 32
        block_hash = "0x" + "bb" * 32
        padded_nh = string_to_bytes32_hex(self.PLAINTEXT_NOTE)

        intent = custody_intent(
            chain_id=31337,
            contract=self.CONTRACT,
            evidence_id=1,
            action=1,
            artifact_sha256="33" * 32,
            note_hash=expected_nh,
            signer=self.SIGNER,
        )
        claim = claim_send(db_file, intent)
        op_id = claim.operation_id
        mark_unknown(db_file, op_id, "CRASH_BEFORE_CONFIRM")

        receipt = self._make_custody_receipt(note_hash_hex=padded_nh, tx_hash=tx_hash, block_hash=block_hash)

        class MockRpcClient:
            def eth_chainId(self):
                return 31337
            def eth_getTransactionReceipt(self, _tx):
                return receipt
            def eth_getBlockByNumber(self, _bn, _full):
                return {"hash": receipt["blockHash"]}

        # Reconcile operation
        res = reconcile_operation(
            db_file,
            op_id,
            MockRpcClient(),
            tx_hash=tx_hash,
        )

        # Must fail reconciliation
        assert res["reconciled"] is False
        assert res["state"] == "UNKNOWN"
        assert "noteHash mismatch" in res.get("error", "")

        # Crucial: operation in DB must REMAIN UNKNOWN
        op = load_operation(db_file, op_id)
        assert op["state"] == "UNKNOWN"

        # Crucial: custody_events must have ZERO verified records
        conn = sqlite3.connect(str(db_file))
        assert conn.execute("SELECT COUNT(*) FROM custody_events WHERE verified = 1").fetchone()[0] == 0
        conn.close()

    def test_explicit_legacy_profile_accepts_plaintext_padded_note_when_sha256_matches(self):
        """Explicit legacy profile (legacy_case_encoding=True) accepts zero-padded plaintext when SHA-256 matches."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8

        padded_nh = string_to_bytes32_hex(self.PLAINTEXT_NOTE)
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        receipt = self._make_custody_receipt(note_hash_hex=padded_nh)

        matched = verify_receipt_and_event(
            receipt,
            expected_event_type=EVENT_TYPE_CUSTODY_RECORDED,
            expected_contract=self.CONTRACT,
            expected_actor=self.SIGNER,
            expected_evidence_id=1,
            expected_action=1,
            expected_artifact_sha256="33" * 32,
            expected_note_hash=expected_nh,
            legacy_case_encoding=True,
        )
        assert matched is not None
        assert matched["topics"][0].lower() == TOPIC_CUSTODY_RECORDED.lower()

    def test_explicit_legacy_profile_rejects_plaintext_padded_note_when_sha256_mismatches(self):
        """Explicit legacy profile (legacy_case_encoding=True) rejects zero-padded plaintext when SHA-256 mismatches."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8

        padded_nh = string_to_bytes32_hex("other-note")
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        receipt = self._make_custody_receipt(note_hash_hex=padded_nh)

        with pytest.raises(RuntimeError, match=r"VERIFICATION_FAILED: noteHash mismatch in CustodyRecorded log \(legacy mode\)"):
            verify_receipt_and_event(
                receipt,
                expected_event_type=EVENT_TYPE_CUSTODY_RECORDED,
                expected_contract=self.CONTRACT,
                expected_actor=self.SIGNER,
                expected_evidence_id=1,
                expected_action=1,
                expected_artifact_sha256="33" * 32,
                expected_note_hash=expected_nh,
                legacy_case_encoding=True,
            )

    def test_verify_custody_receipt_enforces_exact_equality_in_canonical_mode(self):
        """verify_custody_receipt enforces exact bytes32 equality in canonical mode even if raw_note is supplied."""
        from forensics.evidence_identity import string_to_bytes32_hex, sha256_utf8
        from forensics.onchain import verify_custody_receipt

        padded_nh = string_to_bytes32_hex(self.PLAINTEXT_NOTE)
        expected_nh = sha256_utf8(self.PLAINTEXT_NOTE)
        receipt = self._make_custody_receipt(note_hash_hex=padded_nh)

        # In canonical mode (legacy_case_encoding=False), raw_note fallback is disabled: must raise CUSTODY_DATA_MISMATCH
        with pytest.raises(ValueError, match="CUSTODY_DATA_MISMATCH"):
            verify_custody_receipt(
                receipt,
                contract=self.CONTRACT,
                signer=self.SIGNER,
                evidence_id=1,
                action=1,
                artifact="0x" + "33" * 32,
                note="0x" + expected_nh,
                raw_note=self.PLAINTEXT_NOTE,
                legacy_case_encoding=False,
            )

        # In legacy mode (legacy_case_encoding=True), raw_note fallback is permitted
        verify_custody_receipt(
            receipt,
            contract=self.CONTRACT,
            signer=self.SIGNER,
            evidence_id=1,
            action=1,
            artifact="0x" + "33" * 32,
            note="0x" + expected_nh,
            raw_note=self.PLAINTEXT_NOTE,
            legacy_case_encoding=True,
        )

        # In canonical mode with exact SHA-256 on-chain: succeeds
        exact_receipt = self._make_custody_receipt(note_hash_hex=expected_nh)
        verify_custody_receipt(
            exact_receipt,
            contract=self.CONTRACT,
            signer=self.SIGNER,
            evidence_id=1,
            action=1,
            artifact="0x" + "33" * 32,
            note="0x" + expected_nh,
            legacy_case_encoding=False,
        )


