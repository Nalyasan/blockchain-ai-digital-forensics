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
        from test_evidence_p2 import populate_sample_db

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

