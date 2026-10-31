"""Unit Test Suite for Milestone 2 (Requirement R3: H5 SQLite & Custody).

Validates Acceptance Gates:
- G3-01: Multi-Manifest Same Case Linkage (anchor_links primary key by manifest_sha256)
- G3-02: Custody Event Identity & Collision Prevention (chain_id, contract_address, tx_hash, log_index)
- G3-03: Zero INSERT OR REPLACE & Custody History Preservation
- G3-04: Strict Verification Before verified=1 (receipt status=1, blockNumber present, topic match)
- G3-11: Additive SQLite Migration Integrity & Pre-Send Fail-Fast DB Check (DB_REQUIRED, DB_READONLY)
- G3-14: Distinguish EvidenceRegistered vs CustodyRecorded & Package Retention on DB Failure
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest

from forensics.schemas import (
    GROUP3_TABLES,
    group3_schema_present,
    init_db,
    migrate_db,
    migrate_group3,
    rollback_group3,
)
from forensics.onchain_store import (
    CUSTODY,
    EVENT_TYPE_CUSTODY_RECORDED,
    EVENT_TYPE_EVIDENCE_REGISTERED,
    REGISTER,
    TOPIC_CUSTODY_RECORDED,
    TOPIC_EVIDENCE_REGISTERED,
    build_custody_intent,
    build_register_intent,
    canonical_json,
    classify_event_topic,
    fingerprint,
    get_event_topic,
    make_event_id,
    open_existing_rw,
    persist_verified_event,
    pre_send_db_check,
    verify_receipt_and_event,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a fully migrated SQLite test database."""
    db_file = tmp_path / "forensics_test.db"
    conn = init_db(str(db_file))
    conn.close()
    return db_file


@pytest.fixture
def legacy_db(tmp_path: Path) -> Path:
    """Create a legacy SQLite database without Group 3 tables or columns."""
    db_file = tmp_path / "legacy_test.db"
    conn = sqlite3.connect(str(db_file))
    conn.executescript(
        """
        CREATE TABLE blocks(
            chain_id INT, number INT, hash TEXT, parent_hash TEXT, block_timestamp INT,
            block_time_utc TEXT, first_observed_at TEXT, collected_at TEXT, status TEXT DEFAULT 'canonical',
            raw_json TEXT, raw_sha256 TEXT, synthetic INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(chain_id, hash)
        );

        CREATE TABLE transactions(
            chain_id INT, tx_hash TEXT, block_hash TEXT, block_number INT, tx_index INT,
            from_addr TEXT, to_addr TEXT, value_raw TEXT, nonce INT, input TEXT, raw_json TEXT, raw_sha256 TEXT,
            PRIMARY KEY(chain_id, tx_hash, block_hash)
        );

        CREATE TABLE evidence_exports(
            export_id TEXT PRIMARY KEY, case_id TEXT, manifest_path TEXT, manifest_sha256 TEXT,
            storage_uri TEXT, created_at TEXT, operator TEXT, onchain_evidence_id INT
        );

        CREATE TABLE custody_events(
            event_id TEXT PRIMARY KEY, evidence_id INT, case_id TEXT, action INT,
            actor_address TEXT, artifact_sha256 TEXT, note_hash TEXT, chain_id INT,
            contract_address TEXT, tx_hash TEXT, block_number INT, recorded_at TEXT,
            verified INT DEFAULT 0
        );
        """
    )
    # Insert historical custody events
    conn.execute(
        "INSERT INTO custody_events VALUES("
        "'hist-ev-1', 1, 'CASE-HISTORICAL-01', 0, '0x1111111111111111111111111111111111111111', "
        "'0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111', "
        "'0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222', "
        "31337, '0x9999999999999999999999999999999999999999', "
        "'0xcccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333', "
        "100, '2026-01-01T00:00:00Z', 1)"
    )
    conn.commit()
    conn.close()
    return db_file


# ==============================================================================
# Gate G3-01: Multi-Manifest Same Case Linkage
# ==============================================================================
class TestGate3_01_MultiManifestLinkage:
    """Gate G3-01: Multiple distinct manifests for the same case ID are preserved

    and linked in anchor_links by manifest_sha256 without collision or overwriting.
    """

    def test_multi_manifest_same_case_both_linked_in_anchor_links(self, test_db: Path):
        """Two distinct manifests for the same case ID are both linked and verified."""
        chain_id = 31337
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        case_digest = hashlib.sha256(b"CASE-2026-MULTI-01").hexdigest()

        manifest_1_sha = hashlib.sha256(b"manifest_payload_data_package_1").hexdigest()
        manifest_2_sha = hashlib.sha256(b"manifest_payload_data_package_2").hexdigest()

        assert manifest_1_sha != manifest_2_sha

        # Persist manifest 1
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            action=0,
            actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            artifact_sha256=manifest_1_sha,
            manifest_sha256=manifest_1_sha,
            case_digest=case_digest,
            tx_hash="0x1111111111111111111111111111111111111111111111111111111111111111",
            block_number=101,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )

        # Persist manifest 2 for the same case
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=2,
            action=0,
            actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            artifact_sha256=manifest_2_sha,
            manifest_sha256=manifest_2_sha,
            case_digest=case_digest,
            tx_hash="0x2222222222222222222222222222222222222222222222222222222222222222",
            block_number=102,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            # Query all anchor links for this contract
            rows = conn.execute(
                "SELECT manifest_sha256, evidence_id, tx_hash, verified FROM anchor_links "
                "WHERE chain_id=? AND contract_address=? ORDER BY evidence_id",
                (chain_id, contract),
            ).fetchall()

            # Both manifests must be preserved independently
            assert len(rows) == 2

            # Manifest 1 check
            assert rows[0][0] == manifest_1_sha
            assert rows[0][1] == 1
            assert rows[0][2] == "0x1111111111111111111111111111111111111111111111111111111111111111"
            assert rows[0][3] == 1

            # Manifest 2 check
            assert rows[1][0] == manifest_2_sha
            assert rows[1][1] == 2
            assert rows[1][2] == "0x2222222222222222222222222222222222222222222222222222222222222222"
            assert rows[1][3] == 1
        finally:
            conn.close()

    def test_multi_manifest_query_specific_manifest(self, test_db: Path):
        """Querying anchor_links by (chain_id, contract_address, manifest_sha256) returns exact link."""
        chain_id = 31337
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        m1_sha = hashlib.sha256(b"manifest_alpha").hexdigest()
        m2_sha = hashlib.sha256(b"manifest_beta").hexdigest()

        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=10,
            manifest_sha256=m1_sha,
            tx_hash="0xaaaa",
            block_number=1,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=20,
            manifest_sha256=m2_sha,
            tx_hash="0xbbbb",
            block_number=2,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            cur1 = conn.execute(
                "SELECT evidence_id, tx_hash FROM anchor_links WHERE chain_id=? AND contract_address=? AND manifest_sha256=?",
                (chain_id, contract, m1_sha),
            ).fetchone()
            assert cur1 == (10, "0xaaaa")

            cur2 = conn.execute(
                "SELECT evidence_id, tx_hash FROM anchor_links WHERE chain_id=? AND contract_address=? AND manifest_sha256=?",
                (chain_id, contract, m2_sha),
            ).fetchone()
            assert cur2 == (20, "0xbbbb")
        finally:
            conn.close()

    def test_multi_chain_multi_contract_linkage(self, test_db: Path):
        """Same manifest anchored across different chains or contracts does not collide."""
        manifest_sha = hashlib.sha256(b"cross_chain_manifest").hexdigest()

        persist_verified_event(
            test_db,
            chain_id=31337,
            contract="0x1111111111111111111111111111111111111111",
            evidence_id=1,
            manifest_sha256=manifest_sha,
            tx_hash="0xtx1",
            block_number=1,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )
        persist_verified_event(
            test_db,
            chain_id=11155111,
            contract="0x1111111111111111111111111111111111111111",
            evidence_id=100,
            manifest_sha256=manifest_sha,
            tx_hash="0xtx2",
            block_number=5000,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM anchor_links WHERE manifest_sha256=?", (manifest_sha,)
            ).fetchone()[0]
            assert count == 2
        finally:
            conn.close()


# ==============================================================================
# Gate G3-02: Event Identity & Collision Prevention
# ==============================================================================
class TestGate3_02_EventIdentityAndCollision:
    """Gate G3-02: Unique index on (chain_id, contract_address, tx_hash, log_index)

    prevents event collisions while supporting multiple sub-second events.
    """

    def test_subsecond_multiple_custody_events_same_tx(self, test_db: Path):
        """Two custody events in the same transaction with different log_index both persist cleanly."""
        chain_id = 31337
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xdeadbeef1111222233334444555566667777888899990000aaaabbbbccccdddd"

        # Action 0 (COLLECTED) at log_index 0
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            action=0,
            actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            artifact_sha256="0x1111",
            note_hash="0x2222",
            tx_hash=tx_hash,
            block_number=100,
            log_index=0,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt_status=1,
        )

        # Action 1 (ANALYZED) in same tx at log_index 1
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            action=1,
            actor="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            artifact_sha256="0x3333",
            note_hash="0x4444",
            tx_hash=tx_hash,
            block_number=100,
            log_index=1,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt_status=1,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            rows = conn.execute(
                "SELECT log_index, action, artifact_sha256 FROM custody_events "
                "WHERE tx_hash=? ORDER BY log_index",
                (tx_hash,),
            ).fetchall()
            assert len(rows) == 2
            assert rows[0] == (0, 0, "0x1111")
            assert rows[1] == (1, 1, "0x3333")
        finally:
            conn.close()

    def test_duplicate_event_tuple_rejected_by_unique_index(self, test_db: Path):
        """Duplicate (chain_id, contract_address, tx_hash, log_index) is rejected by unique index."""
        chain_id = 31337
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xfeedbeef"
        log_index = 0

        # Initial event insert
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=5,
            action=0,
            actor="0xactor1",
            artifact_sha256="0xart1",
            note_hash="0xnote1",
            tx_hash=tx_hash,
            block_number=50,
            log_index=log_index,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt_status=1,
        )

        # Attempt to insert identical event tuple with different payload
        with pytest.raises(sqlite3.IntegrityError):
            persist_verified_event(
                test_db,
                chain_id=chain_id,
                contract=contract,
                evidence_id=5,
                action=1,
                actor="0xactor2",
                artifact_sha256="0xart2",
                note_hash="0xnote2",
                tx_hash=tx_hash,
                block_number=50,
                log_index=log_index,
                event_type=EVENT_TYPE_CUSTODY_RECORDED,
                receipt_status=1,
            )

        # Verify only original event remains
        conn = sqlite3.connect(str(test_db))
        try:
            rows = conn.execute(
                "SELECT actor_address, artifact_sha256 FROM custody_events WHERE tx_hash=?",
                (tx_hash,),
            ).fetchall()
            assert len(rows) == 1
            assert rows[0] == ("0xactor1", "0xart1")
        finally:
            conn.close()

    def test_canonical_event_id_construction(self):
        """make_event_id constructs deterministic canonical event ID string."""
        eid = make_event_id(31337, "0x5FBdB2315678AFecB367f032d93F642f64180aa3", "0xTXHASH123", 4)
        assert eid == "31337:0x5fbdb2315678afecb367f032d93f642f64180aa3:0xtxhash123:4"


# ==============================================================================
# Gate G3-03: Zero INSERT OR REPLACE in Custody History
# ==============================================================================
class TestGate3_03_NoInsertOrReplace:
    """Gate G3-03: Pure INSERT; zero INSERT OR REPLACE or REPLACE INTO across schemas and store."""

    def test_static_code_inspection_zero_replace_keywords(self):
        """Source files forensics/schemas.py and forensics/onchain_store.py contain zero INSERT OR REPLACE."""
        schemas_path = Path("forensics/schemas.py")
        store_path = Path("forensics/onchain_store.py")

        assert schemas_path.is_file(), "schemas.py must exist"
        assert store_path.is_file(), "onchain_store.py must exist"

        schemas_content = schemas_path.read_text(encoding="utf-8").upper()
        store_content = store_path.read_text(encoding="utf-8").upper()

        forbidden_patterns = [
            "INSERT OR REPLACE",
            "REPLACE INTO",
            "INSERT OR IGNORE",
        ]

        for pattern in forbidden_patterns:
            assert pattern not in schemas_content, f"Forbidden SQL pattern '{pattern}' found in schemas.py"
            assert pattern not in store_content, f"Forbidden SQL pattern '{pattern}' found in onchain_store.py"

    def test_custody_history_preservation_under_attempted_update(self, test_db: Path):
        """Custody records cannot be mutated or clobbered; historical records remain immutable."""
        chain_id = 31337
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0ximmutabletx"

        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            action=0,
            actor="0xoriginalactor",
            artifact_sha256="0xoriginalartifact",
            note_hash="0xoriginalnote",
            tx_hash=tx_hash,
            block_number=10,
            log_index=0,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt_status=1,
        )

        # Attempt to insert conflicting data on same event tuple
        with pytest.raises(sqlite3.IntegrityError):
            persist_verified_event(
                test_db,
                chain_id=chain_id,
                contract=contract,
                evidence_id=1,
                action=0,
                actor="0xmutatedactor",
                artifact_sha256="0xmutatedartifact",
                note_hash="0xmutatednote",
                tx_hash=tx_hash,
                block_number=10,
                log_index=0,
                event_type=EVENT_TYPE_CUSTODY_RECORDED,
                receipt_status=1,
            )

        # Historical record must still have original values
        conn = sqlite3.connect(str(test_db))
        try:
            row = conn.execute(
                "SELECT actor_address, artifact_sha256, note_hash FROM custody_events WHERE tx_hash=?",
                (tx_hash,),
            ).fetchone()
            assert row == ("0xoriginalactor", "0xoriginalartifact", "0xoriginalnote")
        finally:
            conn.close()


# ==============================================================================
# Gate G3-04: Strict Verification Before verified=1
# ==============================================================================
class TestGate3_04_StrictVerification:
    """Gate G3-04: Mark verified=1 ONLY after receipt status==1, valid blockNumber, and topic match."""

    def test_successful_receipt_verification_marks_verified_1(self, test_db: Path):
        """Valid receipt with status=1, blockNumber, and matching topic sets verified=1."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xvalidafterverify"

        receipt = {
            "status": 1,
            "blockNumber": "0x64",  # 100
            "logs": [
                {
                    "address": contract,
                    "topics": [TOPIC_EVIDENCE_REGISTERED, "0x1", "0x2", "0x3"],
                    "data": "0x",
                    "logIndex": "0x0",
                }
            ],
        }

        persist_verified_event(
            test_db,
            chain_id=31337,
            contract=contract,
            evidence_id=1,
            manifest_sha256=hashlib.sha256(b"man1").hexdigest(),
            tx_hash=tx_hash,
            block_number=100,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=receipt,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            custody_row = conn.execute(
                "SELECT verified FROM custody_events WHERE tx_hash=?", (tx_hash,)
            ).fetchone()
            assert custody_row == (1,)

            anchor_row = conn.execute(
                "SELECT verified FROM anchor_links WHERE tx_hash=?", (tx_hash,)
            ).fetchone()
            assert anchor_row == (1,)
        finally:
            conn.close()

    def test_reverted_receipt_status_zero_rejected(self, test_db: Path):
        """Receipt with status=0 is rejected and writes 0 rows to database."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xrevertedtx"

        receipt = {
            "status": 0,  # Reverted!
            "blockNumber": "0x64",
            "logs": [],
        }

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*status"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=2,
                manifest_sha256="0xman2",
                tx_hash=tx_hash,
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=receipt,
            )

        conn = sqlite3.connect(str(test_db))
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM custody_events WHERE tx_hash=?", (tx_hash,)
            ).fetchone()[0]
            assert count == 0
        finally:
            conn.close()

    def test_missing_block_number_rejected(self, test_db: Path):
        """Receipt with missing blockNumber (pending tx) is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xpendingtx"

        receipt = {
            "status": 1,
            "blockNumber": None,  # Not yet mined!
            "logs": [],
        }

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*blockNumber"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=3,
                manifest_sha256="0xman3",
                tx_hash=tx_hash,
                block_number=None,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=receipt,
            )

    def test_topic_mismatch_rejected(self, test_db: Path):
        """Receipt without matching event topic is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xwrongtopic"

        unrelated_topic = "0x0000000000000000000000000000000000000000000000000000000000000000"
        receipt = {
            "status": 1,
            "blockNumber": 100,
            "logs": [
                {
                    "address": contract,
                    "topics": [unrelated_topic],
                    "data": "0x",
                }
            ],
        }

        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED.*topic"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=4,
                manifest_sha256="0xman4",
                tx_hash=tx_hash,
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=receipt,
            )

    def test_verify_receipt_and_event_helper(self):
        """verify_receipt_and_event unit test covering all validation paths."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"

        # Valid EvidenceRegistered log
        valid_receipt = {
            "status": 1,
            "blockNumber": 50,
            "logs": [
                {"address": contract, "topics": [TOPIC_EVIDENCE_REGISTERED]},
            ],
        }
        res = verify_receipt_and_event(valid_receipt, EVENT_TYPE_EVIDENCE_REGISTERED, contract)
        assert res["topics"][0] == TOPIC_EVIDENCE_REGISTERED

        # Status 0 failure
        with pytest.raises(RuntimeError, match="status is not 1"):
            verify_receipt_and_event({"status": 0, "blockNumber": 50}, EVENT_TYPE_EVIDENCE_REGISTERED)

        # Missing blockNumber failure
        with pytest.raises(RuntimeError, match="missing blockNumber"):
            verify_receipt_and_event({"status": 1, "blockNumber": None}, EVENT_TYPE_EVIDENCE_REGISTERED)

        # Topic mismatch failure
        with pytest.raises(RuntimeError, match="topic mismatch"):
            verify_receipt_and_event(
                {"status": 1, "blockNumber": 50, "logs": [{"address": contract, "topics": ["0x9999"]}]},
                EVENT_TYPE_EVIDENCE_REGISTERED,
            )


# ==============================================================================
# Gate G3-11: Additive Migration Integrity & Pre-Send DB Check
# ==============================================================================
class TestGate3_11_DatabaseReadinessAndMigration:
    """Gate G3-11: Additive SQLite migrations preserve historical data;

    pre-send checks refuse transaction dispatch if DB is missing or read-only.
    """

    def test_pre_send_missing_database_raises_db_required(self, tmp_path: Path):
        """pre-send check on non-existent database file raises DB_REQUIRED."""
        missing_db = tmp_path / "non_existent.db"

        with pytest.raises(RuntimeError, match="DB_REQUIRED"):
            open_existing_rw(missing_db)

        with pytest.raises(RuntimeError, match="DB_REQUIRED"):
            pre_send_db_check(missing_db)

    def test_pre_send_readonly_database_raises_db_readonly(self, tmp_path: Path):
        """pre-send check on read-only database raises DB_READONLY."""
        db_file = tmp_path / "readonly.db"
        conn = init_db(str(db_file))
        conn.close()

        # Set read-only permissions
        os.chmod(db_file, stat.S_IREAD)
        try:
            with pytest.raises(RuntimeError, match="DB_READONLY"):
                open_existing_rw(db_file)

            with pytest.raises(RuntimeError, match="DB_READONLY"):
                pre_send_db_check(db_file)
        finally:
            # Restore write permissions for cleanup
            os.chmod(db_file, stat.S_IWRITE)

        # Confirm writable again
        conn = open_existing_rw(db_file)
        conn.close()

    def test_fail_fast_on_missing_schema(self, tmp_path: Path):
        """Unmigrated database fails fast if migrate_before_send is False."""
        db_file = tmp_path / "unmigrated.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE foo(id INT)")
        conn.commit()
        conn.close()

        # Fails when migrate_before_send=False
        with pytest.raises(RuntimeError, match="GROUP3_SCHEMA_MISSING"):
            open_existing_rw(db_file, migrate_before_send=False)

        # Succeeds when migrate_before_send=True
        conn = open_existing_rw(db_file, migrate_before_send=True)
        assert group3_schema_present(conn) is True
        conn.close()

    def test_additive_migration_historical_preservation(self, legacy_db: Path):
        """migrate_group3 preserves 100% of historical rows and passes integrity checks."""
        conn = sqlite3.connect(str(legacy_db))
        try:
            # Pre-migration count and values
            hist_before = conn.execute("SELECT * FROM custody_events").fetchall()
            assert len(hist_before) == 1

            # Run migration
            migrate_group3(conn)
            conn.commit()

            # Verify Group 3 schema is present
            assert group3_schema_present(conn) is True

            # Verify new columns added
            cols = {r[1] for r in conn.execute("PRAGMA table_info(custody_events)").fetchall()}
            assert "log_index" in cols
            assert "event_type" in cols

            # Verify historical rows preserved with exact original data
            hist_after = conn.execute("SELECT event_id, evidence_id, case_id FROM custody_events").fetchall()
            assert len(hist_after) == 1
            assert hist_after[0] == ("hist-ev-1", 1, "CASE-HISTORICAL-01")

            # Check integrity
            integrity = conn.execute("PRAGMA integrity_check").fetchall()
            assert integrity == [("ok",)]

            fk_check = conn.execute("PRAGMA foreign_key_check").fetchall()
            assert fk_check == []
        finally:
            conn.close()

    def test_rollback_group3_preserves_historical_custody(self, legacy_db: Path):
        """rollback_group3 removes additive objects without deleting historical custody rows."""
        conn = sqlite3.connect(str(legacy_db))
        try:
            migrate_group3(conn)
            assert group3_schema_present(conn) is True

            rollback_group3(conn)
            conn.commit()

            # Group 3 tables should be dropped
            assert group3_schema_present(conn) is False

            # Historical custody rows MUST remain intact
            hist = conn.execute("SELECT event_id, case_id FROM custody_events").fetchall()
            assert len(hist) == 1
            assert hist[0] == ("hist-ev-1", "CASE-HISTORICAL-01")
        finally:
            conn.close()


# ==============================================================================
# Gate G3-14: Distinguish EvidenceRegistered vs CustodyRecorded
# ==============================================================================
class TestGate3_14_EventDistinctionAndRetention:
    """Gate G3-14: Distinguish EvidenceRegistered vs CustodyRecorded by topic/signature

    and retain evidence packages on disk upon database write failure.
    """

    def test_event_topic_decoding_and_classification(self):
        """Topic0 correctly decodes to EvidenceRegistered or CustodyRecorded."""
        assert classify_event_topic(TOPIC_EVIDENCE_REGISTERED) == EVENT_TYPE_EVIDENCE_REGISTERED
        assert classify_event_topic(TOPIC_CUSTODY_RECORDED) == EVENT_TYPE_CUSTODY_RECORDED

        # Case insensitivity
        assert classify_event_topic(TOPIC_EVIDENCE_REGISTERED.upper()) == EVENT_TYPE_EVIDENCE_REGISTERED
        assert classify_event_topic(TOPIC_CUSTODY_RECORDED.upper()) == EVENT_TYPE_CUSTODY_RECORDED

        # Unknown topic raises ValueError
        with pytest.raises(ValueError, match="UNKNOWN_EVENT_TOPIC"):
            classify_event_topic("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

    def test_event_type_separation_in_database(self, test_db: Path):
        """EvidenceRegistered populates anchor_links; CustodyRecorded does NOT populate anchor_links."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        chain_id = 31337

        # 1. Register event
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            manifest_sha256=hashlib.sha256(b"manifest1").hexdigest(),
            tx_hash="0xregtx",
            block_number=10,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt_status=1,
        )

        # 2. Custody event
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            action=2,  # TRANSFERRED
            actor="0xactor",
            artifact_sha256="0xartifact",
            note_hash="0xnote",
            tx_hash="0xcusttx",
            block_number=11,
            log_index=0,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt_status=1,
        )

        conn = sqlite3.connect(str(test_db))
        try:
            # custody_events has both with their exact event_type
            rows = conn.execute(
                "SELECT tx_hash, event_type, action FROM custody_events ORDER BY block_number"
            ).fetchall()
            assert len(rows) == 2
            assert rows[0] == ("0xregtx", EVENT_TYPE_EVIDENCE_REGISTERED, 0)
            assert rows[1] == ("0xcusttx", EVENT_TYPE_CUSTODY_RECORDED, 2)

            # anchor_links ONLY has the registration event
            anchor_rows = conn.execute("SELECT tx_hash, event_type FROM anchor_links").fetchall()
            assert len(anchor_rows) == 1
            assert anchor_rows[0] == ("0xregtx", EVENT_TYPE_EVIDENCE_REGISTERED)
        finally:
            conn.close()

    def test_package_retention_on_database_failure(self, tmp_path: Path):
        """Evidence package file on disk is retained intact if database write fails."""
        package_dir = tmp_path / "evidence_pkg"
        package_dir.mkdir()
        manifest_file = package_dir / "manifest.json"
        manifest_content = b'{"case_id": "CASE-123", "evidence": []}'
        manifest_file.write_bytes(manifest_content)
        expected_sha = hashlib.sha256(manifest_content).hexdigest()

        # Simulate read-only database failure
        readonly_db = tmp_path / "failing.db"
        conn = init_db(str(readonly_db))
        conn.close()
        os.chmod(readonly_db, stat.S_IREAD)

        try:
            with pytest.raises(RuntimeError):
                persist_verified_event(
                    readonly_db,
                    chain_id=31337,
                    contract="0x1234567890123456789012345678901234567890",
                    evidence_id=1,
                    manifest_sha256=expected_sha,
                    tx_hash="0xfailtx",
                    block_number=10,
                    log_index=0,
                    event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                    receipt_status=1,
                )
        finally:
            os.chmod(readonly_db, stat.S_IWRITE)

        # Package file on disk MUST still exist and be completely unaltered
        assert manifest_file.is_file(), "Manifest file must not be deleted on DB failure"
        assert manifest_file.read_bytes() == manifest_content
        assert hashlib.sha256(manifest_file.read_bytes()).hexdigest() == expected_sha
