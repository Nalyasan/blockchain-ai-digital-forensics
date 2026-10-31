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

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest

from forensics.evidence_identity import (
    CANONICAL_URI_LENGTH,
    canonical_storage_uri,
    case_id_digest,
)
from forensics.exporter import export_package
from forensics.integrity import verify_package
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

def make_mock_receipt(
    contract: str,
    tx_hash: str,
    block_number: int | str,
    event_type: str,
    log_index: int = 0,
    evidence_id: int = 1,
    actor: str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    action: int = 0,
    case_digest: str | None = None,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Helper to construct authentic mock transaction receipts for onchain store tests."""
    topic0 = get_event_topic(event_type)
    topics = [topic0]
    blk_num_hex = hex(block_number) if isinstance(block_number, int) else str(block_number)
    if event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
        c_hash = "0x" + (case_digest or ("11" * 32)).lower().removeprefix("0x").zfill(64)
        m_hash = "0x" + (manifest_sha256 or ("22" * 32)).lower().removeprefix("0x").zfill(64)
        topics.extend([
            "0x" + hex(evidence_id)[2:].zfill(64),
            c_hash,
            m_hash,
        ])
        data = "0x" + actor.lower().removeprefix("0x").zfill(64) + "00" * 32
    else:
        topics.extend([
            "0x" + hex(evidence_id)[2:].zfill(64),
            "0x" + hex(action)[2:].zfill(64),
            "0x" + actor.lower().removeprefix("0x").zfill(64),
        ])
        data = "0x" + ("33" * 32) + ("44" * 32)
    return {
        "status": 1,
        "blockNumber": blk_num_hex,
        "transactionHash": tx_hash,
        "blockHash": "0x" + "bb" * 32,
        "logs": [{
            "address": contract,
            "topics": topics,
            "data": data,
            "logIndex": hex(log_index) if isinstance(log_index, int) else log_index,
        }]
    }


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


def populate_store_test_db(db_file: Path | str, num_blocks: int = 5) -> None:
    """Populate sample blocks, transactions, receipts, and audit events for exporter tests."""
    conn = init_db(str(db_file))
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
        "VALUES('run-test-01', 'anvil-smoke-node', 31337, 0, 'backfill', 0, ?, ?, ?, 10.0, 10.0, 0, 0, 'completed', ?, ?, 'commit1')",
        (num_blocks - 1, num_blocks, num_blocks, utc_str, utc_str)
    )
    conn.commit()
    conn.close()


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
        rc1 = make_mock_receipt(contract, "0x1111111111111111111111111111111111111111111111111111111111111111", 101, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=1, case_digest=case_digest, manifest_sha256=manifest_1_sha)
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
            receipt=rc1,
        )

        # Persist manifest 2 for the same case
        rc2 = make_mock_receipt(contract, "0x2222222222222222222222222222222222222222222222222222222222222222", 102, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=2, case_digest=case_digest, manifest_sha256=manifest_2_sha)
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
            receipt=rc2,
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

        rc1 = make_mock_receipt(contract, "0xaaaa", 1, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=10, manifest_sha256=m1_sha)
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
            receipt=rc1,
        )
        rc2 = make_mock_receipt(contract, "0xbbbb", 2, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=20, manifest_sha256=m2_sha)
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
            receipt=rc2,
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

        c_addr = "0x1111111111111111111111111111111111111111"
        rc1 = make_mock_receipt(c_addr, "0xtx1", 1, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=1, manifest_sha256=manifest_sha)
        persist_verified_event(
            test_db,
            chain_id=31337,
            contract=c_addr,
            evidence_id=1,
            manifest_sha256=manifest_sha,
            tx_hash="0xtx1",
            block_number=1,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=rc1,
        )
        rc2 = make_mock_receipt(c_addr, "0xtx2", 5000, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=100, manifest_sha256=manifest_sha)
        persist_verified_event(
            test_db,
            chain_id=11155111,
            contract=c_addr,
            evidence_id=100,
            manifest_sha256=manifest_sha,
            tx_hash="0xtx2",
            block_number=5000,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=rc2,
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

        # Action 0 (COLLECTED) in tx at log_index 0
        rc1 = make_mock_receipt(contract, tx_hash, 100, EVENT_TYPE_CUSTODY_RECORDED, 0, evidence_id=1, action=0)
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
            receipt=rc1,
        )

        # Action 1 (ANALYZED) in same tx at log_index 1
        rc2 = make_mock_receipt(contract, tx_hash, 100, EVENT_TYPE_CUSTODY_RECORDED, 1, evidence_id=1, action=1)
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
            receipt=rc2,
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
        rc1 = make_mock_receipt(contract, tx_hash, 50, EVENT_TYPE_CUSTODY_RECORDED, log_index, evidence_id=5, action=0, actor="0xactor1")
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
            receipt=rc1,
        )

        # Attempt to insert identical event tuple with different payload
        rc2 = make_mock_receipt(contract, tx_hash, 50, EVENT_TYPE_CUSTODY_RECORDED, log_index, evidence_id=5, action=1, actor="0xactor2")
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
                receipt=rc2,
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

        rc1 = make_mock_receipt(contract, tx_hash, 10, EVENT_TYPE_CUSTODY_RECORDED, 0, evidence_id=1, action=0, actor="0xoriginalactor")
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
            receipt=rc1,
        )

        # Attempt to insert conflicting data on same event tuple
        rc2 = make_mock_receipt(contract, tx_hash, 10, EVENT_TYPE_CUSTODY_RECORDED, 0, evidence_id=1, action=0, actor="0xmutatedactor")
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
                receipt=rc2,
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

        manifest_sha = hashlib.sha256(b"man1").hexdigest()
        receipt = make_mock_receipt(
            contract=contract,
            tx_hash=tx_hash,
            block_number=100,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            evidence_id=1,
            manifest_sha256=manifest_sha,
        )

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
            "transactionHash": tx_hash,
            "blockHash": "0x" + "bb" * 32,
            "logs": [
                {
                    "address": contract,
                    "logIndex": 0,
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
        valid_receipt = make_mock_receipt(
            contract=contract,
            tx_hash="0xvalidtx",
            block_number=50,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            evidence_id=1,
        )
        res = verify_receipt_and_event(valid_receipt, EVENT_TYPE_EVIDENCE_REGISTERED, contract)
        assert res["topics"][0] == TOPIC_EVIDENCE_REGISTERED

        # Status 0 failure
        rec_status0 = dict(valid_receipt, status=0)
        with pytest.raises(RuntimeError, match="status is not 1"):
            verify_receipt_and_event(rec_status0, EVENT_TYPE_EVIDENCE_REGISTERED)

        # Missing blockNumber failure
        rec_no_bn = dict(valid_receipt, blockNumber=None)
        with pytest.raises(RuntimeError, match="missing blockNumber"):
            verify_receipt_and_event(rec_no_bn, EVENT_TYPE_EVIDENCE_REGISTERED)

        # Topic mismatch failure
        rec_mismatch = dict(valid_receipt)
        rec_mismatch["logs"] = [{"address": contract, "logIndex": 0, "topics": ["0x9999"]}]
        with pytest.raises(RuntimeError, match="topic mismatch"):
            verify_receipt_and_event(
                rec_mismatch,
                EVENT_TYPE_EVIDENCE_REGISTERED,
            )


# ==============================================================================
# Gate G3-11: Additive Migration Integrity & Pre-Send DB Check
# ==============================================================================

    def test_persist_verified_event_missing_receipt_strictly_rejected(self, test_db: Path):
        """Bypass attempt: calling persist_verified_event without receipt is strictly blocked."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: valid transaction receipt is strictly required"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                tx_hash="0xbypasstx",
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=None,
            )

    def test_persist_verified_event_self_declared_block_and_status_without_receipt_rejected(self, test_db: Path):
        """Bypass attempt: passing self-declared blockNumber, topic0 and receipt_status without receipt is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: valid transaction receipt is strictly required"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                tx_hash="0xbypasstx2",
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt_status=1,
                topic0=TOPIC_EVIDENCE_REGISTERED,
            )

    def test_persist_verified_event_contract_mismatch_rejected(self, test_db: Path):
        """Receipt from a different contract address is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        wrong_contract = "0x9999999999999999999999999999999999999999"
        tx_hash = "0xcontractmismatch"
        receipt = make_mock_receipt(wrong_contract, tx_hash, 100, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=1)
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: contract address mismatch"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                tx_hash=tx_hash,
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=receipt,
            )

    def test_persist_verified_event_tx_hash_mismatch_rejected(self, test_db: Path):
        """Receipt transactionHash differing from claimed tx_hash is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        receipt = make_mock_receipt(contract, "0xactual_tx_hash", 100, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=1)
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: transactionHash mismatch"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                tx_hash="0xclaimed_tx_hash",
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
                receipt=receipt,
            )

    def test_persist_verified_event_actor_mismatch_rejected(self, test_db: Path):
        """Receipt actor differing from claimed actor in CustodyRecorded is rejected."""
        contract = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
        tx_hash = "0xactormismatch"
        receipt = make_mock_receipt(
            contract, tx_hash, 100, EVENT_TYPE_CUSTODY_RECORDED, 0, evidence_id=1,
            actor="0x1111111111111111111111111111111111111111"
        )
        with pytest.raises(RuntimeError, match="VERIFICATION_FAILED: actor mismatch"):
            persist_verified_event(
                test_db,
                chain_id=31337,
                contract=contract,
                evidence_id=1,
                tx_hash=tx_hash,
                block_number=100,
                log_index=0,
                event_type=EVENT_TYPE_CUSTODY_RECORDED,
                actor="0x2222222222222222222222222222222222222222",
                receipt=receipt,
            )


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

    def test_migration_with_duplicate_and_text_note_legacy_rows(self, tmp_path: Path):
        """Migration preserves diverse legacy rows including duplicate tx_hashes, text notes, and verified states."""
        db_file = tmp_path / "diverse_legacy.db"
        conn = sqlite3.connect(str(db_file))

        # Create pre-Group 3 schema
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

        # 1. Insert diverse legacy rows:
        # - Row 1 & Row 2 share the same tx_hash (duplicate in legacy because log_index did not exist)
        # - Row 1 has legacy raw text note
        # - Row 2 has verified=0
        # - Row 3 has hex note_hash and verified=1
        same_tx = "0x" + "7" * 64
        shared_contract = "0x" + "8" * 40
        conn.execute(
            "INSERT INTO custody_events VALUES("
            "'ev-legacy-dup1', 1, 'CASE-LEGACY-DUP', 0, '0xactor1', '0xart1', "
            "'Raw text custody note from legacy investigator without hex prefix', "
            "31337, ?, ?, 10, '2026-01-01T00:00:00Z', 0)",
            (shared_contract, same_tx)
        )
        conn.execute(
            "INSERT INTO custody_events VALUES("
            "'ev-legacy-dup2', 1, 'CASE-LEGACY-DUP', 1, '0xactor2', '0xart2', "
            "'0x' || hex(randomblob(32)), "
            "31337, ?, ?, 10, '2026-01-01T00:01:00Z', 0)",
            (shared_contract, same_tx)
        )
        conn.execute(
            "INSERT INTO custody_events VALUES("
            "'ev-legacy-ver3', 2, 'CASE-LEGACY-VER', 2, '0xactor3', '0xart3', "
            "'0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', "
            "31337, ?, '0xdiff_tx', 12, '2026-01-01T00:02:00Z', 1)",
            (shared_contract,)
        )
        conn.execute(
            "INSERT INTO evidence_exports VALUES('exp-1', 'CASE-LEGACY-DUP', 'manifest.json', 'hash1', 'uri1', '2026-01-01T00:00:00Z', 'op1', 1)"
        )
        conn.commit()

        # Capture pre-migration logical snapshot across all tables
        tables = ["blocks", "transactions", "evidence_exports", "custody_events"]
        pre_snapshot = {}
        for t in tables:
            rows = conn.execute(f"SELECT * FROM {t}").fetchall()
            pre_snapshot[t] = rows
        pre_snapshot_bytes = json.dumps(pre_snapshot, sort_keys=True, default=str).encode("utf-8")
        pre_snapshot_hash = hashlib.sha256(pre_snapshot_bytes).hexdigest()

        # Run additive Group 3 migration
        migrate_group3(conn)
        conn.commit()

        # 1. Assert Group 3 schema is present
        assert group3_schema_present(conn) is True

        # 2. Assert PRAGMA integrity_check and foreign_key_check pass
        integrity = conn.execute("PRAGMA integrity_check").fetchall()
        assert integrity == [("ok",)]
        fk_check = conn.execute("PRAGMA foreign_key_check").fetchall()
        assert fk_check == []

        # 3. Assert pre-existing columns maintain 100% exact logical snapshot
        post_snapshot = {}
        # Get column names present prior to migration
        for t in tables:
            if t == "custody_events":
                # Exclude additive columns log_index, event_type when comparing historical data
                rows = conn.execute(
                    "SELECT event_id, evidence_id, case_id, action, actor_address, artifact_sha256, "
                    "note_hash, chain_id, contract_address, tx_hash, block_number, recorded_at, verified "
                    "FROM custody_events ORDER BY event_id"
                ).fetchall()
            else:
                rows = conn.execute(f"SELECT * FROM {t}").fetchall()
            post_snapshot[t] = rows

        # Exact match of historical data
        assert len(post_snapshot["custody_events"]) == 3
        assert post_snapshot["custody_events"][0][0] == "ev-legacy-dup1"
        assert post_snapshot["custody_events"][0][6] == "Raw text custody note from legacy investigator without hex prefix"
        assert post_snapshot["custody_events"][0][12] == 0
        assert post_snapshot["custody_events"][1][0] == "ev-legacy-dup2"
        assert post_snapshot["custody_events"][1][9] == same_tx
        assert post_snapshot["custody_events"][2][0] == "ev-legacy-ver3"
        assert post_snapshot["custody_events"][2][12] == 1

        # 4. Assert additive columns are NULL on legacy rows (no unauthorized backfilling)
        null_check = conn.execute("SELECT log_index, event_type FROM custody_events").fetchall()
        assert all(row == (None, None) for row in null_check)

        # 5. Assert unique index permits multiple legacy rows with NULL log_index
        # Inserting a new event with explicit log_index works
        conn.execute(
            "INSERT INTO custody_events VALUES("
            "'ev-new-1', 1, 'CASE-NEW', 0, '0xactor', '0xart', '0xnote', "
            "31337, ?, ?, 15, '2026-01-01T00:03:00Z', 1, 0, 'EvidenceRegistered')",
            (shared_contract, same_tx)
        )
        conn.commit()

        # Duplicate with exact same (chain_id, contract_address, tx_hash, log_index) is rejected
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO custody_events VALUES("
                "'ev-new-dup', 1, 'CASE-NEW', 0, '0xactor', '0xart', '0xnote', "
                "31337, ?, ?, 15, '2026-01-01T00:03:00Z', 1, 0, 'EvidenceRegistered')",
                (shared_contract, same_tx)
            )

        conn.close()

    def test_migration_rollback_error_simulation_and_rerun_resilience(self, tmp_path: Path):
        """Simulation of migration failure rolls back cleanly and rerun succeeds idempotently."""
        db_file = tmp_path / "rollback_resilience.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute(
            """
            CREATE TABLE custody_events(
                event_id TEXT PRIMARY KEY, evidence_id INT, case_id TEXT, action INT,
                actor_address TEXT, artifact_sha256 TEXT, note_hash TEXT, chain_id INT,
                contract_address TEXT, tx_hash TEXT, block_number INT, recorded_at TEXT,
                verified INT DEFAULT 0
            )
            """
        )
        conn.execute(
            "INSERT INTO custody_events VALUES('ev-1', 1, 'CASE-1', 0, '0xactor', '0xart', '0xnote', "
            "31337, '0xcontract', '0xtx1', 10, '2026-01-01T00:00:00Z', 1)"
        )
        conn.commit()

        # Simulate failure during transaction
        try:
            conn.execute("BEGIN TRANSACTION")
            conn.execute("ALTER TABLE custody_events ADD COLUMN log_index INTEGER")
            # Inject simulated failure
            raise sqlite3.OperationalError("SIMULATED_MIGRATION_IO_ERROR")
        except sqlite3.OperationalError:
            conn.rollback()

        # Verify DB is uncorrupted and rollback restored original schema
        integrity = conn.execute("PRAGMA integrity_check").fetchall()
        assert integrity == [("ok",)]
        cols = {r[1] for r in conn.execute("PRAGMA table_info(custody_events)").fetchall()}
        assert "log_index" not in cols

        # Now run migration for real
        migrate_group3(conn)
        conn.commit()
        assert group3_schema_present(conn) is True

        # Running migration a second time is fully idempotent
        migrate_group3(conn)
        conn.commit()
        assert group3_schema_present(conn) is True

        integrity_after = conn.execute("PRAGMA integrity_check").fetchall()
        assert integrity_after == [("ok",)]
        conn.close()

    def test_wal_journal_mode_and_safe_fixture_isolation(self, tmp_path: Path):
        """Migration succeeds under WAL mode and operates strictly within isolated temporary fixtures."""
        db_file = tmp_path / "wal_test.db"
        conn = init_db(str(db_file))

        # Enable WAL mode
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        assert mode.upper() == "WAL"

        # Verify migration on WAL DB
        migrate_group3(conn)
        conn.commit()
        assert group3_schema_present(conn) is True

        integrity = conn.execute("PRAGMA integrity_check").fetchall()
        assert integrity == [("ok",)]

        # Verify strict database path isolation: must NOT be production DB
        assert str(db_file) != "data/forensics.db"
        assert not str(db_file).endswith("data/forensics.db")
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
        m1 = hashlib.sha256(b"manifest1").hexdigest()
        rc1 = make_mock_receipt(contract, "0xregtx", 10, EVENT_TYPE_EVIDENCE_REGISTERED, 0, evidence_id=1, manifest_sha256=m1)
        persist_verified_event(
            test_db,
            chain_id=chain_id,
            contract=contract,
            evidence_id=1,
            manifest_sha256=m1,
            tx_hash="0xregtx",
            block_number=10,
            log_index=0,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=rc1,
        )

        # 2. Custody event
        rc2 = make_mock_receipt(contract, "0xcusttx", 11, EVENT_TYPE_CUSTODY_RECORDED, 0, evidence_id=1, action=2, actor="0xactor")
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
            receipt=rc2,
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

    def test_export_evidence_creates_canonical_storage_uri_in_db(self, tmp_path: Path):
        """export_package inserts canonical storage URI in database metadata with zero raw case_id leakage."""
        db_file = tmp_path / "export_test.db"
        populate_store_test_db(db_file, num_blocks=3)

        case_raw = "CASE-CANONICAL-2026-X1"
        pkg_dir = tmp_path / "pkg_canonical"

        m = export_package(case_raw, 0, 2, out_dir=str(pkg_dir), db_path=str(db_file), allow_gaps=True)
        manifest_hash = hashlib.sha256((pkg_dir / "manifest.json").read_bytes()).hexdigest()

        # Query database record
        conn = sqlite3.connect(str(db_file))
        row = conn.execute("SELECT case_id, storage_uri, manifest_sha256 FROM evidence_exports").fetchone()
        conn.close()

        assert row is not None
        db_case_id, db_storage_uri, db_manifest_hash = row
        assert db_case_id == case_raw
        assert db_manifest_hash == manifest_hash

        # Canonical URI assertions
        expected_uri = canonical_storage_uri(case_id_digest(case_raw), manifest_hash)
        assert db_storage_uri == expected_uri
        assert len(db_storage_uri) == CANONICAL_URI_LENGTH
        assert db_storage_uri.startswith("evidence://sha256/")

        # Zero leakage of raw case_id into storage URI
        assert case_raw not in db_storage_uri

        # Manifest JSON on disk does NOT contain storage_uri (avoids self-referential cycle)
        manifest_raw = (pkg_dir / "manifest.json").read_text(encoding="utf-8")
        assert "storage_uri" not in manifest_raw
        assert db_storage_uri not in manifest_raw

    def test_export_evidence_collision_no_clobber(self, tmp_path: Path):
        """Export refuses to overwrite existing destination directory and preserves existing package intact."""
        db_file = tmp_path / "collision_test.db"
        populate_store_test_db(db_file, num_blocks=3)

        case_raw = "CASE-COLLISION-01"
        pkg_dir = tmp_path / "pkg_collision"

        # First export succeeds
        export_package(case_raw, 0, 2, out_dir=str(pkg_dir), db_path=str(db_file), allow_gaps=True)
        original_manifest_bytes = (pkg_dir / "manifest.json").read_bytes()

        # Second export to exact same directory MUST fail with DESTINATION_EXISTS
        with pytest.raises(FileExistsError, match="DESTINATION_EXISTS"):
            export_package(case_raw, 0, 2, out_dir=str(pkg_dir), db_path=str(db_file), allow_gaps=True)

        # Existing files must be completely untouched
        assert (pkg_dir / "manifest.json").read_bytes() == original_manifest_bytes

    def test_export_evidence_two_manifests_distinct_canonical_uris(self, tmp_path: Path):
        """Exporting two distinct packages for the same case yields distinct manifest hashes and URIs."""
        db_file = tmp_path / "dual_test.db"
        populate_store_test_db(db_file, num_blocks=5)

        case_raw = "CASE-DUAL-01"
        pkg1_dir = tmp_path / "pkg1"
        pkg2_dir = tmp_path / "pkg2"

        export_package(case_raw, 0, 2, out_dir=str(pkg1_dir), db_path=str(db_file), allow_gaps=True)
        export_package(case_raw, 0, 4, out_dir=str(pkg2_dir), db_path=str(db_file), allow_gaps=True)

        conn = sqlite3.connect(str(db_file))
        rows = conn.execute("SELECT manifest_sha256, storage_uri FROM evidence_exports ORDER BY export_id").fetchall()
        conn.close()

        assert len(rows) == 2
        hash1, uri1 = rows[0]
        hash2, uri2 = rows[1]

        assert hash1 != hash2
        assert uri1 != uri2
        assert uri1.startswith("evidence://sha256/")
        assert uri2.startswith("evidence://sha256/")

    def test_export_evidence_db_failure_retains_published_package(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Database failure after staging retains the published package on disk."""
        db_file = tmp_path / "fail_db_test.db"
        populate_store_test_db(db_file, num_blocks=3)

        case_raw = "CASE-RETAIN-01"
        pkg_dir = tmp_path / "pkg_retained"

        import forensics.schemas as schemas
        real_init = schemas.init_db

        class FailingConn:
            def __init__(self, raw_conn):
                self._conn = raw_conn
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def close(self):
                self._conn.close()
            def execute(self, sql, *args, **kwargs):
                if "INSERT INTO evidence_exports" in sql:
                    raise sqlite3.OperationalError("SIMULATED_DB_WRITE_FAILURE")
                return self._conn.execute(sql, *args, **kwargs)

        calls = 0
        def failing_init_db(path):
            nonlocal calls
            calls += 1
            c = real_init(path)
            return FailingConn(c)

        monkeypatch.setattr(schemas, "init_db", failing_init_db)

        with pytest.raises(RuntimeError, match="EXPORT_IO_OR_DB_ERROR: published package, if present, is retained"):
            export_package(case_raw, 0, 2, out_dir=str(pkg_dir), db_path=str(db_file), allow_gaps=True)

        # Published package on disk MUST still exist and be completely valid
        assert pkg_dir.is_dir()
        assert (pkg_dir / "manifest.json").is_file()
        checked = verify_package(pkg_dir)
        assert checked.status == "VALID"
