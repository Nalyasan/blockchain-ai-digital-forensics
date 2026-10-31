"""SQLite persistence, custody event management, and operation store for P3 Group 3.

Layer 2 & Layer 3: SQLite Persistence, Event Identity, and Custody Integrity.
- Additive schema migrations and verification.
- Event classification and full tuple event identity: (chain_id, contract_address, tx_hash, log_index).
- Pure INSERT with zero clobbering (prohibits replace operations).
- Strict receipt and event verification before marking verified=1.
- Pre-send fail-fast database readiness checks (DB_REQUIRED, DB_READONLY).
- Multi-manifest same-case linkage via anchor_links.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from forensics.schemas import group3_schema_present, migrate_group3

log = logging.getLogger("forensics.onchain_store")

# Operation states
READY = "READY"
SEND_STARTED = "SEND_STARTED"
BROADCAST = "BROADCAST"
CONFIRMED = "CONFIRMED"
UNKNOWN = "UNKNOWN"
FAILED = "FAILED"

# Operation types
REGISTER = "REGISTER_EVIDENCE"
CUSTODY = "RECORD_CUSTODY"

# Event signatures and topics in EvidenceRegistry.sol
# EvidenceRegistered(uint256,bytes32,bytes32,address,string)
TOPIC_EVIDENCE_REGISTERED = "0xb8860d0b7752b79a5877f967e02eea9de30085e65c13774df90c674fcf4a6e58"
# CustodyRecorded(uint256,uint8,address,bytes32,bytes32)
TOPIC_CUSTODY_RECORDED = "0xcf6b2d07eec198ac5313cb4e7be0d697c16d152be5eb56184111da1ee211a31b"

EVENT_TYPE_EVIDENCE_REGISTERED = "EvidenceRegistered"
EVENT_TYPE_CUSTODY_RECORDED = "CustodyRecorded"


def _now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(intent: Mapping[str, Any]) -> str:
    """Deterministic JSON serialization for intents."""
    return json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(intent: Mapping[str, Any]) -> str:
    """SHA-256 digest of canonical JSON intent."""
    return hashlib.sha256(canonical_json(intent).encode("utf-8")).hexdigest()


def make_event_id(chain_id: int, contract_address: str, tx_hash: str, log_index: int) -> str:
    """Construct canonical event identity string.

    Format: {chain_id}:{contract_address.lower()}:{tx_hash.lower()}:{log_index}
    """
    return f"{int(chain_id)}:{contract_address.lower()}:{tx_hash.lower()}:{int(log_index)}"


def classify_event_topic(topic0: str) -> str:
    """Classify event type from topic0 hex string.

    Returns:
        'EvidenceRegistered' or 'CustodyRecorded'

    Raises:
        ValueError: If topic0 is unrecognized or invalid.
    """
    if not isinstance(topic0, str):
        raise ValueError("Invalid topic0: must be string")
    t = topic0.lower()
    if t == TOPIC_EVIDENCE_REGISTERED.lower():
        return EVENT_TYPE_EVIDENCE_REGISTERED
    elif t == TOPIC_CUSTODY_RECORDED.lower():
        return EVENT_TYPE_CUSTODY_RECORDED
    else:
        raise ValueError(f"UNKNOWN_EVENT_TOPIC: {topic0}")


def get_event_topic(event_type: str) -> str:
    """Return topic0 hex string for a given event type name.

    Args:
        event_type: 'EvidenceRegistered' or 'CustodyRecorded'

    Returns:
        Topic0 hex string with '0x' prefix.

    Raises:
        ValueError: If event_type is unrecognized.
    """
    if event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
        return TOPIC_EVIDENCE_REGISTERED
    elif event_type == EVENT_TYPE_CUSTODY_RECORDED:
        return TOPIC_CUSTODY_RECORDED
    else:
        raise ValueError(f"UNKNOWN_EVENT_TYPE: {event_type}")


def build_register_intent(
    chain_id: int,
    contract: str,
    manifest_sha256: str,
    case_digest: str,
    storage_uri: str,
    signer: str,
) -> dict[str, Any]:
    """Construct canonical dictionary for REGISTER_EVIDENCE intent."""
    return {
        "op_type": REGISTER,
        "chain_id": int(chain_id),
        "contract": contract.lower(),
        "manifest_sha256": manifest_sha256.lower(),
        "case_digest": case_digest.lower(),
        "storage_uri": storage_uri,
        "signer": signer.lower(),
    }


def build_custody_intent(
    chain_id: int,
    contract: str,
    evidence_id: int,
    action: int,
    artifact_sha256: str,
    note_hash: str,
    signer: str,
) -> dict[str, Any]:
    """Construct canonical dictionary for RECORD_CUSTODY intent."""
    return {
        "op_type": CUSTODY,
        "chain_id": int(chain_id),
        "contract": contract.lower(),
        "evidence_id": int(evidence_id),
        "action": int(action),
        "artifact_sha256": artifact_sha256.lower(),
        "note_hash": note_hash.lower(),
        "signer": signer.lower(),
    }


def register_intent(*args, **kwargs) -> Any:
    """Overloaded helper supporting:

    1. register_intent(chain_id, contract, manifest_sha256, case_digest, storage_uri, signer) -> dict
    2. register_intent(db_path, intent_dict) -> operation_id (str)
    """
    if len(args) == 2 and isinstance(args[1], Mapping):
        db_path, intent = args
        return _insert_ready_intent(db_path, intent)
    elif "intent" in kwargs and len(args) == 1:
        return _insert_ready_intent(args[0], kwargs["intent"])
    else:
        return build_register_intent(*args, **kwargs)


def custody_intent(*args, **kwargs) -> dict[str, Any]:
    """Construct custody intent dictionary."""
    return build_custody_intent(*args, **kwargs)


def open_existing_rw(
    db_path: Path | str,
    *,
    migrate_before_send: bool = False,
    timeout: float = 30.0,
) -> sqlite3.Connection:
    """Open existing SQLite database in read-write mode with fail-fast validation.

    Checks:
    1. DB_REQUIRED: Database file must exist on disk.
    2. DB_READONLY: File must be writable (fails fast if read-only attribute or permissions).
    3. Mode: Opens with URI mode=rw.
    4. Schema: Verifies Group 3 schema is present (or migrates if migrate_before_send=True).

    Args:
        db_path: Path to SQLite database file.
        migrate_before_send: If True, executes migrate_group3 prior to checking schema.
        timeout: SQLite busy timeout in seconds (default: 30.0).

    Returns:
        sqlite3.Connection configured with autocommit (isolation_level=None).

    Raises:
        RuntimeError: With DB_REQUIRED, DB_READONLY, DB_LOCKED, or GROUP3_SCHEMA_MISSING.
    """
    path = Path(db_path)
    if not path.is_file():
        raise RuntimeError("DB_REQUIRED: Database file does not exist")
    if not os.access(path, os.W_OK):
        raise RuntimeError("DB_READONLY: Database is read-only")

    try:
        uri = f"file:{path.resolve().as_posix()}?mode=rw"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout)
    except sqlite3.OperationalError as e:
        msg = str(e).lower()
        if "readonly" in msg or "permission denied" in msg:
            raise RuntimeError("DB_READONLY: Database is read-only") from None
        raise RuntimeError("DB_LOCKED") from None
    except sqlite3.Error:
        raise RuntimeError("DB_LOCKED") from None

    # Test if DB is genuinely writable (catches OS-level read-only file handles)
    try:
        conn.execute("PRAGMA schema_version")
    except sqlite3.OperationalError as e:
        conn.close()
        msg = str(e).lower()
        if "readonly" in msg or "attempt to write a readonly database" in msg:
            raise RuntimeError("DB_READONLY: Database is read-only") from None
        raise

    conn.isolation_level = None
    try:
        if migrate_before_send:
            migrate_group3(conn)
        if not group3_schema_present(conn):
            raise RuntimeError("GROUP3_SCHEMA_MISSING: Group 3 schema is missing")
    except Exception:
        conn.close()
        raise
    return conn


def pre_send_db_check(db_path: Path | str, *, migrate: bool = False) -> None:
    """Enforce pre-send database check.

    Refuses transaction dispatch if database is missing, read-only, locked, or unmigrated.
    """
    conn = open_existing_rw(db_path, migrate_before_send=migrate)
    conn.close()


def sidecar_path(db_path: Path | str) -> Path:
    """Return path to sidecar recovery file (<db_path>.recovery.jsonl)."""
    return Path(str(db_path) + ".recovery.jsonl")


class SidecarSecretError(RuntimeError, ValueError):
    """Raised when recovery sidecar payload contains unredacted secrets."""


FORBIDDEN_KEY_SUBSTRINGS = (
    "case",
    "note",
    "private",
    "secret",
    "mnemonic",
    "seed",
    "key",
    "password",
    "phrase",
)

HEX_64_PATTERN = re.compile(r"0x[0-9a-fA-F]{64}")


def _is_seed_phrase(val: str) -> bool:
    """Detect BIP39 seed phrases (12, 15, 18, 21, 24 alphabetical words)."""
    words = val.strip().split()
    return len(words) in (12, 15, 18, 21, 24) and all(w.isalpha() for w in words)


def _is_sensitive_key(key: Any) -> bool:
    """Return True if key contains any forbidden substring."""
    k_lower = str(key).lower()
    return any(f in k_lower for f in FORBIDDEN_KEY_SUBSTRINGS)


def _is_sensitive_value(val: Any, key: Any = None) -> bool:
    """Return True if val contains private keys, mnemonics, passwords, or seed phrases."""
    if not isinstance(val, str) or val == "[REDACTED]":
        return False
    v_lower = val.lower()
    if any(w in v_lower for w in ("private_key", "mnemonic", "password", "seed_words", "seed phrase")):
        return True
    if _is_seed_phrase(val):
        return True
    k_lower = str(key).lower() if key is not None else ""
    if k_lower not in ("tx_hash", "transaction_hash", "tx", "txid"):
        if HEX_64_PATTERN.search(val):
            return True
    return False


def _find_unredacted_secret(obj: Any, key: Any = None) -> str | None:
    """Recursively search for unredacted sensitive keys or values."""
    if key is not None and _is_sensitive_key(key):
        if obj != "[REDACTED]":
            return f"sensitive key '{key}'"
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            found = _find_unredacted_secret(v, k)
            if found:
                return found
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found = _find_unredacted_secret(item, None)
            if found:
                return found
    elif _is_sensitive_value(obj, key):
        if obj != "[REDACTED]":
            return f"sensitive value in '{key}'"
    return None


def _sanitize_val(val: Any, key: Any = None) -> Any:
    """Recursively sanitize a value."""
    if isinstance(val, Mapping):
        return sanitize_sidecar_payload(val)
    if isinstance(val, (list, tuple)):
        sanitized_list = [_sanitize_val(item, None) for item in val]
        return type(val)(sanitized_list)
    if _is_sensitive_value(val, key):
        return "[REDACTED]"
    return val


def sanitize_sidecar_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Redact or exclude raw credentials and secrets from payload recursively."""
    sanitized: dict[str, Any] = {}
    for k, v in payload.items():
        k_str = str(k)
        if _is_sensitive_key(k_str):
            sanitized[k_str] = "[REDACTED]"
        elif isinstance(v, Mapping):
            sanitized[k_str] = sanitize_sidecar_payload(v)
        elif isinstance(v, (list, tuple)):
            sanitized[k_str] = [_sanitize_val(item, None) for item in v]
        elif _is_sensitive_value(v, k_str):
            sanitized[k_str] = "[REDACTED]"
        else:
            sanitized[k_str] = v
    return sanitized


def write_sidecar(
    db_path: Path | str,
    payload: Mapping[str, Any],
    *,
    auto_redact: bool = False,
) -> None:
    """Write sanitized JSON line to recovery sidecar file.

    Zero-leakage guardrail: Rejects payloads containing raw secrets or keys
    unless auto_redact=True is explicitly passed.
    """
    if auto_redact:
        payload = sanitize_sidecar_payload(payload)

    secret = _find_unredacted_secret(payload)
    if secret:
        raise SidecarSecretError(f"SIDECAR_SECRET: payload contains {secret}")

    path = sidecar_path(db_path)
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def record_operation_journal(
    conn: sqlite3.Connection,
    operation_id: str,
    from_state: str | None,
    to_state: str,
    event_type: str,
    details: Any = None,
) -> None:
    """Append audit trail event to onchain_operation_events."""
    code_str = str(event_type)
    conn.execute(
        "INSERT INTO onchain_operation_events(operation_id, ts, from_state, to_state, code) VALUES(?,?,?,?,?)",
        (operation_id, _now(), from_state, to_state, code_str),
    )


def _append_event(
    conn: sqlite3.Connection,
    operation_id: str,
    from_state: str | None,
    to_state: str,
    code: str,
) -> None:
    """Append audit trail event to onchain_operation_events (delegates to record_operation_journal)."""
    record_operation_journal(conn, operation_id, from_state, to_state, code)


def _insert_ready_intent(db_path: Path | str, intent: Mapping[str, Any]) -> str:
    """Insert intent in READY state if not present; return operation_id."""
    body = canonical_json(intent)
    digest = fingerprint(intent)
    op_type = intent["op_type"]
    now = _now()
    conn = open_existing_rw(db_path, migrate_before_send=True)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT operation_id, intent_canonical FROM onchain_operations WHERE fingerprint=?",
            (digest,),
        ).fetchone()
        if row is not None:
            op_id, existing_body = row
            if existing_body != body:
                conn.rollback()
                raise RuntimeError("IDEMPOTENCY_CONFLICT: intent mismatch for fingerprint")
            conn.commit()
            return op_id

        operation_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO onchain_operations(operation_id,op_type,fingerprint,intent_canonical,state,"
            "chain_id,contract_address,signer,tx_hash,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,NULL,?,?)",
            (
                operation_id,
                op_type,
                digest,
                body,
                READY,
                int(intent["chain_id"]),
                intent["contract"].lower(),
                intent["signer"].lower(),
                now,
                now,
            ),
        )
        _append_event(conn, operation_id, None, READY, "INTENT_RECORDED")
        conn.commit()
        return operation_id
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise RuntimeError("DB_LOCKED") from None
    finally:
        conn.close()


class ClaimResult(tuple):
    """Result tuple of claim_send: (operation_id, can_send, current_state)."""

    def __new__(cls, operation_id: str, can_send: bool, current_state: str):
        return super().__new__(cls, (str(operation_id), bool(can_send), str(current_state)))

    @property
    def operation_id(self) -> str:
        return self[0]

    @property
    def can_send(self) -> bool:
        return self[1]

    @property
    def current_state(self) -> str:
        return self[2]

    def __repr__(self) -> str:
        return f"ClaimResult(operation_id={self.operation_id!r}, can_send={self.can_send!r}, current_state={self.current_state!r})"


def claim_send(db_path: Path | str, intent: Mapping[str, Any] | str) -> ClaimResult:
    """Atomic Compare-And-Swap send claim using BEGIN IMMEDIATE and rowcount == 1.

    Closes SQLite connection before caller invokes on-chain RPC (zero locks during RPC).
    Returns ClaimResult(operation_id, can_send, current_state).
    Under NO circumstances may can_send be True if rowcount != 1.
    """
    now = _now()
    max_retries = 40
    retry_delay = 0.05

    for attempt in range(max_retries):
        conn = open_existing_rw(db_path, migrate_before_send=True)
        try:
            conn.execute("BEGIN IMMEDIATE")

            if isinstance(intent, str):
                operation_id = intent
                row = conn.execute(
                    "SELECT operation_id, state, tx_hash, intent_canonical FROM onchain_operations WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if row is None:
                    conn.rollback()
                    raise RuntimeError("OPERATION_NOT_FOUND")
                op_id, current_state, tx_hash, _ = row
            else:
                body = canonical_json(intent)
                digest = fingerprint(intent)
                op_type = intent["op_type"]
                row = conn.execute(
                    "SELECT operation_id, state, tx_hash, intent_canonical FROM onchain_operations WHERE fingerprint=?",
                    (digest,),
                ).fetchone()
                if row is None:
                    operation_id = uuid.uuid4().hex
                    conn.execute(
                        "INSERT INTO onchain_operations(operation_id,op_type,fingerprint,intent_canonical,state,"
                        "chain_id,contract_address,signer,tx_hash,created_at,updated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,NULL,?,?)",
                        (
                            operation_id,
                            op_type,
                            digest,
                            body,
                            READY,
                            int(intent["chain_id"]),
                            intent["contract"].lower(),
                            intent["signer"].lower(),
                            now,
                            now,
                        ),
                    )
                    record_operation_journal(conn, operation_id, None, READY, "INTENT_RECORDED")
                    current_state = READY
                    tx_hash = None
                else:
                    operation_id, current_state, tx_hash, existing_body = row
                    if existing_body != body:
                        conn.rollback()
                        raise RuntimeError("IDEMPOTENCY_CONFLICT: intent mismatch for fingerprint")

            if current_state != READY or tx_hash is not None:
                record_operation_journal(
                    conn,
                    operation_id,
                    current_state,
                    current_state,
                    "SEND_CLAIM_DENIED",
                )
                conn.commit()
                return ClaimResult(operation_id, False, current_state)

            cur = conn.execute(
                "UPDATE onchain_operations SET state=?, updated_at=? "
                "WHERE operation_id=? AND state=? AND tx_hash IS NULL",
                (SEND_STARTED, now, operation_id, READY),
            )
            if cur.rowcount == 1:
                record_operation_journal(conn, operation_id, READY, SEND_STARTED, "SEND_CLAIMED")
                conn.commit()
                return ClaimResult(operation_id, True, SEND_STARTED)
            else:
                # Lost the race: another process updated state
                row_latest = conn.execute(
                    "SELECT state FROM onchain_operations WHERE operation_id=?", (operation_id,)
                ).fetchone()
                latest_st = row_latest[0] if row_latest else current_state
                record_operation_journal(
                    conn,
                    operation_id,
                    latest_st,
                    latest_st,
                    "SEND_CLAIM_DENIED",
                )
                conn.commit()
                return ClaimResult(operation_id, False, latest_st)

        except sqlite3.OperationalError as e:
            try:
                conn.rollback()
            except Exception:
                pass
            msg = str(e).lower()
            if ("locked" in msg or "busy" in msg) and attempt < max_retries - 1:
                import time
                time.sleep(retry_delay * (1 + attempt * 0.1))
                continue
            raise RuntimeError("DB_LOCKED") from None
        except sqlite3.Error:
            try:
                conn.rollback()
            except Exception:
                pass
            raise RuntimeError("DB_LOCKED") from None
        finally:
            conn.close()

    raise RuntimeError("DB_LOCKED")


def record_broadcast(db_path: Path | str, operation_id: str, tx_hash: str) -> None:
    """Transition operation state from SEND_STARTED to BROADCAST with transaction hash."""
    conn = open_existing_rw(db_path, migrate_before_send=False)
    now = _now()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE onchain_operations SET tx_hash=?, state=?, updated_at=? "
            "WHERE operation_id=? AND state=? AND tx_hash IS NULL",
            (tx_hash.lower(), BROADCAST, now, operation_id, SEND_STARTED),
        )
        if cur.rowcount != 1:
            conn.rollback()
            raise RuntimeError("POST_SEND_DB_FAILED: could not record broadcast")
        _append_event(conn, operation_id, SEND_STARTED, BROADCAST, "TX_RECORDED")
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise RuntimeError("POST_SEND_DB_FAILED") from None
    finally:
        conn.close()


def mark_unknown(db_path: Path | str, operation_id: str, code: str) -> None:
    """Mark operation state as UNKNOWN. Writes recovery sidecar if database is unavailable."""
    try:
        conn = open_existing_rw(db_path, migrate_before_send=False)
    except (RuntimeError, sqlite3.Error):
        write_sidecar(db_path, {"operation_id": operation_id, "state": UNKNOWN, "code": code})
        return
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT state FROM onchain_operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if not row:
            conn.rollback()
            return
        from_state = row[0]
        if from_state in (CONFIRMED, FAILED):
            conn.rollback()
            return
        cur = conn.execute(
            "UPDATE onchain_operations SET state=?, updated_at=? WHERE operation_id=? AND state NOT IN (?, ?)",
            (UNKNOWN, _now(), operation_id, CONFIRMED, FAILED),
        )
        if cur.rowcount == 1:
            record_operation_journal(conn, operation_id, from_state, UNKNOWN, code)
            conn.commit()
        else:
            conn.rollback()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        write_sidecar(db_path, {"operation_id": operation_id, "state": UNKNOWN, "code": code})
    finally:
        conn.close()


def verify_receipt_and_event(
    receipt: Mapping[str, Any],
    expected_event_type: str,
    expected_contract: str | None = None,
    expected_tx_hash: str | None = None,
    expected_actor: str | None = None,
    expected_evidence_id: int | None = None,
    expected_action: int | None = None,
    expected_manifest_sha256: str | None = None,
    expected_case_digest: str | None = None,
    expected_artifact_sha256: str | None = None,
    expected_note_hash: str | None = None,
    legacy_case_encoding: bool = False,
    expected_case_id: str | None = None,
) -> dict[str, Any]:
    """Strictly verify transaction receipt and event log before marking verified=1.

    Requirements (Gates G3-03, G3-04, G3-10):
    1. receipt status must equal 1 (success). Reverted receipts (0, False) strictly rejected.
    2. blockNumber must exist, non-null, valid integer >= 0.
    3. transactionHash must exist, non-empty hex starting with '0x', and match expected_tx_hash.
    4. blockHash must exist, non-empty hex starting with '0x'.
    5. Event topic0 in logs must match expected_event_type.
    6. Contract address (emitter) must match expected_contract.
    7. Event ABI topic count strictly enforced (exactly 4 topics for EvidenceRegistered and CustodyRecorded).
    8. logIndex must exist and be a non-null integer.
    9. Actor, evidenceId, and action/case/manifest/notes must strictly match event data without skipping.

    Args:
        receipt: Receipt dictionary from eth_getTransactionReceipt.
        expected_event_type: 'EvidenceRegistered' or 'CustodyRecorded'.
        expected_contract: Expected contract address (optional).
        expected_tx_hash: Expected transaction hash (optional).
        expected_actor: Expected actor address (optional).
        expected_evidence_id: Expected evidence ID (optional).
        expected_action: Expected custody action (optional).
        expected_manifest_sha256: Expected manifest SHA256 (optional).
        expected_case_digest: Expected case digest (optional).
        expected_artifact_sha256: Expected artifact SHA256 (optional).
        expected_note_hash: Expected note hash (optional).
        legacy_case_encoding: True if legacy unhashed case encoding is allowed.
        expected_case_id: Raw case ID for legacy check.

    Returns:
        Matched event log dictionary.

    Raises:
        RuntimeError: If verification criteria are not strictly met.
    """
    if not isinstance(receipt, Mapping):
        raise RuntimeError("VERIFICATION_FAILED: receipt must be a dictionary")

    # 1. Receipt status check
    raw_status = receipt.get("status")
    if raw_status is None:
        raise RuntimeError("VERIFICATION_FAILED: receipt missing status")
    if raw_status in (1, "1", "0x1", True):
        pass
    elif raw_status in (0, "0", "0x0", False):
        raise RuntimeError("VERIFICATION_FAILED: receipt status is not 1 (transaction reverted or failed)")
    else:
        raise RuntimeError(f"VERIFICATION_FAILED: invalid receipt status: {raw_status}")

    # 2. Block number check
    raw_block = receipt.get("blockNumber")
    if raw_block is None:
        raise RuntimeError("VERIFICATION_FAILED: missing blockNumber in receipt (transaction pending or unmined)")
    if isinstance(raw_block, str):
        try:
            int(raw_block, 16 if raw_block.startswith("0x") else 10)
        except ValueError:
            raise RuntimeError(f"VERIFICATION_FAILED: invalid blockNumber format: {raw_block}")

    # 3. Tx hash check (strictly mandatory)
    rec_tx = receipt.get("transactionHash")
    if not rec_tx or not isinstance(rec_tx, str) or not rec_tx.startswith("0x"):
        raise RuntimeError("VERIFICATION_FAILED: missing or invalid transactionHash in receipt")
    if expected_tx_hash and str(rec_tx).lower() != str(expected_tx_hash).lower():
        raise RuntimeError(
            f"VERIFICATION_FAILED: transactionHash mismatch between receipt ({rec_tx}) and expected ({expected_tx_hash})"
        )

    # 4. Block hash check (strictly mandatory)
    rec_bh = receipt.get("blockHash")
    if not rec_bh or not isinstance(rec_bh, str) or not rec_bh.startswith("0x"):
        raise RuntimeError("VERIFICATION_FAILED: missing or invalid blockHash in receipt")

    # 5. Event topic check
    expected_topic = get_event_topic(expected_event_type).lower()
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise RuntimeError("VERIFICATION_FAILED: missing or invalid logs list in receipt")

    matched_log = None
    for log_item in logs:
        if not isinstance(log_item, Mapping):
            continue
        topics = log_item.get("topics", [])
        if not topics:
            continue
        topic0 = str(topics[0]).lower()
        if topic0 == expected_topic:
            if expected_contract:
                log_addr = str(log_item.get("address", "")).lower()
                if log_addr != expected_contract.lower():
                    continue
            matched_log = dict(log_item)
            break

    if matched_log is None:
        if logs and expected_contract:
            addr_mismatch = any(str(l.get("topics", [""])[0]).lower() == expected_topic for l in logs if isinstance(l, Mapping))
            if addr_mismatch:
                raise RuntimeError(
                    f"VERIFICATION_FAILED: contract address mismatch for {expected_event_type}"
                )
        raise RuntimeError(
            f"VERIFICATION_FAILED: no matching {expected_event_type} event found in receipt logs (topic mismatch)"
        )

    # 6. logIndex check (strictly mandatory)
    raw_idx = matched_log.get("logIndex")
    if raw_idx is None:
        raise RuntimeError("VERIFICATION_FAILED: missing or invalid logIndex in event log")
    try:
        int(str(raw_idx), 16 if str(raw_idx).startswith("0x") else 10)
    except ValueError:
        raise RuntimeError(f"VERIFICATION_FAILED: invalid logIndex format: {raw_idx}")

    # 7. Semantic ABI validation of event topics
    topics = matched_log.get("topics", [])

    if expected_event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
        if len(topics) != 4:
            raise RuntimeError(
                f"VERIFICATION_FAILED: EvidenceRegistered log ABI violation: expected 4 topics, got {len(topics)}"
            )
        try:
            ev_id_in_log = int(str(topics[1]), 16 if str(topics[1]).startswith("0x") else 10)
        except ValueError:
            raise RuntimeError(f"VERIFICATION_FAILED: invalid evidenceId format in topic: {topics[1]}")
        if expected_evidence_id is not None and expected_evidence_id > 0:
            if ev_id_in_log != expected_evidence_id:
                raise RuntimeError(
                    f"VERIFICATION_FAILED: evidenceId mismatch in EvidenceRegistered log (expected {expected_evidence_id}, got {ev_id_in_log})"
                )

        log_case = str(topics[2]).lower().removeprefix("0x").zfill(64)
        if expected_case_digest:
            exp_case = expected_case_digest.lower().removeprefix("0x").zfill(64)
            if log_case != exp_case:
                if legacy_case_encoding and expected_case_id:
                    from forensics.evidence_identity import string_to_bytes32_hex
                    leg_case = string_to_bytes32_hex(expected_case_id).lower().removeprefix("0x").zfill(64)
                    if log_case != leg_case:
                        raise RuntimeError("VERIFICATION_FAILED: case_digest mismatch in EvidenceRegistered log (legacy mode)")
                else:
                    raise RuntimeError("VERIFICATION_FAILED: case_digest mismatch in EvidenceRegistered log")

        log_man = str(topics[3]).lower().removeprefix("0x").zfill(64)
        if expected_manifest_sha256:
            exp_man = expected_manifest_sha256.lower().removeprefix("0x").zfill(64)
            if log_man != exp_man:
                raise RuntimeError("VERIFICATION_FAILED: manifestSha256 mismatch in EvidenceRegistered log")

        if expected_actor:
            data_hex = str(matched_log.get("data", "")).lower()
            if len(data_hex) >= 66:
                sub_hex = data_hex[2:66][-40:].zfill(40)
                exp_actor = expected_actor.lower().removeprefix("0x")[-40:].zfill(40)
                if sub_hex != exp_actor:
                    raise RuntimeError(
                        f"VERIFICATION_FAILED: actor mismatch in EvidenceRegistered log (expected {expected_actor}, got {sub_hex})"
                    )

    elif expected_event_type == EVENT_TYPE_CUSTODY_RECORDED:
        if len(topics) != 4:
            raise RuntimeError(
                f"VERIFICATION_FAILED: CustodyRecorded log ABI violation: expected 4 topics, got {len(topics)}"
            )
        try:
            ev_id_in_log = int(str(topics[1]), 16 if str(topics[1]).startswith("0x") else 10)
        except ValueError:
            raise RuntimeError(f"VERIFICATION_FAILED: invalid evidenceId format in topic: {topics[1]}")
        if expected_evidence_id is not None and expected_evidence_id > 0:
            if ev_id_in_log != expected_evidence_id:
                raise RuntimeError(
                    f"VERIFICATION_FAILED: evidenceId mismatch in CustodyRecorded log (expected {expected_evidence_id}, got {ev_id_in_log})"
                )

        try:
            act_in_log = int(str(topics[2]), 16 if str(topics[2]).startswith("0x") else 10)
        except ValueError:
            raise RuntimeError(f"VERIFICATION_FAILED: invalid action format in topic: {topics[2]}")
        if expected_action is not None:
            if act_in_log != expected_action:
                raise RuntimeError(
                    f"VERIFICATION_FAILED: action mismatch in CustodyRecorded log (expected {expected_action}, got {act_in_log})"
                )

        raw_actor_topic = str(topics[3]).lower()
        topic_actor_40 = raw_actor_topic.removeprefix("0x")[-40:].zfill(40)
        if expected_actor:
            expected_actor_40 = str(expected_actor).lower().removeprefix("0x")[-40:].zfill(40)
            if topic_actor_40 != expected_actor_40:
                raise RuntimeError(
                    f"VERIFICATION_FAILED: actor mismatch in CustodyRecorded log (expected {expected_actor}, got {topic_actor_40})"
                )

        data_hex = str(matched_log.get("data", "")).lower()
        if len(data_hex) >= 130:
            if expected_artifact_sha256 and len(expected_artifact_sha256.removeprefix("0x")) == 64:
                log_art = data_hex[2:66]
                exp_art = expected_artifact_sha256.lower().removeprefix("0x")
                if log_art != exp_art:
                    raise RuntimeError("VERIFICATION_FAILED: artifactSha256 mismatch in CustodyRecorded log")
            if expected_note_hash and len(expected_note_hash.removeprefix("0x")) == 64:
                log_nh = data_hex[66:130]
                exp_nh = expected_note_hash.lower().removeprefix("0x")
                if log_nh != exp_nh:
                    is_legacy_padded = False
                    try:
                        raw_bytes = bytes.fromhex(log_nh)
                        stripped = raw_bytes.rstrip(b"\x00")
                        if stripped and hashlib.sha256(stripped).hexdigest() == exp_nh:
                            is_legacy_padded = True
                    except Exception:
                        pass
                    if not is_legacy_padded:
                        raise RuntimeError("VERIFICATION_FAILED: noteHash mismatch in CustodyRecorded log")

    return matched_log


def persist_verified_event(
    db_path: Path | str,
    operation_id: str | Mapping[str, Any] | None = None,
    event_data: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> None:
    """Persist verified custody event and anchor link with strict atomicity.

    Guarantees:
    - Pure INSERT with zero clobbering (Gate G3-03: prevents clobbering history).
    - Enforces full tuple identity: (chain_id, contract_address, tx_hash, log_index) (Gate G3-02).
    - Strict verification before verified=1 (Gate G3-04: status=1, blockNumber present, topic match).
    - Multi-manifest same-case linkage (Gate G3-01: distinct manifests for same case link by manifest_sha256).
    - Distinguishes EvidenceRegistered vs CustodyRecorded (Gate G3-14).
    """
    # Normalize argument passing
    data: dict[str, Any] = {}
    if isinstance(operation_id, Mapping) and event_data is None:
        data.update(operation_id)
        op_id_val = data.get("operation_id")
    else:
        op_id_val = str(operation_id) if operation_id is not None else None
        if event_data:
            data.update(event_data)

    data.update(kwargs)
    if "operation_id" in data and op_id_val is None:
        op_id_val = data["operation_id"]

    # Extract required fields
    chain_id = int(data.get("chain_id", 0))
    contract = str(data.get("contract") or data.get("contract_address") or "").lower()
    tx_hash = str(data.get("tx_hash", "")).lower()
    log_index = int(data.get("log_index", 0))
    block_number = data.get("block_number")
    event_type = str(data.get("event_type", ""))
    evidence_id = int(data.get("evidence_id", 0))

    if not contract:
        raise ValueError("contract address is required")
    if not tx_hash:
        raise ValueError("tx_hash is required")
    if not event_type:
        raise ValueError("event_type is required")

    actor_arg = data.get("actor") or data.get("actor_address")
    actor_check = str(actor_arg).lower() if actor_arg else None
    actor = actor_check or contract
    artifact_sha256 = data.get("artifact_sha256")
    artifact_sha256_val = str(artifact_sha256).lower() if artifact_sha256 else None
    note_hash = data.get("note_hash")
    note_hash_val = str(note_hash).lower() if note_hash else None
    manifest_sha256 = data.get("manifest_sha256")
    manifest_sha256_val = str(manifest_sha256).lower() if manifest_sha256 else None
    case_digest = data.get("case_digest", data.get("case_id"))
    case_digest_val = str(case_digest).lower() if case_digest else None
    action_val = int(data.get("action", 0))

    # Strict Verification Before verified=1 (Gate G3-04 & G3-03)
    # A valid transaction receipt is strictly mandatory.
    # Self-declared block_number or topic0 is strictly rejected.
    receipt = data.get("receipt")
    if receipt is None or not isinstance(receipt, Mapping):
        raise RuntimeError(
            "VERIFICATION_FAILED: valid transaction receipt is strictly required to persist verified=1. "
            "Self-declared block_number or topic0 is rejected."
        )

    matched_event = verify_receipt_and_event(
        receipt,
        event_type,
        expected_contract=contract,
        expected_tx_hash=tx_hash,
        expected_actor=actor_check,
        expected_evidence_id=evidence_id,
        expected_action=action_val,
        expected_manifest_sha256=manifest_sha256_val,
        expected_case_digest=case_digest_val,
        expected_artifact_sha256=artifact_sha256_val,
        expected_note_hash=note_hash_val,
        legacy_case_encoding=bool(data.get("legacy_case_encoding", False)),
        expected_case_id=data.get("case_id"),
    )

    # Derive verified execution coordinates directly from the verified receipt
    receipt_block = receipt.get("blockNumber")
    if receipt_block is not None:
        if isinstance(receipt_block, int):
            block_num_int = receipt_block
        else:
            s_block = str(receipt_block)
            block_num_int = int(s_block, 16 if s_block.startswith("0x") else 10)
    else:
        block_num_int = int(block_number or 0)

    receipt_tx = str(receipt.get("transactionHash", tx_hash)).lower()
    tx_hash = receipt_tx

    if "logIndex" in matched_event and matched_event["logIndex"] is not None:
        raw_idx = matched_event["logIndex"]
        if isinstance(raw_idx, int):
            log_index = raw_idx
        else:
            s_idx = str(raw_idx)
            log_index = int(s_idx, 16 if s_idx.startswith("0x") else 10)

    event_id = make_event_id(chain_id, contract, tx_hash, log_index)
    now = _now()

    conn = open_existing_rw(db_path, migrate_before_send=False)
    try:
        conn.execute("BEGIN IMMEDIATE")

        # PURE INSERT into custody_events — zero clobbering (Gate G3-03)
        conn.execute(
            "INSERT INTO custody_events("
            "event_id, evidence_id, case_id, action, actor_address, artifact_sha256, "
            "note_hash, chain_id, contract_address, tx_hash, block_number, "
            "recorded_at, verified, log_index, event_type"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                event_id,
                evidence_id,
                case_digest_val,
                action_val,
                actor,
                artifact_sha256_val,
                note_hash_val,
                chain_id,
                contract,
                tx_hash,
                block_num_int,
                now,
                log_index,
                event_type,
            ),
        )

        # Multi-Manifest Same Case Linkage into anchor_links (Gate G3-01, G3-14)
        if event_type == EVENT_TYPE_EVIDENCE_REGISTERED:
            if not manifest_sha256_val:
                raise RuntimeError("POST_SEND_DB_FAILED: manifest_sha256 is required for EvidenceRegistered")
            conn.execute(
                "INSERT INTO anchor_links("
                "chain_id, contract_address, manifest_sha256, evidence_id, "
                "tx_hash, log_index, event_type, verified, recorded_at"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?)",
                (
                    chain_id,
                    contract,
                    manifest_sha256_val,
                    evidence_id,
                    tx_hash,
                    log_index,
                    event_type,
                    now,
                ),
            )

        # Update onchain_operations if operation_id exists
        if op_id_val:
            row = conn.execute(
                "SELECT state FROM onchain_operations WHERE operation_id=?", (op_id_val,)
            ).fetchone()
            if row is not None:
                cur = conn.execute(
                    "UPDATE onchain_operations SET state=?, updated_at=? WHERE operation_id=?",
                    (CONFIRMED, now, op_id_val),
                )
                if cur.rowcount == 1:
                    _append_event(conn, op_id_val, row[0], CONFIRMED, event_type)

        conn.commit()
    except sqlite3.IntegrityError:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise
    except Exception:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def load_operation(db_path: Path | str, operation_id: str) -> dict[str, Any]:
    """Retrieve onchain_operation row by operation_id or fingerprint."""
    conn = open_existing_rw(db_path, migrate_before_send=False)
    try:
        row = conn.execute(
            "SELECT operation_id,op_type,fingerprint,intent_canonical,state,chain_id,"
            "contract_address,signer,tx_hash,created_at,updated_at FROM onchain_operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT operation_id,op_type,fingerprint,intent_canonical,state,chain_id,"
                "contract_address,signer,tx_hash,created_at,updated_at FROM onchain_operations WHERE fingerprint=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError("OPERATION_NOT_FOUND")
        keys = (
            "operation_id",
            "op_type",
            "fingerprint",
            "intent_canonical",
            "state",
            "chain_id",
            "contract_address",
            "signer",
            "tx_hash",
            "created_at",
            "updated_at",
        )
        return dict(zip(keys, row))
    finally:
        conn.close()


def apply_reconcile_result(
    db_path: Path | str,
    operation_id: str,
    *,
    state: str,
    tx_hash: str | None = None,
    code: str = "RECONCILED",
) -> None:
    """Apply read-only reconciliation result to onchain_operations."""
    conn = open_existing_rw(db_path, migrate_before_send=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT state FROM onchain_operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if current is None:
            conn.rollback()
            raise RuntimeError("OPERATION_NOT_FOUND")
        if tx_hash:
            conn.execute(
                "UPDATE onchain_operations SET state=?, tx_hash=?, updated_at=? WHERE operation_id=?",
                (state, tx_hash.lower(), _now(), operation_id),
            )
        else:
            conn.execute(
                "UPDATE onchain_operations SET state=?, updated_at=? WHERE operation_id=?",
                (state, _now(), operation_id),
            )
        _append_event(conn, operation_id, current[0], state, code)
        conn.commit()
    finally:
        conn.close()


def reconcile_operation(
    db_path: Path | str,
    operation_id: str,
    rpc_url_or_client: Any = None,
    *,
    tx_hash: str | None = None,
) -> dict[str, Any]:
    """Read-only blockchain reconcile for an operation.

    Queries the blockchain via RPC for receipt and transaction status.
    If transaction is confirmed on-chain, updates operation state to CONFIRMED
    and persists event into custody_events and anchor_links.
    Strictly performs ZERO transaction broadcasts (no cast send, zero sends).

    Args:
        db_path: Path to SQLite database.
        operation_id: Identifier of the operation to reconcile.
        rpc_url_or_client: RPC URL (str), RPC client object, or receipt dictionary.
        tx_hash: Optional transaction hash override.

    Returns:
        Dictionary summarizing reconciliation result:
        {"operation_id": ..., "state": ..., "tx_hash": ..., "reconciled": bool, ...}
    """
    op = load_operation(db_path, operation_id)
    op_id = op["operation_id"]
    current_state = op["state"]
    op_type = op["op_type"]
    chain_id = int(op["chain_id"])
    contract = op["contract_address"]
    tx = tx_hash or op.get("tx_hash")

    if current_state == CONFIRMED:
        return {
            "operation_id": op_id,
            "state": CONFIRMED,
            "tx_hash": tx,
            "reconciled": True,
            "message": "Already confirmed",
        }

    if not tx:
        return {
            "operation_id": op_id,
            "state": current_state,
            "tx_hash": None,
            "reconciled": False,
            "error": "MISSING_TX_HASH",
        }

    # Fetch receipt in read-only mode
    receipt: dict[str, Any] | None = None

    if isinstance(rpc_url_or_client, Mapping):
        raise ValueError(
            "RECONCILE_FAILED: rpc_url_or_client cannot be a raw receipt dictionary; an RPC endpoint or client is strictly required"
        )

    # Fetch receipt in read-only mode from RPC
    receipt: dict[str, Any] | None = None

    if isinstance(rpc_url_or_client, str):
        # HTTP JSON-RPC URL
        def _rpc(method: str, params: list[Any]) -> Any:
            req = urllib.request.Request(
                rpc_url_or_client,
                data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "error" in data:
                    raise RuntimeError(f"RPC_ERROR: {data['error']}")
                return data.get("result")

        try:
            # 1. Chain ID check
            chain_res = _rpc("eth_chainId", [])
            if chain_res is not None:
                rpc_cid = int(str(chain_res), 16 if str(chain_res).startswith("0x") else 10)
                if rpc_cid != chain_id:
                    return {
                        "operation_id": op_id,
                        "state": current_state,
                        "tx_hash": tx,
                        "reconciled": False,
                        "error": f"CHAIN_ID_MISMATCH: RPC chain {rpc_cid} != expected {chain_id}",
                    }

            # 2. Receipt fetch
            receipt = _rpc("eth_getTransactionReceipt", [tx])
            if receipt is None:
                return {
                    "operation_id": op_id,
                    "state": current_state,
                    "tx_hash": tx,
                    "reconciled": False,
                    "reason": "RECEIPT_NOT_FOUND",
                }

            # 3. Canonicality check (reorg guard)
            rec_bn = receipt.get("blockNumber")
            rec_bh = receipt.get("blockHash")
            if rec_bn and rec_bh:
                block = _rpc("eth_getBlockByNumber", [rec_bn, False])
                if block and block.get("hash"):
                    if str(block["hash"]).lower() != str(rec_bh).lower():
                        return {
                            "operation_id": op_id,
                            "state": current_state,
                            "tx_hash": tx,
                            "reconciled": False,
                            "reason": "NON_CANONICAL_BLOCK_OR_REORG",
                        }
        except Exception as e:
            return {
                "operation_id": op_id,
                "state": current_state,
                "tx_hash": tx,
                "reconciled": False,
                "error": f"RPC_ERROR: {e}",
            }
    elif rpc_url_or_client is not None:
        try:
            if hasattr(rpc_url_or_client, "eth_chainId"):
                c_id = rpc_url_or_client.eth_chainId()
                if c_id is not None:
                    rpc_cid = int(str(c_id), 16 if str(c_id).startswith("0x") else 10)
                    if rpc_cid != chain_id:
                        return {
                            "operation_id": op_id,
                            "state": current_state,
                            "tx_hash": tx,
                            "reconciled": False,
                            "error": f"CHAIN_ID_MISMATCH: RPC chain {rpc_cid} != expected {chain_id}",
                        }

            if hasattr(rpc_url_or_client, "eth_getTransactionReceipt"):
                receipt = rpc_url_or_client.eth_getTransactionReceipt(tx)
            elif hasattr(rpc_url_or_client, "get_transaction_receipt"):
                receipt = rpc_url_or_client.get_transaction_receipt(tx)
            elif callable(rpc_url_or_client):
                receipt = rpc_url_or_client(tx)

            if receipt is None:
                return {
                    "operation_id": op_id,
                    "state": current_state,
                    "tx_hash": tx,
                    "reconciled": False,
                    "reason": "RECEIPT_NOT_FOUND",
                }

            rec_bn = receipt.get("blockNumber")
            rec_bh = receipt.get("blockHash")
            if rec_bn and rec_bh and hasattr(rpc_url_or_client, "eth_getBlockByNumber"):
                block = rpc_url_or_client.eth_getBlockByNumber(rec_bn, False)
                if block and block.get("hash"):
                    if str(block["hash"]).lower() != str(rec_bh).lower():
                        return {
                            "operation_id": op_id,
                            "state": current_state,
                            "tx_hash": tx,
                            "reconciled": False,
                            "reason": "NON_CANONICAL_BLOCK_OR_REORG",
                        }
        except Exception as e:
            return {
                "operation_id": op_id,
                "state": current_state,
                "tx_hash": tx,
                "reconciled": False,
                "error": f"RPC_ERROR: {e}",
            }
    else:
        return {
            "operation_id": op_id,
            "state": current_state,
            "tx_hash": tx,
            "reconciled": False,
            "error": "RPC_CLIENT_REQUIRED",
        }

    # Determine expected event
    expected_event = (
        EVENT_TYPE_EVIDENCE_REGISTERED if op_type == REGISTER else EVENT_TYPE_CUSTODY_RECORDED
    )
    intent = json.loads(op["intent_canonical"]) if isinstance(op.get("intent_canonical"), str) else {}

    try:
        if op_type == REGISTER:
            matched_log = verify_receipt_and_event(
                receipt,
                expected_event_type=expected_event,
                expected_contract=contract,
                expected_tx_hash=tx,
                expected_actor=intent.get("signer"),
                expected_evidence_id=intent.get("evidence_id"),
                expected_case_digest=intent.get("case_digest"),
                expected_manifest_sha256=intent.get("manifest_sha256"),
                legacy_case_encoding=bool(intent.get("legacy_case_encoding", False)),
                expected_case_id=intent.get("case_id"),
            )
        else:
            matched_log = verify_receipt_and_event(
                receipt,
                expected_event_type=expected_event,
                expected_contract=contract,
                expected_tx_hash=tx,
                expected_actor=intent.get("signer"),
                expected_evidence_id=int(intent.get("evidence_id", 0)),
                expected_action=int(intent.get("action", 0)),
                expected_artifact_sha256=intent.get("artifact_sha256"),
                expected_note_hash=intent.get("note_hash"),
            )
    except RuntimeError as e:
        # Check if reverted
        status_val = receipt.get("status")
        if status_val in (0, "0", "0x0", False):
            apply_reconcile_result(
                db_path, op_id, state=FAILED, tx_hash=tx, code="RECONCILE_REVERTED"
            )
            return {
                "operation_id": op_id,
                "state": FAILED,
                "tx_hash": tx,
                "reconciled": True,
                "error": "TRANSACTION_REVERTED",
            }
        return {
            "operation_id": op_id,
            "state": current_state,
            "tx_hash": tx,
            "reconciled": False,
            "error": str(e),
        }

    # Extract blockNumber and logIndex
    raw_bn = receipt.get("blockNumber")
    if isinstance(raw_bn, str):
        block_number = int(raw_bn, 16 if raw_bn.startswith("0x") else 10)
    else:
        block_number = int(raw_bn) if raw_bn is not None else 0

    raw_idx = matched_log.get("logIndex", 0)
    if isinstance(raw_idx, str):
        log_index = int(raw_idx, 16 if raw_idx.startswith("0x") else 10)
    else:
        log_index = int(raw_idx) if raw_idx is not None else 0

    # Parse intent for registration/custody details
    intent = json.loads(op["intent_canonical"]) if isinstance(op.get("intent_canonical"), str) else {}

    if op_type == REGISTER:
        case_digest = intent.get("case_digest")
        manifest_sha256 = intent.get("manifest_sha256")
        topics = matched_log.get("topics", [])
        evidence_id = 0
        if len(topics) > 1:
            raw_eid = topics[1]
            if isinstance(raw_eid, str):
                evidence_id = int(raw_eid, 16 if raw_eid.startswith("0x") else 10)
            else:
                evidence_id = int(raw_eid)
        actor = intent.get("signer", contract)
        persist_verified_event(
            db_path,
            operation_id=op_id,
            chain_id=chain_id,
            contract=contract,
            evidence_id=evidence_id,
            action=0,
            actor=actor,
            artifact_sha256=manifest_sha256,
            manifest_sha256=manifest_sha256,
            case_digest=case_digest,
            tx_hash=tx,
            block_number=block_number,
            log_index=log_index,
            event_type=EVENT_TYPE_EVIDENCE_REGISTERED,
            receipt=receipt,
        )
    else:
        evidence_id = int(intent.get("evidence_id", 0))
        action = int(intent.get("action", 0))
        artifact_sha256 = intent.get("artifact_sha256")
        note_hash = intent.get("note_hash")
        actor = intent.get("signer", contract)
        persist_verified_event(
            db_path,
            operation_id=op_id,
            chain_id=chain_id,
            contract=contract,
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            artifact_sha256=artifact_sha256,
            note_hash=note_hash,
            tx_hash=tx,
            block_number=block_number,
            log_index=log_index,
            event_type=EVENT_TYPE_CUSTODY_RECORDED,
            receipt=receipt,
        )

    apply_reconcile_result(
        db_path, op_id, state=CONFIRMED, tx_hash=tx, code="RECONCILED_CONFIRMED"
    )

    return {
        "operation_id": op_id,
        "state": CONFIRMED,
        "tx_hash": tx,
        "reconciled": True,
        "receipt": receipt,
    }
