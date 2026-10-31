"""SQLite operation store for P3 Group 3: claim, persist, reconcile, recovery sidecar."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from forensics.schemas import group3_schema_present, migrate_group3


READY = "READY"
SEND_STARTED = "SEND_STARTED"
BROADCAST = "BROADCAST"
CONFIRMED = "CONFIRMED"
UNKNOWN = "UNKNOWN"
FAILED = "FAILED"

REGISTER = "REGISTER_EVIDENCE"
CUSTODY = "RECORD_CUSTODY"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(intent: dict) -> str:
    return json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(intent: dict) -> str:
    return hashlib.sha256(canonical_json(intent).encode("utf-8")).hexdigest()


def register_intent(chain_id, contract, manifest_sha256, case_digest, storage_uri, signer):
    return {
        "op_type": REGISTER,
        "chain_id": int(chain_id),
        "contract": contract.lower(),
        "manifest_sha256": manifest_sha256.lower(),
        "case_digest": case_digest.lower(),
        "storage_uri": storage_uri,
        "signer": signer.lower(),
    }


def custody_intent(chain_id, contract, evidence_id, action, artifact_sha256, note_hash, signer):
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


def open_existing_rw(db_path, *, migrate_before_send=False):
    path = Path(db_path)
    if not path.is_file():
        raise RuntimeError("DB_REQUIRED")
    if not os.access(path, os.W_OK):
        raise RuntimeError("DB_READONLY")
    try:
        conn = sqlite3.connect(path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)
    except sqlite3.Error:
        raise RuntimeError("DB_LOCKED") from None
    conn.isolation_level = None
    try:
        if migrate_before_send:
            migrate_group3(conn)
        if not group3_schema_present(conn):
            raise RuntimeError("GROUP3_SCHEMA_MISSING")
    except Exception:
        conn.close()
        raise
    return conn


def sidecar_path(db_path):
    return Path(str(db_path) + ".recovery.jsonl")


def write_sidecar(db_path, payload: dict):
    forbidden = ("case_id", "note", "private", "password", "key")
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    lowered = text.lower()
    if any(key in payload for key in forbidden) or any(word in lowered for word in ("private_key", "mnemonic")):
        raise RuntimeError("SIDECAR_SECRET")
    path = sidecar_path(db_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def _append_event(conn, operation_id, from_state, to_state, code):
    conn.execute(
        "INSERT INTO onchain_operation_events(operation_id,ts,from_state,to_state,code) VALUES(?,?,?,?,?)",
        (operation_id, _now(), from_state, to_state, code),
    )


def claim_send(db_path, intent: dict) -> str:
    """BEGIN IMMEDIATE, insert-or-reuse READY row, claim SEND_STARTED. Close before RPC."""
    body = canonical_json(intent)
    digest = fingerprint(intent)
    op_type = intent["op_type"]
    now = _now()
    conn = open_existing_rw(db_path, migrate_before_send=True)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT operation_id, state, tx_hash FROM onchain_operations WHERE fingerprint=?",
            (digest,),
        ).fetchone()
        if row is None:
            operation_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO onchain_operations(operation_id,op_type,fingerprint,intent_canonical,state,"
                "chain_id,contract_address,signer,tx_hash,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,NULL,?,?)",
                (operation_id, op_type, digest, body, READY, intent["chain_id"],
                 intent["contract"], intent["signer"], now, now),
            )
            _append_event(conn, operation_id, None, READY, "INTENT_RECORDED")
        else:
            operation_id, state, tx_hash = row
            if state != READY or tx_hash is not None:
                _append_event(conn, operation_id, state, state if state != SEND_STARTED else UNKNOWN,
                              "SEND_CLAIM_DENIED")
                conn.commit()
                if state == SEND_STARTED and not tx_hash:
                    raise RuntimeError("SEND_OUTCOME_UNKNOWN")
                raise RuntimeError("SEND_CLAIM_DENIED")
        cur = conn.execute(
            "UPDATE onchain_operations SET state=?, updated_at=? "
            "WHERE operation_id=? AND state=? AND tx_hash IS NULL",
            (SEND_STARTED, now, operation_id, READY),
        )
        if cur.rowcount != 1:
            conn.rollback()
            raise RuntimeError("SEND_CLAIM_DENIED")
        _append_event(conn, operation_id, READY, SEND_STARTED, "SEND_CLAIMED")
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


def record_broadcast(db_path, operation_id, tx_hash):
    conn = open_existing_rw(db_path, migrate_before_send=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE onchain_operations SET tx_hash=?, state=?, updated_at=? "
            "WHERE operation_id=? AND state=? AND tx_hash IS NULL",
            (tx_hash.lower(), BROADCAST, _now(), operation_id, SEND_STARTED),
        )
        if cur.rowcount != 1:
            conn.rollback()
            raise RuntimeError("POST_SEND_DB_FAILED")
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


def mark_unknown(db_path, operation_id, code):
    try:
        conn = open_existing_rw(db_path, migrate_before_send=False)
    except RuntimeError:
        write_sidecar(db_path, {"operation_id": operation_id, "state": UNKNOWN, "code": code})
        return
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE onchain_operations SET state=?, updated_at=? WHERE operation_id=? AND tx_hash IS NULL",
            (UNKNOWN, _now(), operation_id),
        )
        _append_event(conn, operation_id, SEND_STARTED, UNKNOWN, code)
        conn.commit()
    except sqlite3.Error:
        write_sidecar(db_path, {"operation_id": operation_id, "state": UNKNOWN, "code": code})
    finally:
        conn.close()


def persist_verified_event(db_path, operation_id, *, chain_id, contract, evidence_id, action,
                           actor, artifact_sha256, note_hash, tx_hash, block_number, log_index,
                           event_type, manifest_sha256=None, case_digest=None):
    conn = open_existing_rw(db_path, migrate_before_send=False)
    now = _now()
    event_id = f"{int(chain_id)}:{contract.lower()}:{tx_hash.lower()}:{int(log_index)}"
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO custody_events(event_id,evidence_id,case_id,action,actor_address,"
            "artifact_sha256,note_hash,chain_id,contract_address,tx_hash,block_number,"
            "recorded_at,verified,log_index,event_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (event_id, evidence_id, case_digest, action, actor.lower(),
             artifact_sha256.lower() if artifact_sha256 else None,
             note_hash.lower() if note_hash else None,
             int(chain_id), contract.lower(), tx_hash.lower(), int(block_number),
             now, int(log_index), event_type),
        )
        if event_type == "EvidenceRegistered":
            if not manifest_sha256:
                raise RuntimeError("POST_SEND_DB_FAILED")
            conn.execute(
                "INSERT INTO anchor_links(chain_id,contract_address,manifest_sha256,evidence_id,"
                "tx_hash,log_index,event_type,verified,recorded_at) VALUES(?,?,?,?,?,?,?,1,?)",
                (int(chain_id), contract.lower(), manifest_sha256.lower(), int(evidence_id),
                 tx_hash.lower(), int(log_index), event_type, now),
            )
        cur = conn.execute(
            "UPDATE onchain_operations SET state=?, updated_at=? WHERE operation_id=? AND state=?",
            (CONFIRMED, now, operation_id, BROADCAST),
        )
        if cur.rowcount != 1:
            conn.rollback()
            raise RuntimeError("POST_SEND_DB_FAILED")
        _append_event(conn, operation_id, BROADCAST, CONFIRMED, event_type)
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise RuntimeError("POST_SEND_DB_FAILED") from None
    finally:
        conn.close()


def load_operation(db_path, operation_id):
    conn = open_existing_rw(db_path, migrate_before_send=False)
    try:
        row = conn.execute(
            "SELECT operation_id,op_type,fingerprint,intent_canonical,state,chain_id,"
            "contract_address,signer,tx_hash FROM onchain_operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("OPERATION_NOT_FOUND")
        keys = ("operation_id", "op_type", "fingerprint", "intent_canonical", "state",
                "chain_id", "contract_address", "signer", "tx_hash")
        return dict(zip(keys, row))
    finally:
        conn.close()


def apply_reconcile_result(db_path, operation_id, *, state, tx_hash=None, code="RECONCILED"):
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
