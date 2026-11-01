"""Adversarial replay tests use only newly created databases/copies."""
from dataclasses import replace
import json
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from forensics.ai.investigator import save_analysis_run
from forensics.persistence import EvidenceConflictError
from forensics.real_data_ingest import DEFAULT_RESEARCH_DIR, ingest_real_dataset
from forensics.rules.base import Alert, CalibrationRecord
from forensics.rules.engine import RuleEngine
from forensics.schemas import init_db


@pytest.fixture
def db(tmp_path):
    conn = init_db(tmp_path / "conflicts.db")
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def ingested(tmp_path_factory):
    path = tmp_path_factory.mktemp("ingest-replay") / "evidence.db"
    ingest_real_dataset(DEFAULT_RESEARCH_DIR, path)
    return path


def snapshot(conn, table):
    return conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()


def test_identical_ingestion_replay(ingested, tmp_path):
    path = tmp_path / "replay.db"
    shutil.copyfile(ingested, path)
    with sqlite3.connect(path) as conn:
        before = {t: snapshot(conn, t) for t in ("blocks", "transactions", "asset_transfers")}
    ingest_real_dataset(DEFAULT_RESEARCH_DIR, path)
    with sqlite3.connect(path) as conn:
        assert before == {t: snapshot(conn, t) for t in before}


@pytest.mark.parametrize("table,field,value", [
    ("blocks", "hash", "conflicting-hash"),
    ("blocks", "block_timestamp", 999),
    ("blocks", "raw_json", '{"different":true}'),
    ("transactions", "value_raw", "999"),
    ("transactions", "raw_json", '{"different":true}'),
    ("transactions", "block_hash", "conflicting-block"),
    ("asset_transfers", "amount_raw", "999"),
])
def test_ingestion_rejects_conflict_atomically(ingested, tmp_path, table, field, value):
    path = tmp_path / "conflict.db"
    shutil.copyfile(ingested, path)
    with sqlite3.connect(path) as conn:
        conn.execute(f"UPDATE {table} SET {field}=? WHERE rowid=(SELECT min(rowid) FROM {table})", (value,))
    with sqlite3.connect(path) as conn:
        before = {t: snapshot(conn, t) for t in ("blocks", "transactions", "asset_transfers")}
    with pytest.raises(EvidenceConflictError):
        ingest_real_dataset(DEFAULT_RESEARCH_DIR, path)
    with sqlite3.connect(path) as conn:
        assert before == {t: snapshot(conn, t) for t in before}


@pytest.mark.parametrize("field,value", [("selected_threshold", "999"), ("sample_count", 42), ("snapshot_hash", "changed")])
def test_calibration_history_preserved(db, field, value):
    record = CalibrationRecord("cal", "r1", "1", 1, "NATIVE", 1, 2, 3, 99, "100", "hash", "time")
    record.save_to_db(db)
    db.commit()
    before = snapshot(db, "rule_calibrations")
    replace(record, created_at="later").save_to_db(db)
    assert snapshot(db, "rule_calibrations") == before
    with pytest.raises(EvidenceConflictError):
        replace(record, **{field: value}).save_to_db(db)
    assert snapshot(db, "rule_calibrations") == before


@pytest.mark.parametrize("field,value", [("evidence_refs", [{"amount_raw": "999"}]), ("score", 0.1), ("reason", "changed")])
def test_alert_history_preserved(db, field, value):
    alert = Alert("deterministic-id", "r1", "1", "tx", "tx1", "NATIVE", "HIGH", 1.0,
                  "reason", [{"amount_raw": "100"}], "start", "end", "time")
    engine = RuleEngine(db)
    engine.persist_alerts([alert])
    before = snapshot(db, "alerts")
    engine.persist_alerts([replace(alert, created_at="later")])
    assert snapshot(db, "alerts") == before
    with pytest.raises(EvidenceConflictError):
        engine.persist_alerts([replace(alert, alert_id="new-id"), replace(alert, **{field: value})])
    assert snapshot(db, "alerts") == before


def run_record():
    return dict(analysis_id="run", provider="test", model_name="offline", prompt_version="1",
                tool_calls_log='{"calls":[]}', input_refs="[]", output_json='{"observed_facts":[]}',
                existence_ref_ratio=1.0, content_match_ratio=1.0, injection_detected=0,
                temperature=0.0, seed=0, created_at="time")


@pytest.mark.parametrize("field,value", [
    ("output_json", '{"observed_facts":["changed"]}'),
    ("tool_calls_log", '{"calls":["unauthorized"]}'),
    ("input_refs", '["changed"]'), ("model_name", "changed"),
    ("content_match_ratio", 0.5), ("created_at", "later"),
])
def test_finalized_analysis_is_immutable(db, field, value):
    record = run_record()
    save_analysis_run(db, **record)
    before = snapshot(db, "analysis_runs")
    save_analysis_run(db, **record)
    assert snapshot(db, "analysis_runs") == before
    with pytest.raises(EvidenceConflictError):
        save_analysis_run(db, **(record | {field: value}))
    assert snapshot(db, "analysis_runs") == before


def test_concurrent_finalizers_cannot_replace(tmp_path):
    path = tmp_path / "concurrent.db"
    init_db(path).close()
    def writer(value):
        with sqlite3.connect(path, timeout=10) as conn:
            try:
                save_analysis_run(conn, **(run_record() | {"output_json": json.dumps({"value": value})}))
                return "saved"
            except EvidenceConflictError:
                return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(writer, [1, 2])) == ["conflict", "saved"]
    with sqlite3.connect(path) as conn:
        assert len(snapshot(conn, "analysis_runs")) == 1
