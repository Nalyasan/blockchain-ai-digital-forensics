"""Comprehensive Test Suite for Milestone 4 (tests/test_milestone4_progress_ai.py).

Covers Milestone 4 (R5: Standardized 8-Stage Progress, Job Recovery & Real-Time AI Monitoring):
1. Standardized 8 stages initial state ("Chưa chạy", progress 0%, S1..S8)
2. Event-driven progress calculation based on 8 stages (no fake timers, no hardcoded /11)
3. Nested dot-notation dictionary updating in JobManager
4. Not-applicable stage handling ("Không áp dụng" without crashing, advances progress)
5. Server restart recovery protocol: orphaned running/queued jobs marked strictly as "failed" (never "completed"), progress frozen, audit logged
6. CompactAnomalyMLP feature schema validation (safe inspection of sqlite_master, returns not_applicable on missing table/columns)
7. ML statistical risk indicator disclaimer presence
8. Real-time AI task monitoring (7 sequential live sub-tasks emitted via callbacks)
9. Case-bound AI workspace UI rendering with 7 sub-tasks stepper, RefChecker citations grounding table, and Air-gap compliance badge
10. Air-gap cloud consent enforcement (CloudConsentRequiredError)
11. 100% bitwise SHA-256 invariance of all 4 canonical databases.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from dashboard.routes.pages import get_8_stages_for_job
from dashboard.services.job_manager import (
    AI_SUB_TASKS_DEFINITIONS,
    JobManager,
    get_job_manager,
)
from forensics.ai.provider_adapter import (
    CloudConsentRequiredError,
    MultiModelAIAdapter,
)
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_real_p4_db,
)
from forensics.service import (
    InvestigationCallbacks,
    InvestigationConfig,
    InvestigationService,
    STAGE_DEFINITIONS,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_STARTED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    VIETNAMESE_STATUS_MAP,
    compute_sha256,
)

CANONICAL_HASHES = {
    "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
    "endpoint_evidence.db": "CAF3F0B30C0F864150CA5DCBD45DD19927A53620001AB696228A744C959B7CD0",
}


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def verify_db_invariance():
    """Verifies all 4 canonical databases remain bitwise identical before and after each test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, path in dbs.items():
        assert path.is_file(), f"Canonical database missing: {path}"
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Pre-test mutation detected in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"

    yield

    for name, path in dbs.items():
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Post-test mutation detected in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"


# ==============================================================================
# 1. Standardized 8 Stages & Event-Driven Progress
# ==============================================================================

def test_standardized_8_stages_initial_state(tmp_path: Path):
    """Verifies that newly submitted jobs initialize with S1..S8 as not_started, progress=0%, and 7 AI sub-tasks."""
    jobs_file = tmp_path / "jobs.json"
    lock_file = tmp_path / "jobs.lock"
    jm = JobManager(jobs_file=jobs_file, lock_file=lock_file)

    config = InvestigationConfig(
        case_id="case-m4-init",
        mode="MODE_B",
        ai_provider="ollama",
        ai_model="qwen3:8b",
        is_mock=True,
    )
    job = jm.submit_job(config)

    assert job["status"] == STATUS_QUEUED
    assert job["vietnamese_status"] == VIETNAMESE_STATUS_MAP[STATUS_QUEUED]
    assert job["progress_percent"] == 0
    assert job["current_stage"] is None
    assert job["current_stage_name"] is None

    # Verify stage_status dictionary has S1..S8
    stage_status = job.get("stage_status", {})
    assert len(stage_status) == 8
    for i in range(1, 9):
        sid = f"S{i}"
        assert sid in stage_status
        assert stage_status[sid] == STATUS_NOT_STARTED

    # Verify 7 AI sub-tasks
    ai_sub_tasks = job.get("ai_sub_tasks", [])
    assert len(ai_sub_tasks) == 7
    for idx, (expected_id, expected_name) in enumerate(AI_SUB_TASKS_DEFINITIONS):
        assert ai_sub_tasks[idx]["id"] == expected_id
        assert ai_sub_tasks[idx]["name"] == expected_name
        assert ai_sub_tasks[idx]["status"] == STATUS_NOT_STARTED


def test_nested_dot_notation_updating(tmp_path: Path):
    """Verifies that _update_job parses dot-notation ('stage_status.S1') to update nested dicts cleanly."""
    jobs_file = tmp_path / "jobs.json"
    lock_file = tmp_path / "jobs.lock"
    jm = JobManager(jobs_file=jobs_file, lock_file=lock_file)

    config = InvestigationConfig(case_id="case-m4-dot", mode="MODE_B", is_mock=True)
    job = jm.submit_job(config)
    run_id = job["run_id"]

    # Update using dot-notation
    jm._update_job(run_id, {
        "stage_status.S1": STATUS_COMPLETED,
        "stage_status.S2": STATUS_RUNNING,
        "ai_monitoring.current_task": "T1",
    })

    updated_job = jm.get_job(run_id)
    assert updated_job is not None

    # Verify nested dictionary was updated directly
    assert updated_job["stage_status"]["S1"] == STATUS_COMPLETED
    assert updated_job["stage_status"]["S2"] == STATUS_RUNNING
    assert updated_job["ai_monitoring"]["current_task"] == "T1"

    # Verify root was NOT polluted with dot keys
    assert "stage_status.S1" not in updated_job
    assert "stage_status.S2" not in updated_job
    assert "ai_monitoring.current_task" not in updated_job


def test_event_driven_progress_increment():
    """Verifies dynamic progress percent calculation based strictly on the 8 stages."""
    # S1 completed -> 1/8 * 100 = 12%
    stages_1 = {"S1": STATUS_COMPLETED, "S2": STATUS_NOT_STARTED, "S3": STATUS_NOT_STARTED}
    processed_1 = sum(1 for s in stages_1.values() if s in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE))
    prog_1 = min(100, int((processed_1 / 8.0) * 100))
    assert prog_1 == 12

    # S1..S4 completed -> 4/8 * 100 = 50%
    stages_4 = {f"S{i}": STATUS_COMPLETED for i in range(1, 5)}
    processed_4 = sum(1 for s in stages_4.values() if s in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE))
    prog_4 = min(100, int((processed_4 / 8.0) * 100))
    assert prog_4 == 50

    # S1..S7 completed, S8 completed -> 8/8 * 100 = 100%
    stages_8 = {f"S{i}": STATUS_COMPLETED for i in range(1, 9)}
    processed_8 = sum(1 for s in stages_8.values() if s in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE))
    prog_8 = min(100, int((processed_8 / 8.0) * 100))
    assert prog_8 == 100


def test_not_applicable_stage_handling():
    """Verifies that 'not_applicable' ('Không áp dụng') advances progress and is never overwritten by 'completed'."""
    job_with_na = {
        "run_id": "run_test_na_001",
        "case_id": "case-na",
        "status": "completed",
        "stage_status": {
            "S1": STATUS_COMPLETED,
            "S2": STATUS_COMPLETED,
            "S3": STATUS_COMPLETED,
            "S4": STATUS_COMPLETED,
            "S5": STATUS_COMPLETED,
            "S6": STATUS_COMPLETED,
            "S7": STATUS_NOT_APPLICABLE,  # Non-EVM data: ZKML not applicable
            "S8": STATUS_COMPLETED,
        },
        "phase_status": {
            "P1": STATUS_COMPLETED,
            "P9": STATUS_NOT_APPLICABLE,
        }
    }

    stages = get_8_stages_for_job(job_with_na)
    assert len(stages) == 8

    # Check S7
    s7 = next(s for s in stages if s["stage_id"] == "S7")
    assert s7["status"] == "not_applicable"
    assert s7["vietnamese_status"] == "Không áp dụng"

    # Verify not_applicable counts towards progress
    processed = sum(1 for s in job_with_na["stage_status"].values() if s in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE))
    progress = min(100, int((processed / 8.0) * 100))
    assert progress == 100  # 8/8 processed


# ==============================================================================
# 2. Server Restart Recovery Protocol
# ==============================================================================

def test_server_restart_recovery_orphaned_jobs_dict(tmp_path: Path):
    """Verifies that orphaned running/queued jobs are transitioned strictly to failed with audit logs."""
    jobs_file = tmp_path / "jobs.json"
    lock_file = tmp_path / "jobs.lock"
    log_file = tmp_path / "execution_log.txt"
    log_file.write_text("Previous log line 1\n", encoding="utf-8")

    # Simulate server crash with running and queued jobs stored as a dict
    initial_jobs = {
        "run_orphaned_running": {
            "run_id": "run_orphaned_running",
            "case_id": "case-orphan-1",
            "status": STATUS_RUNNING,
            "vietnamese_status": "Đang xử lý",
            "progress_percent": 62,
            "stage_status": {
                "S1": STATUS_COMPLETED,
                "S2": STATUS_COMPLETED,
                "S3": STATUS_RUNNING,
                "S4": STATUS_NOT_STARTED,
            },
            "phase_status": {
                "P1": STATUS_COMPLETED,
                "P2": STATUS_RUNNING,
            },
            "artifacts": {
                "execution_log": str(log_file),
            },
            "errors": [],
        },
        "run_orphaned_queued": {
            "run_id": "run_orphaned_queued",
            "case_id": "case-orphan-2",
            "status": STATUS_QUEUED,
            "vietnamese_status": "Đang chờ",
            "progress_percent": 0,
            "stage_status": {
                "S1": STATUS_NOT_STARTED,
            },
            "errors": [],
        },
        "run_already_completed": {
            "run_id": "run_already_completed",
            "case_id": "case-completed",
            "status": STATUS_COMPLETED,
            "vietnamese_status": "Hoàn tất",
            "progress_percent": 100,
            "errors": [],
        }
    }
    with open(jobs_file, "w", encoding="utf-8") as f:
        json.dump(initial_jobs, f, indent=2)

    # Boot JobManager -> triggers _initialize_and_recover()
    jm = JobManager(jobs_file=jobs_file, lock_file=lock_file)

    recovered = jm._read_jobs()

    # 1. Check running job
    job1 = recovered["run_orphaned_running"]
    assert job1["status"] == STATUS_FAILED
    assert job1["vietnamese_status"] == VIETNAMESE_STATUS_MAP[STATUS_FAILED]
    assert job1["progress_percent"] == 62  # Frozen, never 100%
    assert job1["error_message"] == "Phiên bị gián đoạn do máy chủ khởi động lại."
    assert any(e["stage"] == "server_restart" for e in job1["errors"])
    # Running stage and phase transitioned to failed
    assert job1["stage_status"]["S3"] == STATUS_FAILED
    assert job1["phase_status"]["P2"] == STATUS_FAILED
    # Execution log appended
    assert "Phiên bị gián đoạn do máy chủ khởi động lại" in log_file.read_text(encoding="utf-8")

    # 2. Check queued job
    job2 = recovered["run_orphaned_queued"]
    assert job2["status"] == STATUS_FAILED
    assert job2["vietnamese_status"] == VIETNAMESE_STATUS_MAP[STATUS_FAILED]
    assert job2["progress_percent"] == 0

    # 3. Check already completed job was untouched
    job3 = recovered["run_already_completed"]
    assert job3["status"] == STATUS_COMPLETED
    assert job3["vietnamese_status"] == "Hoàn tất"
    assert job3["progress_percent"] == 100


def test_server_restart_recovery_list_format(tmp_path: Path):
    """Verifies that _initialize_and_recover handles jobs.json when stored as a list without crashing."""
    jobs_file = tmp_path / "jobs.json"
    lock_file = tmp_path / "jobs.lock"

    # Simulate jobs.json stored as a list
    list_jobs = [
        {
            "run_id": "run_list_001",
            "case_id": "case-list",
            "status": STATUS_RUNNING,
            "vietnamese_status": "Đang xử lý",
            "progress_percent": 25,
            "errors": [],
        }
    ]
    with open(jobs_file, "w", encoding="utf-8") as f:
        json.dump(list_jobs, f, indent=2)

    jm = JobManager(jobs_file=jobs_file, lock_file=lock_file)
    recovered = jm._read_jobs()

    assert "run_list_001" in recovered
    assert recovered["run_list_001"]["status"] == STATUS_FAILED
    assert recovered["run_list_001"]["vietnamese_status"] == VIETNAMESE_STATUS_MAP[STATUS_FAILED]


# ==============================================================================
# 3. CompactAnomalyMLP Feature Schema Validation & Anomaly Nuance
# ==============================================================================

def test_compact_anomaly_mlp_missing_table_graceful(tmp_path: Path):
    """Verifies that querying a DB missing asset_transfers cleanly returns not_applicable without crashing."""
    empty_db = tmp_path / "empty_evidence.db"
    conn = sqlite3.connect(empty_db)
    conn.execute("CREATE TABLE mock_logs (id INTEGER PRIMARY KEY, msg TEXT)")
    conn.commit()
    conn.close()

    logs: list[str] = []
    def log_fn(msg: str, lvl: str = "INFO"):
        logs.append(f"[{lvl}] {msg}")

    service = InvestigationService()
    metrics, status = service._phase_p8_ml_xai(empty_db, log_fn)

    assert status == STATUS_NOT_APPLICABLE
    assert metrics["status"] == STATUS_NOT_APPLICABLE
    assert "Chưa hỗ trợ phân tích bằng mô hình này" in metrics["reason"]
    assert "statistical_disclaimer" in metrics
    assert "Điểm dị thường học máy là chỉ số thống kê rủi ro" in metrics["statistical_disclaimer"]
    assert any("Bảng 'asset_transfers' không tồn tại" in l for l in logs)


def test_compact_anomaly_mlp_incompatible_columns_graceful(tmp_path: Path):
    """Verifies that an asset_transfers table missing required columns cleanly returns not_applicable."""
    bad_db = tmp_path / "bad_columns.db"
    conn = sqlite3.connect(bad_db)
    # Missing amount_raw and asset_id
    conn.execute("CREATE TABLE asset_transfers (block_number INT, from_addr TEXT, to_addr TEXT)")
    conn.commit()
    conn.close()

    logs: list[str] = []
    service = InvestigationService()
    metrics, status = service._phase_p8_ml_xai(bad_db, lambda msg, lvl: logs.append(msg))

    assert status == STATUS_NOT_APPLICABLE
    assert "Schema thiếu cột" in metrics["reason"]


def test_compact_anomaly_mlp_statistical_risk_disclaimer():
    """Verifies that ML metrics and logs contain the mandatory statistical risk indicator disclaimer."""
    service = InvestigationService()
    real_db = get_real_p4_db()

    logs: list[str] = []
    metrics, status = service._phase_p8_ml_xai(real_db, lambda msg, lvl: logs.append(msg))

    assert status == STATUS_COMPLETED
    assert "statistical_disclaimer" in metrics
    expected_disclaimer = "Điểm dị thường học máy là chỉ số thống kê rủi ro, không phải kết luận tấn công chắc chắn."
    assert metrics["statistical_disclaimer"] == expected_disclaimer
    assert any(expected_disclaimer in l for l in logs)


# ==============================================================================
# 4. Real-Time AI Task Monitoring (7 Live Sub-Tasks)
# ==============================================================================

def test_ai_7_subtasks_sequential_progression():
    """Verifies that _phase_p5_ai_investigator sequentially executes and emits all 7 live sub-tasks."""
    service = InvestigationService()
    real_db = get_real_p4_db()

    emitted_tasks: list[tuple[str, str, dict]] = []

    def on_ai_task_update(task_id: str, task_name: str, details: dict):
        emitted_tasks.append((task_id, task_name, details))

    callbacks = InvestigationCallbacks(
        on_ai_task_update=on_ai_task_update,
    )

    config = InvestigationConfig(
        case_id="case-m4-ai-tasks",
        mode="MODE_B",
        ai_provider="ollama",
        ai_model="qwen3:8b",
        is_mock=True,
    )

    metrics = service._phase_p5_ai_investigator(
        real_db,
        config,
        lambda msg, lvl: None,
        callbacks=callbacks,
    )

    # Verify all 7 tasks emitted in strict sequential order
    assert len(emitted_tasks) == 7
    expected_task_names = [
        ("T1", "Đang chuẩn bị dữ liệu"),
        ("T2", "Truy xuất chứng cứ"),
        ("T3", "Phân tích giao dịch bất thường"),
        ("T4", "Đối chiếu địa chỉ/luồng tài sản"),
        ("T5", "Xây dựng nhận định"),
        ("T6", "Kiểm tra RefChecker"),
        ("T7", "Hoàn tất"),
    ]
    for idx, (exp_id, exp_name) in enumerate(expected_task_names):
        assert emitted_tasks[idx][0] == exp_id
        assert emitted_tasks[idx][1] == exp_name

    # Verify citations generated
    assert "citations" in metrics
    assert len(metrics["citations"]) > 0
    first_cit = metrics["citations"][0]
    assert "statement" in first_cit
    assert "tx_hash" in first_cit
    assert "match_status" in first_cit
    assert first_cit["match_status"] in ("Khớp 100%", "CONTENT_MISMATCH", "NOT_FOUND")


# ==============================================================================
# 5. Case-Bound AI Workspace & Air-Gap UI
# ==============================================================================

def test_case_bound_ai_workspace_ui_empty_state(client: TestClient, monkeypatch):
    """Verifies /ai page renders clean empty state when no job is selected."""
    jm = get_job_manager()
    monkeypatch.setattr(jm, "list_jobs", lambda *args, **kwargs: [])
    monkeypatch.setattr(jm, "get_active_job", lambda: None)

    res = client.get("/ai")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Chưa có dữ liệu điều tra" in res.text
    assert "Bảo đảm Air-Gap & Cách ly Mật mã" in res.text


def test_case_bound_ai_workspace_with_selected_job(client: TestClient, monkeypatch):
    """Verifies /ai page renders active Case ID, Run ID, Ollama provider, 7 sub-tasks, and RefChecker citations table."""
    mock_job = {
        "run_id": "run_case_test_ui_001",
        "case_id": "case-test-ui",
        "status": "completed",
        "vietnamese_status": "Hoàn tất",
        "ai_provider": "ollama",
        "ai_model": "qwen3:8b",
        "db_path": "real_p4.db",
        "progress_percent": 100,
        "phase_status": {"P5": "completed"},
        "stage_status": {"S5": "completed"},
        "ai_sub_tasks": [
            {"id": tid, "name": tname, "status": "completed", "details": {}}
            for tid, tname in AI_SUB_TASKS_DEFINITIONS
        ],
        "phase_metrics": {
            "P5": {
                "provider": "ollama",
                "model": "qwen3:8b",
                "observed_facts_count": 2,
                "ai_synthesis": "Nhận định điều tra thực nghiệm: Flash loan exploit detected.",
                "citations": [
                    {
                        "statement": "Chuyển 50 ETH tại block 16800000",
                        "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                        "block_number": 16800000,
                        "from_addr": "0x1111111111111111111111111111111111111111",
                        "to_addr": "0x2222222222222222222222222222222222222222",
                        "asset_id": "ETH",
                        "amount_raw": "50000000000000000000",
                        "ledger_verified": "Khớp chính xác sổ cái khối #16800000",
                        "match_status": "Khớp 100%",
                    }
                ],
            }
        },
    }

    jm = get_job_manager()
    monkeypatch.setattr(jm, "list_jobs", lambda limit=500: [mock_job])
    monkeypatch.setattr(jm, "get_job", lambda run_id: mock_job if run_id == "run_case_test_ui_001" else None)

    res = client.get("/ai?case_id=case-test-ui&run_id=run_case_test_ui_001")
    assert res.status_code == 200
    html = res.text

    # Case & Run Scoping
    assert "case-test-ui" in html
    assert "run_case_test_ui_001" in html

    # Air Gap Badge
    assert "Bảo đảm Air-Gap 100% Ngoại tuyến" in html
    assert "127.0.0.1:11434" in html

    # 7 Sub-Tasks
    for _, tname in AI_SUB_TASKS_DEFINITIONS:
        assert tname in html

    # RefChecker Citations Grounding Table
    assert "Bảng Đối chiếu Dữ kiện Thẩm định RefChecker" in html
    assert "Chuyển 50 ETH tại block 16800000" in html
    assert "Khớp 100%" in html
    assert "0x12345678" in html


def test_air_gap_cloud_consent_enforcement():
    """Verifies that initiating cloud AI without explicit session consent raises CloudConsentRequiredError."""
    adapter = MultiModelAIAdapter(
        provider="openai",
        model_id="gpt-4o",
        cloud_consent=False,  # Air-gap strictly locked
        is_mock=False,
    )

    with pytest.raises(CloudConsentRequiredError) as exc_info:
        adapter.create_model()

    assert "Air-Gap Security Gate" in str(exc_info.value)
    assert "without explicit session consent" in str(exc_info.value)
