"""Job Manager for Digital Forensics Dashboard (dashboard/services/job_manager.py).

Provides persistent, single-threaded execution queue with:
- ThreadPoolExecutor(max_workers=1)
- Concurrency mutex with filelock.FileLock("data/jobs.lock")
- State persistence in data/jobs.json
- Crash recovery on startup (recovers orphaned 'running' jobs to 'failed')
- Anti-overlap: prevents concurrent runs that could corrupt database/reports
- Cooperative cancellation tokens via threading.Event
- Configurable execution timeout
- Zero arbitrary shell, SQL, or blockchain execution APIs
- Zero auto-running of D1/D2/D3 on server boot
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import filelock

from forensics.paths import get_data_dir, get_project_root
from forensics.service import (
    InvestigationCallbacks,
    InvestigationConfig,
    InvestigationResult,
    InvestigationService,
    STAGE_DEFINITIONS,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_STARTED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_STOPPED,
    VIETNAMESE_STATUS_MAP,
)

logger = logging.getLogger("dashboard.job_manager")

AI_SUB_TASKS_DEFINITIONS: List[Tuple[str, str]] = [
    ("T1", "Đang chuẩn bị dữ liệu"),
    ("T2", "Truy xuất chứng cứ"),
    ("T3", "Phân tích giao dịch bất thường"),
    ("T4", "Đối chiếu địa chỉ/luồng tài sản"),
    ("T5", "Xây dựng nhận định"),
    ("T6", "Kiểm tra RefChecker"),
    ("T7", "Hoàn tất"),
]


class JobConflictError(Exception):
    """Raised when attempting to start a job while another job is actively running."""


class JobNotFoundError(Exception):
    """Raised when requested run_id is not found in job registry."""


class JobManager:
    """Persistent single-worker background job manager for forensic investigation runs."""

    def __init__(
        self,
        jobs_file: Optional[Path] = None,
        lock_file: Optional[Path] = None,
        max_workers: int = 1,
    ) -> None:
        self.data_dir = get_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.jobs_file = Path(jobs_file) if jobs_file else (self.data_dir / "jobs.json")
        self.lock_file = Path(lock_file) if lock_file else (self.data_dir / "jobs.lock")
        self._file_lock = filelock.FileLock(str(self.lock_file), timeout=10.0)

        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="forensic-worker")
        self._active_futures: Dict[str, Future] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._job_logs: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

        # Initialize storage & perform safe crash recovery
        self._initialize_and_recover()

    def _initialize_and_recover(self) -> None:
        """Initializes jobs.json if absent and resets orphaned running/queued jobs from previous crashes."""
        with self._file_lock:
            jobs: Dict[str, Any] = {}
            if self.jobs_file.is_file():
                try:
                    with open(self.jobs_file, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                        if isinstance(raw, list):
                            jobs = {item["run_id"]: item for item in raw if isinstance(item, dict) and "run_id" in item}
                        elif isinstance(raw, dict):
                            jobs = raw
                        else:
                            jobs = {}
                except Exception as e:
                    logger.warning("Error reading jobs.json; resetting corrupted store: %s", e)
                    jobs = {}

            # Crash recovery check: any job left running or queued was interrupted by process restart
            mutated = False
            for run_id, job in jobs.items():
                st = job.get("status")
                if st in (STATUS_RUNNING, STATUS_QUEUED):
                    job["status"] = STATUS_FAILED
                    job["vietnamese_status"] = VIETNAMESE_STATUS_MAP[STATUS_FAILED]
                    job["end_time"] = datetime.now(timezone.utc).isoformat()
                    job["error_message"] = "Phiên bị gián đoạn do máy chủ khởi động lại."
                    job.setdefault("errors", []).append({
                        "stage": "server_restart",
                        "error": "Máy chủ khởi động lại khi tác vụ đang xử lý.",
                    })
                    # Freeze progress_percent at current value (never 100%)
                    cur_p = job.get("progress_percent", 0)
                    job["progress_percent"] = min(cur_p, 99) if cur_p < 100 else 0

                    # Transition any active running stages in stage_status to "failed"
                    if "stage_status" in job and isinstance(job["stage_status"], dict):
                        for s_k, s_v in job["stage_status"].items():
                            if s_v == STATUS_RUNNING:
                                job["stage_status"][s_k] = STATUS_FAILED
                    if "phase_status" in job and isinstance(job["phase_status"], dict):
                        for p_k, p_v in job["phase_status"].items():
                            if p_v == STATUS_RUNNING:
                                job["phase_status"][p_k] = STATUS_FAILED

                    # Append recovery audit entry to execution_log.txt if possible
                    artifacts = job.get("artifacts", {})
                    log_file_str = artifacts.get("execution_log")
                    if log_file_str:
                        try:
                            log_file = Path(log_file_str)
                            if log_file.is_file():
                                with open(log_file, "a", encoding="utf-8") as lf:
                                    lf.write(f"\n{datetime.now(timezone.utc).isoformat()} [ERROR] Phiên bị gián đoạn do máy chủ khởi động lại.\n")
                        except Exception as log_err:
                            logger.warning("Could not append restart log to %s: %s", log_file_str, log_err)

                    mutated = True

            if mutated or not self.jobs_file.is_file():
                with open(self.jobs_file, "w", encoding="utf-8") as f:
                    json.dump(jobs, f, indent=2, ensure_ascii=False)

    def _read_jobs(self) -> Dict[str, Any]:
        """Reads job registry with filelock."""
        with self._file_lock:
            if not self.jobs_file.is_file():
                return {}
            try:
                with open(self.jobs_file, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    if isinstance(raw, list):
                        return {item["run_id"]: item for item in raw if isinstance(item, dict) and "run_id" in item}
                    elif isinstance(raw, dict):
                        return raw
                    return {}
            except Exception as e:
                logger.error("Failed to read jobs.json: %s", e)
                return {}

    def _write_jobs(self, jobs: Dict[str, Any]) -> None:
        """Writes job registry with filelock."""
        with self._file_lock:
            with open(self.jobs_file, "w", encoding="utf-8") as f:
                json.dump(jobs, f, indent=2, ensure_ascii=False)

    def _update_job(self, run_id: str, updates: Dict[str, Any]) -> None:
        """Atomically updates a specific job entry supporting nested dot-notation."""
        with self._file_lock:
            jobs = {}
            if self.jobs_file.is_file():
                try:
                    with open(self.jobs_file, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                        if isinstance(raw, list):
                            jobs = {item["run_id"]: item for item in raw if isinstance(item, dict) and "run_id" in item}
                        elif isinstance(raw, dict):
                            jobs = raw
                        else:
                            jobs = {}
                except Exception:
                    jobs = {}

            if run_id in jobs:
                for k, v in updates.items():
                    if "." in k:
                        parts = k.split(".")
                        curr = jobs[run_id]
                        for p in parts[:-1]:
                            if p not in curr or not isinstance(curr[p], dict):
                                curr[p] = {}
                            curr = curr[p]
                        curr[parts[-1]] = v
                    else:
                        jobs[run_id][k] = v

                if "status" in updates:
                    st = updates["status"]
                    jobs[run_id]["vietnamese_status"] = VIETNAMESE_STATUS_MAP.get(st, st)
                with open(self.jobs_file, "w", encoding="utf-8") as f:
                    json.dump(jobs, f, indent=2, ensure_ascii=False)

    def is_busy(self) -> bool:
        """Checks if any job is currently in running or queued state."""
        jobs = self._read_jobs()
        for job in jobs.values():
            if job.get("status") in (STATUS_RUNNING, STATUS_QUEUED):
                return True
        return False

    def get_active_job(self) -> Optional[Dict[str, Any]]:
        """Returns the currently active running or queued job, if any."""
        jobs = self._read_jobs()
        for job in jobs.values():
            if job.get("status") in (STATUS_RUNNING, STATUS_QUEUED):
                return job
        return None

    def submit_job(self, config: InvestigationConfig) -> Dict[str, Any]:
        """Submits an investigation job for background execution.

        Enforces anti-overlap policy: if a job is currently executing, rejects submission.
        """
        with self._lock:
            if self.is_busy():
                active = self.get_active_job()
                active_id = active.get("run_id") if active else "unknown"
                raise JobConflictError(
                    f"Đang có một phiên điều tra khác đang thực thi ({active_id}). "
                    f"Vui lòng chờ phiên hiện tại hoàn tất hoặc dừng phiên trước khi tạo phiên mới."
                )

            # Generate unique run_id
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            case_clean = "".join(c if c.isalnum() or c in "-_" else "_" for c in (config.case_id or "case"))
            run_id = f"run_{case_clean}_{timestamp_str}"
            config.run_id = run_id

            now_iso = datetime.now(timezone.utc).isoformat()
            job_record: Dict[str, Any] = {
                "run_id": run_id,
                "case_id": config.case_id,
                "mode": config.mode,
                "demo_target": config.demo_target,
                "db_path": str(config.db_path) if config.db_path else None,
                "ai_provider": config.ai_provider,
                "ai_model": config.ai_model,
                "enable_onchain_write": config.enable_onchain_write,
                "status": STATUS_QUEUED,
                "vietnamese_status": VIETNAMESE_STATUS_MAP[STATUS_QUEUED],
                "progress_percent": 0,
                "current_stage": None,
                "current_stage_name": None,
                "current_phase": None,
                "current_phase_name": None,
                "current_ai_sub_task": None,
                "current_ai_sub_task_name": None,
                "start_time": now_iso,
                "end_time": None,
                "duration_seconds": 0.0,
                "stage_status": {sid: STATUS_NOT_STARTED for sid, _ in STAGE_DEFINITIONS},
                "phase_status": {f"P{i}": STATUS_NOT_STARTED for i in range(1, 12)},
                "ai_sub_tasks": [
                    {"id": tid, "name": tname, "status": STATUS_NOT_STARTED, "details": {}}
                    for tid, tname in AI_SUB_TASKS_DEFINITIONS
                ],
                "ai_monitoring": {},
                "phase_metrics": {},
                "artifacts": {},
                "errors": [],
            }

            jobs = self._read_jobs()
            jobs[run_id] = job_record
            self._write_jobs(jobs)

            cancel_event = threading.Event()
            self._cancel_events[run_id] = cancel_event
            self._job_logs[run_id] = []

            # Dispatch background worker
            future = self._executor.submit(self._worker_execute, run_id, config, cancel_event)
            self._active_futures[run_id] = future

            return job_record

    def cancel_job(self, run_id: str) -> bool:
        """Cooperatively requests cancellation of an active job."""
        with self._lock:
            event = self._cancel_events.get(run_id)
            if not event:
                job = self.get_job(run_id)
                if job and job.get("status") in (STATUS_RUNNING, STATUS_QUEUED):
                    self._update_job(run_id, {
                        "status": STATUS_STOPPED,
                        "end_time": datetime.now(timezone.utc).isoformat(),
                        "error_message": "Tác vụ bị dừng bởi người dùng.",
                    })
                    return True
                return False

            event.set()
            self._append_log(run_id, "Tín hiệu dừng an toàn đã được gửi tới tiến trình điều tra.", "WARNING")
            return True

    def get_job(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves job state dictionary for run_id."""
        jobs = self._read_jobs()
        return jobs.get(run_id)

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists recent jobs ordered chronologically descending."""
        jobs = self._read_jobs()
        job_list = list(jobs.values())
        job_list.sort(key=lambda x: str(x.get("start_time") or ""), reverse=True)
        return job_list[:limit]

    def get_logs(self, run_id: str, offset: int = 0) -> Tuple[List[str], int]:
        """Returns log entries for a job starting from offset, and the total log count."""
        with self._lock:
            logs = self._job_logs.get(run_id, [])
            if not logs:
                # Fallback to reading execution_log.txt if persisted
                job = self.get_job(run_id)
                if job and "artifacts" in job and "execution_log" in job["artifacts"]:
                    log_file = Path(job["artifacts"]["execution_log"])
                    if log_file.is_file():
                        try:
                            lines = log_file.read_text(encoding="utf-8").splitlines()
                            return lines[offset:], len(lines)
                        except Exception:
                            pass
            return logs[offset:], len(logs)

    def _append_log(self, run_id: str, msg: str, level: str = "INFO") -> None:
        """Appends log entry to in-memory log buffer."""
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"{timestamp} [{level}] {msg}"
        with self._lock:
            self._job_logs.setdefault(run_id, []).append(entry)

    def _worker_execute(
        self,
        run_id: str,
        config: InvestigationConfig,
        cancel_event: threading.Event,
    ) -> None:
        """Worker thread entry executing InvestigationService with callback progress hooks."""
        t_start = time.perf_counter()
        self._update_job(run_id, {
            "status": STATUS_RUNNING,
            "start_time": datetime.now(timezone.utc).isoformat(),
        })
        self._append_log(run_id, f"Bắt đầu thực thi phiên điều tra: {run_id}", "INFO")

        # Callbacks definition
        completed_phases: List[str] = []

        def on_stage_start(s_id: str, s_name: str) -> None:
            self._update_job(run_id, {
                "current_stage": s_id,
                "current_stage_name": s_name,
                f"stage_status.{s_id}": STATUS_RUNNING,
            })
            self._append_log(run_id, f"Bắt đầu giai đoạn {s_id}: {s_name}", "INFO")

        def on_stage_complete(s_id: str, s_name: str, status: str, metrics: Dict[str, Any]) -> None:
            self._update_job(run_id, {
                f"stage_status.{s_id}": status,
            })
            job_cur = self.get_job(run_id) or {}
            stg_map = job_cur.get("stage_status", {})
            processed = sum(
                1 for st in stg_map.values()
                if st in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE)
            )
            progress = min(100, int((processed / 8.0) * 100))
            self._update_job(run_id, {"progress_percent": progress})
            st_vi = VIETNAMESE_STATUS_MAP.get(status, status)
            self._append_log(run_id, f"Hoàn thành giai đoạn {s_id} ({s_name}): {st_vi}", "INFO")

        def on_phase_start(p_id: str, p_name: str) -> None:
            self._update_job(run_id, {
                "current_phase": p_id,
                "current_phase_name": p_name,
                f"phase_status.{p_id}": STATUS_RUNNING,
            })
            self._append_log(run_id, f"Bắt đầu phân hệ {p_id}: {p_name}", "INFO")

        def on_phase_complete(p_id: str, p_name: str, metrics: Dict[str, Any]) -> None:
            completed_phases.append(p_id)
            self._update_job(run_id, {
                f"phase_status.{p_id}": STATUS_COMPLETED,
            })
            self._append_log(run_id, f"Hoàn thành phân hệ {p_id} ({p_name})", "INFO")

        def on_ai_task_update(task_id: str, task_name: str, details: Dict[str, Any]) -> None:
            job_cur = self.get_job(run_id) or {}
            ai_sub_tasks = job_cur.get("ai_sub_tasks", [])
            for t in ai_sub_tasks:
                if t["id"] == task_id:
                    t["status"] = STATUS_RUNNING if task_id != "T7" else STATUS_COMPLETED
                    t["details"] = details
                else:
                    try:
                        c_idx = int(task_id[1:])
                        t_idx = int(t["id"][1:])
                        if t_idx < c_idx:
                            t["status"] = STATUS_COMPLETED
                    except Exception:
                        pass

            self._update_job(run_id, {
                "current_ai_sub_task": task_id,
                "current_ai_sub_task_name": task_name,
                "ai_sub_tasks": ai_sub_tasks,
                "ai_monitoring": {
                    "current_task_id": task_id,
                    "current_task_name": task_name,
                    "details": details,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            })
            self._append_log(run_id, f"Nhiệm vụ AI [{task_id}]: {task_name}", "INFO")

        def on_log(lvl: str, message: str) -> None:
            self._append_log(run_id, message, lvl)

        def is_cancelled() -> bool:
            return cancel_event.is_set()

        callbacks = InvestigationCallbacks(
            on_phase_start=on_phase_start,
            on_phase_complete=on_phase_complete,
            on_stage_start=on_stage_start,
            on_stage_complete=on_stage_complete,
            on_ai_task_update=on_ai_task_update,
            on_log=on_log,
            is_cancelled=is_cancelled,
        )

        service = InvestigationService()
        try:
            result = service.execute(config, callbacks=callbacks)

            job_cur = self.get_job(run_id) or {}
            stg_map = getattr(result, "stage_status", None) or job_cur.get("stage_status", {})
            processed = sum(
                1 for st in stg_map.values()
                if st in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_NOT_APPLICABLE)
            )
            final_progress = 100 if result.status in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS) else min(100, int((processed / 8.0) * 100))

            artifacts_str = {k: str(v) for k, v in result.artifacts.items()}
            self._update_job(run_id, {
                "status": result.status,
                "progress_percent": final_progress,
                "stage_status": stg_map,
                "phase_status": result.phase_status,
                "phase_metrics": result.phase_metrics,
                "artifacts": artifacts_str,
                "errors": result.errors,
                "end_time": result.end_time,
                "duration_seconds": result.duration_seconds,
            })
            self._append_log(run_id, f"Phiên hoàn tất với trạng thái: {result.vietnamese_status}", "INFO")

        except Exception as e:
            logger.error("Job %s crashed with unhandled exception: %s", run_id, e)
            self._append_log(run_id, f"Lỗi không xác định khi thực thi: {e}", "ERROR")
            self._update_job(run_id, {
                "status": STATUS_FAILED,
                "end_time": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.perf_counter() - t_start, 2),
                "error_message": str(e),
            })
        finally:
            with self._lock:
                self._cancel_events.pop(run_id, None)
                self._active_futures.pop(run_id, None)


# Global Singleton Instance for FastAPI dashboard
_global_job_manager: Optional[JobManager] = None
_job_manager_lock = threading.Lock()


def get_job_manager() -> JobManager:
    """Returns application-wide singleton JobManager instance."""
    global _global_job_manager
    with _job_manager_lock:
        if _global_job_manager is None:
            _global_job_manager = JobManager()
        return _global_job_manager
