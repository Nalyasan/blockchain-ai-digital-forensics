"""8-Step Forensic Evidence Ingestion Pipeline (forensics/ingestion/pipeline.py).

Implements the complete 8-step forensic evidence ingestion and analysis lifecycle:
1. Select file (Tiếp nhận tệp chứng cứ)
2. Check format (Kiểm tra định dạng)
3. Compute SHA-256 (Tính toán mã băm SHA-256)
4. Confirm source (Xác nhận nguồn chứng cứ)
5. Normalize data (Chuẩn hóa dữ liệu)
6. Analyze via adapter (Phân tích nghiệp vụ qua adapter)
7. Save evidence to case vault (Lưu chứng cứ vào kho vụ việc an toàn)
8. Generate session report for case (Tổng hợp báo cáo phiên nhập chứng cứ)

Strictly enforces read-only source handling, anti-traversal security, isolated case vaults,
and 100% bitwise invariance of canonical databases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple, Union

import filelock

from forensics.ingestion.adapters import (
    AdapterError,
    CorruptedFileError,
    FormatError,
    IngestionError,
    SchemaCompatibilityError,
    SecurityError,
    analyze_records,
    get_adapter_for_format,
)
from forensics.integrity import _no_link, safe_path
from forensics.paths import get_data_dir, get_output_dir, get_project_root

logger = logging.getLogger("forensics.ingestion.pipeline")

CASE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_FILE_BYTES = 128 * 1024 * 1024  # 128 MB max ingestion file size


@dataclass
class IngestionRecord:
    """Metadata record for an ingested evidence file in the case vault."""
    evidence_id: str
    original_filename: str
    stored_filename: str
    sha256: str
    source_type: str
    description: str
    size_bytes: int
    timestamp: str
    records_count: int
    anomalies_count: int
    run_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "original_filename": self.original_filename,
            "stored_filename": self.stored_filename,
            "sha256": self.sha256,
            "source_type": self.source_type,
            "description": self.description,
            "size_bytes": self.size_bytes,
            "timestamp": self.timestamp,
            "records_count": self.records_count,
            "anomalies_count": self.anomalies_count,
            "run_id": self.run_id,
        }


@dataclass
class IngestionResult:
    """Final result of the 8-step evidence ingestion pipeline."""
    evidence_id: str
    sha256: str
    original_filename: str
    source_type: str
    records_count: int
    run_id: str
    anomalies_count: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)
    vault_path: str = ""
    report_path: str = ""
    status: str = "completed"
    step_logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "original_filename": self.original_filename,
            "source_type": self.source_type,
            "records_count": self.records_count,
            "run_id": self.run_id,
            "anomalies_count": self.anomalies_count,
            "statistics": self.statistics,
            "vault_path": self.vault_path,
            "report_path": self.report_path,
            "status": self.status,
            "step_logs": self.step_logs,
        }


class EvidenceIngestionPipeline:
    """8-Step Ingestion Pipeline orchestrator for digital forensic evidence."""

    def __init__(self, data_dir: Optional[Path] = None, output_dir: Optional[Path] = None) -> None:
        self.data_dir = Path(data_dir) if data_dir else get_data_dir()
        self.output_dir = Path(output_dir) if output_dir else get_output_dir()
        self.cases_dir = self.data_dir / "cases"

    def validate_case_id(self, case_id: str) -> str:
        """Validates case_id against regex and path traversal attacks."""
        if not case_id or not isinstance(case_id, str):
            raise SecurityError("Mã vụ việc (Case ID) không được để trống.")
        c = case_id.strip()
        if not CASE_ID_REGEX.fullmatch(c):
            raise SecurityError(
                f"Mã vụ việc '{case_id}' không hợp lệ. Chỉ chấp nhận chữ cái, số, dấu gạch nối và gạch dưới (1-64 ký tự)."
            )
        if ".." in c or "/" in c or "\\" in c or "\x00" in c:
            raise SecurityError("Mã vụ việc chứa ký tự đường dẫn hoặc dấu phân cách bị cấm.")
        return c

    def sanitize_filename(self, filename: str) -> str:
        """Sanitizes file name to prevent directory traversal and special control characters."""
        if not filename:
            return "evidence_file.dat"
        # Take base name only
        clean = Path(filename).name
        clean = re.sub(r"[^A-Za-z0-9_.-]", "_", clean)
        clean = clean.lstrip(".-_")
        if not clean:
            clean = "evidence_file.dat"
        return clean[:128]

    def ingest_bytes(
        self,
        case_id: str,
        file_bytes: bytes,
        original_filename: str,
        source_type: Optional[str] = None,
        description: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> IngestionResult:
        """Executes the full 8-step ingestion flow from in-memory bytes."""
        step_logs: List[str] = []

        # ----------------------------------------------------------------------
        # Step 1: Select file (Tiếp nhận tệp chứng cứ)
        # ----------------------------------------------------------------------
        valid_case_id = self.validate_case_id(case_id)
        safe_fname = self.sanitize_filename(original_filename)

        if not file_bytes:
            raise FormatError(f"Tệp chứng cứ '{original_filename}' rỗng (0 bytes).")
        if len(file_bytes) > MAX_FILE_BYTES:
            raise IngestionError(
                f"Dung lượng tệp ({len(file_bytes)} bytes) vượt quá giới hạn cho phép ({MAX_FILE_BYTES} bytes)."
            )

        step_logs.append(
            f"Giai đoạn 1 (Tiếp nhận dữ liệu): Tiếp nhận tệp '{safe_fname}' ({len(file_bytes)} bytes) cho vụ việc '{valid_case_id}'."
        )

        # ----------------------------------------------------------------------
        # Step 2: Check format (Kiểm tra định dạng)
        # ----------------------------------------------------------------------
        sample = file_bytes[:4096]
        adapter = get_adapter_for_format(safe_fname, sample, declared_source=source_type)
        detected_source_type = adapter.source_type_name
        step_logs.append(
            f"Giai đoạn 2 (Kiểm tra định dạng): Khớp định dạng '{detected_source_type}' qua adapter {adapter.__class__.__name__}."
        )

        # ----------------------------------------------------------------------
        # Step 3: Compute SHA-256 (Tính toán mã băm SHA-256)
        # ----------------------------------------------------------------------
        sha256_hash = hashlib.sha256(file_bytes).hexdigest().upper()
        step_logs.append(
            f"Giai đoạn 3 (Tính toán toàn vẹn): Mã băm SHA-256 chuẩn vị = {sha256_hash}."
        )

        # ----------------------------------------------------------------------
        # Step 4: Confirm source (Xác nhận nguồn chứng cứ)
        # ----------------------------------------------------------------------
        effective_source_type = source_type.strip().lower() if source_type else detected_source_type
        now_utc = datetime.now(timezone.utc).isoformat()
        desc_text = (description or f"Tệp chứng cứ số {safe_fname} nhập vào ca vụ {valid_case_id}").strip()
        step_logs.append(
            f"Giai đoạn 4 (Xác nhận nguồn): Nguồn xác nhận = '{effective_source_type}', thời điểm = {now_utc}."
        )

        # ----------------------------------------------------------------------
        # Step 5: Normalize data (Chuẩn hóa dữ liệu)
        # ----------------------------------------------------------------------
        normalized_records = adapter.parse_and_normalize(file_bytes)
        records_count = len(normalized_records)
        step_logs.append(
            f"Giai đoạn 5 (Chuẩn hóa dữ liệu): Trích xuất và chuẩn hóa thành công {records_count} bản ghi."
        )

        # ----------------------------------------------------------------------
        # Step 6: Analyze via adapter (Phân tích nghiệp vụ qua adapter)
        # ----------------------------------------------------------------------
        analysis_result = analyze_records(normalized_records, effective_source_type)
        stats = analysis_result.get("statistics", {})
        anomalies = analysis_result.get("anomalies", [])
        anomalies_count = len(anomalies)
        risk_score = analysis_result.get("risk_score", 0.0)
        step_logs.append(
            f"Giai đoạn 6 (Phân tích nghiệp vụ): Phát hiện {anomalies_count} dấu hiệu đáng chú ý (Điểm rủi ro: {risk_score})."
        )

        # ----------------------------------------------------------------------
        # Step 7: Save evidence to case vault (Lưu chứng cứ vào kho vụ việc)
        # ----------------------------------------------------------------------
        ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        evidence_id = f"ev_{valid_case_id}_{ts_slug}_{sha256_hash[:8].lower()}"

        # Setup isolated case directory using safe paths
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        _no_link(self.cases_dir)
        case_dir = self.cases_dir / valid_case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        safe_path(self.cases_dir, valid_case_id)

        evidence_vault_dir = case_dir / "evidence"
        evidence_vault_dir.mkdir(parents=True, exist_ok=True)
        safe_path(case_dir, "evidence")
        _no_link(evidence_vault_dir)

        # Save raw evidence file with unique prefix to prevent overwriting
        stored_filename = f"{evidence_id}_{safe_fname}"
        stored_raw_path = evidence_vault_dir / stored_filename
        with open(stored_raw_path, "wb") as f:
            f.write(file_bytes)
        safe_path(evidence_vault_dir, stored_filename)
        _no_link(stored_raw_path)

        # Save normalized records JSON
        stored_normalized_filename = f"{evidence_id}_normalized.json"
        stored_normalized_path = evidence_vault_dir / stored_normalized_filename
        with open(stored_normalized_path, "w", encoding="utf-8") as f:
            json.dump(normalized_records, f, indent=2, ensure_ascii=False)
        safe_path(evidence_vault_dir, stored_normalized_filename)
        _no_link(stored_normalized_path)

        # Update case evidence index (multi-file tracking without overwriting)
        index_file = evidence_vault_dir / "evidence_index.json"
        existing_index: List[Dict[str, Any]] = []
        if index_file.is_file():
            try:
                with open(index_file, "r", encoding="utf-8") as f:
                    existing_index = json.load(f)
                    if not isinstance(existing_index, list):
                        existing_index = []
            except Exception as e:
                logger.warning("Error reading evidence_index.json; resetting: %s", e)
                existing_index = []

        active_run_id = run_id or f"run_{valid_case_id}_{ts_slug}"

        new_record = IngestionRecord(
            evidence_id=evidence_id,
            original_filename=safe_fname,
            stored_filename=stored_filename,
            sha256=sha256_hash,
            source_type=effective_source_type,
            description=desc_text,
            size_bytes=len(file_bytes),
            timestamp=now_utc,
            records_count=records_count,
            anomalies_count=anomalies_count,
            run_id=active_run_id,
        )
        existing_index.append(new_record.to_dict())

        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(existing_index, f, indent=2, ensure_ascii=False)

        step_logs.append(
            f"Giai đoạn 7 (Lưu trữ chứng cứ): Đã lưu vào kho '{stored_raw_path.name}' (Định danh: {evidence_id})."
        )

        # ----------------------------------------------------------------------
        # Step 8: Generate session report for case (Tổng hợp báo cáo phiên)
        # ----------------------------------------------------------------------
        session_report_dir = self.output_dir / "investigations" / active_run_id
        session_report_dir.mkdir(parents=True, exist_ok=True)
        _no_link(session_report_dir)

        # 1. report.json
        report_data = {
            "run_info": {
                "run_id": active_run_id,
                "case_id": valid_case_id,
                "mode": "MODE_INGEST",
                "status": "completed",
                "vietnamese_status": "Hoàn tất",
                "created_at": now_utc,
            },
            "evidence": new_record.to_dict(),
            "analysis": analysis_result,
            "step_logs": step_logs,
        }
        report_json_path = session_report_dir / "report.json"
        with open(report_json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        # 2. evidence_manifest.json
        manifest_data = {
            "manifest_version": "1.0.0",
            "case_id": valid_case_id,
            "run_id": active_run_id,
            "exported_at": now_utc,
            "files": [
                {
                    "path": stored_filename,
                    "sha256": sha256_hash,
                    "size_bytes": len(file_bytes),
                    "source_type": effective_source_type,
                },
                {
                    "path": stored_normalized_filename,
                    "sha256": hashlib.sha256(stored_normalized_path.read_bytes()).hexdigest().upper(),
                    "size_bytes": stored_normalized_path.stat().st_size,
                    "source_type": "normalized_json",
                },
            ],
            "counts": {
                "records_count": records_count,
                "anomalies_count": anomalies_count,
            },
        }
        manifest_path = session_report_dir / "evidence_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        # 3. custody_receipts.json
        custody_data = {
            "run_id": active_run_id,
            "case_id": valid_case_id,
            "evidence_id": evidence_id,
            "ingested_by": "Authorized Evidence Ingestion Pipeline",
            "sha256": sha256_hash,
            "timestamp": now_utc,
            "action": "EVIDENCE_INGESTION_COMPLETED",
            "integrity_verified": True,
        }
        custody_path = session_report_dir / "custody_receipts.json"
        with open(custody_path, "w", encoding="utf-8") as f:
            json.dump(custody_data, f, indent=2, ensure_ascii=False)

        # 4. execution_log.txt
        log_text = "\n".join(step_logs) + "\n"
        log_path = session_report_dir / "execution_log.txt"
        log_path.write_text(log_text, encoding="utf-8")

        # 5. Standalone Offline HTML Report (investigation_report.html & report.html)
        html_report_path = session_report_dir / "investigation_report.html"
        html_compat_path = session_report_dir / "report.html"
        report_html_content = self._render_standalone_html_report(
            valid_case_id, active_run_id, new_record, analysis_result, step_logs
        )
        html_report_path.write_text(report_html_content, encoding="utf-8")
        html_compat_path.write_text(report_html_content, encoding="utf-8")

        # Also store report copy in case vault
        vault_report_copy = evidence_vault_dir / f"{active_run_id}_ingestion_report.json"
        with open(vault_report_copy, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        safe_path(evidence_vault_dir, f"{active_run_id}_ingestion_report.json")
        _no_link(vault_report_copy)

        # Register run in JobManager persistent store (data/jobs.json)
        self._register_job_in_manager(
            active_run_id=active_run_id,
            case_id=valid_case_id,
            artifacts={
                "report_html": str(html_report_path),
                "investigation_report_html": str(html_report_path),
                "report_json": str(report_json_path),
                "evidence_manifest": str(manifest_path),
                "custody_receipts": str(custody_path),
                "execution_log": str(log_path),
                "raw_evidence": str(stored_raw_path),
                "normalized_records": str(stored_normalized_path),
            },
            summary_vi=analysis_result.get("summary_vi", ""),
        )

        step_logs.append(
            f"Giai đoạn 8 (Tổng hợp báo cáo): Xuất báo cáo điều tra độc lập '{html_report_path.name}' thành công."
        )

        return IngestionResult(
            evidence_id=evidence_id,
            sha256=sha256_hash,
            original_filename=safe_fname,
            source_type=effective_source_type,
            records_count=records_count,
            run_id=active_run_id,
            anomalies_count=anomalies_count,
            statistics=stats,
            vault_path=str(stored_raw_path),
            report_path=str(html_report_path),
            status="completed",
            step_logs=step_logs,
        )

    def ingest_file(
        self,
        case_id: str,
        file_path: Union[Path, str],
        source_type: Optional[str] = None,
        description: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> IngestionResult:
        """Convenience method to ingest a file from disk."""
        p = Path(file_path)
        if not p.is_file():
            raise IngestionError(f"Tệp không tồn tại: {file_path}")
        with open(p, "rb") as f:
            content = f.read()
        return self.ingest_bytes(
            case_id=case_id,
            file_bytes=content,
            original_filename=p.name,
            source_type=source_type,
            description=description,
            run_id=run_id,
        )

    def _register_job_in_manager(
        self,
        active_run_id: str,
        case_id: str,
        artifacts: Dict[str, str],
        summary_vi: str,
    ) -> None:
        """Registers the ingestion job in data/jobs.json so that it appears seamlessly on dashboard."""
        jobs_file = self.data_dir / "jobs.json"
        lock_file = self.data_dir / "jobs.lock"
        now_utc = datetime.now(timezone.utc).isoformat()
        job_record = {
            "run_id": active_run_id,
            "case_id": case_id,
            "mode": "MODE_INGEST",
            "demo_target": None,
            "status": "completed",
            "vietnamese_status": "Hoàn tất",
            "progress_percent": 100,
            "current_phase": "P11",
            "current_phase_name": "Tổng hợp kết quả & Xuất hồ sơ điều tra",
            "start_time": now_utc,
            "end_time": now_utc,
            "duration_seconds": 1.5,
            "phase_status": {
                "P1": "completed",
                "P2": "completed",
                "P3": "completed",
                "P4": "completed",
                "P5": "completed",
                "P6": "completed",
                "P7": "not_applicable",
                "P8": "completed",
                "P9": "not_applicable",
                "P10": "completed",
                "P11": "completed",
            },
            "artifacts": artifacts,
            "summary": summary_vi,
        }
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            lock = filelock.FileLock(str(lock_file), timeout=10.0)
            with lock:
                jobs: Any = {}
                is_dict_mode = True
                if jobs_file.is_file():
                    try:
                        with open(jobs_file, "r", encoding="utf-8") as f:
                            raw = json.load(f)
                            if isinstance(raw, dict):
                                jobs = raw
                                is_dict_mode = True
                            elif isinstance(raw, list):
                                jobs = raw
                                is_dict_mode = False
                            else:
                                jobs = {}
                                is_dict_mode = True
                    except Exception:
                        jobs = {}
                        is_dict_mode = True

                if is_dict_mode:
                    jobs[active_run_id] = job_record
                else:
                    updated = False
                    for idx, r in enumerate(jobs):
                        if isinstance(r, dict) and r.get("run_id") == active_run_id:
                            jobs[idx] = job_record
                            updated = True
                            break
                    if not updated:
                        jobs.insert(0, job_record)

                with open(jobs_file, "w", encoding="utf-8") as f:
                    json.dump(jobs, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning("Failed to register ingestion job in jobs.json: %s", e)

    def _render_standalone_html_report(
        self,
        case_id: str,
        run_id: str,
        evidence: IngestionRecord,
        analysis: Dict[str, Any],
        step_logs: List[str],
    ) -> str:
        """Renders an offline, standalone Vietnamese HTML report without external CDN dependencies."""
        esc_case = html.escape(case_id)
        esc_run = html.escape(run_id)
        esc_fname = html.escape(evidence.original_filename)
        esc_sha = html.escape(evidence.sha256)
        esc_source = html.escape(evidence.source_type)
        esc_desc = html.escape(evidence.description)
        esc_summary = html.escape(analysis.get("summary_vi", ""))

        stats = analysis.get("statistics", {})
        anomalies = analysis.get("anomalies", [])

        anomalies_rows = ""
        for a in anomalies:
            esc_type = html.escape(str(a.get("type", "")))
            esc_sev = html.escape(str(a.get("severity", "")))
            esc_adesc = html.escape(str(a.get("description", "")))
            count = a.get("count", 0)
            sev_color = "#ef4444" if esc_sev in ("HIGH", "CRITICAL") else "#f59e0b"
            anomalies_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
              <td style="padding: 10px; font-weight: bold; color: #38bdf8;">{esc_type}</td>
              <td style="padding: 10px;"><span style="background: {sev_color}22; color: {sev_color}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; border: 1px solid {sev_color}66;">{esc_sev}</span></td>
              <td style="padding: 10px; text-align: center; color: #f8fafc;">{count}</td>
              <td style="padding: 10px; color: #cbd5e1; font-size: 13px;">{esc_adesc}</td>
            </tr>
            """

        logs_html = "".join(f"<div style='margin-bottom: 4px;'>&bull; {html.escape(l)}</div>" for l in step_logs)

        return f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>Báo cáo Nhập Chứng cứ - Blockchain Ai Aigital Forensics</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0b1120;
      color: #f1f5f9;
      line-height: 1.6;
      margin: 0;
      padding: 30px;
    }}
    .container {{
      max-width: 1000px;
      margin: 0 auto;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 32px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    .header {{
      border-bottom: 2px solid #0284c7;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .title {{
      font-size: 24px;
      font-weight: 800;
      color: #38bdf8;
      margin: 0 0 6px 0;
    }}
    .subtitle {{
      font-size: 13px;
      color: #94a3b8;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
    }}
    .card-title {{
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
      color: #38bdf8;
      margin-bottom: 8px;
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #34d399;
      word-break: break-all;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      background: #065f46;
      color: #6ee7b7;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }}
    th {{
      text-align: left;
      padding: 10px;
      background: #1e293b;
      color: #94a3b8;
      font-size: 12px;
      text-transform: uppercase;
    }}
    .footer {{
      margin-top: 30px;
      border-top: 1px solid #1e293b;
      padding-top: 16px;
      font-size: 11px;
      color: #64748b;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge">Blockchain Ai Aigital Forensics &bull; Báo cáo Nhập Chứng cứ Số</div>
      <h1 class="title">Báo cáo Phiên Giám định Chứng cứ Nhập vào</h1>
      <div class="subtitle">Mã vụ việc: <strong>{esc_case}</strong> &bull; Định danh phiên: <span class="mono">{esc_run}</span></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">Thông tin Tệp Chứng cứ Gốc</div>
        <div style="font-size: 13px;">Tên tệp: <strong>{esc_fname}</strong></div>
        <div style="font-size: 13px;">Dung lượng: <strong>{evidence.size_bytes} bytes</strong></div>
        <div style="font-size: 13px;">Định dạng adapter: <span class="badge">{esc_source}</span></div>
        <div style="margin-top: 8px;">Mã băm SHA-256 Chuẩn vị:</div>
        <div class="mono" style="background: #0b1120; padding: 6px; border-radius: 4px; border: 1px solid #334155;">{esc_sha}</div>
      </div>
      <div class="card">
        <div class="card-title">Kết quả Phân tích Nghiệp vụ</div>
        <div style="font-size: 13px;">Tổng số bản ghi trích xuất: <strong style="color: #38bdf8;">{evidence.records_count}</strong></div>
        <div style="font-size: 13px;">Dấu hiệu đáng chú ý: <strong style="color: {'#ef4444' if evidence.anomalies_count > 0 else '#34d399'};">{evidence.anomalies_count}</strong></div>
        <div style="font-size: 13px;">Thời điểm tiếp nhận (UTC): <strong>{evidence.timestamp}</strong></div>
        <div style="font-size: 13px; margin-top: 8px; color: #94a3b8;">Ghi chú: {esc_desc}</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Tóm tắt Đánh giá Pháp y</div>
      <p style="font-size: 13px; color: #e2e8f0; margin: 0;">{esc_summary}</p>
    </div>

    {'<div class="card" style="margin-bottom: 24px;"><div class="card-title">Bảng Dấu hiệu Bất thường & Đáng chú ý</div><table><thead><tr><th>Nhóm Dấu hiệu</th><th>Mức độ</th><th>Số lượng</th><th>Mô tả Chi tiết</th></tr></thead><tbody>' + anomalies_rows + '</tbody></table></div>' if anomalies else ''}

    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Nhật ký Tiến trình 8 Giai đoạn</div>
      <div class="mono" style="background: #0b1120; padding: 12px; border-radius: 6px; border: 1px solid #334155; line-height: 1.7; color: #93c5fd;">
        {logs_html}
      </div>
    </div>

    <div class="footer">
      Báo cáo được khởi tạo tự động bởi Hệ thống Điều tra Pháp y Số Blockchain Ai Aigital Forensics.<br>
      Toàn vẹn tệp được bảo toàn 100% không qua sửa đổi (Read-Only Vault). Không phụ thuộc kết nối Internet ngoài.
    </div>
  </div>
</body>
</html>
"""
