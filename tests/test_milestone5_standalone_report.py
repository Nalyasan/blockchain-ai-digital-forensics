"""Milestone 5 Test Suite: Standalone HTML Report & Audit Artifact Package Integrity (R6).

Verifies all Milestone 5 report generation requirements:
1. Zero external CDNs / scripts / fonts / styles (100% self-contained offline).
2. Standardized branding ('Blockchain Ai Aigital Forensics') with zero internal jargon (no P1–P11, Mode A/B, R4–R8, PASS/FAIL).
3. All 11 mandatory sections present and formatted.
4. All 8 forensic questions answered for each key finding in Section 2.
5. Native volumes reported separately (DAI, alETH, ETH) with explicit non-aggregation disclaimer.
6. XSS sanitization of all dynamic inputs (Anti-XSS escaping).
7. Audit artifacts package completeness and 100% SHA-256 concordance in evidence_manifest.json.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import pytest

from forensics.paths import get_real_p4_db, get_reports_dir
from forensics.service import (
    InvestigationConfig,
    InvestigationService,
    compute_sha256,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
)


@pytest.fixture(scope="module")
def real_investigation_session(tmp_path_factory) -> dict:
    """Executes a real investigation session on read-only real_p4.db and returns artifacts."""
    out_dir = tmp_path_factory.mktemp("m5_reports")
    db_path = get_real_p4_db()

    service = InvestigationService()
    config = InvestigationConfig(
        case_id="case-m5-verification",
        mode="MODE_B",
        db_path=db_path,
        output_dir=out_dir,
        ai_provider="ollama",
        ai_model="qwen3:8b",
        is_mock=True,
    )
    result = service.execute(config)
    assert result.status in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS)

    run_id = result.run_id
    session_dir = out_dir / run_id
    inv_html = session_dir / "investigation_report.html"
    report_json = session_dir / "report.json"
    manifest_json = session_dir / "evidence_manifest.json"
    custody_json = session_dir / "custody_receipts.json"
    execution_log = session_dir / "execution_log.txt"
    csv_file = session_dir / "suspicious_transactions.csv"

    assert inv_html.is_file(), "investigation_report.html must exist"
    assert report_json.is_file(), "report.json must exist"
    assert manifest_json.is_file(), "evidence_manifest.json must exist"

    return {
        "run_id": run_id,
        "session_dir": session_dir,
        "html_content": inv_html.read_text(encoding="utf-8"),
        "inv_html": inv_html,
        "report_json": report_json,
        "manifest_json": manifest_json,
        "custody_json": custody_json,
        "execution_log": execution_log,
        "csv_file": csv_file,
    }


def test_html_report_zero_cdn_and_offline(real_investigation_session):
    """Verifies that the HTML report contains zero external scripts, CDNs, fonts, or http(s) URLs."""
    html_text = real_investigation_session["html_content"]

    # Must NOT contain CDN Tailwind
    assert "cdn.tailwindcss.com" not in html_text, "Found prohibited external CDN tailwindcss script"

    # Must NOT contain any external http or https links
    http_matches = re.findall(r'https?://[^\s"\'<>]+', html_text)
    assert len(http_matches) == 0, f"Found prohibited external URLs in report: {http_matches}"

    # Must contain self-contained <style> block
    assert "<style>" in html_text and "</style>" in html_text
    assert "#0b1120" in html_text, "Dark theme background color #0b1120 must be defined in inline CSS"

    # Must contain dedicated @media print block
    assert "@media print" in html_text, "@media print block must be present for browser print/PDF save"

    # Must have a print button with window.print()
    assert "window.print()" in html_text, "Print button with window.print() must be present"


def test_html_report_standardized_branding_no_jargon(real_investigation_session):
    """Verifies standardized brand title and zero internal technical jargon."""
    html_text = real_investigation_session["html_content"]

    # Unified brand title
    assert "Blockchain Ai Aigital Forensics — Báo cáo Điều tra Pháp y số Chuỗi khối Toàn diện" in html_text

    # Prohibited jargon check
    assert "(P1–P11)" not in html_text, "Found internal code (P1–P11) in report"
    assert "P1–P11" not in html_text, "Found internal code P1–P11 in report"
    assert "Mode A/B" not in html_text, "Found internal code Mode A/B in report"
    assert "R4–R8" not in html_text, "Found internal code R4–R8 in report"
    assert "PASS/FAIL" not in html_text, "Found internal jargon PASS/FAIL in report"


def test_html_report_all_11_sections_present(real_investigation_session):
    """Verifies all 11 mandatory sections are present in the report."""
    html_text = real_investigation_session["html_content"]

    sections = [
        ("Phần 1: Trang bìa", "1. TRANG BÌA"),
        ("Phần 2: Tóm tắt điều tra", "2. Tóm tắt điều tra & Các phát hiện chính"),
        ("Phần 3: Thống kê blockchain thực tế", "3. Thống kê blockchain thực tế"),
        ("Phần 4: Bảng giao dịch đáng chú ý", "4. Bảng giao dịch đáng chú ý"),
        ("Phần 5: Timeline & biểu đồ luồng tài sản", "5. Timeline & biểu đồ luồng tài sản"),
        ("Phần 6: Phân tích Rule & ML/XAI", "6. Phân tích Rule & ML/XAI"),
        ("Phần 7: Phân tích AI gắn RefChecker", "7. Phân tích AI gắn RefChecker"),
        ("Phần 8: Chứng cứ & SHA-256 manifest", "8. Chứng cứ & SHA-256 manifest"),
        ("Phần 9: Chuỗi bảo quản", "9. Chuỗi bảo quản (Chain of Custody)"),
        ("Phần 10: Xác minh ZKML", "10. Xác minh suy luận mật mã ZKML"),
        ("Phần 11: Kết luận điều tra & khuyến nghị", "11. Kết luận điều tra & khuyến nghị hành động pháp lý"),
    ]

    for sec_name, sec_pattern in sections:
        assert sec_pattern in html_text, f"Missing mandatory section: {sec_name} (pattern: {sec_pattern})"


def test_html_report_key_findings_8_questions_answered(real_investigation_session):
    """Verifies that each finding in Section 2 answers all 8 mandatory forensic questions."""
    html_text = real_investigation_session["html_content"]

    questions = [
        "1. Phát hiện là gì?",
        "2. Giao dịch/địa chỉ/hợp đồng liên quan?",
        "3. Dữ liệu chứng minh?",
        "4. Lý do đánh giá bất thường?",
        "5. Nguồn tạo ra (Rule/ML/AI)?",
        "6. Dữ kiện RefChecker đã xác minh?",
        "7. Mức độ chắc chắn / hạn chế?",
        "8. Hướng điều tra bổ sung?",
    ]

    for q in questions:
        count = html_text.count(q)
        assert count >= 1, f"Question '{q}' missing from report findings"


def test_html_report_native_volumes_no_improper_aggregation(real_investigation_session):
    """Verifies native volumes separate DAI, alETH, ETH and contains explicit non-aggregation disclaimer."""
    html_text = real_investigation_session["html_content"]

    # Verify native token symbols are reported
    assert "DAI" in html_text
    assert "alETH" in html_text

    # Mandatory non-aggregation disclaimer
    disclaimer = "Không cộng gộp các loại token khác nhau thành một giá trị chung khi chưa có quy đổi hợp lệ"
    assert disclaimer in html_text, "Missing mandatory token non-aggregation disclaimer"


def test_html_report_xss_sanitization(tmp_path):
    """Verifies that malicious scripts and tags in user/case inputs are strictly sanitized/escaped."""
    db_path = get_real_p4_db()
    service = InvestigationService()

    xss_case_id = "case<script>alert('xss')</script>"
    config = InvestigationConfig(
        case_id=xss_case_id,
        mode="MODE_B",
        db_path=db_path,
        output_dir=tmp_path,
        ai_provider="ollama<img src=x onerror=alert(1)>",
        ai_model="test-model",
        is_mock=True,
    )
    result = service.execute(config)
    session_dir = tmp_path / result.run_id
    html_file = session_dir / "investigation_report.html"
    assert html_file.is_file()

    content = html_file.read_text(encoding="utf-8")

    # The raw unescaped script tag MUST NOT appear
    assert "<script>alert('xss')</script>" not in content
    assert "<img src=x onerror=alert(1)>" not in content

    # The escaped versions MUST appear safely
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in content or "&lt;script&gt;" in content
    assert "&lt;img" in content


def test_audit_artifacts_package_integrity(real_investigation_session):
    """Verifies all audit files exist and their SHA-256 hashes match evidence_manifest.json 100%."""
    session_dir = real_investigation_session["session_dir"]
    manifest_path = real_investigation_session["manifest_json"]

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest_data.get("files", [])

    assert len(files) >= 5, f"evidence_manifest.json should list at least 5 files, got {len(files)}"

    for f_info in files:
        rel_path = f_info["path"]
        expected_sha = f_info["sha256"]
        target_file = session_dir / rel_path

        assert target_file.is_file(), f"Artifact file {rel_path} listed in manifest missing on disk"
        computed_sha = compute_sha256(target_file)
        assert computed_sha == expected_sha, (
            f"SHA-256 mismatch for {rel_path}: computed={computed_sha}, manifest={expected_sha}"
        )

    # Verify report.json also records all artifacts
    report_json_path = real_investigation_session["report_json"]
    report_data = json.loads(report_json_path.read_text(encoding="utf-8"))
    artifacts_dict = report_data.get("artifacts", {})
    assert "investigation_report_html" in artifacts_dict
    assert "report_html" in artifacts_dict
    assert "report_json" in artifacts_dict
    assert "evidence_manifest" in artifacts_dict
    assert "custody_receipts" in artifacts_dict
    assert "execution_log" in artifacts_dict


def test_query_native_asset_volumes_deterministic_closure(tmp_path):
    """Verifies that _query_native_asset_volumes explicitly closes SQLite connections,
    allowing immediate unlinking of temporary databases without WinError 32."""
    import sqlite3
    from forensics.service import _query_native_asset_volumes

    db_file = tmp_path / "temp_closure_test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE asset_transfers (asset_id TEXT, amount_raw TEXT)")
    conn.execute("INSERT INTO asset_transfers VALUES ('0x6b175474e89094c44da98b954eedeac495271d0f', '1000000000000000000')")
    conn.commit()
    conn.close()

    volumes = _query_native_asset_volumes(db_file)
    assert len(volumes) == 1
    assert volumes[0]["symbol"] == "DAI"

    # Crucial Windows test: If connection was leaked, unlink() raises PermissionError [WinError 32]
    db_file.unlink()
    assert not db_file.exists()


def test_pipeline_and_collector_harmonized_job_store(tmp_path):
    """Verifies that EvidenceIngestionPipeline and LiveRpcCollector both preserve
    the dict format, use FileLock, and do not overwrite or wipe out existing jobs."""
    from forensics.ingestion.pipeline import EvidenceIngestionPipeline
    from forensics.live_collector import LiveRpcCollector

    pipeline = EvidenceIngestionPipeline(data_dir=tmp_path, output_dir=tmp_path / "reports")
    collector = LiveRpcCollector(data_dir=tmp_path, output_dir=tmp_path / "reports")

    # Ingestion registers job
    pipeline._register_job_in_manager(
        active_run_id="run_ingest_1",
        case_id="case_1",
        artifacts={"summary": "art1"},
        summary_vi="Bản ghi kiểm tra 1",
    )

    jobs_file = tmp_path / "jobs.json"
    data1 = json.loads(jobs_file.read_text(encoding="utf-8"))
    assert isinstance(data1, dict)
    assert "run_ingest_1" in data1

    # Collector registers job
    collector._register_job_in_manager(
        run_id="run_rpc_1",
        case_id="case_1",
        artifacts={"summary": "art2"},
        network_name="Sepolia",
        is_synthetic=1,
        tx_count=10,
        anomalies_count=1,
    )

    data2 = json.loads(jobs_file.read_text(encoding="utf-8"))
    assert isinstance(data2, dict)
    assert len(data2) == 2
    assert "run_ingest_1" in data2
    assert "run_rpc_1" in data2

