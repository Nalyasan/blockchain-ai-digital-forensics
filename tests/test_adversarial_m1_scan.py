"""Adversarial Scanner for Milestone 1: Jargon Elimination & UI Conformance.

Author: Empirical Challenger (critic, specialist)
Targets:
- Forbidden technical jargon in templates and rendered HTML:
  "Mode A", "Mode B", "P1".."P11", "R4".."R8", "PASS/FAIL", "VICTORY CONFIRMED", "VERIFIED"
- Static hardcoded mock numbers (e.g. fake Shapley values, static stats)
- Empty state message "Chưa có dữ liệu điều tra" across all 8 business pages
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Dict, List, Tuple
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from dashboard.services.job_manager import get_job_manager

FORBIDDEN_JARGON_PATTERNS: Dict[str, str] = {
    "Mode A": r"\bMode\s+A\b",
    "Mode B": r"\bMode\s+B\b",
    "P1..P11": r"\bP(1[01]|[1-9])\b",
    "R4..R8": r"\bR[4-8]\b",
    "PASS/FAIL": r"PASS\s*/\s*FAIL",
    "VICTORY CONFIRMED": r"VICTORY\s+CONFIRMED",
    "VERIFIED": r"\bVERIFIED\b",
}

BUSINESS_PAGES: List[Tuple[str, str]] = [
    ("/", "Tổng quan"),
    ("/progress", "Tiến độ"),
    ("/evidence", "Chứng cứ"),
    ("/ai", "Phân tích AI"),
    ("/ml-xai", "Phân tích bất thường"),
    ("/blockchain", "Bảo quản chứng cứ"),
    ("/zkml", "Xác minh suy luận"),
    ("/reports", "Báo cáo điều tra"),
]


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


def mask_non_ui_content(html_content: str, mask_jinja: bool = False) -> str:
    """Masks non-visible content (<script>, <style>, HTML comments, and optionally Jinja tags)
    with spaces while preserving line breaks and original line positions.

    This adheres strictly to Requirement R1:
    'Loại bỏ hoàn toàn các phụ đề và thuật ngữ kỹ thuật nội bộ (Mode A/B, P1–P11, R4–R8,
    PASS/FAIL, VICTORY CONFIRMED, VERIFIED) khỏi giao diện nghiệp vụ người dùng...
    trong khi vẫn lưu giữ đầy đủ log kỹ thuật, API schema và hồ sơ kiểm toán.'

    Technical JavaScript mapping structures (such as stagePhaseMapping translating UI stages
    to internal phases) and backend API schema queries (such as phase_metrics.get("P8"))
    are excluded from visible UI presentation checks.
    """
    def repl(m: re.Match) -> str:
        # Preserve newlines so reported line numbers exactly match original file lines
        return re.sub(r"[^\n]", " ", m.group(0))

    # Mask script blocks containing internal logic & schema mappings
    text = re.sub(r"<script\b[^>]*>[\s\S]*?</script>", repl, html_content, flags=re.IGNORECASE)
    # Mask style blocks
    text = re.sub(r"<style\b[^>]*>[\s\S]*?</style>", repl, text, flags=re.IGNORECASE)
    # Mask HTML comments
    text = re.sub(r"<!--[\s\S]*?-->", repl, text)

    if mask_jinja:
        # Mask Jinja control blocks {% ... %} and variable access {{ ... }}
        # which hold technical schema queries like selected_job.phase_metrics.get("P8")
        text = re.sub(r"\{%[\s\S]*?%\}", repl, text)
        text = re.sub(r"\{\{[\s\S]*?\}\}", repl, text)

    return text


def test_scan_templates_for_forbidden_jargon():
    """Scans all Jinja2 HTML templates for forbidden jargon in visible UI markup."""
    templates_dir = Path("dashboard/templates")
    findings = []

    for tpl_path in sorted(templates_dir.glob("*.html")):
        raw_content = tpl_path.read_text(encoding="utf-8")
        content = mask_non_ui_content(raw_content, mask_jinja=True)
        for label, pat in FORBIDDEN_JARGON_PATTERNS.items():
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = content[:m.start()].count("\n") + 1
                line = raw_content.splitlines()[line_no - 1].strip()
                findings.append({
                    "file": tpl_path.name,
                    "line": line_no,
                    "pattern": label,
                    "content": line,
                })

    # Save to a structured artifact
    output_file = Path("tests/m1_scan_templates_jargon.json")
    output_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    assert len(findings) == 0, f"Found {len(findings)} forbidden jargon occurrences in visible template UI markup: {findings}"


def test_scan_rendered_pages_empty_state_for_forbidden_jargon(client: TestClient):
    """Scans all rendered HTML pages in empty/default state for forbidden jargon in visible UI."""
    urls = [
        "/",
        "/launcher",
        "/progress",
        "/evidence",
        "/ai",
        "/ml-xai",
        "/blockchain",
        "/zkml",
        "/demo-center",
        "/reports",
        "/settings",
    ]
    findings = []
    for u in urls:
        res = client.get(u)
        assert res.status_code == 200
        raw_text = res.text
        text = mask_non_ui_content(raw_text, mask_jinja=False)
        for label, pat in FORBIDDEN_JARGON_PATTERNS.items():
            for m in re.finditer(pat, text, re.IGNORECASE):
                line_no = text[:m.start()].count("\n") + 1
                line = raw_text.splitlines()[line_no - 1].strip()
                findings.append({
                    "url": u,
                    "line": line_no,
                    "pattern": label,
                    "content": line,
                })

    output_file = Path("tests/m1_scan_rendered_empty_jargon.json")
    output_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    assert len(findings) == 0, f"Found {len(findings)} forbidden jargon occurrences in rendered empty pages: {findings}"


def test_scan_rendered_pages_with_job_for_forbidden_jargon(client: TestClient):
    """Submits a job and scans all rendered HTML pages with active job data for forbidden jargon in visible UI."""
    res = client.post("/api/investigations", json={
        "case_id": "scan-adv-002",
        "continue_case": True,
        "mode": "MODE_A",
        "demo_target": "D1",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
    })
    assert res.status_code == 201
    run_id = res.json()["run_id"]

    urls = [
        f"/?case_id=scan-adv-002&run_id={run_id}",
        f"/progress?case_id=scan-adv-002&run_id={run_id}",
        f"/evidence?case_id=scan-adv-002&run_id={run_id}",
        f"/ai?case_id=scan-adv-002&run_id={run_id}",
        f"/ml-xai?case_id=scan-adv-002&run_id={run_id}",
        f"/blockchain?case_id=scan-adv-002&run_id={run_id}",
        f"/zkml?case_id=scan-adv-002&run_id={run_id}",
        f"/reports?case_id=scan-adv-002",
        f"/reports/{run_id}",
    ]
    findings = []
    for u in urls:
        res = client.get(u)
        assert res.status_code == 200
        raw_text = res.text
        text = mask_non_ui_content(raw_text, mask_jinja=False)
        for label, pat in FORBIDDEN_JARGON_PATTERNS.items():
            for m in re.finditer(pat, text, re.IGNORECASE):
                line_no = text[:m.start()].count("\n") + 1
                line = raw_text.splitlines()[line_no - 1].strip()
                findings.append({
                    "url": u,
                    "line": line_no,
                    "pattern": label,
                    "content": line,
                })

    output_file = Path("tests/m1_scan_rendered_job_jargon.json")
    output_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    assert len(findings) == 0, f"Found {len(findings)} forbidden jargon occurrences in rendered job pages: {findings}"


def test_visible_jargon_leak_adversarial_detection():
    """Confirms that the scanner genuinely catches visible jargon leaks when present in UI markup."""
    sample_leak = "<h2 class='font-bold'>Giai đoạn Mode A: EVM Replay P5 PASS/FAIL</h2>"
    processed = mask_non_ui_content(sample_leak)
    detected = []
    for label, pat in FORBIDDEN_JARGON_PATTERNS.items():
        if re.search(pat, processed, re.IGNORECASE):
            detected.append(label)
    assert "Mode A" in detected
    assert "P1..P11" in detected
    assert "PASS/FAIL" in detected



def test_hardcoded_mock_numbers_scan(client: TestClient):
    """Checks if any page displays static mock Shapley values or fake stats."""
    res_ml = client.get("/ml-xai?case_id=nonexistent&run_id=nonexistent")
    assert res_ml.status_code == 200
    # Must NOT have fake Shapley values
    assert "+0.3842" not in res_ml.text
    assert "-0.1420" not in res_ml.text


def test_empty_state_compliance_across_8_business_pages(client: TestClient, monkeypatch):
    """Verifies that all 8 business pages show 'Chưa có dữ liệu điều tra' when accessed without an active case or run."""
    jm = get_job_manager()
    monkeypatch.setattr(jm, "list_jobs", lambda *args, **kwargs: [])
    monkeypatch.setattr(jm, "get_active_job", lambda: None)

    REQUIRED_PHRASE = "Chưa có dữ liệu điều tra"
    missing_pages = []

    for path, name in BUSINESS_PAGES:
        res = client.get(path)
        assert res.status_code == 200
        if REQUIRED_PHRASE not in res.text:
            missing_pages.append({"page": name, "path": path})

    output_file = Path("tests/m1_scan_empty_state.json")
    output_file.write_text(json.dumps({
        "required_phrase": REQUIRED_PHRASE,
        "missing_pages": missing_pages,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    assert not missing_pages, f"Pages missing '{REQUIRED_PHRASE}': {missing_pages}"
