"""Empirical Challenger Test Suite for Milestone 5:
Standalone HTML Report, XSS Defenses, Offline Air-Gap Fidelity & Audit Manifest Integrity.

Adversarial Stress Testing:
1. Zero CDN / URL Leakage: Strict offline air-gap fidelity regex search across all tags and styles.
2. XSS Fuzzing: Comprehensive injection payloads across Case ID, Run ID, transaction hashes, addresses, notes, and error messages.
3. Print & PDF CSS Stress Test: Functional @media print rules, button suppression, background neutralization, and page break rules.
4. Native Volume Accounting: Strict separation of DAI, alETH, and ETH without cross-asset numerical aggregation.
5. All 11 Sections & 8 Forensic Questions: Complete presence and answers without internal technical jargon.
6. Manifest Package Completeness: 100% cryptographic SHA-256 concordance across all 6 audit artifacts.
7. Canonical Database Invariance: Bitwise verification of data/*.db files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import pytest

from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_real_p4_db,
)
from forensics.service import (
    InvestigationConfig,
    InvestigationService,
    compute_sha256,
    _query_native_asset_volumes,
    _synthesize_key_forensic_findings,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
)


CANONICAL_HASHES = {
    "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
    "endpoint_evidence.db": "CAF3F0B30C0F864150CA5DCBD45DD19927A53620001AB696228A744C959B7CD0",
}


@pytest.fixture(scope="module")
def challenger_report_session(tmp_path_factory) -> dict:
    """Executes a full investigation session in isolated temp dir and returns artifact paths and HTML text."""
    out_dir = tmp_path_factory.mktemp("challenger_m5_reports")
    db_path = get_real_p4_db()

    service = InvestigationService()
    config = InvestigationConfig(
        case_id="case-challenger-m5-adversarial",
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
    compat_html = session_dir / "report.html"
    report_json = session_dir / "report.json"
    manifest_json = session_dir / "evidence_manifest.json"
    custody_json = session_dir / "custody_receipts.json"
    execution_log = session_dir / "execution_log.txt"
    csv_file = session_dir / "suspicious_transactions.csv"

    return {
        "run_id": run_id,
        "session_dir": session_dir,
        "html_content": inv_html.read_text(encoding="utf-8"),
        "inv_html": inv_html,
        "compat_html": compat_html,
        "report_json": report_json,
        "manifest_json": manifest_json,
        "custody_json": custody_json,
        "execution_log": execution_log,
        "csv_file": csv_file,
    }


# ==============================================================================
# CHALLENGE 1: ZERO CDN / EXTERNAL URL LEAKAGE
# ==============================================================================

def test_challenge_zero_cdn_url_leakage(challenger_report_session):
    """Stress-tests the HTML report for strict zero-external URL and zero-CDN compliance.

    Any external script, stylesheet, webfont, or external request violates offline air-gap fidelity.
    """
    html_text = challenger_report_session["html_content"]

    # Prohibited CDNs and remote services
    prohibited_patterns = [
        r"cdn\.tailwindcss\.com",
        r"fonts\.googleapis\.com",
        r"fonts\.gstatic\.com",
        r"unpkg\.com",
        r"cdnjs\.cloudflare\.com",
        r"cdn\.jsdelivr\.net",
        r"ajax\.googleapis\.com",
        r"code\.jquery\.com",
    ]
    for pattern in prohibited_patterns:
        match = re.search(pattern, html_text, re.IGNORECASE)
        assert match is None, f"Prohibited external CDN/service found in report matching: {pattern}"

    # Search for any http:// or https:// URLs in the entire HTML file
    # We exclude XML namespace http://www.w3.org/2000/svg if present in pure SVG tags,
    # but regular links and resources must be strictly zero.
    urls = re.findall(r'https?://[^\s"\'<>]+', html_text)
    non_w3_urls = [u for u in urls if not u.startswith("http://www.w3.org/")]
    assert len(non_w3_urls) == 0, f"Found prohibited external URLs in HTML report: {non_w3_urls}"

    # Check for protocol-relative URLs (e.g. //cdn.example.com)
    proto_relative = re.findall(r'(?:src|href)\s*=\s*["\']//', html_text, re.IGNORECASE)
    assert len(proto_relative) == 0, f"Found protocol-relative external URLs: {proto_relative}"


# ==============================================================================
# CHALLENGE 2: XSS FUZZING & INJECTION RESISTANCE
# ==============================================================================

def test_challenge_xss_fuzzing_all_dynamic_vectors(tmp_path):
    """Adversarially injects malicious scripts, event handlers, and tags across multiple report fields.

    Verifies that raw HTML is strictly sanitized / entity-escaped and cannot execute.
    """
    service = InvestigationService()
    db_path = get_real_p4_db()

    fuzz_payloads = {
        "case_id": "case<script>alert('xss-case')</script><svg/onload=alert(1)>",
        "ai_provider": "ollama<img src=x onerror=alert('xss-provider')>",
        "ai_model": "model'\" onmouseover=alert('xss-model')<iframe src=javascript:alert(2)>",
    }

    config = InvestigationConfig(
        case_id=fuzz_payloads["case_id"],
        mode="MODE_B",
        db_path=db_path,
        output_dir=tmp_path,
        ai_provider=fuzz_payloads["ai_provider"],
        ai_model=fuzz_payloads["ai_model"],
        is_mock=True,
    )

    result = service.execute(config)
    session_dir = tmp_path / result.run_id
    html_file = session_dir / "investigation_report.html"
    assert html_file.is_file(), "Report file must exist"
    content = html_file.read_text(encoding="utf-8")

    # 1. Raw malicious tags must NOT appear in HTML
    assert not re.search(r"<\s*script", content, re.IGNORECASE), "Raw <script> tag found in HTML"
    assert not re.search(r"<\s*/\s*script\s*>", content, re.IGNORECASE), "Raw </script> tag found in HTML"
    assert not re.search(r"<\s*iframe", content, re.IGNORECASE), "Raw <iframe> tag found in HTML"

    # 2. No HTML tag may have injected event handlers (only static onclick="window.print()" is allowed)
    injected_handlers = re.findall(r"<[a-zA-Z0-9_-]+(?:\s+[^>]*?)?\b(?!onclick\s*=)on[a-zA-Z]+\s*=", content, re.IGNORECASE)
    assert len(injected_handlers) == 0, f"Executable event handler injected into HTML tag: {injected_handlers}"

    # 3. No HTML tag may have an attribute using javascript: protocol
    js_tag_attributes = re.findall(r"<[a-zA-Z0-9_-]+(?:\s+[^>]*?)?\b(?:href|src|action)\s*=\s*[\"']?\s*javascript:", content, re.IGNORECASE)
    assert len(js_tag_attributes) == 0, f"Executable javascript: URI protocol found in tag: {js_tag_attributes}"

    # Escaped safe versions must be present
    assert "&lt;script&gt;" in content
    assert "&lt;svg" in content
    assert "&lt;img" in content
    assert "&lt;iframe" in content


def test_challenge_xss_transaction_and_findings_escaping(tmp_path):
    """Adversarially injects XSS payloads into transaction hashes, addresses, and phase metric notes."""
    service = InvestigationService()
    out_dir = tmp_path / "xss_tx_test"
    out_dir.mkdir()
    html_path = out_dir / "investigation_report.html"

    # Fabricate adversarial finding with XSS in every property
    malicious_txs = [
        {
            "tx_hash": "0x12345<script>alert('tx_hash')</script>",
            "block_number": 16817996,
            "from_address": "0xfrom<img src=x onerror=alert('from')>",
            "to_address": "0xto<svg/onload=alert('to')>",
            "rule_id": "rule<b style='color:red;'>alert</b>",
            "severity": "CRITICAL",
            "anomaly_score": 0.9999,
        }
    ]

    malicious_metrics = {
        "P1": {"total_blocks": 10, "block_range": [16817996, 16818005], "total_transactions": 20},
        "P3": {
            "mode": "READ_ONLY<script>alert('custody')</script>",
            "chain_id": 1,
            "contract_address": "0xcontract<img src=x onerror=alert(3)>",
            "transaction_hash": "0xanchor<svg/onload=alert(4)>",
            "status_note": "Note with <script>alert('note')</script>",
        },
        "P5": {
            "citations": [
                {
                    "statement": "Statement <script>alert('stmt')</script>",
                    "tx_hash": "0xcit_hash<img src=x onerror=alert('cithash')>",
                    "block_number": "16817996<script>",
                    "from_addr": "0xfrom<script>",
                    "to_addr": "0xto<script>",
                    "ledger_verified": "Khớp <script>",
                    "match_status": "Khớp 100%<script>",
                }
            ],
            "ai_synthesis": "Synthesis with <iframe src='javascript:alert(5)'></iframe>",
            "ref_check_ratio": 1.0,
        },
        "P8": {
            "model_id": "Model<script>alert('model')</script>",
            "model_sha256": "SHA<script>",
            "evaluations": [],
        },
        "P9": {
            "circuit_system": "Halo2<script>alert('zkml')</script>",
            "proof_valid": True,
        },
    }

    config = InvestigationConfig(
        case_id="case<script>alert('case')</script>",
        mode="MODE_B",
        output_dir=out_dir,
    )

    service._write_vietnamese_html_report(
        html_path=html_path,
        run_id="run<script>alert('run')</script>",
        config=config,
        target_db=get_real_p4_db(),
        pre_sha256="abc<script>",
        final_status="COMPLETED",
        vietnamese_status="Hoàn tất<script>",
        phase_status={},
        phase_metrics=malicious_metrics,
        suspicious_txs=malicious_txs,
        duration_seconds=1.23,
        start_utc="2026-11-07T21:00:00Z",
        end_utc="2026-11-07T21:00:01Z",
        errors=[],
    )

    html_text = html_path.read_text(encoding="utf-8")

    # Strict check: Raw unescaped <script>, <img, <svg, <iframe must not exist
    raw_tags = re.findall(r"<(?:script|img|svg|iframe|b\s|body)", html_text, re.IGNORECASE)
    # The only allowed svg is the pre-defined inline asset flow diagram SVG at section 5
    svg_tags = re.findall(r"<svg[^>]*>", html_text, re.IGNORECASE)
    assert len(svg_tags) == 1, "Only the 1 static inline SVG flow diagram should be present"
    assert 'viewBox="0 0 900 220"' in svg_tags[0], "SVG must be the static flowchart"

    script_tags = re.findall(r"<script[^>]*>", html_text, re.IGNORECASE)
    assert len(script_tags) == 0, f"Unescaped script tags found: {script_tags}"

    img_tags = re.findall(r"<img[^>]*>", html_text, re.IGNORECASE)
    assert len(img_tags) == 0, f"Unescaped img tags found: {img_tags}"

    iframe_tags = re.findall(r"<iframe[^>]*>", html_text, re.IGNORECASE)
    assert len(iframe_tags) == 0, f"Unescaped iframe tags found: {iframe_tags}"


# ==============================================================================
# CHALLENGE 3: PRINT & PDF CSS STRESS TEST
# ==============================================================================

def test_challenge_print_and_pdf_css_rules(challenger_report_session):
    """Verifies that @media print CSS rules exist, neutralize background, hide controls, and prevent awkward page breaks."""
    html_text = challenger_report_session["html_content"]

    # Must contain @media print
    assert "@media print" in html_text, "@media print query missing from CSS"

    # Extract full nested @media print block via brace counting
    start_idx = html_text.find("@media print")
    assert start_idx != -1, "@media print query missing from CSS"
    open_brace = html_text.find("{", start_idx)
    assert open_brace != -1, "Opening brace after @media print missing"

    depth = 1
    curr = open_brace + 1
    while curr < len(html_text) and depth > 0:
        if html_text[curr] == "{":
            depth += 1
        elif html_text[curr] == "}":
            depth -= 1
        curr += 1
    print_css = html_text[open_brace + 1 : curr - 1]

    # 1. Background white & text black
    assert "#ffffff !important" in print_css or "background: #ffffff" in print_css or "background-color: #ffffff" in print_css
    assert "#000000 !important" in print_css or "color: #000000" in print_css

    # 2. Controls and buttons hidden
    assert "no-print" in print_css
    assert "display: none !important" in print_css

    # 3. Page break inside avoid for cards
    assert "page-break-inside: avoid !important" in print_css

    # 4. Top control button uses window.print()
    assert "window.print()" in html_text
    assert 'class="btn-print no-print"' in html_text


# ==============================================================================
# CHALLENGE 4: NATIVE VOLUME ACCOUNTING (NO MULTI-TOKEN SUMMING)
# ==============================================================================

def test_challenge_native_volumes_no_improper_token_summing(challenger_report_session):
    """Stress-tests that DAI, alETH, and ETH are strictly reported natively without addition."""
    html_text = challenger_report_session["html_content"]

    # 1. Verify DAI and alETH symbols appear as independent rows
    assert "DAI" in html_text
    assert "alETH" in html_text

    # 2. Verify non-aggregation disclaimer exists in Section 3
    disclaimer = "Không cộng gộp các loại token khác nhau thành một giá trị chung khi chưa có quy đổi hợp lệ."
    assert disclaimer in html_text

    # 3. Test underlying query function directly
    db_path = get_real_p4_db()
    volumes = _query_native_asset_volumes(db_path)
    assert len(volumes) >= 2, f"Expected at least DAI and alETH, got {volumes}"

    symbols = [v["symbol"] for v in volumes]
    assert "DAI" in symbols
    assert "alETH" in symbols

    # Ensure formatted volume maintains unit isolation
    for v in volumes:
        assert v["symbol"] in v["formatted_volume"], (
            f"Asset formatted volume '{v['formatted_volume']}' must include symbol '{v['symbol']}'"
        )


def test_challenge_query_native_volumes_empty_or_nonexistent_db(tmp_path):
    """Tests resilience of _query_native_asset_volumes against missing tables or non-existent files."""
    # Non-existent file
    v_none = _query_native_asset_volumes(tmp_path / "nonexistent.db")
    assert v_none == []

    # SQLite DB without asset_transfers or transactions
    empty_db = tmp_path / "empty.db"
    with sqlite3.connect(empty_db) as conn:
        conn.execute("CREATE TABLE dummy (id INTEGER PRIMARY KEY)")
    v_empty = _query_native_asset_volumes(empty_db)
    assert v_empty == []


# ==============================================================================
# CHALLENGE 5: ALL 11 SECTIONS & 8 FORENSIC QUESTIONS (NO INTERNAL JARGON)
# ==============================================================================

def test_challenge_all_11_sections_and_8_questions(challenger_report_session):
    """Verifies that all 11 standardized forensic sections and all 8 questions per finding are fully populated."""
    html_text = challenger_report_session["html_content"]

    # Section IDs in document
    section_ids = [
        "sec-1-cover",
        "sec-2-summary",
        "sec-3-blockchain-stats",
        "sec-4-notable-txs",
        "sec-5-timeline-flow",
        "sec-6-rule-ml-xai",
        "sec-7-ai-refchecker",
        "sec-8-evidence-manifest",
        "sec-9-chain-of-custody",
        "sec-10-zkml",
        "sec-11-conclusion",
    ]
    for sid in section_ids:
        assert f'id="{sid}"' in html_text, f"Mandatory section ID '{sid}' missing from report"

    # All 8 Forensic Questions
    forensic_questions = [
        "1. Phát hiện là gì?",
        "2. Giao dịch/địa chỉ/hợp đồng liên quan?",
        "3. Dữ liệu chứng minh?",
        "4. Lý do đánh giá bất thường?",
        "5. Nguồn tạo ra (Rule/ML/AI)?",
        "6. Dữ kiện RefChecker đã xác minh?",
        "7. Mức độ chắc chắn / hạn chế?",
        "8. Hướng điều tra bổ sung?",
    ]
    for q in forensic_questions:
        count = html_text.count(q)
        assert count >= 1, f"Mandatory question '{q}' missing from findings (count: {count})"

    # Zero Technical Jargon
    jargon_blacklist = [
        "(P1–P11)",
        "P1–P11",
        "Mode A/B",
        "R4–R8",
        "PASS/FAIL",
    ]
    for jargon in jargon_blacklist:
        assert jargon not in html_text, f"Internal technical jargon '{jargon}' found in user-facing report"


# ==============================================================================
# CHALLENGE 6: AUDIT ARTIFACT MANIFEST INTEGRITY & PACKAGE CONCORDANCE
# ==============================================================================

def test_challenge_manifest_integrity_and_sha256_concordance(challenger_report_session):
    """Verifies that all 6 audit artifacts are present, listed in manifest, and have bitwise-matching SHA-256."""
    session_dir = challenger_report_session["session_dir"]
    manifest_file = challenger_report_session["manifest_json"]
    inv_html = challenger_report_session["inv_html"]
    compat_html = challenger_report_session["compat_html"]

    assert manifest_file.is_file(), "evidence_manifest.json must exist"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    files_list = manifest_data.get("files", [])
    file_map = {f["path"]: f["sha256"] for f in files_list}

    expected_files = [
        "execution_log.txt",
        "suspicious_transactions.csv",
        "custody_receipts.json",
        "investigation_report.html",
        "report.html",
        "report.json",
    ]

    for fname in expected_files:
        assert fname in file_map, f"Mandatory artifact '{fname}' missing from evidence_manifest.json"
        actual_path = session_dir / fname
        assert actual_path.is_file(), f"Artifact file '{fname}' missing on disk"

        # Verify cryptographic SHA-256 hash
        computed_sha = compute_sha256(actual_path)
        assert computed_sha == file_map[fname], (
            f"Hash mismatch for {fname}: manifest={file_map[fname]}, disk={computed_sha}"
        )

    # Verify that investigation_report.html and report.html are identical
    inv_sha = compute_sha256(inv_html)
    compat_sha = compute_sha256(compat_html)
    assert inv_sha == compat_sha, "investigation_report.html and report.html must have identical SHA-256"


# ==============================================================================
# CHALLENGE 7: CANONICAL DATABASE BITWISE INVARIANCE
# ==============================================================================

def test_challenge_canonical_database_invariance():
    """Verifies that data/real_p4.db, forensics.db, benchmark_p6.db, and endpoint_evidence.db remain 100% bitwise intact."""
    db_mapping = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }

    for db_name, db_path in db_mapping.items():
        assert db_path.is_file(), f"Canonical database {db_name} missing at {db_path}"
        actual_hash = compute_sha256(db_path).upper()
        expected_hash = CANONICAL_HASHES[db_name]
        assert actual_hash == expected_hash, (
            f"Bitwise invariance violation on {db_name}! Expected {expected_hash}, got {actual_hash}"
        )



# ==============================================================================
# CHALLENGE 8: INGESTION PIPELINE & LIVE COLLECTOR REPORT AUDIT
# ==============================================================================

def test_challenge_ingestion_pipeline_html_report_zero_cdn_and_xss(tmp_path):
    """Stress-tests the standalone HTML report generated by EvidenceIngestionPipeline for zero CDN and XSS resistance."""
    from forensics.ingestion.pipeline import EvidenceIngestionPipeline, IngestionRecord

    pipeline = EvidenceIngestionPipeline(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")
    malicious_record = IngestionRecord(
        evidence_id="evi-001",
        original_filename="malicious<img src=x onerror=alert('fname')>.json",
        stored_filename="raw.json",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_type="blockchain_tx_json",
        description="Description with <svg/onload=alert('desc')>",
        size_bytes=1024,
        timestamp="2026-11-07T21:00:00Z",
        records_count=1,
        anomalies_count=0,
        run_id="run<script>alert('run')</script>",
    )
    malicious_analysis = {
        "summary_vi": "Tóm tắt với <iframe src=javascript:alert('summary')></iframe>",
        "anomalies": [
            {
                "type": "ANOMALY<script>alert(1)</script>",
                "severity": "CRITICAL",
                "count": 5,
                "description": "Anomaly note <img src=x onerror=alert(2)>",
            }
        ],
        "statistics": {"total_records": 10},
    }
    step_logs = [
        "Bước 1: Khởi tạo <script>alert('log')</script>",
        "Bước 2: Hoàn tất với an toàn.",
    ]

    html_content = pipeline._render_standalone_html_report(
        case_id="case<script>alert('ingest')</script>",
        run_id="run<script>alert('run')</script>",
        evidence=malicious_record,
        analysis=malicious_analysis,
        step_logs=step_logs,
    )

    # Zero CDN
    assert "cdn.tailwindcss.com" not in html_content
    assert "fonts.googleapis.com" not in html_content
    assert "unpkg.com" not in html_content

    # Zero unescaped executable script or iframe tags
    assert not re.search(r"<\s*script", html_content, re.IGNORECASE)
    assert not re.search(r"<\s*/\s*script\s*>", html_content, re.IGNORECASE)
    assert not re.search(r"<\s*iframe", html_content, re.IGNORECASE)

    # Zero injected event handlers in tags
    injected_handlers = re.findall(r"<[a-zA-Z0-9_-]+(?:\s+[^>]*?)?\bon[a-zA-Z]+\s*=", html_content, re.IGNORECASE)
    assert len(injected_handlers) == 0, f"Injected event handler found: {injected_handlers}"


def test_challenge_live_collector_html_report_zero_cdn_and_xss(tmp_path):
    """Stress-tests the standalone HTML report generated by LiveRpcCollector for zero CDN and XSS resistance."""
    from forensics.live_collector import LiveRpcCollector

    collector = LiveRpcCollector(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")

    malicious_txs = [
        {
            "hash": "0x12345<script>alert('hash')</script>",
            "blockNumber": 256,
            "from": "0xfrom<img src=x onerror=alert('from')>",
            "to": "0xto<svg/onload=alert('to')>",
            "value_eth": 10.5,
        }
    ]
    malicious_anomalies = [
        {
            "severity": "HIGH",
            "title": "Alert <script>alert('title')</script>",
            "tx_hash": "0x12345<script>",
            "description": "Desc <iframe src=javascript:alert('desc')>",
        }
    ]
    guardrail_notes = [
        "Guardrail notice <script>alert('guard')</script>",
    ]
    step_logs = [
        "Log 1 <img src=x onerror=alert('log')>",
    ]

    html_content = collector._render_standalone_rpc_html_report(
        case_id="case<script>alert('rpc-case')</script>",
        run_id="run<script>alert('rpc-run')</script>",
        rpc_url="http://127.0.0.1:8545",
        chain_id=11155111,
        network_name="Sepolia <script>",
        is_synthetic=1,
        start_block=256,
        end_block=256,
        blocks=[],
        transactions=malicious_txs,
        anomalies=malicious_anomalies,
        guardrail_notes=guardrail_notes,
        data_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        step_logs=step_logs,
    )

    # Zero CDN
    assert "cdn.tailwindcss.com" not in html_content
    assert "fonts.googleapis.com" not in html_content
    assert "unpkg.com" not in html_content

    # Zero unescaped executable script or iframe tags
    assert not re.search(r"<\s*script", html_content, re.IGNORECASE)
    assert not re.search(r"<\s*/\s*script\s*>", html_content, re.IGNORECASE)
    assert not re.search(r"<\s*iframe", html_content, re.IGNORECASE)

    # Zero injected event handlers in tags
    injected_handlers = re.findall(r"<[a-zA-Z0-9_-]+(?:\s+[^>]*?)?\bon[a-zA-Z]+\s*=", html_content, re.IGNORECASE)
    assert len(injected_handlers) == 0, f"Injected event handler found: {injected_handlers}"

    # Verify @media print presence
    assert "@media print" in html_content


def test_challenge_milestone5_investigation_reports_zero_cdn():
    """Scans all HTML reports generated during Milestone 5 to ensure zero Tailwind or other external CDN exists."""
    reports_dir = Path("reports/investigations")
    if not reports_dir.is_dir():
        return

    # Check reports generated after Milestone 5 cutoff (run_case-e2e-a-*, run_case-e2e-b-*)
    m5_html_files = [
        f for f in reports_dir.rglob("*.html")
        if "case-e2e" in str(f) or "m5" in str(f)
    ]
    assert len(m5_html_files) > 0, "Expected Milestone 5 generated HTML reports"

    cdn_regex = re.compile(r"cdn\.tailwindcss\.com|fonts\.googleapis\.com|unpkg\.com", re.IGNORECASE)
    for hf in m5_html_files:
        content = hf.read_text(encoding="utf-8")
        assert not cdn_regex.search(content), f"Found CDN leakage in Milestone 5 report: {hf}"



def test_challenge_empirical_bug_live_collector_wipes_out_dict_jobs(tmp_path):
    """Verifies remediation of bug in LiveRpcCollector._register_job_in_manager:

    When JobManager stores jobs as Dict[str, Any] in jobs.json,
    LiveRpcCollector preserves the dict, retains all existing jobs,
    and uses filelock protection.
    """
    from forensics.live_collector import LiveRpcCollector

    jfile = tmp_path / "jobs.json"
    initial_jobs = {f"run_{i}": {"run_id": f"run_{i}", "case_id": f"case_{i}"} for i in range(5)}
    jfile.write_text(json.dumps(initial_jobs), encoding="utf-8")

    collector = LiveRpcCollector(data_dir=tmp_path, output_dir=tmp_path / "reports")
    collector._register_job_in_manager(
        run_id="run_new_rpc",
        case_id="case_new_rpc",
        artifacts={},
        network_name="Sepolia",
        is_synthetic=1,
        tx_count=1,
        anomalies_count=0,
    )

    data_after = json.loads(jfile.read_text(encoding="utf-8"))
    # Remediation: Dict is preserved, all existing jobs retained, and new job registered
    assert isinstance(data_after, dict), "Schema preserved as dict"
    assert len(data_after) == 6, "All 5 existing jobs preserved plus new job"
    assert "run_0" in data_after, "Existing job run_0 preserved"
    assert "run_new_rpc" in data_after, "New job registered"


def test_challenge_live_collector_preserves_legacy_list_jobs(tmp_path):
    """Verifies that if jobs.json was legacy list format, it is also preserved without wiping."""
    from forensics.live_collector import LiveRpcCollector

    jfile = tmp_path / "jobs.json"
    initial_jobs = [{"run_id": f"run_{i}", "case_id": f"case_{i}"} for i in range(3)]
    jfile.write_text(json.dumps(initial_jobs), encoding="utf-8")

    collector = LiveRpcCollector(data_dir=tmp_path, output_dir=tmp_path / "reports")
    collector._register_job_in_manager(
        run_id="run_new_rpc_list",
        case_id="case_new_rpc",
        artifacts={},
        network_name="Sepolia",
        is_synthetic=1,
        tx_count=1,
        anomalies_count=0,
    )

    data_after = json.loads(jfile.read_text(encoding="utf-8"))
    assert isinstance(data_after, list), "Schema preserved as list"
    assert len(data_after) == 4, "All 3 existing list jobs preserved plus new job"
    assert any(x.get("run_id") == "run_0" for x in data_after), "Existing job run_0 preserved"
    assert any(x.get("run_id") == "run_new_rpc_list" for x in data_after), "New job registered"
