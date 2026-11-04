"""Comprehensive test suite for Phase 6 Threat Intelligence Data Adapters & Gate P6-02.

Covers:
1. Normal, malformed, duplicate, and formula injection CSV parsing.
2. Dual-mode Excel parsing (pure Python OpenXML fallback verification), columnar unpivoting,
   InitialAddress 'Tx_tatal' aliasing, and inert hyperlink handling.
3. JSON parsing with mixed date formats (ISO, US legacy M/D/YY, empty), address validation,
   and schema violations.
4. Append-only persistence into benchmark_p6.db, duplicate handling, and conflict error raising.
5. Cryptographic provenance verification (SHA-256 matches, commit matches).
6. Strict database isolation checks (confirms real_p4.db and canonical databases are never touched).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
import zipfile
import xml.etree.ElementTree as ET
import pytest

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    compute_file_sha256,
    compute_payload_sha256,
    is_valid_eth_address,
    is_valid_tx_hash,
    normalize_eth_address,
    normalize_tx_hash,
    sanitize_formula_injection,
)
from forensics.adapters.csv_adapter import parse_csv_file, parse_forta_csv
from forensics.adapters.json_adapter import normalize_mew_date, parse_json_file, parse_mew_darklist_json
from forensics.adapters.persistence_benchmark import (
    EvidenceConflictError,
    assert_database_isolation,
    init_benchmark_db,
    insert_intel_batch,
    insert_intel_record,
)
from forensics.adapters.xlsx_adapter import (
    OpenXMLFallbackWorkbook,
    parse_ptxphish_xlsx,
    parse_xlsx_file,
    recover_numeric_address,
)


# =============================================================================
# Helper to create valid OpenXML XLSX fixtures without third-party dependencies
# =============================================================================

def create_test_openxml_xlsx(
    output_path: Path,
    sheets_data: dict[str, list[list[str]]],
) -> Path:
    """Create a minimal valid OpenXML .xlsx file containing the given sheets and row data."""
    # Build shared strings table
    unique_strings: list[str] = []
    string_to_idx: dict[str, int] = {}

    def get_sst_idx(text: str) -> int:
        if text not in string_to_idx:
            string_to_idx[text] = len(unique_strings)
            unique_strings.append(text)
        return string_to_idx[text]

    sheet_names = list(sheets_data.keys())

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # [Content_Types].xml
        content_types = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
            '<Default Extension="xml" ContentType="application/xml"/>',
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>',
        ]
        for idx in range(1, len(sheet_names) + 1):
            content_types.append(
                f'<Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            )
        content_types.append("</Types>")
        z.writestr("[Content_Types].xml", "".join(content_types))

        # _rels/.rels
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>",
        )

        # xl/_rels/workbook.xml.rels
        wb_rels = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
            '<Relationship Id="rIdSharedStrings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>',
        ]
        for idx in range(1, len(sheet_names) + 1):
            wb_rels.append(
                f'<Relationship Id="rIdSheet{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
            )
        wb_rels.append("</Relationships>")
        z.writestr("xl/_rels/workbook.xml.rels", "".join(wb_rels))

        # Build worksheets
        for idx, (sname, rows) in enumerate(sheets_data.items(), start=1):
            ws_parts = [
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
                "<sheetData>",
            ]
            for r_idx, row in enumerate(rows, start=1):
                ws_parts.append(f'<row r="{r_idx}">')
                for c_idx, cell_val in enumerate(row, start=1):
                    if cell_val is not None:
                        col_letters = ""
                        num = c_idx
                        while num > 0:
                            num, rem = divmod(num - 1, 26)
                            col_letters = chr(ord("A") + rem) + col_letters
                        ref = f"{col_letters}{r_idx}"
                        s_idx = get_sst_idx(str(cell_val))
                        ws_parts.append(f'<c r="{ref}" t="s"><v>{s_idx}</v></c>')
                ws_parts.append("</row>")
            ws_parts.append("</sheetData></worksheet>")
            z.writestr(f"xl/worksheets/sheet{idx}.xml", "".join(ws_parts))

        # xl/workbook.xml
        wb_parts = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
            "<sheets>",
        ]
        for idx, sname in enumerate(sheet_names, start=1):
            wb_parts.append(f'<sheet name="{sname}" sheetId="{idx}" r:id="rIdSheet{idx}"/>')
        wb_parts.append("</sheets></workbook>")
        z.writestr("xl/workbook.xml", "".join(wb_parts))

        # xl/sharedStrings.xml
        sst_parts = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(unique_strings)}" uniqueCount="{len(unique_strings)}">',
        ]
        for s in unique_strings:
            escaped = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            sst_parts.append(f"<si><t>{escaped}</t></si>")
        sst_parts.append("</sst>")
        z.writestr("xl/sharedStrings.xml", "".join(sst_parts))

    return output_path


# =============================================================================
# CSV ADAPTER TESTS (T-P6-01, T-P6-02, T-P6-04, etc.)
# =============================================================================

def test_csv_normal_parsing(tmp_path: Path):
    """T-P6-01: Verify successful parsing of standard Forta phishing_scams CSV."""
    csv_file = tmp_path / "phishing_scams.csv"
    csv_content = (
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,Fake_Phishing3901,phish-hack,False\n"
        "0x00000006e55a9364b657e3b91cd0411b4fd11ac2,Adidas Metaverse,phish-hack,True\n"
    )
    csv_file.write_text(csv_content, encoding="utf-8")

    batch = parse_forta_csv(csv_file, source_commit="test_commit_01")
    assert batch.valid_records == 2
    assert batch.rejected_records == 0
    assert batch.total_raw_records == 2

    # Check EOA record
    eoa_rec = batch.records[0]
    assert eoa_rec.entity_type == "address"
    assert eoa_rec.entity_value == "0x000000000532b45f47779fce440748893b257865"
    assert eoa_rec.threat_category == "PHISHING"
    assert eoa_rec.threat_sub_tactic == "Fake_Phishing3901"
    assert eoa_rec.source_commit == "test_commit_01"

    # Check Contract record
    contract_rec = batch.records[1]
    assert contract_rec.entity_type == "contract"
    assert contract_rec.entity_value == "0x00000006e55a9364b657e3b91cd0411b4fd11ac2"
    assert contract_rec.threat_category == "PHISHING"


def test_csv_formula_injection_sanitization(tmp_path: Path):
    """T-P6-02: Verify formula injection prefixes (=, @, +, -, tab) are safely neutralized."""
    csv_file = tmp_path / "formula_test.csv"
    csv_content = (
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,=cmd|' /C calc'!A0,phish-hack,False\n"
        "0x00000000072d54638c2c2a3da3f715360269eea1,@SUM(1+1),phish-hack,False\n"
        "0x0000000009324b6434d7766af41908e4c49ee1d7,+malicious_payload,phish-hack,False\n"
        "0x0000000086c5d614bec59dfd2c9b88f7cb57f23c,-12345,phish-hack,False\n"
    )
    csv_file.write_text(csv_content, encoding="utf-8")

    batch = parse_forta_csv(csv_file)
    assert batch.valid_records == 4

    for rec in batch.records:
        meta = json.loads(rec.raw_metadata_json)
        tag = meta["etherscan_tag"]
        # Invariant: Must not start with raw formula execution characters
        assert not tag.startswith(("=", "@", "+", "-"))
        assert tag.startswith("'")


def test_csv_malformed_and_invalid_addresses(tmp_path: Path):
    """T-P6-07/T-P6-08: Verify malformed rows and invalid address syntax are rejected."""
    csv_file = tmp_path / "malformed_test.csv"
    csv_content = (
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,ValidTag,phish-hack,False\n"
        "0x12345,TruncatedAddress,phish-hack,False\n"  # 7 chars, invalid
        "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ,NonHex,phish-hack,False\n"  # non-hex
        ",EmptyAddress,phish-hack,False\n"  # empty address
        "ShortRow\n"  # short row
    )
    csv_file.write_text(csv_content, encoding="utf-8")

    batch = parse_forta_csv(csv_file)
    assert batch.valid_records == 1
    assert batch.rejected_records == 4
    assert len(batch.rejections) == 4
    # All rejections have auditable reasons
    for rej in batch.rejections:
        assert "rejection_reason" in rej
        assert "row_identifier" in rej


def test_csv_duplicate_handling(tmp_path: Path):
    """T-P6-04: Verify address duplicated across rows (multi-tag scraping) is captured per row."""
    csv_file = tmp_path / "duplicate_test.csv"
    csv_content = (
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,Tag1,phish-hack,False\n"
        "0x000000000532b45f47779fce440748893b257865,Tag2_Updated,phish-hack,False\n"
    )
    csv_file.write_text(csv_content, encoding="utf-8")

    batch = parse_forta_csv(csv_file)
    assert batch.valid_records == 2
    assert batch.records[0].row_identifier == "2"
    assert batch.records[1].row_identifier == "3"
    assert batch.records[0].entity_value == batch.records[1].entity_value


# =============================================================================
# EXCEL ADAPTER TESTS (T-P6-03, T-P6-04, T-P6-05, etc.)
# =============================================================================

def test_excel_dual_mode_fallback(tmp_path: Path):
    """Explicitly verify that standard library OpenXML fallback works independently without openpyxl."""
    xlsx_path = tmp_path / "fallback_test.xlsx"
    sheets_data = {
        "Ice Phishing": [
            ["address", "label"],
            ["0x000000000532b45f47779fce440748893b257865", "phish-hack"],
            ["0x00000006e55a9364b657e3b91cd0411b4fd11ac2", "phish-hack"],
        ]
    }
    create_test_openxml_xlsx(xlsx_path, sheets_data)

    # Force standard-library OpenXML reader
    batch = parse_ptxphish_xlsx(xlsx_path, force_fallback=True)
    assert batch.valid_records == 2
    assert batch.records[0].entity_value == "0x000000000532b45f47779fce440748893b257865"
    assert batch.records[0].threat_category == "ICE_PHISHING"


def test_excel_columnar_unpivoting(tmp_path: Path):
    """T-P6-03: Verify PTXPHISH.xlsx columnar tactic-source unpivoting without cross-column corruption."""
    xlsx_path = tmp_path / "ptxphish_matrix.xlsx"
    tx1 = "0x3f4946fb8ab2c240a223b8ab58193451c5b243c98a69838256d079809f2d75a0"
    tx2 = "0x3ff7d30d032473e831a6121930b2ab2dc2d1df2bb90bb7164d3d357132107697"
    tx_kol = "0x009bfd19a732c32373548c1087aa68b12ff32dddae5ba0d7d30fdc77c6f6969a"

    # Row 1: Title, Row 2: Category, Row 3: Sub-category, Row 4: Tactics, Row 5+: Data
    matrix_rows = [
        ["TXSPHISH", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None],
        ["Exploiting legitimate contracts", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None],
        ["Ice phishing scam", None, "Ice phishing scam", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, "Benign"],
        # Col A (Approve), Col B (Source), Col C (Permit), Col D (Source) ... Col AA (Benign KOL)
        ["Approve", "Source", "Permit", "Source", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, "Benign KOL"],
        [tx1, "https://twitter.com/scamsniffer/status/1", tx2, "https://twitter.com/scamsniffer/status/2", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, tx_kol],
        [tx1, "https://twitter.com/scamsniffer/status/1", None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None],
    ]
    create_test_openxml_xlsx(xlsx_path, {"Sheet1": matrix_rows})

    batch = parse_ptxphish_xlsx(xlsx_path, force_fallback=True)
    # tx1 (row 5 Col A), tx2 (row 5 Col C), tx_kol (row 5 Col AA), tx1 (row 6 Col A)
    assert batch.valid_records == 4

    # Verify Col A Approve record
    rec_approve = next(r for r in batch.records if r.row_identifier == "Sheet1:A5")
    assert rec_approve.entity_type == "tx_hash"
    assert rec_approve.entity_value == tx1.lower()
    assert rec_approve.threat_category == "ICE_PHISHING"
    assert rec_approve.threat_sub_tactic == "Approve"
    meta_approve = json.loads(rec_approve.raw_metadata_json)
    assert meta_approve["evidence_url"] == "https://twitter.com/scamsniffer/status/1"

    # Verify Col AA Benign KOL record
    rec_kol = next(r for r in batch.records if r.row_identifier == "Sheet1:AA5")
    assert rec_kol.threat_category == "BENIGN_CONTROL"
    assert rec_kol.threat_sub_tactic == "Benign KOL"


def test_excel_initial_address_alias_and_numeric(tmp_path: Path):
    """Verify InitialAddress.xlsx unpivoting, aliasing 'Tx_tatal' -> 'Tx_total', and numeric recovery."""
    xlsx_path = tmp_path / "initial_address_test.xlsx"
    addr1 = "0x7f9241ac942ba97085ef1a1542d270bfd6a987fd"
    # Address without 0x coerced to numeric string
    addr2_raw = "0000553f880ffa3728b290e04e819053a3590000"

    rows = [
        ["Approve", "Tx_tatal", "Type", None, "permit", "Tx_tatal", "Type"],
        [addr1, "1", "1", None, addr2_raw, "9", "1"],
    ]
    create_test_openxml_xlsx(xlsx_path, {"Sheet1": rows})

    batch = parse_ptxphish_xlsx(xlsx_path, force_fallback=True)
    assert batch.valid_records == 2

    rec1 = batch.records[0]
    assert rec1.entity_value == addr1.lower()
    assert rec1.threat_category == "ICE_PHISHING"
    meta1 = json.loads(rec1.raw_metadata_json)
    assert "Tx_total" in meta1
    assert "Tx_tatal" not in meta1  # Aliased!

    rec2 = batch.records[1]
    assert rec2.entity_value == f"0x{addr2_raw.lower()}"


def test_excel_inert_hyperlink_handling(tmp_path: Path):
    """Verify that hyperlinks/URLs in source cells are treated strictly as inert text (never dereferenced)."""
    xlsx_path = tmp_path / "inert_link_test.xlsx"
    tx1 = "0x3f4946fb8ab2c240a223b8ab58193451c5b243c98a69838256d079809f2d75a0"
    evil_url = "http://127.0.0.1:9999/malicious_payload_fetch"

    rows = [
        ["TXSPHISH", None],
        ["Exploiting legitimate contracts", None],
        ["Ice phishing scam", None],
        ["Approve", "Source"],
        [tx1, evil_url],
    ]
    create_test_openxml_xlsx(xlsx_path, {"Sheet1": rows})

    batch = parse_ptxphish_xlsx(xlsx_path, force_fallback=True)
    assert batch.valid_records == 1
    meta = json.loads(batch.records[0].raw_metadata_json)
    assert meta["evidence_url"] == evil_url


# =============================================================================
# JSON ADAPTER TESTS (T-P6-06, T-P6-07, Date Formats)
# =============================================================================

def test_json_mew_darklist_normal(tmp_path: Path):
    """T-P6-06: Verify standard MEW Darklist JSON parsing."""
    json_path = tmp_path / "addresses-darklist.json"
    data = [
        {
            "address": "0x09750ad360fdb7a2ee23669c4503c974d86d8694",
            "comment": "XRP phishing website",
            "date": "2020-11-17",
        },
        {
            "address": "0xc915ec7f4cfd1c0a8aba090f03bfaab588aef9b4",
            "comment": "=MALICIOUS_FORMULA_IN_COMMENT",
            "date": "2020-11-14",
        },
    ]
    json_path.write_text(json.dumps(data), encoding="utf-8")

    batch = parse_mew_darklist_json(json_path)
    assert batch.valid_records == 2
    assert batch.records[0].entity_value == "0x09750ad360fdb7a2ee23669c4503c974d86d8694"
    assert batch.records[0].threat_category == "PHISHING"

    # Formula injection sanitized in comment
    meta1 = json.loads(batch.records[1].raw_metadata_json)
    assert meta1["comment"].startswith("'=")


def test_json_mixed_date_formats(tmp_path: Path):
    """Verify multi-format date normalization (ISO, US legacy M/D/YY, empty strings)."""
    assert normalize_mew_date("2020-11-17") == "2020-11-17T00:00:00Z"
    assert normalize_mew_date("7/22/17") == "2017-07-22T00:00:00Z"
    assert normalize_mew_date("07/22/2017") == "2017-07-22T00:00:00Z"
    assert normalize_mew_date("") is None
    assert normalize_mew_date(None) is None

    json_path = tmp_path / "mixed_dates.json"
    data = [
        {"address": "0x09750ad360fdb7a2ee23669c4503c974d86d8694", "comment": "ISO", "date": "2020-11-17"},
        {"address": "0xc915ec7f4cfd1c0a8aba090f03bfaab588aef9b4", "comment": "US", "date": "7/22/17"},
        {"address": "0xecb6ffac05d8b4660b99b475b359fe454c77d153", "comment": "Empty", "date": ""},
    ]
    json_path.write_text(json.dumps(data), encoding="utf-8")

    batch = parse_mew_darklist_json(json_path)
    assert batch.valid_records == 3

    meta_iso = json.loads(batch.records[0].raw_metadata_json)
    assert meta_iso["reported_date"] == "2020-11-17T00:00:00Z"

    meta_us = json.loads(batch.records[1].raw_metadata_json)
    assert meta_us["reported_date"] == "2017-07-22T00:00:00Z"

    meta_empty = json.loads(batch.records[2].raw_metadata_json)
    assert meta_empty["reported_date"] is None


def test_json_malformed_and_schema_violations(tmp_path: Path):
    """T-P6-07: Verify malformed JSON, root not list, and invalid items are logged as rejections."""
    # 1. Non-list root
    json_dict = tmp_path / "dict_root.json"
    json_dict.write_text('{"error": "not a list"}', encoding="utf-8")
    batch1 = parse_mew_darklist_json(json_dict)
    assert batch1.rejected_records == 1
    assert "SCHEMA_VIOLATION" in batch1.rejections[0]["rejection_reason"]

    # 2. Syntax error
    json_bad = tmp_path / "syntax_error.json"
    json_bad.write_text('[{"address": "0x123", ]', encoding="utf-8")
    batch2 = parse_mew_darklist_json(json_bad)
    assert batch2.rejected_records == 1
    assert "MALFORMED_JSON_SYNTAX" in batch2.rejections[0]["rejection_reason"]

    # 3. Invalid items inside list
    json_items = tmp_path / "bad_items.json"
    data = [
        "not_an_object",
        {"address": "0x123"},  # invalid hex
        {"address": "0x09750ad360fdb7a2ee23669c4503c974d86d8694"},  # valid
    ]
    json_items.write_text(json.dumps(data), encoding="utf-8")
    batch3 = parse_mew_darklist_json(json_items)
    assert batch3.valid_records == 1
    assert batch3.rejected_records == 2


# =============================================================================
# PERSISTENCE & G5-02 APPEND-ONLY TESTS (T-P6-09, T-P6-10, T-P6-12)
# =============================================================================

def test_persistence_append_only_and_idempotency(tmp_path: Path):
    """T-P6-09: Verify append-only persistence and idempotent replay with zero duplicates."""
    db_path = tmp_path / "test_benchmark.db"
    conn = init_benchmark_db(db_path)

    record = ThreatIntelRecord(
        source_file_path="datasets/working/test.csv",
        source_file_sha256="abc123sha256",
        source_commit="commit_hash",
        row_identifier="2",
        raw_payload_sha256="payload123",
        entity_type="address",
        entity_value="0x000000000532b45f47779fce440748893b257865",
        threat_category="PHISHING",
        threat_sub_tactic="test_tag",
        confidence_score=1.0,
        data_source="forta",
        raw_metadata_json='{"tag":"test"}',
        ingestion_timestamp="2026-11-02T00:00:00Z",
    )

    # First insert: should succeed
    res1 = insert_intel_record(conn, record)
    conn.commit()
    assert res1 is True

    # Replay with identical non-replay data (ingestion_timestamp can differ)
    record_replay = ThreatIntelRecord(
        source_file_path="datasets/working/test.csv",
        source_file_sha256="abc123sha256",
        source_commit="commit_hash",
        row_identifier="2",
        raw_payload_sha256="payload123",
        entity_type="address",
        entity_value="0x000000000532b45f47779fce440748893b257865",
        threat_category="PHISHING",
        threat_sub_tactic="test_tag",
        confidence_score=1.0,
        data_source="forta",
        raw_metadata_json='{"tag":"test"}',
        ingestion_timestamp="2026-11-02T01:00:00Z",  # Different timestamp
    )
    res2 = insert_intel_record(conn, record_replay)
    assert res2 is False  # Identical replay accepted without duplicate

    cur = conn.cursor()
    count = cur.execute("SELECT COUNT(*) FROM threat_intel_records").fetchone()[0]
    assert count == 1
    conn.close()


def test_persistence_conflict_detection(tmp_path: Path):
    """T-P6-10: Verify conflicting modification to accepted record raises EvidenceConflictError."""
    db_path = tmp_path / "test_conflict.db"
    conn = init_benchmark_db(db_path)

    record_orig = ThreatIntelRecord(
        source_file_path="datasets/working/test.csv",
        source_file_sha256="sha256_orig",
        source_commit="commit_orig",
        row_identifier="2",
        raw_payload_sha256="payload_hash",
        entity_type="address",
        entity_value="0x000000000532b45f47779fce440748893b257865",
        threat_category="PHISHING",
        threat_sub_tactic="original_tag",
        confidence_score=1.0,
        data_source="forta",
        raw_metadata_json='{"tag":"original"}',
        ingestion_timestamp="2026-11-02T00:00:00Z",
    )
    insert_intel_record(conn, record_orig)
    conn.commit()

    # Conflicting replay: same primary key, but different threat_category
    record_conflicting = ThreatIntelRecord(
        source_file_path="datasets/working/test.csv",
        source_file_sha256="sha256_orig",
        source_commit="commit_orig",
        row_identifier="2",
        raw_payload_sha256="payload_hash",
        entity_type="address",
        entity_value="0x000000000532b45f47779fce440748893b257865",
        threat_category="EXPLOIT",  # Changed category!
        threat_sub_tactic="original_tag",
        confidence_score=1.0,
        data_source="forta",
        raw_metadata_json='{"tag":"original"}',
        ingestion_timestamp="2026-11-02T00:00:00Z",
    )

    with pytest.raises(EvidenceConflictError) as exc_info:
        insert_intel_record(conn, record_conflicting)
    assert "conflicting threat_category" in str(exc_info.value)
    conn.close()


def test_provenance_verification(tmp_path: Path):
    """T-P6-11: Verify cryptographic provenance preservation (SHA-256 and commit)."""
    csv_file = tmp_path / "provenance_check.csv"
    csv_content = (
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,Tag,phish-hack,False\n"
    )
    csv_file.write_text(csv_content, encoding="utf-8")
    expected_sha256 = compute_file_sha256(csv_file)
    expected_commit = "deadbeef12345678"

    batch = parse_forta_csv(csv_file, source_commit=expected_commit)
    assert batch.file_sha256 == expected_sha256
    assert batch.source_commit == expected_commit

    rec = batch.records[0]
    assert rec.source_file_sha256 == expected_sha256
    assert rec.source_commit == expected_commit
    assert rec.raw_payload_sha256 == compute_payload_sha256(
        "0x000000000532b45f47779fce440748893b257865,Tag,phish-hack,False"
    )


def test_database_isolation():
    """T-P6-12: Verify that real_p4.db and canonical production databases are rejected."""
    with pytest.raises(ValueError) as exc1:
        assert_database_isolation("D:/Projest/worktrees/p4_real_integration/data/real_p4.db")
    assert "Database isolation violation" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        assert_database_isolation("D:/Projest/Blockchain/data/forensics.db")
    assert "Database isolation violation" in str(exc2.value)

    with pytest.raises(ValueError) as exc3:
        init_benchmark_db("D:/Projest/worktrees/p4_real_integration/data/real_p4.db")
    assert "Database isolation violation" in str(exc3.value)


# =============================================================================
# INTEGRATED BATCH PERSISTENCE TEST
# =============================================================================

def test_insert_intel_batch(tmp_path: Path):
    """Verify end-to-end batch ingestion and persistence into benchmark DB."""
    db_path = tmp_path / "batch_test.db"
    conn = init_benchmark_db(db_path)

    csv_file = tmp_path / "batch_test.csv"
    csv_file.write_text(
        "address,etherscan_tag,etherscan_labels,is_contract\n"
        "0x000000000532b45f47779fce440748893b257865,Tag1,phish-hack,False\n"
        "0x00000006e55a9364b657e3b91cd0411b4fd11ac2,Tag2,phish-hack,True\n"
        "invalid_hex,Tag3,phish-hack,False\n",
        encoding="utf-8",
    )

    batch = parse_forta_csv(csv_file)
    summary = insert_intel_batch(conn, batch)

    assert summary["valid"] == 2
    assert summary["rejected"] == 1
    assert summary["total"] == 3

    # Verify source table populated
    cur = conn.cursor()
    src_row = cur.execute("SELECT valid_records, rejected_records FROM threat_intel_sources").fetchone()
    assert src_row == (2, 1)

    # Verify rejection logged
    rej_count = cur.execute("SELECT COUNT(*) FROM threat_intel_rejections").fetchone()[0]
    assert rej_count == 1
    conn.close()
