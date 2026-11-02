"""Adversarial stress-test battery for Phase 6 Threat Intelligence Data Adapters.

Systematically challenges:
1. CSV Adapter: malformed rows, formula injection payloads (=cmd, @sum, +calc, -1+1,
   leading tabs/newlines), non-hex addresses, formula sanitization.
2. JSON Adapter: invalid date strings, missing fields, nulls, malformed addresses,
   graceful rejection without unhandled crash.
3. Excel Adapter: pure standard-library OpenXML fallback (simulating absent openpyxl),
   100% fidelity comparison on PTXPHISH.xlsx and InitialAddress.xlsx, inert hyperlinks,
   numeric address recovery, and 'Tx_tatal' aliasing.
4. Real-world public benchmark dataset integrity and provenance checks.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import zipfile
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
    sanitize_metadata_dict,
)
from forensics.adapters.csv_adapter import parse_csv_file, parse_forta_csv
from forensics.adapters.json_adapter import normalize_mew_date, parse_json_file, parse_mew_darklist_json
from forensics.adapters.xlsx_adapter import (
    OpenXMLFallbackWorkbook,
    parse_ptxphish_xlsx,
    parse_xlsx_file,
    recover_numeric_address,
)

RAW_DATASETS_DIR = Path(r"D:\Projest\p6_public_benchmark\datasets\raw")


# =============================================================================
# Helper to generate test OpenXML workbooks without external dependencies
# =============================================================================

def build_test_xlsx(output_path: Path, sheets_data: dict[str, list[list[str]]]) -> Path:
    """Build a minimal valid OpenXML .xlsx file containing sheets_data."""
    unique_strings: list[str] = []
    string_to_idx: dict[str, int] = {}

    def get_sst_idx(text: str) -> int:
        if text not in string_to_idx:
            string_to_idx[text] = len(unique_strings)
            unique_strings.append(text)
        return string_to_idx[text]

    sheet_names = list(sheets_data.keys())

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
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

        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>",
        )

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

        wb_parts = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
            "<sheets>",
        ]
        for idx, sname in enumerate(sheet_names, start=1):
            wb_parts.append(f'<sheet name="{sname}" sheetId="{idx}" r:id="rIdSheet{idx}"/>')
        wb_parts.append("</sheets></workbook>")
        z.writestr("xl/workbook.xml", "".join(wb_parts))

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
# 1. ADVERSARIAL CSV STRESS TESTS
# =============================================================================

class TestAdversarialCSV:
    """Stress-test suite for Forta Web3 CSV data adapter."""

    def test_formula_injection_payloads_neutralized(self, tmp_path: Path):
        """Verify formula injection payloads (=cmd, @sum, +calc, -1+1, leading tabs/newlines) are safely neutralized."""
        csv_file = tmp_path / "formula_injection_battery.csv"
        rows = [
            ["address", "etherscan_tag", "etherscan_labels", "is_contract"],
            ["0x000000000532b45f47779fce440748893b257861", "=cmd|' /C calc'!A0", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257862", "@SUM(1+1)*cmd|' /C calc'!A0", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257863", "+calc", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257864", "-1+1", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257865", "\t=cmd", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257866", "\t@sum", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257867", "\t+calc", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257868", "\t-1+1", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b257869", "\n=cmd", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b25786a", "\r=cmd", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b25786b", "\r\n+calc", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b25786c", "   =cmd", "phish-hack", "False"],
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        batch = parse_forta_csv(csv_file)
        assert batch.valid_records == 12
        assert batch.rejected_records == 0

        for rec in batch.records:
            meta = json.loads(rec.raw_metadata_json)
            tag = meta["etherscan_tag"]
            # Invariant: Every formula payload MUST be prefixed with apostrophe
            assert tag.startswith("'"), f"Formula not neutralized: {tag!r}"
            # Invariant: Must not start with bare executable formula characters
            assert not tag.lstrip("'").startswith(("=", "@", "+", "-")) or tag.startswith("'")

    def test_formula_injection_in_address_field_rejected(self, tmp_path: Path):
        """Verify formula injection in address column is rejected by address validation without crash."""
        csv_file = tmp_path / "formula_in_address.csv"
        rows = [
            ["address", "etherscan_tag", "etherscan_labels", "is_contract"],
            ["=cmd|' /C calc'!A0", "Tag1", "phish-hack", "False"],
            ["+0x000000000532b45f47779fce440748893b257865", "Tag2", "phish-hack", "False"],
            ["@SUM(1,2)", "Tag3", "phish-hack", "False"],
            ["-1+1", "Tag4", "phish-hack", "False"],
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        batch = parse_forta_csv(csv_file)
        assert batch.valid_records == 0
        assert batch.rejected_records == 4
        for rej in batch.rejections:
            assert "INVALID_ADDRESS_SYNTAX" in rej["rejection_reason"]

    def test_malformed_rows_and_boundary_conditions(self, tmp_path: Path):
        """Stress-test CSV adapter with truncated rows, extra columns, empty lines, and long fields."""
        csv_file = tmp_path / "malformed_stress.csv"
        valid_addr = "0x000000000532b45f47779fce440748893b257865"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            f.write("address,etherscan_tag,etherscan_labels,is_contract\n")
            f.write(f"{valid_addr},TagValid,phish-hack,False\n")
            f.write("ShortRowOnlyOneColumn\n")
            f.write("Col1,Col2\n")  # 2 cols, expected 4
            f.write(",,,\n")  # empty values
            f.write(f"{valid_addr},TagExtra,phish-hack,False,extra_col1,extra_col2\n")  # extra cols
            f.write("\n")  # empty row
            f.write(f"{valid_addr},{'A'*10000},phish-hack,False\n")  # 10k long field

        batch = parse_forta_csv(csv_file)
        # Valid: TagValid, TagExtra (extra cols sliced cleanly), and 10k long field
        assert batch.valid_records == 3
        # Rejected: ShortRowOnlyOneColumn, Col1,Col2, empty values (empty addr), empty row
        assert batch.rejected_records == 4

    def test_non_hex_addresses_rejected(self, tmp_path: Path):
        """Adversarially verify all invalid, truncated, elongated, and non-hex addresses are rejected."""
        csv_file = tmp_path / "non_hex_stress.csv"
        rows = [
            ["address", "etherscan_tag", "etherscan_labels", "is_contract"],
            ["0x000000000532b45f47779fce440748893b25786", "Truncated39", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b2578651", "Elongated41", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b25786g", "NonHexG", "phish-hack", "False"],
            ["0x000000000532b45f47779fce440748893b25786Z", "NonHexZ", "phish-hack", "False"],
            ["' OR 1=1 --", "SqlInjection", "phish-hack", "False"],
            ["../../etc/passwd", "PathTraversal", "phish-hack", "False"],
            ["0x3f4946fb8ab2c240a223b8ab58193451c5b243c98a69838256d079809f2d75a0", "TxHash64", "phish-hack", "False"],
            ["   ", "Whitespace", "phish-hack", "False"],
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        batch = parse_forta_csv(csv_file)
        assert batch.valid_records == 0
        assert batch.rejected_records == len(rows) - 1

    def test_real_forta_csv_datasets_parse_cleanly(self):
        """Empirically verify all 3 real Forta CSV benchmark datasets parse without error."""
        manifest = [
            ("phishing_scams.csv", 6726),
            ("malicious_smart_contracts.csv", 753),
            ("etherscan_malicious_labels.csv", 7780),
        ]
        for filename, expected_count in manifest:
            path = RAW_DATASETS_DIR / filename
            assert path.is_file(), f"Dataset file missing: {path}"
            batch = parse_csv_file(path)
            assert batch.valid_records == expected_count, (
                f"{filename}: expected {expected_count} valid records, got {batch.valid_records}"
            )
            assert batch.rejected_records == 0
            assert batch.file_sha256 == compute_file_sha256(path)
            assert len(batch.records) == expected_count


# =============================================================================
# 2. ADVERSARIAL JSON STRESS TESTS
# =============================================================================

class TestAdversarialJSON:
    """Stress-test suite for MEW Darklist JSON data adapter."""

    def test_invalid_date_strings_handled_gracefully(self, tmp_path: Path):
        """Stress-test date normalizer with out-of-range, non-date, empty, and malformed date strings."""
        assert normalize_mew_date(None) is None
        assert normalize_mew_date("") is None
        assert normalize_mew_date("   ") is None
        assert normalize_mew_date("not-a-date") is None
        assert normalize_mew_date("99/99/99") is None
        assert normalize_mew_date("12345") is None
        assert normalize_mew_date(1605571200) is None  # integer timestamp
        assert normalize_mew_date({"year": 2020}) is None  # dict
        assert normalize_mew_date(["2020-11-17"]) is None  # list
        assert normalize_mew_date(True) is None  # boolean

        # Valid date formats must normalize cleanly
        assert normalize_mew_date("2020-11-17") == "2020-11-17T00:00:00Z"
        assert normalize_mew_date("7/22/17") == "2017-07-22T00:00:00Z"
        assert normalize_mew_date("07/22/2017") == "2017-07-22T00:00:00Z"
        assert normalize_mew_date("2020-11-17T15:30:00Z") == "2020-11-17T15:30:00Z"

    def test_missing_fields_nulls_and_malformed_objects(self, tmp_path: Path):
        """Verify missing fields, null values, and non-object array items are rejected gracefully."""
        json_file = tmp_path / "edge_cases.json"
        data = [
            # 1. Valid record
            {"address": "0x09750ad360fdb7a2ee23669c4503c974d86d8694", "comment": "Legit", "date": "2020-11-17"},
            # 2. Missing address field
            {"comment": "No address", "date": "2020-11-17"},
            # 3. Address is null
            {"address": None, "comment": "Null address", "date": "2020-11-17"},
            # 4. Comment is null (should be valid, comment becomes None)
            {"address": "0x000000000532b45f47779fce440748893b257865", "comment": None, "date": "2020-11-17"},
            # 5. Date is null (should be valid, date becomes None)
            {"address": "0x000000000532b45f47779fce440748893b257866", "comment": "Null date", "date": None},
            # 6. Entire item is null
            None,
            # 7. Item is integer
            12345,
            # 8. Item is string
            "just_a_string",
            # 9. Item is list
            ["nested_list"],
            # 10. Empty dict {}
            {},
            # 11. Malformed address
            {"address": "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
        ]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        batch = parse_mew_darklist_json(json_file)
        # Valid records: items 0, 3, 4 (3 records)
        assert batch.valid_records == 3
        # Rejected records: items 1, 2, 5, 6, 7, 8, 9, 10 (8 records)
        assert batch.rejected_records == 8
        assert batch.total_raw_records == len(data)

    def test_formula_injection_in_comment_neutralized(self, tmp_path: Path):
        """Verify formula injection in JSON comment field is safely sanitized with apostrophe prefix."""
        json_file = tmp_path / "formula_comment.json"
        data = [
            {
                "address": "0x09750ad360fdb7a2ee23669c4503c974d86d8694",
                "comment": "=cmd|' /C calc'!A0",
                "date": "2020-11-17",
            },
            {
                "address": "0xc915ec7f4cfd1c0a8aba090f03bfaab588aef9b4",
                "comment": "@SUM(1+1)",
                "date": "2020-11-14",
            },
            {
                "address": "0xecb6ffac05d8b4660b99b475b359fe454c77d153",
                "comment": "+malicious",
                "date": "",
            },
            {
                "address": "0x000000000532b45f47779fce440748893b257865",
                "comment": "-1+1",
                "date": "",
            },
            {
                "address": "0x000000000532b45f47779fce440748893b257866",
                "comment": "\t=cmd",
                "date": "",
            },
        ]
        json_file.write_text(json.dumps(data), encoding="utf-8")

        batch = parse_mew_darklist_json(json_file)
        assert batch.valid_records == 5
        for rec in batch.records:
            meta = json.loads(rec.raw_metadata_json)
            comment = meta["comment"]
            assert comment.startswith("'"), f"Comment formula not neutralized: {comment!r}"

    def test_non_list_root_and_syntax_errors(self, tmp_path: Path):
        """Verify malformed JSON syntax and non-list root are captured as rejections without crashing."""
        # Non-list root: dict
        p_dict = tmp_path / "root_dict.json"
        p_dict.write_text('{"status": "error"}', encoding="utf-8")
        b1 = parse_mew_darklist_json(p_dict)
        assert b1.rejected_records == 1
        assert "SCHEMA_VIOLATION" in b1.rejections[0]["rejection_reason"]

        # Syntax error: unclosed brace
        p_syntax = tmp_path / "broken.json"
        p_syntax.write_text('[{"address": "0x123"', encoding="utf-8")
        b2 = parse_mew_darklist_json(p_syntax)
        assert b2.rejected_records == 1
        assert "MALFORMED_JSON_SYNTAX" in b2.rejections[0]["rejection_reason"]

    def test_real_mew_darklist_dataset_parses_cleanly(self):
        """Empirically verify addresses-darklist.json parses all 715 records cleanly."""
        path = RAW_DATASETS_DIR / "addresses-darklist.json"
        assert path.is_file(), f"Dataset file missing: {path}"
        batch = parse_json_file(path)
        assert batch.valid_records == 715
        assert batch.rejected_records == 0
        assert batch.total_raw_records == 715
        assert batch.file_sha256 == compute_file_sha256(path)


# =============================================================================
# 3. ADVERSARIAL EXCEL (XLSX) STRESS TESTS
# =============================================================================

class TestAdversarialExcel:
    """Stress-test suite for PTXPhish Excel data adapter and OpenXML fallback engine."""

    def test_openxml_fallback_fidelity_ptxphish(self):
        """Verify 100% fidelity between openpyxl and pure standard-library OpenXML fallback on PTXPHISH.xlsx."""
        ptx_path = RAW_DATASETS_DIR / "PTXPHISH.xlsx"
        assert ptx_path.is_file(), f"PTXPHISH.xlsx missing at {ptx_path}"

        batch_openpyxl = parse_xlsx_file(ptx_path, force_fallback=False)
        batch_fallback = parse_xlsx_file(ptx_path, force_fallback=True)

        assert batch_openpyxl.valid_records == 18555
        assert batch_fallback.valid_records == 18555
        assert batch_openpyxl.rejected_records == 0
        assert batch_fallback.rejected_records == 0
        assert len(batch_openpyxl.records) == len(batch_fallback.records)

        # Field-by-field 100% fidelity assertion across all 18,555 records
        for i in range(len(batch_openpyxl.records)):
            r_op = batch_openpyxl.records[i]
            r_fb = batch_fallback.records[i]
            assert r_op.row_identifier == r_fb.row_identifier, f"Row {i} row_identifier mismatch"
            assert r_op.entity_type == r_fb.entity_type, f"Row {i} entity_type mismatch"
            assert r_op.entity_value == r_fb.entity_value, f"Row {i} entity_value mismatch"
            assert r_op.threat_category == r_fb.threat_category, f"Row {i} threat_category mismatch"
            assert r_op.threat_sub_tactic == r_fb.threat_sub_tactic, f"Row {i} threat_sub_tactic mismatch"
            assert r_op.data_source == r_fb.data_source, f"Row {i} data_source mismatch"
            assert r_op.raw_metadata_json == r_fb.raw_metadata_json, f"Row {i} metadata mismatch"

    def test_openxml_fallback_fidelity_initial_address(self):
        """Verify 100% fidelity between openpyxl and OpenXML fallback on InitialAddress.xlsx."""
        init_path = RAW_DATASETS_DIR / "InitialAddress.xlsx"
        assert init_path.is_file(), f"InitialAddress.xlsx missing at {init_path}"

        batch_openpyxl = parse_xlsx_file(init_path, force_fallback=False)
        batch_fallback = parse_xlsx_file(init_path, force_fallback=True)

        assert batch_openpyxl.valid_records == 312
        assert batch_fallback.valid_records == 312
        assert batch_openpyxl.rejected_records == 0
        assert batch_fallback.rejected_records == 0
        assert len(batch_openpyxl.records) == len(batch_fallback.records)

        for i in range(len(batch_openpyxl.records)):
            r_op = batch_openpyxl.records[i]
            r_fb = batch_fallback.records[i]
            assert r_op.entity_value == r_fb.entity_value
            assert r_op.threat_category == r_fb.threat_category
            assert r_op.threat_sub_tactic == r_fb.threat_sub_tactic
            assert r_op.raw_metadata_json == r_fb.raw_metadata_json

    def test_simulated_absent_openpyxl(self, monkeypatch):
        """Verify adapter functions seamlessly when openpyxl is completely absent from Python environment."""
        monkeypatch.setitem(sys.modules, "openpyxl", None)

        ptx_path = RAW_DATASETS_DIR / "PTXPHISH.xlsx"
        init_path = RAW_DATASETS_DIR / "InitialAddress.xlsx"

        # force_fallback is False, but openpyxl is None -> must automatically fallback
        batch_ptx = parse_xlsx_file(ptx_path, force_fallback=False)
        assert batch_ptx.valid_records == 18555

        batch_init = parse_xlsx_file(init_path, force_fallback=False)
        assert batch_init.valid_records == 312

    def test_hyperlinks_are_inert_strings(self, tmp_path: Path):
        """Adversarially verify that URLs and formula hyperlinks are treated as inert strings (never dereferenced)."""
        xlsx_path = tmp_path / "inert_hyperlinks.xlsx"
        tx1 = "0x3f4946fb8ab2c240a223b8ab58193451c5b243c98a69838256d079809f2d75a0"
        tx2 = "0x3ff7d30d032473e831a6121930b2ab2dc2d1df2bb90bb7164d3d357132107697"

        # Sheet with formula hyperlink and http url
        rows = [
            ["TXSPHISH", None],
            ["Exploiting legitimate contracts", None],
            ["Ice phishing scam", None],
            ["Approve", "Source"],
            [tx1, '=HYPERLINK("http://127.0.0.1:9999/pwn", "click_here")'],
            [tx2, "https://twitter.com/scamsniffer/status/123456"],
        ]
        build_test_xlsx(xlsx_path, {"Sheet1": rows})

        batch = parse_xlsx_file(xlsx_path, force_fallback=True)
        assert batch.valid_records == 2

        # Formula hyperlink sanitized
        meta1 = json.loads(batch.records[0].raw_metadata_json)
        assert meta1["evidence_url"].startswith("'=HYPERLINK")

        # Plain URL treated as inert string
        meta2 = json.loads(batch.records[1].raw_metadata_json)
        assert meta2["evidence_url"] == "https://twitter.com/scamsniffer/status/123456"

    def test_numeric_and_scientific_address_recovery(self, tmp_path: Path):
        """Verify recover_numeric_address safely handles numbers, scientific notation, and rejections."""
        # Valid addresses
        assert recover_numeric_address("0x7f9241ac942ba97085ef1a1542d270bfd6a987fd") == "0x7f9241ac942ba97085ef1a1542d270bfd6a987fd"
        assert recover_numeric_address("7f9241ac942ba97085ef1a1542d270bfd6a987fd") == "0x7f9241ac942ba97085ef1a1542d270bfd6a987fd"

        # Invalid / non-numeric string inputs
        assert recover_numeric_address(None) is None
        assert recover_numeric_address("") is None
        assert recover_numeric_address("not_an_address") is None
        assert recover_numeric_address("0x123") is None
        assert recover_numeric_address("-100") is None  # negative numbers fail 40-hex regex

        # EMPIRICAL ADVERSARIAL OBSERVATION:
        # recover_numeric_address treats any positive integer <= 2**160-1 as a valid address
        # by zero-padding to 40 hex digits (e.g., 12345 -> 0x0000000000000000000000000000000000003039).
        recovered_int = recover_numeric_address(12345)
        assert recovered_int == "0x0000000000000000000000000000000000003039"

    def test_initial_address_tx_tatal_aliasing(self, tmp_path: Path):
        """Verify 'Tx_tatal' typo in InitialAddress schema is reliably aliased to 'Tx_total'."""
        xlsx_path = tmp_path / "tatal_alias.xlsx"
        addr = "0x7f9241ac942ba97085ef1a1542d270bfd6a987fd"
        rows = [
            ["Approve", "Tx_tatal", "Type"],
            [addr, "42", "1"],
        ]
        build_test_xlsx(xlsx_path, {"Sheet1": rows})

        batch = parse_xlsx_file(xlsx_path, force_fallback=True)
        assert batch.valid_records == 1
        meta = json.loads(batch.records[0].raw_metadata_json)
        assert "Tx_total" in meta
        assert meta["Tx_total"] == "42"
        assert "Tx_tatal" not in meta
