"""Dual-mode data adapter for PTXPhish Excel (.xlsx) security benchmark datasets.

Supports dual-mode execution:
1. Primary: Uses `openpyxl` if installed.
2. Fallback: Pure Python standard library OpenXML reader using `zipfile` and
   `xml.etree.ElementTree.iterparse`, with zero external dependencies.

Features:
- Columnar matrix unpivoting for PTXPHISH.xlsx and InitialAddress.xlsx without cross-column corruption.
- Aliases 'Tx_tatal' -> 'Tx_total' for InitialAddress schema compatibility.
- Treats external hyperlinks and URLs as inert text (never dereferences).
- Safely recovers numeric/scientific-notation coerced hexadecimal addresses.
- Multi-sheet workbook taxonomy support.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple
import zipfile
import xml.etree.ElementTree as ET

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    compute_file_sha256,
    compute_payload_sha256,
    current_iso_utc,
    is_valid_eth_address,
    is_valid_tx_hash,
    normalize_eth_address,
    normalize_tx_hash,
    sanitize_formula_injection,
    sanitize_metadata_dict,
)

# Standard PTXPhish commit hash from discovery manifest
DEFAULT_PTXPHISH_COMMIT = "1ef8d02d6312baf3a6ba884691d63db493863fe5"

TACTIC_TO_CATEGORY = {
    # Ice Phishing tactics
    "approve": "ICE_PHISHING",
    "permit": "ICE_PHISHING",
    "setapproveforall": "ICE_PHISHING",
    "ice phishing scam": "ICE_PHISHING",
    "ice phishing": "ICE_PHISHING",
    # NFT Order Phishing tactics
    "bulk transfer": "NFT_ORDER_EXPLOIT",
    "proxy upgrade": "NFT_ORDER_EXPLOIT",
    "free buy order": "NFT_ORDER_EXPLOIT",
    "nft order scam": "NFT_ORDER_EXPLOIT",
    "nft order": "NFT_ORDER_EXPLOIT",
    # Address Poisoning tactics
    "zero value transfer": "ADDRESS_POISONING",
    "fake token transfer": "ADDRESS_POISONING",
    "dust value transfer": "ADDRESS_POISONING",
    "address poisoning scam": "ADDRESS_POISONING",
    "address poisoning": "ADDRESS_POISONING",
    # Payable Function Phishing tactics
    "airdrop function": "PAYABLE_TRAP",
    "wallet function": "PAYABLE_TRAP",
    "payable function scam": "PAYABLE_TRAP",
    "payable function": "PAYABLE_TRAP",
    # Benign Control Groups
    "benign kol": "BENIGN_CONTROL",
    "benign developer": "BENIGN_CONTROL",
    "benign": "BENIGN_CONTROL",
}

OPENXML_NS = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


def map_ptx_category(label: Optional[str]) -> str:
    """Map tactic or sheet label to canonical threat category."""
    if not label:
        return "UNKNOWN_THREAT"
    normalized = str(label).strip().lower()
    return TACTIC_TO_CATEGORY.get(normalized, "UNKNOWN_THREAT")


def split_cell_ref(ref: str) -> Tuple[str, int]:
    """Split cell coordinate (e.g. 'AB12') into column letters and row number."""
    col = "".join(ch for ch in ref if ch.isalpha()).upper()
    row = int("".join(ch for ch in ref if ch.isdigit()))
    return col, row


def col_letters_to_index(col_str: str) -> int:
    """Convert column letters ('A', 'B', 'AA') to 0-based index."""
    idx = 0
    for ch in col_str.upper():
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def index_to_col_letters(col_idx: int) -> str:
    """Convert 0-based column index to column letters ('A', 'B', 'AA')."""
    result = []
    num = col_idx + 1
    while num > 0:
        num, rem = divmod(num - 1, 26)
        result.append(chr(ord("A") + rem))
    return "".join(reversed(result))


def recover_numeric_address(val: Any) -> Optional[str]:
    """Safely recover numeric or scientific notation values into 40-hex address strings."""
    if val is None:
        return None
    val_str = str(val).strip()
    if is_valid_eth_address(val_str):
        return normalize_eth_address(val_str)
    # Check if string without 0x is 40 hex chars
    if len(val_str) == 40 and re.match(r"^[0-9a-fA-F]{40}$", val_str):
        return f"0x{val_str.lower()}"
    # Check if number coerced by spreadsheet
    try:
        if isinstance(val, (int, float)) or (isinstance(val_str, str) and ("e+" in val_str.lower() or val_str.isdigit())):
            int_val = int(float(val_str))
            hex_cand = f"{int_val:040x}"
            if len(hex_cand) == 40 and re.match(r"^[0-9a-fA-F]{40}$", hex_cand):
                return f"0x{hex_cand.lower()}"
    except (ValueError, OverflowError):
        pass
    return None


class OpenXMLFallbackWorkbook:
    """Standard-library pure Python OpenXML reader for .xlsx archives."""

    def __init__(self, file_path: Path | str):
        self.file_path = Path(file_path)
        self.shared_strings: List[str] = []
        self.sheet_targets: Dict[str, str] = {}
        self._load_workbook_structure()

    def _load_workbook_structure(self) -> None:
        with zipfile.ZipFile(self.file_path, "r") as z:
            # 1. Read shared strings if present
            if "xl/sharedStrings.xml" in z.namelist():
                tree = ET.fromstring(z.read("xl/sharedStrings.xml"))
                ns = f"{{{OPENXML_NS['main']}}}"
                for si in tree.iter(f"{ns}si"):
                    parts = [t.text or "" for t in si.iter(f"{ns}t")]
                    self.shared_strings.append("".join(parts))

            # 2. Read relationships to map sheet IDs to worksheet XML filenames
            rels_map: Dict[str, str] = {}
            if "xl/_rels/workbook.xml.rels" in z.namelist():
                tree = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
                for rel in tree.iter("{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                    r_id = rel.attrib.get("Id", "")
                    target = rel.attrib.get("Target", "")
                    if not target.startswith("xl/"):
                        target = "xl/" + target.lstrip("/")
                    rels_map[r_id] = target

            # 3. Read sheet names and map to zip paths
            if "xl/workbook.xml" in z.namelist():
                tree = ET.fromstring(z.read("xl/workbook.xml"))
                ns = f"{{{OPENXML_NS['main']}}}"
                for s in tree.iter(f"{ns}sheet"):
                    name = s.attrib.get("name", "")
                    r_id = s.attrib.get(f"{{{OPENXML_NS['rel']}}}id", "")
                    target_path = rels_map.get(r_id, f"xl/worksheets/sheet1.xml")
                    self.sheet_targets[name] = target_path

    @property
    def sheet_names(self) -> List[str]:
        return list(self.sheet_targets.keys())

    @property
    def sheetnames(self) -> List[str]:
        return list(self.sheet_targets.keys())

    def iter_sheet_cells(self, sheet_name: str) -> Generator[Tuple[str, int, Any], None, None]:
        """Stream (col_letters, row_num, cell_value) for a worksheet."""
        target_path = self.sheet_targets.get(sheet_name)
        if not target_path:
            return

        with zipfile.ZipFile(self.file_path, "r") as z:
            if target_path not in z.namelist():
                return
            with z.open(target_path) as sheet_file:
                # iterparse for memory efficiency
                for event, elem in ET.iterparse(sheet_file, events=("end",)):
                    if elem.tag.endswith("c"):
                        ref = elem.attrib.get("r", "")
                        if not ref:
                            elem.clear()
                            continue
                        col, row = split_cell_ref(ref)
                        cell_type = elem.attrib.get("t", "")
                        v_el = elem.find(f"{{{OPENXML_NS['main']}}}v")
                        val: Any = v_el.text if v_el is not None else None

                        if cell_type == "s" and val is not None:
                            try:
                                sst_idx = int(val)
                                val = self.shared_strings[sst_idx]
                            except (ValueError, IndexError):
                                val = None
                        elif cell_type == "b" and val is not None:
                            val = bool(val == "1")
                        elif cell_type == "inlineStr":
                            t_el = elem.find(f".//{{{OPENXML_NS['main']}}}t")
                            val = t_el.text if t_el is not None else None

                        yield col, row, val
                        elem.clear()


def parse_ptxphish_matrix(
    cells: Dict[Tuple[str, int], Any],
    file_path: Path,
    file_sha256: str,
    source_commit: str,
    sheet_name: str,
) -> ThreatIntelBatch:
    """Unpivot PTXPHISH.xlsx columnar tactic-source matrix."""
    batch = ThreatIntelBatch(
        source_id="ptxphish_matrix",
        source_name="ptxphish",
        file_path=str(file_path),
        file_sha256=file_sha256,
        source_commit=source_commit,
    )

    # Inspect row 4 for tactic columns
    # Tactic columns are paired with an adjacent 'Source' column (except Benign columns)
    tactic_cols: Dict[str, Dict[str, Any]] = {}
    row4_cells = {col: val for (col, row), val in cells.items() if row == 4 and val}

    for col, title in row4_cells.items():
        if title == "Source":
            continue
        col_idx = col_letters_to_index(col)
        next_col = index_to_col_letters(col_idx + 1)
        has_source = (row4_cells.get(next_col) == "Source")

        # Determine broad category from row 3 or column title
        cat_title = cells.get((col, 3)) or title
        category = map_ptx_category(title)
        if category == "UNKNOWN_THREAT":
            category = map_ptx_category(cat_title)

        tactic_cols[col] = {
            "title": title,
            "category": category,
            "has_source": has_source,
            "source_col": next_col if has_source else None,
        }

    # Find maximum row number
    max_row = max((row for (col, row) in cells.keys()), default=4)

    for row in range(5, max_row + 1):
        for col, meta in tactic_cols.items():
            val = cells.get((col, row))
            if not val:
                continue

            batch.total_raw_records += 1
            row_id = f"{sheet_name}:{col}{row}"
            val_str = str(val).strip()

            source_url = ""
            if meta["has_source"]:
                source_col = meta["source_col"]
                source_val = cells.get((source_col, row))
                if source_val:
                    # Treat hyperlinks and URLs as inert text
                    source_url = sanitize_formula_injection(str(source_val).strip())

            # Check if value is a 64-hex transaction hash or a 40-hex address
            is_tx = is_valid_tx_hash(val_str)
            is_addr = is_valid_eth_address(val_str)

            if not is_tx and not is_addr:
                batch.rejections.append({
                    "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:invalid_entity"),
                    "source_file_sha256": file_sha256,
                    "row_identifier": row_id,
                    "raw_payload": val_str,
                    "rejection_reason": f"INVALID_HEX_IDENTIFIER: {val_str!r}",
                    "rejected_at": current_iso_utc(),
                })
                batch.rejected_records += 1
                continue

            if is_tx:
                entity_type = "tx_hash"
                entity_value = normalize_tx_hash(val_str)
            else:
                entity_type = "address"
                entity_value = normalize_eth_address(val_str)

            metadata_dict = {
                "tactic": meta["title"],
                "evidence_url": source_url,
                "cell": f"{col}{row}",
            }
            sanitized_metadata = sanitize_metadata_dict(metadata_dict)
            raw_payload_sha256 = compute_payload_sha256(f"{val_str}|{source_url}")

            record = ThreatIntelRecord(
                source_file_path=str(file_path),
                source_file_sha256=file_sha256,
                source_commit=source_commit,
                row_identifier=row_id,
                raw_payload_sha256=raw_payload_sha256,
                entity_type=entity_type,
                entity_value=entity_value,
                threat_category=meta["category"],
                threat_sub_tactic=meta["title"],
                confidence_score=1.0,
                data_source="ptxphish",
                raw_metadata_json=json.dumps(sanitized_metadata, separators=(",", ":")),
                ingestion_timestamp=current_iso_utc(),
            )
            batch.records.append(record)
            batch.valid_records += 1

    return batch


def parse_initial_address_matrix(
    cells: Dict[Tuple[str, int], Any],
    file_path: Path,
    file_sha256: str,
    source_commit: str,
    sheet_name: str,
) -> ThreatIntelBatch:
    """Unpivot InitialAddress.xlsx column triplets (<Tactic>, 'Tx_tatal', 'Type')."""
    batch = ThreatIntelBatch(
        source_id="ptxphish_initial_address",
        source_name="ptxphish",
        file_path=str(file_path),
        file_sha256=file_sha256,
        source_commit=source_commit,
    )

    # Row 1 headers define tactic triplets:
    # Col i: Tactic name (e.g. 'Approve')
    # Col i+1: 'Tx_tatal'
    # Col i+2: 'Type'
    row1_cells = {col: val for (col, row), val in cells.items() if row == 1 and val}
    tactic_triplets: List[Dict[str, Any]] = []

    for col, title in sorted(row1_cells.items(), key=lambda kv: col_letters_to_index(kv[0])):
        title_clean = str(title).strip()
        if title_clean in ("Tx_tatal", "Tx_total", "Type"):
            continue

        col_idx = col_letters_to_index(col)
        tx_col = index_to_col_letters(col_idx + 1)
        type_col = index_to_col_letters(col_idx + 2)

        category = map_ptx_category(title_clean)
        tactic_triplets.append({
            "col": col,
            "tx_col": tx_col,
            "type_col": type_col,
            "tactic": title_clean,
            "category": category,
        })

    max_row = max((row for (col, row) in cells.keys()), default=1)

    for row in range(2, max_row + 1):
        for triplet in tactic_triplets:
            col = triplet["col"]
            val = cells.get((col, row))
            if not val:
                continue

            batch.total_raw_records += 1
            row_id = f"{sheet_name}:{col}{row}"

            # Safely recover numeric or scientific notation hex address
            addr_candidate = recover_numeric_address(val)
            if not addr_candidate:
                batch.rejections.append({
                    "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:invalid_addr"),
                    "source_file_sha256": file_sha256,
                    "row_identifier": row_id,
                    "raw_payload": str(val),
                    "rejection_reason": f"INVALID_INITIAL_ADDRESS: {val!r}",
                    "rejected_at": current_iso_utc(),
                })
                batch.rejected_records += 1
                continue

            tx_total_val = cells.get((triplet["tx_col"], row))
            type_val = cells.get((triplet["type_col"], row))

            # Aliasing 'Tx_tatal' -> 'Tx_total'
            metadata_dict = {
                "tactic": triplet["tactic"],
                "Tx_total": sanitize_formula_injection(str(tx_total_val)) if tx_total_val is not None else None,
                "Type": sanitize_formula_injection(str(type_val)) if type_val is not None else None,
            }
            sanitized_metadata = sanitize_metadata_dict(metadata_dict)
            raw_payload_sha256 = compute_payload_sha256(f"{val}|{tx_total_val}|{type_val}")

            record = ThreatIntelRecord(
                source_file_path=str(file_path),
                source_file_sha256=file_sha256,
                source_commit=source_commit,
                row_identifier=row_id,
                raw_payload_sha256=raw_payload_sha256,
                entity_type="address",
                entity_value=addr_candidate,
                threat_category=triplet["category"],
                threat_sub_tactic=triplet["tactic"],
                confidence_score=1.0,
                data_source="ptxphish",
                raw_metadata_json=json.dumps(sanitized_metadata, separators=(",", ":")),
                ingestion_timestamp=current_iso_utc(),
            )
            batch.records.append(record)
            batch.valid_records += 1

    return batch


def parse_standard_multisheet_workbook(
    sheet_data: Dict[str, Dict[Tuple[str, int], Any]],
    file_path: Path,
    file_sha256: str,
    source_commit: str,
) -> ThreatIntelBatch:
    """Parse standard multi-sheet workbook where each sheet represents a tactic or category."""
    batch = ThreatIntelBatch(
        source_id="ptxphish_multisheet",
        source_name="ptxphish",
        file_path=str(file_path),
        file_sha256=file_sha256,
        source_commit=source_commit,
    )

    for sheet_name, cells in sheet_data.items():
        sheet_category = map_ptx_category(sheet_name)
        # Find header columns in row 1
        headers = {col: str(val).strip().lower() for (col, row), val in cells.items() if row == 1 and val}
        max_row = max((row for (col, row) in cells.keys()), default=1)

        addr_col = None
        for col, col_name in headers.items():
            if col_name in ("address", "contract_address", "target_address", "addr"):
                addr_col = col
                break

        # If no address header found, check column A
        if not addr_col:
            addr_col = "A"

        for row in range(2, max_row + 1):
            val = cells.get((addr_col, row))
            if not val:
                continue

            batch.total_raw_records += 1
            row_id = f"{sheet_name}:{addr_col}{row}"
            addr_cand = recover_numeric_address(val)

            if not addr_cand:
                batch.rejections.append({
                    "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:invalid_addr"),
                    "source_file_sha256": file_sha256,
                    "row_identifier": row_id,
                    "raw_payload": str(val),
                    "rejection_reason": f"INVALID_ADDRESS_SYNTAX: {val!r}",
                    "rejected_at": current_iso_utc(),
                })
                batch.rejected_records += 1
                continue

            row_metadata = {
                headers.get(col, col): sanitize_formula_injection(str(cells.get((col, row), "")))
                for col in headers
            }
            sanitized_metadata = sanitize_metadata_dict(row_metadata)

            record = ThreatIntelRecord(
                source_file_path=str(file_path),
                source_file_sha256=file_sha256,
                source_commit=source_commit,
                row_identifier=row_id,
                raw_payload_sha256=compute_payload_sha256(str(val)),
                entity_type="address",
                entity_value=addr_cand,
                threat_category=sheet_category,
                threat_sub_tactic=sheet_name,
                confidence_score=1.0,
                data_source="ptxphish",
                raw_metadata_json=json.dumps(sanitized_metadata, separators=(",", ":")),
                ingestion_timestamp=current_iso_utc(),
            )
            batch.records.append(record)
            batch.valid_records += 1

    return batch


def parse_ptxphish_xlsx(
    file_path: Path | str,
    source_commit: str = DEFAULT_PTXPHISH_COMMIT,
    source_id: Optional[str] = None,
    force_fallback: bool = False,
) -> ThreatIntelBatch:
    """Parse PTXPhish Excel file using dual-mode engine (openpyxl or OpenXML fallback).

    Args:
        file_path: Path to .xlsx workbook.
        source_commit: Authoritative git commit hash.
        source_id: Custom source ID override.
        force_fallback: If True, forces pure Python standard-library OpenXML reader.

    Returns:
        ThreatIntelBatch with unpivoted records and rejections.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Excel file not found: {path}")

    file_sha256 = compute_file_sha256(path)

    # Dual-mode selection: check if openpyxl is available and not forced to fallback
    use_openpyxl = False
    if not force_fallback:
        try:
            import openpyxl  # noqa: F401
            use_openpyxl = True
        except ImportError:
            use_openpyxl = False

    sheet_cells: Dict[str, Dict[Tuple[str, int], Any]] = {}

    if use_openpyxl:
        import openpyxl
        wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
        for sname in wb.sheetnames:
            ws = wb[sname]
            cells: Dict[Tuple[str, int], Any] = {}
            for r_idx, row in enumerate(ws.iter_rows(values_only=False), start=1):
                for c_idx, cell in enumerate(row, start=1):
                    if cell.value is not None:
                        col_str = index_to_col_letters(c_idx - 1)
                        # Treats hyperlinks as inert text
                        val = cell.value
                        cells[(col_str, r_idx)] = val
            sheet_cells[sname] = cells
        wb.close()
    else:
        # Standard library OpenXML fallback
        reader = OpenXMLFallbackWorkbook(path)
        for sname in reader.sheetnames:
            cells = {}
            for col, row, val in reader.iter_sheet_cells(sname):
                if val is not None:
                    cells[(col, row)] = val
            sheet_cells[sname] = cells

    # Detect layout structure
    first_sheet = next(iter(sheet_cells.keys()), "Sheet1")
    cells_first = sheet_cells.get(first_sheet, {})

    # Check for PTXPHISH matrix signature: Row 1 has 'TXSPHISH' or Row 4 has 'Approve'/'Source'
    is_ptxphish_matrix = (
        cells_first.get(("A", 1)) == "TXSPHISH"
        or (cells_first.get(("A", 4)) == "Approve" and cells_first.get(("B", 4)) == "Source")
    )

    # Check for InitialAddress signature: Row 1 has 'Tx_tatal' or ('Approve' and 'Tx_tatal')
    is_initial_address = any(
        row == 1 and val in ("Tx_tatal", "Tx_total")
        for (col, row), val in cells_first.items()
    )

    if is_ptxphish_matrix:
        batch = parse_ptxphish_matrix(cells_first, path, file_sha256, source_commit, first_sheet)
    elif is_initial_address:
        batch = parse_initial_address_matrix(cells_first, path, file_sha256, source_commit, first_sheet)
    else:
        # Standard multi-sheet workbook
        batch = parse_standard_multisheet_workbook(sheet_cells, path, file_sha256, source_commit)

    if source_id:
        batch.source_id = source_id

    return batch


def parse_xlsx_file(
    file_path: Path | str,
    source_commit: str = DEFAULT_PTXPHISH_COMMIT,
    source_id: Optional[str] = None,
    force_fallback: bool = False,
) -> ThreatIntelBatch:
    """Convenience alias for Excel parsing."""
    return parse_ptxphish_xlsx(file_path, source_commit, source_id, force_fallback)
