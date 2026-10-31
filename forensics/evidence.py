"""Trích xuất và đóng gói chứng cứ kỹ thuật số có khả năng tái lập (Mục 6.2 & 6.3).
Quản lý manifest.json, tính package_digest và xác minh toàn vẹn gói chứng cứ.
"""
import os
import re
import json
import hashlib
import sqlite3
import logging
import subprocess
from datetime import datetime, timezone

from forensics import __version__
from forensics.schemas import init_db
from collector import extract_transfers, sha, get_commit_hash

log = logging.getLogger("forensics.evidence")

# Regex bắt buộc cho case_id: chỉ ký tự thường, hoa, số, gạch ngang, gạch dưới, dài 1-64
CASE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Danh sách ALLOWLIST nghiêm ngặt cho cấu hình (Tuyệt đối KHÔNG có RPC_URL, key hay mật khẩu)
ALLOWED_CONFIG_KEYS = {
    "RPC_LABEL",
    "CONFIRMATIONS",
    "RPC_SYNTHETIC",
    "RATE_LIMIT_RPS",
    "POLL_INTERVAL",
    "TIMEOUT",
    "commit_hash",
    "version",
}

def validate_case_id(case_id: str) -> str:
    """Xác thực case_id theo biểu thức chính quy ^[A-Za-z0-9_-]{1,64}$."""
    if not isinstance(case_id, str) or not CASE_ID_REGEX.match(case_id):
        raise ValueError(
            f"case_id '{case_id}' không hợp lệ. Chỉ chấp nhận các ký tự [A-Za-z0-9_-] có độ dài từ 1 đến 64 ký tự."
        )
    return case_id

def get_operator(operator_arg: str = None) -> str:
    """Lấy định danh điều tra viên/operator từ đối số CLI hoặc biến OPERATOR_NAME.
    TUYỆT ĐỐI KHÔNG lấy username hệ điều hành.
    """
    op = operator_arg or os.environ.get("OPERATOR_NAME")
    if not op or not op.strip():
        return "unspecified"
    return op.strip()

def sanitize_config(extra_config: dict = None) -> dict:
    """Lọc cấu hình qua ALLOWLIST nghiêm ngặt để đưa vào manifest.json.
    Tuyệt đối không lưu RPC_URL (chứa API key), ANCHOR_*, *_KEY, *_PASSWORD.
    """
    base = {
        "RPC_LABEL": os.environ.get("RPC_LABEL", "unknown"),
        "CONFIRMATIONS": int(os.environ.get("CONFIRMATIONS", "2")),
        "RPC_SYNTHETIC": os.environ.get("RPC_SYNTHETIC", "false").lower() in ("true", "1", "yes"),
        "RATE_LIMIT_RPS": float(os.environ.get("RATE_LIMIT_RPS", "5")),
        "POLL_INTERVAL": float(os.environ.get("POLL_INTERVAL", "3")),
        "TIMEOUT": float(os.environ.get("TIMEOUT", "15")),
        "commit_hash": get_commit_hash(),
        "version": __version__,
    }
    if extra_config:
        for k, v in extra_config.items():
            if k in ALLOWED_CONFIG_KEYS:
                base[k] = v
    # Lọc lại lần cuối để đảm bảo 100% chỉ có ALLOWLIST
    return {k: base[k] for k in sorted(base.keys()) if k in ALLOWED_CONFIG_KEYS}

def is_working_tree_dirty() -> bool:
    from forensics.provenance import get_git_state
    state = get_git_state()
    if state.state == 'UNKNOWN':
        raise RuntimeError('GIT_UNKNOWN')
    return state.state == 'DIRTY'


def compute_file_sha256(filepath: str) -> str:
    """Tính SHA-256 của file trên đĩa."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def verify_local_range(c: sqlite3.Connection, start_block: int, end_block: int) -> dict:
    """Kiểm tra toàn vẹn SQLite cục bộ cho khoảng block: SHA-256 raw_json và parent_hash."""
    bad = 0
    # 1. Blocks
    blks = c.execute(
        "SELECT number, hash, parent_hash, raw_json, raw_sha256, status FROM blocks "
        "WHERE number BETWEEN ? AND ? ORDER BY number ASC, status ASC",
        (start_block, end_block)
    ).fetchall()

    prev_canonical = None
    for b_num, b_hash, b_parent, raw, raw_h, status in blks:
        if raw and sha(json.loads(raw)) != raw_h:
            bad += 1
        if status == "canonical":
            if prev_canonical and b_num == prev_canonical[0] + 1:
                if b_parent.lower() != prev_canonical[1].lower():
                    bad += 1
            prev_canonical = (b_num, b_hash)

    # 2. Transactions
    txs = c.execute(
        "SELECT raw_json, raw_sha256 FROM transactions WHERE block_number BETWEEN ? AND ?",
        (start_block, end_block)
    ).fetchall()
    for raw, raw_h in txs:
        if raw and sha(json.loads(raw)) != raw_h:
            bad += 1

    # 3. Receipts
    rcs = c.execute(
        "SELECT r.raw_json, r.raw_sha256 FROM receipts r "
        "JOIN transactions t ON t.chain_id=r.chain_id AND t.tx_hash=r.tx_hash AND t.block_hash=r.block_hash "
        "WHERE t.block_number BETWEEN ? AND ?",
        (start_block, end_block)
    ).fetchall()
    for raw, raw_h in rcs:
        if raw and sha(json.loads(raw)) != raw_h:
            bad += 1

    return {
        "status": "PASSED" if bad == 0 else "FAILED",
        "mismatches": bad
    }

def verify_derived_range(c: sqlite3.Connection, start_block: int, end_block: int) -> dict:
    """Kiểm tra tính khớp giữa asset_transfers và dữ liệu thô cho các block canonical."""
    bad = 0
    blocks = c.execute(
        "SELECT chain_id, number, hash, raw_json, synthetic FROM blocks "
        "WHERE status='canonical' AND number BETWEEN ? AND ? ORDER BY number",
        (start_block, end_block)
    ).fetchall()

    for chain_id, b_num, b_hash, blk_raw_json, synth in blocks:
        blk = json.loads(blk_raw_json)
        receipts = {}
        for tx_h, r_json in c.execute(
            "SELECT tx_hash, raw_json FROM receipts WHERE chain_id=? AND block_hash=?",
            (chain_id, b_hash)
        ).fetchall():
            receipts[tx_h.lower()] = json.loads(r_json)

        derived = extract_transfers(chain_id, blk, receipts, synth)
        derived_map = {(t["chain_id"], t["block_hash"], t["tx_hash"].lower(), t["log_index"]): t for t in derived}

        stored = c.execute(
            "SELECT chain_id, block_hash, tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic "
            "FROM asset_transfers WHERE chain_id=? AND block_hash=?",
            (chain_id, b_hash)
        ).fetchall()
        stored_map = {
            (r[0], r[1], r[2].lower(), r[3]): {
                "asset_id": r[4], "from_addr": r[5], "to_addr": r[6], "amount_raw": r[7], "synthetic": r[8]
            } for r in stored
        }

        if set(derived_map.keys()) != set(stored_map.keys()):
            bad += 1
            continue

        for k, d_tf in derived_map.items():
            s_tf = stored_map[k]
            for field in ("asset_id", "from_addr", "to_addr", "amount_raw", "synthetic"):
                if str(d_tf[field]).lower() != str(s_tf[field]).lower():
                    bad += 1

    return {
        "status": "PASSED" if bad == 0 else "FAILED",
        "mismatches": bad
    }

def export_evidence(case_id, start_block, end_block, out_dir=None, db_path=None,
                    operator=None, allow_gaps=False, require_final=False, chain_id=None,
                    migrate_group3_schema=False):
    from forensics.exporter import export_package
    return export_package(case_id, start_block, end_block, out_dir, db_path,
                          operator, allow_gaps, require_final, chain_id,
                          migrate_group3_schema=migrate_group3_schema)


def verify_manifest(manifest_path_or_dir, db_path=None):
    """Compatibility API; structured callers use integrity.verify_package."""
    from forensics.integrity import verify_package
    result = verify_package(manifest_path_or_dir, db_path)
    messages = {
        'UNSAFE_PATH': 'Từ chối đường dẫn tuyệt đối hoặc path traversal/alias không an toàn',
        'MISSING_FILE': 'Thiếu file trên đĩa',
        'EXTRA_FILE': 'Phát hiện file thừa trên đĩa',
        'HASH_MISMATCH': 'Sai lệch SHA-256',
        'SIZE_MISMATCH': 'Sai lệch kích thước',
        'DB_MANIFEST_MISMATCH': 'manifest_sha256 không khớp với bản ghi DB',
        'SEMANTIC_MISMATCH': 'Mâu thuẫn dữ liệu ngữ nghĩa',
        'SYNTHETIC_MISMATCH': 'Mâu thuẫn cờ synthetic',
        'SOURCE_LABEL_MISMATCH': 'Mâu thuẫn rpc_label',
    }
    codes = result.details.get('violations', [result.reason_code.value])
    return result.status == 'VALID', ([] if result.status == 'VALID' else [
        code + ': ' + messages.get(code, 'Không xác minh được gói chứng cứ') for code in codes])
