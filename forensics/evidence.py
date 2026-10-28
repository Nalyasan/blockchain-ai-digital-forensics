"""Trích xuất và đóng gói chứng cứ kỹ thuật số có khả năng tái lập (Mục 6.2 & 6.3).
Quản lý manifest.json, tính package_digest và xác minh toàn vẹn gói chứng cứ.
"""
import os
import re
import json
import hashlib
import sqlite3
import logging
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

def export_evidence(
    case_id: str,
    start_block: int,
    end_block: int,
    out_dir: str = None,
    db_path: str = None,
    operator: str = None,
    allow_gaps: bool = False,
    require_final: bool = False
) -> dict:
    """Xuất gói chứng cứ có thể tái lập trong một transaction đọc nhất quán của SQLite.
    Tạo raw_blocks.jsonl, timeline.csv, asset_transfers.csv, audit_events.jsonl và manifest.json.
    """
    validate_case_id(case_id)
    op = get_operator(operator)
    db_file = db_path or os.environ.get("DB_PATH", "data/forensics.db")
    if not os.path.exists(db_file):
        raise FileNotFoundError(f"Không tìm thấy database SQLite tại '{db_file}'")

    target_dir = out_dir or os.path.join("evidence", case_id)
    os.makedirs(target_dir, exist_ok=True)

    # Đọc dữ liệu trong một READ TRANSACTION nhất quán duy nhất
    read_conn = sqlite3.connect(db_file, isolation_level=None)
    try:
        read_conn.execute("BEGIN DEFERRED")

        # 1. Truy vấn blocks
        blk_rows = read_conn.execute(
            "SELECT chain_id, number, hash, parent_hash, block_timestamp, block_time_utc, "
            "first_observed_at, collected_at, status, raw_json, raw_sha256, synthetic "
            "FROM blocks WHERE number BETWEEN ? AND ? ORDER BY number ASC, status ASC",
            (start_block, end_block)
        ).fetchall()

        if not blk_rows:
            raise ValueError(f"Không tìm thấy block nào trong khoảng {start_block}..{end_block}")

        # Kiểm tra thuần khiết synthetic: CẤM trộn 0 và 1 trong cùng một gói
        synthetics = set(r[11] for r in blk_rows)
        if 0 in synthetics and 1 in synthetics:
            raise ValueError("Không được trộn lẫn dữ liệu synthetic (1) và non-synthetic (0) trong cùng một gói chứng cứ")
        package_synthetic = list(synthetics)[0]

        # Kiểm tra block canonical và gaps
        canonical_rows = [r for r in blk_rows if r[8] == "canonical"]
        orphaned_rows = [r for r in blk_rows if r[8] == "orphaned"]
        canonical_nums = sorted(set(r[1] for r in canonical_rows))
        all_expected_nums = set(range(start_block, end_block + 1))
        missing_nums = sorted(all_expected_nums - set(canonical_nums))

        gaps = []
        if missing_nums:
            g_start = missing_nums[0]
            g_end = missing_nums[0]
            for num in missing_nums[1:]:
                if num == g_end + 1:
                    g_end = num
                else:
                    gaps.append([g_start, g_end])
                    g_start = g_end = num
            gaps.append([g_start, g_end])

            if not allow_gaps:
                raise ValueError(
                    f"Phát hiện {len(missing_nums)} block bị thiếu (gaps: {gaps}) trong khoảng {start_block}..{end_block}. "
                    "Sử dụng cờ --allow-gaps nếu muốn tiếp tục xuất gói."
                )

        # Kiểm tra unfinalized blocks theo CONFIRMATIONS
        confirmations = int(os.environ.get("CONFIRMATIONS", "2"))
        max_canonical = read_conn.execute("SELECT MAX(number) FROM blocks WHERE status='canonical'").fetchone()[0]
        unfinalized_threshold = (max_canonical - confirmations + 1) if max_canonical is not None else 0
        unfinalized_blocks = [n for n in canonical_nums if n >= unfinalized_threshold]

        if unfinalized_blocks:
            if require_final:
                raise ValueError(
                    f"Khoảng block chứa {len(unfinalized_blocks)} block chưa finalize (trong ngưỡng confirmations={confirmations}). "
                    "Từ chối xuất vì bật cờ --require-final."
                )
            is_finalized = False
        else:
            is_finalized = True

        # 2. Truy vấn transactions
        tx_rows = read_conn.execute(
            "SELECT chain_id, tx_hash, block_hash, block_number, tx_index, from_addr, to_addr, "
            "value_raw, nonce, input, raw_json, raw_sha256 FROM transactions "
            "WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC, tx_index ASC",
            (start_block, end_block)
        ).fetchall()

        # 3. Truy vấn asset_transfers
        transfer_rows = read_conn.execute(
            "SELECT transfer_id, chain_id, block_number, block_hash, block_timestamp, tx_hash, "
            "log_index, asset_id, from_addr, to_addr, amount_raw, synthetic FROM asset_transfers "
            "WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC, log_index ASC",
            (start_block, end_block)
        ).fetchall()

        # 4. Truy vấn audit_events liên quan đến các block này
        min_utc = min(r[5] for r in blk_rows if r[5]) if blk_rows else ""
        max_utc = max(r[5] for r in blk_rows if r[5]) if blk_rows else ""
        audit_all = read_conn.execute(
            "SELECT id, ts, action, object_ref, metadata FROM audit_events ORDER BY id ASC"
        ).fetchall()

        relevant_audits = []
        for a_row in audit_all:
            ref = a_row[3] or ""
            ts = a_row[1] or ""
            if any(f"block:{n}" in ref for n in range(start_block, end_block + 1)):
                relevant_audits.append(a_row)
            elif min_utc and max_utc and min_utc <= ts <= max_utc + "T23:59:59Z":
                relevant_audits.append(a_row)
            elif "COLLECT" in a_row[2] or "REORG" in a_row[2]:
                relevant_audits.append(a_row)

        if not relevant_audits and audit_all:
            relevant_audits = audit_all[-20:]

        # 5. Chạy integrity checks
        local_result = verify_local_range(read_conn, start_block, end_block)
        derived_result = verify_derived_range(read_conn, start_block, end_block)

        chain_id = blk_rows[0][0]
    finally:
        read_conn.execute("ROLLBACK")
        read_conn.close()

    # ---------- Ghi các file chứng cứ ra đĩa ----------
    # 1. raw_blocks.jsonl
    raw_blocks_path = os.path.join(target_dir, "raw_blocks.jsonl")
    with open(raw_blocks_path, "w", encoding="utf-8") as f:
        for r in blk_rows:
            item = {
                "chain_id": r[0],
                "number": r[1],
                "hash": r[2],
                "parent_hash": r[3],
                "block_timestamp": r[4],
                "block_time_utc": r[5],
                "first_observed_at": r[6],
                "collected_at": r[7],
                "status": r[8],
                "raw_sha256": r[10],
                "synthetic": r[11],
                "raw_json": json.loads(r[9]) if r[9] else None,
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    # 2. timeline.csv
    timeline_path = os.path.join(target_dir, "timeline.csv")
    with open(timeline_path, "w", encoding="utf-8") as f:
        f.write("timestamp_utc,block_number,event_type,tx_hash,from_addr,to_addr,asset_id,amount_raw,status\n")
        # Ghi các sự kiện theo thứ tự thời gian
        timeline_events = []
        for r in blk_rows:
            timeline_events.append({
                "ts": r[5], "b": r[1], "type": "BLOCK", "tx": "", "from": "", "to": "",
                "asset": "", "amount": "", "status": r[8]
            })
        for t in tx_rows:
            b_ts = next((r[5] for r in blk_rows if r[1] == t[3]), "")
            timeline_events.append({
                "ts": b_ts, "b": t[3], "type": "TX", "tx": t[1], "from": t[5] or "",
                "to": t[6] or "", "asset": "NATIVE", "amount": t[7] or "0", "status": "mined"
            })
        for tf in transfer_rows:
            b_ts = next((r[5] for r in blk_rows if r[1] == tf[2]), "")
            timeline_events.append({
                "ts": b_ts, "b": tf[2], "type": "TRANSFER", "tx": tf[5], "from": tf[8] or "",
                "to": tf[9] or "", "asset": tf[7], "amount": tf[10], "status": "success"
            })

        timeline_events.sort(key=lambda x: (x["ts"] or "", x["b"], x["type"], x["tx"]))
        for e in timeline_events:
            f.write(f"{e['ts']},{e['b']},{e['type']},{e['tx']},{e['from']},{e['to']},{e['asset']},{e['amount']},{e['status']}\n")

    # 3. asset_transfers.csv
    transfers_path = os.path.join(target_dir, "asset_transfers.csv")
    with open(transfers_path, "w", encoding="utf-8") as f:
        f.write("transfer_id,chain_id,block_number,block_hash,block_timestamp,tx_hash,log_index,asset_id,from_addr,to_addr,amount_raw,synthetic\n")
        for tf in transfer_rows:
            f.write(f"{tf[0]},{tf[1]},{tf[2]},{tf[3]},{tf[4]},{tf[5]},{tf[6]},{tf[7]},{tf[8]},{tf[9]},{tf[10]},{tf[11]}\n")

    # 4. audit_events.jsonl
    audits_path = os.path.join(target_dir, "audit_events.jsonl")
    with open(audits_path, "w", encoding="utf-8") as f:
        for a in relevant_audits:
            meta = json.loads(a[4]) if a[4] else {}
            f.write(json.dumps({"id": a[0], "ts": a[1], "action": a[2], "object_ref": a[3], "metadata": meta}, ensure_ascii=False) + "\n")

    # Tính kích thước và SHA-256 cho danh sách file
    package_files = [
        {"path": "raw_blocks.jsonl", "filepath": raw_blocks_path},
        {"path": "timeline.csv", "filepath": timeline_path},
        {"path": "asset_transfers.csv", "filepath": transfers_path},
        {"path": "audit_events.jsonl", "filepath": audits_path},
    ]

    files_manifest_list = []
    for p_info in package_files:
        files_manifest_list.append({
            "path": p_info["path"],
            "size_bytes": os.path.getsize(p_info["filepath"]),
            "sha256": compute_file_sha256(p_info["filepath"])
        })
    files_manifest_list.sort(key=lambda x: x["path"])

    # Tính package_digest xác định: SHA-256 của danh sách [[path, sha256], ...] đã sắp xếp, KHÔNG chứa thời gian
    digest_items = [[f["path"], f["sha256"]] for f in files_manifest_list]
    digest_payload = json.dumps(digest_items, separators=(',', ':'), ensure_ascii=False)
    package_digest = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()

    exported_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    manifest = {
        "manifest_version": "1.0.0",
        "case_id": case_id,
        "exported_at": exported_at,
        "operator": op,
        "chain_id": chain_id,
        "rpc_label": os.environ.get("RPC_LABEL", "unknown"),
        "synthetic": bool(package_synthetic),
        "block_range": {
            "start_block": start_block,
            "end_block": end_block
        },
        "block_timestamps_utc": {
            "start": min_utc,
            "end": max_utc
        },
        "software": {
            "version": __version__,
            "commit_hash": get_commit_hash()
        },
        "sanitized_config": sanitize_config(),
        "finalization": {
            "confirmations": confirmations,
            "is_finalized": is_finalized,
            "unfinalized_blocks_count": len(unfinalized_blocks),
            "unfinalized_blocks": unfinalized_blocks
        },
        "counts": {
            "total_blocks": len(blk_rows),
            "canonical_blocks": len(canonical_rows),
            "orphaned_blocks": len(orphaned_rows),
            "transactions": len(tx_rows),
            "asset_transfers": len(transfer_rows),
            "audit_events": len(relevant_audits)
        },
        "integrity_checks": {
            "verify_local": local_result,
            "verify_derived": derived_result,
            "gaps_count": len(missing_nums),
            "gaps": gaps
        },
        "package_digest": package_digest,
        "files": files_manifest_list
    }

    manifest_path = os.path.join(target_dir, "manifest.json")
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    with open(manifest_path, "wb") as f:
        f.write(manifest_bytes)

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    # Ghi nhận bản ghi xuất chứng cứ vào bảng evidence_exports của SQLite
    export_id = f"exp-{case_id}-{start_block}_{end_block}"
    storage_uri = f"evidence://{case_id}/manifest.json"
    manifest_rel_path = "manifest.json"

    write_conn = init_db(db_file)
    with write_conn:
        write_conn.execute(
            """INSERT OR REPLACE INTO evidence_exports(
                 export_id, case_id, manifest_path, manifest_sha256, storage_uri, created_at, operator, onchain_evidence_id
               ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (export_id, case_id, manifest_rel_path, manifest_sha256, storage_uri, exported_at, op)
        )

    log.info("Đã xuất gói chứng cứ %s vào %s (package_digest=%s, manifest_sha256=%s)",
             case_id, target_dir, package_digest, manifest_sha256)

    return manifest

def verify_manifest(manifest_path_or_dir: str, db_path: str = None) -> tuple[bool, list[str]]:
    """Xác minh gói chứng cứ trên đĩa đối chiếu với manifest.json và SQLite evidence_exports.
    Kiểm tra:
    1. Đường dẫn an toàn (không tuyệt đối, không chứa '..').
    2. Tồn tại, kích thước size_bytes và băm SHA-256 từng file.
    3. Không có file lạ thừa trong thư mục gói.
    4. package_digest khớp với danh sách file.
    5. manifest_sha256 khớp với bảng evidence_exports trong DB nếu db_path được cấp.
    Trả về (is_valid: bool, errors: list[str]).
    """
    errors = []
    if os.path.isdir(manifest_path_or_dir):
        pkg_dir = manifest_path_or_dir
        manifest_file = os.path.join(pkg_dir, "manifest.json")
    else:
        manifest_file = manifest_path_or_dir
        pkg_dir = os.path.dirname(manifest_file) or "."

    if not os.path.exists(manifest_file):
        return False, [f"MISMATCH: File manifest không tồn tại: {manifest_file}"]

    with open(manifest_file, "rb") as f:
        manifest_raw = f.read()
    computed_manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()

    try:
        manifest_data = json.loads(manifest_raw.decode("utf-8"))
    except Exception as e:
        return False, [f"MISMATCH: manifest.json không thể giải mã JSON ({e})"]

    if "files" not in manifest_data or not isinstance(manifest_data["files"], list):
        return False, ["MISMATCH: manifest.json thiếu trường 'files' hợp lệ"]

    manifest_files = manifest_data["files"]
    listed_paths = set()

    for item in manifest_files:
        rel_path = item.get("path")
        if not rel_path:
            errors.append("MISMATCH: Phần tử trong 'files' thiếu thuộc tính 'path'")
            continue

        # Kiểm tra an toàn đường dẫn: từ chối tuyệt đối hoặc chứa '..'
        norm_path = rel_path.replace("\\", "/")
        if norm_path.startswith("/") or ":" in norm_path:
            errors.append(f"MISMATCH: Từ chối đường dẫn tuyệt đối trong manifest: '{rel_path}'")
            continue
        parts = norm_path.split("/")
        if ".." in parts:
            errors.append(f"MISMATCH: Từ chối đường dẫn chứa '..' (path traversal) trong manifest: '{rel_path}'")
            continue

        listed_paths.add(norm_path)
        full_path = os.path.join(pkg_dir, *parts)

        if not os.path.exists(full_path):
            errors.append(f"MISMATCH: Thiếu file trên đĩa: {rel_path}")
            continue

        exp_size = item.get("size_bytes")
        act_size = os.path.getsize(full_path)
        if exp_size is not None and act_size != exp_size:
            errors.append(f"MISMATCH: Sai lệch kích thước file {rel_path}: kỳ vọng {exp_size}, thực tế {act_size}")

        exp_sha = item.get("sha256")
        act_sha = compute_file_sha256(full_path)
        if exp_sha and act_sha.lower() != exp_sha.lower():
            errors.append(f"MISMATCH: Sai lệch SHA-256 file {rel_path}: kỳ vọng {exp_sha}, thực tế {act_sha}")

    # Kiểm tra file lạ thừa trên đĩa không được liệt kê
    for root, _, filenames in os.walk(pkg_dir):
        for fname in filenames:
            if fname == "manifest.json":
                continue
            disk_rel = os.path.relpath(os.path.join(root, fname), pkg_dir).replace("\\", "/")
            if disk_rel not in listed_paths:
                errors.append(f"MISMATCH: Phát hiện file thừa trên đĩa không được liệt kê trong manifest: {disk_rel}")

    # Kiểm tra package_digest
    exp_digest = manifest_data.get("package_digest")
    if exp_digest:
        digest_items = [[f["path"], f["sha256"]] for f in sorted(manifest_files, key=lambda x: x.get("path", ""))]
        digest_payload = json.dumps(digest_items, separators=(',', ':'), ensure_ascii=False)
        calc_digest = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()
        if calc_digest.lower() != exp_digest.lower():
            errors.append(f"MISMATCH: Sai lệch package_digest: kỳ vọng {exp_digest}, tính toán {calc_digest}")

    # Kiểm tra đối chiếu với SQLite evidence_exports nếu db_path được cung cấp
    if db_path and os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        case_id = manifest_data.get("case_id")
        row = conn.execute(
            "SELECT manifest_sha256 FROM evidence_exports WHERE case_id=?",
            (case_id,)
        ).fetchone()
        conn.close()
        if not row:
            errors.append(f"MISMATCH: Không tìm thấy bản ghi case_id '{case_id}' trong evidence_exports của DB")
        elif row[0].lower() != computed_manifest_sha256.lower():
            errors.append(f"MISMATCH: manifest_sha256 không khớp với bản ghi DB: file={computed_manifest_sha256} vs DB={row[0]}")

    return len(errors) == 0, errors
