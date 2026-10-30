"""Kiểm thử tự động cho Giai đoạn P2:
- Quản lý Schema tập trung (13 bảng) và migration an toàn (forensics/schemas.py).
- Đóng gói chứng cứ tái lập (forensics/evidence.py).
- Danh sách ALLOWLIST cho cấu hình (loại bỏ hoàn toàn RPC_URL, secret, key).
- Kiểm tra toàn vẹn gói chứng cứ (verify-manifest) chống can thiệp, file thừa, sai lệch hash/size, path traversal.
- Kiểm tra package_digest xác định, không phụ thuộc thời gian.
- Kiểm tra validation case_id và operator.
- Kiểm tra cấm trộn lẫn synthetic.
- Kiểm tra kiểm soát data gaps và require-final.
- Giao diện CLI (forensics/cli.py).
"""
import os
import sys
import json
import sqlite3
import hashlib
import subprocess
import pytest
from datetime import datetime, timezone

from forensics.schemas import init_db, migrate_db, SCHEMA
from forensics.evidence import (
    export_evidence,
    verify_manifest,
    validate_case_id,
    get_operator,
    sanitize_config,
    ALLOWED_CONFIG_KEYS
)
from collector import sha

def populate_sample_db(db_path, num_blocks=5, synthetic=0):
    """Tạo DB mẫu chứa blocks, transactions, receipts, logs, asset_transfers, audit_events."""
    conn = init_db(db_path)
    chain_id = 31337
    prev_hash = "0x" + "0" * 64

    for n in range(num_blocks):
        b_hash = f"0x{n:064x}"
        utc_str = datetime.fromtimestamp(1700000000 + n * 12, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1 giao dịch ETH chuyển tiền
        tx_hash = f"0x{n+100:064x}"
        from_a = "0x1111111111111111111111111111111111111111"
        to_a = "0x2222222222222222222222222222222222222222"
        val = 1000000000000000000
        tx_obj = {
            "hash": tx_hash, "blockHash": b_hash, "blockNumber": hex(n), "transactionIndex": "0x0",
            "from": from_a, "to": to_a, "value": hex(val), "nonce": "0x0", "input": "0x"
        }
        tx_raw = json.dumps(tx_obj, sort_keys=True, separators=(',', ':'))
        tx_sha = sha(tx_obj)

        blk_data = {
            "number": hex(n),
            "hash": b_hash,
            "parentHash": prev_hash,
            "timestamp": hex(1700000000 + n * 12),
            "transactions": [tx_obj]
        }
        b_raw = json.dumps(blk_data, sort_keys=True, separators=(',', ':'))
        b_sha = sha(blk_data)

        conn.execute(
            "INSERT INTO blocks(chain_id, number, hash, parent_hash, block_timestamp, block_time_utc, "
            "first_observed_at, collected_at, status, raw_json, raw_sha256, synthetic) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'canonical', ?, ?, ?)",
            (chain_id, n, b_hash, prev_hash, 1700000000 + n * 12, utc_str, utc_str, utc_str, b_raw, b_sha, synthetic)
        )
        conn.execute(
            "INSERT INTO transactions(chain_id, tx_hash, block_hash, block_number, tx_index, "
            "from_addr, to_addr, value_raw, nonce, input, raw_json, raw_sha256) "
            "VALUES(?, ?, ?, ?, 0, ?, ?, ?, 0, '0x', ?, ?)",
            (chain_id, tx_hash, b_hash, n, from_a, to_a, str(val), tx_raw, tx_sha)
        )

        # Full RPC receipt identity is needed by the 1.1 completeness verifier.
        rc_obj = {"transactionHash": tx_hash, "blockHash": b_hash, "blockNumber": hex(n),
                  "transactionIndex": "0x0", "contractAddress": None,
                  "status": "0x1", "gasUsed": "0x5208", "logs": [],
                  "from": from_a, "to": to_a, "cumulativeGasUsed": "0x5208",
                  "effectiveGasPrice": "0x1", "logsBloom": "0x" + "0" * 512}
        rc_raw = json.dumps(rc_obj, sort_keys=True, separators=(',', ':'))
        rc_sha = sha(rc_obj)
        conn.execute(
            "INSERT INTO receipts(chain_id, tx_hash, block_hash, status, gas_used, raw_json, raw_sha256) "
            "VALUES(?, ?, ?, 1, 21000, ?, ?)",
            (chain_id, tx_hash, b_hash, rc_raw, rc_sha)
        )

        conn.execute(
            "INSERT INTO asset_transfers(chain_id, block_number, block_hash, block_timestamp, tx_hash, "
            "log_index, asset_id, from_addr, to_addr, amount_raw, synthetic) "
            "VALUES(?, ?, ?, ?, ?, -1, 'NATIVE', ?, ?, ?, ?)",
            (chain_id, n, b_hash, 1700000000 + n * 12, tx_hash, from_a, to_a, str(val), synthetic)
        )

        conn.execute(
            "INSERT INTO audit_events(ts, action, object_ref, metadata) VALUES(?, 'COLLECT_BLOCK', ?, ?)",
            (utc_str, f"block:{n}", json.dumps({"hash": b_hash}))
        )

        prev_hash = b_hash

    # Ghi nhận 1 phiên collector_runs để kiểm tra rpc_label được trích xuất từ DB
    conn.execute(
        "INSERT INTO collector_runs(run_id, rpc_label, chain_id, synthetic, mode, start_block, end_block, "
        "blocks_count, txs_count, blocks_per_sec, txs_per_sec, retries_count, gaps_count, status, started_at, ended_at, commit_hash) "
        "VALUES('run-01', 'anvil-node-db', 31337, ?, 'backfill', 0, ?, ?, ?, 10.0, 10.0, 0, 0, 'completed', ?, ?, 'commit1')",
        (synthetic, num_blocks - 1, num_blocks, num_blocks, utc_str, utc_str)
    )

    conn.commit()
    conn.close()

def test_sanitized_config_allowlist_and_secret_exclusion(tmp_path, monkeypatch):
    """Test 1: sanitized_config sử dụng ALLOWLIST nghiêm ngặt; tuyệt đối không rò rỉ RPC_URL, key, mật khẩu."""
    fake_secret_key = "0xSUPER_SECRET_PRIVATE_KEY_DO_NOT_LEAK_99999"
    fake_rpc_url = "https://sepolia.infura.io/v3/API_KEY_LEAK_PROTECTION_77777"
    fake_password = "ADMIN_TOP_SECRET_PASSWORD"

    monkeypatch.setenv("RPC_URL", fake_rpc_url)
    monkeypatch.setenv("ANCHOR_PRIVATE_KEY", fake_secret_key)
    monkeypatch.setenv("SECRET_PASSWORD", fake_password)
    monkeypatch.setenv("RPC_LABEL", "test-safe-rpc")
    monkeypatch.setenv("CONFIRMATIONS", "2")
    monkeypatch.setenv("RPC_SYNTHETIC", "false")
    monkeypatch.setenv("RATE_LIMIT_RPS", "10")

    cfg = sanitize_config({"LEAKY_INTERNAL_KEY": "SHOULD_BE_DROPPED"})

    # Kiểm tra dictionary cấu hình đã lọc
    assert "RPC_URL" not in cfg
    assert "ANCHOR_PRIVATE_KEY" not in cfg
    assert "SECRET_PASSWORD" not in cfg
    assert "LEAKY_INTERNAL_KEY" not in cfg
    assert cfg["RPC_LABEL"] == "test-safe-rpc"
    for k in cfg:
        assert k in ALLOWED_CONFIG_KEYS

    # Xuất gói chứng cứ và quét (grep) toàn bộ tệp trong gói
    db_file = str(tmp_path / "test_secrets.db")
    populate_sample_db(db_file, num_blocks=3)

    out_dir = str(tmp_path / "pkg_secrets")
    manifest = export_evidence("case-sec-01", 0, 2, out_dir=out_dir, db_path=db_file)

    # Đảm bảo không có dấu vết của secret trong bất kỳ tệp nào
    for root, _, files in os.walk(out_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                assert fake_secret_key not in content
                assert fake_rpc_url not in content
                assert fake_password not in content
                assert "API_KEY_LEAK_PROTECTION_77777" not in content

def test_case_id_validation_and_operator(monkeypatch):
    """Test 2: Xác thực biểu thức chính quy của case_id và logic trích xuất operator."""
    # Hợp lệ
    assert validate_case_id("case-001") == "case-001"
    assert validate_case_id("CASE_2026_01") == "CASE_2026_01"
    assert validate_case_id("case_abc-123") == "case_abc-123"

    # Không hợp lệ: có slash, backslash, path traversal, khoảng trắng, ký tự đặc biệt
    for invalid in ["case/01", "case\\01", "../case01", "case 01", "case@01", "", "a" * 65]:
        with pytest.raises(ValueError):
            validate_case_id(invalid)

    # Operator
    monkeypatch.delenv("OPERATOR_NAME", raising=False)
    assert get_operator(None) == "unspecified"
    assert get_operator("Alice_Investigator") == "Alice_Investigator"

    monkeypatch.setenv("OPERATOR_NAME", "Bob_Examiner")
    assert get_operator(None) == "Bob_Examiner"
    assert get_operator("Charlie_Reviewer") == "Charlie_Reviewer"

def test_synthetic_purity_rejection(tmp_path):
    """Test 3: Từ chối xuất gói nếu dải block chứa cả synthetic=0 và synthetic=1."""
    db_file = str(tmp_path / "test_mixed_synth.db")
    conn = init_db(db_file)
    # Block 0: synthetic = 0
    conn.execute(
        "INSERT INTO blocks(chain_id, number, hash, parent_hash, block_timestamp, block_time_utc, status, synthetic) "
        "VALUES(31337, 0, '0x00', '0x', 1700000000, '2023-11-14T22:13:20Z', 'canonical', 0)"
    )
    # Block 1: synthetic = 1
    conn.execute(
        "INSERT INTO blocks(chain_id, number, hash, parent_hash, block_timestamp, block_time_utc, status, synthetic) "
        "VALUES(31337, 1, '0x01', '0x00', 1700000012, '2023-11-14T22:13:32Z', 'canonical', 1)"
    )
    conn.commit()
    conn.close()

    out_dir = str(tmp_path / "pkg_mixed")
    with pytest.raises(ValueError, match="Không được trộn lẫn dữ liệu synthetic"):
        export_evidence("case-mixed", 0, 1, out_dir=out_dir, db_path=db_file)

def test_deterministic_package_digest(tmp_path, monkeypatch):
    """Test 4: package_digest là xác định (deterministic) và không phụ thuộc vào mốc thời gian exported_at."""
    db_file = str(tmp_path / "test_digest.db")
    populate_sample_db(db_file, num_blocks=4)

    out_dir_1 = str(tmp_path / "pkg_digest_1")
    out_dir_2 = str(tmp_path / "pkg_digest_2")

    # Lần xuất 1
    m1 = export_evidence("case-d-1", 0, 3, out_dir=out_dir_1, db_path=db_file)

    # Lần xuất 2 (cùng dữ liệu nguồn)
    m2 = export_evidence("case-d-2", 0, 3, out_dir=out_dir_2, db_path=db_file)

    assert m1["package_digest"] == m2["package_digest"]
    assert len(m1["package_digest"]) == 64

def test_verify_manifest_path_traversal_and_absolute_paths(tmp_path):
    """Test 5: verify-manifest từ chối các đường dẫn tuyệt đối hoặc path traversal '..'."""
    pkg_dir = str(tmp_path / "pkg_traversal")
    os.makedirs(pkg_dir, exist_ok=True)

    # 1. Manifest chứa đường dẫn tuyệt đối
    manifest_abs = {
        "manifest_version": "1.0.0",
        "case_id": "case-bad-path-1",
        "files": [{"path": "/etc/passwd", "size_bytes": 100, "sha256": "abc"}]
    }
    with open(os.path.join(pkg_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest_abs, f)

    ok, errors = verify_manifest(pkg_dir)
    assert not ok
    assert any("Từ chối đường dẫn tuyệt đối" in e for e in errors)

    # 2. Manifest chứa '..'
    manifest_dots = {
        "manifest_version": "1.0.0",
        "case_id": "case-bad-path-2",
        "files": [{"path": "../secret_file.txt", "size_bytes": 100, "sha256": "abc"}]
    }
    with open(os.path.join(pkg_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest_dots, f)

    ok, errors = verify_manifest(pkg_dir)
    assert not ok
    assert any("path traversal" in e for e in errors)

def test_verify_manifest_tampering_and_mismatches(tmp_path):
    """Test 6: Kiểm tra phát hiện mọi sai lệch toàn vẹn trong verify-manifest:
    - Thiếu file
    - Sai kích thước
    - Sửa 1 byte (sai hash)
    - File lạ thừa trên đĩa
    - Sửa chính manifest.json (lệch manifest_sha256 trong SQLite)
    """
    db_file = str(tmp_path / "test_tamper.db")
    populate_sample_db(db_file, num_blocks=4)

    pkg_dir = str(tmp_path / "pkg_tamper")
    export_evidence("case-tamper-01", 0, 3, out_dir=pkg_dir, db_path=db_file)

    # 1. Trạng thái nguyên vẹn ban đầu: OK
    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert ok
    assert len(errors) == 0

    # 2. Xóa 1 file: timeline.csv -> MISMATCH thiếu file
    timeline_file = os.path.join(pkg_dir, "timeline.csv")
    with open(timeline_file, "r", encoding="utf-8") as f:
        timeline_backup = f.read()
    os.remove(timeline_file)

    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert not ok
    assert any("Thiếu file trên đĩa" in e for e in errors)

    # Khôi phục timeline.csv
    with open(timeline_file, "w", encoding="utf-8") as f:
        f.write(timeline_backup)

    # 3. Sửa 1 byte trong asset_transfers.csv -> MISMATCH sai hash
    transfers_file = os.path.join(pkg_dir, "asset_transfers.csv")
    with open(transfers_file, "rb") as f:
        tf_data = bytearray(f.read())
    tf_data[-1] ^= 0x01  # đảo 1 bit
    with open(transfers_file, "wb") as f:
        f.write(tf_data)

    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert not ok
    assert any("Sai lệch SHA-256" in e for e in errors)

    # 4. Thêm file lạ thừa trên đĩa không có trong manifest
    extra_file = os.path.join(pkg_dir, "unexpected_payload.txt")
    with open(extra_file, "w", encoding="utf-8") as f:
        f.write("Trojan or unverified payload")

    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert not ok
    assert any("Phát hiện file thừa trên đĩa" in e for e in errors)
    os.remove(extra_file)

    # 5. Sửa chính file manifest.json -> đối chiếu DB thấy lệch manifest_sha256
    manifest_file = os.path.join(pkg_dir, "manifest.json")
    with open(manifest_file, "r", encoding="utf-8") as f:
        m_json = json.load(f)
    m_json["operator"] = "Attacker_Modified_Operator"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(m_json, f, indent=2)

    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert not ok
    assert any("manifest_sha256 không khớp với bản ghi DB" in e for e in errors)

def test_confirmations_and_require_final(tmp_path, monkeypatch):
    """Test 7: Xử lý block trong ngưỡng CONFIRMATIONS và cờ --require-final."""
    monkeypatch.setenv("CONFIRMATIONS", "3")
    db_file = str(tmp_path / "test_final.db")
    populate_sample_db(db_file, num_blocks=5)  # blocks 0..4, latest = 4, threshold = 4 - 3 + 1 = 2

    # Với require_final=True trên dải 0..4 (chứa block 2, 3, 4 unfinalized) -> từ chối
    with pytest.raises(ValueError, match="chưa finalize"):
        export_evidence("case-final-rej", 0, 4, out_dir=str(tmp_path / "p1"), db_path=db_file, require_final=True)

    # Với require_final=False -> thành công nhưng manifest cảnh báo is_finalized=False
    m = export_evidence("case-final-ok", 0, 4, out_dir=str(tmp_path / "p2"), db_path=db_file, require_final=False)
    assert m["finalization"]["is_finalized"] is False
    assert m["finalization"]["unfinalized_blocks_count"] > 0

def test_data_gaps_handling(tmp_path):
    """Test 8: Phát hiện khoảng thiếu dữ liệu (gaps) và cờ --allow-gaps."""
    db_file = str(tmp_path / "test_gaps.db")
    populate_sample_db(db_file, num_blocks=5)

    # Xóa block 2 để tạo gap [2, 2]
    conn = sqlite3.connect(db_file)
    conn.execute("DELETE FROM blocks WHERE number=2")
    conn.commit()
    conn.close()

    # Không có allow_gaps -> từ chối xuất
    with pytest.raises(ValueError, match="block bị thiếu"):
        export_evidence("case-gap-err", 0, 4, out_dir=str(tmp_path / "pgap1"), db_path=db_file, allow_gaps=False)

    # Có allow_gaps -> xuất thành công, ghi nhận gap trong manifest
    m = export_evidence("case-gap-ok", 0, 4, out_dir=str(tmp_path / "pgap2"), db_path=db_file, allow_gaps=True)
    assert m["integrity_checks"]["gaps_count"] == 1
    assert m["integrity_checks"]["gaps"] == [[2, 2]]

def test_schema_migration_full_13_tables(tmp_path):
    """Test 9: Migration trên DB cũ chỉ có các bảng sơ khai lên đủ 13 bảng theo Mục 6.2."""
    db_file = str(tmp_path / "old_version.db")
    conn = sqlite3.connect(db_file)
    # Giả lập DB cũ thiếu cột synthetic và thiếu 5 bảng mới
    conn.executescript("""
        CREATE TABLE blocks(
            chain_id INT, number INT, hash TEXT, parent_hash TEXT, block_timestamp INT,
            block_time_utc TEXT, first_observed_at TEXT, collected_at TEXT, status TEXT DEFAULT 'canonical',
            raw_json TEXT, raw_sha256 TEXT, PRIMARY KEY(chain_id, hash)
        );
        INSERT INTO blocks(chain_id, number, hash) VALUES(1, 100, '0xabc');
    """)
    conn.commit()

    # Chạy migration
    migrate_db(conn)

    # Kiểm tra cột synthetic đã được bổ sung
    cols = [r[1] for r in conn.execute("PRAGMA table_info(blocks)").fetchall()]
    assert "synthetic" in cols

    # Kiểm tra đủ 13 bảng
    expected_tables = {
        "blocks", "transactions", "receipts", "logs", "checkpoints",
        "audit_events", "asset_transfers", "collector_runs",
        "alerts", "analysis_runs", "evidence_exports", "custody_events", "reviews"
    }
    actual_tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    for tbl in expected_tables:
        assert tbl in actual_tables

    # Dữ liệu cũ còn nguyên
    row = conn.execute("SELECT number, hash, synthetic FROM blocks WHERE number=100").fetchone()
    assert row == (100, "0xabc", 0)
    conn.close()

def test_forensics_cli_end_to_end(tmp_path):
    """Test 10: Chạy thử toàn bộ các lệnh CLI forensics bằng subprocess."""
    db_file = str(tmp_path / "cli_test.db")
    populate_sample_db(db_file, num_blocks=4)

    pkg_dir = str(tmp_path / "cli_pkg")

    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"

    # 1. export-evidence
    res = subprocess.run(
        [sys.executable, "-m", "forensics.cli", "export-evidence",
         "--case-id", "case-cli-01", "--start-block", "0", "--end-block", "3",
         "--out-dir", pkg_dir, "--db", db_file, "--operator", "CLI_Tester"],
        capture_output=True, encoding="utf-8", errors="replace", env=sub_env, check=False
    )
    assert res.returncode == 0
    assert "Đã xuất thành công gói chứng cứ 'case-cli-01'" in res.stdout

    # 2. verify-manifest
    res = subprocess.run(
        [sys.executable, "-m", "forensics.cli", "verify-manifest", pkg_dir, "--db", db_file],
        capture_output=True, encoding="utf-8", errors="replace", env=sub_env, check=False
    )
    assert res.returncode == 0
    assert "toàn vẹn và khớp hoàn toàn" in res.stdout

    # 3. verify-local
    res = subprocess.run(
        [sys.executable, "-m", "forensics.cli", "verify-local", "--db", db_file],
        capture_output=True, encoding="utf-8", errors="replace", env=sub_env, check=False
    )
    assert res.returncode == 0

    # 4. verify-derived
    res = subprocess.run(
        [sys.executable, "-m", "forensics.cli", "verify-derived", "--db", db_file],
        capture_output=True, encoding="utf-8", errors="replace", env=sub_env, check=False
    )
    assert res.returncode == 0

def test_manifest_source_consistency_and_contradiction(tmp_path, monkeypatch):
    """Test 11: rpc_label và cờ synthetic được trích xuất từ dữ liệu trong DB;
    mục software chứa working_tree_dirty; verify-manifest bắt mâu thuẫn giữa manifest và sanitized_config.
    """
    # Đặt biến môi trường khác hẳn với DB
    monkeypatch.setenv("RPC_LABEL", "env-rpc-contradict")
    monkeypatch.setenv("RPC_SYNTHETIC", "false")

    db_file = str(tmp_path / "test_source.db")
    # DB lưu synthetic=1 và collector_runs có rpc_label='anvil-node-db'
    populate_sample_db(db_file, num_blocks=3, synthetic=1)

    pkg_dir = str(tmp_path / "pkg_source")
    manifest = export_evidence("case-src-01", 0, 2, out_dir=pkg_dir, db_path=db_file)

    # 1. Xác nhận lấy từ DB, không lấy từ biến môi trường
    assert manifest["rpc_label"] == "anvil-node-db"
    assert manifest["synthetic"] is True
    assert manifest["sanitized_config"]["RPC_LABEL"] == "anvil-node-db"
    assert manifest["sanitized_config"]["RPC_SYNTHETIC"] is True

    # 2. Xác nhận software có trường working_tree_dirty kiểu bool
    assert "working_tree_dirty" in manifest["software"]
    assert isinstance(manifest["software"]["working_tree_dirty"], bool)

    # 3. Gói nguyên vẹn -> verify-manifest OK
    ok, errors = verify_manifest(pkg_dir, db_path=db_file)
    assert ok
    assert len(errors) == 0

    # 4. Cố tình tạo mâu thuẫn: sửa sanitized_config.RPC_SYNTHETIC thành False trong khi synthetic là True
    manifest_path = os.path.join(pkg_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        m_data = json.load(f)
    m_data["sanitized_config"]["RPC_SYNTHETIC"] = False
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(m_data, f, indent=2)

    ok, errors = verify_manifest(pkg_dir)
    assert not ok
    assert any("Mâu thuẫn cờ synthetic" in e for e in errors)

    # 5. Cố tình tạo mâu thuẫn rpc_label
    m_data["sanitized_config"]["RPC_SYNTHETIC"] = True
    m_data["sanitized_config"]["RPC_LABEL"] = "tampered-label"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(m_data, f, indent=2)

    ok, errors = verify_manifest(pkg_dir)
    assert not ok
    assert any("Mâu thuẫn rpc_label" in e for e in errors)
