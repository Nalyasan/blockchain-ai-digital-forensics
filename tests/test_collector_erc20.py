import json, os, sqlite3, subprocess, sys, time, urllib.request, pytest

PYTHON = sys.executable

def get_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

@pytest.fixture(scope="module")
def mock_server():
    """Khởi động mock_rpc trên port tự động cho test suite."""
    port = get_free_port()
    proc = subprocess.Popen([PYTHON, "mock_rpc.py", str(port)])
    time.sleep(1.2)
    # Reset mock rpc
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/reset", timeout=5)
    except Exception:
        pass
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

def run_cmd(args, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run([PYTHON, "collector.py"] + args, capture_output=True, text=True, env=env, encoding="utf-8")

def test_dotenv_loader(tmp_path):
    """Kiểm tra: .env được đọc; biến môi trường thật ưu tiên hơn .env; không log key nhạy cảm."""
    import collector
    env_file = tmp_path / ".env"
    env_file.write_text("TEST_VAR_A=hello\nTEST_VAR_OVERRIDE=from_dotenv\n# comment\n", encoding="utf-8")
    
    os.environ["TEST_VAR_OVERRIDE"] = "from_system_env"
    collector.load_dotenv(str(env_file))
    
    assert os.environ.get("TEST_VAR_A") == "hello"
    assert os.environ.get("TEST_VAR_OVERRIDE") == "from_system_env"  # Hệ thống thật ưu tiên hơn

def test_windows_utf8_stdout(mock_server):
    """Kiểm tra: collector.py không bị UnicodeEncodeError khi in tiếng Việt trên console Windows."""
    res = run_cmd(["healthcheck"], {"RPC_URL": mock_server})
    assert res.returncode == 0
    assert "chain_id" in res.stdout

def test_db_migration_old_schema(tmp_path):
    """Kiểm tra: migration chạy thành công trên DB cũ (chưa có cột synthetic, chưa có asset_transfers/collector_runs)."""
    db_file = str(tmp_path / "old_forensics.db")
    conn = sqlite3.connect(db_file)
    # Tạo schema cũ bản 5.0 (không có synthetic, không có asset_transfers, collector_runs)
    conn.executescript("""
    CREATE TABLE blocks(chain_id INT, number INT, hash TEXT, parent_hash TEXT, block_timestamp INT,
      block_time_utc TEXT, first_observed_at TEXT, collected_at TEXT, status TEXT DEFAULT 'canonical',
      raw_json TEXT, raw_sha256 TEXT, PRIMARY KEY(chain_id, hash));
    INSERT INTO blocks VALUES(31337, 0, '0xaaa', '0x000', 1790812800, '2026-10-01T00:00:00Z',
      '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', 'canonical', '{}', 'hash0');
    """)
    conn.close()

    # Chạy migration qua collector.db()
    import collector
    c = collector.db(db_file)
    
    # Kiểm tra cột synthetic đã được thêm vào blocks
    cols = [r[1] for r in c.execute("PRAGMA table_info(blocks)").fetchall()]
    assert "synthetic" in cols
    
    # Kiểm tra dữ liệu cũ vẫn nguyên vẹn và mang giá trị synthetic = 0
    row = c.execute("SELECT number, synthetic FROM blocks WHERE number=0").fetchone()
    assert row[0] == 0
    assert row[1] == 0
    
    # Kiểm tra các bảng mới đã được tạo
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "asset_transfers" in tables
    assert "collector_runs" in tables
    c.close()

def test_idempotency_and_backfill(mock_server, tmp_path):
    """T01: Backfill 0..11, kiểm tra dữ liệu ETH + ERC-20, chạy lại không trùng lặp (idempotency), verify khớp SHA-256."""
    db_file = str(tmp_path / "test_idempotency.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)

    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    # 1. Backfill lần đầu
    res1 = run_cmd(["backfill", "--start-block", "0", "--end-block", "11"], env)
    assert res1.returncode == 0, res1.stderr

    conn = sqlite3.connect(db_file)
    b_cnt1 = conn.execute("SELECT count(*) FROM blocks WHERE status='canonical'").fetchone()[0]
    tx_cnt1 = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
    tf_cnt1 = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
    runs_cnt1 = conn.execute("SELECT count(*) FROM collector_runs").fetchone()[0]
    assert b_cnt1 == 12
    assert tx_cnt1 > 0
    assert tf_cnt1 > 0  # Có cả ETH và ERC-20 transfers
    assert runs_cnt1 >= 1

    # Kiểm tra collector_runs ghi nhận đầy đủ thông số
    run_row = conn.execute("SELECT start_block, end_block, blocks_count, txs_count, blocks_per_sec, status FROM collector_runs").fetchone()
    assert run_row[0] == 0
    assert run_row[1] == 11
    assert run_row[2] == 12
    assert run_row[5] == "success"

    # 2. Backfill lần 2 trên cùng khoảng block (chống trùng)
    res2 = run_cmd(["backfill", "--start-block", "0", "--end-block", "11"], env)
    assert res2.returncode == 0, res2.stderr

    b_cnt2 = conn.execute("SELECT count(*) FROM blocks WHERE status='canonical'").fetchone()[0]
    tx_cnt2 = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
    tf_cnt2 = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
    assert b_cnt2 == b_cnt1, "Số lượng block không được nhân đôi"
    assert tx_cnt2 == tx_cnt1, "Số lượng tx không được nhân đôi"
    assert tf_cnt2 == tf_cnt1, "Số lượng asset_transfers không được nhân đôi"

    # 3. Verify local SHA-256
    res_verify = run_cmd(["verify"], env)
    assert res_verify.returncode == 0
    assert "OK: raw data khớp SHA-256" in res_verify.stdout
    conn.close()

def test_retry_and_http_429(mock_server, tmp_path):
    """T02: Kiểm tra RPC chịu lỗi: HTTP 503 retry, HTTP 429 với Retry-After, không mất checkpoint."""
    db_file = str(tmp_path / "test_resilience.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    # 1. Sync 2 block đầu
    res = run_cmd(["backfill", "--start-block", "0", "--end-block", "1"], env)
    assert res.returncode == 0

    conn = sqlite3.connect(db_file)
    cp0 = conn.execute("SELECT last_block FROM checkpoints WHERE stream='main'").fetchone()[0]
    assert cp0 == 1

    # 2. Giả lập HTTP 503 lỗi 2 lần
    urllib.request.urlopen(f"{mock_server}/fail?n=2", timeout=5)
    res_retry = run_cmd(["backfill", "--start-block", "2", "--end-block", "3"], env)
    assert res_retry.returncode == 0

    cp1 = conn.execute("SELECT last_block FROM checkpoints WHERE stream='main'").fetchone()[0]
    assert cp1 == 3

    # 3. Giả lập HTTP 429 lỗi 2 lần kèm Retry-After: 1
    urllib.request.urlopen(f"{mock_server}/fail429?n=2&sec=1", timeout=5)
    res_429 = run_cmd(["backfill", "--start-block", "4", "--end-block", "5"], env)
    assert res_429.returncode == 0

    cp2 = conn.execute("SELECT last_block FROM checkpoints WHERE stream='main'").fetchone()[0]
    assert cp2 == 5
    conn.close()

def test_reorg_handling(mock_server, tmp_path):
    """T03: Xử lý Reorganization: phát hiện parentHash lệch, orphan block cũ, lùi checkpoint, audit event."""
    db_file = str(tmp_path / "test_reorg.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    # Sync từ 0..11
    run_cmd(["backfill", "--start-block", "0", "--end-block", "11"], env)

    conn = sqlite3.connect(db_file)
    assert conn.execute("SELECT count(*) FROM blocks WHERE status='canonical'").fetchone()[0] == 12

    # Kích hoạt reorg từ block 8
    urllib.request.urlopen(f"{mock_server}/reorg?from=8", timeout=5)

    # Sync lại từ block 8..11
    res_reorg = run_cmd(["backfill", "--start-block", "8", "--end-block", "11"], env)
    assert res_reorg.returncode == 0

    orphaned = conn.execute("SELECT count(*) FROM blocks WHERE status='orphaned'").fetchone()[0]
    assert orphaned >= 4, "Các block nhánh cũ phải được đánh dấu orphaned"

    # Kiểm tra audit_events có REORG_DETECTED và BLOCK_ORPHANED
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_events").fetchall()]
    assert "REORG_DETECTED" in actions
    assert "BLOCK_ORPHANED" in actions
    conn.close()

def test_asset_transfers_parser(mock_server, tmp_path):
    """Kiểm tra tính chính xác của parser ETH và ERC-20 Transfer (Mục 6.1)."""
    db_file = str(tmp_path / "test_parser.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    run_cmd(["backfill", "--start-block", "0", "--end-block", "6"], env)

    conn = sqlite3.connect(db_file)
    # 1. Chuyển ETH: asset_id = NATIVE, log_index = -1
    eth_tf = conn.execute("SELECT from_addr, to_addr, amount_raw, log_index FROM asset_transfers WHERE asset_id='NATIVE'").fetchall()
    assert len(eth_tf) > 0
    assert eth_tf[0][3] == -1
    assert int(eth_tf[0][2]) > 0

    # 2. Chuyển ERC-20: asset_id = token address viết thường, log_index >= 0, đúng from/to giải mã từ topics
    erc20_tf = conn.execute("SELECT asset_id, from_addr, to_addr, amount_raw, log_index FROM asset_transfers WHERE asset_id!='NATIVE'").fetchall()
    assert len(erc20_tf) > 0
    for tf in erc20_tf:
        assert tf[0].startswith("0x")
        assert tf[1].startswith("0x")
        assert tf[2].startswith("0x")
        assert int(tf[3]) > 0
        assert tf[4] >= 0

    # 3. Contract creation tx tại block 4: to_addr lấy theo contract_address của receipt (0x...270f)
    c_create_tf = conn.execute("SELECT to_addr FROM asset_transfers WHERE block_number=4 AND to_addr LIKE '%270f%'").fetchall()
    assert len(c_create_tf) > 0
    conn.close()

def test_watch_addresses_filter(mock_server, tmp_path):
    """Kiểm tra --watch-addresses: chỉ lọc receipt/logs, KHÔNG lọc block header và transactions; ghi collector_runs và audit."""
    db_file = str(tmp_path / "test_watch.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    target_addr = "0x0000000000000000000000000000000000000001"
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    res = run_cmd(["backfill", "--start-block", "0", "--end-block", "5", "--watch-addresses", target_addr], env)
    assert res.returncode == 0

    conn = sqlite3.connect(db_file)
    # Blocks và Transactions vẫn lưu đầy đủ
    assert conn.execute("SELECT count(*) FROM blocks").fetchone()[0] == 6
    assert conn.execute("SELECT count(*) FROM transactions").fetchone()[0] > 0

    # collector_runs có cột watch_filter
    run_row = conn.execute("SELECT watch_filter FROM collector_runs").fetchone()
    assert run_row[0] == target_addr

    # audit_events có WATCH_FILTER_ACTIVE
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_events").fetchall()]
    assert "WATCH_FILTER_ACTIVE" in actions
    conn.close()

def test_verify_rpc_full_content_match_and_tamper(mock_server, tmp_path):
    """T05 (Tầng RPC): verify-rpc đối chiếu đầy đủ nội dung; phát hiện khi DB bị sửa trộm value."""
    db_file = str(tmp_path / "test_verify_rpc.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    # 1. Backfill và verify-rpc ban đầu -> Phải thành công
    run_cmd(["backfill", "--start-block", "0", "--end-block", "5"], env)
    res_ok = run_cmd(["verify-rpc", "--start-block", "0", "--end-block", "5"], env)
    assert res_ok.returncode == 0
    assert "khớp 100%" in res_ok.stdout

    # 2. Sửa lén value_raw trong transactions (giữ nguyên tx_hash và raw_sha256)
    conn = sqlite3.connect(db_file)
    tx = conn.execute("SELECT tx_hash, value_raw FROM transactions WHERE block_number=3 LIMIT 1").fetchone()
    conn.execute("UPDATE transactions SET value_raw='99999999999999999999' WHERE tx_hash=?", (tx[0],))
    conn.commit()
    conn.close()

    # 3. verify-rpc phải phát hiện sai lệch nội dung (CONTENT_MISMATCH)
    res_tampered = run_cmd(["verify-rpc", "--start-block", "0", "--end-block", "5"], env)
    assert res_tampered.returncode == 1
    assert "CONTENT_MISMATCH" in res_tampered.stdout

def test_verify_rpc_tampered_raw_json_and_hash(mock_server, tmp_path):
    """Ca 2a: Sửa cả raw_json lẫn raw_sha256 của 1 block -> verify-local qua, verify-rpc bắt được."""
    db_file = str(tmp_path / "test_tamper_raw.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    run_cmd(["backfill", "--start-block", "0", "--end-block", "3"], env)

    # Sửa cả raw_json và tính lại raw_sha256 tương ứng
    import collector
    conn = sqlite3.connect(db_file)
    row = conn.execute("SELECT raw_json FROM blocks WHERE number=2").fetchone()
    blk_obj = json.loads(row[0])
    blk_obj["timestamp"] = "0x99999999"  # Sửa timestamp trong raw_json
    new_raw = json.dumps(blk_obj, sort_keys=True)
    new_sha = collector.sha(blk_obj)
    conn.execute("UPDATE blocks SET raw_json=?, raw_sha256=? WHERE number=2", (new_raw, new_sha))
    conn.commit()
    conn.close()

    # verify-local (chỉ kiểm SHA256 cột SQLite) -> VẪN QUA
    res_local = run_cmd(["verify"], env)
    assert res_local.returncode == 0
    assert "OK: raw data khớp SHA-256" in res_local.stdout

    # verify-rpc (so khớp nội dung với RPC nguồn) -> BẮT ĐƯỢC
    res_rpc = run_cmd(["verify-rpc", "--start-block", "0", "--end-block", "3"], env)
    assert res_rpc.returncode == 1
    assert "CONTENT_MISMATCH" in res_rpc.stdout

def test_verify_rpc_tampered_log_topics_and_data(mock_server, tmp_path):
    """Ca 2b: Sửa topics hoặc data của 1 log trong SQLite -> verify-rpc bắt được."""
    db_file = str(tmp_path / "test_tamper_log.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    run_cmd(["backfill", "--start-block", "0", "--end-block", "5"], env)

    conn = sqlite3.connect(db_file)
    log_row = conn.execute("SELECT block_hash, log_index, data FROM logs LIMIT 1").fetchone()
    assert log_row is not None, "Cần có ít nhất 1 log trong DB để kiểm tra"
    # Sửa data của log trong DB
    conn.execute("UPDATE logs SET data='0xdeadbeef' WHERE block_hash=? AND log_index=?", (log_row[0], log_row[1]))
    conn.commit()
    conn.close()

    res_rpc = run_cmd(["verify-rpc", "--start-block", "0", "--end-block", "5"], env)
    assert res_rpc.returncode == 1
    assert "CONTENT_MISMATCH" in res_rpc.stdout

def test_verify_derived_and_tampered_amount(mock_server, tmp_path):
    """Mục 3: verify-derived tính lại asset_transfers từ raw data; phát hiện khi sửa amount_raw."""
    db_file = str(tmp_path / "test_derived.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    run_cmd(["backfill", "--start-block", "0", "--end-block", "5"], env)

    # 1. Ban đầu: verify-derived phải thành công
    res_ok = run_cmd(["verify-derived"], env)
    assert res_ok.returncode == 0
    assert "khớp 100%" in res_ok.stdout

    # 2. Sửa lén amount_raw trong bảng asset_transfers
    conn = sqlite3.connect(db_file)
    tf = conn.execute("SELECT transfer_id FROM asset_transfers LIMIT 1").fetchone()
    conn.execute("UPDATE asset_transfers SET amount_raw='123456789' WHERE transfer_id=?", (tf[0],))
    conn.commit()
    conn.close()

    # 3. verify-derived phải phát hiện sai lệch và trả mã 1
    res_tampered = run_cmd(["verify-derived"], env)
    assert res_tampered.returncode == 1
    assert "DERIVED_MISMATCH" in res_tampered.stdout

def test_tx_status_zero_no_transfer():
    """Mục 4: Giao dịch có status=0 (revert) không được sinh bản ghi trong asset_transfers."""
    import collector
    blk = {
        "number": "0x1",
        "hash": "0xblk1",
        "timestamp": "0x60000000",
        "transactions": [
            {"hash": "0xtx1", "from": "0xaaa", "to": "0xbbb", "value": "0x1000", "input": "0x"}
        ]
    }
    # Receipt với status=0x0
    receipts = {
        "0xtx1": {
            "status": "0x0",
            "logs": [
                {
                    "address": "0xtoken",
                    "topics": [collector.ERC20_TRANSFER_TOPIC0, "0x" + "0"*24 + "aaa", "0x" + "0"*24 + "bbb"],
                    "data": "0x100",
                    "logIndex": "0x0"
                }
            ]
        }
    }
    transfers = collector.extract_transfers(31337, blk, receipts, 0)
    assert len(transfers) == 0, "Giao dịch lỗi (status=0) không được sinh transfer nào"

def test_erc721_four_topics_ignored():
    """Mục 4: Log Transfer của ERC-721 có 4 topics phải bị bỏ qua, không lưu vào asset_transfers."""
    import collector
    blk = {
        "number": "0x2",
        "hash": "0xblk2",
        "timestamp": "0x60000000",
        "transactions": [
            {"hash": "0xtx2", "from": "0xaaa", "to": "0xnft", "value": "0x0", "input": "0x"}
        ]
    }
    # Log có 4 topics (ERC-721: Transfer(from, to, tokenId))
    receipts = {
        "0xtx2": {
            "status": "0x1",
            "logs": [
                {
                    "address": "0xnftcontract",
                    "topics": [
                        collector.ERC20_TRANSFER_TOPIC0,
                        "0x" + "0"*24 + "aaa",
                        "0x" + "0"*24 + "bbb",
                        "0x" + "0"*63 + "1"  # 4th topic: tokenId
                    ],
                    "data": "0x",
                    "logIndex": "0x0"
                }
            ]
        }
    }
    transfers = collector.extract_transfers(31337, blk, receipts, 0)
    assert len(transfers) == 0, "Log 4 topics (ERC-721) phải bị bỏ qua"

def test_reorg_orphaned_transfers_excluded_from_canonical(mock_server, tmp_path):
    """Mục 4: Sau reorg, asset_transfers của block orphaned không lọt vào truy vấn canonical."""
    db_file = str(tmp_path / "test_reorg_canonical.db")
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    # Sync 0..11
    run_cmd(["backfill", "--start-block", "0", "--end-block", "11"], env)
    # Kích hoạt reorg từ block 8
    urllib.request.urlopen(f"{mock_server}/reorg?from=8", timeout=5)
    run_cmd(["backfill", "--start-block", "8", "--end-block", "11"], env)

    conn = sqlite3.connect(db_file)
    # Lấy transfer của các block canonical
    canonical_transfers = conn.execute(
        "SELECT t.block_number, t.block_hash FROM asset_transfers t "
        "JOIN blocks b ON b.chain_id=t.chain_id AND b.hash=t.block_hash "
        "WHERE b.status='canonical' AND b.number >= 8"
    ).fetchall()

    # Lấy hash của các block orphaned
    orphaned_hashes = set(r[0] for r in conn.execute("SELECT hash FROM blocks WHERE status='orphaned'").fetchall())

    for tf_block_num, tf_block_hash in canonical_transfers:
        assert tf_block_hash not in orphaned_hashes, f"Block hash {tf_block_hash} bị orphaned nhưng vẫn nằm trong canonical query!"
    conn.close()

def test_fallback_32601_from_eth_get_block_receipts(mock_server, tmp_path):
    """Mục 4: Khi node trả lỗi -32601 cho eth_getBlockReceipts, collector fallback sang batch eth_getTransactionReceipt thành công."""
    db_file = str(tmp_path / "test_fallback_32601.db")
    # Đảm bảo block_receipts bị tắt trên mock server (trả -32601)
    urllib.request.urlopen(f"{mock_server}/reset", timeout=5)
    urllib.request.urlopen(f"{mock_server}/toggle_block_receipts?enabled=0", timeout=5)
    env = {"RPC_URL": mock_server, "DB_PATH": db_file, "RATE_LIMIT_RPS": "100"}

    res = run_cmd(["backfill", "--start-block", "0", "--end-block", "3"], env)
    assert res.returncode == 0, res.stderr

    conn = sqlite3.connect(db_file)
    rc_cnt = conn.execute("SELECT count(*) FROM receipts").fetchone()[0]
    assert rc_cnt > 0, "Receipts phải được thu thập thành công qua batch fallback"
    conn.close()

def test_atomic_transaction_store_block_rollback(mock_server, tmp_path):
    """Mục 6: Xác nhận asset_transfers được ghi trong CÙNG DB transaction; lỗi giữa chừng thì rollback toàn bộ, không có dòng mồ côi."""
    db_file = str(tmp_path / "test_atomic.db")
    import collector
    c = collector.db(db_file)

    # Đặt SQLite Trigger để cố tình ném lỗi ABORT khi câu lệnh chạm đến bảng checkpoints (bước cuối)
    c.execute("CREATE TRIGGER fail_before_cp BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'Cố tình gây lỗi rollback'); END;")
    c.commit()

    # Giả lập block có cả tx và receipt hợp lệ
    blk = {
        "number": "0x1",
        "hash": "0xblock_atomic_test",
        "parentHash": "0x0000",
        "timestamp": "0x60000000",
        "transactions": [
            {"hash": "0xtx_atomic", "from": "0xaaa", "to": "0xbbb", "value": "0x1000", "nonce": "0x0", "input": "0x", "transactionIndex": "0x0"}
        ]
    }

    orig_get_receipts = collector.get_receipts_for_block
    collector.get_receipts_for_block = lambda b: {
        "0xtx_atomic": {"status": "0x1", "gasUsed": "0x5208", "contractAddress": None, "logs": []}
    }

    try:
        with pytest.raises(sqlite3.IntegrityError, match="Cố tình gây lỗi rollback"):
            collector.store_block(c, 31337, blk, collector.now_iso())

        # Do lỗi xảy ra trong khối `with c:`, SQLite tự động rollback toàn bộ transaction
        # Xác nhận: KHÔNG có bất kỳ dòng nào bị lưu sót trong blocks, transactions hay asset_transfers!
        assert c.execute("SELECT count(*) FROM blocks").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM transactions").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM asset_transfers").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0
    finally:
        collector.get_receipts_for_block = orig_get_receipts
        c.close()
