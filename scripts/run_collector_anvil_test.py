#!/usr/bin/env python3
"""Kịch bản thực thi Bước f: Kiểm thử thực tế trên Anvil Node (Foundry).
- Gửi 1 giao dịch ETH thật
- Deploy contract MockERC20 và gửi 1 chuyển token ERC-20 Transfer thật
- Dùng collector.py thu thập (backfill)
- Xác minh bảng asset_transfers và chạy lệnh verify-rpc
- Lưu toàn bộ log vào results/p1/step_f_anvil_verification.log
"""
import os, sys, time, subprocess, sqlite3, json, re

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ANVIL_PORT = 8547
ANVIL_URL = f"http://127.0.0.1:{ANVIL_PORT}"
DB_PATH = "results/p1/anvil_forensics.db"
LOG_FILE = "results/p1/step_f_anvil_verification.log"
FOUNDRY_DIR = os.path.abspath("tools/foundry")
ANVIL_EXE = os.path.join(FOUNDRY_DIR, "anvil.exe")
CAST_EXE = os.path.join(FOUNDRY_DIR, "cast.exe")
FORGE_EXE = os.path.join(FOUNDRY_DIR, "forge.exe")

# Tài khoản mặc định 0, 1, 2 trên Anvil
ACCOUNT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCOUNT_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ACCOUNT_2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

log_lines = []
def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    log_lines.append(line)

def run_proc(cmd, desc="", env=None):
    log(f"CHẠY: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
    if res.stdout.strip():
        log(f"STDOUT: {res.stdout.strip()}")
    if res.stderr.strip():
        log(f"STDERR: {res.stderr.strip()}")
    if res.returncode != 0:
        raise RuntimeError(f"Lỗi khi thực hiện {desc}: exit code {res.returncode}")
    return res.stdout.strip()

def main():
    if os.path.exists(DB_PATH):
        try: os.remove(DB_PATH)
        except Exception: pass
    os.makedirs("results/p1", exist_ok=True)

    log("=== BẮT ĐẦU BƯỚC F: KIỂM THỬ THỰC TẾ TRÊN ANVIL ===")
    
    # 1. Khởi động Anvil
    log(f"1. Khởi động Anvil node trên cổng {ANVIL_PORT}...")
    anvil_proc = subprocess.Popen([ANVIL_EXE, "--port", str(ANVIL_PORT), "--silent"])
    time.sleep(2)

    try:
        # Kiểm tra Anvil sẵn sàng
        chain_id_hex = run_proc([CAST_EXE, "chain-id", "--rpc-url", ANVIL_URL], "check chain-id")
        log(f"Anvil online! Chain ID: {chain_id_hex}")

        # 2. Gửi 1 giao dịch ETH thật: 2.5 ETH từ Account 0 sang Account 1
        log("2. Gửi 1 giao dịch ETH thật (2.5 ETH từ Account 0 -> Account 1)...")
        tx_eth_out = run_proc([
            CAST_EXE, "send", "--rpc-url", ANVIL_URL, "--private-key", KEY_0,
            ACCOUNT_1, "--value", "2.5ether"
        ], "Giao dịch ETH")
        eth_tx_hash = re.search(r"transactionHash\s+(0x[a-fA-F0-9]{64})", tx_eth_out)
        eth_tx_hash = eth_tx_hash.group(1) if eth_tx_hash else "tx_eth"
        log(f"ETH Tx Hash thành công: {eth_tx_hash}")

        # 3. Deploy MockERC20 contract bằng forge create
        log("3. Deploy contract MockERC20 lên Anvil...")
        deploy_out = run_proc([
            FORGE_EXE, "create", "--root", "contracts", "--rpc-url", ANVIL_URL,
            "--private-key", KEY_0, "--broadcast", "src/MockToken.sol:MockERC20",
            "--constructor-args", "1000000000000000000000000"
        ], "Deploy MockERC20")
        
        m_addr = re.search(r"Deployed to:\s+(0x[a-fA-F0-9]{40})", deploy_out)
        if not m_addr:
            raise RuntimeError("Không tìm thấy địa chỉ contract sau khi deploy")
        token_address = m_addr.group(1)
        log(f"MockERC20 Token deployed tại địa chỉ: {token_address}")

        # 4. Gửi 1 giao dịch ERC-20 Transfer thật: chuyển 500 FTT từ Account 0 sang Account 2
        log("4. Gửi 1 giao dịch ERC-20 Transfer thật (500 FTT từ Account 0 -> Account 2)...")
        erc20_amount_wei = "500000000000000000000"  # 500 * 10^18
        tx_erc20_out = run_proc([
            CAST_EXE, "send", "--rpc-url", ANVIL_URL, "--private-key", KEY_0,
            token_address, "transfer(address,uint256)", ACCOUNT_2, erc20_amount_wei
        ], "Chuyển ERC-20")
        erc20_tx_hash = re.search(r"transactionHash\s+(0x[a-fA-F0-9]{64})", tx_erc20_out)
        erc20_tx_hash = erc20_tx_hash.group(1) if erc20_tx_hash else "tx_erc20"
        log(f"ERC-20 Tx Hash thành công: {erc20_tx_hash}")

        # 5. Lấy blockNumber hiện tại trên Anvil
        latest_block_hex = run_proc([CAST_EXE, "block-number", "--rpc-url", ANVIL_URL], "block-number")
        latest_block = int(latest_block_hex)
        log(f"Block hiện tại trên Anvil: {latest_block}")

        # 6. Chạy collector.py backfill
        log("5. Chạy collector.py backfill để thu thập dữ liệu từ Anvil...")
        env = os.environ.copy()
        env["RPC_URL"] = ANVIL_URL
        env["DB_PATH"] = DB_PATH
        env["RPC_SYNTHETIC"] = "true"
        env["RPC_LABEL"] = "anvil-local-p1"
        
        collector_out = run_proc([
            sys.executable, "collector.py", "backfill", "--start-block", "0", "--end-block", str(latest_block)
        ], "collector backfill", env=env)

        # 7. Kiểm tra dữ liệu SQLite & bảng asset_transfers
        log("6. Đối soát dữ liệu trong SQLite...")
        conn = sqlite3.connect(DB_PATH)
        b_cnt = conn.execute("SELECT count(*) FROM blocks").fetchone()[0]
        tx_cnt = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
        tf_cnt = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
        run_row = conn.execute("SELECT run_id, mode, blocks_count, txs_count, blocks_per_sec, status FROM collector_runs").fetchone()

        log(f"Kết quả SQLite: blocks={b_cnt}, transactions={tx_cnt}, asset_transfers={tf_cnt}")
        log(f"Collector run record: {run_row}")

        log("--- Chi tiết các chuyển giao tài sản (asset_transfers) ---")
        transfers = conn.execute("SELECT block_number, tx_hash, asset_id, from_addr, to_addr, amount_raw, synthetic FROM asset_transfers ORDER BY block_number, log_index").fetchall()
        for t in transfers:
            log(f"  Block {t[0]} | Tx: {t[1][:14]}... | Asset: {t[2][:14]}... | From: {t[3][:10]}... | To: {t[4][:10]}... | Amount: {t[5]} | Synthetic: {t[6]}")

        # Xác nhận chuyển ETH có thật
        eth_found = any(t[2] == "NATIVE" and t[5] == "2500000000000000000" and t[4].lower() == ACCOUNT_1.lower() for t in transfers)
        # Xác nhận chuyển ERC-20 có thật
        erc20_found = any(t[2].lower() == token_address.lower() and t[5] == erc20_amount_wei and t[4].lower() == ACCOUNT_2.lower() for t in transfers)
        
        assert eth_found, "Không tìm thấy bản ghi chuyển ETH 2.5 ether trong asset_transfers!"
        assert erc20_found, "Không tìm thấy bản ghi chuyển ERC-20 500 FTT trong asset_transfers!"
        log("Xác nhận: Bản ghi chuyển ETH gốc và ERC-20 Transfer tồn tại và khớp chính xác trong asset_transfers.")
        conn.close()

        # 8. Chạy verify-derived
        log("7. Chạy lệnh verify-derived kiểm tra tính toán lại từ raw data...")
        verify_derived_out = run_proc([
            sys.executable, "collector.py", "verify-derived"
        ], "collector verify-derived", env=env)
        assert "khớp 100%" in verify_derived_out, f"verify-derived thất bại: {verify_derived_out}"
        log(f"Kết quả verify-derived: {verify_derived_out}")

        # 9. Chạy verify-rpc
        log("8. Chạy lệnh verify-rpc so khớp nội dung đầy đủ giữa SQLite và Anvil node...")
        verify_out = run_proc([
            sys.executable, "collector.py", "verify-rpc", "--start-block", "0", "--end-block", str(latest_block)
        ], "collector verify-rpc", env=env)
        assert "khớp 100%" in verify_out, f"verify-rpc thất bại: {verify_out}"
        log(f"Kết quả verify-rpc: {verify_out}")

        log("=== Hoàn tất Bước f: Đạt toàn bộ yêu cầu kiểm thử ===")

    finally:
        anvil_proc.terminate()
        try: anvil_proc.wait(timeout=3)
        except Exception: anvil_proc.kill()
        log("Anvil node đã dừng an toàn.")

        # Ghi log ra file kết quả xác minh Anvil
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(log_lines) + "\n")
        print(f"Toàn bộ log đã được lưu vào: {LOG_FILE}")

if __name__ == "__main__":
    main()
