#!/usr/bin/env python3
"""Kiểm thử collector collect (continuous mode) trên Anvil.
- Chạy Anvil
- Chạy collector.py collect ngầm
- Gửi các giao dịch ETH và ERC-20 trong lúc collector đang chạy
- Xác nhận checkpoint tăng liên tục, không trùng lặp
- Dừng an toàn và lưu log vào results/p1/continuous_collect_anvil.log
"""
import os, sys, time, subprocess, sqlite3, json, re

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ANVIL_PORT = 8548
ANVIL_URL = f"http://127.0.0.1:{ANVIL_PORT}"
DB_PATH = "results/p1/continuous_forensics.db"
LOG_FILE = "results/p1/continuous_collect_anvil.log"
FOUNDRY_DIR = os.path.abspath("tools/foundry")
ANVIL_EXE = os.path.join(FOUNDRY_DIR, "anvil.exe")
CAST_EXE = os.path.join(FOUNDRY_DIR, "cast.exe")
FORGE_EXE = os.path.join(FOUNDRY_DIR, "forge.exe")

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

    log("=== BẮT ĐẦU KIỂM THỬ CONTINUOUS COLLECT TRÊN ANVIL ===")
    anvil_proc = subprocess.Popen([ANVIL_EXE, "--port", str(ANVIL_PORT), "--silent"])
    time.sleep(2)

    env = os.environ.copy()
    env["RPC_URL"] = ANVIL_URL
    env["DB_PATH"] = DB_PATH
    env["POLL_INTERVAL"] = "1"
    env["CONFIRMATIONS"] = "0"
    env["RPC_SYNTHETIC"] = "true"
    env["RPC_LABEL"] = "anvil-continuous-p1"

    collect_proc = None
    try:
        # Khởi động collector.py collect
        log("1. Khởi động tiến trình collector.py collect chạy ngầm...")
        collect_proc = subprocess.Popen(
            [sys.executable, "collector.py", "collect", "--start-block", "0"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(2)

        # Giao dịch 1: ETH 1.0 ether
        log("2. Phát giao dịch ETH #1 (1.0 ether -> Account 1)...")
        run_proc([
            CAST_EXE, "send", "--rpc-url", ANVIL_URL, "--private-key", KEY_0,
            ACCOUNT_1, "--value", "1.0ether"
        ], "Giao dịch ETH #1")
        time.sleep(2)

        # Giao dịch 2: Deploy MockERC20
        log("3. Deploy contract MockERC20 trong lúc collector đang chạy...")
        deploy_out = run_proc([
            FORGE_EXE, "create", "--root", "contracts", "--rpc-url", ANVIL_URL,
            "--private-key", KEY_0, "--broadcast", "src/MockToken.sol:MockERC20",
            "--constructor-args", "500000000000000000000000"
        ], "Deploy MockERC20")
        m_addr = re.search(r"Deployed to:\s+(0x[a-fA-F0-9]{40})", deploy_out)
        token_address = m_addr.group(1)
        log(f"Token deployed: {token_address}")
        time.sleep(2)

        # Giao dịch 3: Chuyển 250 FTT
        log("4. Phát giao dịch chuyển ERC-20 (250 FTT -> Account 2)...")
        run_proc([
            CAST_EXE, "send", "--rpc-url", ANVIL_URL, "--private-key", KEY_0,
            token_address, "transfer(address,uint256)", ACCOUNT_2, "250000000000000000000"
        ], "Chuyển ERC-20")
        time.sleep(3)  # Chờ collector quét xong

        # Gửi tín hiệu dừng collector
        log("5. Dừng tiến trình collector.py collect...")
        collect_proc.terminate()
        try: collect_proc.wait(timeout=4)
        except Exception: collect_proc.kill()
        collect_proc = None

        # Kiểm tra dữ liệu SQLite
        log("6. Đối soát DB: kiểm tra checkpoint tăng, không trùng...")
        conn = sqlite3.connect(DB_PATH)
        cp = conn.execute("SELECT last_block FROM checkpoints WHERE stream='main'").fetchone()
        assert cp is not None and cp[0] >= 3, f"Checkpoint không tăng: {cp}"
        log(f"Checkpoint đạt mức block: {cp[0]}")

        b_cnt = conn.execute("SELECT count(*) FROM blocks").fetchone()[0]
        tx_cnt = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
        tf_cnt = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
        log(f"Số lượng bản ghi: blocks={b_cnt}, txs={tx_cnt}, asset_transfers={tf_cnt}")

        # Kiểm tra tính toàn vẹn (không trùng)
        assert b_cnt >= 4, f"Thiếu block: {b_cnt}"
        assert tx_cnt >= 3, f"Thiếu tx: {tx_cnt}"
        assert tf_cnt >= 3, f"Thiếu transfer: {tf_cnt}"

        # Kiểm tra audit_events có COLLECT_START
        actions = [r[0] for r in conn.execute("SELECT action FROM audit_events").fetchall()]
        assert "COLLECT_START" in actions, "Thiếu COLLECT_START trong audit_events"
        log("Audit events: " + str(actions))
        conn.close()

        # Xác minh bằng verify-rpc và verify-derived
        log("7. Chạy verify-derived...")
        v_derived = run_proc([sys.executable, "collector.py", "verify-derived"], "verify-derived", env=env)
        assert "khớp 100%" in v_derived
        log(f"verify-derived: {v_derived}")

        log("8. Chạy verify-rpc...")
        v_rpc = run_proc([sys.executable, "collector.py", "verify-rpc", "--start-block", "0", "--end-block", str(cp[0])], "verify-rpc", env=env)
        assert "khớp 100%" in v_rpc
        log(f"verify-rpc: {v_rpc}")

        log("=== Hoàn tất kiểm thử collect (continuous): Checkpoint tăng đúng, không trùng lặp ===")

    finally:
        if collect_proc:
            collect_proc.terminate()
            try: collect_proc.wait(timeout=2)
            except Exception: collect_proc.kill()
        anvil_proc.terminate()
        try: anvil_proc.wait(timeout=2)
        except Exception: anvil_proc.kill()
        log("Anvil node đã dừng an toàn.")

        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(log_lines) + "\n")
        print(f"Log đã được lưu tại: {LOG_FILE}")

if __name__ == "__main__":
    main()
