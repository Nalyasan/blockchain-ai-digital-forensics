"""Kịch bản kiểm nghiệm thực tế Giai đoạn P3 trên Anvil:
1. Khởi động node Anvil (Chain ID: 31337).
2. Deploy contract EvidenceRegistry.sol bằng Foundry forge create (--unlocked --from, không dùng private-key).
3. Chạy lệnh CLI anchor neo gói chứng cứ results/p2/case-anvil-p1-001.
4. Chạy lệnh CLI custody ghi nhận sự kiện CustodyRecord on-chain.
5. Chạy lệnh CLI verify-onchain khi dữ liệu nguyên vẹn -> xác nhận khớp với bản ghi on-chain (exit 0).
6. Kịch bản T05 Ca 3: Sửa file chứng cứ sau khi neo -> verify-onchain phát hiện và báo MISMATCH (exit 1).
7. Ghi nhận log đầy đủ vào results/p3/step_p3_anvil_verification.log.
"""
import os
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import json
import time
import socket
import logging
import sqlite3
import subprocess

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def run_proc(cmd, env=None, check=True):
    print(f">> Chạy lệnh: {' '.join(cmd)}")
    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        sub_env.update(env)
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=sub_env, check=False)
    if check and res.returncode != 0:
        print(f"LỖI (returncode={res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}", file=sys.stderr)
        raise RuntimeError(f"Lệnh thất bại: {' '.join(cmd)}")
    return res

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    results_dir = os.path.join(root_dir, "results", "p3")
    os.makedirs(results_dir, exist_ok=True)
    log_file = os.path.join(results_dir, "step_p3_anvil_verification.log")

    log_fp = open(log_file, "w", encoding="utf-8")
    def log_print(msg):
        print(msg)
        log_fp.write(msg + "\n")
        log_fp.flush()

    log_print("================================================================================")
    log_print(" BẮT ĐẦU KIỂM NGHIỆM GIAI ĐOẠN P3 TRÊN ANVIL (SMART CONTRACT & CHAIN OF CUSTODY) ")
    log_print("================================================================================\n")

    port = get_free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    anvil_bin = os.path.join(root_dir, "tools", "foundry", "anvil.exe")
    forge_bin = os.path.join(root_dir, "tools", "foundry", "forge.exe")

    log_print(f"1. Khởi động Anvil trên port {port} (Chain ID: 31337)...")
    anvil_proc = subprocess.Popen([anvil_bin, "--port", str(port), "--chain-id", "31337"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    try:
        # 2. Deploy EvidenceRegistry.sol
        log_print("2. Triển khai hợp đồng EvidenceRegistry.sol bằng forge create (--unlocked --from, không dùng private key)...")
        deploy_res = run_proc([
            forge_bin, "create", "contracts/src/EvidenceRegistry.sol:EvidenceRegistry",
            "--rpc-url", rpc_url,
            "--unlocked",
            "--from", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "--broadcast"
        ])
        log_print(deploy_res.stdout)

        # Trích xuất địa chỉ hợp đồng
        contract_addr = None
        for line in deploy_res.stdout.splitlines():
            if "Deployed to:" in line:
                contract_addr = line.split("Deployed to:")[1].strip()
                break

        assert contract_addr and contract_addr.startswith("0x"), f"Không tìm thấy contract address trong output: {deploy_res.stdout}"
        log_print(f">> Hợp đồng EvidenceRegistry đã deploy tại: {contract_addr}\n")

        # 3. Chuẩn bị database mẫu & gói chứng cứ
        db_path = os.path.join(root_dir, "results", "p1", "anvil_forensics.db")
        manifest_pkg = os.path.join(root_dir, "results", "p2", "case-anvil-p1-001")
        env_anchor = {
            "ANCHOR_RPC_URL": rpc_url,
            "ANCHOR_CHAIN_ID": "31337",
            "ANCHOR_FROM": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        }

        # 4. Neo chứng cứ lên blockchain (anchor)
        log_print("3. Thực hiện lệnh CLI 'anchor' neo gói chứng cứ lên EvidenceRegistry...")
        anchor_res = run_proc([
            sys.executable, "-m", "forensics.cli", "anchor",
            manifest_pkg,
            "--contract", contract_addr,
            "--db", db_path,
            "--rpc-url", rpc_url,
            "--from", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        ], env=env_anchor)
        log_print(anchor_res.stdout)
        assert anchor_res.returncode == 0, "Lệnh anchor thất bại"
        assert "OK: Neo chứng cứ thành công lên blockchain!" in anchor_res.stdout
        assert "Evidence ID: 1" in anchor_res.stdout

        # Kiểm tra SQLite
        conn = sqlite3.connect(db_path)
        row_exp = conn.execute("SELECT onchain_evidence_id FROM evidence_exports WHERE case_id='case-anvil-p1-001'").fetchone()
        assert row_exp and row_exp[0] == 1, f"evidence_exports chưa cập nhật onchain_evidence_id: {row_exp}"
        row_custody = conn.execute("SELECT evidence_id, action, contract_address, verified FROM custody_events WHERE evidence_id=1").fetchone()
        assert row_custody and row_custody[0] == 1, f"custody_events chưa ghi nhận: {row_custody}"
        row_audit = conn.execute("SELECT action, object_ref, metadata FROM audit_events WHERE action='ANCHOR_EVIDENCE' ORDER BY id DESC LIMIT 1").fetchone()
        assert row_audit and "allow_dirty" in row_audit[2], f"audit_events chưa ghi nhận allow_dirty: {row_audit}"
        conn.close()
        log_print(">> Xác nhận: DB SQLite đã cập nhật onchain_evidence_id=1, bản ghi custody_events và audit_events.\n")

        # 5. Ghi nhận sự kiện hành trình tiếp theo (custody)
        log_print("4. Thực hiện lệnh CLI 'custody' ghi nhận hành trình ANALYZED on-chain...")
        custody_res = run_proc([
            sys.executable, "-m", "forensics.cli", "custody",
            "--evidence-id", "1",
            "--action", "1",  # ANALYZED
            "--artifact-hash", "0x1111222233334444555566667777888899990000111122223333444455556666",
            "--note", "AI Investigator verified all rules",
            "--contract", contract_addr,
            "--db", db_path,
            "--rpc-url", rpc_url,
            "--from", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        ], env=env_anchor)
        log_print(custody_res.stdout)
        assert custody_res.returncode == 0
        assert "OK: Ghi nhận custody event thành công!" in custody_res.stdout
        log_print(">> Xác nhận: Sự kiện CustodyRecord đã ghi nhận thành công on-chain.\n")

        # 6. Xác minh tầng 3 (verify-onchain) khi dữ liệu nguyên vẹn
        log_print("5. Thực hiện lệnh CLI 'verify-onchain' trên gói chứng cứ nguyên vẹn...")
        verify_ok = run_proc([
            sys.executable, "-m", "forensics.cli", "verify-onchain",
            manifest_pkg,
            "--contract", contract_addr,
            "--db", db_path,
            "--rpc-url", rpc_url
        ], env=env_anchor)
        log_print(verify_ok.stdout)
        assert verify_ok.returncode == 0
        assert "OK: Khớp 100% với bản ghi on-chain" in verify_ok.stdout
        log_print(">> Xác nhận: verify-onchain xác thực thành công dữ liệu nguyên vẹn (Mã thoát 0).\n")

        # 7. Kịch bản thử nghiệm: Sửa file chứng cứ sau khi neo -> verify-onchain phát hiện và báo MISMATCH
        log_print("6. Kịch bản T05 Ca 3: Can thiệp sửa file dữ liệu sau khi neo on-chain...")
        tamper_dir = os.path.join(root_dir, "results", "p3", "case-tampered-t05")
        os.makedirs(tamper_dir, exist_ok=True)
        for fname in os.listdir(manifest_pkg):
            src_f = os.path.join(manifest_pkg, fname)
            dst_f = os.path.join(tamper_dir, fname)
            if os.path.isfile(src_f):
                with open(src_f, "rb") as rf, open(dst_f, "wb") as wf:
                    wf.write(rf.read())

        # Sửa 1 byte trong asset_transfers.csv
        tf_file = os.path.join(tamper_dir, "asset_transfers.csv")
        with open(tf_file, "r+b") as f:
            f.seek(50)
            b = f.read(1)
            f.seek(50)
            f.write(b"X" if b != b"X" else b"Y")

        # Cố tình cập nhật lại manifest.json để qua mặt tầng local verify-manifest
        manifest_tamper_file = os.path.join(tamper_dir, "manifest.json")
        with open(manifest_tamper_file, "r", encoding="utf-8") as f:
            m_data = json.load(f)

        import hashlib
        with open(tf_file, "rb") as f:
            new_tf_sha = hashlib.sha256(f.read()).hexdigest()
        for item in m_data["files"]:
            if item["path"] == "asset_transfers.csv":
                item["sha256"] = new_tf_sha

        with open(manifest_tamper_file, "w", encoding="utf-8") as f:
            json.dump(m_data, f, indent=2)

        log_print(">> Đã sửa 1 byte trong asset_transfers.csv và cập nhật hash trong manifest.json cục bộ.")
        log_print(">> Chạy verify-onchain để kiểm tra phát hiện giả mạo đối chiếu với Smart Contract bất biến...")

        verify_tamper = run_proc([
            sys.executable, "-m", "forensics.cli", "verify-onchain",
            tamper_dir,
            "--contract", contract_addr,
            "--evidence-id", "1",
            "--rpc-url", rpc_url
        ], env=env_anchor, check=False)

        log_print(f"Mã thoát: {verify_tamper.returncode}")
        log_print(f"STDOUT: {verify_tamper.stdout}")
        log_print(f"STDERR: {verify_tamper.stderr}")

        assert verify_tamper.returncode == 1, f"Kỳ vọng mã thoát 1 khi bị can thiệp nhưng nhận {verify_tamper.returncode}"
        assert "MISMATCH: Dữ liệu trên đĩa không khớp với bản ghi bất biến on-chain" in verify_tamper.stderr
        log_print(">> Xác nhận: Kẻ tấn công sửa file và tự sinh lại manifest cục bộ bị Smart Contract phát hiện MISMATCH (exit 1).\n")

        log_print("================================================================================")
        log_print(" HOÀN TẤT KIỂM NGHIỆM GIAI ĐOẠN P3 TRÊN ANVIL (TẤT CẢ TIÊU CHÍ ĐÃ ĐỐI SOÁT) ")
        log_print("================================================================================")

    finally:
        log_fp.close()
        anvil_proc.terminate()
        anvil_proc.wait()

if __name__ == "__main__":
    main()
