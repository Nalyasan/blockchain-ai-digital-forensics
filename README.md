# BLOCKCHAIN + AI DIGITAL FORENSICS (HỆ THỐNG ĐIỀU TRA SỐ)

> **Dự án Nghiên cứu Khoa học — Đề tài 8: Điều tra số kết hợp Blockchain và Trí tuệ Nhân tạo (K18 An toàn Thông tin)**  
> **Đặc tả căn cứ:** `AGENT.md` v6.1 (Phạm vi P1–P11: Vận hành thực tế trên Terminal CLI đa nền tảng)  
> **Kiến trúc cốt lõi:** Multi-Source Evidence Ingestion (ISO/IEC 27037) $\rightarrow$ Explainable AI & Machine Learning $\rightarrow$ Zero-Knowledge Machine Learning (Halo2 BN254 Pairing) $\rightarrow$ Decentralized Identity (W3C DID) & Smart Contract Chain of Custody (EIP-712).

---

## 1. TỔNG QUAN HỆ THỐNG

Hệ thống **Blockchain + AI Digital Forensics** là giải pháp điều tra số tiên tiến giải quyết đồng thời hai bài toán trọng tâm: **bảo toàn tính toàn vẹn tuyệt đối của chuỗi chứng cứ số** và **kiểm chứng mật mã học quá trình suy luận của Trí tuệ Nhân tạo (AI)**.

### Ba Trụ Cột Công Nghệ:
1. **Trụ cột A — AI First Responder, Học Máy & Explainable AI (XAI):**
   - Thu thập dấu vết đa nguồn (EVM on-chain + Host logs) tuân thủ nghiêm ngặt nguyên tắc bảo quản chứng cứ **ISO/IEC 27037**.
   - Mô hình học máy phát hiện bất thường dòng tiền độc lập `CompactAnomalyMLP` (ONNX, 321 tham số, triệt tiêu hoàn toàn rò rỉ nhãn và thời gian).
   - Giải thích suy luận định lượng bằng **Exact Shapley Values (SHAP)** có đo lường độ trung thực cục bộ ($R^2$) và độ ổn định nhiễu.
   - Ánh xạ chiến thuật & kỹ thuật **MITRE ATT&CK** v14.1 có căn cứ chứng cứ bắt buộc và cơ chế từ chối gán nhãn sai (`abstain / NOT_MAPPED`).
   - Điều tra viên AI (**AI Investigator**) vận hành trong khuôn khổ rào chắn an toàn: **Tool Whitelist** (tối đa 5 bước công cụ), **Ref Checker** (bắt buộc trích dẫn mã chứng cứ thực tế từ CSDL chỉ đọc, triệt tiêu ảo giác), và **SafetyGuard** (chặn 100% Prompt Injection và lệnh can thiệp hệ điều hành trái phép).
2. **Trụ cột B — Smart Contract Chain of Custody & Decentralized Identity (DID):**
   - Quản lý chuỗi hành trình chứng cứ bất biến bằng Smart Contract Solidity 0.8.24 trên máy ảo Ethereum (EVM).
   - Định danh phân tán theo chuẩn W3C DID Core 1.0 (`did:ethr` / `did:key`).
   - Ký nhận và chuyển giao quyền lưu giữ chứng cứ giữa các tác viên bằng chữ ký có cấu trúc **EIP-712** chống phát lại (`monotonic nonce` + `deadline`).
3. **Trụ cột C — Zero-Knowledge Machine Learning (ZKML):**
   - Chứng minh tính toàn vẹn của suy luận AI bằng ZK-SNARK sử dụng hệ chứng minh **Halo2 KZG**.
   - Hợp đồng thông minh `Halo2Verifier.sol` thực hiện phép toán ghép cặp đường cong elip **BN254 Pairing thật trên EVM** (~1.13M gas).
   - Ràng buộc mật mã học giữa mã băm mô hình, cam kết đầu vào, cam kết đầu ra và bằng chứng tính toán; tự động hoàn tác (revert) 100% trước mọi hành vi sửa đổi dữ liệu.

---

## 2. YÊU CẦU TIÊN QUYẾT & CÀI ĐẶT ĐA NỀN TẢNG (SETUP)

Hệ thống được thiết kế để chạy trực tiếp trên dòng lệnh (Terminal / CLI) của **bất kỳ hệ điều hành nào**: Linux, macOS, hoặc Windows.

### 2.1 Yêu Cầu Môi Trường
- **Python:** Phiên bản `3.11`, `3.12`, hoặc `3.13` (64-bit).
- **Git:** Quản lý mã nguồn.
- **Foundry (`forge`, `anvil`, `cast`):** Bộ công cụ phát triển và kiểm thử Smart Contract EVM.

---

### 2.2 Cài Đặt Công Cụ Tiên Quyết Theo Từng Hệ Điều Hành

#### Trên Linux (Ubuntu / Debian):
```bash
# 1. Cài đặt Python 3, pip và venv
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl

# 2. Cài đặt bộ công cụ Foundry (forge, anvil, cast)
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
```

#### Trên macOS (Apple Silicon / Intel):
```bash
# 1. Cài đặt Python và Foundry qua Homebrew
brew install python git curl
curl -L https://foundry.paradigm.xyz | bash
source ~/.zshrc
foundryup
```

#### Trên Windows (PowerShell):
```powershell
# 1. Cài đặt Python 3.13 (nếu chưa có)
winget install Python.Python.3.13

# 2. Cài đặt Foundry (hoặc sử dụng bản có sẵn trong thư mục tools/foundry)
powershell -c "irm https://foundry.paradigm.xyz | iex"
foundryup
```

---

### 2.3 Khởi Tạo Môi Trường Ảo & Cài Đặt Thư Viện

Sau khi clone kho mã nguồn, mở Terminal tại thư mục dự án:

#### Trên Linux / macOS:
```bash
# 1. Tạo môi trường ảo .venv
python3 -m venv .venv
source .venv/bin/activate

# 2. Cài đặt toàn bộ phụ thuộc (Bao gồm PyTorch, ONNX, EZKL, Pydantic AI, Web3)
pip install --upgrade pip
pip install -r requirements.txt
```

#### Trên Windows (PowerShell):
```powershell
# 1. Tạo môi trường ảo .venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Cài đặt toàn bộ phụ thuộc
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

### 2.4 Cấu Hình Biến Môi Trường (`.env`)

Sao chép tệp cấu hình mẫu và chỉnh sửa theo nhu cầu vận hành:

```bash
# Linux / macOS
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

#### Bảng Tham Số Cấu Hình Trong `.env`:

| Biến môi trường | Chế độ Kiểm thử Cục bộ (Local Anvil) | Chế độ Vận hành Thật (Live Sepolia / Gemini API) | Mô tả |
|---|---|---|---|
| `FORENSICS_OFFLINE` | `1` | `0` | Khóa các kết nối ra ngoài internet khi chạy offline |
| `ANCHOR_CHAIN_ID` | `31337` | `11155111` (Sepolia) | Chain ID của mạng blockchain đích |
| `ANCHOR_RPC_URL` | `http://127.0.0.1:8545` | `https://eth-sepolia.g.alchemy.com/v2/KEY` | Địa chỉ RPC node Ethereum |
| `ANCHOR_PRIVATE_KEY`| *(Khóa Anvil mặc định)* | `0x_PRIVATE_KEY_VI_CUA_BAN` | Khóa ký giao dịch neo chứng cứ |
| `AI_PROVIDER` | `test` hoặc `none` | `gemini` (hoặc `ollama`, `openai`) | Nhà cung cấp LLM cho điều tra viên AI |
| `GEMINI_API_KEY` | *(Để trống)* | `AIzaSy...` | Khóa API từ Google AI Studio |

---

## 3. HƯỚNG DẪN VẬN HÀNH THỰC TẾ BẰNG DÒNG LỆNH (CLI)

Tất cả các lệnh dưới đây sử dụng cú pháp chuẩn, hoạt động đồng nhất trên Linux, macOS và Windows (chỉ cần thay `python3` trên Linux/macOS hoặc `python` trên Windows).

---

### 3.1 Khởi Động Node Blockchain Cục Bộ (EVM Node)

Khi cần thử nghiệm hoặc vận hành cục bộ mà không tốn phí gas mạng thật, mở một cửa sổ Terminal riêng và khởi động EVM node Anvil:

```bash
anvil --host 127.0.0.1 --port 8545
```
*Node sẽ lắng nghe giao dịch trên cổng `8545` với Chain ID `31337`.*

---

### 3.2 Phân Hệ 1: Thu Thập Dữ Liệu Blockchain On-Chain (`collector.py`)

Công cụ `collector.py` thực hiện giao tiếp RPC, trích xuất block, transaction, receipt và event logs:

```bash
# 1. Kiểm tra tình trạng kết nối tới RPC Node
python3 collector.py healthcheck

# 2. Thu thập dữ liệu liên tục thời gian thực (Live Continuous Collection)
python3 collector.py collect --start-block 19000000 --watch-addresses 0x2718294287B224551D7054c66114372338E8A79C

# 3. Thu thập dữ liệu lịch sử theo khoảng khối (Historical Backfill)
python3 collector.py backfill --start-block 16817990 --end-block 16818010

# 4. Kiểm tra tính toàn vẹn mật mã học của dữ liệu đã thu thập
python3 collector.py verify

# 5. Xuất dòng thời gian (Timeline) giao dịch của một địa chỉ ví nghi vấn
python3 collector.py timeline --address 0xb66cd966670d962c227b3eaba30a872dbfb995db
```

---

### 3.3 Phân Hệ 2: Thu Thập Dấu Vết Máy Chủ Chuẩn ISO/IEC 27037 (`forensics.endpoint`)

Tiếp nhận nhật ký máy chủ (Windows Event Log JSONL, Sysmon, Linux auditd/syslog) và lập hồ sơ chứng cứ số:

```bash
# 1. Tiếp nhận tệp nhật ký, tính SHA-256 gốc và sinh acquisition_manifest.json
python3 -m forensics.endpoint.adapters \
    --source-type host_file \
    --path data/sample_host_logs/sysmon_incident_sample.jsonl \
    --consent-case "CASE-2026-LIVE-01" \
    --investigator-did "did:ethr:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# 2. Kích hoạt First Responder phân tích dấu vết dưới sự bảo vệ của SafetyGuard
python3 -m forensics.endpoint.first_responder \
    --manifest acquisition_manifest.json \
    --policy strict
```

---

### 3.4 Phân Hệ 3: Phát Hiện Bất Thường Bằng Học Máy & Giải Thích XAI (`forensics.ml`)

Chạy mô hình học máy `CompactAnomalyMLP` và giải thích quyết định suy luận:

```bash
# 1. Trích xuất đặc trưng và suy luận bất thường bằng mô hình ONNX
python3 -m forensics.ml.infer \
    --model models/anomaly_detector_v1.onnx \
    --features-input data/sample_features.json \
    --output-inference results/inference_record.json

# 2. Giải thích quyết định mô hình bằng Exact Shapley Values (XAI)
python3 -m forensics.ml.xai \
    --inference-record results/inference_record.json \
    --calculate-fidelity \
    --output-explanation results/xai_explanation.json

# 3. Ánh xạ kỹ thuật tấn công MITRE ATT&CK v14.1 có căn cứ chứng cứ
python3 -m forensics.ml.mitre \
    --evidence-input results/xai_explanation.json \
    --output-mitre results/mitre_mapping.json
```

---

### 3.5 Phân Hệ 4: Sinh Bằng Chứng Mật Mã ZKML & Xác Minh Trên Smart Contract

Kiểm chứng tính toàn vẹn của suy luận AI bằng chứng minh toán học ZK-SNARK:

```bash
# 1. Biên dịch bộ Smart Contract Solidity (bao gồm trình giải mã ghép cặp BN254)
forge build --root contracts

# 2. Chạy kiểm thử xác minh Halo2 BN254 KZG Pairing trực tiếp trên EVM
forge test --root contracts --match-contract Halo2RealVerifierTest -vvv

# 3. Thực hiện xác minh suy luận qua hợp đồng InferenceVerifier on-chain
python3 scripts/verify_m3_zkml_anvil.py
```
*Giao dịch xác minh on-chain sẽ kiểm tra: `SHA256(Input) == InputCommitment` $\rightarrow$ `ModelHash == TargetHash` $\rightarrow$ `Halo2Verifier.verifyProof(proof, instances) == true`.*

---

### 3.6 Phân Hệ 5: Quản Lý Chuỗi Hành Trình Chứng Cứ (Chain of Custody & DID)

Quản lý đăng ký, niêm phong và chuyển giao quyền lưu giữ chứng cứ giữa các điều tra viên:

```bash
# 1. Neo mã băm chứng cứ số lên Smart Contract EvidenceRegistryDID
python3 -m forensics.did.custody \
    --action anchor \
    --evidence-id "EVID-2026-LIVE-001" \
    --evidence-hash "0x4a72d829377488801d0a52df0473abf16f51be0e653ae832a85e43a6dd9de341" \
    --actor-did "did:ethr:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# 2. Chuyển giao chứng cứ giữa 2 điều tra viên (Alice -> Bob) với chữ ký EIP-712
python3 scripts/run_custody_handover_demo.py
```

---

### 3.7 Phân Hệ 6: Vận Hành Điều Tra Viên AI (AI Investigator)

Giao tiếp với Agent điều tra viên có kiểm soát quyền hạn chặt chẽ:

```bash
# Chạy truy vấn điều tra vụ việc (Agent tự động truy vấn CSDL chỉ đọc, qua Tool Whitelist và Ref Checker)
python3 -m forensics.ai.investigator \
    --case-id "CASE-EULER-2026" \
    --query "Truy vết địa chỉ nhận tiền lớn nhất từ giao dịch khai thác và đối chiếu với danh sách đen."
```

---

## 4. KIỂM ĐỊNH TÍNH TOÀN VẸN & BỘ KIỂM THỬ TỰ ĐỘNG

Dự án duy trì bộ kiểm thử toàn diện bảo vệ tính toàn vẹn dữ liệu và mã nguồn:

```bash
# 1. Kiểm tra tính toàn vẹn 4 CSDL bất biến (Phải trả về 4/4 MATCH và PASS)
python3 scripts/verify_m0_baseline.py

# 2. Chạy 175 ca kiểm thử Smart Contract Solidity trên Foundry
forge test --root contracts

# 3. Chạy toàn bộ bộ kiểm thử hồi quy Python (Pytest)
python3 -m pytest tests/ -q --tb=short
```

---

## 5. DỮ LIỆU BẢO VỆ — MÃ BĂM BẤT BIẾN (CANONICAL HASHES)

Các tệp dữ liệu chuẩn sau đây được bảo vệ nghiêm ngặt tính toàn vẹn bitwise SHA-256:

| Tệp Dữ Liệu | SHA-256 Chuẩn | Mô Tả |
|---|---|---|
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | Khối và giao dịch thực tế từ Ethereum Mainnet |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | Cơ sở dữ liệu chứng cứ và dấu vết số |
| `data/benchmark_p6.db`| `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | Tập đối chuẩn Threat Intelligence |
| `models/anomaly_detector_v1.onnx` | `d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff` | Trọng số mạng nơ-ron phân loại bất thường |

---

## 6. TÀI LIỆU NGHIÊN CỨU & KIẾN TRÚC THAM CHIẾU

- 📖 **Đặc tả mục tiêu kỹ thuật:** [`AGENT.md`](AGENT.md)
- 🏛️ **Tài liệu kiến trúc runtime 7 phân tầng:** [`docs/architecture.md`](docs/architecture.md)
- 📊 **Ma trận đối chiếu các cổng nghiệm thu:** [`reports/GAP_MATRIX_T01_T25.md`](reports/GAP_MATRIX_T01_T25.md)
- 🔬 **Báo cáo đánh giá thực nghiệm (Demo D1/D2/D3):** [`reports/DEMO_EVALUATION_REPORT.md`](reports/DEMO_EVALUATION_REPORT.md)
- 🛡️ **Báo cáo kiểm chứng toán học ZKML:** [`reports/ZKML_VERIFICATION.md`](reports/ZKML_VERIFICATION.md)

---

## 7. GIẤY PHÉP & BẢN QUYỀN

- Mã nguồn dự án phát hành theo giấy phép **MIT License**.
- Dữ liệu nghiên cứu tuân thủ các quy tắc pháp chứng số, bảo vệ thông tin nhận dạng cá nhân (Zero PII) và sử dụng hợp pháp cho mục đích nghiên cứu học thuật.
