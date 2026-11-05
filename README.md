# BLOCKCHAIN + AI DIGITAL FORENSICS (HỆ THỐNG ĐIỀU TRA SỐ)

> **Dự án Nghiên cứu Học thuật — Đề tài 8: Điều tra số kết hợp Blockchain và Trí tuệ Nhân tạo (K18 ATTT)**  
> **Phiên bản hệ thống:** `v6.0.0` (Chuẩn hóa 12 thành phần chức năng theo `AGENT.md` v6.0)  
> **Kiến trúc cốt lõi:** Multi-Source Ingestion (ISO/IEC 27037) $\rightarrow$ Explainable AI & Machine Learning $\rightarrow$ Zero-Knowledge Machine Learning (ZKML Halo2 BN254 Pairing) $\rightarrow$ Decentralized Identity (W3C DID) & Smart Contract Chain of Custody (EIP-712).

---

## 1. TỔNG QUAN HỆ THỐNG

Hệ thống **Blockchain + AI Digital Forensics** là nền tảng điều tra số đa nguồn thế hệ mới, giải quyết triệt để bài toán **toàn vẹn dữ liệu chứng cứ** và **tính minh bạch, kiểm chứng được của suy luận AI** trong điều tra an ninh mạng.

Hệ thống được xây dựng trên **3 trụ cột công nghệ cốt lõi**:
1. **Trụ cột A — AI Agents & Explainable AI (XAI):**
   - Bộ thu thập đa nguồn (EVM Logs + Host Logs) tuân thủ tiêu chuẩn pháp chứng số **ISO/IEC 27037**.
   - Mô hình học máy phát hiện gian lận dòng tiền độc lập (`CompactAnomalyMLP` ONNX 321 tham số, triệt tiêu hoàn toàn rò rỉ nhãn và thời gian).
   - Giải thích quyết định cục bộ bằng chỉ số định lượng SHAP (`ExactShapleyExplainer` với kiểm chuẩn độ trung thực $R^2$ và độ ổn định nhiễu).
   - Tự động ánh xạ chiến thuật & kỹ thuật **MITRE ATT&CK** v14.1 có căn cứ chứng cứ, kèm cơ chế từ chối gán nhãn sai (`abstain / NOT_MAPPED`).
   - Điều tra viên AI (**AI Investigator**) vận hành trong khuôn khổ rào chắn an toàn đa lớp: **Tool Whitelist** (tối đa 5 bước công cụ), **Ref Checker** (bắt buộc trích dẫn ID thực từ CSDL, triệt tiêu ảo giác), và **SafetyGuard** (chặn 100% Prompt Injection và lệnh can thiệp OS trái phép).
2. **Trụ cột B — Smart Contract Chain of Custody & Decentralized Identity (DID):**
   - Quản lý chuỗi hành trình chứng cứ số bất biến bằng Smart Contract Solidity 0.8.24 trên máy ảo Ethereum (EVM).
   - Ràng buộc định danh điều tra viên qua chuẩn W3C DID Core 1.0 (`did:ethr` / `did:key`).
   - Ký nhận và chuyển giao chứng cứ giữa các tác viên bằng chữ ký có cấu trúc **EIP-712** chống tấn công phát lại (`monotonic nonce` + `deadline`).
3. **Trụ cột C — Zero-Knowledge Machine Learning (ZKML):**
   - Chứng minh tính toàn vẹn của quá trình suy luận AI bằng chứng minh không tiết lộ tri thức (ZK-SNARK) sử dụng hệ chứng minh **Halo2 KZG**.
   - Hợp đồng thông minh `Halo2Verifier.sol` thực hiện phép toán ghép cặp đường cong elip **BN254 Pairing thật trên EVM** (~1.13M gas).
   - Ràng buộc toán học chặt chẽ giữa mã băm mô hình, cam kết đầu vào, cam kết đầu ra và proof bytes; tự động hoàn tác (revert) 100% nếu có bất kỳ sự can thiệp hoặc tráo đổi dữ liệu nào.

---

## 2. CẤU TRÚC THƯ MỤC DỰ ÁN

Hệ thống tổ chức thành **12 thành phần chức năng chuẩn hóa**:

```text
D:\Projest\Blockchain\
├── collector.py                      # [Blockchain Collector] CLI thu thập khối, giao dịch, log EVM
├── mock_rpc.py                       # Mock RPC phục vụ môi trường kiểm thử offline
├── .env.example                      # Cấu hình mẫu môi trường an toàn (không chứa secret)
├── requirements.txt                  # 101 gói phụ thuộc nền tảng
├── requirements-ml-zkml.lock.txt     # 12 gói mở rộng PyTorch, ONNX, EZKL
│
├── forensics/                        # 72 module Python xử lý nghiệp vụ pháp chứng
│   ├── acquisition/ / endpoint/      # [Endpoint Acquisition] Thu thập Host/EVM log theo ISO/IEC 27037 & SafetyGuard
│   ├── adapters/                     # [Threat Intelligence] Bộ nạp dữ liệu đe dọa, screening, benchmark
│   ├── ai/                           # [AI Investigator] Pydantic AI Agent, Ref Checker, Tool Whitelist, SafetyGuard
│   ├── did/                          # [Identity & Custody] Xử lý W3C DID, xác thực chữ ký EIP-712, phân quyền RBAC
│   ├── evaluation/                   # [Integration & Evaluation] Tổng hợp báo cáo đánh giá thực nghiệm
│   ├── ml/                           # [ML/XAI] Trích xuất đặc trưng, suy luận ONNX, SHAP XAI, MITRE ATT&CK
│   ├── rules/                        # [Rule Engine] 4 quy tắc phát hiện tất định R1–R4 (ETH/ERC-20)
│   ├── zkml/                         # [ZKML] Bộ mã hóa lượng tử hóa, cam kết mật mã học, sinh & nạp proof Halo2
│   ├── evidence.py                   # [Evidence Store & Package] Quản lý chứng cứ, manifest, xuất gói tar/zip
│   ├── integrity.py                  # Kiểm tra tính toàn vẹn 3 tầng và cấu trúc lược đồ
│   ├── onchain.py                    # Giao tiếp EVM RPC, tương tác Cast/Forge, che dấu bí mật an toàn
│   └── paths.py                      # Tiện ích đường dẫn độc lập hệ thống và kiểm tra mã băm CSDL
│
├── contracts/                        # Smart Contracts Solidity 0.8.24 & Kiểm thử Foundry
│   ├── src/
│   │   ├── Halo2Verifier.sol         # Hợp đồng xác minh BN254 KZG Pairing thật
│   │   ├── InferenceVerifier.sol     # Wrapper xác minh cam kết ZKML & kiểm tra Model Hash
│   │   ├── EvidenceRegistry.sol      # Sổ đăng ký chứng cứ & Chain of Custody (kế thừa P3)
│   │   └── EvidenceRegistryDID.sol   # Sổ đăng ký mở rộng hỗ trợ DID và EIP-712
│   └── test/                         # 7 suite kiểm thử Foundry (175 tests, 100% PASS)
│
├── circuits/anomaly_detector_v1/     # Hiện vật mạch toán học ZKML Halo2
│   ├── settings.json, network.compiled, vk.key, pk.key, kzg.srs
│   ├── baseline_proof.json           # Proof thật 5.504 bytes của mạng CompactAnomalyMLP
│   └── Halo2Verifier.abi.json
│
├── models/                           # Hiện vật mô hình học máy
│   ├── anomaly_detector_v1.onnx      # Đồ thị ONNX (321 trọng số, SHA-256: d1b9ce82...)
│   ├── anomaly_detector_v1_meta.json # Siêu dữ liệu mô hình và danh sách đặc trưng
│   └── dataset_manifest.json         # Nguồn gốc tập dữ liệu huấn luyện
│
├── data/                             # Dữ liệu chuẩn bất biến (Canonical Protected Datasets)
│   ├── forensics.db                  # Evidence Store chuẩn (SHA-256: 3F2B0DFC...)
│   ├── real_p4.db                    # Khối và giao dịch thực từ Ethereum Mainnet (SHA-256: 6BD9AED4...)
│   ├── benchmark_p6.db               # Tập đối chuẩn Threat Intel (SHA-256: C7FF724C...)
│   └── sample_host_logs/             # Mẫu nhật ký máy chủ chuẩn hóa
│
├── tools/foundry/                    # Bộ công cụ EVM Windows x64: forge.exe, anvil.exe, cast.exe
├── wheels/                           # 101 gói wheel Python cài đặt offline
├── scripts/                          # Các kịch bản CLI, xác minh toàn vẹn, đóng gói portable
└── tests/                            # 90 tệp kiểm thử tự động (1998 test cases)
```

---

## 3. CÀI ĐẶT & THIẾT LẬP MÔI TRƯỜNG

### 3.1 Yêu cầu hệ thống
- **Hệ điều hành:** Windows 10/11 x64 (hoặc Linux x64).
- **Python:** Python `3.11` đến `3.13` (64-bit).
- **Công cụ Blockchain:** Foundry (`forge`, `anvil`, `cast`) — *Đã đóng gói sẵn trong `tools/foundry/` cho Windows*.

### 3.2 Khởi tạo môi trường ảo

Mở PowerShell tại thư mục dự án:

```powershell
Set-Location D:\Projest\Blockchain

# 1. Tạo môi trường ảo Python
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Cài đặt các thư viện nền tảng (101 packages)
# Lựa chọn A: Cài offline từ thư mục wheels có sẵn (không cần Internet)
pip install --no-index --find-links=wheels -r requirements.txt

# Lựa chọn B: Cài trực tiếp từ mạng (nếu máy có Internet)
pip install -r requirements.txt
```

### 3.3 Thiết lập tệp cấu hình `.env`

Tạo tệp `.env` từ `.env.example`:
```powershell
Copy-Item .env.example .env
```

Chỉnh sửa `.env` phù hợp với chế độ vận hành:

| Biến môi trường | Giá trị mặc định (Local Test / Anvil) | Giá trị khi Chạy Thật (Live Sepolia / Gemini) |
|---|---|---|
| `FORENSICS_OFFLINE` | `1` | `0` |
| `ANCHOR_CHAIN_ID` | `31337` (Anvil) | `11155111` (Ethereum Sepolia) |
| `ANCHOR_RPC_URL` | `http://127.0.0.1:8545` | `https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY` |
| `ANCHOR_PRIVATE_KEY`| Khóa Anvil mặc định | `0x_PRIVATE_KEY_VI_CUA_BAN` |
| `AI_PROVIDER` | `none` hoặc `test` | `gemini` (hoặc `ollama`, `openai`) |
| `GEMINI_API_KEY` | *(Để trống)* | `AIzaSy...` (Lấy từ Google AI Studio) |

---

## 4. HƯỚNG DẪN VẬN HÀNH DÒNG LỆNH (TERMINAL CLI)

Dưới đây là các câu lệnh vận hành thực tế cho từng phân hệ của dự án từ Terminal.

### 4.1 Khởi động Node Blockchain Cục Bộ (Terminal riêng)

Nếu chạy kiểm thử nội bộ trên EVM node chuẩn trước khi phát lên mạng công khai:
```powershell
# Mở Terminal mới và chạy:
.\tools\foundry\anvil.exe --host 127.0.0.1 --port 8545
```

---

### 4.2 Module 1: Thu thập Dữ liệu Blockchain On-Chain (`collector.py`)

Công cụ `collector.py` cho phép tương tác trực tiếp với node RPC Ethereum:

```powershell
# 1. Kiểm tra trạng thái kết nối tới RPC node
python collector.py healthcheck

# 2. Thu thập dữ liệu liên tục thời gian thực (Live Continuous Streaming)
python collector.py collect --start-block 19000000 --watch-addresses 0x2718294287B224551D7054c66114372338E8A79C

# 3. Thu thập dữ liệu lịch sử theo khoảng khối hoặc mốc thời gian (Backfill)
python collector.py backfill --start-block 16817990 --end-block 16818010

# 4. Kiểm tra tính toàn vẹn và đối chiếu mã băm của dữ liệu đã cào
python collector.py verify

# 5. Xuất dòng thời gian (Timeline) các giao dịch theo địa chỉ ví cần điều tra
python collector.py timeline --address 0xb66cd966670d962c227b3eaba30a872dbfb995db
```

---

### 4.3 Module 2: Thu thập Dấu vết Máy chủ chuẩn ISO/IEC 27037 (`forensics.endpoint`)

Thu thập nhật ký từ máy chủ (Windows Event Log JSONL, Sysmon, Linux auditd) và tạo hồ sơ pháp chứng:

```powershell
# 1. Tiếp nhận tệp nhật ký, tính SHA-256 gốc và tạo acquisition_manifest.json
python -m forensics.endpoint.adapters `
    --source-type host_file `
    --path data/sample_host_logs/sysmon_incident_sample.jsonl `
    --consent-case "CASE-2026-INCIDENT-01" `
    --investigator-did "did:ethr:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# 2. Kích hoạt First Responder tự động phân loại dấu vết dưới sự bảo vệ của SafetyGuard
python -m forensics.endpoint.first_responder `
    --manifest acquisition_manifest.json `
    --policy strict
```

---

### 4.4 Module 3: Phát hiện Bất thường ML & Giải thích Minh bạch XAI (`forensics.ml`)

Chạy mô hình học máy độc lập để phát hiện dấu hiệu rửa tiền / tấn công dòng tiền:

```powershell
# 1. Thực hiện suy luận bất thường bằng mô hình ONNX CompactAnomalyMLP
python -m forensics.ml.infer `
    --model models/anomaly_detector_v1.onnx `
    --features-input data/sample_features.json `
    --output-inference results/inference_record.json

# 2. Giải thích kết quả suy luận bằng Exact Shapley Values (XAI)
python -m forensics.ml.xai `
    --inference-record results/inference_record.json `
    --calculate-fidelity `
    --output-explanation results/xai_explanation.json

# 3. Ánh xạ kỹ thuật tấn công MITRE ATT&CK (có kiểm tra điều kiện căn cứ chứng cứ)
python -m forensics.ml.mitre `
    --evidence-input results/xai_explanation.json `
    --output-mitre results/mitre_mapping.json
```

---

### 4.5 Module 4: Sinh & Xác Minh Bằng Chứng Mật Mã ZKML Trên EVM

Kiểm chứng suy luận AI bằng ZK-SNARK Halo2 và Smart Contract:

```powershell
# Thêm Foundry vào biến môi trường PATH
$env:PATH = "D:\Projest\Blockchain\tools\foundry;$env:PATH"

# 1. Biên dịch bộ hợp đồng thông minh (Bao gồm bộ giải mã ghép cặp elip BN254)
forge build --root contracts

# 2. Chạy bộ kiểm thử xác minh Halo2 BN254 KZG Pairing trực tiếp trên Foundry
forge test --root contracts --match-contract Halo2RealVerifierTest -vvv

# 3. Tương tác xác minh suy luận qua hợp đồng InferenceVerifier trên mạng Anvil/Sepolia
python scripts/verify_m3_zkml_anvil.py
```

*Hợp đồng sẽ đối chiếu: `SHA256(Input) == InputCommitment` $\rightarrow$ `ModelHash == TargetHash` $\rightarrow$ `Halo2Verifier.verifyProof(proof, instances) == true` $\rightarrow$ Ghi nhận kết quả hợp lệ lên blockchain.*

---

### 4.6 Module 5: Quản lý Chuỗi Hành Trình Chứng Cứ (Chain of Custody & DID)

Quản lý đăng ký và chuyển giao quyền lưu giữ chứng cứ giữa các điều tra viên:

```powershell
# 1. Neo mã băm chứng cứ số lên Smart Contract EvidenceRegistryDID
python -m forensics.did.custody `
    --action anchor `
    --evidence-id "EVID-2026-DAI-001" `
    --evidence-hash "0x4a72d829377488801d0a52df0473abf16f51be0e653ae832a85e43a6dd9de341" `
    --actor-did "did:ethr:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# 2. Chuyển giao chứng cứ giữa 2 điều tra viên (Alice -> Bob) với chữ ký EIP-712
python scripts/run_custody_handover_demo.py
```

---

### 4.7 Module 6: Tương tác với Điều tra viên AI (AI Investigator)

Giao tiếp với Agent điều tra viên có kiểm soát quyền hạn:

```powershell
# Chạy truy vấn điều tra một vụ việc (Agent tự động đọc DB chỉ đọc, qua Tool Whitelist và Ref Checker)
python -m forensics.ai.investigator `
    --case-id "CASE-EULER-2026" `
    --query "Truy vết địa chỉ nhận tiền lớn nhất từ giao dịch khai thác và đối chiếu với danh sách đen."
```

---

## 5. BỘ KIỂM THỬ ĐÁNH GIÁ CHẤT LƯỢNG (TEST SUITE)

Hệ thống được bảo vệ bởi **2.173 ca kiểm thử tự động**, đạt tỷ lệ đỗ **100%**:

```powershell
# 1. Xác minh tính toàn vẹn 4 tài sản CSDL bất biến (4/4 MATCH)
python scripts/verify_m0_baseline.py

# 2. Chạy 175 ca kiểm thử Smart Contract trên Foundry (Solidity)
forge test --root contracts

# 3. Chạy 126 ca kiểm thử khói nhanh (Smoke test trong ~18 giây)
powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1

# 4. Chạy toàn bộ 1.998 ca kiểm thử hồi quy Python (Pytest)
python -m pytest tests -q --tb=short
```

---

## 6. ĐÓNG GÓI BẢN PHÁT HÀNH ĐỘC LẬP (PORTABLE RELEASE)

Dự án cung cấp công cụ tự động đóng gói toàn bộ mã nguồn, dữ liệu chuẩn, binary Foundry và 101 bánh xe Python vào một tệp nén duy nhất để chuyển giao sang máy khác mà không phụ thuộc Internet:

```powershell
# 1. Đóng gói tệp ZIP di động vào thư mục dist/
python scripts/portable.py build --root . --output-dir dist

# 2. Kiểm tra tính toàn vẹn của tệp ZIP vừa đóng gói
python scripts/portable.py verify dist/blockchain_ai_forensics_portable_v6.0.0.zip
```

*Chi tiết quy trình giải nén sạch và thiết lập trên máy mới: xem [`README_SETUP.md`](README_SETUP.md).*

---

## 7. CÁC TÀI LIỆU NGHIÊN CỨU & NGHIỆM THU ĐI KÈM

- 📖 **Kiến trúc chi tiết 7 phân tầng:** [`docs/architecture.md`](docs/architecture.md)
- 📊 **Ma trận 25 cổng nghiệm thu (T01–T25):** [`reports/GAP_MATRIX_T01_T25.md`](reports/GAP_MATRIX_T01_T25.md)
- 📋 **Báo cáo bàn giao tổng thể:** [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md)
- 📝 **Báo cáo nghiệm thu cuối cùng v6.0:** [`reports/FINAL_ACCEPTANCE_REPORT_v6.md`](reports/FINAL_ACCEPTANCE_REPORT_v6.md)
- 🔬 **Báo cáo đối kháng & an ninh (Demo D1/D2/D3):** [`reports/DEMO_EVALUATION_REPORT.md`](reports/DEMO_EVALUATION_REPORT.md)
- 🛡️ **Báo cáo kiểm chứng ZKML:** [`reports/ZKML_VERIFICATION.md`](reports/ZKML_VERIFICATION.md)

---

## 8. GIẤY PHÉP & BẢN QUYỀN

- Mã nguồn dự án được phân phối dưới giấy phép **MIT License**.
- Các bộ dữ liệu on-chain phục vụ nghiên cứu học thuật tuân thủ quy chuẩn trích dẫn khoa học và quyền riêng tư (Zero PII). Chi tiết xem [`LICENSES_AND_DATA_RIGHTS.md`](LICENSES_AND_DATA_RIGHTS.md).
