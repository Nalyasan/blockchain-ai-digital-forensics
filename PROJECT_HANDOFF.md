# BÀN GIAO DỰ ÁN — Điều tra số kết hợp Blockchain và AI (`PROJECT_HANDOFF.md`)

> **Phiên bản hệ thống:** v6.0.0 (AGENT.md v6.0)  
> **Ngày bàn giao:** 2026-11-05  
> **Nhánh chính:** `integration/p7-p10-dev`  
> **Commit HEAD tại thời điểm bàn giao:** Xem `git log --oneline -1`  
> **Đặc tả căn cứ:** `AGENT.md` v6.0 (SHA-256: `DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E`)

---

## 1. Tổng quan dự án

**Tên đề tài:** *Điều tra số kết hợp Blockchain và AI (Blockchain + AI Digital Forensics)* — Đề tài 8, K18 An toàn Thông tin.

**Bài toán:** Tự động nhận biết dấu hiệu bất thường từ nguồn dữ liệu số, thu thập và bảo quản chứng cứ có thể đối chiếu, hỗ trợ điều tra bằng AI với giải thích kiểm chứng được, đồng thời dùng Smart Contract và cơ chế chứng minh mật mã (ZKML) để củng cố tính toàn vẹn của chứng cứ và quá trình suy luận.

**Ba trụ cột nghiên cứu:**
1. **Trụ cột A — AI Agents & Explainable AI (XAI):** Thu thập dấu vết có kiểm soát, phát hiện bất thường bằng ML + Rule Engine, giải thích bằng SHAP + MITRE ATT&CK.
2. **Trụ cột B — Smart Contract Chain of Custody & DID:** Quản lý chuỗi hành trình chứng cứ bất biến trên Anvil EVM, DID W3C Core 1.0, chữ ký EIP-712.
3. **Trụ cột C — Zero-Knowledge Machine Learning (ZKML):** Xác minh suy luận AI bằng ZK-SNARK Halo2 KZG, verifier BN254 pairing thật trên EVM.

---

## 2. Bản đồ 12 thành phần chức năng

| # | Thành phần chức năng | Module chính | Chức năng |
|---|---|---|---|
| 1 | **Blockchain Collector** | `collector.py`, `forensics/real_data_ingest.py` | Thu thập block/tx/receipt/log EVM, backfill, reorg-aware |
| 2 | **Evidence Store** | `forensics/evidence.py`, `forensics/schemas.py`, `forensics/integrity.py` | Lưu trữ bất biến, SHA-256 provenance, schema validation |
| 3 | **Evidence Package** | `forensics/evidence.py` (export/manifest), `forensics/rules/anchored.py` | Đóng gói chứng cứ, manifest, đọc lại từ on-chain anchor |
| 4 | **Rule Engine** | `forensics/rules/` | 4 quy tắc R1–R4 (ETH/ERC-20), tách biệt hoàn toàn khỏi ML |
| 5 | **AI Investigator** | `forensics/ai/` | Điều tra viên AI, tool whitelist, prompt injection guard |
| 6 | **Threat Intelligence** | `forensics/adapters/` | Benchmark, screening, persistence, validate & import |
| 7 | **Endpoint Acquisition** | `forensics/endpoint/` | ISO/IEC 27037 4-bước, EVM/Host adapters, SafetyGuard |
| 8 | **ML/XAI** | `forensics/ml/`, `models/` | CompactAnomalyMLP (321 params), SHAP, MITRE mapping |
| 9 | **ZKML** | `forensics/zkml/`, `circuits/anomaly_detector_v1/` | Halo2 KZG prove/verify, circuit artifacts |
| 10 | **Identity & Custody** | `forensics/did/`, `contracts/src/EvidenceRegistry*.sol` | DID↔signer, EIP-712, 2-actor custody transfer |
| 11 | **Integration & Evaluation** | `scripts/demo_d*.py`, `forensics/evaluation/` | Demo D1/D2/D3, báo cáo đánh giá |
| 12 | **Portable Release** | `scripts/portable.py`, `*.ps1` scripts | Đóng gói ZIP, cài đặt offline, smoke test |

> Bảng đối chiếu đầy đủ tên cũ (P1–P12) ↔ tên chức năng: xem [`docs/naming_cross_reference.md`](docs/naming_cross_reference.md).

---

## 3. Cấu trúc thư mục chính

```text
D:\Projest\Blockchain\
├── AGENT.md                          # Đặc tả v6.0
├── PROJECT_HANDOFF.md                # Tài liệu bàn giao này
├── README_SETUP.md                   # Hướng dẫn cài đặt portable
├── PORTABILITY_TEST_REPORT.md        # Kết quả T25
├── LICENSES_AND_DATA_RIGHTS.md       # Giấy phép & quyền dữ liệu
├── cleanup_manifest.json             # Manifest dọn dẹp M6
├── collector.py                      # Blockchain Collector
├── mock_rpc.py                       # Mock RPC cho offline
├── .env.example                      # Cấu hình mẫu (không chứa bí mật)
├── requirements.txt / *.lock.txt     # Phụ thuộc Python
├── SHA256SUMS.txt                    # Bảng băm phân phối
│
├── forensics/                        # 72 modules Python
│   ├── adapters/                     # Threat Intelligence
│   ├── ai/                           # AI Investigator
│   ├── did/                          # DID & Identity
│   ├── endpoint/                     # Endpoint Acquisition
│   ├── evaluation/                   # Đánh giá tổng hợp
│   ├── ml/                           # ML/XAI/MITRE
│   ├── rules/                        # Rule Engine (R1–R4)
│   ├── zkml/                         # ZKML Codec/Prover
│   ├── evidence.py, integrity.py     # Evidence Store/Package
│   ├── onchain.py                    # On-chain interactions
│   └── paths.py                      # Path & hash utilities
│
├── contracts/
│   ├── src/                          # 7 Solidity contracts
│   │   ├── Halo2Verifier.sol         # BN254 KZG pairing verifier
│   │   ├── InferenceVerifier.sol     # ZKML inference wrapper
│   │   ├── EvidenceRegistry.sol      # CoC (legacy compatible)
│   │   └── EvidenceRegistryDID.sol   # CoC + DID + EIP-712
│   └── test/                         # 7 Foundry test suites
│
├── models/
│   ├── anomaly_detector_v1.onnx      # ML model (321 params)
│   ├── anomaly_detector_v1_meta.json # Model metadata
│   └── dataset_manifest.json         # Dataset provenance
│
├── circuits/anomaly_detector_v1/     # ZKML artifacts
│   ├── settings.json, network.compiled
│   ├── vk.key, kzg.srs, pk.key
│   ├── baseline_proof.json (5.504 bytes)
│   └── Halo2Verifier.abi.json
│
├── data/                             # 3 canonical DBs (immutable)
│   ├── forensics.db, real_p4.db, benchmark_p6.db
│   └── sample_host_logs/            # Host log fixtures
│
├── scripts/                          # 38 scripts
│   ├── demo_d1_evm.py / demo_d2_host.py / demo_d3_adversarial.py
│   ├── portable.py                   # Build/verify ZIP
│   ├── verify_m0_baseline.py         # Canonical hash check
│   └── verify_protected_hashes.py
│
├── tests/                            # 90 test files
├── reports/                          # Báo cáo nghiệm thu
├── results/verification/             # JSON kết quả kiểm chứng
├── tools/foundry/                    # forge/anvil/cast (Windows x64)
├── wheels/                           # 101 offline .whl packages
├── docs/                             # Tài liệu kiến trúc
│   ├── architecture.md
│   ├── naming_cross_reference.md
│   └── legacy/agent_v5.1.txt
│
├── dist/                             # Portable ZIP output
│   └── blockchain_ai_forensics_portable_v6.0.0.zip
│
├── setup.ps1 / smoke_test.ps1 / run_full_tests.ps1 / verify_integrity.ps1
└── .gitignore
```

---

## 4. Thiết lập môi trường phát triển

### 4.1 Yêu cầu hệ thống
- **OS:** Windows 10/11 x64
- **Python:** CPython 3.13.x (64-bit) — yêu cầu cho wheels đóng gói sẵn
- **PowerShell:** 5.1+ hoặc 7+
- **Mạng:** Không cần (chế độ offline mặc định)

### 4.2 Cài đặt từ mã nguồn
```powershell
# Clone hoặc giải nén
Set-Location D:\Projest\Blockchain

# Tạo .venv từ wheels offline
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --no-index --find-links=wheels -r requirements.txt

# Sao chép cấu hình
Copy-Item .env.example .env  # Chỉnh sửa nếu cần
```

### 4.3 Cài đặt từ gói Portable
Xem hướng dẫn chi tiết: [`README_SETUP.md`](README_SETUP.md)

---

## 5. Các lệnh vận hành chính

### 5.1 Kiểm chứng tính toàn vẹn
```powershell
# Kiểm tra 4 tài sản bảo vệ (3 DB + .env)
python scripts/verify_m0_baseline.py

# Kiểm tra hash mở rộng
python scripts/verify_protected_hashes.py
```

### 5.2 Biên dịch và kiểm thử Smart Contract (Foundry)
```powershell
$env:PATH = "D:\Projest\Blockchain\tools\foundry;$env:PATH"

# Biên dịch
forge build --root contracts

# Chạy test (175 tests, 7 suites)
forge test --root contracts -vvv
```

### 5.3 Chạy bộ kiểm thử Python (pytest)
```powershell
$env:FORENSICS_OFFLINE = "1"
$env:AI_PROVIDER = "none"
$env:ANCHOR_CHAIN_ID = "31337"
$env:ANCHOR_RPC_URL = "http://127.0.0.1:8545"
$env:PYTHONUTF8 = "1"
$env:PATH = "D:\Projest\Blockchain\tools\foundry;$env:PATH"

# Chạy tất cả (cần Anvil đang lắng nghe trên 8545)
python -m pytest tests -q --tb=short
```

### 5.4 Chạy Demo đầu-cuối
```powershell
# Khởi động Anvil (terminal riêng)
.\tools\foundry\anvil.exe --host 127.0.0.1 --port 8545

# Demo D1: EVM Incident Replay (8 pha, ZKML + DID + CoC)
python scripts/demo_d1_evm.py

# Demo D2: Host Log ISO/IEC 27037 (6 pha)
python scripts/demo_d2_host.py

# Demo D3: Adversarial Security (35/35 vectors, 6 gates)
python scripts/demo_d3_adversarial.py
```

### 5.5 Đóng gói và kiểm thử Portable Release
```powershell
# Build ZIP
python scripts/portable.py build . dist

# Verify ZIP
python scripts/portable.py verify dist/blockchain_ai_forensics_portable_v6.0.0.zip
```

---

## 6. Dữ liệu được bảo vệ — SHA-256 Canonical

Các tài sản sau TUYỆT ĐỐI KHÔNG được sửa đổi nội dung. Mọi thay đổi hash sẽ làm FAIL toàn bộ test suite:

| Tài sản | SHA-256 |
|---|---|
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` |
| `data/benchmark_p6.db` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` |
| `.env` (bản gốc) | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` |
| `.env` (từ `.env.example`) | `438BBE0069FC1C5B44A5ED6E19922DFCE6CB5F65BC33B29BE3D799E614A66B50` |
| `models/anomaly_detector_v1.onnx` | `d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff` |
| `AGENT.md` v6.0 | `DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E` |

> **Lưu ý `.env`:** Trên bản portable, `setup.ps1` tạo `.env` từ `.env.example`, hash khác bản gốc. Hệ thống chấp nhận cả hai qua `forensics.paths.accepted_env_sha256()`. Ba CSDL SQLite vẫn khóa cứng 1 hash duy nhất.

---

## 7. Kiến trúc hợp đồng thông minh

```text
Halo2Verifier.sol (BN254 KZG pairing, ~1.136K gas)
       ↑ delegatecall
InferenceVerifier.sol (SHA-256 input/output commitment + modelHash check)
       ↑ called by
EvidenceRegistryDID.sol (CoC + DID + EIP-712 nonce/deadline)
       ↑ backward-compatible with
EvidenceRegistry.sol (legacy P3 CoC, 5 event types)
```

Xem chi tiết: [`docs/architecture.md`](docs/architecture.md)

---

## 8. Kết quả kiểm thử tổng hợp

### 8.1 Foundry (Smart Contract)
- **175 tests** trong **7 suites** — **100% PASS, 0 FAIL, 0 SKIP**
- Gas `Halo2Verifier.verifyProof`: 1,135,772 – 1,137,038

### 8.2 Pytest (Python)
- Xem chi tiết tại `results/verification/m6_full_regression_junit.xml` và `reports/FINAL_ACCEPTANCE_REPORT_v6.md`

### 8.3 Ma trận T01–T25
- **25/25 gates: DONE** (T25 = giải nén sạch trên cùng máy)
- **T25-B (máy vật lý thứ hai): NOT_VERIFIED**
- Chi tiết: [`reports/GAP_MATRIX_T01_T25.md`](reports/GAP_MATRIX_T01_T25.md)

---

## 9. Các giới hạn đã biết và hạng mục còn mở

1. **T25-B — Kiểm thử trên máy Windows vật lý thứ hai:** `NOT_VERIFIED`. Cần sao chép `dist/blockchain_ai_forensics_portable_v6.0.0.zip` sang máy khác và chạy toàn bộ quy trình `verify_integrity.ps1` → `setup.ps1` → `smoke_test.ps1`.

2. **Xác nhận học thuật từ giảng viên:** Mức bắt buộc ZKML (prototype PoC hay triển khai đầy đủ), DL/GNN (tùy chọn nghiên cứu), tiêu chuẩn bảo quản chứng cứ.

3. **12 gói ML/ZKML mở rộng:** `torch`, `ezkl`, `onnx`, ... chưa có trong `wheels/`. Không ảnh hưởng smoke test. Xem `requirements-ml-zkml.lock.txt`.

4. **ZKML chỉ áp dụng cho Demo D1 (EVM):** Mạch Halo2 biên dịch cho `CompactAnomalyMLP` 10 đặc trưng dòng tiền. Demo D2 (host log) ghi `ARCHITECTURAL_LIMITATION` — không mock.

5. **Ground truth ML:** 12 cửa sổ dương tính / 5.265 tổng → precision/recall có độ bất định lớn. Đây là PoC học thuật.

6. **An toàn `_run_cast`:** Commit M6 sửa hồi quy rò rỉ stderr của `cast`. Luôn dùng thông báo hằng số `CAST_EXIT_{code}: công cụ không hoàn tất yêu cầu`.

7. **70 test SKIPPED kế thừa:** Từ baseline P1–P6, yêu cầu Gemini API key hoặc Sepolia RPC. Không có SKIP nhân tạo mới.

---

## 10. Tài liệu tham chiếu

| Tài liệu | Đường dẫn |
|---|---|
| Đặc tả v6.0 | [`AGENT.md`](AGENT.md) |
| Kiến trúc hệ thống | [`docs/architecture.md`](docs/architecture.md) |
| Bảng đối chiếu tên | [`docs/naming_cross_reference.md`](docs/naming_cross_reference.md) |
| Ma trận T01–T25 | [`reports/GAP_MATRIX_T01_T25.md`](reports/GAP_MATRIX_T01_T25.md) |
| Thay đổi, gaps, giới hạn | [`reports/V6_CHANGES_GAPS_AND_LIMITATIONS.md`](reports/V6_CHANGES_GAPS_AND_LIMITATIONS.md) |
| Báo cáo nghiệm thu cuối | [`reports/FINAL_ACCEPTANCE_REPORT_v6.md`](reports/FINAL_ACCEPTANCE_REPORT_v6.md) |
| Hướng dẫn cài đặt portable | [`README_SETUP.md`](README_SETUP.md) |
| Kiểm thử tính di động | [`PORTABILITY_TEST_REPORT.md`](PORTABILITY_TEST_REPORT.md) |
| Dọn dẹp & khôi phục | [`cleanup_manifest.json`](cleanup_manifest.json), [`reports/CLEANUP_MANIFEST_AND_RESTORE.md`](reports/CLEANUP_MANIFEST_AND_RESTORE.md) |
| Giấy phép & quyền dữ liệu | [`LICENSES_AND_DATA_RIGHTS.md`](LICENSES_AND_DATA_RIGHTS.md) |
| Báo cáo demo D1/D2/D3 | `reports/DEMO_D*_SUMMARY.md`, `reports/DEMO_EVALUATION_REPORT.md` |
| Báo cáo ZKML | [`reports/ZKML_VERIFICATION.md`](reports/ZKML_VERIFICATION.md) |

---

## 11. Quy trình bàn giao cho người tiếp nhận

1. **Đọc** `AGENT.md` v6.0 (§0 Quy tắc, §1 Phạm vi, §12 Tiêu chí nghiệm thu).
2. **Chạy** `python scripts/verify_m0_baseline.py` — xác minh 4 tài sản canonical.
3. **Chạy** Foundry tests: `forge test --root contracts` — phải 175/175 PASS.
4. **Chạy** pytest: `python -m pytest tests -q` — đối chiếu với số liệu trong `FINAL_ACCEPTANCE_REPORT_v6.md`.
5. **Đọc** `reports/GAP_MATRIX_T01_T25.md` — hiểu trạng thái từng gate.
6. **Đọc** `reports/V6_CHANGES_GAPS_AND_LIMITATIONS.md` — hiểu các khoảng trống.
7. **Nếu cần demo:** chạy `demo_d1_evm.py` trên Anvil cục bộ.
8. **Nếu cần portable:** giải nén ZIP sang máy mới theo `README_SETUP.md`.

---

*Tài liệu bàn giao này được tạo tự động dựa trên kết quả kiểm chứng thực tế của Milestone M6. Mọi số liệu đều có thể tái lập bằng các lệnh nêu trên.*
