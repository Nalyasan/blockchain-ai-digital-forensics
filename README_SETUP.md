# HƯỚNG DẪN CÀI ĐẶT VÀ VẬN HÀNH GÓI PORTABLE (`README_SETUP.md`)

- **Hệ thống**: Điều tra số kết hợp Blockchain và AI (*Blockchain + AI Digital Forensics* — Academic PoC, `AGENT.md` v6.0)
- **Nền tảng mục tiêu**: Windows 10/11 x64 (hoạt động độc lập ở chế độ offline, không phụ thuộc ổ đĩa hay tên người dùng máy nguồn)
- **Gói phát hành**: `blockchain_ai_forensics_portable_v6.0.0.zip`

---

## 1. Thành phần tích hợp sẵn trong gói Portable Release

Gói phân phối tự thân (self-contained) bao gồm toàn bộ 12 thành phần chức năng chuẩn hóa:
1. **Blockchain Collector** (`collector.py`, `mock_rpc.py`) & **Evidence Store / Evidence Package** (`forensics/`).
2. **Rule Engine** (`forensics/rules/`), **AI Investigator** (`forensics/ai/`), **Threat Intelligence** (`forensics/adapters/`).
3. **Endpoint Acquisition** theo ISO/IEC 27037 (`forensics/endpoint/`).
4. **ML/XAI** (`forensics/ml/`, mô hình đã huấn luyện `models/anomaly_detector_v1.onnx` và metadata `models/anomaly_detector_v1_meta.json`).
5. **ZKML** (`forensics/zkml/`, mạch Halo2 BN254 KZG biên dịch sẵn cùng khóa `pk.key`, `vk.key`, `kzg.srs`, `settings.json`, `baseline_proof.json` trong `circuits/anomaly_detector_v1/` và hợp đồng xác minh thực `contracts/src/Halo2Verifier.sol` + `contracts/src/InferenceVerifier.sol`).
6. **Identity & Custody** (`forensics/did/`, `contracts/src/EvidenceRegistry.sol`, `contracts/src/EvidenceRegistryDID.sol`).
7. **Integration & Evaluation** (`scripts/demo_d1_evm.py`, `scripts/demo_d2_host.py`, `scripts/demo_d3_adversarial.py`, `forensics/evaluation/`).
8. **Công cụ & Dữ liệu chuẩn đi kèm**:
   - Bộ công cụ Foundry đóng gói sẵn cho Windows x64: `tools/foundry/forge.exe`, `tools/foundry/anvil.exe`, `tools/foundry/cast.exe`.
   - 3 cơ sở dữ liệu chuẩn SQLite chỉ đọc (`data/forensics.db`, `data/real_p4.db`, `data/benchmark_p6.db`).
   - Thư mục `wheels/` chứa **101 gói `.whl` offline** khớp với `requirements.txt` (CPython 3.13 `win_amd64`).
   - Tệp khóa phiên bản đầy đủ `requirements.lock.txt` (113 gói) và `requirements-ml-zkml.lock.txt` (12 gói mở rộng `torch`/`onnx`/`ezkl`).
   - Bảng băm mật mã `SHA256SUMS.txt` và tệp cấu hình mẫu không chứa bí mật `.env.example`.

---

## 2. Yêu cầu hệ thống tối thiểu trên máy đích

- **Hệ điều hành**: Windows 10 hoặc Windows 11 (64-bit / `win_amd64`).
- **Python**: CPython `3.13.x` (64-bit) để tương thích trực tiếp với các gói biên dịch C-extension (`pydantic_core`, `cryptography`, `cffi`, `pymupdf`, `pywin32`, `rpds-py`) trong `wheels/`. (Mã nguồn Python tương thích với Python >= 3.11 nếu người dùng tự cung cấp môi trường Python có sẵn).
- **PowerShell**: Windows PowerShell 5.1+ hoặc PowerShell 7+.
- **Kết nối mạng**: **Không yêu cầu** cho kiểm tra toàn vẹn, biên dịch/kiểm thử hợp đồng thông minh Foundry (kể cả xác minh BN254 KZG pairing thật trên `Halo2Verifier.sol`), cài đặt 101 gói bánh xe offline và chạy `smoke_test.ps1`.
  - *Lưu ý minh bạch về 12 gói mở rộng ML/ZKML*: Thư mục `wheels/` đóng gói 101 gói nền tảng trong `requirements.txt`. Các mô-đun suy luận ML thuần Python (`CompactAnomalyMLP`), giải thích SHAP chính xác (`ExactShapleyExplainer`), ánh xạ MITRE ATT&CK và xác minh hợp đồng `Halo2Verifier.sol` trên Anvil chạy **100% offline không cần cài thêm gói**. Nếu muốn sinh bằng chứng Halo2 mới qua Python `ezkl==23.0.5` hoặc huấn luyện lại ONNX bằng `torch==2.15.0` bên trong `.venv` mới tinh, cần bổ sung các bánh xe trong `requirements-ml-zkml.lock.txt` vào `wheels/` hoặc chạy `.\setup.ps1 -InstallMlZkmlOnline` trên máy có mạng.

---

## 3. Quy trình giải nén, cài đặt và xác minh từng bước

### Bước 1: Giải nén vào thư mục độc lập bất kỳ
Giải nén `blockchain_ai_forensics_portable_v6.0.0.zip` vào bất kỳ thư mục trống nào (ví dụ `C:\ForensicsPoC\`):
```powershell
Expand-Archive -LiteralPath .\blockchain_ai_forensics_portable_v6.0.0.zip -DestinationPath C:\ForensicsPoC
Set-Location C:\ForensicsPoC
```

### Bước 2: Kiểm tra tính toàn vẹn mật mã (`SHA256SUMS.txt` & Canonical DBs)
Trước khi chạy bất kỳ mã nguồn nào, xác minh toàn bộ tệp giải nén và 3 CSDL chuẩn:
```powershell
powershell -ExecutionPolicy Bypass -File .\verify_integrity.ps1
```
Lệnh phải trả về `INTEGRITY VERIFICATION PASSED (100% SHA-256 CONCORDANCE)` với mã thoát `0`.

### Bước 3: Thiết lập môi trường Offline (`.venv` & `.env`)
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```
- Kịch bản tự động tạo tệp `.env` an toàn (chế độ offline, khóa các mạng công khai, không chứa khóa bí mật) từ `.env.example` nếu chưa tồn tại.
- Tạo môi trường ảo `.venv` và cài đặt offline 101 gói từ `wheels/` (`--no-index --find-links=wheels`).
- Nếu máy đích đã có sẵn môi trường Python cài đủ 113 gói trong `requirements.lock.txt`, có thể dùng `.\setup.ps1 -SkipVenv`.

### Bước 4: Chạy kiểm thử khói cô lập (`smoke_test.ps1`)
```powershell
powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1
```
Kịch bản kiểm tra: (1) `SHA256SUMS.txt` + CSDL chuẩn, (2) CLI `forensics.cli` và `collector.py`, (3) Hợp đồng `Halo2Verifier.sol` + `InferenceVerifier.sol` với phép ghép cặp đường cong elip BN254 thật và 5 kịch bản giả mạo trên Foundry, (4) Bộ kiểm thử Pytest đa thành phần, và (5) Tính bất biến bitwise của CSDL sau khi chạy.

### Bước 5: Chạy toàn bộ bộ kiểm thử và kịch bản thực nghiệm D1 / D2 / D3
```powershell
# Chạy toàn bộ 175 bài kiểm thử Foundry + toàn bộ bộ kiểm thử Pytest:
powershell -ExecutionPolicy Bypass -File .\run_full_tests.ps1

# Chạy kèm 3 kịch bản tích hợp đầu-cuối D1 (EVM), D2 (Host Log ISO 27037), D3 (Adversarial 35 vectors):
powershell -ExecutionPolicy Bypass -File .\run_full_tests.ps1 -IncludeDemos
```

---

## 4. Các lệnh CLI tiêu biểu (Theo tên thành phần chức năng chuẩn hóa)

```powershell
# 1. Blockchain Collector & Evidence Store: Kiểm tra toàn vẹn cục bộ
python -m forensics.cli verify-local --db data/real_p4.db

# 2. Rule Engine: Phân tích bất thường giao dịch cửa sổ tấn công Euler Finance
python -m forensics.cli analyze --db data/real_p4.db --start-block 16817990 --end-block 16818110 --cal-start-block 16816000 --cal-end-block 16817989 --no-persist

# 3. Threat Intelligence & Evaluation: Đánh giá thực nghiệm đa chế độ
python scripts/evaluate.py --mode incident --data data/real_p4.db --incident euler --unit all --output results/evaluation/euler

# 4. ZKML Verifiable Inference: Triển khai & xác minh Halo2 proof thật trên Anvil cục bộ
python scripts/verify_m3_zkml_anvil.py

# 5. Integration & Evaluation: Chạy từng kịch bản D1, D2, D3
python scripts/demo_d1_evm.py
python scripts/demo_d2_host.py
python scripts/demo_d3_adversarial.py
```

---

## 5. Bảo mật vận hành khi sử dụng gói Portable

- Mặc định mọi kết nối ra mạng ngoài và chuỗi công khai bị chặn (`FORENSICS_OFFLINE=1`, `AI_PROVIDER=none`, `ANCHOR_CHAIN_ID=31337`).
- Gói phát hành **không chứa** tệp `.env` gốc, khóa riêng thật, API key hay dữ liệu định danh cá nhân (PII). Các khóa dùng trong kịch bản Anvil (`0xac0974...`, `0x59c699...`, `0x5de411...`) chỉ là khóa thử nghiệm công khai tiêu chuẩn của Foundry Anvil cục bộ, tuyệt đối không dùng trên mạng thật.
