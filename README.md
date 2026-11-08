# Blockchain Ai Aigital Forensics

**Blockchain Ai Aigital Forensics** là nền tảng điều tra số chuyên sâu kết hợp phân tích dữ liệu Blockchain, Học máy giải thích được (Explainable AI / SHAP), Trí tuệ nhân tạo đa mô hình (Multi-Model AI), Chứng minh suy luận không tiết lộ thông tin (ZKML Halo2 KZG) và Chuỗi hành trình chứng cứ bất biến trên Smart Contract (W3C DID & EIP-712).

Hệ thống cung cấp ứng dụng Web Dashboard trực quan trên nền **FastAPI + Uvicorn** cùng công cụ dòng lệnh (CLI), hỗ trợ điều tra độc lập theo từng vụ việc (`Case ID`) và phiên phân tích (`Run ID`), tự động xuất báo cáo phân tích chuyên môn độc lập (`investigation_report.html`).

---

## 1. Kiến Trúc & Tính Năng Cốt Lõi

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ 1. TIẾP NHẬN & THU THẬP CHỨNG CỨ SỐ (ISO/IEC 27037)                           │
│   - Nhập tệp chứng cứ: JSON/JSONL, CSV, SQLite DB, Host Logs (Merkle RFC 6962)│
│   - Điều tra trực tiếp qua RPC: Chỉ đọc, Anti-SSRF, kiểm soát dải Block/Tx    │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
┌───────────────────────────────────────▼───────────────────────────────────────┐
│ 2. PHÁT HIỆN BẤT THƯỜNG HAI TẦNG (DUAL-ENGINE ANOMALY DETECTION)              │
│   - Rule Engine: Phát hiện chuyển khoản lớn, tần suất cao, gom/phát tán vốn   │
│   - Machine Learning: CompactAnomalyMLP (ONNX) + Giải thích Exact Shapley XAI │
│   - Hợp nhất xác suất: Noisy-OR & đối chiếu chiến thuật MITRE ATT&CK          │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
┌───────────────────────────────────────▼───────────────────────────────────────┐
│ 3. PHÂN TÍCH AI ĐA MÔ HÌNH & ĐỐI CHIẾU DỮ KIỆN (REFCHECKER)                   │
│   - Hỗ trợ: Ollama Local (mặc định), OpenAI, Anthropic Claude, Gemini, Custom │
│   - Bảo vệ Air-Gap: Không tự động gửi dữ liệu nhạy cảm ra đám mây             │
│   - RefChecker: Kiểm chứng chéo từng nhận định AI với chứng cứ gốc (SHA-256)  │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
┌───────────────────────────────────────▼───────────────────────────────────────┐
│ 4. BẢO QUẢN CHỨNG CỨ & XÁC MINH SUY LUẬN MẬT MÃ HỌC ON-CHAIN                  │
│   - Chain of Custody: Hợp đồng thông minh EvidenceRegistryDID (W3C DID/EIP-712)│
│   - ZKML Verifier: Xác minh bằng chứng suy luận Halo2 BN254 KZG trên EVM      │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
┌───────────────────────────────────────▼───────────────────────────────────────┐
│ 5. GIAO DIỆN ĐIỀU TRA WEB DASHBOARD & BÁO CÁO ĐỘC LẬP                         │
│   - Quản lý đa vụ việc (Case ID / Run ID cách ly dữ liệu hoàn toàn)           │
│   - Theo dõi tiến độ thực tế 8 giai đoạn & giám sát tác vụ AI thời gian thực  │
│   - Xuất báo cáo độc lập ngoại tuyến: investigation_report.html (hỗ trợ PDF)  │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Các năng lực chính:
- **Quản lý vụ việc cách ly hoàn toàn:** Mỗi vụ việc (`Case ID`) hỗ trợ nhiều phiên điều tra (`Run ID`) độc lập. Toàn bộ chứng cứ, cảnh báo, kết quả AI/ML, biên nhận lưu giữ và báo cáo được cách ly theo từng phiên.
- **Hai luồng thu thập chứng cứ thực tế:**
  1. **Nhập tệp chứng cứ:** Hỗ trợ giao dịch JSON/JSONL, CSV, cơ sở dữ liệu SQLite tương thích và nhật ký máy chủ (Host logs). Tự động kiểm tra định dạng, tính mã băm SHA-256, đóng gói cây Merkle RFC 6962 và chống leo thang thư mục (Path Traversal / Symlink Escape).
  2. **Điều tra trực tiếp qua Blockchain RPC:** Kết nối RPC ở chế độ chỉ đọc (`eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`) với bộ lọc **Anti-SSRF** đa tầng (chặn IP nội bộ, loopback không cấp phép, cloud metadata, DNS rebinding và HTTP redirect).
- **Phát hiện bất thường & Giải thích mô hình (ML & XAI):** Kiểm tra tính tương thích đặc trưng (Feature Schema Pre-check) trước khi suy luận bằng mô hình `CompactAnomalyMLP`, tính toán đóng góp đặc trưng bằng **Exact Shapley Values (SHAP)** và hợp nhất với tập quy tắc tĩnh qua công thức **Noisy-OR**.
- **Phân tích AI có căn cứ (Grounded Multi-Model AI):** Mặc định ưu tiên mô hình cục bộ qua **Ollama**; hỗ trợ cấu hình OpenAI, Anthropic Claude, Google Gemini và Custom Provider. Mọi nhận định đều được đối chiếu tự động qua **RefChecker** gắn với `Evidence ID`, `Transaction Hash` và `Block Number`.
- **Xác minh suy luận ZKML & Bảo quản chứng cứ (Chain of Custody):** Hợp đồng thông minh Solidity `InferenceVerifier.sol`, `Halo2Verifier.sol` và `EvidenceRegistryDID.sol` chống phát lại bằng chứng (`ProofAlreadyVerified`), chống ghi đè hồ sơ (`RecordAlreadyExists`) và xác thực chữ ký chuyển giao quyền lưu giữ theo chuẩn **EIP-712**.
- **Báo cáo phân tích Blockchain độc lập (`investigation_report.html`):** Tự động tổng hợp báo cáo HTML tiếng Việt hoàn chỉnh, hoạt động ngoại tuyến 100% (không phụ thuộc CDN ngoài), hỗ trợ in/lưu PDF trực tiếp từ trình duyệt và trả lời đầy đủ 8 câu hỏi nghiệp vụ điều tra cho từng phát hiện.

---

## 2. Cấu Trúc Thư Mục Cốt Lõi

```text
├── contracts/                  # Hợp đồng thông minh Solidity (Foundry)
│   ├── src/
│   │   ├── EvidenceRegistry.sol
│   │   ├── EvidenceRegistryDID.sol
│   │   ├── Halo2Verifier.sol
│   │   ├── InferenceVerifier.sol
│   │   └── interfaces/
│   └── test/                   # Bộ kiểm thử hợp đồng thông minh & bảo mật
├── dashboard/                  # Ứng dụng Web FastAPI Dashboard
│   ├── app.py                  # Khởi tạo FastAPI application
│   ├── schemas.py              # Pydantic validation schemas
│   ├── routes/                 # Các tuyến API REST & giao diện HTML
│   ├── services/               # JobManager quản lý tiến trình 8 giai đoạn & báo cáo
│   ├── static/                 # Tài nguyên tĩnh (CSS, JavaScript)
│   └── templates/              # Giao diện người dùng Jinja2
├── forensics/                  # Lõi xử lý nghiệp vụ điều tra số (Forensic Core)
│   ├── ai/                     # Multi-Model AI Provider Adapter, Tools & RefChecker
│   ├── collector/              # Thu thập dữ liệu Blockchain EVM
│   ├── did/                    # Quản lý định danh W3C DID & chữ ký EIP-712
│   ├── endpoint/               # Phân tích nhật ký máy chủ & đóng gói chứng cứ
│   ├── evidences/              # Quản lý kho chứng cứ & kiểm tra toàn vẹn SHA-256
│   ├── ingestion/              # Bộ nạp và chuẩn hóa tệp chứng cứ (JSON/CSV/SQLite/Log)
│   ├── ml/                     # Mô hình CompactAnomalyMLP & giải thích SHAP XAI
│   ├── report/                 # Bộ tổng hợp dữ liệu báo cáo điều tra
│   ├── rules/                  # Động cơ quy tắc phát hiện bất thường dòng tiền
│   ├── threat_intel/           # Đối chiếu tình báo mối đe dọa & MITRE ATT&CK
│   ├── zkml/                   # Tạo và xác minh bằng chứng Halo2 KZG
│   ├── live_collector.py       # Bộ thu thập dữ liệu RPC trực tiếp có giới hạn
│   ├── paths.py                # Quản lý và phân giải đường dẫn đa nền tảng
│   ├── rpc_guard.py            # Rào chắn bảo mật Anti-SSRF cho kết nối RPC
│   └── service.py              # Lớp điều phối dịch vụ điều tra trung tâm
├── models/                     # Trọng số mô hình ONNX & cấu hình đặc trưng
├── circuits/                   # Mạch biên dịch ZKML Halo2 & khóa xác minh (vk.key)
├── scripts/
│   └── run_dashboard.py        # Script khởi chạy máy chủ Web Dashboard (Uvicorn)
├── tests/                      # Bộ kiểm thử đơn vị, tích hợp & bảo mật (Pytest)
├── investigate_case.py         # Giao diện điều tra dòng lệnh (CLI)
└── requirements.txt            # Danh sách thư viện Python phụ thuộc
```

---

## 3. Yêu Cầu Hệ Thống & Cài Đặt

### 3.1. Yêu cầu tiên quyết
- **Hệ điều hành:** Windows 10/11 hoặc Linux (Kali Linux / Ubuntu / Debian).
- **Python:** Phiên bản 3.11, 3.12 hoặc 3.13 (64-bit).
- **Foundry (`forge`, `anvil`, `cast`):** Phục vụ biên dịch, kiểm thử Smart Contract và chạy mạng EVM cục bộ khi cần ghi nhận Chain of Custody.
- **Ollama (Tùy chọn khuyến nghị):** Chạy mô hình ngôn ngữ lớn cục bộ tại `http://127.0.0.1:11434`.

### 3.2. Cài đặt môi trường Python

**Trên Windows (PowerShell / CMD):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install fastapi jinja2 uvicorn filelock python-multipart
```

**Trên Linux (Kali / Ubuntu):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install fastapi jinja2 uvicorn filelock python-multipart
```

### 3.3. Cấu hình biến môi trường (Tùy chọn)
Hệ thống tự động nhận diện thư mục gốc của dự án thông qua `forensics/paths.py`. Bạn có thể tùy chỉnh qua biến môi trường hoặc tệp `.env`:

```ini
DATABASE_PATH=data/forensics.db
MODEL_PATH=models/anomaly_detector_v1.onnx
OUTPUT_DIR=reports/investigations
RPC_URL=http://127.0.0.1:8545
OLLAMA_URL=http://127.0.0.1:11434/v1
HOST=127.0.0.1
PORT=8000
```

---

## 4. Hướng Dẫn Sử Dụng

### 4.1. Khởi chạy Giao diện Web Dashboard
Chạy lệnh sau từ thư mục gốc của dự án (hoặc từ bất kỳ thư mục làm việc nào):

```bash
python scripts/run_dashboard.py --host 127.0.0.1 --port 8000
```

Truy cập ứng dụng trên trình duyệt tại: **`http://127.0.0.1:8000`**

#### Các chức năng chính trên Dashboard:
1. **Tổng quan (`/`):** Bảng điều khiển 4 khu vực gồm: khởi tạo điều tra mới, theo dõi phiên đang xử lý, danh sách hồ sơ gần đây và giám sát trạng thái thực tế của các dịch vụ (Cơ sở dữ liệu, AI Provider, Blockchain RPC, Mô hình ML, Dịch vụ báo cáo).
2. **Khởi chạy điều tra (`/launcher`):**
   - **Tạo vụ điều tra mới:** Nhập `Case ID` riêng biệt, tên vụ việc và phạm vi điều tra.
   - **Nhập tệp chứng cứ:** Tải lên tệp JSON, JSONL, CSV, SQLite DB hoặc Host log để kiểm tra SHA-256, chuẩn hóa và phân tích tự động.
   - **Điều tra trực tiếp:** Kết nối nguồn Blockchain RPC được cấp phép ở chế độ chỉ đọc, kiểm tra Chain ID và thu thập dữ liệu theo địa chỉ ví, hợp đồng thông minh, mã giao dịch hoặc khoảng khối (Block Range).
3. **Tiến độ (`/progress`):** Theo dõi trực tiếp 8 giai đoạn xử lý nghiệp vụ:
   - *(1) Tiếp nhận dữ liệu $\rightarrow$ (2) Kiểm tra tính toàn vẹn $\rightarrow$ (3) Trích xuất và chuẩn hóa chứng cứ $\rightarrow$ (4) Phát hiện dấu hiệu bất thường $\rightarrow$ (5) Phân tích AI và giải thích kết quả $\rightarrow$ (6) Đối chiếu dữ kiện $\rightarrow$ (7) Xác minh và bảo quản chứng cứ $\rightarrow$ (8) Tổng hợp báo cáo điều tra.*
4. **Chứng cứ (`/evidence`):** Tra cứu danh mục chứng cứ của vụ việc, đối chiếu mã băm SHA-256, nguồn thu thập và xuất tệp manifest.
5. **Phân tích AI (`/ai`):** Quan sát nhà cung cấp AI, model thực tế, nhiệm vụ AI đang thực thi và bảng kết quả đối chiếu trích dẫn chứng cứ (`RefChecker`).
6. **Phân tích bất thường (`/ml-xai`):** Xem danh sách cảnh báo từ Rule Engine, điểm số bất thường từ `CompactAnomalyMLP` và mức đóng góp của từng đặc trưng (SHAP).
7. **Bảo quản chứng cứ (`/blockchain`):** Kiểm tra lịch sử lưu giữ chứng cứ (Chain of Custody), định danh DID và biên nhận giao dịch.
8. **Xác minh suy luận (`/zkml`):** Kiểm tra cam kết mô hình, đầu vào/đầu ra và trạng thái xác minh bằng chứng Halo2 KZG.
9. **Báo cáo điều tra (`/reports`):** Xem trực tiếp, tải xuống hoặc in PDF báo cáo tổng hợp `investigation_report.html` của từng phiên điều tra.
10. **Cài đặt (`/settings`):** Thiết lập nhà cung cấp AI, kiểm tra kết nối RPC và cấu hình thư mục xuất báo cáo.

---

### 4.2. Điều tra qua Giao diện Dòng lệnh (CLI)

Chạy phân tích ở chế độ chỉ đọc mặc định (an toàn, không phát sinh giao dịch on-chain):
```bash
python investigate_case.py --db data/real_p4.db
```

Chạy phân tích kèm ghi nhận Chain of Custody lên mạng EVM cục bộ (yêu cầu khởi chạy `anvil` tại cổng `8545`):
```bash
python investigate_case.py --db data/real_p4.db --enable-onchain-write
```

Sau khi hoàn tất, hồ sơ kết quả của phiên điều tra được lưu độc lập tại thư mục:
`reports/investigations/<run_id>/`
- `investigation_report.html`: Báo cáo phân tích Blockchain tổng hợp hoàn chỉnh (mở trực tiếp trên trình duyệt, hoạt động ngoại tuyến, hỗ trợ in PDF).
- `report.json`: Dữ liệu kết quả cấu trúc JSON.
- `evidence_manifest.json`: Biên bản mã băm SHA-256 và nguồn gốc chứng cứ.
- `custody_receipts.json`: Biên nhận giao dịch lưu giữ chứng cứ.
- `execution_log.txt`: Nhật ký thực thi kỹ thuật.

---

## 5. Kiểm Thử Hệ Thống

### 5.1. Kiểm thử Python (Pytest)
```bash
# Chạy toàn bộ bộ kiểm thử đơn vị, tích hợp và bảo mật
python -m pytest

# Kiểm thử riêng ứng dụng Web Dashboard & API
python -m pytest tests/test_dashboard_api.py -v

# Kiểm thử luồng nạp tệp chứng cứ và điều tra RPC an toàn
python -m pytest tests/test_evidence_ingestion.py tests/test_safe_rpc_investigation.py -v
```

### 5.2. Kiểm thử Smart Contract (Foundry)
```bash
forge test --root contracts -vv
```

---

## 6. Nguyên Tắc Bảo Mật & Toàn Vẹn Chứng Cứ

- **Bảo toàn chứng cứ gốc:** Mọi tệp chứng cứ và cơ sở dữ liệu đầu vào chỉ được truy cập ở chế độ chỉ đọc (`mode=ro`) hoặc sao chụp có kiểm chứng mã băm SHA-256.
- **Chống tấn công SSRF & Path Traversal:** Toàn bộ đường dẫn tệp và URL RPC được kiểm tra nghiêm ngặt qua danh sách cho phép và bộ chuẩn hóa đường dẫn trước khi truy cập.
- **Bảo mật dữ liệu AI (Air-Gap Mặc định):** Mặc định sử dụng mô hình cục bộ (Ollama); tuyệt đối không tự động gửi chứng cứ hoặc dữ liệu nhạy cảm ra dịch vụ đám mây nếu người dùng chưa cấu hình khóa API và cấp quyền cho phiên làm việc.
- **Chống XSS trong Báo cáo:** Tất cả dữ liệu động từ giao dịch Blockchain, tệp tải lên và phản hồi của mô hình AI đều được làm sạch (`html.escape`) trước khi kết xuất vào `investigation_report.html`.

---

## 7. Giấy Phép

Dự án được phát hành theo giấy phép **MIT License**.
