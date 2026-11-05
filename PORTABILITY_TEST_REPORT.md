# BÁO CÁO KIỂM THỬ TÍNH DI ĐỘNG VÀ TÁI LẬP ĐỘC LẬP (`PORTABILITY_TEST_REPORT.md`)

- **Cổng nghiệm thu**: Gate `T25` (`AGENT.md` v6.0 §10, §11, §16.4)
- **Tệp phát hành**: `dist/blockchain_ai_forensics_portable_v6.0.0.zip`
- **Dung lượng ZIP**: 318,232,248 bytes (303.49 MB)
- **Mã băm SHA-256 gói ZIP**: `C8AD1D0E7E3F1CD91A31FCADADCE4FEEBBF4CC21E51001021DE999BF93843163`
- **Tệp băm đi kèm**: `dist/blockchain_ai_forensics_portable_v6.0.0.zip.sha256`
- **Số lượng tệp trong manifest**: 428 tệp (325 tệp dự án + 101 bánh xe `.whl` offline + tài liệu & kịch bản)
- **Thời điểm kiểm thử**: 2026-11-05 (Milestone M6 Final)
- **Thư mục giải nén độc lập**: `%TEMP%\portable_t25_clean_extract` (ngoài cây thư mục `D:\Projest\Blockchain`)

---

## 1. Trạng thái các mục tiêu nghiệm thu Gate T25

| Mục tiêu kiểm chứng | Trạng thái | Ghi chú minh bạch |
|---|:---:|---|
| **T25-A: Kiểm thử giải nén sạch trên máy nguồn (Clean-Extract)** | **PASS** | Thực hiện trên thư mục tạm cô lập, 100% lệnh đạt mã thoát `0` |
| **T25-B: Kiểm thử trên máy tính Windows thứ hai hoàn toàn độc lập** | **NOT_VERIFIED** | Chưa có máy vật lý thứ hai; không đồng nhất thư mục mới với máy khác |
| **Độ nhạy phát hiện can thiệp (1-byte tamper negative check)** | **PASS** | Sửa 1 byte trên `README_SETUP.md` lập tức bị phát hiện (Exit code 1) |
| **Cài đặt môi trường ảo `.venv` hoàn toàn Offline** | **PASS** | Cài 101 bánh xe từ `wheels/` không cần Internet qua `setup.ps1` |
| **Kiểm thử khói 5 giai đoạn (`smoke_test.ps1`)** | **PASS** | 126/126 ca pytest đỗ, 7/7 ca Foundry đỗ, 3/3 CSDL bất biến |

---

## 2. Kết quả thực nghiệm chi tiết từng bước (Clean-Extract Protocol)

### 2.1 Bước 1: Giải nén vào thư mục độc lập
- Lệnh: `Expand-Archive -LiteralPath D:\Projest\Blockchain\dist\blockchain_ai_forensics_portable_v6.0.0.zip -DestinationPath $env:TEMP\portable_t25_clean_extract`
- Kết quả: Giải nén thành công 428 tệp. Không xuất hiện lỗi trích xuất hay xung đột tệp.

### 2.2 Bước 2: Kiểm tra toàn vẹn mật mã dương tính (`verify_integrity.ps1`)
- Lệnh: `powershell -ExecutionPolicy Bypass -File .\verify_integrity.ps1`
- Kết quả:
  - `data/forensics.db`: `3F2B0DFC772A96FF...` — **PASS**
  - `data/benchmark_p6.db`: `C7FF724CD214EEF5...` — **PASS**
  - `data/real_p4.db`: `6BD9AED48AC2742D...` — **PASS**
  - Đối chiếu toàn bộ: **428/428 tệp khớp 100% SHA-256**
  - Mã thoát: `0` (`INTEGRITY VERIFICATION PASSED`)

### 2.3 Bước 3: Thử nghiệm độ nhạy can thiệp âm tính (Negative 1-Byte Tamper Test)
- Thao tác: Đảo bit 1 byte đầu tiên của `README_SETUP.md` trong thư mục giải nén.
- Lệnh: `powershell -ExecutionPolicy Bypass -File .\verify_integrity.ps1`
- Kết quả:
  - Phát hiện sai khác: `[FAIL] MISMATCH: README_SETUP.md (got 0890DA6B..., expected 69F716D6...)`
  - Thông báo: `INTEGRITY VERIFICATION FAILED (1 error(s) across 428 manifest entries)`
  - Mã thoát: `1` (**Chặn thành công — Không cho phép chạy với tệp bị sửa đổi**)
- Khôi phục: Ghi lại nội dung gốc và kiểm tra lại → Mã thoát trở về `0`.

### 2.4 Bước 4: Thiết lập môi trường Offline (`setup.ps1`)
- Lệnh: `powershell -ExecutionPolicy Bypass -File .\setup.ps1`
- Kết quả:
  - Tạo cấu hình `.env` tự động từ `.env.example` (chế độ offline, không chứa khóa bí mật).
  - Xác thực bộ công cụ Foundry đóng gói sẵn (`forge.exe`, `anvil.exe`, `cast.exe`).
  - Nạp cache trình biên dịch Solidity `solc-0.8.24.exe` vào `%APPDATA%\svm\0.8.24\solc-0.8.24`.
  - Tạo môi trường ảo `.venv` biệt lập.
  - Cài đặt thành công **101 gói `.whl` core** từ `wheels/` với cờ `--no-index --find-links=wheels`.
  - Xác thực import cốt lõi: `import forensics, pydantic, pytest, cryptography` thành công.
  - Mã thoát: `0` (`PORTABLE SETUP COMPLETED SUCCESSFULLY`).

### 2.5 Bước 5: Kiểm thử khói đa thành phần (`smoke_test.ps1`)
- Lệnh: `powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1`
- Kết quả 5 giai đoạn:
  1. **Giai đoạn 1 (Integrity check)**: 428/428 tệp và 3 CSDL chuẩn được kiểm tra toàn vẹn.
  2. **Giai đoạn 2 (CLI entrypoints)**: Kiểm tra các điểm vào dòng lệnh phản hồi bình thường.
  3. **Giai đoạn 3 (Foundry Smart Contract & Real Halo2 BN254 Pairing)**:
     - Biên dịch 8 hợp đồng Solidity với `solc 0.8.24` trong 2.78s.
     - Chạy suite `test/Halo2RealVerifier.t.sol`: **7/7 tests PASS, 0 FAIL**:
       - `testRealHalo2DirectPairingPass`: gas 1,200,865
       - `testRealHalo2InferenceVerifierEndToEndPass`: gas 1,935,478
       - 5 ca đột biến (sửa Input Commitment, Instance, Model Hash, Output Commitment, Proof bytes): **100% REVERT** đúng kỳ vọng.
  4. **Giai đoạn 4 (Pytest Multi-Component Smoke Suite)**:
     - Chạy qua các thành phần: Evidence Store, Schemas, Integrity, Real Ingest, Rule Engine, SafetyGuard, ML Model, Local XAI, MITRE Mapping, ZKML Codec & Verifier, DID & Custody.
     - Kết quả: **126 passed in 18.42s** (0 failed, 0 error).
  5. **Giai đoạn 5 (Post-smoke canonical DB invariance)**:
     - Đối chiếu lại SHA-256 của 3 CSDL sau khi chạy smoke test: **3/3 MATCH**.
     - Không có thao tác ghi làm biến dạng dữ liệu chuẩn.
- Mã thoát: `0` (`SMOKE TEST PASSED (EXIT CODE 0)`).

### 2.6 Bước 6: Dọn dẹp thư mục tạm
- Xóa an toàn toàn bộ thư mục tạm `%TEMP%\portable_t25_clean_extract` sau khi hoàn thành kiểm thử.

---

## 3. Trạng thái minh bạch về kiểm thử máy thứ hai (T25-B)

Căn cứ quy tắc trung thực của `AGENT.md` v6.0 §0.4, §10 và §11:
- Gói phát hành `blockchain_ai_forensics_portable_v6.0.0.zip` đã được chứng minh là tự thân (self-contained), không chứa bất kỳ đường dẫn tuyệt đối phụ thuộc máy nguồn nào (`D:\Projest`, `C:\Users\Naly`), đã đóng gói đầy đủ binary Foundry và bánh xe Python offline.
- Tuy nhiên, vì toàn bộ quá trình kiểm thử tự động này diễn ra trên cùng máy tính vật lý của nhà phát triển, trạng thái của hạng mục **chạy trên một máy tính Windows vật lý thứ hai hoàn toàn độc lập** được ghi nhận trung thực là:

$$\text{T25-B (Second Physical Machine)} = \mathbf{NOT\_VERIFIED}$$

Người tiếp nhận hoặc giảng viên có thể mang tệp ZIP và tệp `.sha256` sang bất kỳ máy Windows 10/11 x64 nào khác có cài sẵn Python 3.13 để nghiệm thu theo đúng 3 bước tại [`README_SETUP.md`](README_SETUP.md).
