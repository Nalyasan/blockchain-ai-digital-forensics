# BÁO CÁO TỔNG HỢP CÁC THAY ĐỔI, KHOẢNG TRỐNG CÒN LẠI VÀ GIỚI HẠN HỆ THỐNG (`V6_CHANGES_GAPS_AND_LIMITATIONS.md`)

- **Dự án**: Điều tra số kết hợp Blockchain và AI (*Blockchain + AI Digital Forensics* — Academic PoC, Đề tài 8)
- **Tài liệu đặc tả căn cứ**: `AGENT.md` v6.0 (SHA-256: `DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E`)
- **Nhánh phát triển**: `integration/p7-p10-dev`

---

## 1. Tổng hợp các thay đổi kỹ thuật theo `AGENT.md` v6.0 (Milestones M0–M6)

### 1.1 Thiết lập đặc tả chuẩn & Chuẩn hóa danh xưng / Quy ước code (M0–M1)
- Đưa `AGENT.md` v6.0 lên làm đặc tả chính tại gốc dự án và lưu trữ nguyên trạng bản tiền nhiệm tại `docs/legacy/agent_v5.1.txt` (`A4B883D3...`).
- Chuẩn hóa toàn bộ hệ thống thành **12 thành phần chức năng rõ nghĩa** (`Blockchain Collector`, `Evidence Store`, `Evidence Package`, `Rule Engine`, `AI Investigator`, `Threat Intelligence`, `Endpoint Acquisition`, `ML/XAI`, `ZKML`, `Identity & Custody`, `Integration & Evaluation`, `Portable Release`), lập bảng đối chiếu hai chiều tại `docs/naming_cross_reference.md`.
- Đổi tên đồng bộ các tệp kiểm thử và kịch bản đang duy trì, dọn bỏ các chú thích mô tả lại cú pháp/nhãn giai đoạn, chỉ giữ lại chú thích giải thích ràng buộc an toàn, thiết kế và thuật toán phức tạp.

### 1.2 Hoàn thiện Endpoint Acquisition theo ISO/IEC 27037 & Safety Guards (M4–M5)
- Bổ sung giao diện `EvidenceSourceAdapter` cùng các adapter chạy đầu-cuối cho nguồn EVM (`EVMCollectorAdapter`) và nguồn log máy chủ (`HostLogFileAdapter` cho JSONL/EVTX chuẩn hóa, `OsqueryLiveAdapter` kèm gắn cờ `synthetic=true` trung thực khi chạy fixture).
- Triển khai quy trình 4 bước *Identification → Collection → Acquisition → Preservation*, xuất `acquisition_manifest.json` ghi nhận `consent_scope`, `original_sha256`, `copy_sha256`, mốc thời gian UTC và mã định danh tác viên.
- Gia cố `SafetyGuard` trong `forensics/endpoint/first_responder.py`: chặn 100% lệnh thực thi shell, chuỗi lệnh mã hóa PowerShell, chèn công tắc dòng lệnh (`-Command`, `/c`, `-e`), xóa log, sửa ACL, cô lập mạng và tự động ký giao dịch; ưu tiên phân loại theo động từ lệnh để không nhầm lẫn ngữ nghĩa.

### 1.3 Tái thiết quy trình Machine Learning, Local XAI & MITRE ATT&CK (M2)
- **Triệt tiêu rò rỉ nhãn và thời gian**: Loại bỏ hoàn toàn việc lấy bảng `alerts` của Rule Engine làm ground truth cho ML; sửa lỗi gom địa chỉ xuyên thời gian bằng cách khóa nhãn theo đúng cửa sổ sự cố `[start_block, end_block]` trong `forensics/ml/ground_truth.py`; bộ tiền xử lý (`RobustScaler`) chỉ `fit` trên tập `train`.
- **An toàn đơn vị tài sản & Reorg**: Chuẩn hóa lượng chuyển giao theo `decimals` của từng token (`forensics/ml/features.py`), loại bỏ các khối `orphaned` khi trích xuất đặc trưng; đồng bộ trọng số mô hình `CompactAnomalyMLP` (321 tham số) với đồ thị `models/anomaly_detector_v1.onnx` (`d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff`) và `models/dataset_manifest.json`.
- **XAI định lượng & MITRE có căn cứ**: Bổ sung phép đo trung thực cục bộ (`fidelity_r2`) và độ ổn định nhiễu (`stability_score`) cho `ExactShapleyExplainer`, kèm trạng thái từ chối `NOT_EXPLAINABLE` khi đầu vào suy biến. Bổ sung lược đồ MITRE ATT&CK v14.1 (`tactic_id`, `mapping_rule`, `required_evidence`, `analyst_review_status`) và cơ chế dừng `NOT_MAPPED` (abstain) khi không đủ chứng cứ bắt buộc.

### 1.4 ZKML Verifiable Inference thực (Halo2 / EZKL) & Hợp đồng BN254 Pairing trên Anvil (M3–M5)
- Khởi tạo bộ hiện vật mạch cố định tại `circuits/anomaly_detector_v1/` (`settings.json`, `network.compiled`, `vk.key`, `kzg.srs`, `circuit_meta.json`, `baseline_proof.json`, `Halo2Verifier.abi.json`) khớp trực tiếp với `models/anomaly_detector_v1.onnx`.
- Sinh và tích hợp **hợp đồng xác minh ghép cặp đường cong elip BN254 KZG thật** `contracts/src/Halo2Verifier.sol` (biên dịch với `via_ir = true`, `code_size_limit = 65536`), được gọi bởi `contracts/src/InferenceVerifier.sol`.
- Thực thi ràng buộc mật mã học ngay trên EVM: `InferenceVerifier._computeHalo2InputCommitment(instances)` tái tính SHA-256 trên chuỗi từ 10 đặc trưng đầu vào lượng tử hóa (`scale = 7`), kiểm tra `bytes32(instances[10]) == outputCommitment`, đối chiếu `modelHash`, rồi mới chấp nhận kết quả `Halo2Verifier.verifyProof(proof, instances)` (~`1,135,772`–`1,137,038` gas trên Anvil). Tự động revert 100% trước mọi hành vi sửa proof bytes, sửa tín hiệu công khai (`instances`), tráo model hash hoặc cam kết đầu vào/đầu ra.

### 1.5 Định danh phân tán W3C DID & Chuỗi hành trình chứng cứ 2 tác viên (M4)
- Hoàn thiện đối chiếu `DID ↔ public key ↔ Ethereum signer ↔ RBAC role`, chữ ký có cấu trúc EIP-712 chống phát lại (`monotonic nonce` + `deadline`), và kịch bản chuyển giao 2 tác viên (`Alice Collector` → `Bob Analyst`) trên `EvidenceRegistryDID.sol` có kiểm chứng biên nhận giao dịch Anvil và đối chiếu khớp mã băm đầu-cuối, giữ nguyên tính tương thích ngược với `EvidenceRegistry.sol` và nhánh đọc lại chứng cứ đã neo (`forensics/rules/anchored.py`).
- Bổ sung kiểm tra ngữ nghĩa lược đồ `1.0.0` (`block_range`, `counts`, `gaps`) trong `forensics/integrity.py`.

### 1.6 Tích hợp thực nghiệm D1 / D2 / D3, Dọn dẹp an toàn & Đóng gói Portable (M5–M6)
- Xây dựng và chạy thực tế 3 kịch bản đầu-cuối: `scripts/demo_d1_evm.py` (8 pha gồm cả vòng lặp đọc lại chứng cứ đã neo), `scripts/demo_d2_host.py` (6 pha theo ISO/IEC 27037), `scripts/demo_d3_adversarial.py` (chặn đóng kín `35/35` vector tấn công qua 6 cổng), cùng bộ tổng hợp báo cáo truy vết `forensics/evaluation/report_generator.py` (`reports/DEMO_EVALUATION_REPORT.md`).
- Thực hiện dọn dẹp an toàn có kiểm chứng mã băm và lập `cleanup_manifest.json` (thu hồi ~784.76 MB tệp rác/cache, xóa vĩnh viễn `osint-attack-surface/` theo ủy quyền, sao lưu ngoài repo các tệp nháp độc lập).
- Gỡ bỏ toàn bộ đường dẫn cứng phụ thuộc máy nguồn (`D:\Projest`, `C:\Users\Naly`), đóng gói `solc-0.8.24.exe` cùng Foundry binaries và 101 bánh xe Python vào `dist/blockchain_ai_forensics_portable_v6.0.0.zip`, tạo bộ 4 kịch bản PowerShell và 3 tài liệu bắt buộc của thành phần **Portable Release**, và thực thi kiểm thử giải nén cô lập ngoài thư mục dự án.

---

## 2. Các khoảng trống còn lại và trạng thái chưa xác minh (Honest Remaining Gaps)

Tuân thủ nguyên tắc trung thực tuyệt đối của `AGENT.md` v6.0 (§0.4, §10, §11):

1. **Kiểm thử vật lý trên máy tính Windows thứ hai độc lập (`NOT_VERIFIED` trong Gate `T25`)**:
   - Đã hoàn thành kiểm thử giải nén sạch vào thư mục cô lập bên ngoài dự án (`%TEMP%\portable_t25_clean_extract`), xác minh `SHA256SUMS.txt` (cả ca dương tính lẫn ca âm tính sửa 1 byte), tạo `.venv` offline từ 101 bánh xe và chạy `smoke_test.ps1` đạt mã thoát `0`.
   - Tuy nhiên, toàn bộ quá trình này diễn ra trong một phiên làm việc trên cùng máy vật lý nguồn. Theo đúng quy tắc của `AGENT.md` v6.0 §10, hạng mục **chạy thực nghiệm trên một máy tính Windows vật lý thứ hai hoàn toàn tách biệt** được ghi nhận trung thực là **`NOT_VERIFIED`** cho đến khi người phụ trách sao chép tệp ZIP sang máy thứ hai để chạy kiểm chứng.
2. **Phạm vi Wheelhouse Offline đối với 12 gói mở rộng ML/ZKML**:
   - Thư mục `wheels/` đóng gói sẵn **101 gói `.whl` offline** của `requirements.txt` — đủ để chạy offline 100% toàn bộ hệ thống cốt lõi (Collector, Evidence Store/Package, Rule Engine, AI Investigator chế độ offline, Threat Intelligence, Endpoint Acquisition, suy luận ML thuần Python + SHAP XAI + MITRE, DID/Custody và kiểm thử hợp đồng `Halo2Verifier.sol` trên Foundry).
   - 12 gói mở rộng phục vụ huấn luyện lại PyTorch/ONNX hoặc gọi trình sinh bằng chứng Python `ezkl==23.0.5` trực tiếp trong một `.venv` trắng đã được khóa phiên bản chính xác tại `requirements-ml-zkml.lock.txt`, nhưng tệp `.whl` nhị phân của chúng chưa có sẵn trong kho bánh xe cục bộ (hệ thống không tự ý tải mạng khi chưa có lệnh cho phép).
3. **Giới hạn kiến trúc ZKML đối với kịch bản Host Log Demo D2**:
   - Mạch Halo2 hiện tại (`circuits/anomaly_detector_v1/`) được biên dịch chuyên biệt cho mô hình `CompactAnomalyMLP` 10 đặc trưng dòng tiền EVM (dùng trong Demo D1 và D3). Trong Demo D2 (nhật ký máy chủ ISO/IEC 27037), hệ thống ghi nhận trung thực trạng thái `ARCHITECTURAL_LIMITATION / NOT_APPLICABLE (No Mocks)` thay vì dùng bằng chứng giả lập, đúng theo `AGENT.md` v6.0 §9.1.
4. **Phần mở rộng nghiên cứu Deep Learning / GNN (`OPTIONAL_RESEARCH`)**:
   - Hệ thống triển khai đầy đủ mô hình học máy thực `CompactAnomalyMLP` kèm đối chuẩn thống kê; nhánh GNN/Deep Learning quy mô lớn nêu trong gợi ý mở rộng của tài liệu định hướng được giữ ở trạng thái `OPTIONAL_RESEARCH` theo `AGENT.md` v6.0 §6.1.
5. **70 ca kiểm thử bị bỏ qua (`SKIPPED`) kế thừa từ Baseline P1–P6**:
   - Bộ kiểm thử toàn cục giữ nguyên các bài kiểm thử được đánh dấu `skip` có chủ đích theo chính sách an toàn của baseline (ví dụ các bài yêu cầu khóa API Gemini thật, kết nối RPC Sepolia trực tiếp hoặc tập dữ liệu thô nằm ngoài repo). Không có bất kỳ `SKIP` nhân tạo nào được thêm mới để che giấu lỗi.

---

## 3. Giới hạn khoa học, thống kê và pháp chứng (Methodological & Forensic Limitations)

1. **Cỡ mẫu Ground Truth độc lập trong đánh giá ML**:
   - Do không được phép dùng cảnh báo từ Rule Engine làm nhãn chuẩn giả tạo và không coi `0 blacklist match = benign` (Giả định Thế giới Mở — OWA), tập nhãn sự cố hậu kiểm độc lập trên dữ liệu Mainnet cục bộ có số lượng cửa sổ dương tính hữu hạn (12 cửa sổ quanh hai vụ tấn công Euler và Curve). Các chỉ số thực nghiệm (`ROC-AUC`, `PR-AUC`, phân phối điểm bất thường) phải được diễn giải như kết quả minh chứng quy trình chống rò rỉ dữ liệu ở quy mô PoC, không phải tuyên bố khả năng khái quát hóa trên toàn bộ mạng Ethereum.
2. **Ranh giới giữa bảo toàn dữ liệu, giải thích XAI và kiểm chứng ZKML**:
   - **Evidence Package & Smart Contract Custody** chỉ chứng minh dữ liệu không bị sửa đổi *kể từ thời điểm thu thập và đóng gói*, không tự động chứng minh thiết bị nguồn không bị can thiệp trước khi thu thập.
   - **SHAP XAI** phản ánh đóng góp toán học cục bộ của các đặc trưng đối với đầu ra mô hình `CompactAnomalyMLP`, không đồng nghĩa với chứng minh nhân quả pháp lý của hành vi tấn công.
   - **ZKML Proof (Halo2 KZG)** chứng minh phép suy luận tuân thủ chính xác mạch số học và cam kết đầu vào/đầu ra đã niêm phong, không chứng minh mô hình không có sai số dự báo.
3. **Quyền riêng tư, dữ liệu nghiên cứu có điều kiện và phạm vi pháp lý**:
   - Tập dữ liệu PTXPhish trong `data/benchmark_p6.db` là hiện vật nghiên cứu học thuật có điều kiện, tuyệt đối không dùng cho mục đích thương mại hoặc tải lên đám mây trả phí.
   - Hệ thống không lưu PII hay nhật ký thô lên chuỗi khối, nhưng mã băm và địa chỉ ví vẫn là dữ liệu giả danh có khả năng liên kết; sản phẩm là PoC học thuật, không thay thế quy trình giám định tư pháp được cấp phép.
