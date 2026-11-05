# BẢNG ĐỐI CHIẾU DANH XƯNG THÀNH PHẦN VÀ TRUY VẾT KIẾN TRÚC
# STANDARDIZED COMPONENT NAMING & ARCHITECTURAL TRACEABILITY CROSS-REFERENCE

- **Mã tài liệu / Document ID**: `NAMING_CROSS_REFERENCE`
- **Phiên bản / Version**: 6.0.0 (AGENT.md v6.0 Final Verified)
- **Dự án / Project**: Blockchain + AI Digital Forensics System (Academic PoC — Đề tài 8)
- **Tài liệu đặc tả căn cứ / Authoritative Specification**: `AGENT.md` v6.0 (`DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E`)
- **Yêu cầu triển khai / Implementation Requirement**: Requirement R4 (Standardized Functional Naming)
- **Trạng thái / Status**: ACTIVE & MAINTAINED

---

## 1. MỤC ĐÍCH VÀ NGUYÊN TẮC CHUẨN HÓA

Nhằm đáp ứng yêu cầu của giảng viên hướng dẫn Đề tài 8 và chỉ thị kỹ thuật tại **Requirement R4**, hệ thống loại bỏ triệt để cách đặt tên tuần tự theo nhãn giai đoạn lịch sử (P1 đến P12) trong toàn bộ các tài liệu đang duy trì, giao diện dòng lệnh (CLI), sơ đồ kiến trúc và mã nguồn hoạt động.

Toàn bộ hệ thống được quy hoạch và chuẩn hóa thành **12 thành phần chức năng rõ nghĩa (Functional Components C01–C12)**. 

### Nguyên tắc bảo tồn bất biến:
1. **Không sửa đổi tài liệu lịch sử**: Các tài liệu gốc (`AGENT.md v6.0`, `docs/legacy/agent_v5.1.txt`), lịch sử Git, commit log, tệp manifest đã đóng dấu mã băm, và các báo cáo nghiệm thu lịch sử trong thư mục `reports/` được bảo vệ nguyên trạng để bảo đảm tính toàn vẹn của chuỗi bằng chứng kỹ thuật.
2. **Tính tương thích hai chiều**: Mọi thành phần chức năng mới đều giữ sự liên kết chặt chẽ với các tiêu chí nghiệm thu T01–T25 và các module kế thừa đã được kiểm thử hồi quy đạt 100%.

---

## 2. BẢNG ĐỐI CHIẾU TỔNG THỂ 12 THÀNH PHẦN CHỨC NĂNG

Bảng dưới đây thiết lập mối liên kết toàn diện giữa Mã định danh chuẩn hóa, Tên thành phần chức năng, Nhãn kế thừa lịch sử, Mục tương ứng trong đặc tả `AGENT.md v6.0`, Mô tả chức năng, Module mã nguồn thực tế, Bộ kiểm thử và Sản phẩm bàn giao (Deliverables):

| Mã | Tên thành phần chức năng | Nhãn kế thừa | Mục đặc tả AGENT.md v6.0 | Mô tả chức năng & Trách nhiệm kiến trúc | Module mã nguồn chính | Bộ kiểm thử chính | Sản phẩm bàn giao & Artifacts | Trạng thái |
|:---:|---|:---:|:---:|---|---|---|---|:---:|
| **C01** | **Blockchain Collector** | P1 | §4 P1, §11 T01–T03, §13 | Thu thập khối, giao dịch, biên nhận và logs EVM (ETH/ERC-20); cơ chế chịu lỗi RPC exponential backoff & failover; xử lý reorg 12 khối với con trỏ checkpoint nguyên tử; bảo toàn mã băm SHA-256 dữ liệu thô. | `collector.py`<br>`mock_rpc.py`<br>`forensics/paths.py` | `tests/test_collector_erc20.py`<br>`tests/test_receipt_patch.py`<br>`scripts/run_p1_anvil_test.py`<br>`scripts/test_continuous_anvil.py` | Bảng `blocks`, `transactions`, `receipts`, `logs`, `asset_transfers`<br>Tệp `raw_blocks.jsonl` | **HOÀN THÀNH** |
| **C02** | **Evidence Store** | P2 (Storage) | §4 P2, §11 T04–T05, §13 | Lưu trữ chứng cứ số bất biến trên cơ sở dữ liệu SQLite; quản lý lược đồ dữ liệu chuẩn hóa; theo dõi nguồn gốc dữ liệu (provenance); nhật ký kiểm toán `audit_events` và xác thực tính toàn vẹn đa tầng. | `forensics/schemas.py`<br>`forensics/persistence.py`<br>`forensics/provenance.py`<br>`forensics/real_data_ingest.py` | `tests/test_integrity_2a.py`<br>`tests/test_provenance_2a.py`<br>`tests/test_persistence_conflicts.py`<br>`tests/test_real_data_ingest.py`<br>`tests/test_output_preservation.py` | `data/forensics.db` (CANONICAL)<br>`data/real_p4.db` (CANONICAL)<br>`data/endpoint_evidence.db` | **HOÀN THÀNH** |
| **C03** | **Evidence Package** | P2 (Package) | §4 P2, §11 T04, §13 | Đóng gói chứng cứ theo cấu trúc cây Merkle (RFC 6962); tạo định danh URI chuẩn hóa `evidence://sha256/<case_hash>/<manifest_hash>/manifest.json`; xuất manifest và niêm phong mật mã học tệp bằng chứng. | `forensics/evidence.py`<br>`forensics/evidence_identity.py`<br>`forensics/exporter.py`<br>`forensics/integrity.py`<br>`scripts/evidence_output.py` | `tests/test_evidence_p2.py`<br>`tests/test_evidence_identity.py`<br>`tests/test_p4_anchored_package.py`<br>`tests/test_group2a_smoke.py`<br>`tests/test_group2b_smoke.py` | `manifest.json`<br>`timeline.csv`<br>`asset_transfers.csv`<br>`raw_blocks.jsonl` | **HOÀN THÀNH** |
| **C04** | **Rule Engine** | P4 | §4 P4, §11 T04, §13 | Phát hiện bất thường mang tính tất định dựa trên tập luật phân tích chuyển giao tài sản Mainnet: R1 (Chuyển tiền lớn P99), R2 (Tần suất cao), R3 (Gom/tán quỹ Fan-In/Out), R4 (Luân chuyển siêu tốc Rapid Pass-Through); xử lý an toàn số thập phân token; sinh cảnh báo kèm `evidence_refs`. | `forensics/rules/__init__.py`<br>`forensics/rules/base.py`<br>`forensics/rules/engine.py`<br>`forensics/rules/anchored.py`<br>`forensics/rules/large_transfer.py`<br>`forensics/rules/high_frequency.py`<br>`forensics/rules/fan_in_out.py`<br>`forensics/rules/rapid_pass_through.py` | `tests/test_rules.py`<br>`tests/test_real_data_rules.py`<br>`tests/test_p3_p4_flow.py`<br>`tests/p4_fixtures.py`<br>`scripts/run_p4_smoke.py`<br>`scripts/run_real_rules.py` | Bảng `alerts` trong `forensics.db`<br>Bản ghi cảnh báo với SHA-256 `alert_id` và `evidence_refs` bất biến | **HOÀN THÀNH** |
| **C05** | **AI Investigator** | P5 | §4 P5, §11 T09–T11, §13 | Tác nhân điều tra AI Pydantic hoạt động trong khuôn khổ an toàn: cách ly CSDL 5 tầng (`mode=ro`), bộ lọc 38 mẫu phòng vệ prompt injection, ngân sách tối đa 5 bước công cụ, bộ thẩm định trích dẫn 2 pha Ref Checker phân biệt `ObservedFact` và `ExternalThreatLabel`. | `forensics/ai/__init__.py`<br>`forensics/ai/investigator.py`<br>`forensics/ai/sanitizer.py`<br>`forensics/ai/ref_checker.py`<br>`forensics/ai/tools.py`<br>`forensics/ai/db_readonly.py`<br>`forensics/ai/provider.py`<br>`forensics/ai/schemas.py` | `tests/test_ai_investigator.py`<br>`tests/test_ai_security.py`<br>`tests/test_ai_db_readonly.py`<br>`tests/test_ai_db_readonly_adversarial.py`<br>`tests/test_ai_tools.py`<br>`tests/test_ai_tools_adversarial.py`<br>`tests/test_ai_provider.py`<br>`tests/test_ai_threat_intel.py`<br>`tests/test_p5_real_incidents.py` | Hồ sơ điều tra có trích dẫn nguồn xác thực<br>Nhật ký truy vấn đã khử khuẩn | **HOÀN THÀNH** |
| **C06** | **Threat Intelligence** | P6 | §4 P6, §11 T08, §13 | Thu thập và nạp dữ liệu tình báo mối đe dọa nguồn mở (Forta, PTXPhish, MEW); phòng chống tiêm mã công thức CSV; cơ chế sàng lọc theo Giả định Thế giới Mở (OWA); động cơ đánh giá thực nghiệm đa đơn vị. | `forensics/adapters/__init__.py`<br>`forensics/adapters/base.py`<br>`forensics/adapters/screening.py`<br>`forensics/adapters/benchmark_runner.py`<br>`forensics/adapters/csv_adapter.py`<br>`forensics/adapters/json_adapter.py`<br>`forensics/adapters/xlsx_adapter.py`<br>`forensics/adapters/persistence_benchmark.py`<br>`scripts/fetch_labels.py`<br>`scripts/generate_benchmark.py` | `tests/test_p6_adapters.py`<br>`tests/test_p6_screening.py`<br>`tests/test_adversarial_adapters.py`<br>`tests/test_adversarial_p6_screening.py`<br>`tests/test_challenger1_adversarial.py` | `data/benchmark_p6.db` (CANONICAL: 34.841 bản ghi)<br>Ma trận sàng lọc và đánh giá CTI | **HOÀN THÀNH** |
| **C07** | **Endpoint Acquisition** | P7 | §5 P7, §11 T12–T13, §13 | Thu thập chứng cứ số máy chủ đa nguồn theo chuẩn ISO/IEC 27037 (Nhận diện -> Thu thập -> Sao chép -> Bảo quản); adapter kết nối daemon osquery/WMI và log tĩnh (JSONL/EVTX); tạo `acquisition_manifest.json` ghi nhận `consent_scope`, `original_sha256`/`copy_sha256`, timestamp UTC; AI First Responder tuân thủ 5 điều cấm an toàn. | `forensics/endpoint/__init__.py`<br>`forensics/endpoint/daemon.py`<br>`forensics/endpoint/first_responder.py`<br>`forensics/endpoint/schemas.py`<br>`forensics/endpoint/store.py` | `tests/test_p7_endpoint.py`<br>`tests/test_p7_first_responder_safety.py`<br>`tests/test_p7_adversarial_challenger.py` | `data/endpoint_evidence.db`<br>`acquisition_manifest.json`<br>`reports/P7_FIRST_RESPONDER_REPORT.md` | **HOÀN THÀNH** |
| **C08** | **Machine Learning & XAI** | P8 | §6 P8, §11 T14–T17, §13 | Mô hình học máy phát hiện bất thường MLP với nhãn ground-truth độc lập (không lấy nhãn từ Rule Engine); phân chia tập train/val/test theo trình tự thời gian; scaler chỉ fit trên train; chuẩn hóa đơn vị token; đồng bộ đồ thị ONNX; giải thích cục bộ SHAP (fidelity & stability); ánh xạ MITRE ATT&CK kèm cơ chế abstain (`NOT_MAPPED`). | `forensics/ml/__init__.py`<br>`forensics/ml/dataset.py`<br>`forensics/ml/features.py`<br>`forensics/ml/model.py`<br>`forensics/ml/registry.py`<br>`forensics/ml/xai.py`<br>`forensics/ml/mitre.py`<br>`forensics/ml/corroboration.py`<br>`scripts/train_p8_model.py` | `tests/test_p8_ml_foundations.py`<br>`tests/test_p8_xai_corroboration.py`<br>`tests/test_p8_mitre_ai_integration.py` | `models/anomaly_detector_v1.onnx`<br>`models/anomaly_detector_v1_meta.json`<br>`reports/P8_ML_XAI_REPORT.md` | **HOÀN THÀNH** |
| **C09** | **ZKML Verifiable Inference** | P9 | §7 P9, §11 T20–T22, §13 | Kiểm chứng tính toàn vẹn suy luận bằng Zero-Knowledge ML thật (Halo2 / EZKL, không dùng mock proof); mạch số học fixed-point; cam kết KZG; ràng buộc mật mã 5 thành phần (`model_hash \|\| circuit \|\| input \|\| output \|\| record_id`); tự động từ chối bằng chứng bị can thiệp; verifier on-chain trên Anvil (`InferenceVerifier.sol` với `--via-ir`). | `forensics/zkml/__init__.py`<br>`forensics/zkml/export.py`<br>`forensics/zkml/circuit.py`<br>`forensics/zkml/prover.py`<br>`forensics/zkml/verifier.py`<br>`contracts/src/InferenceVerifier.sol` | `tests/test_p9_zkml.py`<br>`tests/test_p9_adversarial_challenger.py`<br>`contracts/test/InferenceVerifier.t.sol` | Mạch và khóa trong `models/zkml/` (`settings.json`, `pk.key`, `vk.key`)<br>Bằng chứng thực `proof.json`<br>`reports/P9_ZKML_REPORT.md` | **HOÀN THÀNH** |
| **C10** | **Identity & Custody** | P3 / P10 | §4 P3, §8 P10, §11 T06–T07, T18–T19, §13 | Hợp đồng thông minh quản lý chuỗi hành trình chứng cứ (Solidity 0.8.24); định danh phân tán W3C DID Core 1.0 (`did:ethr` / `did:key`); phân quyền RBAC đa vai trò; chữ ký số EIP-712 chống replay bằng monotonic nonce và deadline; xác lập giao dịch nguyên tử (CAS); cơ chế Zero Automatic Retries; kịch bản chuyển giao 2 tác viên với biên nhận và đối chiếu mã băm. | `forensics/did/__init__.py`<br>`forensics/did/artifacts.py`<br>`forensics/did/client.py`<br>`forensics/did/eip712.py`<br>`forensics/did/resolution.py`<br>`forensics/onchain.py`<br>`forensics/onchain_ops.py`<br>`forensics/onchain_store.py`<br>`contracts/src/EvidenceRegistry.sol`<br>`contracts/src/EvidenceRegistryDID.sol` | `tests/test_p10_custody.py`<br>`tests/test_onchain_store.py`<br>`tests/test_onchain_group3.py`<br>`tests/test_onchain_group3_smoke.py`<br>`tests/test_onchain_guard.py`<br>`tests/test_onchain_blockers.py`<br>`tests/test_onchain_2b.py`<br>`tests/test_onchain_d1.py`<br>`contracts/test/EvidenceRegistry.t.sol`<br>`contracts/test/EvidenceRegistryDID.t.sol`<br>`contracts/test/ChallengerDIDAdversarial.t.sol` | `contracts/src/EvidenceRegistry.sol`<br>`contracts/src/EvidenceRegistryDID.sol`<br>`reports/P10_DID_CUSTODY_REPORT.md` | **HOÀN THÀNH** |
| **C11** | **Integration & Evaluation** | P11 / Evaluation | §9 P11, §11 T23–T24, §13 | Kiểm thử tích hợp toàn diện và đánh giá thực nghiệm: kịch bản D1 (EVM Forensic Replay), D2 (Host Log Forensic Replay per ISO 27037), D3 (Multi-Gateway Adversarial Replay); bộ sinh báo cáo pháp chứng truy vết đầu cuối nối từ evidence -> alert -> ML -> investigation -> custody/proof; phân tách minh bạch các chỉ số kiểm thử. | `forensics/evaluation.py`<br>`scripts/evaluate.py`<br>`scripts/run_g5_verification.py`<br>`scripts/run_g6c_regression.py` | `tests/test_p1_p10_integration.py`<br>`tests/test_evaluation_portable.py`<br>`tests/test_empirical_challenger_iter2.py`<br>`tests/test_adversarial_db_concurrency.py`<br>`tests/test_adversarial_m2.py` | `reports/P1_P10_INTEGRATION_REPORT.md`<br>`reports/P1_P10_TEST_RESULTS.md`<br>`reports/DEMO_D1_EVM_REPORT.json`<br>`reports/DEMO_D2_HOST_REPORT.json` | **HOÀN THÀNH** |
| **C12** | **Portable Release** | P12 / Packaging | §10 P12, §11 T25, §13 | Bản phát hành độc lập chạy offline trên môi trường Windows x64 không phụ thuộc vào đường dẫn tuyệt đối hoặc tên người dùng nguồn; tự động hóa cài đặt và kiểm thử qua PowerShell; wheelhouse 101 gói thư viện; đối chiếu mã băm `SHA256SUMS.txt`; vượt qua cổng giải nén và kiểm thử sạch trên thư mục mới (Gate T25). | `scripts/portable.py`<br>`setup_env.bat`<br>`run_tests.bat`<br>`run_evaluation.bat` | `tests/test_evaluation_portable.py`<br>Kiểm thử trích xuất thư mục sạch (Gate T25) | Gói phân phối portable độc lập trong `dist/`<br>`README_SETUP.md`<br>`PORTABILITY_TEST_REPORT.md`<br>`LICENSES_AND_DATA_RIGHTS.md`<br>`SHA256SUMS.txt` | **HOÀN THÀNH** |

---

## 3. ÁNH XẠ 25 CỔNG NGHIỆM THU KỸ THUẬT (T01–T25) VỚI CÁC THÀNH PHẦN

Đặc tả `AGENT.md v6.0 §11` quy định 25 cổng nghiệm thu bắt buộc (T01–T25). Dưới đây là bảng đối chiếu ánh xạ các cổng này vào 12 thành phần chức năng:

| Cổng | Tên kịch bản kiểm tra | Thành phần chức năng chính | Trọng tâm kiểm chứng | Trạng thái kỹ thuật |
|:---:|---|:---:|---|:---:|
| **T01** | Multi-chain transaction collection | **Blockchain Collector (C01)** | Thu thập khối, giao dịch, biên nhận và logs EVM trên RPC | **DONE** |
| **T02** | RPC resilience & failover | **Blockchain Collector (C01)** | Thử lại với exponential backoff, xử lý HTTP 429 và RPC crash | **DONE** |
| **T03** | 12-block reorg unwinder | **Blockchain Collector (C01)** | Phát hiện và quay lui trạng thái khi chuỗi phân nhánh 12 khối | **DONE** |
| **T04** | Rule Engine deterministic detection | **Rule Engine (C04)** & **Evidence Store (C02)** | Phát hiện các mẫu hành vi R1–R4 trên `asset_transfers` | **DONE** |
| **T05** | Three-layer verification | **Evidence Store (C02)** & **Evidence Package (C03)** | Xác minh tính toàn vẹn tại CSDL cục bộ, đối chiếu RPC và on-chain | **DONE** |
| **T06** | Smart Contract on-chain custody | **Identity & Custody (C10)** | Đăng ký chứng cứ bất biến và ghi nhật ký trên `EvidenceRegistry.sol` | **DONE** |
| **T07** | Key safety & replay guardrails | **Identity & Custody (C10)** | Chống lộ private key, kiểm tra địa chỉ ký và chống gửi lại giao dịch | **DONE** |
| **T08** | Threat Intel & OWA evaluation | **Threat Intelligence (C06)** | Nhập dữ liệu Forta/PTXPhish/MEW, phòng chống CSV injection | **DONE** |
| **T09** | AI Investigator bounded execution | **AI Investigator (C05)** | Tuân thủ ngân sách 5 bước và danh sách trắng công cụ (Whitelist) | **DONE** |
| **T10** | Two-stage Ref Checker | **AI Investigator (C05)** | Xác thực tồn tại và đối chiếu giá trị nội dung trích dẫn chứng cứ | **DONE** |
| **T11** | Prompt Injection defense | **AI Investigator (C05)** | Ngăn chặn 38 mẫu tiêm mã độc qua nội dung on-chain không tin cậy | **DONE** |
| **T12** | Multi-source Acquisition (ISO 27037) | **Endpoint Acquisition (C07)** | Thu thập song song nguồn EVM và host logs JSONL/EVTX có manifest, consent, SHA-256 | **DONE** |
| **T13** | First Responder policy guards | **Endpoint Acquisition (C07)** | Chặn quyền chạy shell, xóa log, sửa ACL, cô lập mạng, ký giao dịch | **DONE** |
| **T14** | ML inference reproducibility | **ML/XAI (C08)** | Tái lập suy luận mô hình với mã băm ONNX cố định (`d1b9ce82...`) và feature extractor | **DONE** |
| **T15** | ML anti-leakage & ground truth | **ML/XAI (C08)** | Tách độc lập nhãn ground truth, cửa sổ thời gian không rò rỉ, scaler chỉ fit trên train | **DONE** |
| **T16** | Local XAI quantitative fidelity | **ML/XAI (C08)** | Giải thích cục bộ Exact SHAP, đo lường fidelity ($R^2 = 0.9993$), stability ($0.9999$) và `NOT_EXPLAINABLE` | **DONE** |
| **T17** | Grounded MITRE ATT&CK mapping | **ML/XAI (C08)** | Ánh xạ kỹ thuật kèm `required_evidence`, phiên bản ATT&CK v14.1 và cơ chế `NOT_MAPPED` | **DONE** |
| **T18** | DID ↔ Signer binding & verification | **Identity & Custody (C10)** | Xác thực quan hệ giữa DID W3C, khóa công khai, RBAC và chữ ký EIP-712 chống replay | **DONE** |
| **T19** | Two-actor custody transfer | **Identity & Custody (C10)** | Chuyển giao giữa 2 tác viên với biên nhận Anvil thực tế và đối soát khớp mã băm | **DONE** |
| **T20** | ZKML real Halo2 positive proof | **ZKML (C09)** | Sinh proof thật `5,504` bytes bằng Halo2/EZKL tại `circuits/anomaly_detector_v1/` | **DONE** |
| **T21** | ZKML automated tamper rejection | **ZKML (C09)** | Tự động từ chối khi sửa đổi input, output, model hash, public instances hoặc proof bytes | **DONE** |
| **T22** | ZKML Anvil on-chain verification | **ZKML (C09)** & **Identity & Custody (C10)** | Triển khai `Halo2Verifier.sol` + `InferenceVerifier.sol` trên Anvil (~`1.14M` gas) | **DONE** |
| **T23** | End-to-end case replay (D1/D2) | **Integration & Evaluation (C11)** | Replay thực nghiệm D1 (EVM 8 pha + re-read) & D2 (Host ISO 27037 6 pha) có báo cáo truy vết | **DONE** |
| **T24** | Multi-gateway adversarial defense | **Integration & Evaluation (C11)** | Kịch bản D3 chặn đóng kín `35/35` vector tấn công trên 6 cổng phòng vệ; zero PII/secret leak | **DONE** |
| **T25** | Portable clean-extract execution | **Portable Release (C12)** | Giải nén và kiểm thử sạch trên thư mục độc lập (`DONE`); máy vật lý thứ hai: `NOT_VERIFIED` | **PARTIAL** (Clean-extract `DONE`; máy vật lý thứ hai `NOT_VERIFIED`) |

---

## 4. BẢNG ĐỐI CHIẾU LỆNH CLI, TỆP KỊCH BẢN VÀ HỢP ĐỒNG

| Lệnh CLI / Tệp kịch bản | Thành phần chức năng đại diện | Mô tả hành vi & Mục đích sử dụng |
|---|---|---|
| `python collector.py healthcheck` | **Blockchain Collector (C01)** | Kiểm tra tình trạng kết nối RPC và độ ổn định của mạng |
| `python collector.py verify` | **Blockchain Collector (C01)** | Xác minh tính nhất quán giữa dữ liệu khối đã lưu và hash thực tế |
| `python -m forensics.rules.anchored` | **Rule Engine (C04)** & **Evidence Package (C03)** | Chạy tập luật trên gói chứng cứ đã đăng ký on-chain (Dual-Read) |
| `python scripts/run_real_rules.py` | **Rule Engine (C04)** | Thực thi kiểm tra tập luật R1–R4 trên CSDL chuẩn `real_p4.db` |
| `python scripts/evaluate.py` | **Threat Intelligence (C06)** | Chạy đánh giá sàng lọc và phân loại CTI trên `benchmark_p6.db` |
| `python scripts/train_p8_model.py` | **ML/XAI (C08)** | Huấn luyện mô hình MLP, chuẩn hóa đặc trưng và xuất metadata |
| `python -m forensics.zkml.prover` | **ZKML (C09)** | Khởi tạo nhân chứng (witness) và sinh proof suy luận Halo2 thực tế |
| `contracts/src/EvidenceRegistryDID.sol` | **Identity & Custody (C10)** | Hợp đồng thông minh đăng ký chứng cứ, DID và chữ ký EIP-712 |
| `contracts/src/InferenceVerifier.sol` | **ZKML (C09)** | Hợp đồng thông minh xác minh ZKML proof on-chain trên Anvil |
| `python scripts/demo_d1_evm.py` | **Integration & Evaluation (C11)** | Thực thi ca điều tra thực nghiệm mẫu D1 từ nguồn khối EVM |
| `python scripts/demo_d2_host.py` | **Integration & Evaluation (C11)** | Thực thi ca điều tra thực nghiệm mẫu D2 từ nguồn host log ISO 27037 |
| `python scripts/demo_d3_adversarial.py` | **Integration & Evaluation (C11)** | Thực thi kịch bản tấn công đối kháng đa tầng D3 để kiểm tra độ bền |
| `python scripts/portable.py bundle` | **Portable Release (C12)** | Đóng gói sản phẩm portable độc lập kèm wheelhouse và checksum |

---

## 5. RANH GIỚI BẢO TỒN VÀ QUY TẮC BẤT BIẾN

Tuân thủ nghiêm ngặt Yêu cầu **R1**, **R4** và **R5**:

### Những thành phần ĐƯỢC PHÉP và PHẢI chuẩn hóa theo tên chức năng mới:
- Tài liệu đang duy trì (`README.txt`, `PROJECT.txt`, `docs/architecture.md`, `docs/naming_cross_reference.md`).
- Sơ đồ kiến trúc hệ thống và giao diện hiển thị CLI mới.
- Chú thích mã nguồn (comments), tên hàm, tên biến và thông điệp lỗi trong các module đang phát triển hoạt động.
- Các báo cáo kỹ thuật được tạo mới từ Milestone M0 trở đi (`reports/BASELINE_AUDIT_v6.md`, `reports/GAP_MATRIX_T01_T25.md`,...).

### Những thành phần TUYỆT ĐỐI KHÔNG ĐƯỢC PHÉP thay đổi chỉ để gỡ nhãn P:
1. **Đặc tả chính và tài liệu tiền nhiệm**: `AGENT.md v6.0`, `docs/legacy/agent_v5.1.txt`.
2. **Lịch sử Git**: Toàn bộ commit history, tag, thông tin tác giả và nhật ký commit.
3. **Cơ sở dữ liệu chuẩn đã niêm phong**: `data/real_p4.db`, `data/forensics.db`, `data/benchmark_p6.db`, `.env`.
4. **Hồ sơ nghiệm thu lịch sử**: Các báo cáo đã nghiệm thu trong `reports/` (`P7_P10_BASELINE_AUDIT.md`, `P1_P10_INTEGRATION_REPORT.md`, `P1_P10_TEST_RESULTS.md`,...) và ở thư mục gốc (`P3_FINAL_ACCEPTANCE_REPORT.txt`, `P4_ACCEPTANCE_REPORT.txt`, `P5_ACCEPTANCE_REPORT.txt`, `COMPLETION_REPORT.txt`,...).
5. **Chứng cứ và Manifest lịch sử**: Tệp xuất chứng cứ, `acquisition_manifest.json`, và mã băm SHA-256 đã đóng gói.
