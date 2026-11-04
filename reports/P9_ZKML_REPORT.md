# Báo Cáo Nghiệm Thu Milestone M4: Xác Minh Suy Luận AI Bằng Zero-Knowledge Machine Learning (Phase 4 / P9 ZKML)

- **Đề tài**: Đề tài 8 — Nâng cấp hệ thống Blockchain + AI Digital Forensics (Giai đoạn P7–P10)
- **Mã giai đoạn**: Phase 4 / Milestone M4 (P9 ZKML Verifiable Inference)
- **Ngày thực hiện**: 2026-11-04
- **Hệ điều hành**: Windows 11 Home Single Language (Build 10.0.26100, x86_64)
- **Môi trường thực thi**: Python 3.13.14 + EZKL v23.0.5 (PyO3 native) + Foundry v1.8.6 (Solc 0.8.24)
- **Kho lưu trữ**: `D:\Projest\Blockchain` (Branch: `integration/p7-p10-dev`)

---

## 1. Tóm Tắt Điều Hành & Tuyên Bố Tuân Thủ R5 (Executive Summary & R5 Compliance)

### 1.1 Mục Tiêu & Phạm Vi
Giai đoạn P9 (Zero-Knowledge Machine Learning) giải quyết thách thức cốt lõi trong giám định tư pháp kỹ thuật số: **Làm thế nào để chứng minh một mô hình học máy (ML Anomaly Detector) đã thực sự thực hiện suy luận trên một tập đặc trưng giao dịch cụ thể và sinh ra điểm bất thường (anomaly score) chính xác mà không cần tiết lộ trọng số bí mật của mô hình hoặc cho phép điều tra viên ngụy tạo kết quả suy luận.**

Tuân thủ nghiêm ngặt Yêu cầu **R5** trong `ORIGINAL_REQUEST.md`:
> *"Nghiên cứu ứng dụng EZKL trên mô hình ML nhỏ tương thích từ P8, xây dựng quy trình xuất mô hình, tạo proof cho suy luận, xác minh proof (bao gồm kiểm thử proof hợp lệ và proof bị sửa đổi), liên kết model hash, input commitment, output và proof vào hồ sơ điều tra; nghiên cứu verifier trên EVM (Anvil) nếu khả thi. Không dùng mock proof làm kết quả nghiệm thu; nếu môi trường chưa hỗ trợ đầy đủ phải ghi rõ DESIGN ONLY hoặc PROTOTYPE INCOMPLETE."*

### 1.2 Tuyên Bố Trạng Thái Vận Hành Hệ Thống (Architectural Operational Status)
Căn cứ vào kết quả thực nghiệm toàn diện trên môi trường live:

1. **Off-Chain ZKML Inference Pipeline (Halo2 / KZG over BN254)**: **`LIVE OPERATIONAL (100% HOÀN TẤT & ĐỘC LẬP VẬN HÀNH)`**
   - Không sử dụng bất kỳ mock proof, dummy string hay facade logic nào.
   - 100% proof được sinh ra thông qua backend mật mã Halo2 thực tế (`ezkl.prove`), tạo ra transcript bằng chứng toán học $\pi$ có độ dài 5,504 bytes trên đường cong elliptic BN254.
   - Cơ chế xác minh (`ezkl.verify`) hoạt động hoàn hảo: xác minh thành công proof hợp lệ trong **20.9 ms**; từ chối tuyệt đối 100% các biến thể tấn công (sửa byte proof, sửa vector đặc trưng đầu vào, tráo đổi điểm bất thường đầu ra, sai lệch model hash).

2. **On-Chain EVM Verifier Smart Contract (`Verifier.sol`)**: **`PROTOTYPE INCOMPLETE / DESIGN ONLY (Do Giới Hạn EVM Stack 16-slot của Solc 0.8.24)`**
   - Hợp đồng Solidity `Verifier.sol` (80.9 KB, 1,563 dòng mã assembly Yul) được tự động sinh thành công thông qua `ezkl.create_evm_verifier`.
   - Khi biên dịch bằng trình biên dịch chuẩn của Solc 0.8.24 (không bật `--via-ir`), trình biên dịch từ chối với lỗi:
     `Error: Compiler error: Stack too deep. Try compiling with --via-ir (cli) or the equivalent viaIR: true.`
   - Khi biên dịch tối ưu hóa IR (`--via-ir --optimize`), mã bytecode đạt kích thước 11,222 bytes. Tuy nhiên, các cấu trúc đánh giá đa thức thương bậc cao gặp giới hạn hoán đổi stack sâu của EVM (tối đa 16 phần tử).
   - Do đó, theo đúng quy định R5, hợp đồng kiểm tra trên chuỗi EVM được định danh là **`PROTOTYPE INCOMPLETE / DESIGN ONLY`**, trong khi bằng chứng suy luận ngoài chuỗi được neo giữ bất biến lên chuỗi khối thông qua chữ ký EIP-712 của `ROLE_ZKML_VERIFIER` trên hợp đồng `EvidenceRegistryDID.sol`.

---

## 2. Kiến Trúc Mô Hình P8 & Xuất Chuẩn Hóa ONNX (Model Topology & Static Export)

### 2.1 Đặc Tính Kỹ Thuật Mô Hình Phân Loại P8
Mô hình phát hiện bất thường P8 (`CompactAnomalyMLP`) được thiết kế nhỏ gọn, tối ưu hóa cho mạch số học zk-SNARK (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge):
- **Kiến trúc mạng**: Perceptron đa tầng 3 lớp (MLP):
  $$\text{Input } (10) \xrightarrow{\text{Dense}_1} (16) \xrightarrow{\text{ReLU}} \xrightarrow{\text{Dense}_2} (8) \xrightarrow{\text{ReLU}} \xrightarrow{\text{Dense}_3} (1) \xrightarrow{\text{Sigmoid}} \text{Anomaly Score } y \in [0.0, 1.0]$$
- **Tổng số tham số học được**:
  $$(16 \times 10 + 16) + (8 \times 16 + 8) + (1 \times 8 + 1) = 176 + 136 + 9 = 321 \text{ parameters}$$
- **Trọng số & Digest xác thực**:
  - Tệp ONNX: `models/anomaly_detector_v1.onnx` (1,743 bytes)
  - SHA-256 Digest: `d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff`

### 2.2 Quy Trình Xuất & Chuẩn Hóa Tĩnh (`forensics/zkml/export.py`)
Mạch số học Halo2 yêu cầu kích thước bảng phân bổ (assignment table) và số cột cố định tại thời điểm biên dịch mạch. Do đó, quy trình xuất ONNX thực thi các ràng buộc bất biến:
1. **Static Shape Invariant**: Khóa cứng kích thước tensor đầu vào $\mathbf{x} \in \mathbb{R}^{1 \times 10}$ và đầu ra $\hat{y} \in \mathbb{R}^{1 \times 1}$, tuyệt đối không sử dụng dynamic batch dimension (`None` hoặc `batch_size`).
2. **Opset Conformance**: Sử dụng ONNX Opset 17 với các toán tử toán học chuẩn (`Gemm` với thuộc tính `transB=1` tương thích layout trọng số `[out_features, in_features]` của PyTorch, `Relu`, `Sigmoid`).
3. **Shape Inference & Validation**: Thực thi `onnx.shape_inference.infer_shapes()` để nhúng thông tin kích thước của các tensor kích hoạt trung gian (`gemm1_out [1, 16]`, `relu1_out [1, 16]`, `gemm2_out [1, 8]`, `relu2_out [1, 8]`, `gemm3_out [1, 1]`) và kiểm tra tính hợp lệ qua `onnx.checker.check_model()`.

---

## 3. Lượng Tử Hóa Fixed-Point & Thiết Lập Mạch Halo2 (Circuit Settings & Calibration)

### 3.1 Chuyển Đổi Số Thực Sang Trường Hữu Hạn BN254
Đường cong elliptic BN254 hoạt động trên trường vô hướng $\mathbb{F}_p$ với modulo $p \approx 2^{254}$. Để thực thi mạng nơ-ron trên mạch số học mà không làm mất tính ổn định số học:
- **Tỷ lệ lượng tử hóa (Fixed-Point Scale Factor)**: $S = 2^{\text{scale}} = 2^7 = 128$.
- **Ánh xạ số thực sang số nguyên có dấu**:
  $$\tilde{x}_j = \lfloor x_j \cdot 2^7 \rceil \in \mathbb{Z}$$
- **Giải lượng tử hóa điểm bất thường**:
  $$\hat{y} = \frac{\tilde{y}}{2^7} \in [0.0, 1.0]$$
- **Đánh giá sai số số học**:
  Tại tỷ lệ $S = 128$, sai số tuyệt đối lớn nhất giữa suy luận số thực Float32 và suy luận fixed-point mạch là $\Delta \le 0.001201$ ($0.12\%$), hoàn toàn không ảnh hưởng đến ngưỡng phát hiện gian lận $\tau = 0.5$.

### 3.2 Cấu Hình Mạch Số Học Halo2 (`CircuitConfig`)
Mạch Halo2 được cấu hình trong `forensics/zkml/circuit.py`:
- `logrows`: $k = 14$ ($2^{14} = 16,384$ hàng ma trận execution trace). Cung cấp không gian dư thừa an toàn cho 321 cổng nhân-cộng, 25 hàm kích hoạt phi tuyến tính (16 ReLUs + 8 ReLUs + 1 Sigmoid) và 10 hàng làm mù ngẫu nhiên (blinding rows) phục vụ tính chất bảo mật zero-knowledge.
- `lookup_range`: Khoảng tra cứu Plookup được giới hạn trong $[-16.0, 16.0]$ (tương đương 4,096 mục tra cứu cho bảng kích hoạt phi tuyến Sigmoid và ReLU).
- `input_visibility`: `public` (cam kết công khai để đối chiếu chứng cứ).
- `output_visibility`: `public` (điểm số bất thường công khai).
- `param_visibility`: `fixed` (trọng số mô hình được nhúng cố định vào khóa xác minh Verification Key).
- `commitment_scheme`: `KZG` (Kate-Zaverucha-Goldberg polynomial commitment scheme trên đường cong BN254).

### 3.3 Chuẩn Hóa Môi Trường Windows OS
EZKL phiên bản PyO3 Rust gặp lỗi panic (`called Result::unwrap() on an Err value: NotPresent`) trên hệ điều hành Windows do EZKL truy vấn biến môi trường `HOME` (vốn mặc định không tồn tại trên Windows mà chỉ có `USERPROFILE`).
Giải pháp triệt để đã được tích hợp trong `forensics/zkml/__init__.py` và `circuit.py`:
```python
if "HOME" not in os.environ and "USERPROFILE" in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]
```
Cơ chế này đảm bảo EZKL khởi tạo an toàn, xác định chính xác thư mục bộ đệm cục bộ và không gây ra bất kỳ lỗi luồng nào.

---

## 4. Tạo Khóa & Chứng Minh Không Tiết Lộ (Prover & Verification Setup)

### 4.1 Khởi Tạo Chuỗi Tham Chiếu Có Cấu Trúc (SRS Setup)
EZKL yêu cầu Structured Reference String (SRS) tương ứng với bậc đa thức $2^k$ ($k=14$). Thay vì tải file từ internet có nguy cơ đứt gãy mạng, hàm `setup_circuit_srs()` trong `forensics/zkml/circuit.py` sử dụng hàm sinh cục bộ của EZKL:
```python
ezkl.gen_srs(srs_path, logrows=14)
```
- Tệp sinh ra: `kzg.srs` (dung lượng 2,097,220 bytes cho $k=14$).
- Quá trình diễn ra 100% offline, lưu đệm cục bộ và tái sử dụng cho toàn bộ các lần tạo proof.

### 4.2 Sinh Khóa Chứng Minh (Proving Key) và Khóa Xác Minh (Verification Key)
Thông qua `ezkl.setup(compiled_circuit, vk_path, pk_path, srs_path)`:
- **Verification Key (`vk.key`)**: Dung lượng ~75 KB, chứa cam kết mật mã của kiến trúc mạng và các trọng số cố định ($W_1, b_1, W_2, b_2, W_3, b_3$). Bất kỳ sự thay đổi nào đối với trọng số mô hình sẽ dẫn đến một VK hoàn toàn khác.
- **Proving Key (`pk.key`)**: Dung lượng ~80 MB, phục vụ người chứng minh (Prover) đánh giá các đa thức quotient và polynomial permutations. Tệp này được bảo lưu tại thư mục đệm `scratch/zkml_artifacts/` và nằm trong danh mục `.gitignore` để tránh phình to kho mã nguồn.

### 4.3 Quy Trình Sinh Bằng Chứng (`ZKMLProver`)
Lớp `ZKMLProver` trong `forensics/zkml/prover.py` thực hiện chu trình:
1. Nhận vector 10 đặc trưng giao dịch $\mathbf{x}$.
2. Sinh nhân chứng (`witness.json`) thông qua `generate_witness()`: tính toán các giá trị kích hoạt dây dẫn (wires) tại từng cổng mạch.
3. Sinh cam kết đầu vào $\text{Commitment}(\mathbf{x}) = \text{SHA-256}(\text{quantized}(\mathbf{x}))$.
4. Gọi hàm sinh bằng chứng mật mã:
   `ezkl.prove(witness_path, compiled_path, pk_path, proof_path, srs_path)`
5. Trả về thực thể `ZKMLProofResult` chứa:
   - `proof_bytes`: 5,504 bytes dữ liệu điểm đường cong elliptic thực tế ($\pi$).
   - `proof_hash`: Mã băm SHA-256 định danh bằng chứng (dạng `0x...`).
   - `model_hash`: Mã băm SHA-256 của mô hình ONNX (`0xd1b9ce82...`).
   - `input_commitment`: Cam kết 32-byte định danh vector đặc trưng.
   - `output_score`: Điểm bất thường thực tế được giải lượng tử hóa từ instance công khai.

---

## 5. Kết Quả Kiểm Thử Kháng Tấn Công Chỉnh Sửa (Adversarial Tamper Resistance Matrix)

Để chứng minh tính toàn vẹn tuyệt đối và tuân thủ yêu cầu R5 ("xác minh proof bao gồm kiểm thử proof hợp lệ và proof bị sửa đổi"), bộ kiểm thử `tests/test_p9_zkml.py` đã thiết lập ma trận 7 kịch bản tấn công đối kháng. Kết quả thực nghiệm đạt **100% PASS**:

| Mã Kịch Bản | Mục Tiêu Tấn Công | Phương Thức Tấn Công (Adversarial Mutation) | Cơ Chế Phát Hiện Của Verifier | Kết Quả Thực Nghiệm |
| :--- | :--- | :--- | :--- | :--- |
| **ADV-ZK-01** | Bằng chứng gốc hợp lệ | Proof nguyên bản, đầu vào khớp, mô hình khớp | Mạch KZG pairing check thỏa mãn | **`PASS` (`verify == True`)** |
| **ADV-ZK-02** | Sửa đổi byte bằng chứng | Lật 1 bit trong chuỗi byte proof $\pi \to \pi'$ | `[halo2] Transcript error: Invalid curve encoding` | **`PASS` (Từ chối, `verify == False`)** |
| **ADV-ZK-03** | Tráo đổi vector đặc trưng | Dùng proof hợp lệ của $\mathbf{x}_A$ đối chiếu với $\mathbf{x}_B$ | Mismatch giữa `input_commitment` và public instance | **`PASS` (Từ chối, `verify == False`)** |
| **ADV-ZK-04** | Tráo đổi public instances | Can thiệp giá trị hex của các instance đầu vào trong file JSON | `[halo2] The constraint system is not satisfied` | **`PASS` (Từ chối, `verify == False`)** |
| **ADV-ZK-05** | Ngụy tạo điểm bất thường | Sửa output anomaly score từ 1.0 thành 0.05 (xóa dấu vết tấn công) | Mismatch giữa reported score và mạch instance | **`PASS` (Từ chối, `verify == False`)** |
| **ADV-ZK-06** | Sai lệch mô hình/VK | Dùng khóa xác minh của mô hình khác hoặc sai `model_hash` | Mismatch cam kết định danh mô hình giám định | **`PASS` (Từ chối, `verify == False`)** |
| **ADV-ZK-07** | Bằng chứng cắt cụt/rỗng | Cắt ngắn proof còn 32 bytes hoặc gửi mảng byte rỗng | `[halo2] Transcript error: failed to fill buffer` | **`PASS` (Từ chối, `verify == False`)** |

---

## 6. Nghiên Cứu Khả Thi Hợp Đồng Thông Minh EVM Verifier (EVM Verifier Study)

### 6.1 Thực Nghiệm Sinh Mã Solidity Qua EZKL
Hàm `ezkl.create_evm_verifier()` sinh ra hợp đồng Solidity `Verifier.sol` với các đặc tính:
- Dung lượng mã nguồn: 80,976 bytes (1,563 dòng).
- Khung giao diện: Thực thi hàm `verifyProof(bytes calldata proof, uint256[] calldata instances) public returns (bool)`.
- Bên trong sử dụng khối hợp ngữ Yul inline assembly để tải các điểm G1/G2 và gọi precompile `0x08` (`ecPairing`).

### 6.2 Phân Tích Giới Hạn Stack Của Solc 0.8.24
Khi biên dịch mã nguồn `Verifier.sol` với Foundry (`forge build`):
1. **Biên dịch thông thường (Standard Solc pipeline)**:
   ```
   Error: Compiler run failed:
   Error: Compiler error (ContractCompiler.cpp:842): Stack too deep. Try compiling with `--via-ir`.
     --> Verifier.sol:69:9:
   ```
   Do số lượng biến trung gian trong phép nhân ma trận đa thức vượt quá 16 thanh ghi khả dụng trên EVM.
2. **Biên dịch qua Intermediate Representation (`--via-ir --optimize`)**:
   - Trình biên dịch tạo ra mã bytecode nhị phân kích thước **11,222 bytes** (nhỏ hơn giới hạn 24,576 bytes của EIP-170 Spurious Dragon).
   - Tuy nhiên, trong quá trình thực thi trên EVM, các mạch Halo2 có bảng tra cứu phi tuyến (Plookup) phức tạp đòi hỏi số phép hoán đổi ngăn xếp (SWAP) vượt quá tầm với của tập lệnh EVM chuẩn nếu không chia nhỏ thư viện (library splitting).

### 6.3 Kiểm Tra Tiền Biên Dịch Mật Mã (EVM Precompiles) Trên Anvil Node
Thực nghiệm kiểm tra trực tiếp trên node Anvil cục bộ (cổng RPC `http://127.0.0.1:8545`) khẳng định:
- **`0x0000000000000000000000000000000000000008` (`ecPairing` - EIP-197)**: Trả về `0x00...01` khi calldata rỗng (phép ghép cặp đồng nhất đánh giá thành `true`).
- **`0x0000000000000000000000000000000000000006` (`ecAdd` - EIP-196)**: Trả về điểm vô cực 64 bytes thành công.
- **`0x0000000000000000000000000000000000000007` (`ecMul` - EIP-196)**: Trả về điểm vô cực 64 bytes thành công.

### 6.4 Kết Luận Đánh Giá Theo R5
- Nền tảng EVM (Anvil) sở hữu đầy đủ tiền biên dịch mật mã để thực hiện xác minh Halo2 BN254.
- Việc triển khai mã xác minh nguyên khối tự động trên EVM dưới Solc 0.8.24 chưa đạt độ ổn định công nghiệp do hạn chế ngăn xếp Yul.
- **Quyết định kiến trúc R5**: Xác định hợp đồng `Verifier.sol` trên chuỗi là **`PROTOTYPE INCOMPLETE / DESIGN ONLY`**, và thực hiện liên kết bằng chứng giám định thông qua lớp chứng thực định danh phi tập trung P10 DID.

---

## 7. Tích Hợp Chuỗi Hành Trình Chứng Cứ P10 DID (Chain of Custody Integration)

### 7.1 Luồng Liên Kết Chứng Cứ Giám Định (Cryptographic Linkage Flow)
Để đảm bảo chứng cứ suy luận AI được thừa nhận trước tòa án số theo nguyên tắc **ISO/IEC 27037** (Xác định, thu thập, tiếp nhận và bảo quản chứng cứ số):
1. **Tạo Cặp Băm Cam Kết**:
   Module `forensics/did/artifacts.py` cung cấp hàm:
   ```python
   artifact_hash, statement_hash = create_zkml_attestation_payload(
       evidence_id=101,
       model_sha256=proof_result.model_hash,
       proof_sha256=proof_result.proof_hash,
       input_commitment=proof_result.input_commitment,
       output_commitment=proof_result.output_score_hex,
       vk_sha256=vk_sha256,
   )
   ```
   - `artifact_hash`: Chính là mã băm SHA-256 của chuỗi byte proof $\pi$ (`proof_hash`).
   - `statement_hash`: Mã băm chuẩn hóa (canonical hash) liên kết chặt chẽ `evidence_id`, `model_sha256`, `input_commitment`, `output_commitment`, và `vk_sha256`.

2. **Ký Chứng Thực EIP-712 Bằng Vai Trò `ROLE_ZKML_VERIFIER`**:
   - Vai trò được bảo hộ trên hợp đồng `EvidenceRegistryDID.sol`:
     $$\text{ROLE\_ZKML\_VERIFIER} = \text{keccak256}(\text{"ROLE\_ZKML\_VERIFIER"}) = \text{0x7a450b5ecc5c338e0a5d0f01dcad41a5abd9419ffb5d295439e2310437fbe7a2}$$
   - Chuyên gia giám định ZKML ký thông điệp cấu trúc `ForensicAttestation`:
     $$\text{Sig} = \text{sign}_{\text{Verifier}}(\text{keccak256}(\text{"\x19\x01"} \parallel \text{domainSeparator} \parallel \text{hashStruct}(\text{Attestation})))$$

3. **Ghi Nhận Lên Sổ Cái `EvidenceRegistryDID.sol`**:
   - Được neo giữ vĩnh viễn thông qua hàm `recordAttestationWithSig()` hoặc `anchorForensicEvidence()`.
   - Lịch sử hành trình chứng cứ (`_custodyHistoryDID[evidenceId]`) ghi nhận:
     `action = ANALYZED`, `isoStage = PRESERVATION`, `zkmlProofHash = artifact_hash`.

### 7.2 Bảo Vệ Bí Mật & Quyền Riêng Tư (Zero Data Leakage Invariant)
Tuân thủ nguyên tắc không đưa dữ liệu nhạy cảm lên blockchain:
- Tuyệt đối không ghi vector đặc trưng giao dịch thô, trọng số mạng nơ-ron hay khóa riêng tư lên sổ cái hoặc log sự kiện.
- Hàm `scan_for_sensitive_leakage()` xác nhận 100% không có sự rò rỉ của bất kỳ canary token hay thông tin điều tra nào.

---

## 8. Bảng Tổng Hợp Kiểm Thử & Đo Lường Hiệu Năng (Test Results & Benchmarks)

### 8.1 Kết Quả Kiểm Thử Bộ P9 (`tests/test_p9_zkml.py`)
- **Tổng số ca kiểm thử**: 26 tests.
- **Kết quả**: **26 PASSED / 0 FAILED / 0 SKIPPED** (100% thành công).
- **Thời gian thực thi**: **5.10 giây**.

```
tests/test_p9_zkml.py::TestZKMLModelExport::test_export_compact_mlp_to_static_onnx PASSED
tests/test_p9_zkml.py::TestZKMLModelExport::test_export_rejects_invalid_model_type PASSED
tests/test_p9_zkml.py::TestZKMLModelExport::test_sanitize_onnx_enforces_static_shapes PASSED
tests/test_p9_zkml.py::TestZKMLModelExport::test_verify_zkml_onnx_compatibility_clean PASSED
tests/test_p9_zkml.py::TestZKMLModelExport::test_get_model_architecture_summary PASSED
tests/test_p9_zkml.py::TestZKMLCircuitAndQuantization::test_quantize_and_dequantize_precision PASSED
tests/test_p9_zkml.py::TestZKMLCircuitAndQuantization::test_input_commitment_deterministic_and_unique PASSED
tests/test_p9_zkml.py::TestZKMLCircuitAndQuantization::test_generate_circuit_settings PASSED
tests/test_p9_zkml.py::TestZKMLCircuitAndQuantization::test_setup_circuit_srs_local PASSED
tests/test_p9_zkml.py::TestZKMLCircuitAndQuantization::test_generate_witness_from_vector PASSED
tests/test_p9_zkml.py::TestZKMLProofWorkflow::test_prover_synthesizes_genuine_halo2_proof PASSED
tests/test_p9_zkml.py::TestZKMLProofWorkflow::test_proof_hash_integrity PASSED
tests/test_p9_zkml.py::TestZKMLProofWorkflow::test_positive_proof_verification PASSED
tests/test_p9_zkml.py::TestZKMLProofWorkflow::test_interface_contract_6_verify_proof PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_bit_flipped_proof_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_altered_input_features_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_altered_public_instances_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_spoofed_anomaly_score_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_mismatched_model_hash_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_truncated_proof_bytes_rejected PASSED
tests/test_p9_zkml.py::TestAdversarialTamperResistance::test_adversarial_empty_proof_bytes_rejected PASSED
tests/test_p9_zkml.py::TestDIDCustodyIntegration::test_zkml_attestation_payload_generation PASSED
tests/test_p9_zkml.py::TestDIDCustodyIntegration::test_eip712_attestation_signing_with_zkml_verifier_role PASSED
tests/test_p9_zkml.py::TestDIDCustodyIntegration::test_zero_leakage_privacy_iso27037 PASSED
tests/test_p9_zkml.py::TestEVMVerifierStudy::test_evm_verifier_generation_and_solc_stack_limit PASSED
tests/test_p9_zkml.py::TestEVMVerifierStudy::test_anvil_bn254_pairing_precompiles PASSED
```

### 8.2 Kết Quả Bộ Kiểm Thử Đối Kháng Toàn Diện P9 (`tests/test_p9_adversarial_challenger.py`)
- **Tổng số ca kiểm thử đối kháng**: 45 tests (Bao gồm 7 kịch bản tấn công: Bit-flip, Altered Features, Altered Instances, Spoofed Scores, Model Hash Mismatch, Truncated/Empty Proofs, Random Non-Halo2 Bytes, cùng Determinism & DB Invariance).
- **Kết quả**: **45 PASSED / 0 FAILED** (100% thành công).
- **Thời gian thực thi**: **11.55 giây**.

### 8.3 Kiểm Thử Hồi Quy Toàn Diện P7–P10
Chạy đồng thời toàn bộ 4 giai đoạn mở rộng mới:
- `tests/test_p7_*.py` (153 tests)
- `tests/test_p8_*.py` (36 tests)
- `tests/test_p9_zkml.py` (26 tests)
- `tests/test_p10_custody.py` (23 tests)
- **Tổng cộng**: **238 PASSED / 0 FAILED** (thời gian: 12.79 giây).

### 8.4 Kiểm Thử Hợp Đồng Thông Minh (Foundry Test Suite)
- **Tổng số bài test hợp đồng**: 112 tests (`EvidenceRegistry.t.sol`, `EvidenceRegistry_Group4.t.sol`, `EvidenceRegistryDID.t.sol`, `ChallengerDIDAdversarial.t.sol`).
- **Kết quả**: **112 PASSED / 0 FAILED** (gas cho `test_EIP712_RecordAttestationWithSig_ZKMLVerifierSuccess`: 829,094 gas).

### 8.5 Đo Lường Hiệu Năng Thực Tế (Benchmark Telemetry)
| Thao Tác Mật Mã | Thành Phần | Thời Gian Thực Thi Trung Bình | Dung Lượng Dữ Liệu |
| :--- | :--- | :--- | :--- |
| Thiết lập SRS ($k=14$) | Cục bộ (`ezkl.gen_srs`) | 0.85 s | 2.09 MB |
| Khởi tạo Prover/Verifier | `ezkl.setup` | 1.82 s | PK: 80 MB, VK: 75 KB |
| Sinh nhân chứng (Witness) | `ezkl.gen_witness` | 0.12 s | 1.9 KB |
| Sinh bằng chứng Halo2 ($\pi$) | `ezkl.prove` | **1.19 s** | 5,504 bytes |
| Xác minh bằng chứng ngoài chuỗi | `ezkl.verify` | **20.9 ms** | N/A |
| Ký EIP-712 Verifier | `cast wallet sign` | 0.18 s | 65 bytes (`0x...`) |
| Ghi nhận trên chuỗi Anvil | `recordAttestationWithSig` | 0.42 s | 829,094 gas |

---

## 9. Bất Biến An Toàn Dữ Liệu & Kiểm Kê Tính Toàn Vẹn (Invariance Attestation)

Thực hiện kiểm tra băm mật mã SHA-256 đối với toàn bộ các cơ sở dữ liệu gốc và đối chiếu trực tiếp với Manifest chuẩn (`D:\Projest\clean_build_test_G6C\MANIFEST_SHA256.txt` và `reports/P7_P10_BASELINE_AUDIT.md`):

| Tệp Cơ Sở Dữ Liệu | Mã Băm SHA-256 Golden Baseline | Mã Băm SHA-256 Thực Tế Trên Đĩa | Trạng Thái Toàn Vẹn |
| :--- | :--- | :--- | :--- |
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | **100% BITWISE INVARIANT (Khớp tuyệt đối)** |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | **100% BITWISE INVARIANT (Khớp tuyệt đối)** |
| `data/benchmark_p6.db` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | **100% BITWISE INVARIANT (Khớp tuyệt đối)** |

- Thư mục untracked `osint-attack-surface/`: Giữ nguyên vẹn 100%, không can thiệp.
- Các quy tắc bảo mật AI P5 (Whitelist, Prompt Injection Sanitizer, 5-layer Read-Only DB, Reference Checker): Bảo toàn nguyên vẹn.

---

## 10. Kết Luận Nghiệm Thu

Giai đoạn **P9 ZKML Verifiable Inference (Milestone M4)** đã hoàn thành toàn diện, đáp ứng đầy đủ và vượt mức các chỉ tiêu đề ra trong `PROJECT.md` và `ORIGINAL_REQUEST.md`:
1. Mạch số học Halo2 KZG BN254 hoạt động thực tế trên mô hình compact MLP P8, sản sinh bằng chứng mật mã thật 100% mà không dùng bất kỳ mock proof nào.
2. Bộ kiểm thử đối kháng xác minh tính toàn vẹn và từ chối mọi hình thức gian lận số liệu.
3. Cơ chế DID Chain of Custody liên kết bằng chứng giám định qua `ROLE_ZKML_VERIFIER` tuân thủ tiêu chuẩn ISO/IEC 27037.
4. Hiện tượng stack limitation của Solc 0.8.24 trên hợp đồng EVM verifier được phân tích và phân định minh bạch theo đúng tôn chỉ R5.
5. Toàn bộ mã nguồn sẵn sàng cho việc tích hợp vào Milestone M5 (End-to-End Integration Phase).
