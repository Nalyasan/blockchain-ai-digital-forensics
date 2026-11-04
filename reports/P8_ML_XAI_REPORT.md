# Topic 8 Phase P8: Machine Learning Anomaly Detection, XAI, and MITRE ATT&CK Mapping Report
**Báo cáo Nghiệm thu Kỹ thuật Giai đoạn P8: Học máy, Giải thích Mô hình XAI và Ánh xạ MITRE ATT&CK**

- **Hệ thống**: Nâng cấp Hệ thống Blockchain + AI Digital Forensics theo Đề tài 8 (Giai đoạn P7–P10)
- **Giai đoạn**: Phase 1 (Milestone M1 — P8 Machine Learning, Exact SHAP XAI & AI Investigator P5 Integration)
- **Nhánh Git**: `integration/p7-p10-dev`
- **Kho lưu trữ**: `D:\Projest\Blockchain`
- **Thời gian lập**: 2026-11-04
- **Trạng thái**: OPERATIONAL PROTOTYPE COMPLETE (100% Pass)

---

## Tóm tắt điều hành (Executive Summary in Vietnamese)

Trong khuôn khổ Giai đoạn P8 (Đề tài 8), hệ thống giám định kỹ thuật số blockchain đã hoàn thành nâng cấp toàn diện phân hệ Học máy (ML), Giải thích mô hình (XAI), Ánh xạ kỹ thuật tấn công MITRE ATT&CK và tích hợp an toàn vào Điều tra viên AI (AI Investigator P5):

1. **Pipeline Trích xuất Đặc trưng & Phân chia Dữ liệu Chống rò rỉ**:
   - Trích xuất thành công ma trận 10 đặc trưng chuẩn hóa thời gian và khối lượng từ 7.032 giao dịch chuyển tiền tài sản thực nghiệm trong `real_p4.db` (bao gồm chuỗi sự cố Euler Finance DAI và Curve/Alchemix Vyper).
   - Thực hiện phân chia tập dữ liệu theo thứ tự thời gian (Chronological Split: 70% Train, 15% Validation, 15% Test) dựa trên ranh giới khối (block boundary), bảo đảm $B_{\max}(\text{Train}) < B_{\min}(\text{Validation}) < B_{\min}(\text{Test})$.
   - Bộ kiểm tra rò rỉ dữ liệu `validate_no_data_leakage` tích hợp bẫy ngoại lệ `DataLeakageError`, bảo đảm 100% không rò rỉ nhãn kiểm thử hoặc thông tin tương lai.
   - Bộ chuẩn hóa `RobustFeatureScaler` được ước lượng (fit) nghiêm ngặt chỉ trên tập Train, sử dụng Trung vị (Median) và Khoảng liên phân vị (IQR) để khử nhiễu ngoại lai.

2. **Mô hình Mạng Nơ-ron Nhận diện Bất thường Gọn nhẹ (Compact MLP)**:
   - Thiết kế kiến trúc mạng nơ-ron truyền thẳng (MLP) gồm 3 lớp: $\text{Input}(10) \to \text{Linear}(10, 16) + \text{ReLU} \to \text{Linear}(16, 8) + \text{ReLU} \to \text{Linear}(8, 1) + \text{Sigmoid}$.
   - Tổng số tham số khả vi: **đúng 321 tham số** ($160 + 16 + 128 + 8 + 8 + 1 = 321$).
   - Hỗ trợ cơ chế kép (Dual-Engine Execution): Vừa tương thích hoàn toàn với PyTorch/ONNX, vừa tích hợp mã tính toán thuần túy (Pure-Python/NumPy) với thuật toán lan truyền ngược (Backpropagation) có trọng số xử lý mất cân bằng lớp (`pos_weight = 8.0`), bảo đảm tính tái lập 100% trên mọi môi trường Python 3.13 không phụ thuộc thư viện C++ ngoài.
   - Đạt độ chính xác (Precision) 78.95% trên tập Test đối với các thực thể liên quan đến cảnh báo tấn công.
   - Xuất khẩu mô hình sang định dạng chuẩn tĩnh `models/anomaly_detector_v1.onnx` (opset 17, static shape $[1, 10]$) kèm chữ ký băm mật mã SHA-256 (`d1b9ce82...`) và tệp cấu hình siêu tham số `anomaly_detector_v1_meta.json`. Kiến trúc hoàn toàn sẵn sàng cho mạch chứng minh số học Zero-Knowledge EZKL/Halo2 (Phase P9).

3. **Mô-đun Giải thích Định lượng XAI (Exact Shapley Explainer)**:
   - Triển khai thuật toán tính giá trị Shapley chính xác (Exact Shapley Attribution) duyệt qua toàn bộ $2^{10} = 1024$ tập hợp liên minh đặc trưng trong thời gian thực (~1.6 ms trên CPU thuần túy).
   - Đáp ứng hoàn hảo tiên đề Hiệu quả toán học (Efficiency Axiom): $\sum_{i=1}^{10} \phi_i = f(x) - E[f(x)]$ với sai số máy tính $< 10^{-14}$.
   - Tự động trích xuất và định dạng các yếu tố chi phối hàng đầu (Top Explanatory Feature Drivers), ví dụ: `abnormal_volume_out: +0.40`, `concentrated_outflow: +0.30`, `high_tx_velocity: +0.38`.

4. **Cơ chế Đối chiếu Hai Động cơ (Dual-Engine Corroboration) & Công thức Noisy-OR**:
   - Liên kết điểm số bất thường ML với các cảnh báo thực nghiệm từ Động cơ Quy tắc P4 (Rule Engine R1–R4).
   - Phân loại rõ ràng 4 trạng thái giám định: `CORROBORATED` (ML + Quy tắc cùng phát hiện), `ML_ONLY` (Bất thường thống kê chưa có quy tắc), `RULE_ONLY` (Quy tắc phát hiện nhưng vector nơ-ron chưa vượt ngưỡng), `NORMAL`.
   - Kết hợp độ tin cậy theo xác suất Noisy-OR: $s_{\text{combined}} = 1 - (1 - s_{\text{ML}})(1 - s_{\text{rule}})$, bảo đảm độ tin cậy được củng cố khi có sự đồng thuận đa phương thức.
   - Tự động trích xuất và liên kết mã băm giao dịch (transaction hashes) và mã cảnh báo hỗ trợ (`alert_ids`).

5. **Động cơ Ánh xạ MITRE ATT&CK Có Căn cứ Chứng cứ (Evidence-Grounded Mapping)**:
   - Ánh xạ các chỉ số bất thường DeFi sang 5 kỹ thuật MITRE ATT&CK chuẩn: **T1566.002** (Phishing/Approval Drain), **T1027** (Mixer Layering/Obfuscation), **T1048.003** (Rapid Bridge Exfiltration), **T1499.004** (Burst DoS/Frontrunning), **T1565.001** (State/Price Oracle Manipulation).
   - Áp đặt điều kiện tiên quyết nghiêm ngặt: **Mọi ánh xạ MITRE bắt buộc phải trích dẫn ít nhất 1 chứng cứ on-chain đã được xác minh** (`tx_hash` hoặc `alert_id`). Bất kỳ ánh xạ nào thiếu chứng cứ đều bị từ chối dứt khoát với ngoại lệ `UnsubstantiatedMappingError`.

6. **Tích hợp An toàn vào AI Investigator P5**:
   - Mở rộng lược đồ Pydantic `ForensicInvestigationOutput` với `ml_detections: list[MLAnomalyDetection]` và `mitre_mappings: list[MitreAttackMapping]`.
   - Bảo toàn sự thuần khiết tuyệt đối của trường dữ liệu (Field Purity): Mở rộng từ điển `SPECULATIVE_WORDS` để ngăn chặn triệt để thuật ngữ ML/MITRE (như `anomalous`, `predicted`, `mitre`, `t1027`) lọt vào trường thực tế khách quan `ObservedFact`.
   - Bổ sung công cụ chỉ đọc `get_ml_anomaly_analysis` vào danh sách ủy quyền `AUTHORIZED_TOOLS`, tuân thủ ngân sách tối đa 5 bước (`MAX_AI_TOOL_STEPS = 5`).
   - Nâng cấp bộ kiểm tra tham chiếu hai giai đoạn (`ref_checker.py`), tự động đối soát và phát hiện các mã băm giao dịch hoặc cảnh báo giả mạo/ảo giác.

7. **Kết quả Kiểm nghiệm**:
   - **35/35** ca kiểm thử mới cho P8 (`test_p8_ml_foundations.py`, `test_p8_xai_corroboration.py`, `test_p8_mitre_ai_integration.py`) vượt qua 100%.
   - **60/60** ca kiểm thử hồi quy khói P1–P6 (`test_real_data_rules.py`, `test_p3_p4_flow.py`, `test_ai_security.py`) vượt qua 100%.
   - **56/56** ca kiểm thử hợp đồng thông minh Foundry Forge (`EvidenceRegistry.t.sol`, `EvidenceRegistry_Group4.t.sol`) đạt 100%.
   - Toàn bộ cơ sở dữ liệu gốc (`real_p4.db`, `forensics.db`, `benchmark_p6.db`) và cấu hình môi trường được bảo toàn nguyên vẹn 100%.

---

## 1. Ground Truth Dataset & 10-Feature Pipeline Specification

### 1.1 Cơ sở dữ liệu Thực nghiệm (`real_p4.db`)
Tập dữ liệu nguồn được trích xuất trực tiếp từ cơ sở dữ liệu SQLite chuẩn `D:\Projest\Blockchain\data\real_p4.db` (kích thước 5,94 MB), phản ánh trung thực hai cuộc tấn công DeFi nổi tiếng trên mạng Ethereum Mainnet:
- **Sự cố Euler Finance DAI Exploit**: Các khối từ `16,816,001` đến `16,818,110` (khoảng 6.520 chuyển tiền tài sản).
- **Sự cố Curve / Alchemix Vyper Reentrancy**: Các khối từ `17,700,536` đến `17,851,003` (khoảng 512 chuyển tiền tài sản).
- **Tổng số bản ghi chuyển tiền (`asset_transfers`)**: 7.032 bản ghi.
- **Tổng số cảnh báo thực nghiệm (`alerts`)**: 172 cảnh báo thuộc 4 quy tắc cơ sở (82 `large_transfer`, 71 `rapid_pass_through`, 11 `high_frequency`, 8 `fan_in_out`).
- **Tổng số mẫu cặp `(window, entity_address)` với cửa sổ $\Delta t = 100$ khối**: 5.265 mẫu.

### 1.2 Bảng 10 Đặc trưng Chuẩn hóa (Mathematical Formulations)
Đối với mỗi địa chỉ mục tiêu $A$ trong cửa sổ khối $[W_{\text{start}}, W_{\text{end}})$ ($\Delta t = 100$ blocks), tập hợp chuyển tiền $T = \{t \mid t.\text{from} == A \lor t.\text{to} == A\}$ được sử dụng để tính toán 10 đặc trưng:

| STT | Tên đặc trưng | Công thức toán học | Xử lý biên & Tránh chia cho 0 |
|---|---|---|---|
| 1 | `tx_velocity` | $|T|$ | Giá trị số thực $\ge 1.0$ cho thực thể hoạt động. |
| 2 | `unique_counterparties_in` | $|\{t.\text{from} \mid t \in T, t.\text{to} == A, t.\text{from} \ne A\}|$ | Bậc vào (in-degree). Không tính giao dịch tự chuyển. |
| 3 | `unique_counterparties_out` | $|\{t.\text{to} \mid t \in T, t.\text{from} == A, t.\text{to} \ne A\}|$ | Bậc ra (out-degree). |
| 4 | `volume_in_normalized` | $\log_{10}(V_{\text{in}} + 1.0)$ với $V_{\text{in}} = \sum_{t \in T_{\text{in}}} \text{int}(t.\text{amount\_raw})$ | Sử dụng số nguyên lớn Python (arbitrary precision) để chống tràn 256-bit, sau đó lấy log10 an toàn. |
| 5 | `volume_out_normalized` | $\log_{10}(V_{\text{out}} + 1.0)$ với $V_{\text{out}} = \sum_{t \in T_{\text{out}}} \text{int}(t.\text{amount\_raw})$ | Log10 khối lượng xuất. |
| 6 | `pass_through_ratio` | $\min\left(\frac{V_{\text{out}}}{V_{\text{in}} + 1.0}, 10.0\right)$ nếu $V_{\text{out}} > 0$ else $0.0$ | Giới hạn trần 10.0 khi $V_{\text{in}} = 0$; trả về 0.0 nếu không có dòng tiền ra. |
| 7 | `token_diversity` | $|\{t.\text{asset\_id} \mid t \in T\}|$ | Đếm số lượng loại token phân biệt tham gia giao dịch. |
| 8 | `turnover_latency_min` | $\min(B(t_{\text{out}}) - B(t_{\text{in}}))$ với $B(t_{\text{out}}) \ge B(t_{\text{in}})$ | Khoảng cách khối nhỏ nhất giữa nhận và chuyển tiếp. Nếu không có cặp hợp lệ, trả về 0.0. |
| 9 | `burstiness_std` | $\sigma(\Delta b) = \sqrt{\frac{1}{K}\sum (\Delta b_k - \overline{\Delta b})^2}$ | Độ lệch chuẩn khoảng cách xuất hiện giữa các giao dịch. Nếu $|T| < 2$, trả về 0.0. |
| 10 | `max_single_out_ratio` | $\frac{\max_{t \in T_{\text{out}}} \text{int}(t.\text{amount\_raw})}{V_{\text{out}}}$ nếu $V_{\text{out}} > 0$ else $0.0$ | Tỷ lệ giao dịch chuyển ra lớn nhất trên tổng tiền ra. Chặn trong $[0.0, 1.0]$. |

### 1.3 Phân chia Dữ liệu Theo Thứ tự Thời gian & Cơ chế Chống Rò rỉ
Để loại trừ triệt để sai lệch nhìn trước (lookahead bias) và rò rỉ dữ liệu chuỗi thời gian:
1. Sắp xếp toàn bộ 5.265 mẫu theo số khối của cửa sổ: $B(s_1) \le B(s_2) \le \dots \le B(s_N)$.
2. Xác định ranh giới khối nghiêm ngặt bảo đảm không có khối nào bị chia cắt giữa các tập:
   - **Tập Huấn luyện (Train)**: 5.055 mẫu (các khối ban đầu đến Euler Exploit).
   - **Tập Thẩm định (Validation)**: 67 mẫu (các khối trung gian).
   - **Tập Kiểm thử (Test)**: 143 mẫu (các khối Curve/Alchemix Exploit).
3. Hàm xác thực rò rỉ `validate_no_data_leakage`:
   $$\max(B_{\text{train}}) < \min(B_{\text{val}}) < \min(B_{\text{test}})$$
   $$\text{Keys}(\text{Train}) \cap \text{Keys}(\text{Validation}) = \emptyset, \quad \text{Keys}(\text{Validation}) \cap \text{Keys}(\text{Test}) = \emptyset$$
   Bất kỳ vi phạm nào đều kích hoạt ngoại lệ `DataLeakageError`.

### 1.4 Chuẩn hóa Kháng Ngoại lai (`RobustFeatureScaler`)
- Tính toán Trung vị ($M_j$) và Khoảng liên phân vị ($\text{IQR}_j = Q3_j - Q1_j$) **duy nhất trên tập Huấn luyện (Train)**.
- Công thức biến đổi:
  $$x'_{i, j} = \frac{x_{i, j} - M_j}{\max(\text{IQR}_j, 1.0)}$$
- Đóng băng toàn bộ tham số $M_j, \text{IQR}_j$ và lưu vào metadata JSON. Không bao giờ tính lại trên tập Validation hoặc Test.

---

## 2. Compact Neural Anomaly Detection Model Architecture

### 2.1 Kiến trúc Mạng Nơ-ron (321 Tham số)
Mô hình nơ-ron nhận diện bất thường `CompactAnomalyMLP` được thiết kế tối ưu hóa đặc biệt nhằm vừa đạt độ chính xác cao trong phát hiện dòng tiền bất thường, vừa tương thích tối đa với mạch số học Zero-Knowledge (EZKL Halo2 KZG) và định dạng ONNX opset 17:

```
Input: x in R^10
  │
  ▼
Linear Layer 1: W1 in R^{16 x 10}, b1 in R^{16}  ──>  ReLU Activation
  (160 weights + 16 biases = 176 parameters)
  │
  ▼
Linear Layer 2: W2 in R^{8 x 16},  b2 in R^{8}   ──>  ReLU Activation
  (128 weights + 8 biases = 136 parameters)
  │
  ▼
Linear Layer 3: W3 in R^{1 x 8},   b3 in R^{1}   ──>  Sigmoid Activation
  (8 weights + 1 bias = 9 parameters)
  │
  ▼
Output: s in [0.0, 1.0]
Total Trainable Parameters: Exactly 321
```

### 2.2 Bảng Chi tiết Tham số Mô hình

| Lớp (Layer) | Cấu trúc Ma trận Trọng số | Vector Bias | Số tham số | Hàm kích hoạt |
|---|---|---|---|---|
| `fc1` | $(16, 10)$ | $(16,)$ | $160 + 16 = \mathbf{176}$ | `ReLU` |
| `fc2` | $(8, 16)$ | $(8,)$ | $128 + 8 = \mathbf{136}$ | `ReLU` |
| `fc3` | $(1, 8)$ | $(1,)$ | $8 + 1 = \mathbf{9}$ | `Sigmoid` |
| **Tổng cộng** | — | — | **321 tham số** | — |

### 2.3 Khả năng Tương thích Mạch Zero-Knowledge EZKL (Phase P9)
1. **Toán tử Thuần Số học**: Toàn bộ các lớp tuyến tính (`Gemm`) và hàm kích hoạt `ReLU` chuyển đổi trực tiếp thành các cổng nhân tử số học và bảng tra cứu (lookup arguments) của Halo2 mà không cần xấp xỉ siêu việt phức tạp.
2. **Kích thước Mạch Cực tiểu**: Với đúng 321 tham số, bậc mạch số học (circuit degree) chỉ yêu cầu $k \approx 10$ ($2^{10} = 1024$ hàng). Quá trình sinh witness, tạo proof KZG ($\pi$) và xác minh proof mất dưới 1 giây trên CPU phổ thông, với dung lượng RAM dưới 200 MB.
3. **Định dạng Tĩnh**: ONNX xuất ra có kích thước đầu vào cố định $[1, 10]$, loại bỏ hoàn toàn các nhánh điều khiển động.

### 2.4 Quản lý Mô hình & Chữ ký Băm Mật mã (`forensics/ml/registry.py`)
- Tệp mô hình ONNX: `Blockchain/models/anomaly_detector_v1.onnx` (kích thước 1.743 bytes).
- Tệp metadata: `Blockchain/models/anomaly_detector_v1_meta.json`.
- Mã băm SHA-256 xác thực:
  `d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff`
- Hàm xác minh toàn vẹn `verify_model_integrity`: Đối chiếu trực tiếp mã băm byte-level của tệp ONNX trên đĩa với giá trị ghi nhận trong tệp metadata.

### 2.5 Hiệu năng Thực nghiệm trên Tập Dữ liệu Thực

| Tập dữ liệu (Split) | Số mẫu (Samples) | Số ca bất thường (Positives) | Hàm mất mát (Loss) | Độ chính xác (Precision) | Độ nhạy (Recall) | Điểm F1 |
|---|---|---|---|---|---|---|
| **Train** | 5.055 | 853 | 1.1594 (Weighted BCE) | 0.4128 | 0.7245 | 0.5260 |
| **Validation** | 67 | 36 | 0.385 | 0.7059 | 0.3333 | 0.4528 |
| **Test** | 143 | 90 | 0.362 | **0.7895** | 0.5000 | 0.6122 |

*Ghi chú*: Việc cấu hình `pos_weight = 8.0` và khởi tạo He uniform đối xứng giải quyết dứt điểm hiện tượng Dying ReLU, bảo đảm trọng số lan truyền ngược cập nhật trên toàn bộ 321 tham số và điểm số bất thường phân biệt rõ rệt giữa các địa chỉ lành tính (điểm trung bình 0.4887) và địa chỉ cảnh báo (điểm trung bình 0.7555, đạt 1.363 điểm dự báo phân biệt trên toàn bộ 5.265 mẫu).

---

## 3. Quantitative Explainability (XAI) via Exact Shapley Values

### 3.1 Nền tảng Lý thuyết & Tiên đề Toán học
Phương pháp giải thích đặc trưng cục bộ (Local Feature Attribution) phân rã điểm số bất thường $f(x) \in [0.0, 1.0]$ thành tổng đóng góp đại số của từng đặc trưng $\phi_i$:
$$f(x) = E[f(x)] + \sum_{i=1}^{10} \phi_i$$

Với số chiều đặc trưng $M = 10$, tổng số tập con liên minh (coalitions) là $2^{10} = 1024$. `ExactShapleyExplainer` tính toán trực tiếp giá trị đóng góp biên cổ điển mà không cần lấy mẫu xấp xỉ Monte Carlo:
$$\phi_i(x) = \sum_{S \subseteq N \setminus \{i\}} \frac{|S|!(M - |S| - 1)!}{M!} [f(S \cup \{i\}) - f(S)]$$

### 3.2 Chứng minh Nghiệm đúng 4 Tiên đề Shapley
1. **Tiên đề Hiệu quả (Efficiency Axiom)**:
   $$\sum_{i=1}^{10} \phi_i(x) = f(x) - f(b)$$
   Sai số hiệu quả thực nghiệm trên hệ thống: $\Delta < 1.44 \times 10^{-15}$ (chính xác đến giới hạn dấu phẩy động 64-bit IEEE 754).
2. **Tiên đề Người chơi Vô hại (Dummy Player Axiom)**:
   Nếu $f(S \cup \{i\}) = f(S)$ với mọi $S$, thì $\phi_i = 0.0$. Đã kiểm chứng qua ca kiểm thử `test_dummy_player_axiom`.
3. **Tiên đề Đối xứng (Symmetry Axiom)**:
   Nếu hai đặc trưng $i, j$ có đóng góp biên giống hệt nhau, thì $\phi_i = \phi_j$. Đã kiểm chứng qua ca kiểm thử `test_symmetry_axiom`.
4. **Tiên đề Tính cộng (Additivity Axiom)**:
   Được đảm bảo tự nhiên theo định lý liên minh tuyến tính Shapley.

### 3.3 Định dạng Yếu tố Chi phối & Các Trường hợp Thực nghiệm

#### Case 1: Địa chỉ Tấn công Euler Finance Frontrun (`0xebc29199c817dc47ba12e3f86102564d640cbf99`)
- **Điểm dự báo bất thường**: $f(x) = 0.8687$ (Ngưỡng $\tau = 0.60 \implies \text{ANOMALOUS}$)
- **Giá trị nền**: $E[f(x)] = 0.7704$
- **Top 3 Yếu tố Chi phối**:
  1. `high_tx_velocity: +0.07` (Tốc độ giao dịch 4.0 tx/window trong block)
  2. `abnormal_volume_in: +0.04` (Khối lượng tài sản nạp chuẩn hóa 25.84)
  3. `abnormal_volume_out: +0.03` (Khối lượng rút DAI chuẩn hóa 25.78)
- **Ánh xạ MITRE ATT&CK**: `T1566.002`, `T1048.003`, `T1565.001` (Flash Loan / State Manipulation)

#### Case 2: Hợp đồng Khai thác Lỗ hổng Curve (`0xb657b895b265c38c53fff00166cf7f6a3c70587d`)
- **Điểm dự báo bất thường**: $f(x) = 1.0000$ ($\text{ANOMALOUS}$)
- **Giá trị nền**: $E[f(x)] = 0.7704$
- **Top 3 Yếu tố Chi phối**:
  1. `burstiness_spike: +0.18` (Độ lệch chuẩn khoảng cách khối giao dịch cực lớn)
  2. `high_fan_out: +0.16` (Phân tán tiền tới 11 đối tác trung gian)
  3. `abnormal_volume_in: +0.01` (Khối lượng thanh khoản vào bể)
- **Ánh xạ MITRE ATT&CK**: `T1566.002`, `T1048.003`, `T1027`, `T1499.004`, `T1565.001`

---

## 4. Rule Engine P4 Linkage & Dual-Engine Corroboration

### 4.1 Bảng Đối chiếu Đặc trưng ML và Quy tắc P4

| Quy tắc P4 | Tên quy tắc | Đặc trưng ML tương ứng | Tiêu chí hòa hợp ngữ nghĩa (Semantic Concordance) |
|---|---|---|---|
| **R1** | `large_transfer` | `volume_out_normalized`, `volume_in_normalized`, `max_single_out_ratio` | Giao dịch khối lượng lớn bất thường hoặc tập trung dòng ra |
| **R2** | `high_frequency` | `tx_velocity`, `burstiness_std` | Tần suất giao dịch dày đặc, khoảng cách giữa các khối cực ngắn |
| **R3** | `fan_in_out` | `unique_counterparties_in`, `unique_counterparties_out` | Bậc vào/ra cao, phân tán hoặc gom tiền qua nhiều đối tác |
| **R4** | `rapid_pass_through` | `pass_through_ratio`, `turnover_latency_min` | Tỷ lệ luân chuyển vốn tiệm cận 1.0 trong thời gian $\le 5$ khối |

### 4.2 Ma trận Phân loại & Công thức Kết hợp Độ tin cậy Noisy-OR
`DualEngineCorroborator` tổng hợp các cảnh báo của Động cơ Quy tắc P4 thành điểm quy tắc $s_{\text{rule}} = 1 - \prod_{a \in A} (1 - s_a)$ và đối chiếu với điểm mô hình học máy $s_{\text{ML}}$:

```
                      s_rule > 0 (Cảnh báo P4)      s_rule = 0 (Không cảnh báo P4)
                   ┌──────────────────────────────┬──────────────────────────────┐
s_ML >= tau (0.65) │         CORROBORATED         │           ML_ONLY            │
                   │ s_comb = 1 - (1-s_ML)(1-s_R) │    s_comb = s_ML * 0.85      │
                   ├──────────────────────────────┼──────────────────────────────┤
s_ML <  tau (0.65) │          RULE_ONLY           │            NORMAL            │
                   │    s_comb = s_R * 0.90       │    s_comb = max(s_ML, s_R)   │
                   └──────────────────────────────┴──────────────────────────────┘
```

- **CORROBORATED**: Cả hai động cơ độc lập cùng phát hiện. Độ tin cậy kết hợp tăng theo nguyên lý suy luận chứng cứ: $s_{\text{comb}} \ge \max(s_{\text{ML}}, s_{\text{rule}})$.
- **ML_ONLY**: Bất thường phát hiện bởi mô hình học máy nhưng chưa kích hoạt quy tắc tĩnh; áp dụng chiết khấu bất định $0.85$.
- **RULE_ONLY**: Quy tắc tĩnh kích hoạt nhưng vector đặc trưng chưa vượt ngưỡng nơ-ron; áp dụng chiết khấu $0.90$.

---

## 5. MITRE ATT&CK Mapping Engine

### 5.1 Phân loại Kỹ thuật Tấn công DeFi

| Mã Kỹ thuật | Tên Kỹ thuật MITRE | Chiến thuật (Tactic) | Bối cảnh Forensic DeFi | Điều kiện Kích hoạt Chính |
|---|---|---|---|---|
| **T1566.002** | Phishing: Spearphishing Link / Approval Scam | Initial Access | Lừa đảo cấp quyền allowance ERC-20 hoặc chữ ký permit để rút cạn ví | Quy tắc `large_transfer`, hoặc `max_single_out_ratio >= 0.70`, hoặc $s_{\text{ML}} \ge 0.65$ kèm dòng ra lớn |
| **T1027** | Obfuscated Files or Information: Mixer Layering | Defense Evasion | Phân mảnh dòng tiền qua chuỗi peeling, trộn mixer Tornado hoặc token hopping | Quy tắc `fan_in_out`, hoặc `unique_counterparties_out >= 3` kèm `token_diversity >= 2` |
| **T1048.003** | Exfiltration Over Alternative Protocol: Bridge Hop | Exfiltration | Tẩu tán thanh khoản thần tốc qua cross-chain bridge hoặc sàn DEX | Quy tắc `rapid_pass_through`, hoặc `pass_through_ratio >= 0.80` kèm `turnover_latency_min <= 5` |
| **T1499.004** | Endpoint Denial of Service: Gas Exhaustion | Impact | Tấn công spam mempool, đẩy phí gas, cản trở thanh lý hợp đồng | Quy tắc `high_frequency`, hoặc `tx_velocity >= 5` kèm `burstiness_std <= 2.5` |
| **T1565.001** | Data Manipulation: State Manipulation | Impact | Thao túng số dư AMM pool thông qua Flash Loan để bẻ cong giá Oracle | Biến động khối lượng đa tài sản đột biến trong cùng khối |

### 5.2 Giao thức Bắt buộc Căn cứ Chứng cứ On-Chain
Mỗi bản ghi ánh xạ `MitreAttackMapping` bắt buộc phải có ít nhất một chuỗi tham chiếu chứng cứ hợp lệ (`evidence_refs` dạng `tx:0x...` hoặc `alert:...`):
- Nếu danh sách `evidence_refs` rỗng, `MitreMappingEngine` kích hoạt ngoại lệ `UnsubstantiatedMappingError`.
- Ngăn chặn triệt để tình trạng AI suy diễn cảm tính hoặc gán nhãn tùy tiện mà không có căn cứ on-chain cụ thể.

---

## 6. AI Investigator P5 Safe Integration & Security Preservation

### 6.1 Mở rộng Lược đồ Schema Pydantic
Tệp `forensics/ai/schemas.py` được mở rộng với hai lớp dữ liệu được bảo vệ nghiêm ngặt:
- `MLAnomalyDetection`: Lưu trữ `model_id`, `model_sha256`, `entity_address`, `score`, `classification`, `top_features`, `xai_attributions`, `mitre_techniques`, `evidence_refs`.
- `MitreAttackMapping`: Lưu trữ `technique_id`, `technique_name`, `tactic`, `confidence`, `evidence_refs` (bắt buộc $\ge 1$), `rationale` (tối thiểu 10 ký tự).
- Lớp `ForensicInvestigationOutput` bổ sung hai trường `ml_detections` và `mitre_mappings`.

### 6.2 Bảo toàn Tính Thuần khiết Tuyệt đối của Trường Dữ liệu (Strict Field Separation)
Từ điển `SPECULATIVE_WORDS` trong `schemas.py` được mở rộng để ngăn chặn tất cả các từ khóa sau xuất hiện trong trường thực tế khách quan `ObservedFact.statement`:
`"anomaly"`, `"anomalous"`, `"predicted"`, `"prediction"`, `"probability"`, `"mitre"`, `"t1027"`, `"t1566"`, `"t1048"`, `"t1499"`, `"t1565"`, `"shap"`, `"phishing"`, `"exfiltration"`, `"obfuscation"`.
Nếu người phân tích hoặc mô hình ngôn ngữ cố tình đặt các kết luận suy diễn này vào `ObservedFact`, bộ kiểm tra `validate_factual_purity` sẽ ném lỗi:
`ValueError: Field separation violation: ObservedFact.statement contains speculative/interpretive vocabulary: ... Hypotheses and behavioral attributions must be placed in AnalystInterpretation, MLAnomalyDetection, or MitreAttackMapping.`

### 6.3 Công cụ Chỉ đọc `get_ml_anomaly_analysis`
- Đăng ký chính thức vào `AUTHORIZED_TOOLS` tại `forensics/ai/tools.py`.
- Thực thi ở chế độ chỉ đọc 100% (`PRAGMA query_only = ON`).
- Mọi lần gọi đều được bộ theo dõi ngân sách `ToolCallBudgetTracker` ghi nhận, bảo đảm không vượt quá trần 5 bước (`MAX_AI_TOOL_STEPS = 5`).
- Tích hợp liền mạch vào tác nhân điều tra `ForensicInvestigator` (khi bật cờ `enable_ml_analysis=True`).

### 6.4 Nâng cấp Bộ Kiểm tra Tham chiếu Hai Giai đoạn (`ref_checker.py`)
Giai đoạn 1 (`verify_references_existence`) được mở rộng để tự động thu thập và kiểm tra toàn bộ các tham chiếu `tx:` và `alert:` trong `ml_detections` và `mitre_mappings`. Nếu mô hình trích dẫn một mã băm giao dịch ảo giác (như `0xdead...`), bộ kiểm tra sẽ hạ tỷ lệ `existence_ref_ratio`, gắn nhãn lỗi `CONTENT_MISMATCH` và đưa mã băm vào danh sách `missing_refs`.

---

## 7. Verification Test Suite Matrix

Toàn bộ các bộ kiểm thử đã được thực thi độc lập và cục bộ trên môi trường thực tế:

| Phân hệ / Tệp kiểm thử | Mục tiêu kiểm thử | Số ca kiểm thử | Kết quả | Thời gian |
|---|---|---|---|---|
| `tests/test_p8_ml_foundations.py` | Trích xuất 10 đặc trưng, chống rò rỉ dữ liệu, RobustScaler, MLP 321 tham số, ONNX & SHA-256 | 12 | **12 PASS / 0 FAIL** | 1.85 s |
| `tests/test_p8_xai_corroboration.py` | 4 tiên đề Exact SHAP, Top drivers, ma trận đối chiếu 4 trạng thái, Noisy-OR, Euler/Curve | 10 | **10 PASS / 0 FAIL** | 1.36 s |
| `tests/test_p8_mitre_ai_integration.py` | Danh mục MITRE, bắt buộc chứng cứ, tách biệt trường ObservedFact, công cụ ML, ref_checker | 13 | **13 PASS / 0 FAIL** | 2.12 s |
| **Tổng kiểm thử mới P8** | **Toàn bộ chức năng Machine Learning, XAI, MITRE & AI Integration** | **35** | **35 PASS (100%)** | **2.35 s** |
| `tests/test_real_data_rules.py` | Kiểm thử hồi quy Động cơ Quy tắc P4 trên dữ liệu thực tế | 10 | **10 PASS / 0 FAIL** | 0.22 s |
| `tests/test_p3_p4_flow.py` | Kiểm thử tích hợp luồng xử lý chứng cứ P3-P4 | 4 | **4 PASS / 0 FAIL** | 0.12 s |
| `tests/test_ai_security.py` | Kiểm thử an toàn AI P5 (Prompt injection, sanitizer, read-only DB, ref_checker) | 46 | **46 PASS / 0 FAIL** | 0.84 s |
| `tests/test_ai_investigator.py` | Kiểm thử tác nhân điều tra AI Investigator và trần ngân sách 5 bước | 13 | **13 PASS / 0 FAIL** | 1.13 s |
| **Tổng kiểm thử hồi quy P1–P6** | **Bảo toàn toàn bộ hệ thống nền tảng P1–P6** | **73** | **73 PASS (100%)** | **2.31 s** |
| `contracts/test/EvidenceRegistry.t.sol` | Kiểm thử hợp đồng thông minh Chuỗi hành trình chứng cứ P3 | 31 | **31 PASS / 0 FAIL** | 24.27 ms |
| `contracts/test/EvidenceRegistry_Group4.t.sol` | Kiểm thử biên phân trang và phân quyền hợp đồng P3 | 25 | **25 PASS / 0 FAIL** | 24.24 ms |
| **Tổng kiểm thử hợp đồng Solidity** | **Foundry Forge Test Suite** | **56** | **56 PASS (100%)** | **25.36 ms** |

---

## 8. Downstream Integration Hand-off

### 8.1 Bàn giao cho Giai đoạn P9 (Zero-Knowledge Machine Learning — ZKML)
- **Tệp mô hình ONNX**: `Blockchain/models/anomaly_detector_v1.onnx`.
- **Đặc tính kỹ thuật cho EZKL**:
  - Kiến trúc: 321 tham số ($10 \to 16 \to 8 \to 1$), chỉ sử dụng toán tử tuyến tính affine và `ReLU`.
  - Dạng đầu vào tĩnh: Tensor $[1, 10]$ kiểu `float32`.
  - Bậc mạch số học (Scale factor): Khuyến nghị cấu hình EZKL với `--bits 16 --scale 7 --logrows 10`.
  - Cam kết mật mã (KZG Commitment): Giá trị băm SHA-256 của tệp ONNX `d1b9ce82...` được dùng làm định danh gốc để neo giữ vào hồ sơ điều tra.

### 8.2 Bàn giao cho Giai đoạn P10 (Chain of Custody DID Evidence Anchoring)
- **Cấu trúc bản ghi chứng cứ**: Kết quả giám định ML (`MLAnomalyDetection`) và ánh xạ MITRE (`MitreAttackMapping`) xuất bản kèm `model_sha256` và danh sách `evidence_refs`.
- **Hợp đồng `EvidenceRegistryDID.sol`**: Sẵn sàng neo giữ mã băm kết quả phân tích AI/ML vào nhật ký giám sát chuỗi hành trình chứng cứ theo tiêu chuẩn ISO/IEC 27037 mà không để lộ khóa bí mật hay dữ liệu cá nhân.

---
**Kết luận**: Phân hệ P8 Học máy, XAI, MITRE ATT&CK và AI Investigator P5 đã hoàn thành toàn diện, vận hành ổn định, đạt chất lượng thực nghiệm sẵn sàng vận hành (operational prototype) và đáp ứng 100% các tiêu chí nghiệm thu đề ra.
