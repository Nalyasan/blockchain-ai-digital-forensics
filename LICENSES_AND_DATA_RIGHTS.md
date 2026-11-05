# GIẤY PHÉP PHẦN MỀM, QUYỀN SỬ DỤNG DỮ LIỆU VÀ GIỚI HẠN PHÁP CHỨNG (`LICENSES_AND_DATA_RIGHTS.md`)

- **Dự án**: Điều tra số kết hợp Blockchain và AI (*Blockchain + AI Digital Forensics* — Academic PoC)
- **Đặc tả tham chiếu**: `AGENT.md` v6.0 (§9.3, §10, §15)

---

## 1. Quyền sở hữu mã nguồn dự án (Academic Research PoC)

Mã nguồn của hệ thống (bao gồm `collector.py`, gói `forensics/`, hợp đồng thông minh trong `contracts/`, kịch bản thực nghiệm trong `scripts/` và bộ kiểm thử trong `tests/`) được phát triển cho mục đích **nghiên cứu học thuật và minh chứng khái niệm (Proof of Concept)** trong khuôn khổ học phần *Ứng dụng Blockchain trong An toàn thông tin (Đề tài 8)*.

- Mã hợp đồng thông minh (`EvidenceRegistry.sol`, `EvidenceRegistryDID.sol`, `InferenceVerifier.sol`, `Halo2Verifier.sol`) khai báo `SPDX-License-Identifier: MIT`.
- Phần mềm được cung cấp nguyên trạng (*"AS IS"*) phục vụ kiểm tra học thuật, giảng dạy và tái lập kết quả thực nghiệm; không đi kèm cam kết bảo hành thương mại hay chứng nhận pháp lý.

---

## 2. Giấy phép công cụ và thư viện bên thứ ba đi kèm

1. **Foundry Toolchain (`tools/foundry/forge.exe`, `anvil.exe`, `cast.exe`)**:
   - Phân phối theo giấy phép kép **Apache License 2.0 / MIT License** của dự án Foundry (`foundry-rs/foundry`).
2. **Thư viện Python đóng gói trong `wheels/` và khóa trong `requirements.lock.txt`**:
   - Các gói mã nguồn mở (`pydantic`, `pydantic-ai`, `pytest`, `cryptography`, `httpx`, `rich`, `numpy`, `onnx`, `torch`, `ezkl`, v.v.) giữ nguyên giấy phép gốc của từng nhà phát triển (MIT, BSD-3-Clause, Apache-2.0, MPL-2.0 / AGPL/Apache tùy thành phần; chi tiết nằm trong thư mục `*.dist-info/LICENSE*` bên trong từng tệp `.whl`).
   - Lưu ý riêng về `pymupdf`: sử dụng trong phạm vi nghiên cứu học thuật phi thương mại; nếu tái phân phối thương mại cần tuân thủ điều khoản AGPL-3.0 hoặc giấy phép thương mại của Artifex.

---

## 3. Nguồn gốc và quyền sử dụng các tập dữ liệu đi kèm (`AGENT.md` §9.3)

| Tệp / Tập dữ liệu | Nguồn gốc dữ liệu | Quyền sử dụng & Ràng buộc phân phối |
|---|---|---|
| `data/forensics.db` | Dữ liệu khối/giao dịch cơ sở phục vụ kiểm thử nội bộ hệ thống. | Chỉ dùng cho kiểm thử học thuật nội bộ; giữ nguyên mã băm SHA-256 chuẩn (`3F2B0DFC...`). |
| `data/real_p4.db` | Dữ liệu giao dịch lịch sử công khai trên chuỗi khối Ethereum Mainnet quanh hai sự cố Euler Finance (khối `16816000–16818110`) và Curve/Alchemix (`17700000–17806830`). | Dữ liệu sổ cái công khai Ethereum; chỉ đọc (`mode=ro`) để tái lập thực nghiệm phát hiện bất thường và truy vết chứng cứ. Không chứa PII ngoài chuỗi. |
| `data/benchmark_p6.db` — Nguồn **Forta** (`15,259` bản ghi) & **MyEtherWallet Darklist** (`715` bản ghi) | Nguồn tình báo mối đe dọa công khai trên GitHub (Forta Scam Detector feeds & MEW `ethereum-lists`). | Dữ liệu công khai theo giấy phép mở của kho nguồn; được gắn nhãn `ExternalThreatLabel` (không tự động đồng nhất với sự thật đã xác minh độc lập). |
| `data/benchmark_p6.db` — Nguồn **PTXPhish** (`18,867` bản ghi, bao gồm cả mẫu đối chứng lành tính `BENIGN_CONTROL`) | Tập dữ liệu nghiên cứu học thuật về lừa đảo trên Ethereum (PTXPhish). | **DỮ LIỆU NGHIÊN CỨU CÓ ĐIỀU KIỆN (`CONDITIONAL ACADEMIC RESEARCH ARTIFACT`)**: Chỉ được phép lưu hành nội bộ phục vụ kiểm tra/chấm điểm học thuật offline của đề tài. **Nghiêm cấm** đóng gói phân phối thương mại, phát tán công khai đại trà hoặc tải tập dữ liệu này lên các dịch vụ đám mây / API trả phí bên ngoài (`AGENT.md` §9.3 & §15). |
| `tests/fixtures/` & Dữ liệu mẫu Host Log (Demo D2) | Tệp nhật ký sự kiện máy chủ giả lập hợp lệ (`synthetic=true`) phục vụ minh chứng quy trình ISO/IEC 27037. | Dữ liệu giả lập an toàn, không thu thập từ máy người dùng thật, không chứa bí mật hay thông tin định danh cá nhân (PII). |

---

## 4. Tuyên bố miễn trừ về quyền riêng tư, GDPR và giá trị pháp chứng (`AGENT.md` §15)

1. **Không tuyên bố giá trị chứng cứ tự động trước tòa**: Hệ thống là nguyên mẫu nghiên cứu học thuật (*Academic PoC*). Mặc dù áp dụng cấu trúc đóng gói theo nguyên tắc ISO/IEC 27037, cây Merkle, chữ ký số EIP-712 và neo mã băm lên hợp đồng thông minh, giá trị pháp lý của chứng cứ số trong tố tụng thực tế còn phụ thuộc vào thẩm quyền thu thập, quy trình pháp luật sở tại và giám định độc lập đối với thiết bị nguồn.
2. **Giới hạn về quyền riêng tư và GDPR trên chuỗi khối**: Hệ thống tuân thủ nguyên tắc chỉ ghi mã băm mật mã (`SHA-256`, commitments), định danh giả danh (`DID`, địa chỉ ví) và trạng thái sự kiện lên hợp đồng thông minh Anvil cục bộ — tuyệt đối không ghi nhật ký thô, khóa bí mật hoặc PII trực tiếp lên chuỗi. Tuy nhiên, mã băm chứng cứ và địa chỉ ví vẫn có khả năng liên kết ngược (*linkable pseudonymous data*); hệ thống **không tuyên bố tự động tuân thủ toàn diện GDPR** hay đảm bảo ẩn danh tuyệt đối.
3. **Giới hạn của ML, XAI và ZKML**:
   - Kết quả từ Rule Engine, mô hình ML và XAI chỉ là tín hiệu hỗ trợ điều tra (*investigative leads*), không phải kết luận buộc tội.
   - Bằng chứng ZKML (Halo2 / EZKL) chỉ chứng minh tính nhất quán toán học rằng phép suy luận đã cam kết được thực thi đúng theo mạch và trọng số mô hình đã cố định; ZKML **không** chứng minh dữ liệu đầu vào trung thực lúc thu thập hay mô hình không có sai số thống kê.
