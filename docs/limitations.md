# Tài liệu Giới hạn Kỹ thuật Hệ thống (System Limitations)

Tài liệu này ghi nhận trung thực và minh bạch toàn bộ các giới hạn kỹ thuật của hệ thống Blockchain Forensics tính đến giai đoạn P2, phục vụ công tác điều tra số và đánh giá bằng chứng pháp lý.

---

## 1. Cơ chế Kiểm tra Toàn vẹn Cục bộ vs. Neo Chứng cứ On-chain

Hệ thống cung cấp ba cơ chế kiểm tra toàn vẹn ở tầng dữ liệu cục bộ:
- `verify-local`: Tính toán lại hàm băm SHA-256 trên nội dung JSON chuẩn hóa của các bảng `blocks`, `transactions`, `receipts` và kiểm tra tính liên tục của `parentHash` giữa các block liền kề trong cơ sở dữ liệu SQLite.
- `verify-derived`: Đối chiếu tính toán độc lập của bảng `asset_transfers` từ dữ liệu thô (giao dịch ETH và sự kiện `Transfer` ERC-20 trong `logs`) nhằm phát hiện sai lệch logic trích xuất.
- `verify-manifest`: Băm lại toàn bộ các tệp vật lý trong gói chứng cứ trên đĩa (`raw_blocks.jsonl`, `timeline.csv`, `asset_transfers.csv`, `audit_events.jsonl`), so sánh với kích thước và SHA-256 được mô tả trong `manifest.json`, đồng thời đối chiếu với bảng `evidence_exports` trong SQLite.

### Giới hạn kỹ thuật quan trọng:
- **Phạm vi bảo vệ:** Các cơ chế trên được thiết kế để **phát hiện sai lệch dữ liệu (tamper-detection)** do lỗi phần cứng lưu trữ, sự cố sao chép file, hoặc chỉnh sửa sơ suất trên một bảng/tệp đơn lẻ.
- **Không có khả năng chống sửa đổi chủ đích toàn diện:** Một đối tượng có quyền ghi (write access) trên hệ thống tập tin cục bộ có thể sửa đổi đồng thời cả nội dung dữ liệu thô, tính toán lại giá trị SHA-256 tương ứng để ghi đè vào SQLite, sinh lại tệp `manifest.json` và cập nhật lại bảng `evidence_exports`. Do đó, hệ sinh thái cục bộ **tuyệt đối không sử dụng thuật ngữ "chống giả mạo" (tamper-proof)**.
- **Tính bất biến thực sự:** Khả năng chứng minh tính toàn vẹn không thể chối cãi chỉ đạt được khi giá trị băm `manifest_sha256` được neo vào hợp đồng thông minh công khai bất biến (`EvidenceRegistry.sol`) trên blockchain với chữ ký số xác thực của điều tra viên (triển khai ở giai đoạn P3).

---

## 2. Giới hạn Thu thập Giao dịch Nội bộ (Internal Transactions)

- **Nguyên lý thu thập:** Bộ thu thập (`collector.py`) kết nối với các node Ethereum qua giao thức chuẩn JSON-RPC (`eth_getBlockByNumber`, `eth_getBlockReceipts` hoặc `eth_getTransactionReceipt`).
- **Giao dịch nội bộ (Internal Transactions):** Các giao dịch chuyển giao giá trị nội bộ sinh ra bởi chỉ lệnh `CALL`, `DELEGATECALL`, hoặc `SELFDESTRUCT` bên trong các smart contract (ví dụ: rút tiền từ hợp đồng đa chữ ký, router sàn DEX Uniswap chuyển ETH ra ví người dùng, hoặc các cuộc tấn công re-entrancy) **không phát sinh transaction envelope riêng biệt và không có receipt riêng**.
- **Hệ quả pháp y:** Bảng `asset_transfers` chỉ ghi nhận:
  1. Chuyển ETH gốc ở tầng giao dịch cấp cao (`transactions.value > 0`).
  2. Chuyển token ERC-20 phát ra sự kiện log tiêu chuẩn `Transfer(address,address,uint256)`.
- **Giải pháp yêu cầu:** Để thu thập đầy đủ toàn bộ luồng luân chuyển giá trị nội bộ này, hạ tầng bắt buộc phải cấu hình node Archive/Tracing có kích hoạt Tracer API chuyên dụng (`debug_traceTransaction` hoặc `trace_block` với call tracer).

---

## 3. Tính chất Dữ liệu Môi trường Thử nghiệm Sepolia Testnet

- **Đặc điểm dữ liệu:** Sepolia là mạng thử nghiệm công khai (public testnet), chịu nhiều lưu lượng thử nghiệm mang tính ngẫu nhiên, faucet spam, test bot, và triển khai hợp đồng thử nghiệm không tuân theo các quy luật kinh tế thực tế của Ethereum Mainnet.
- **Thiếu nhãn chuẩn (Ground Truth):** Sepolia không có các bộ dữ liệu nhãn công khai chuẩn hóa về các vụ tấn công exploit, rửa tiền hoặc trừng phạt kinh tế như trên Mainnet.
- **Phương pháp đánh giá trên Sepolia:** Không thể tính toán trực tiếp các chỉ số `Recall` hay `False Positive Rate (FPR)` trên Sepolia. Thay vào đó, việc đánh giá chỉ có thể thực hiện thông qua phương pháp lấy mẫu ngẫu nhiên $N$ cảnh báo (alerts) cho điều tra viên rà soát thủ công (`reviews`) để ước lượng độ chuẩn xác `Estimated Precision` kèm khoảng tin cậy Wilson 95%.

---

## 4. Yêu cầu về Node Lưu trữ Lịch sử (Archive Node)

- **Full Node tiêu chuẩn:** Các Full Node thông thường chỉ lưu trữ trạng thái thế giới (world state) của các block gần nhất và thường xuyên cắt tỉa (prune) trạng thái lịch sử cũ để tiết kiệm dung lượng đĩa.
- **Hạn chế khi Replay:** Khi thực hiện tái lập (replay) các sự cố bảo mật trong lịch sử hoặc chạy fork từ một block cũ cách xa hiện tại (`anvil --fork-url <RPC> --fork-block-number <N>`), nếu RPC nguồn không phải là Archive Node thì các lệnh truy vấn số dư, storage hoặc receipts của các block cũ sẽ bị node từ chối phục vụ. Do đó, quy trình tái lập sự cố thực nghiệm bắt buộc phải có quyền truy cập vào Archive RPC.
