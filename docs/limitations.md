# Tài liệu Giới hạn Kỹ thuật Hệ thống (System Limitations)

Tài liệu này ghi nhận trung thực và minh bạch toàn bộ các giới hạn kỹ thuật của hệ thống Blockchain Forensics tính đến giai đoạn P3, phục vụ công tác điều tra số và đánh giá bằng chứng pháp lý.

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

- **Full Node tiêu chuẩn:** Các Full Node thông thường lưu trữ đầy đủ khối (blocks), giao dịch (transactions) và biên lai (receipts) trong lịch sử. Tuy nhiên, Full Node định kỳ cắt tỉa (prune) trạng thái thế giới (world state — số dư tài khoản, biến lưu trữ storage của smart contract) của các block cũ và không hỗ trợ Trace API cho các giao dịch lịch sử cách xa hiện tại.
- **Hạn chế khi Replay:** Khi thực hiện tái lập (replay) các sự cố bảo mật trong lịch sử hoặc chạy fork từ một block cũ (`anvil --fork-url <RPC> --fork-block-number <N>`), nếu cần truy cập trạng thái tài khoản/storage lịch sử hoặc chạy công cụ phân tích trace (`debug_traceTransaction` / `trace_block`), Full Node sẽ từ chối do đã prune state. Khi đó, quy trình tái lập sự cố bắt buộc phải có quyền truy cập vào Archive RPC Node có kích hoạt tracer.

---

## 5. Rủi ro Lộ Khóa & Thu hồi Quyền Investigator khi Chuyển quyền Quản trị (Ownership Transfer)

- Trong mô hình phân quyền của `EvidenceRegistry.sol`, việc chuyển giao quyền sở hữu diễn ra khi thay đổi điều hành viên hoặc bàn giao hệ thống điều tra.
- Khi chuyển quyền qua cơ chế 2 bước (`transferOwnership` và `acceptOwnership`), hợp đồng bắt buộc phải **tự động thu hồi quyền điều tra viên của owner cũ** (`authorizedInvestigators[oldOwner] = false`). Điều này nhằm triệt tiêu **rủi ro lộ khóa riêng tư (key compromise)**: nếu khóa riêng tư của owner cũ sau này bị lộ, bị lưu trữ thiếu an toàn hoặc bị chuyển giao cho bên thứ ba, kẻ tấn công không thể sử dụng khóa cũ này để đăng ký bằng chứng giả mạo hay ghi đè lịch sử hành trình (custody events). Nếu owner mới muốn cấp lại quyền cho địa chỉ đó làm điều tra viên, họ phải gọi `setInvestigator` một cách tường minh.

---

## 6. Chính sách Quản lý Khóa & Quy chuẩn An toàn On-chain (P3 Hardening)

1. **Xử lý `storageUri` trong `EvidenceRegistry.sol`**:
   - Hợp đồng giới hạn độ dài byte `1 <= bytes(storageUri).length <= 256` (revert `ZeroValue` nếu rỗng và `UriTooLong` nếu vượt quá 256 bytes).
   - Bất biến chuỗi không khoảng trắng được cưỡng chế trực tiếp on-chain thông qua hàm nội bộ `_isNonWhitespace`: nếu chuỗi chỉ toàn ký tự khoảng trắng (space 0x20, tab 0x09, newline 0x0A, carriage return 0x0D), hợp đồng sẽ lập tức revert với custom error `WhitespaceUri()`. Client-side (`forensics/onchain.py`) đồng thời thực hiện chuẩn hóa và `strip()` chuỗi trước khi gửi.
2. **Quy trình chuyển quyền quản trị 2 bước và hủy đề cử đang chờ**:
   - `transferOwnership` từ chối `address(0)` (`ZeroValue`) và từ chối chính chủ sở hữu hiện tại (`SameOwner`) nhằm ngăn ngừa tự khóa (self-lockout) làm mất quyền investigator.
   - Nếu đang tồn tại một đề cử chuyển quyền chưa được chấp thuận (`pendingOwner != address(0)`), các lệnh đề cử mới sẽ bị chặn với lỗi `PendingTransferExists(pendingOwner)`. Chủ sở hữu hiện tại bắt buộc phải gọi `cancelOwnershipTransfer()` một cách tường minh trước khi đề cử địa chỉ mới.
   - Khi `acceptOwnership()` được thực thi, chủ sở hữu mới tự động được cấp quyền investigator (`authorizedInvestigators[newOwner] = true`), đồng thời quyền investigator của chủ sở hữu cũ bị thu hồi ngay lập tức (`authorizedInvestigators[oldOwner] = false`).
3. **Chốt chặn an toàn khóa (Key Safety Guard), Loopback RPC & Ràng buộc Keystore**:
   - Phương thức gửi giao dịch qua `--unlocked` / `--from` CHỈ được phép hoạt động trên chuỗi Anvil (`chain_id == 31337`) VÀ RPC endpoint bắt buộc phải là địa chỉ loopback cục bộ (`127.0.0.1`, `localhost`, `::1`). Bất kỳ RPC từ xa nào (dù khai báo chain ID 31337) đều bị từ chối chế độ unlocked và bắt buộc phải dùng Foundry keystore (`--account`).
   - Giao dịch ghi on-chain (`anchor`, `custody`) TUYỆT ĐỐI KHÔNG cho phép cờ ghi đè (`--override-chain-id`) nhằm loại trừ hoàn toàn nguy cơ vô tình thực thi trên Ethereum Mainnet hoặc các mạng trái phép.
   - Trên các mạng công khai (Sepolia `11155111` hoặc các chain khác), hệ thống bắt buộc sử dụng keystore đã mã hóa (`--account` và tùy chọn `--password-file`). Tuyệt đối không cho phép truyền khóa riêng tư trực tiếp qua đối số dòng lệnh hoặc biến môi trường.
   - Hệ thống từ chối mọi giao dịch sử dụng 10 tài khoản mặc định của Anvil trên bất kỳ mạng nào có `chain_id != 31337`.
4. **Kiểm tra trạng thái Working Tree khi Neo Bằng chứng (Anchor)**:
   - Hệ thống đối soát cả trường `working_tree_dirty` trong tệp `manifest.json` và trạng thái thực tế từ Git (`git status --porcelain`) tại thời điểm thực thi lệnh `anchor`.
   - Các tệp nhật ký thực thi runtime (`*.log`) được loại trừ khỏi kiểm tra dirty-tree vì chúng là kết quả đầu ra của chính kịch bản chạy thử nghiệm, trong khi toàn bộ mã nguồn, cấu hình và tệp chứng cứ được giám sát nghiêm ngặt.
   - Nếu phát hiện thư mục làm việc chưa sạch, lệnh sẽ bị từ chối trừ khi người dùng chỉ định rõ cờ `--allow-dirty`. Việc sử dụng cờ này sẽ được ghi nhận bền vững vào bảng `audit_events` và bảng `custody_events` trong cơ sở dữ liệu SQLite để phục vụ truy vết.
