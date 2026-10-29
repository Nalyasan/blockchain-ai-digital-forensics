# Tài liệu Giới hạn Kỹ thuật Hệ thống (System Limitations)

## Cập nhật P3 — nhóm 1b (29/10/2026)

- `scripts/run_p3_group1b_checks.py` chạy `forge test --root contracts` và `python -m pytest tests/ -q` trong bản sao tạm có SHA-256 đối chiếu từng file nguồn. Chỉ sao chép danh sách nguồn, công cụ và fixture cho phép; không mở, băm, sao chép `.env` hoặc kế thừa biến RPC/ví/API của người dùng. Foundry biên dịch offline. Bản sao không có `.git`; kiểm thử guard dirty-tree vẫn thuộc các test riêng của nhóm 1, không suy diễn từ smoke này.
- `scripts/run_p3_group1b_smoke.py` chạy Anvil thật trên `127.0.0.1`, cổng riêng, chain 31337, không fork. Deploy bytecode vừa biên dịch; tạo ví mã hóa bằng cast thật, nạp tiền và cấp quyền chỉ trên Anvil. Đối chiếu địa chỉ từ keystore với transaction, receipt, registeredBy, custody actor và SQLite. Gói/DB mẫu được sao chép; hash mẫu gốc phải giữ nguyên.
- Trên Windows với cast 1.8.6, đổi HOME/USERPROFILE không chuyển thư mục tra cứu `--account`. Harness vì vậy đặt **một tệp keystore tên ngẫu nhiên, được tạo độc quyền** trong thư mục Foundry mặc định; chỉ tài khoản hiện tại và SYSTEM được cấp quyền. Mật khẩu nằm trong thư mục tạm riêng. Harness xóa đúng tệp nó tạo khi kết thúc; không sửa hoặc liệt kê ví sẵn có. Nếu bị kill cưỡng bức hoặc mất điện, việc cleanup không được bảo đảm; không dùng ví smoke ngoài Anvil. Đường chạy này đã kiểm tra trên Windows; không tuyên bố tương thích mọi hệ điều hành.
- Mật khẩu tạo ví được truyền qua môi trường riêng của đúng subprocess tạo ví, không qua argv; thao tác ký dùng password-file. Không ghi stdout/stderr thô của công cụ ví. Anvil stdout/stderr bị loại bỏ vì lúc khởi động có thể chứa khóa mặc định. Mọi lỗi báo ra dùng stage/type/mã lỗi hoặc nhãn chẩn đoán hữu hạn.
- Ca từ chối chạy cả anchor và custody: lệch `--from`/ANCHOR_FROM, sai mật khẩu, thiếu keystore, thiếu bytecode, lệch chain cấu hình với RPC, client không phải Anvil, RPC không đáp ứng, HTTP ngoài loopback, HTTPS ngoài loopback và thiếu keystore trên chain khác 31337. Với lời gọi trực tiếp, observer chuyển nguyên lời gọi tới cast thật, kiểm tra không có `cast send`; nonce, block height, nextEvidenceId và DB phải không đổi. CLI cũng kiểm tra lệch `--from` với exit 1 và trạng thái không đổi.
- Các chain 11155111 và 1 được **mô phỏng bằng proxy chỉ đọc trên loopback**; mọi phương thức ngoài allowlist đọc đều bị từ chối. Mười địa chỉ được suy ra bằng cast thật và đối chiếu eth_accounts của Anvil. Mainnet bị chặn ở allowlist trước bước kiểm tra tài khoản; Sepolia mô phỏng kiểm tra danh sách tài khoản mặc định. Đây không phải kiểm thử trên mạng công khai. Với ca URL HTTPS ngoài loopback, harness chỉ chuyển tuyến các truy vấn đọc về Anvil cục bộ, không giả kết quả RPC và không kết nối host ngoài.
- Redaction được kiểm chứng bằng lỗi RPC có canary đi qua stderr của cast thật: chuỗi 64 hex có/không `0x`, mật khẩu giả, cụm 12 từ giả và API token giả. Harness xác nhận lỗi gốc có các canary, sau đó kiểm tra chúng không xuất hiện trong thông báo ứng dụng, stdout/stderr ứng dụng, log, DB/audit hoặc báo cáo. Các mật khẩu ví tạm và token lỗi kết nối cũng được kiểm tra. Đây không phải bằng chứng rằng mọi đường lỗi trong toàn dự án đều đã được rà soát.
- Rà lại diff `2d5eb3e^..2d5eb3e`: thực tế có **ba hàm test cũ** thay đổi, không phải hai: `test_chain_id_allowlist` bỏ chấp nhận override và kiểm tra API từ chối tham số đã bỏ; `test_chain_id_write_override_blocked` bỏ đối số không còn được hỗ trợ, vẫn kiểm tra chặn chain; `test_non_loopback_rpc_rejected_for_unlocked` đổi URL sang HTTPS để kiểm tra đúng guard unlocked. Nhóm 1b không xóa, bỏ qua hoặc sửa các test cũ này.

Nhóm 1b chỉ xác minh khóa/guard và cách chạy kiểm thử an toàn. Các lỗi integrity, export append-only, bảo vệ caseId, noteHash/idempotency và định dạng URI/phân trang vẫn chờ nhóm 2–5; không triển khai P4 và chưa được phép ký/deploy Sepolia/Mainnet.

## Cập nhật P3 — nhóm 1 (29/10/2026)

- Guard của `anchor` và `custody` lấy địa chỉ thật bằng `cast wallet address --account`, đối chiếu với `--from`/`ANCHOR_FROM` nếu có, rồi mới kiểm tra chain và danh sách Anvil. Receipt phải có `from` khớp signer; địa chỉ này được ghi vào DB.
- Mười địa chỉ Anvil được tính bằng cast tại runtime. Không có fallback tĩnh; thiếu cast, timeout, đầu ra sai hoặc địa chỉ trùng đều chặn thao tác trên chain khác 31337. So sánh địa chỉ không phân biệt hoa/thường và chấp nhận đầu vào có/không có `0x`.
- Mọi `cast send` của hai luồng được cố định `--chain` theo chain đã kiểm tra. API không còn `override_chain_id`. RPC chỉ nhận http/https, yêu cầu HTTPS ngoài loopback; truy vấn Python từ chối redirect. `--unlocked` còn yêu cầu chain 31337, loopback và clientVersion nhận diện Anvil. Kiểm tra tên client là lớp phòng vệ bổ sung; RPC độc hại vẫn có thể giả câu trả lời.
- Trước gửi phải có bytecode contract. Việc có bytecode chưa chứng minh đó là đúng phiên bản EvidenceRegistry; xác minh/ghim contract và toàn vẹn gói thuộc nhóm 2.
- Cast chạy với `shell=False`, timeout; loại các cấu hình ví ETH_/TEMPO_, PRIVATE_KEY và CHAIN kế thừa khỏi môi trường subprocess. Lỗi cast/RPC dùng mã và thông điệp cố định, không chuyển tiếp stdout/stderr/args. Timeout gửi là trạng thái chưa xác định, không tự thử gửi lại; sidecar/reconcile thuộc nhóm 3.
- Kiểm thử nhóm 1 dùng mock RPC và mock gửi giao dịch. Test so mười địa chỉ chạy cast thật ngoại tuyến, không ký hoặc phát giao dịch.

Các bổ sung đã duyệt cho nhóm sau, **chưa triển khai trong nhóm 1**:

- Nhóm 2: các ngoại lệ synthetic trên chain khác 31337, unfinalized, integrity FAILED và gap phải có cờ riêng, `--reason` và audit; giữ nguyên parser dùng chung đã đúng.
- Nhóm 3: caseId = SHA-256(case_id), URI `evidence://sha256/<case_hash_hex>/manifest.json`; không lộ case_id gốc trong URI/event/ghi chú/log. Export append-only theo manifest hash, không REPLACE. Hoàn thiện custody, idempotency, sidecar và reconcile.
- Nhóm 4: prefix evidence://, ASCII 0x21–0x7E, trần 256 byte; thêm getCustodyCount/getCustodyAt và giữ getCustodyHistory. Giữ logic ownership đã đúng.
- Nhóm 5: hoàn thiện test/script/LOW; mọi nguồn gửi để rà soát phải lấy nguyên văn từ checkout kèm Git blob ID tại HEAD và SHA-256 file.

Các mô tả cũ bên dưới về gói, DB và dirty-tree chưa có nghĩa các lỗi nhóm 2–5 đã được sửa.

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
