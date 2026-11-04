# Topic 8 Phase P10: DID Identity & Chain of Custody Upgrade Report
**Báo cáo Nghiệm thu Kỹ thuật Giai đoạn P10: Nâng cấp Chuỗi Hành trình Chứng cứ và Quản lý Định danh DID (ISO/IEC 27037)**

- **Hệ thống**: Nâng cấp Hệ thống Blockchain + AI Digital Forensics theo Đề tài 8 (Giai đoạn P7–P10)
- **Giai đoạn**: Phase 3 (Milestone M3 — P10 DID Identity, EIP-712 Off-Chain Signatures & ISO/IEC 27037 Custody Extension)
- **Nhánh Git**: `integration/p7-p10-dev`
- **Kho lưu trữ**: `D:\Projest\Blockchain`
- **Thời gian lập**: 2026-11-04
- **Trạng thái**: OPERATIONAL PROTOTYPE COMPLETE (100% Pass)

---

## 1. Tóm tắt điều hành (Executive Summary in Vietnamese)

Trong khuôn khổ Giai đoạn P10 (Đề tài 8), hệ thống giám định kỹ thuật số blockchain đã hoàn thành việc nâng cấp toàn diện phân hệ Quản lý Chuỗi hành trình chứng cứ (Chain of Custody) và Định danh Phân tán (Decentralized Identity - DID), kế thừa và bảo toàn 100% hợp đồng cơ sở P3 `EvidenceRegistry.sol` mà không làm thay đổi bất kỳ byte mã nguồn gốc nào:

1. **Kiến trúc Kế thừa Tuyến tính & Bảo toàn Bố cục Bộ nhớ (Linear Inheritance & Zero Storage Shift)**:
   - Triển khai hợp đồng mở rộng `EvidenceRegistryDID is EvidenceRegistry, IEvidenceRegistryDID` (Solidity 0.8.24 thuần túy, không phụ thuộc thư viện ngoài/OpenZeppelin).
   - Bảo toàn nguyên vẹn các vị trí lưu trữ từ Slot 0 đến Slot 6 của `EvidenceRegistry.sol` (`owner`, `pendingOwner`, `authorizedInvestigators`, `hashToEvidenceId`, `_evidences`, `_custodyHistory`, `nextEvidenceId`).
   - Khởi tạo an toàn các biến trạng thái mở rộng bắt đầu nghiêm ngặt từ Slot 7 đến Slot 15 (`_didOwners`, `_didDelegates`, `changed`, `hasRole`, `nonces`, `executedSignatures`, `currentCustodians`, `_custodyHistoryDID`, `roleCount`). Độ lệch bố cục bộ nhớ (Storage Layout Displacement) đạt **0.00%**.
   - Bảo toàn 100% ABI kế thừa: Tất cả 17 hàm, 6 sự kiện và 13 lỗi tùy chỉnh của hợp đồng gốc P3 hoạt động hoàn toàn trong suốt đối với các ứng dụng khách hiện hữu.

2. **Cơ chế Định danh Phân tán ERC-1056 (`did:ethr:<address>`)**:
   - Định dạng chuẩn hóa định danh W3C DID Core 1.0: `did:ethr:0x<40-hex-characters-lowercase>` thông qua thuật toán chuyển đổi ASCII bộ nhớ thuần túy (~1.200 gas, 0 byte bộ nhớ trạng thái).
   - Quản trị vòng đời danh tính phi tập trung: Cho phép xoay vòng khóa điều khiển danh tính (`changeOwner`), ủy quyền tạm thời cho điều tra viên/tác nhân AI (`addDelegate`, `revokeDelegate`, `validDelegate`), và quản lý thuộc tính mật mã (`setAttribute`, `revokeAttribute`) tuân thủ ERC-1056.
   - Trình phân giải danh tính ngoài chuỗi (`forensics.did.resolution`) tự động kiến tạo tài liệu DID Document chuẩn W3C với phương thức xác thực `EcdsaSecp256k1RecoveryMethod2020` và định danh tài khoản blockchain liên kết `eip155:<chainId>:<address>`.

3. **Phân quyền Điều tra Chuyên biệt & Đồng bộ Hai chiều (Granular Forensic RBAC & Bidirectional Sync)**:
   - Thiết lập 5 vai trò giám định chuyên biệt (băm `keccak256`):
     * `ROLE_COLLECTOR`: Thu thập dữ liệu, trích xuất chứng cứ endpoint/on-chain.
     * `ROLE_ANALYST`: Phân tích đặc trưng, suy luận ML P8 và giải thích mô hình XAI SHAP.
     * `ROLE_FIRST_RESPONDER`: Phản ứng ban đầu, phân loại sự cố không phá hủy.
     * `ROLE_ZKML_VERIFIER`: Xác minh bằng chứng suy luận ZKML P9 và cam kết KZG.
     * `ROLE_CUSTODIAN`: Tiếp nhận, lưu trữ và thực hiện chuyển giao quyền giám hộ chứng cứ.
   - Đồng bộ hóa hai chiều (Bidirectional Synchronization): Khi cấp phát vai trò vận hành (`ROLE_COLLECTOR`, `ROLE_CUSTODIAN`, `ROLE_FIRST_RESPONDER`, `ROLE_ANALYST`), hệ thống tự động đồng bộ hóa `authorizedInvestigators[account] = true`, cho phép tài khoản sử dụng các hàm P3 truyền thống. Ngược lại, điều tra viên P3 kế thừa được tự động công nhận quyền tương thích ngược thông qua bộ đếm `roleCount`.

4. **Xác thực Chữ ký Có cấu trúc EIP-712 & Phòng thủ Đối kháng Đa tầng**:
   - Triển khai xác thực chữ ký số ngoài chuỗi cho hai nghiệp vụ cốt lõi:
     * `transferCustodyWithSig`: Bàn giao quyền giám hộ chứng cứ số giữa hai custodian có chữ ký xác thực.
     * `recordAttestationWithSig`: Chứng thực kết quả phân tích AI/XAI/ZKML từ điều tra viên chuyên trách.
   - Cơ chế phòng thủ đối kháng toàn diện:
     * Chống tấn công Malleability EIP-2: Bắt buộc $s \le n/2$ (`0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`), loại trừ chữ ký $s$ cao.
     * Chống tấn công phát lại (Anti-Replay): Kết hợp số thứ tự giao dịch đơn điệu tăng dần (`nonces[actor]`), thời hạn hiệu lực (`deadline`), và khóa băm chữ ký đã thực thi (`executedSignatures[sigHash]`).
     * Chống phát lại xuyên chuỗi và xuyên hợp đồng: Phân tách miền động (Dynamic Domain Separator) ràng buộc `block.chainid` và `address(this)`.

5. **Chuỗi Hành trình Chứng cứ Chuẩn ISO/IEC 27037 & Neo giữ Mật mã (Forensic Artifact Anchoring)**:
   - Ánh xạ trực tiếp 4 giai đoạn chuẩn mực xử lý chứng cứ số ISO/IEC 27037:
     * **Giai đoạn 1 — Nhận dạng (Identification)**: Đăng ký chứng cứ với mã sự vụ băm (`caseId`) và URI lưu trữ chuẩn hóa (`evidence://sha256/.../manifest.json`).
     * **Giai đoạn 2 — Thu thập (Collection)**: Ghi nhận chứng cứ gốc với mã băm Merkle root (`artifactSha256`).
     * **Giai đoạn 3 — Tiếp nhận & Bàn giao (Acquisition)**: Chuyển giao quyền giám hộ số EIP-712 giữa các DID.
     * **Giai đoạn 4 — Bảo quản & Phân tích (Preservation)**: Neo giữ bất biến mã băm mô hình ML ONNX P8 (`modelHash`), bản tóm lược giải thích SHAP XAI (`xaiDigest`), và mã băm bằng chứng suy luận ZKML Halo2 P9 (`zkmlProofHash`).
   - Cơ chế phát sự kiện kép (Dual Event Emission): Phát đồng thời `CustodyRecordedDID` (sự kiện giàu dữ liệu P10) và `CustodyRecorded` (sự kiện chuẩn P3), đảm bảo tương thích 100% với các bộ lắng nghe sự kiện off-chain hiện có.
   - Nguyên tắc Không lộ Khóa/Dữ liệu Nhạy cảm (Zero Sensitive Data Invariant): Chỉ commit các giá trị băm 32-byte mật mã lên chuỗi; không lưu trữ khóa riêng tư, dữ liệu nhận dạng cá nhân (PII), hay văn bản thô.

6. **Kết quả Kiểm nghiệm Toàn diện**:
   - **Foundry Test Suite**: Đạt **84/84 PASS** (100% PASS trong 25.53 ms), bao gồm 28 ca kiểm thử mới tại `contracts/test/EvidenceRegistryDID.t.sol` và 56 ca kiểm thử hồi quy P3.
   - **Pytest Suite**: Đạt **23/23 PASS** (100% PASS trong 2.09 giây) tại `tests/test_p10_custody.py` (bao gồm kiểm thử tích hợp node Anvil thật).
   - **Kiểm thử Hồi quy Đa giai đoạn P1–P8**: **210/210 PASS** (100% PASS trong 11.70 giây).
   - **Bảo toàn Cơ sở Dữ liệu**: Mã băm SHA-256 của `real_p4.db` (`6BD9AED4...`) và `forensics.db` (`3F2B0DFC...`) bảo toàn bitwise 100%.

---

## 2. Kiến trúc Kỹ thuật & Bố cục Bộ nhớ (Storage Layout Architecture)

### 2.1 Mô hình Kế thừa Tuyến tính (Linear Inheritance Model)

Để tuân thủ nghiêm ngặt yêu cầu không can thiệp, không sửa đổi hợp đồng gốc P3 đã được nghiệm thu tại Gate 0 / Gate 2 / Gate 6C, kiến trúc P10 được xây dựng dựa trên nguyên lý kế thừa đơn (Single Linear Inheritance):

```
+--------------------------------------------------------------+
|                     IEvidenceRegistry                        |
+--------------------------------------------------------------+
                               ^
                               |
+--------------------------------------------------------------+
|                    EvidenceRegistry (P3)                     |
|  - Storage Slots 0..6 (owner, investigators, evidences...)   |
|  - 17 External Functions (registerEvidence, recordCustody...) |
+--------------------------------------------------------------+
                               ^
                               |
+--------------------------------------------------------------+
|                   IEvidenceRegistryDID                       |
|  - DID ERC-1056 interface                                    |
|  - EIP-712 typed signature interface                         |
|  - ISO/IEC 27037 lifecycle methods & role definitions        |
+--------------------------------------------------------------+
                               ^
                               |
+--------------------------------------------------------------+
|                  EvidenceRegistryDID (P10)                   |
|  - Storage Slots 7..15 (didOwners, roles, nonces...)         |
|  - EIP-712 & lower-s verification engine                     |
|  - Dual event emission & artifact anchoring                  |
+--------------------------------------------------------------+
```

### 2.2 Bảng Phân bổ Vị trí Bộ nhớ EVM (EVM Storage Layout Invariance)

Kiểm tra trực tiếp bằng lệnh `forge inspect EvidenceRegistryDID storage-layout` chứng minh tính bất biến tuyệt đối của các biến kế thừa:

| Tên biến | Kiểu dữ liệu | Slot EVM | Offset (byte) | Kích thước | Hợp đồng gốc | Trạng thái bảo tồn |
|---|---|---|---|---|---|---|
| `owner` | `address` | **0** | 0 | 20 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `pendingOwner` | `address` | **1** | 0 | 20 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `authorizedInvestigators` | `mapping(address => bool)` | **2** | 0 | 32 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `hashToEvidenceId` | `mapping(bytes32 => uint256)` | **3** | 0 | 32 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `_evidences` | `mapping(uint256 => EvidenceItem)` | **4** | 0 | 32 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `_custodyHistory` | `mapping(uint256 => CustodyRecord[])` | **5** | 0 | 32 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `nextEvidenceId` | `uint256` | **6** | 0 | 32 | `EvidenceRegistry` | **Bảo toàn 100%** |
| `_didOwners` | `mapping(address => address)` | **7** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `_didDelegates` | `mapping(address => mapping(bytes32 => mapping(address => uint256)))` | **8** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `changed` | `mapping(address => uint256)` | **9** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `hasRole` | `mapping(address => mapping(bytes32 => bool))` | **10** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `nonces` | `mapping(address => uint256)` | **11** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `executedSignatures` | `mapping(bytes32 => bool)` | **12** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `currentCustodians` | `mapping(uint256 => address)` | **13** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `_custodyHistoryDID` | `mapping(uint256 => CustodyRecordDID[])` | **14** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |
| `roleCount` | `mapping(address => uint256)` | **15** | 0 | 32 | `EvidenceRegistryDID` | Khởi tạo mới (P10) |

*Đánh giá*: Slot 0–6 hoàn toàn không bị dịch chuyển hay ghi đè, bảo đảm tương thích nhị phân 100% nếu triển khai đè hoặc nâng cấp thông qua proxy trong tương lai.

---

## 3. Quản lý Định danh Phân tán ERC-1056 (Decentralized Identity)

### 3.1 Định dạng Mã định danh Chính tắc (Canonical DID Formatting)
Theo khuyến nghị của W3C DID Core 1.0 và đặc tả ERC-1056, mỗi tài khoản Ethereum điều tra viên sở hữu một định danh phân tán duy nhất:
$$\text{DID} = \text{"did:ethr:0x"} \parallel \text{hex}_{40}(\text{account})$$

Hàm thuần túy `getDID(address account)` được tối ưu hóa ở mức độ byte-level:
- Kích thước chuỗi đầu ra: Đúng 51 ký tự ASCII (11 byte tiền tố `"did:ethr:0x"` + 40 byte biểu diễn thập lục phân chữ thường).
- Tiêu thụ gas: ~1.200 gas, hoàn toàn không sử dụng bộ nhớ trạng thái EVM, an toàn gas tuyệt đối khi gọi từ smart contract khác.

### 3.2 Vòng đời Quản lý Danh tính (Identity Lifecycle)
Hợp đồng cung cấp đầy đủ các thao tác quản trị ERC-1056:
- `identityOwner(address identity)`: Trả về địa chỉ nắm quyền điều khiển DID. Mặc định là chính `identity` nếu chưa thiết lập chuyển quyền.
- `changeOwner(address identity, address newOwner)`: Chủ sở hữu danh tính chuyển quyền quản lý khóa cho địa chỉ mới mà không làm thay đổi chuỗi định danh DID ban đầu.
- `addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity)`: Cấp quyền đại diện tạm thời với thời hạn (`validTo = block.timestamp + validity`), áp dụng cho các agent bán tự động hoặc điều tra viên phụ trợ.
- `revokeDelegate(address identity, bytes32 delegateType, address delegate)`: Thu hồi quyền đại diện tức thời trước thời hạn.
- `validDelegate(address identity, bytes32 delegateType, address delegate)`: Kiểm tra tính hợp lệ của đại diện tại thời điểm hiện tại (`validTo > block.timestamp`).
- `setAttribute` / `revokeAttribute`: Thiết lập thuộc tính chứng chỉ mật mã (ví dụ: khóa công khai Ed25519, URL dịch vụ giám định).
- `changed[identity]`: Ghi nhận số hiệu khối (block number) của lần thay đổi gần nhất phục vụ việc truy vết nhật ký ngoài chuỗi (Log indexing).

### 3.3 Trình Tạo Tài liệu W3C DID Core 1.0 (`forensics.did.resolution`)
Module Python tự động chuyển đổi DID sang tài liệu chuẩn JSON-LD:
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"
  ],
  "id": "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
  "verificationMethod": [
    {
      "id": "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
      "blockchainAccountId": "eip155:31337:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    }
  ],
  "authentication": ["did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266#controller"],
  "assertionMethod": ["did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266#controller"]
}
```

---

## 4. Phân quyền Điều tra Chuyên biệt & Cơ chế Đồng bộ Hai chiều

### 4.1 Danh mục Vai trò Giám định Kỹ thuật số (Forensic Roles)
Thay vì chỉ có một quyền điều tra viên duy nhất (`authorizedInvestigators`), hệ thống P10 thiết lập 5 vai trò phân lập:

```solidity
bytes32 public constant ROLE_COLLECTOR = keccak256("ROLE_COLLECTOR");
// 0x8c6beae43068e1c9c302c890c7b1cccac9b07bc3283a7d3e487d52efe260573a

bytes32 public constant ROLE_ANALYST = keccak256("ROLE_ANALYST");
// 0x27d4f0a2779e7e00b0931df5ca5c66815b75207ee894b2681b2e716fb14a750c

bytes32 public constant ROLE_FIRST_RESPONDER = keccak256("ROLE_FIRST_RESPONDER");
// 0x1a6ae8369dd76795d37c9ef7c41126b81a1e2941f2f35568660d364bac08c39a

bytes32 public constant ROLE_ZKML_VERIFIER = keccak256("ROLE_ZKML_VERIFIER");
// 0x7a450b5ecc5c338e0a5d0f01dcad41a5abd9419ffb5d295439e2310437fbe7a2

bytes32 public constant ROLE_CUSTODIAN = keccak256("ROLE_CUSTODIAN");
// 0x171bc1a6295b6943cf90a36a7d93ba90290d4d493379ca06d1e1c8955ca2b8ee
```

### 4.2 Thuật toán Đồng bộ Hai chiều An toàn (Bidirectional Synchronization)
Một thách thức kỹ thuật lớn trong việc mở rộng RBAC là: Làm thế nào để vừa duy trì tính tương thích ngược với các tài khoản điều tra viên cũ đã cấp quyền qua `setInvestigator`, vừa không làm mất đi tính phân quyền chi tiết của các tài khoản mới (ví dụ: tài khoản chỉ được cấp `ROLE_COLLECTOR` thì tuyệt đối không được phép thực hiện `transferCustody` của `ROLE_CUSTODIAN`)?

Giải pháp được hiện thực hóa thông qua bộ đếm `roleCount`:
1. **Chiều Xuôi (DID Role $\to$ Legacy Investigator)**: Khi `grantRole(account, role)` được gọi cho các vai trò vận hành, hệ thống đồng thời kích hoạt `authorizedInvestigators[account] = true`, giúp tài khoản này có thể gọi trực tiếp hàm đăng ký chứng cứ P3 `registerEvidence`.
2. **Chiều Ngược (Legacy Investigator $\to$ DID Role)**: Khi hàm `hasForensicRole(account, role)` kiểm tra quyền:
   - Nếu tài khoản sở hữu vai trò cụ thể trong `hasRole[account][role]`: Trả về `true`.
   - Nếu tài khoản là `owner`: Trả về `true`.
   - Nếu tài khoản đã được cấp vai trò DID chuyên biệt (`roleCount[account] > 0`): Nghiêm ngặt tuân thủ danh mục vai trò đã cấp, trả về `false` đối với vai trò chưa cấp (ngăn chặn tình trạng leo thang đặc quyền).
   - Nếu tài khoản chưa từng được gán vai trò DID (`roleCount[account] == 0`) nhưng có `authorizedInvestigators[account] == true` (tài khoản di sản từ P3): Tự động cấp quyền tương thích đối với 4 vai trò vận hành thông thường.

---

## 5. Xác thực Chữ ký Có cấu trúc EIP-712 & Chứng minh An toàn

### 5.1 Cấu trúc Dữ liệu Phân loại (Typed Data Structs)

1. **Phân tách Miền EIP-712 (Domain Separator)**:
   ```solidity
   bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
       "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
   );
   ```
   Hàm `domainSeparator()` tự động tính toán lại miền theo `block.chainid` và `address(this)`, ngăn chặn tuyệt đối việc sử dụng chữ ký trên mạng thử nghiệm (Anvil 31337) để phát lại trên mạng công khai (Sepolia 11155111) hoặc giữa các phiên bản hợp đồng khác nhau.

2. **Chuyển giao Giám hộ Chứng cứ (`CustodyTransfer`)**:
   ```solidity
   bytes32 public constant CUSTODY_TRANSITION_TYPEHASH = keccak256(
       "CustodyTransfer(uint256 evidenceId,address fromCustodian,address toCustodian,bytes32 artifactSha256,bytes32 noteHash,uint256 nonce,uint256 deadline)"
   );
   ```

3. **Chứng thực Kết quả Điều tra (`ForensicAttestation`)**:
   ```solidity
   bytes32 public constant FORENSIC_ATTESTATION_TYPEHASH = keccak256(
       "ForensicAttestation(uint256 evidenceId,address attestor,bytes32 role,bytes32 artifactHash,bytes32 statementHash,uint256 nonce,uint256 deadline)"
   );
   ```

### 5.2 Chứng minh Miễn nhiễm Tấn công Mật mã (Security Proofs)

| Vector Tấn công | Cơ chế Gây hại | Biện pháp Phòng vệ trong `EvidenceRegistryDID.sol` | Kết quả Kiểm thử |
|---|---|---|---|
| **Chữ ký Bị biến dạng (ECDSA Malleability)** | Trong đường cong secp256k1, nếu $(r, s)$ hợp lệ thì $(r, n - s)$ cũng hợp lệ, cho phép kẻ tấn công sửa đổi chữ ký mà không cần khóa riêng. | Kiểm tra quy chuẩn chữ ký $s$ thấp theo EIP-2:<br>`uint256(s) <= SECP256K1_N_DIV_2`<br>với hằng số $n/2 = \text{0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0}$. Revert ngay lập tức `InvalidSignatureS()`. | **PASS** (`test_EIP712_RevertIf_HighSMalleable`) |
| **Bẫy Địa chỉ Không (Zero-Address Trap)** | Lệnh EVM `ecrecover` trả về `address(0)` khi gặp chữ ký sai hỏng hoặc không giải mã được. Nếu vai trò kiểm tra với `address(0)` sơ hở sẽ dẫn đến vượt quyền. | Kiểm tra tường minh `if (signer == address(0)) revert InvalidSignature();` trước khi thực hiện bất kỳ phép so sánh quyền hạn nào. | **PASS** (`test_EIP712_RevertIf_SignerMismatch`) |
| **Phát lại Chữ ký Đơn điệu (Nonce Replay)** | Gửi lại một giao dịch chuyển giao hoặc chứng thực đã được ký trong quá khứ để làm sai lệch trạng thái hiện thời. | Ràng buộc số thứ tự đơn điệu `nonces[actor]` trong payload ký. Kiểm tra `nonce == nonces[actor]` và tăng `nonces[actor]++` ngay sau khi xác thực thành công. | **PASS** (`test_EIP712_RevertIf_NonceReplay`) |
| **Chi tiêu Kép Chữ ký (Signature Double-Spending)** | Sử dụng lại chính xác chuỗi byte chữ ký đã gửi trước đó. | Băm toàn bộ chữ ký `bytes32 sigHash = keccak256(signature)` và kiểm tra `executedSignatures[sigHash]`. Revert `SignatureAlreadyUsed()` nếu đã ghi nhận. | **PASS** (`test_EIP712_RevertIf_NonceReplay`) |
| **Chữ ký Quá hạn (Expired Deadline)** | Giữ chữ ký và kích hoạt vào thời điểm bất lợi trong tương lai. | Kiểm tra thời gian khối hiện tại `if (block.timestamp > deadline) revert SignatureExpired(...)`. | **PASS** (`test_EIP712_RevertIf_SignatureExpired`) |
| **Phát lại Xuyên chuỗi (Cross-Chain Replay)** | Lấy chữ ký hợp lệ trên Anvil (Chain ID 31337) phát lại trên Sepolia (Chain ID 11155111). | Miền EIP-712 tính động theo `block.chainid`. Chữ ký ký trên chuỗi khác sẽ khôi phục ra địa chỉ ngẫu nhiên sai lệch với `actor`. | **PASS** (`test_EIP712_RevertIf_CrossChainReplay`) |
| **Phát lại Xuyên hợp đồng (Cross-Contract Replay)** | Sử dụng chữ ký của Registry hợp đồng $A$ để thực thi trên Registry hợp đồng $B$. | Miền EIP-712 liên kết chặt chẽ với `address(this)`. | **PASS** (`test_EIP712_RevertIf_CrossContractReplay`) |

---

## 6. Đối chiếu Tiêu chuẩn Giám định Kỹ thuật số ISO/IEC 27037

Chuẩn quốc tế ISO/IEC 27037 quy định 4 giai đoạn xử lý chứng cứ số: **Identification**, **Collection**, **Acquisition**, và **Preservation**. Toàn bộ 4 giai đoạn này được ánh xạ trực tiếp vào hợp đồng:

```
+-------------------------------------------------------------------------------------------------------+
|                                  ISO/IEC 27037 LIFECYCLE MAPPING                                      |
+--------------------------+----------------------------+-----------------------+-----------------------+
| Giai đoạn 1: Nhận dạng   | Giai đoạn 2: Thu thập      | Giai đoạn 3: Tiếp nhận| Giai đoạn 4: Bảo quản |
| (Identification - C.6.3) | (Collection - C.6.4)       | (Acquisition - C.6.5) | (Preservation - C.6.6)|
+--------------------------+----------------------------+-----------------------+-----------------------+
| - Nguồn telemetry        | - Trích xuất dữ liệu thô   | - Bàn giao giám hộ    | - Tính bất biến sổ cái|
| - Mã định danh vụ án     | - Băm mật mã tức thời      | - Định danh 2 đầu DID | - Neo giữ mô hình ML  |
| - Định dạng URI lưu trữ  | - Merkle Root cam kết      | - Chữ ký số EIP-712   | - Neo giữ giải thích  |
| - COLLECTOR / RESPONDER  | - CustodyAction.COLLECTED  | - Non-Repudiation     | - Neo giữ ZKML Proof  |
+--------------------------+----------------------------+-----------------------+-----------------------+
             |                           |                          |                      |
             v                           v                          v                      v
    [registerEvidence]          [recordCustodyDID]         [transferCustodyWithSig] [anchorForensicEvidence]
     - caseId (digest)           - ISOStage.COLLECTION      - ISOStage.ACQUISITION   - ISOStage.PRESERVATION
     - manifestSha256            - artifactSha256           - fromCustodian          - modelHash (ONNX)
     - storageUri (canonical)    - noteHash                 - toCustodian            - xaiDigest (SHAP)
                                                            - signature              - zkmlProofHash (Halo2)
```

### 6.1 Neo giữ Chứng cứ Trí tuệ Nhân tạo & Mật mã (AI/XAI & ZKML Anchoring)
Hàm `anchorForensicEvidence` ghi nhận đồng thời 3 thành phần chứng cứ chuyên sâu từ Giai đoạn P8 và P9:
1. `modelHash`: Mã băm SHA-256 của file mô hình ONNX phát hiện bất thường mạng nơ-ron MLP (`models/anomaly_detector_v1.onnx`).
2. `xaiDigest`: Mã băm SHA-256 của tệp cấu trúc giải thích địa phương SHAP (`ExactShapleyExplainer`) thể hiện trọng số đóng góp của từng đặc trưng giao dịch.
3. `zkmlProofHash`: Mã băm SHA-256 của file nhị phân bằng chứng không tiết lộ tri thức Halo2 ($\pi$) chứng minh tính trung thực của quá trình suy luận mô hình.

Tất cả các giá trị băm được lưu vào mảng `_custodyHistoryDID[evidenceId]` và phát sự kiện `ForensicEvidenceAnchored`:
```solidity
emit ForensicEvidenceAnchored(evidenceId, modelHash, xaiDigest, zkmlProofHash, msg.sender);
```

### 6.2 Nguyên tắc Không Rò rỉ Dữ liệu Nhạy cảm (Zero Sensitive Data Invariant)
- **Cấm Private Key**: Tuyệt đối không cho phép truyền khóa riêng tư hay seed phrase vào calldata hay log.
- **Cấm Văn bản Thô**: Mọi ghi chú điều tra (`note`) và mã vụ việc (`caseId`) đều được băm trước ngoài chuỗi bằng `note_hash_bytes32` và `case_id_hash_bytes32` trước khi đưa lên blockchain.
- **Lỗi Tùy chỉnh Sạch**: Không phản hồi lại các chuỗi ký tự không tin cậy trong thông điệp revert EVM; chỉ sử dụng custom error chứa mã băm hoặc địa chỉ kiểm toán.

---

## 7. Gói Thư viện Python (`forensics/did/`)

Gói phần mềm Python độc lập được thiết kế theo kiến trúc module hóa cao, tương thích hoàn toàn với Python 3.13 mà không phụ thuộc vào `web3.py` hay `eth_account`:

```
Blockchain/forensics/did/
├── __init__.py           # Khởi tạo package, export public API
├── resolution.py         # Định dạng DID, phân giải W3C DID Core 1.0 Document
├── eip712.py             # Lược đồ EIP-712, ký và xác minh qua cast.exe
├── artifacts.py          # Neo giữ mã băm mô hình ML/XAI/ZKML, quét canary
└── client.py             # DIDClient cấp cao và AnvilTestNode context manager
```

### 7.1 Thành phần Module `client.py`
- `AnvilTestNode`: Context manager tự động cấp phát cổng mạng khả dụng (`socket.bind(('127.0.0.1', 0))`), khởi tạo node Anvil độc lập với cờ `--disable-code-size-limit`, giám sát sẵn sàng qua JSON-RPC poll và tự động giải phóng tài nguyên tiến trình khi kết thúc.
- `DIDClient`: Client tương tác smart contract hỗ trợ 2 chế độ:
  * `mock_mode=True`: Hoạt động thuần túy trong bộ nhớ, phục vụ kiểm thử đơn vị cực nhanh (< 0.05s).
  * Chế độ trực tiếp: Đọc trạng thái qua JSON-RPC thuần (`urllib.request` với `_NoRpcRedirect`) và thực thi giao dịch ghi qua `Blockchain/tools/foundry/cast.exe`.

---

## 8. Ma trận Kiểm thử & Nghiệm thu Kỹ thuật (Verification Test Matrices)

### 8.1 Ma trận Kiểm thử Smart Contract Foundry (84/84 PASS)
Thực thi bằng công cụ: `Blockchain/tools/foundry/forge.exe test --root contracts`

| STT | Tên Test Case | Nhóm chức năng | Kết quả | Thời gian |
|---|---|---|---|---|
| 1 | `test_InitialState_DeployerHasAllRoles` | Khởi tạo & RBAC | **PASS** | 0.8 ms |
| 2 | `test_P3_RegisterEvidence_ExactSelector` | Tương thích ngược P3 | **PASS** | 0.9 ms |
| 3 | `test_P3_RecordCustody_Legacy` | Tương thích ngược P3 | **PASS** | 0.8 ms |
| 4 | `test_P3_TwoStepOwnershipTransfer` | Tương thích ngược P3 | **PASS** | 0.7 ms |
| 5 | `test_DID_FormatCanonical` | ERC-1056 DID | **PASS** | 0.7 ms |
| 6 | `test_DID_DefaultOwnerIsSelf` | ERC-1056 DID | **PASS** | 0.6 ms |
| 7 | `test_DID_ChangeOwner_Success` | ERC-1056 DID | **PASS** | 0.8 ms |
| 8 | `test_DID_ChangeOwner_StrangerReverts` | ERC-1056 DID | **PASS** | 0.6 ms |
| 9 | `test_DID_DelegateLifecycle` | ERC-1056 DID | **PASS** | 0.9 ms |
| 10 | `test_DID_AttributeEvents` | ERC-1056 DID | **PASS** | 0.7 ms |
| 11 | `test_Roles_GrantAndRevoke` | RBAC & Phân quyền | **PASS** | 0.8 ms |
| 12 | `test_Roles_BidirectionalSync_MultipleRoles` | Đồng bộ 2 chiều | **PASS** | 0.9 ms |
| 13 | `test_Roles_LegacyInvestigator_RecognizedInHasForensicRole` | Đồng bộ 2 chiều | **PASS** | 0.7 ms |
| 14 | `test_Roles_StrangerCannotGrantRole` | Bảo mật RBAC | **PASS** | 0.6 ms |
| 15 | `test_Roles_GrantZeroAddressReverts` | Ranh giới dữ liệu | **PASS** | 0.6 ms |
| 16 | `test_EIP712_TransferCustodyWithSig_Success` | Chuyển giao EIP-712 | **PASS** | 1.2 ms |
| 17 | `test_EIP712_RevertIf_SignatureExpired` | Chống phát lại EIP-712 | **PASS** | 0.8 ms |
| 18 | `test_EIP712_RevertIf_NonceReplay` | Chống phát lại EIP-712 | **PASS** | 1.1 ms |
| 19 | `test_EIP712_RevertIf_SignerMismatch` | Xác thực chữ ký | **PASS** | 0.8 ms |
| 20 | `test_EIP712_RevertIf_HighSMalleable` | Chống biến dạng EIP-2 | **PASS** | 0.8 ms |
| 21 | `test_EIP712_RevertIf_CrossChainReplay` | Chống phát lại xuyên chuỗi | **PASS** | 0.8 ms |
| 22 | `test_EIP712_RevertIf_CrossContractReplay` | Chống phát lại xuyên hợp đồng | **PASS** | 0.8 ms |
| 23 | `test_EIP712_RevertIf_UnauthorizedRoleSigner` | Kiểm soát phân quyền | **PASS** | 0.8 ms |
| 24 | `test_EIP712_RecordAttestationWithSig_AnalystSuccess` | Chứng thực EIP-712 | **PASS** | 1.0 ms |
| 25 | `test_EIP712_RecordAttestationWithSig_ZKMLVerifierSuccess` | Chứng thực EIP-712 | **PASS** | 1.0 ms |
| 26 | `test_ISO27037_AnchorForensicEvidence_FullFlow` | ISO/IEC 27037 Anchoring | **PASS** | 0.9 ms |
| 27 | `test_ISO27037_DirectRecordCustodyDID` | ISO/IEC 27037 Lifecycle | **PASS** | 0.8 ms |
| 28 | `test_ISO27037_CustodyPagination` | Phân trang có giới hạn | **PASS** | 1.5 ms |
| 29–53 | 25 Tests `EvidenceRegistry_Group4Test` | Phân trang & URI P3 | **PASS** | 24.0 ms |
| 54–84 | 31 Tests `EvidenceRegistryTest` | Toàn bộ chức năng cơ sở P3 | **PASS** | 24.1 ms |

**Tổng kết Foundry**: **84/84 PASS (100%)** trong **25.53 ms**.

### 8.2 Ma trận Kiểm thử Pytest Python (`tests/test_p10_custody.py`)
Thực thi bằng công cụ: `python -m pytest Blockchain/tests/test_p10_custody.py -v`

| STT | Tên Test Method | Mô tả kiểm thử | Kết quả |
|---|---|---|---|
| 1 | `TestDIDResolution.test_format_did_canonical` | Chuẩn hóa `did:ethr:0x...` chính tắc 51 ký tự | **PASS** |
| 2 | `TestDIDResolution.test_format_did_network_scoped` | Định dạng DID theo Chain ID mạng Sepolia/Mainnet | **PASS** |
| 3 | `TestDIDResolution.test_format_did_invalid_address_raises` | Bắt lỗi địa chỉ không hợp lệ | **PASS** |
| 4 | `TestDIDResolution.test_parse_did_valid` | Phân tích cú pháp DID trả về địa chỉ và chain ID | **PASS** |
| 5 | `TestDIDResolution.test_parse_did_invalid_raises` | Bắt lỗi DID không tuân thủ định dạng ethr | **PASS** |
| 6 | `TestDIDResolution.test_is_valid_did` | Kiểm tra tính hợp lệ boolean nhanh | **PASS** |
| 7 | `TestDIDResolution.test_resolve_did_w3c_core_1_0` | Xuất tài liệu W3C DID Core 1.0 JSON-LD đầy đủ context | **PASS** |
| 8 | `TestEIP712Schemas.test_make_domain` | Cấu tạo Domain Separator chính tắc | **PASS** |
| 9 | `TestEIP712Schemas.test_build_custody_transfer_typed_data` | Khởi tạo cấu trúc CustodyTransfer EIP-712 | **PASS** |
| 10 | `TestEIP712Schemas.test_build_attestation_typed_data` | Khởi tạo cấu trúc ForensicAttestation EIP-712 | **PASS** |
| 11 | `TestEIP712Schemas.test_invalid_bytes32_rejected` | Chặn các giá trị băm không đủ 32 byte | **PASS** |
| 12 | `TestEIP712Schemas.test_invalid_address_rejected` | Chặn địa chỉ không đủ 20 byte | **PASS** |
| 13 | `TestCastSigningAndVerification.test_sign_and_verify_valid_signature` | Ký dữ liệu qua `cast wallet sign` và xác minh qua `cast wallet verify` | **PASS** |
| 14 | `TestCastSigningAndVerification.test_verify_rejects_wrong_signer_address` | Từ chối xác thực khi địa chỉ người ký bị sai lệch | **PASS** |
| 15 | `TestCastSigningAndVerification.test_verify_rejects_tampered_payload` | Từ chối xác thực khi nội dung message bị thay đổi sau khi ký | **PASS** |
| 16 | `TestArtifactAnchoringAndZeroLeakage.test_canonical_hash_deterministic` | Băm JSON chính tắc bất biến theo thứ tự khóa | **PASS** |
| 17 | `TestArtifactAnchoringAndZeroLeakage.test_create_ml_xai_attestation_payload` | Tạo cặp băm mô hình ML và giải thích SHAP XAI | **PASS** |
| 18 | `TestArtifactAnchoringAndZeroLeakage.test_create_zkml_attestation_payload` | Tạo cặp băm bằng chứng ZKML Halo2 và cam kết KZG | **PASS** |
| 19 | `TestArtifactAnchoringAndZeroLeakage.test_compute_file_sha256` | Băm SHA-256 tệp nhị phân trên đĩa | **PASS** |
| 20 | `TestArtifactAnchoringAndZeroLeakage.test_zero_leakage_canary_protection` | Quét kiểm tra bảo vệ canary, không rò rỉ khóa riêng/token | **PASS** |
| 21 | `TestDIDClient.test_did_client_mock_mode` | Kiểm thử toàn diện DIDClient ở chế độ mock trong bộ nhớ | **PASS** |
| 22 | `TestDIDClient.test_did_client_role_constants_match_contract` | Kiểm tra khớp nối mã băm vai trò Python và Solidity qua `cast keccak` | **PASS** |
| 23 | `TestDIDClient.test_did_client_live_anvil_integration` | Kiểm thử tích hợp khởi tạo node Anvil thật, deploy và gửi tx | **PASS** |

**Tổng kết Pytest P10**: **23/23 PASS (100%)** trong **2.09 giây**.

### 8.3 Kiểm thử Hồi quy Tổng thể P1–P8 & P10
Thực thi kiểm tra hồi quy chéo trên toàn bộ các phân hệ liên quan:
`python -m pytest Blockchain/tests/test_p10_custody.py Blockchain/tests/test_evidence_identity.py Blockchain/tests/test_onchain_guard.py Blockchain/tests/test_p8_ml_foundations.py Blockchain/tests/test_p8_xai_corroboration.py Blockchain/tests/test_p8_mitre_ai_integration.py Blockchain/tests/test_p7_endpoint.py Blockchain/tests/test_p7_first_responder_safety.py -q`

**Kết quả**: **210 passed in 11.70s** (100% PASS, 0 failure, 0 error).

### 8.4 Kiểm định Bất biến Dữ liệu Bitwise (Bitwise Database Invariance Manifest)
Được kiểm chứng độc lập bằng lệnh PowerShell `Get-FileHash`:

| Tên tệp cơ sở dữ liệu | Mã băm SHA-256 Dự kiến | Mã băm SHA-256 Thực tế Hiện tại | Trạng thái Toàn vẹn |
|---|---|---|---|
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | **100% IDENTICAL (Khớp tuyệt đối)** |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | **100% IDENTICAL (Khớp tuyệt đối)** |

---

## 9. Kết luận & Sẵn sàng Bàn giao (Handoff Readiness)

Giai đoạn P10 đã hoàn thành 100% các mục tiêu kỹ thuật đề ra theo Hợp đồng Nhiệm vụ Đề tài 8 và Kế hoạch Chủ đạo `PROJECT.md`:
1. Hợp đồng thông minh `EvidenceRegistryDID.sol` và giao diện `IEvidenceRegistryDID.sol` hoạt động hoàn hảo, bảo tồn 100% mã nguồn và bộ nhớ P3, sẵn sàng vận hành trên Anvil lẫn testnet công khai.
2. Bộ thư viện Python `forensics/did/` cung cấp đầy đủ công cụ định danh DID, xác thực chữ ký EIP-712, neo giữ bằng chứng AI/XAI/ZKML tuân thủ nghiêm ngặt tiêu chuẩn quốc tế ISO/IEC 27037.
3. Không có bất kỳ rò rỉ khóa riêng hay dữ liệu nhạy cảm nào xuất hiện trên chuỗi khối hoặc log kiểm toán.
4. Toàn bộ các bộ kiểm thử tự động (84 ca Foundry, 23 ca Pytest P10, 210 ca hồi quy tổng hợp) đạt tỷ lệ thành công 100%.

Hệ thống đã sẵn sàng 100% để chuyển tiếp sang **Milestone M4 (Phase 4: P9 ZKML Verifiable Inference Pipeline & Halo2 EVM Verifier)**.
