// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title EvidenceRegistry
 * @notice Hợp đồng quản lý chuỗi hành trình chứng cứ (Chain of Custody) bất biến trên blockchain (Mục 6.5).
 */
contract EvidenceRegistry {
    enum CustodyAction { COLLECTED, ANALYZED, TRANSFERRED, EXPORTED }

    struct EvidenceItem {
        uint256 evidenceId;
        bytes32 caseId;
        bytes32 manifestSha256;
        string storageUri;
        address registeredBy;
        uint256 registeredAt;
        bool exists;
    }

    struct CustodyRecord {
        uint256 evidenceId;
        CustodyAction action;
        address actor;
        bytes32 artifactSha256;
        bytes32 noteHash;
        uint256 timestamp;
    }

    uint256 public constant MAX_URI_BYTES = 256;

    address public owner;
    address public pendingOwner;
    mapping(address => bool) public authorizedInvestigators;
    mapping(bytes32 => uint256) public hashToEvidenceId;

    mapping(uint256 => EvidenceItem) private _evidences;
    mapping(uint256 => CustodyRecord[]) private _custodyHistory;

    // evidenceId bắt đầu từ 1 (0 là giá trị mặc định đại diện cho "chưa đăng ký" trong hashToEvidenceId)
    uint256 public nextEvidenceId = 1;

    error Unauthorized(address caller);
    error DuplicateManifestHash(bytes32 manifestSha256, uint256 existingEvidenceId);
    error EvidenceNotFound(uint256 evidenceId);
    error ZeroValue();
    error SameOwner();
    error PendingTransferExists(address pendingOwner);
    error UriTooLong(uint256 length, uint256 maxLength);
    error WhitespaceUri();
    error NoPendingTransfer();

    event InvestigatorUpdated(address indexed account, bool authorized);
    event EvidenceRegistered(
        uint256 indexed evidenceId,
        bytes32 indexed caseId,
        bytes32 indexed manifestSha256,
        address submitter,
        string storageUri
    );
    event CustodyRecorded(
        uint256 indexed evidenceId,
        CustodyAction indexed action,
        address indexed actor,
        bytes32 artifactSha256,
        bytes32 noteHash
    );
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    modifier onlyInvestigator() {
        if (!authorizedInvestigators[msg.sender]) revert Unauthorized(msg.sender);
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedInvestigators[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit InvestigatorUpdated(msg.sender, true);
    }

    /// @notice Đề cử owner mới (quy trình 2 bước).
    /// @dev Chặn address(0) (ZeroValue), chặn chính owner hiện tại (SameOwner) để tránh tự thu hồi quyền investigator.
    ///      Nếu đang có đề cử chờ xử lý, bắt buộc gọi cancelOwnershipTransfer() trước (PendingTransferExists).
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroValue();
        if (newOwner == owner) revert SameOwner();
        if (pendingOwner != address(0)) revert PendingTransferExists(pendingOwner);
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Hủy bỏ lời đề cử chuyển quyền đang chờ. Chỉ owner hiện tại gọi được.
    function cancelOwnershipTransfer() external onlyOwner {
        if (pendingOwner == address(0)) revert NoPendingTransfer();
        pendingOwner = address(0);
        emit OwnershipTransferCancelled(msg.sender);
    }

    /// @notice pendingOwner chấp nhận quyền sở hữu.
    /// @dev Cấp quyền investigator cho owner mới, và thu hồi quyền investigator của owner cũ để giảm thiểu rủi ro lộ khóa.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized(msg.sender);
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);

        // Cấp quyền investigator cho owner mới
        authorizedInvestigators[msg.sender] = true;
        emit InvestigatorUpdated(msg.sender, true);

        // Thu hồi quyền investigator của owner cũ để giảm thiểu rủi ro lộ khóa
        authorizedInvestigators[oldOwner] = false;
        emit InvestigatorUpdated(oldOwner, false);

        emit OwnershipTransferred(oldOwner, msg.sender);
    }

    function setInvestigator(address account, bool authorized) external onlyOwner {
        authorizedInvestigators[account] = authorized;
        emit InvestigatorUpdated(account, authorized);
    }

    /// @dev Kiểm tra mảng byte có chứa ít nhất một ký tự không phải khoảng trắng (space, tab, newline, carriage return).
    function _isNonWhitespace(bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 char = b[i];
            if (char != 0x20 && char != 0x09 && char != 0x0a && char != 0x0d) {
                return true;
            }
        }
        return false;
    }

    /// @notice Đăng ký gói chứng cứ số bất biến.
    /// @dev storageUri phải có độ dài byte từ 1 đến MAX_URI_BYTES (256) và không được chỉ chứa khoảng trắng.
    function registerEvidence(
        bytes32 caseId,
        bytes32 manifestSha256,
        string calldata storageUri
    ) external onlyInvestigator returns (uint256 evidenceId) {
        if (caseId == bytes32(0)) revert ZeroValue();
        if (manifestSha256 == bytes32(0)) revert ZeroValue();
        bytes memory uriBytes = bytes(storageUri);
        if (uriBytes.length == 0) revert ZeroValue();
        if (uriBytes.length > MAX_URI_BYTES) {
            revert UriTooLong(uriBytes.length, MAX_URI_BYTES);
        }
        if (!_isNonWhitespace(uriBytes)) {
            revert WhitespaceUri();
        }

        uint256 existingId = hashToEvidenceId[manifestSha256];
        if (existingId != 0) {
            revert DuplicateManifestHash(manifestSha256, existingId);
        }

        evidenceId = nextEvidenceId++;
        hashToEvidenceId[manifestSha256] = evidenceId;

        _evidences[evidenceId] = EvidenceItem({
            evidenceId: evidenceId,
            caseId: caseId,
            manifestSha256: manifestSha256,
            storageUri: storageUri,
            registeredBy: msg.sender,
            registeredAt: block.timestamp,
            exists: true
        });

        emit EvidenceRegistered(evidenceId, caseId, manifestSha256, msg.sender, storageUri);
    }

    function recordCustody(
        uint256 evidenceId,
        CustodyAction action,
        bytes32 artifactSha256,
        bytes32 noteHash
    ) external onlyInvestigator {
        // Kiểm tra EvidenceNotFound TRƯỚC
        if (!_evidences[evidenceId].exists) {
            revert EvidenceNotFound(evidenceId);
        }
        if (artifactSha256 == bytes32(0)) {
            revert ZeroValue();
        }

        CustodyRecord memory record = CustodyRecord({
            evidenceId: evidenceId,
            action: action,
            actor: msg.sender,
            artifactSha256: artifactSha256,
            noteHash: noteHash,
            timestamp: block.timestamp
        });

        _custodyHistory[evidenceId].push(record);

        emit CustodyRecorded(evidenceId, action, msg.sender, artifactSha256, noteHash);
    }

    function verifyEvidence(
        uint256 evidenceId,
        bytes32 expectedManifestSha256
    ) external view returns (bool isValid, address submitter, uint256 registeredAt) {
        EvidenceItem memory item = _evidences[evidenceId];
        if (!item.exists) {
            return (false, address(0), 0);
        }
        if (item.manifestSha256 == expectedManifestSha256) {
            return (true, item.registeredBy, item.registeredAt);
        }
        return (false, item.registeredBy, item.registeredAt);
    }

    function getEvidence(uint256 evidenceId) external view returns (EvidenceItem memory) {
        EvidenceItem memory item = _evidences[evidenceId];
        if (!item.exists) {
            revert EvidenceNotFound(evidenceId);
        }
        return item;
    }

    function getCustodyHistory(uint256 evidenceId) external view returns (CustodyRecord[] memory) {
        if (!_evidences[evidenceId].exists) {
            revert EvidenceNotFound(evidenceId);
        }
        return _custodyHistory[evidenceId];
    }
}
