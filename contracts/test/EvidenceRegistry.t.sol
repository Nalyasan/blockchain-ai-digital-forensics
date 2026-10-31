// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/EvidenceRegistry.sol";

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function expectRevert(bytes calldata) external;
    function warp(uint256) external;
    function assume(bool) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
}

contract EvidenceRegistryTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    EvidenceRegistry public registry;
    address public deployer;
    address public alice;
    address public bob;
    address public stranger;

    bytes32 constant CASE_001 = bytes32("CASE-2026-001");
    bytes32 constant CASE_002 = bytes32("CASE-2026-002");
    bytes32 constant MANIFEST_HASH_1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant MANIFEST_HASH_2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 constant MANIFEST_HASH_3 = 0x3333333333333333333333333333333333333333333333333333333333333333;
    string constant STORAGE_URI = "evidence://case-001/manifest.json";
    bytes32 constant ART_HASH = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    bytes32 constant NOTE_HASH = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

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
        EvidenceRegistry.CustodyAction indexed action,
        address indexed actor,
        bytes32 artifactSha256,
        bytes32 noteHash
    );
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        deployer = address(this);
        alice = address(0xA11CE);
        bob = address(0xB0B);
        stranger = address(0xBAD);
        registry = new EvidenceRegistry();
    }

    // ==================== 1. Khởi tạo ====================
    function test_InitialState() public view {
        assert(registry.owner() == deployer);
        assert(registry.pendingOwner() == address(0));
        assert(registry.authorizedInvestigators(deployer) == true);
        assert(registry.nextEvidenceId() == 1);
        assert(registry.MAX_URI_BYTES() == 256);
    }

    // ==================== 2. Ownership Transfer 2 bước ====================
    function test_TransferOwnership_ZeroAddressReverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.transferOwnership(address(0));
    }

    function test_TransferOwnership_SameOwnerReverts() public {
        // Chặn chuyển quyền cho chính mình: phòng ngừa self-lockout và mất quyền investigator
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.SameOwner.selector));
        registry.transferOwnership(deployer);

        // Trạng thái không bị ảnh hưởng
        assert(registry.owner() == deployer);
        assert(registry.pendingOwner() == address(0));
        assert(registry.authorizedInvestigators(deployer) == true);
    }

    function test_TransferOwnership_PendingTransferExistsReverts() public {
        // Đề cử Alice
        registry.transferOwnership(alice);
        assert(registry.pendingOwner() == alice);

        // Thử ghi đè sang Bob khi chưa hủy Alice -> revert PendingTransferExists
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.PendingTransferExists.selector, alice));
        registry.transferOwnership(bob);

        // Hủy đề cử đang chờ
        registry.cancelOwnershipTransfer();
        assert(registry.pendingOwner() == address(0));

        // Bây giờ đề cử Bob thành công
        registry.transferOwnership(bob);
        assert(registry.pendingOwner() == bob);
    }

    function test_AcceptOwnership_StrangerReverts() public {
        registry.transferOwnership(alice);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.acceptOwnership();
    }

    function test_AcceptOwnership_GrantsNewOwnerAndRevokesOldOwner() public {
        // Ban đầu Alice KHÔNG phải là investigator
        assert(registry.authorizedInvestigators(alice) == false);

        registry.transferOwnership(alice);

        // Alice chấp nhận:
        // 1. Cấp quyền investigator cho Alice (owner mới)
        // 2. Thu hồi investigator của Deployer (owner cũ)
        // 3. Phát OwnershipTransferred
        vm.expectEmit(true, false, false, true);
        emit InvestigatorUpdated(alice, true);
        vm.expectEmit(true, false, false, true);
        emit InvestigatorUpdated(deployer, false);
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferred(deployer, alice);

        vm.prank(alice);
        registry.acceptOwnership();

        // Xác nhận trạng thái
        assert(registry.owner() == alice);
        assert(registry.pendingOwner() == address(0));
        assert(registry.authorizedInvestigators(deployer) == false);
        assert(registry.authorizedInvestigators(alice) == true);

        // Alice có thể đăng ký chứng cứ
        vm.prank(alice);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        assert(eid == 1);
    }

    function test_OldOwner_CannotRegisterAfterTransfer() public {
        registry.transferOwnership(alice);
        vm.prank(alice);
        registry.acceptOwnership();

        // Deployer (owner cũ) gọi registerEvidence -> revert Unauthorized
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, deployer));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
    }

    function test_OldOwner_CannotRecordCustodyAfterTransfer() public {
        // Deployer đăng ký trước khi chuyển quyền
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.transferOwnership(alice);
        vm.prank(alice);
        registry.acceptOwnership();

        // Deployer (owner cũ) gọi recordCustody -> revert Unauthorized
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, deployer));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);
    }

    // ==================== 3. Hủy lời chuyển quyền ====================
    function test_CancelOwnershipTransfer_Success() public {
        registry.transferOwnership(alice);
        assert(registry.pendingOwner() == alice);

        vm.expectEmit(true, false, false, true);
        emit OwnershipTransferCancelled(deployer);
        registry.cancelOwnershipTransfer();

        assert(registry.pendingOwner() == address(0));
        assert(registry.owner() == deployer);

        // Alice không thể acceptOwnership sau khi hủy
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, alice));
        registry.acceptOwnership();
    }

    function test_CancelOwnershipTransfer_NoPending_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.NoPendingTransfer.selector));
        registry.cancelOwnershipTransfer();
    }

    function test_CancelOwnershipTransfer_StrangerReverts() public {
        registry.transferOwnership(alice);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.cancelOwnershipTransfer();
    }

    // ==================== 4. Người lạ bị Unauthorized ====================
    function test_StrangerCannotRegisterEvidence() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
    }

    function test_StrangerCannotRecordCustody() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, ART_HASH, NOTE_HASH);
    }

    function test_StrangerCannotSetInvestigator() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.setInvestigator(stranger, true);
    }

    // ==================== 5. Revoked investigator ====================
    function test_RevokedInvestigatorCannotRecordCustody() public {
        registry.setInvestigator(alice, true);
        vm.prank(alice);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.setInvestigator(alice, false);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, alice));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, ART_HASH, NOTE_HASH);
    }

    // ==================== 6. Đăng ký & Chống trùng ====================
    function test_RegisterEvidenceSuccess() public {
        vm.expectEmit(true, true, true, true);
        emit EvidenceRegistered(1, CASE_001, MANIFEST_HASH_1, deployer, STORAGE_URI);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        assert(eid == 1);
        assert(registry.hashToEvidenceId(MANIFEST_HASH_1) == 1);

        EvidenceRegistry.EvidenceItem memory item = registry.getEvidence(eid);
        assert(item.evidenceId == 1);
        assert(item.caseId == CASE_001);
        assert(item.manifestSha256 == MANIFEST_HASH_1);
        assert(keccak256(bytes(item.storageUri)) == keccak256(bytes(STORAGE_URI)));
        assert(item.registeredBy == deployer);
        assert(item.exists == true);
    }

    function test_DuplicateManifestHashReverts() public {
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        vm.expectRevert(
            abi.encodeWithSelector(EvidenceRegistry.DuplicateManifestHash.selector, MANIFEST_HASH_1, 1)
        );
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://retry");
    }

    // ==================== 7. ZeroValue ====================
    function test_ZeroValue_CaseId() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.registerEvidence(bytes32(0), MANIFEST_HASH_1, STORAGE_URI);
    }

    function test_ZeroValue_ManifestSha256() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.registerEvidence(CASE_001, bytes32(0), STORAGE_URI);
    }

    function test_ZeroValue_EmptyStorageUri() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "");
    }

    function test_WhitespaceUriReverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.WhitespaceUri.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, " ");

        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.WhitespaceUri.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "   ");

        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.WhitespaceUri.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "\t\n\r ");
    }

    function test_ZeroValue_ArtifactSha256() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, bytes32(0), bytes32(0));
    }

    // ==================== 8. Thứ tự kiểm tra: EvidenceNotFound trước ZeroValue ====================
    function test_RecordCustody_EvidenceNotFound_Before_ZeroValue() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.EvidenceNotFound.selector, 999));
        registry.recordCustody(999, EvidenceRegistry.CustodyAction.COLLECTED, bytes32(0), bytes32(0));
    }

    function test_GetEvidence_NonExistent_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.EvidenceNotFound.selector, 888));
        registry.getEvidence(888);
    }

    function test_GetCustodyHistory_NonExistent_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.EvidenceNotFound.selector, 888));
        registry.getCustodyHistory(888);
    }

    // ==================== 9. UriTooLong ====================
    function test_UriTooLongReverts() public {
        bytes memory prefix = bytes("evidence://");

        bytes memory longBytes = new bytes(257);
        for (uint256 i = 0; i < prefix.length; i++) longBytes[i] = prefix[i];
        for (uint256 i = prefix.length; i < 257; i++) longBytes[i] = "a";
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.UriTooLong.selector, 257, 256));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(longBytes));

        // 256 bytes: OK
        bytes memory maxBytes = new bytes(256);
        for (uint256 i = 0; i < prefix.length; i++) maxBytes[i] = prefix[i];
        for (uint256 i = prefix.length; i < 256; i++) maxBytes[i] = "b";
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(maxBytes));
        assert(eid == 1);
    }

    // ==================== 10. Events chính xác ====================
    function test_EventsEmittedCorrectly() public {
        vm.expectEmit(true, false, false, true);
        emit InvestigatorUpdated(alice, true);
        registry.setInvestigator(alice, true);

        vm.expectEmit(true, true, true, true);
        emit EvidenceRegistered(1, CASE_001, MANIFEST_HASH_1, deployer, STORAGE_URI);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        vm.expectEmit(true, true, true, true);
        emit CustodyRecorded(eid, EvidenceRegistry.CustodyAction.COLLECTED, deployer, ART_HASH, NOTE_HASH);
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);
    }

    // ==================== 11. CustodyRecord đầy đủ & thứ tự ====================
    function test_CustodyRecord_DetailedFieldsAndOrdering() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        bytes32 art1 = 0x1111000000000000000000000000000000000000000000000000000000000000;
        bytes32 note1 = 0x9999000000000000000000000000000000000000000000000000000000000000;
        bytes32 art2 = 0x2222000000000000000000000000000000000000000000000000000000000000;
        bytes32 note2 = 0x8888000000000000000000000000000000000000000000000000000000000000;

        vm.warp(1700000100);
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, art1, note1);
        vm.warp(1700000200);
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, art2, note2);

        EvidenceRegistry.CustodyRecord[] memory records = registry.getCustodyHistory(eid);
        assert(records.length == 2);

        assert(records[0].evidenceId == eid);
        assert(records[0].action == EvidenceRegistry.CustodyAction.COLLECTED);
        assert(records[0].actor == deployer);
        assert(records[0].artifactSha256 == art1);
        assert(records[0].noteHash == note1);
        assert(records[0].timestamp == 1700000100);

        assert(records[1].evidenceId == eid);
        assert(records[1].action == EvidenceRegistry.CustodyAction.ANALYZED);
        assert(records[1].actor == deployer);
        assert(records[1].artifactSha256 == art2);
        assert(records[1].noteHash == note2);
        assert(records[1].timestamp == 1700000200);
        assert(records[0].timestamp < records[1].timestamp);
    }

    // ==================== 12. 2 evidence tách biệt lịch sử ====================
    function test_SeparateCustodyHistories() public {
        uint256 eid1 = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://c1");
        uint256 eid2 = registry.registerEvidence(CASE_002, MANIFEST_HASH_2, "evidence://c2");

        registry.recordCustody(eid1, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, bytes32(0));
        registry.recordCustody(eid1, EvidenceRegistry.CustodyAction.ANALYZED, ART_HASH, bytes32(0));
        registry.recordCustody(eid2, EvidenceRegistry.CustodyAction.TRANSFERRED, ART_HASH, bytes32(0));

        assert(registry.getCustodyHistory(eid1).length == 2);
        assert(registry.getCustodyHistory(eid2).length == 1);
        assert(registry.getCustodyHistory(eid1)[0].action == EvidenceRegistry.CustodyAction.COLLECTED);
        assert(registry.getCustodyHistory(eid2)[0].action == EvidenceRegistry.CustodyAction.TRANSFERRED);
    }

    // ==================== 13. verifyEvidence ====================
    function test_VerifyEvidence() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        (bool ok, address sub, uint256 at) = registry.verifyEvidence(eid, MANIFEST_HASH_1);
        assert(ok && sub == deployer && at > 0);

        (bool bad, , ) = registry.verifyEvidence(eid, MANIFEST_HASH_2);
        assert(!bad);

        (bool missing, , ) = registry.verifyEvidence(999, MANIFEST_HASH_1);
        assert(!missing);
    }

    // ==================== 14. Fuzz test ====================
    function testFuzz_RegisterEvidence(bytes32 caseId, bytes32 manifestSha256, uint8 rawLen) public {
        vm.assume(caseId != bytes32(0));
        vm.assume(manifestSha256 != bytes32(0));
        // Đảm bảo URI hợp lệ với tiền tố evidence:// và length >= 12 và <= 256 byte
        bytes memory prefix = bytes("evidence://");
        uint256 length = 12 + (uint256(rawLen) % (256 - 11));
        bytes memory b = new bytes(length);
        for (uint256 i = 0; i < prefix.length; i++) b[i] = prefix[i];
        for (uint256 i = prefix.length; i < length; i++) b[i] = bytes1(uint8(65 + (i % 26)));

        uint256 expectedId = registry.nextEvidenceId();
        uint256 eid = registry.registerEvidence(caseId, manifestSha256, string(b));
        assert(eid == expectedId);
        assert(registry.hashToEvidenceId(manifestSha256) == eid);
        (bool valid, address sub, ) = registry.verifyEvidence(eid, manifestSha256);
        assert(valid && sub == deployer);
    }
}
