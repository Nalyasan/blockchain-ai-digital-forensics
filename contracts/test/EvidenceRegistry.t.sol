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
    address public stranger;

    bytes32 constant CASE_001 = bytes32("CASE-2026-001");
    bytes32 constant CASE_002 = bytes32("CASE-2026-002");
    bytes32 constant MANIFEST_HASH_1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant MANIFEST_HASH_2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
    string constant STORAGE_URI = "evidence://case-001/manifest.json";

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
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        deployer = address(this);
        alice = address(0xA11CE);
        stranger = address(0xBAD);

        registry = new EvidenceRegistry();
    }

    // ---------- 1. Test Khởi tạo ban đầu ----------
    function test_InitialState() public view {
        assert(registry.owner() == deployer);
        assert(registry.pendingOwner() == address(0));
        assert(registry.authorizedInvestigators(deployer) == true);
        assert(registry.nextEvidenceId() == 1);
        assert(registry.MAX_URI_BYTES() == 256);
    }

    // ---------- 2. Test Chuyển giao quyền sở hữu 2 bước (2-step Ownership Transfer) ----------
    function test_TwoStepOwnershipTransfer() public {
        // 1. Cố tình chuyển cho address(0) -> ZeroValue
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.transferOwnership(address(0));

        // 2. Chuyển đề cử cho Alice
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferStarted(deployer, alice);
        registry.transferOwnership(alice);
        assert(registry.pendingOwner() == alice);
        assert(registry.owner() == deployer);

        // 3. Người lạ cố tình gọi acceptOwnership -> revert Unauthorized
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.acceptOwnership();

        // 4. Alice chấp nhận quyền sở hữu
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferred(deployer, alice);
        registry.acceptOwnership();

        assert(registry.owner() == alice);
        assert(registry.pendingOwner() == address(0));
    }

    // ---------- 3. Test Kiểm tra phát Event chính xác ----------
    function test_EventsEmittedCorrectly() public {
        // Event InvestigatorUpdated
        vm.expectEmit(true, false, false, true);
        emit InvestigatorUpdated(alice, true);
        registry.setInvestigator(alice, true);

        // Event EvidenceRegistered
        vm.expectEmit(true, true, true, true);
        emit EvidenceRegistered(1, CASE_001, MANIFEST_HASH_1, deployer, STORAGE_URI);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        // Event CustodyRecorded
        bytes32 art = 0x1234000000000000000000000000000000000000000000000000000000000000;
        bytes32 note = 0x5678000000000000000000000000000000000000000000000000000000000000;
        vm.expectEmit(true, true, true, true);
        emit CustodyRecorded(eid, EvidenceRegistry.CustodyAction.COLLECTED, deployer, art, note);
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, art, note);
    }

    // ---------- 4. Test T07: Người lạ gọi hàm bảo vệ bị Unauthorized ----------
    function test_StrangerCannotRegisterEvidence() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
    }

    function test_StrangerCannotRecordCustody() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, bytes32(uint256(1)), bytes32(0));
    }

    function test_StrangerCannotSetInvestigator() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.setInvestigator(stranger, true);
    }

    // ---------- 5. Test Investigator bị thu hồi quyền gọi recordCustody -> Unauthorized ----------
    function test_RevokedInvestigatorCannotRecordCustody() public {
        registry.setInvestigator(alice, true);
        vm.prank(alice);
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        // Thu hồi quyền của Alice
        registry.setInvestigator(alice, false);

        // Alice cố tình ghi nhận Custody -> revert Unauthorized
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, alice));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, bytes32(uint256(1)), bytes32(0));
    }

    // ---------- 6. Test T06: Chống trùng manifestSha256 ----------
    function test_DuplicateManifestHashReverts() public {
        uint256 eid1 = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        assert(eid1 == 1);

        vm.expectRevert(
            abi.encodeWithSelector(EvidenceRegistry.DuplicateManifestHash.selector, MANIFEST_HASH_1, 1)
        );
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001-retry/manifest.json");
    }

    // ---------- 7. Test Ba trường hợp ZeroValue ----------
    function test_ZeroValue_CaseId() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.registerEvidence(bytes32(0), MANIFEST_HASH_1, STORAGE_URI);
    }

    function test_ZeroValue_ManifestSha256() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.registerEvidence(CASE_001, bytes32(0), STORAGE_URI);
    }

    function test_ZeroValue_ArtifactSha256() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, bytes32(0), bytes32(0));
    }

    // ---------- 8. Test Thứ tự kiểm tra: EvidenceNotFound kiểm tra TRƯỚC ZeroValue ----------
    function test_RecordCustody_EvidenceNotFound_Before_ZeroValue() public {
        // Gọi với evidenceId không tồn tại VÀ artifactSha256 = 0
        // Phải revert EvidenceNotFound trước!
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

    // ---------- 9. Test UriTooLong ----------
    function test_UriTooLongReverts() public {
        // Tạo chuỗi 257 ký tự
        bytes memory longBytes = new bytes(257);
        for (uint256 i = 0; i < 257; i++) {
            longBytes[i] = "a";
        }
        string memory longUri = string(longBytes);

        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.UriTooLong.selector, 257, 256));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, longUri);

        // Chuỗi 256 ký tự phải thành công
        bytes memory maxBytes = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            maxBytes[i] = "b";
        }
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(maxBytes));
        assert(eid == 1);
    }

    // ---------- 10. Test Đầy đủ các trường của CustodyRecord (timestamp, actor, hash, thứ tự) ----------
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

        // Record 1
        assert(records[0].evidenceId == eid);
        assert(records[0].action == EvidenceRegistry.CustodyAction.COLLECTED);
        assert(records[0].actor == deployer);
        assert(records[0].artifactSha256 == art1);
        assert(records[0].noteHash == note1);
        assert(records[0].timestamp == 1700000100);

        // Record 2
        assert(records[1].evidenceId == eid);
        assert(records[1].action == EvidenceRegistry.CustodyAction.ANALYZED);
        assert(records[1].actor == deployer);
        assert(records[1].artifactSha256 == art2);
        assert(records[1].noteHash == note2);
        assert(records[1].timestamp == 1700000200);

        // Thứ tự thời gian
        assert(records[0].timestamp < records[1].timestamp);
    }

    // ---------- 11. Test Lịch sử Custody của 2 Evidence hoàn toàn tách biệt ----------
    function test_SeparateCustodyHistoriesForDifferentEvidences() public {
        uint256 eid1 = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        uint256 eid2 = registry.registerEvidence(CASE_002, MANIFEST_HASH_2, "evidence://case-002/manifest.json");

        bytes32 art = 0x3333000000000000000000000000000000000000000000000000000000000000;

        // Evidence 1 có 2 hành động
        registry.recordCustody(eid1, EvidenceRegistry.CustodyAction.COLLECTED, art, bytes32(0));
        registry.recordCustody(eid1, EvidenceRegistry.CustodyAction.ANALYZED, art, bytes32(0));

        // Evidence 2 chỉ có 1 hành động
        registry.recordCustody(eid2, EvidenceRegistry.CustodyAction.TRANSFERRED, art, bytes32(0));

        EvidenceRegistry.CustodyRecord[] memory h1 = registry.getCustodyHistory(eid1);
        EvidenceRegistry.CustodyRecord[] memory h2 = registry.getCustodyHistory(eid2);

        assert(h1.length == 2);
        assert(h2.length == 1);
        assert(h1[0].action == EvidenceRegistry.CustodyAction.COLLECTED);
        assert(h1[1].action == EvidenceRegistry.CustodyAction.ANALYZED);
        assert(h2[0].action == EvidenceRegistry.CustodyAction.TRANSFERRED);
    }

    // ---------- 12. Fuzz Test cho registerEvidence ----------
    function testFuzz_RegisterEvidence(bytes32 caseId, bytes32 manifestSha256, uint8 rawLen) public {
        vm.assume(caseId != bytes32(0));
        vm.assume(manifestSha256 != bytes32(0));

        // Độ dài tối đa 256 bytes
        uint256 length = uint256(rawLen) % 256;
        bytes memory b = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            b[i] = bytes1(uint8(65 + (i % 26)));
        }
        string memory fuzzUri = string(b);

        uint256 expectedId = registry.nextEvidenceId();
        uint256 eid = registry.registerEvidence(caseId, manifestSha256, fuzzUri);

        assert(eid == expectedId);
        assert(registry.hashToEvidenceId(manifestSha256) == eid);

        (bool valid, address sub, uint256 regAt) = registry.verifyEvidence(eid, manifestSha256);
        assert(valid == true);
        assert(sub == deployer);
        assert(regAt == block.timestamp);
    }
}
