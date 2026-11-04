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

contract EvidenceRegistry_Group4Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    EvidenceRegistry public registry;
    address public deployer;
    address public alice;

    bytes32 constant CASE_001 = bytes32("CASE-2026-001");
    bytes32 constant MANIFEST_HASH_1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant MANIFEST_HASH_2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 constant ART_HASH = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    bytes32 constant NOTE_HASH = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    function setUp() public {
        deployer = address(this);
        alice = address(0xA11CE);
        registry = new EvidenceRegistry();
    }

    // URI Prefix Invariance Tests

    function test_RevertIf_UriMissingPrefix_Http() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriPrefix.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "http://evidence/manifest.json");
    }

    function test_RevertIf_UriMissingPrefix_RawPath() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriPrefix.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "case-001/manifest.json");
    }

    function test_RevertIf_UriPrefixCaseSensitive_Uppercase() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriPrefix.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "EVIDENCE://case-001/manifest.json");
    }

    function test_RevertIf_UriPrefixCaseSensitive_MixedCase() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriPrefix.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "Evidence://case-001/manifest.json");
    }

    function test_RevertIf_UriPrefixOnly() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriReference.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://");
    }

    function test_RevertIf_UriPrefixWhitespaceOnlyRef() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriReference.selector));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://   ");
    }

    // Character Validation Tests

    function test_RevertIf_UriContainsNullByte() public {
        // Null byte at index 15
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x00), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x00)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsNewline() public {
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x0a), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x0a)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsTab() public {
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x09), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x09)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsControlChar() public {
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x1f), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x1f)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsDelChar() public {
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x7f), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x7f)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsNonAsciiHighByte() public {
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0x80), "manifest");
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0x80)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    function test_RevertIf_UriContainsMultiByteUtf8() public {
        // Unicode character e.g. 🔒 is \xF0\x9F\x94\x92 (4 bytes, first is 0xF0)
        bytes memory bad = abi.encodePacked("evidence://test", bytes1(0xf0), bytes1(0x9f), bytes1(0x94), bytes1(0x92));
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidUriCharacter.selector, 15, bytes1(0xf0)));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(bad));
    }

    // URI Length Boundary Tests (256 vs 257)

    function test_ValidUri_Exact256Bytes() public {
        bytes memory exact256 = new bytes(256);
        bytes memory prefix = bytes("evidence://");
        for (uint256 i = 0; i < prefix.length; i++) {
            exact256[i] = prefix[i];
        }
        for (uint256 i = prefix.length; i < 256; i++) {
            exact256[i] = "x";
        }
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(exact256));
        assert(eid == 1);
        EvidenceRegistry.EvidenceItem memory item = registry.getEvidence(eid);
        assert(bytes(item.storageUri).length == 256);
    }

    function test_RevertIf_UriExceeds256Bytes_257Bytes() public {
        bytes memory exact257 = new bytes(257);
        bytes memory prefix = bytes("evidence://");
        for (uint256 i = 0; i < prefix.length; i++) {
            exact257[i] = prefix[i];
        }
        for (uint256 i = prefix.length; i < 257; i++) {
            exact257[i] = "x";
        }
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.UriTooLong.selector, 257, 256));
        registry.registerEvidence(CASE_001, MANIFEST_HASH_1, string(exact257));
    }

    // Custody Pagination Tests

    function test_CustodyPagination_EmptyHistory() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 0, 10);
        assert(total == 0);
        assert(records.length == 0);
        assert(registry.getCustodyCount(eid) == 0);
    }

    function test_CustodyPagination_SingleEvent() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);

        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 0, 10);
        assert(total == 1);
        assert(records.length == 1);
        assert(records[0].evidenceId == eid);
        assert(records[0].action == EvidenceRegistry.CustodyAction.COLLECTED);
        assert(records[0].artifactSha256 == ART_HASH);
        assert(records[0].noteHash == NOTE_HASH);
        assert(registry.getCustodyCount(eid) == 1);
    }

    function test_CustodyPagination_MultipleEventsAndPages() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");

        // Record 5 custody events
        for (uint256 i = 1; i <= 5; i++) {
            bytes32 art = bytes32(uint256(i));
            bytes32 note = bytes32(uint256(i * 100));
            registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, art, note);
        }
        assert(registry.getCustodyCount(eid) == 5);

        // Page 1: offset 0, limit 2 -> items 1, 2
        (EvidenceRegistry.CustodyRecord[] memory p1, uint256 total1) = registry.getCustodyHistory(eid, 0, 2);
        assert(total1 == 5);
        assert(p1.length == 2);
        assert(p1[0].artifactSha256 == bytes32(uint256(1)));
        assert(p1[1].artifactSha256 == bytes32(uint256(2)));

        // Page 2: offset 2, limit 2 -> items 3, 4
        (EvidenceRegistry.CustodyRecord[] memory p2, uint256 total2) = registry.getCustodyHistory(eid, 2, 2);
        assert(total2 == 5);
        assert(p2.length == 2);
        assert(p2[0].artifactSha256 == bytes32(uint256(3)));
        assert(p2[1].artifactSha256 == bytes32(uint256(4)));

        // Page 3: offset 4, limit 2 -> item 5 (partial page)
        (EvidenceRegistry.CustodyRecord[] memory p3, uint256 total3) = registry.getCustodyHistory(eid, 4, 2);
        assert(total3 == 5);
        assert(p3.length == 1);
        assert(p3[0].artifactSha256 == bytes32(uint256(5)));
    }

    function test_CustodyPagination_OffsetBeyondTotal() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);

        // offset 5 when total is 1 -> returns empty array, total = 1
        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 5, 10);
        assert(total == 1);
        assert(records.length == 0);
    }

    function test_CustodyPagination_LimitZero() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);

        // limit 0 -> returns empty array, total = 1
        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 0, 0);
        assert(total == 1);
        assert(records.length == 0);
    }

    function test_RevertIf_CustodyPagination_LimitExceedsMax() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        // MAX_PAGE_SIZE = 50. limit = 51 must revert PageSizeTooLarge(51, 50)
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.PageSizeTooLarge.selector, 51, 50));
        registry.getCustodyHistory(eid, 0, 51);
    }

    function test_CustodyPagination_MatchesFullHistory() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        for (uint256 i = 1; i <= 7; i++) {
            registry.recordCustody(eid, EvidenceRegistry.CustodyAction.ANALYZED, bytes32(uint256(i)), bytes32(uint256(i)));
        }

        EvidenceRegistry.CustodyRecord[] memory full = registry.getCustodyHistory(eid);
        assert(full.length == 7);

        // Fetch using pages of size 3
        uint256 pageSize = 3;
        uint256 fetchedCount = 0;
        for (uint256 offset = 0; offset < full.length; offset += pageSize) {
            (EvidenceRegistry.CustodyRecord[] memory page, uint256 total) = registry.getCustodyHistory(eid, offset, pageSize);
            assert(total == 7);
            for (uint256 j = 0; j < page.length; j++) {
                assert(page[j].artifactSha256 == full[fetchedCount].artifactSha256);
                assert(page[j].noteHash == full[fetchedCount].noteHash);
                fetchedCount++;
            }
        }
        assert(fetchedCount == full.length);
    }

    function test_CustodyPagination_ExactMaxLimit() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        // MAX_PAGE_SIZE = 50. limit = 50 should succeed
        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 0, 50);
        assert(total == 0);
        assert(records.length == 0);
    }

    function test_CustodyPagination_ViewDoesNotModifyState() public {
        uint256 eid = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, "evidence://case-001/manifest.json");
        registry.recordCustody(eid, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);

        uint256 nextIdBefore = registry.nextEvidenceId();
        uint256 countBefore = registry.getCustodyCount(eid);

        (EvidenceRegistry.CustodyRecord[] memory records, uint256 total) = registry.getCustodyHistory(eid, 0, 10);
        assert(total == 1);
        assert(records.length == 1);

        // Assert contract state has not mutated
        assert(registry.nextEvidenceId() == nextIdBefore);
        assert(registry.getCustodyCount(eid) == countBefore);
    }

    function test_CustodyPagination_EvidenceNotFoundReverts() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.EvidenceNotFound.selector, 9999));
        registry.getCustodyHistory(9999, 0, 10);

        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.EvidenceNotFound.selector, 9999));
        registry.getCustodyCount(9999);
    }
}
