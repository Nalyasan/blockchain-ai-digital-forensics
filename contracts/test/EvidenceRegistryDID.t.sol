// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/EvidenceRegistryDID.sol";
import "../src/interfaces/IEvidenceRegistryDID.sol";

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function expectRevert() external;
    function expectRevert(bytes calldata) external;
    function expectRevert(bytes4) external;
    function warp(uint256) external;
    function assume(bool) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
}

/**
 * @title EvidenceRegistryDIDTest
 * @notice Comprehensive test suite for Phase 3 (P10) EvidenceRegistryDID contract:
 *         - P3 backward compatibility & storage layout invariance
 *         - ERC-1056 Decentralized Identity (DID) lifecycle
 *         - Granular forensic RBAC & bidirectional synchronization
 *         - EIP-712 typed signature verification & adversarial vectors (anti-replay, malleability, cross-chain)
 *         - ISO/IEC 27037 4-stage lifecycle & AI/XAI/ZKML artifact anchoring
 */
contract EvidenceRegistryDIDTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool b) internal pure {
        assert(b);
    }

    function assertFalse(bool b) internal pure {
        assert(!b);
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        assert(a == b);
    }

    function assertEq(address a, address b) internal pure {
        assert(a == b);
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        assert(a == b);
    }

    function assertEq(string memory a, string memory b) internal pure {
        assert(keccak256(bytes(a)) == keccak256(bytes(b)));
    }

    function assertEq(bytes memory a, bytes memory b) internal pure {
        assert(keccak256(a) == keccak256(b));
    }

    EvidenceRegistryDID public registry;
    address public deployer;

    uint256 constant ALICE_PK = 0xA11CE01;
    uint256 constant BOB_PK = 0xB0B01;
    uint256 constant CHARLIE_PK = 0xC0C01;
    uint256 constant STRANGER_PK = 0xBAD01;

    address public alice;
    address public bob;
    address public charlie;
    address public stranger;

    bytes32 constant CASE_001 = bytes32("CASE-2026-P10-001");
    bytes32 constant MANIFEST_HASH_1 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant MANIFEST_HASH_2 = 0x2222222222222222222222222222222222222222222222222222222222222222;
    string constant STORAGE_URI = "evidence://case-001/manifest.json";

    bytes32 constant ART_HASH = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    bytes32 constant NOTE_HASH = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    bytes32 constant MODEL_HASH = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 constant XAI_DIGEST = 0x6666666666666666666666666666666666666666666666666666666666666666;
    bytes32 constant ZKML_PROOF_HASH = 0x7777777777777777777777777777777777777777777777777777777777777777;

    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Events for expectEmit
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
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event DIDOwnerChanged(address indexed identity, address newOwner, uint256 previousChange);
    event DIDDelegateChanged(address indexed identity, bytes32 indexed delegateType, address delegate, uint256 validTo, uint256 previousChange);
    event DIDAttributeChanged(address indexed identity, bytes32 indexed name, bytes value, uint256 validTo, uint256 previousChange);
    event CustodyTransferred(
        uint256 indexed evidenceId,
        address indexed fromCustodian,
        address indexed toCustodian,
        bytes32 artifactSha256,
        bytes32 noteHash,
        uint256 timestamp
    );
    event ForensicEvidenceAnchored(
        uint256 indexed evidenceId,
        bytes32 indexed modelHash,
        bytes32 indexed xaiDigest,
        bytes32 zkmlProofHash,
        address actor
    );

    function setUp() public {
        deployer = address(this);
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        charlie = vm.addr(CHARLIE_PK);
        stranger = vm.addr(STRANGER_PK);

        registry = new EvidenceRegistryDID();
    }

    // =========================================================================
    // 1. Initial State & Backward Compatibility (P3 Invariance)
    // =========================================================================

    function test_InitialState_DeployerHasAllRoles() public view {
        assertEq(registry.owner(), deployer);
        assertTrue(registry.authorizedInvestigators(deployer));
        assertTrue(registry.hasRole(deployer, registry.ROLE_COLLECTOR()));
        assertTrue(registry.hasRole(deployer, registry.ROLE_ANALYST()));
        assertTrue(registry.hasRole(deployer, registry.ROLE_FIRST_RESPONDER()));
        assertTrue(registry.hasRole(deployer, registry.ROLE_ZKML_VERIFIER()));
        assertTrue(registry.hasRole(deployer, registry.ROLE_CUSTODIAN()));
        assertEq(registry.identityOwner(deployer), deployer);
        assertEq(registry.nextEvidenceId(), 1);
    }

    function test_P3_RegisterEvidence_ExactSelector() public {
        uint256 id = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);
        assertEq(id, 1);
        assertEq(registry.hashToEvidenceId(MANIFEST_HASH_1), 1);

        EvidenceRegistry.EvidenceItem memory item = registry.getEvidence(1);
        assertEq(item.evidenceId, 1);
        assertEq(item.caseId, CASE_001);
        assertEq(item.manifestSha256, MANIFEST_HASH_1);
        assertEq(item.storageUri, STORAGE_URI);
        assertEq(item.registeredBy, deployer);
        assertTrue(item.exists);

        (bool valid, address sub, ) = registry.verifyEvidence(1, MANIFEST_HASH_1);
        assertTrue(valid);
        assertEq(sub, deployer);
    }

    function test_P3_RecordCustody_Legacy() public {
        uint256 id = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.recordCustody(id, EvidenceRegistry.CustodyAction.COLLECTED, ART_HASH, NOTE_HASH);
        assertEq(registry.getCustodyCount(id), 1);

        EvidenceRegistry.CustodyRecord[] memory hist = registry.getCustodyHistory(id);
        assertEq(hist.length, 1);
        assertEq(hist[0].evidenceId, 1);
        assertEq(uint8(hist[0].action), uint8(EvidenceRegistry.CustodyAction.COLLECTED));
        assertEq(hist[0].actor, deployer);
        assertEq(hist[0].artifactSha256, ART_HASH);
        assertEq(hist[0].noteHash, NOTE_HASH);
    }

    function test_P3_TwoStepOwnershipTransfer() public {
        registry.transferOwnership(alice);
        assertEq(registry.pendingOwner(), alice);

        vm.prank(alice);
        registry.acceptOwnership();

        assertEq(registry.owner(), alice);
        assertEq(registry.pendingOwner(), address(0));
        assertTrue(registry.authorizedInvestigators(alice));
        assertFalse(registry.authorizedInvestigators(deployer));
    }

    // =========================================================================
    // 2. ERC-1056 Decentralized Identity (DID) Lifecycle
    // =========================================================================

    function test_DID_FormatCanonical() public view {
        string memory did = registry.getDID(alice);
        // Canonical length: "did:ethr:0x" (11) + 40 hex chars = 51 bytes
        assertEq(bytes(did).length, 51);

        // Verify known address
        string memory deployerDID = registry.getDID(deployer);
        assertEq(bytes(deployerDID).length, 51);
    }

    function test_DID_DefaultOwnerIsSelf() public view {
        assertEq(registry.identityOwner(alice), alice);
        assertEq(registry.identityOwner(bob), bob);
    }

    function test_DID_ChangeOwner_Success() public {
        vm.prank(alice);
        registry.changeOwner(alice, bob);
        assertEq(registry.identityOwner(alice), bob);

        // Now Bob controls Alice's DID
        vm.prank(bob);
        registry.changeOwner(alice, charlie);
        assertEq(registry.identityOwner(alice), charlie);
    }

    function test_DID_ChangeOwner_StrangerReverts() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.changeOwner(alice, stranger);
    }

    function test_DID_DelegateLifecycle() public {
        bytes32 dType = keccak256("FORENSIC_SUB_INVESTIGATOR");
        assertFalse(registry.validDelegate(alice, dType, bob));

        // Alice adds Bob as delegate for 3600 seconds
        vm.prank(alice);
        registry.addDelegate(alice, dType, bob, 3600);
        assertTrue(registry.validDelegate(alice, dType, bob));

        // Advance 1800 seconds - still valid
        vm.warp(block.timestamp + 1800);
        assertTrue(registry.validDelegate(alice, dType, bob));

        // Advance past 3600 seconds - expired
        vm.warp(block.timestamp + 2000);
        assertFalse(registry.validDelegate(alice, dType, bob));

        // Alice adds Bob again, then revokes early
        vm.prank(alice);
        registry.addDelegate(alice, dType, bob, 3600);
        assertTrue(registry.validDelegate(alice, dType, bob));

        vm.prank(alice);
        registry.revokeDelegate(alice, dType, bob);
        assertFalse(registry.validDelegate(alice, dType, bob));
    }

    function test_DID_AttributeEvents() public {
        bytes32 attrName = keccak256("publicKey/Ed25519");
        bytes memory attrVal = hex"1234567890abcdef";

        vm.prank(alice);
        registry.setAttribute(alice, attrName, attrVal, 86400);

        vm.prank(alice);
        registry.revokeAttribute(alice, attrName, attrVal);
    }

    // =========================================================================
    // 3. Granular Forensic Roles & Bidirectional Synchronization
    // =========================================================================

    function test_Roles_GrantAndRevoke() public {
        bytes32 roleCol = registry.ROLE_COLLECTOR();
        assertFalse(registry.hasRole(alice, roleCol));
        assertFalse(registry.hasForensicRole(alice, roleCol));

        registry.grantRole(alice, roleCol);
        assertTrue(registry.hasRole(alice, roleCol));
        assertTrue(registry.hasForensicRole(alice, roleCol));
        // Bidirectional sync: authorizedInvestigators is true
        assertTrue(registry.authorizedInvestigators(alice));

        registry.revokeRole(alice, roleCol);
        assertFalse(registry.hasRole(alice, roleCol));
        assertFalse(registry.hasForensicRole(alice, roleCol));
        // Bidirectional sync: authorizedInvestigators is false
        assertFalse(registry.authorizedInvestigators(alice));
    }

    function test_Roles_BidirectionalSync_MultipleRoles() public {
        bytes32 roleCol = registry.ROLE_COLLECTOR();
        bytes32 roleCust = registry.ROLE_CUSTODIAN();

        registry.grantRole(alice, roleCol);
        registry.grantRole(alice, roleCust);
        assertTrue(registry.authorizedInvestigators(alice));

        // Revoke one role; alice still has CUSTODIAN, so authorizedInvestigators remains true
        registry.revokeRole(alice, roleCol);
        assertTrue(registry.authorizedInvestigators(alice));

        // Revoke second role; now false
        registry.revokeRole(alice, roleCust);
        assertFalse(registry.authorizedInvestigators(alice));
    }

    function test_Roles_LegacyInvestigator_RecognizedInHasForensicRole() public {
        // Owner uses legacy P3 method setInvestigator
        registry.setInvestigator(bob, true);
        assertTrue(registry.authorizedInvestigators(bob));

        // bob automatically satisfies hasForensicRole for operational roles
        assertTrue(registry.hasForensicRole(bob, registry.ROLE_COLLECTOR()));
        assertTrue(registry.hasForensicRole(bob, registry.ROLE_ANALYST()));
        assertTrue(registry.hasForensicRole(bob, registry.ROLE_CUSTODIAN()));
        assertTrue(registry.hasForensicRole(bob, registry.ROLE_FIRST_RESPONDER()));
    }

    function test_Roles_StrangerCannotGrantRole() public {
        bytes32 role = registry.ROLE_COLLECTOR();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.Unauthorized.selector, stranger));
        registry.grantRole(alice, role);
    }

    function test_Roles_GrantZeroAddressReverts() public {
        bytes32 role = registry.ROLE_COLLECTOR();
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.ZeroValue.selector));
        registry.grantRole(address(0), role);
    }

    // =========================================================================
    // 4. EIP-712 Typed Signatures: Custody Transfer
    // =========================================================================

    function _signDigest(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _transferStructHash(
        uint256 evidenceId,
        address fromCust,
        address toCust,
        bytes32 artSha,
        bytes32 nHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                registry.CUSTODY_TRANSFER_TYPEHASH(),
                evidenceId,
                fromCust,
                toCust,
                artSha,
                nHash,
                nonce,
                deadline
            )
        );
    }

    function _signTransfer(
        uint256 pk,
        uint256 evidenceId,
        address fromCust,
        address toCust,
        bytes32 artSha,
        bytes32 nHash,
        uint256 nonce,
        uint256 deadline
    ) internal returns (bytes memory) {
        bytes32 structHash = _transferStructHash(evidenceId, fromCust, toCust, artSha, nHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash));
        return _signDigest(pk, digest);
    }

    function _signTransferCustomDomain(
        uint256 pk,
        bytes32 structHash,
        address contractAddr,
        uint256 cId
    ) internal returns (bytes memory) {
        bytes32 domainSep = keccak256(
            abi.encode(
                registry.EIP712_DOMAIN_TYPEHASH(),
                keccak256(bytes("EvidenceRegistryDID")),
                keccak256(bytes("1")),
                cId,
                contractAddr
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        return _signDigest(pk, digest);
    }

    function _makeMalleableTransferSig(
        uint256 pk,
        uint256 evidenceId,
        address fromCust,
        address toCust,
        bytes32 artSha,
        bytes32 nHash,
        uint256 nonce,
        uint256 deadline
    ) internal returns (bytes memory) {
        bytes32 structHash = _transferStructHash(evidenceId, fromCust, toCust, artSha, nHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        bytes32 malleableS = bytes32(SECP256K1_N - uint256(s));
        uint8 malleableV = (v == 27) ? 28 : 27;
        return abi.encodePacked(r, malleableS, malleableV);
    }

    function test_EIP712_TransferCustodyWithSig_Success() public {
        // 1. Setup: Alice collects evidence
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = registry.nonces(alice);

        // 2. Alice signs transfer to Bob
        bytes memory sig = _signTransfer(
            ALICE_PK,
            evidenceId,
            alice,
            bob,
            ART_HASH,
            NOTE_HASH,
            nonce,
            deadline
        );

        // 3. Relayer / stranger submits transaction
        vm.prank(stranger);
        registry.transferCustodyWithSig(
            evidenceId,
            alice,
            bob,
            ART_HASH,
            NOTE_HASH,
            nonce,
            deadline,
            sig
        );

        // 4. Verify post-transfer state
        assertEq(registry.nonces(alice), 1);
        assertEq(registry.currentCustodians(evidenceId), bob);
        assertEq(registry.getCustodyCountDID(evidenceId), 1);

        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registry.getCustodyHistoryDID(evidenceId);
        assertEq(records.length, 1);
        assertEq(records[0].actor, alice);
        assertEq(records[0].recipient, bob);
        assertEq(uint8(records[0].action), uint8(EvidenceRegistry.CustodyAction.TRANSFERRED));
        assertEq(uint8(records[0].isoStage), uint8(IEvidenceRegistryDID.ISOStage.ACQUISITION));
        assertEq(records[0].artifactSha256, ART_HASH);
        assertEq(records[0].noteHash, NOTE_HASH);
        assertEq(records[0].signature, sig);
    }

    function test_EIP712_RevertIf_SignatureExpired() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _signTransfer(
            ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline
        );

        // Warp past deadline
        vm.warp(block.timestamp + 200);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.SignatureExpired.selector,
                deadline,
                block.timestamp
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_EIP712_RevertIf_NonceReplay() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(
            ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline
        );

        // First execution succeeds
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);

        // Second execution with same nonce fails
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.InvalidNonce.selector,
                1,
                0
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_EIP712_RevertIf_SignerMismatch() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;

        // Bob signs instead of Alice
        bytes memory sig = _signTransfer(
            BOB_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.SignerMismatch.selector,
                alice,
                bob
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_EIP712_RevertIf_HighSMalleable() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;

        bytes memory malleableSig = _makeMalleableTransferSig(
            ALICE_PK,
            evidenceId,
            alice,
            bob,
            ART_HASH,
            NOTE_HASH,
            0,
            deadline
        );

        vm.expectRevert(EvidenceRegistryDID.InvalidSignatureS.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, malleableSig);
    }

    function test_EIP712_RevertIf_CrossChainReplay() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;

        // Sign for chainId 1 (Ethereum Mainnet) instead of current test chainId (31337)
        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes memory sig = _signTransferCustomDomain(ALICE_PK, sHash, address(registry), 1);

        // Signature signed for another chain will recover a wrong signer address
        vm.expectRevert();
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_EIP712_RevertIf_CrossContractReplay() public {
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(alice, registry.ROLE_CUSTODIAN());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;

        // Sign with a different contract address
        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes memory sig = _signTransferCustomDomain(ALICE_PK, sHash, address(0xDEADBEEF), block.chainid);

        vm.expectRevert();
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_EIP712_RevertIf_UnauthorizedRoleSigner() public {
        // Alice has COLLECTOR but lacks CUSTODIAN role
        registry.grantRole(alice, registry.ROLE_COLLECTOR());
        registry.grantRole(bob, registry.ROLE_CUSTODIAN());

        vm.prank(alice);
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(
            ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline
        );

        bytes32 custRole = registry.ROLE_CUSTODIAN();
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                alice,
                custRole
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    // =========================================================================
    // 5. EIP-712 Typed Signatures: Forensic Attestation
    // =========================================================================

    function _signAttestation(
        uint256 pk,
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline
    ) internal returns (bytes memory) {
        bytes32 domainSep = registry.domainSeparator();
        bytes32 structHash = keccak256(
            abi.encode(
                registry.FORENSIC_ATTESTATION_TYPEHASH(),
                evidenceId,
                attestor,
                role,
                artifactHash,
                statementHash,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        return _signDigest(pk, digest);
    }

    function test_EIP712_RecordAttestationWithSig_AnalystSuccess() public {
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.grantRole(alice, registry.ROLE_ANALYST());

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAttestation(
            ALICE_PK,
            evidenceId,
            alice,
            registry.ROLE_ANALYST(),
            MODEL_HASH,
            XAI_DIGEST,
            0,
            deadline
        );

        registry.recordAttestationWithSig(
            evidenceId,
            alice,
            registry.ROLE_ANALYST(),
            MODEL_HASH,
            XAI_DIGEST,
            0,
            deadline,
            sig
        );

        assertEq(registry.nonces(alice), 1);
        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registry.getCustodyHistoryDID(evidenceId);
        assertEq(records.length, 1);
        assertEq(records[0].actor, alice);
        assertEq(uint8(records[0].action), uint8(EvidenceRegistry.CustodyAction.ANALYZED));
        assertEq(uint8(records[0].isoStage), uint8(IEvidenceRegistryDID.ISOStage.PRESERVATION));
        assertEq(records[0].modelHash, MODEL_HASH);
        assertEq(records[0].xaiDigest, XAI_DIGEST);
    }

    function test_EIP712_RecordAttestationWithSig_ZKMLVerifierSuccess() public {
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.grantRole(bob, registry.ROLE_ZKML_VERIFIER());

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAttestation(
            BOB_PK,
            evidenceId,
            bob,
            registry.ROLE_ZKML_VERIFIER(),
            ZKML_PROOF_HASH,
            NOTE_HASH,
            0,
            deadline
        );

        registry.recordAttestationWithSig(
            evidenceId,
            bob,
            registry.ROLE_ZKML_VERIFIER(),
            ZKML_PROOF_HASH,
            NOTE_HASH,
            0,
            deadline,
            sig
        );

        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registry.getCustodyHistoryDID(evidenceId);
        assertEq(records.length, 1);
        assertEq(records[0].actor, bob);
        assertEq(records[0].zkmlProofHash, ZKML_PROOF_HASH);
    }

    // =========================================================================
    // 6. ISO/IEC 27037 Lifecycle & Forensic Anchoring
    // =========================================================================

    function test_ISO27037_AnchorForensicEvidence_FullFlow() public {
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        // Deployer holds ANALYST & ZKML_VERIFIER roles
        registry.anchorForensicEvidence(
            evidenceId,
            MODEL_HASH,
            XAI_DIGEST,
            ZKML_PROOF_HASH,
            ART_HASH,
            NOTE_HASH
        );

        assertEq(registry.getCustodyCountDID(evidenceId), 1);
        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registry.getCustodyHistoryDID(evidenceId);
        assertEq(records.length, 1);
        assertEq(records[0].modelHash, MODEL_HASH);
        assertEq(records[0].xaiDigest, XAI_DIGEST);
        assertEq(records[0].zkmlProofHash, ZKML_PROOF_HASH);
        assertEq(records[0].artifactSha256, ART_HASH);
        assertEq(records[0].noteHash, NOTE_HASH);
        assertEq(uint8(records[0].isoStage), uint8(IEvidenceRegistryDID.ISOStage.PRESERVATION));
    }

    function test_ISO27037_DirectRecordCustodyDID() public {
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        registry.recordCustodyDID(
            evidenceId,
            EvidenceRegistry.CustodyAction.COLLECTED,
            IEvidenceRegistryDID.ISOStage.COLLECTION,
            registry.ROLE_COLLECTOR(),
            alice,
            ART_HASH,
            NOTE_HASH,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );

        assertEq(registry.getCustodyCountDID(evidenceId), 1);
        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registry.getCustodyHistoryDID(evidenceId);
        assertEq(uint8(records[0].isoStage), uint8(IEvidenceRegistryDID.ISOStage.COLLECTION));
        assertEq(records[0].recipient, alice);
    }

    function test_ISO27037_CustodyPagination() public {
        uint256 evidenceId = registry.registerEvidence(CASE_001, MANIFEST_HASH_1, STORAGE_URI);

        // Insert 5 custody records
        for (uint256 i = 0; i < 5; i++) {
            registry.recordCustodyDID(
                evidenceId,
                EvidenceRegistry.CustodyAction.ANALYZED,
                IEvidenceRegistryDID.ISOStage.PRESERVATION,
                registry.ROLE_ANALYST(),
                address(0),
                keccak256(abi.encodePacked("art", i)),
                keccak256(abi.encodePacked("note", i)),
                MODEL_HASH,
                XAI_DIGEST,
                ZKML_PROOF_HASH
            );
        }

        // Test normal page
        (IEvidenceRegistryDID.CustodyRecordDID[] memory p1, uint256 total) = registry.getCustodyHistoryDID(evidenceId, 0, 2);
        assertEq(total, 5);
        assertEq(p1.length, 2);

        // Test second page
        (IEvidenceRegistryDID.CustodyRecordDID[] memory p2, ) = registry.getCustodyHistoryDID(evidenceId, 2, 2);
        assertEq(p2.length, 2);

        // Test tail page
        (IEvidenceRegistryDID.CustodyRecordDID[] memory p3, ) = registry.getCustodyHistoryDID(evidenceId, 4, 2);
        assertEq(p3.length, 1);

        // Test offset out of bounds returns empty
        (IEvidenceRegistryDID.CustodyRecordDID[] memory pEmpty, ) = registry.getCustodyHistoryDID(evidenceId, 10, 2);
        assertEq(pEmpty.length, 0);

        // Test limit > MAX_PAGE_SIZE (50) reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.PageSizeTooLarge.selector,
                51,
                50
            )
        );
        registry.getCustodyHistoryDID(evidenceId, 0, 51);
    }
}
