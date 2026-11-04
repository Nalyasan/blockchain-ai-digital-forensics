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
 * @title ChallengerDIDAdversarialTest
 * @notice Independent empirical adversarial challenge suite probing:
 *         1. Signature Malleability (high-s, s=n-s, non-canonical v, corrupt length)
 *         2. Cross-Chain & Cross-Contract Replay attacks
 *         3. Nonce Reuse & Signature Hash Replay attacks
 *         4. Expired Deadline & exact boundary conditions
 *         5. Role Privilege Escalation & Access Control bypasses
 *         6. Zero-Value & boundary input attacks
 */
contract ChallengerDIDAdversarialTest {
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

    bytes32 public roleCollector;
    bytes32 public roleAnalyst;
    bytes32 public roleFirst;
    bytes32 public roleZkml;
    bytes32 public roleCustodian;

    bytes32 constant CASE_001 = bytes32("CASE-2026-ADV-001");
    bytes32 constant MANIFEST_HASH = 0x1111111111111111111111111111111111111111111111111111111111111111;
    string constant STORAGE_URI = "evidence://adv-001/manifest.json";

    bytes32 constant ART_HASH = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    bytes32 constant NOTE_HASH = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    bytes32 constant MODEL_HASH = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 constant XAI_DIGEST = 0x6666666666666666666666666666666666666666666666666666666666666666;
    bytes32 constant ZKML_PROOF_HASH = 0x7777777777777777777777777777777777777777777777777777777777777777;

    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function setUp() public {
        deployer = address(this);
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        charlie = vm.addr(CHARLIE_PK);
        stranger = vm.addr(STRANGER_PK);

        registry = new EvidenceRegistryDID();

        roleCollector = registry.ROLE_COLLECTOR();
        roleAnalyst = registry.ROLE_ANALYST();
        roleFirst = registry.ROLE_FIRST_RESPONDER();
        roleZkml = registry.ROLE_ZKML_VERIFIER();
        roleCustodian = registry.ROLE_CUSTODIAN();
    }

    // Helper: compute transfer struct hash
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

    // Helper: compute attestation struct hash
    function _attestationStructHash(
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(
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
    }

    // Helper: sign digest
    function _signDigest(uint256 pk, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // Helper: sign transfer
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
        bytes32 sHash = _transferStructHash(evidenceId, fromCust, toCust, artSha, nHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        return _signDigest(pk, digest);
    }

    // Helper: sign attestation
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
        bytes32 sHash = _attestationStructHash(evidenceId, attestor, role, artifactHash, statementHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        return _signDigest(pk, digest);
    }

    // Helper: make malleable transfer sig
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
        bytes32 sHash = _transferStructHash(evidenceId, fromCust, toCust, artSha, nHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes32 sPrime = bytes32(SECP256K1_N - uint256(s));
        uint8 vPrime = (v == 27) ? 28 : 27;
        return abi.encodePacked(r, sPrime, vPrime);
    }

    // Helper: make malleable attestation sig
    function _makeMalleableAttestationSig(
        uint256 pk,
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline
    ) internal returns (bytes memory) {
        bytes32 sHash = _attestationStructHash(evidenceId, attestor, role, artifactHash, statementHash, nonce, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        bytes32 sPrime = bytes32(SECP256K1_N - uint256(s));
        uint8 vPrime = (v == 27) ? 28 : 27;
        return abi.encodePacked(r, sPrime, vPrime);
    }

    // Helper: setup Alice as evidence creator and custodian, Bob as custodian
    function _setupCustodiansAndEvidence() internal returns (uint256) {
        registry.grantRole(alice, roleCollector);
        registry.grantRole(alice, roleCustodian);
        registry.grantRole(bob, roleCustodian);

        vm.prank(alice);
        return registry.registerEvidence(CASE_001, MANIFEST_HASH, STORAGE_URI);
    }

    // =========================================================================
    // Vector 1: Signature Malleability (High-S, non-canonical V, length check)
    // =========================================================================

    function test_ADV_01_Transfer_HighS_Malleability_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory malleableSig = _makeMalleableTransferSig(
            ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline
        );

        vm.expectRevert(EvidenceRegistryDID.InvalidSignatureS.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, malleableSig);
    }

    function test_ADV_02_Attestation_HighS_Malleability_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory malleableSig = _makeMalleableAttestationSig(
            ALICE_PK, evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        vm.expectRevert(EvidenceRegistryDID.InvalidSignatureS.selector);
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, malleableSig
        );
    }

    function test_ADV_03_Transfer_Boundary_S_GreaterThanHalfN_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        (, bytes32 r, ) = vm.sign(ALICE_PK, digest);

        // Exactly n/2 + 1
        bytes32 boundaryS = bytes32(SECP256K1_N_DIV_2 + 1);
        bytes memory craftedSig = abi.encodePacked(r, boundaryS, uint8(27));

        vm.expectRevert(EvidenceRegistryDID.InvalidSignatureS.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, craftedSig);
    }

    function test_ADV_04_Invalid_V_Values_Revert() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), sHash));
        (, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);

        // Test v = 0, 1, 26, 29
        uint8[4] memory badVs = [uint8(0), uint8(1), uint8(26), uint8(29)];
        for (uint256 i = 0; i < badVs.length; i++) {
            bytes memory badSig = abi.encodePacked(r, s, badVs[i]);
            vm.expectRevert(EvidenceRegistryDID.InvalidSignatureV.selector);
            registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, badSig);
        }
    }

    function test_ADV_05_Invalid_Signature_Length_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory shortSig = new bytes(64); // missing v
        vm.expectRevert(EvidenceRegistryDID.InvalidSignature.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, shortSig);

        bytes memory longSig = new bytes(66); // 1 extra byte
        vm.expectRevert(EvidenceRegistryDID.InvalidSignature.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, longSig);
    }

    // =========================================================================
    // Vector 2: Cross-Chain & Cross-Contract Replay
    // =========================================================================

    function test_ADV_06_CrossChain_Transfer_Replay_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        // Alice signs with chainId = 1 (Mainnet) while contract is on chainId = 31337
        bytes32 foreignDomain = keccak256(
            abi.encode(
                registry.EIP712_DOMAIN_TYPEHASH(),
                keccak256(bytes("EvidenceRegistryDID")),
                keccak256(bytes("1")),
                uint256(1), // chainId 1
                address(registry)
            )
        );
        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes32 foreignDigest = keccak256(abi.encodePacked("\x19\x01", foreignDomain, sHash));
        bytes memory sig = _signDigest(ALICE_PK, foreignDigest);

        // In verification, ecrecover on local digest will yield recovered != alice
        vm.expectRevert();
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_07_CrossChain_Attestation_Replay_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 foreignDomain = keccak256(
            abi.encode(
                registry.EIP712_DOMAIN_TYPEHASH(),
                keccak256(bytes("EvidenceRegistryDID")),
                keccak256(bytes("1")),
                uint256(137), // Polygon
                address(registry)
            )
        );
        bytes32 sHash = _attestationStructHash(evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline);
        bytes32 foreignDigest = keccak256(abi.encodePacked("\x19\x01", foreignDomain, sHash));
        bytes memory sig = _signDigest(ALICE_PK, foreignDigest);

        vm.expectRevert();
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );
    }

    function test_ADV_08_CrossContract_Transfer_Replay_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        // Alice signs for a different contract address 0xDEADBEEF
        bytes32 foreignDomain = keccak256(
            abi.encode(
                registry.EIP712_DOMAIN_TYPEHASH(),
                keccak256(bytes("EvidenceRegistryDID")),
                keccak256(bytes("1")),
                block.chainid,
                address(0xDEADBEEF)
            )
        );
        bytes32 sHash = _transferStructHash(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        bytes32 foreignDigest = keccak256(abi.encodePacked("\x19\x01", foreignDomain, sHash));
        bytes memory sig = _signDigest(ALICE_PK, foreignDigest);

        vm.expectRevert();
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_09_CrossType_Signature_Replay_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 1 hours;

        // Alice signs an attestation
        bytes memory attestationSig = _signAttestation(
            ALICE_PK, evidenceId, alice, roleAnalyst, ART_HASH, NOTE_HASH, 0, deadline
        );

        // Attacker attempts to replay attestation signature in transferCustodyWithSig
        vm.expectRevert();
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, attestationSig);
    }

    // =========================================================================
    // Vector 3: Nonce Reuse & Double Spending Defenses
    // =========================================================================

    function test_ADV_10_NonceReuse_IdenticalCall_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);

        // 1st call passes
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);

        // 2nd call with same nonce must revert with InvalidNonce(expected 1, provided 0)
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.InvalidNonce.selector,
                1,
                0
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_11_Attestation_SignatureAlreadyUsed_TriggeredIfNonceSpoofed() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAttestation(
            ALICE_PK, evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        // 1st call passes
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );

        // Attacker observes Alice's nonce is now 1, and calls with nonce = 1, but passing the OLD signature
        // The contract's executedSignatures check fires BEFORE signature recovery!
        vm.expectRevert(EvidenceRegistryDID.SignatureAlreadyUsed.selector);
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 1, deadline, sig
        );
    }

    function test_ADV_12_Attestation_NonceReuse_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signAttestation(
            ALICE_PK, evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        // First attestation succeeds
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );

        // Duplicate attestation reverts with InvalidNonce
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.InvalidNonce.selector,
                1,
                0
            )
        );
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );
    }

    function test_ADV_13_Out_Of_Order_Nonce_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        // Alice is at nonce 0, but signature is crafted with nonce 5
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 5, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.InvalidNonce.selector,
                0,
                5
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 5, deadline, sig);
    }

    // =========================================================================
    // Vector 4: Expired Deadline & Exact Boundary
    // =========================================================================

    function test_ADV_14_Expired_Deadline_Transfer_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);

        // Advance 1 second past deadline
        vm.warp(deadline + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.SignatureExpired.selector,
                deadline,
                deadline + 1
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_15_Expired_Deadline_Attestation_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(alice, roleAnalyst);
        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _signAttestation(
            ALICE_PK, evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        vm.warp(deadline + 5);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.SignatureExpired.selector,
                deadline,
                deadline + 5
            )
        );
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );
    }

    function test_ADV_16_Exact_Deadline_Boundary_Succeeds() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);

        // Warp exactly to deadline: block.timestamp == deadline
        vm.warp(deadline);

        // In Solidity: `if (block.timestamp > deadline) revert SignatureExpired(...)`
        // At exact deadline, execution must SUCCEED.
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);

        assertEq(registry.currentCustodians(evidenceId), bob);
    }

    // =========================================================================
    // Vector 5: Role Privilege Escalation & Access Control
    // =========================================================================

    function test_ADV_17_Transfer_From_Unauthorized_Sender_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(bob, roleCustodian);
        uint256 deadline = block.timestamp + 1 hours;

        // Stranger has no role
        bytes memory sig = _signTransfer(STRANGER_PK, evidenceId, stranger, bob, ART_HASH, NOTE_HASH, 0, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                stranger,
                roleCustodian
            )
        );
        registry.transferCustodyWithSig(evidenceId, stranger, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_18_Transfer_To_Unauthorized_Recipient_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;

        // Stranger has no ROLE_CUSTODIAN
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, stranger, ART_HASH, NOTE_HASH, 0, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                stranger,
                roleCustodian
            )
        );
        registry.transferCustodyWithSig(evidenceId, alice, stranger, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_19_Custody_Theft_NonCurrentCustodian_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        registry.grantRole(charlie, roleCustodian);
        uint256 deadline = block.timestamp + 1 hours;

        // 1. Alice transfers custody to Bob
        bytes memory sig1 = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);
        registry.transferCustodyWithSig(evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig1);
        assertEq(registry.currentCustodians(evidenceId), bob);

        // 2. Now Charlie (a custodian, but NOT the holder of evidenceId) tries to transfer it to Alice!
        bytes memory sig2 = _signTransfer(CHARLIE_PK, evidenceId, charlie, alice, ART_HASH, NOTE_HASH, 0, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.NotCurrentCustodian.selector,
                evidenceId,
                charlie
            )
        );
        registry.transferCustodyWithSig(evidenceId, charlie, alice, ART_HASH, NOTE_HASH, 0, deadline, sig2);
    }

    function test_ADV_20_Attestation_UnauthorizedRole_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        // Alice only has COLLECTOR and CUSTODIAN, NOT ANALYST
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory sig = _signAttestation(
            ALICE_PK, evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                alice,
                roleAnalyst
            )
        );
        registry.recordAttestationWithSig(
            evidenceId, alice, roleAnalyst, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );
    }

    function test_ADV_21_Attestation_FabricatedRole_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 fakeRole = keccak256("ROLE_SUPER_ADMIN");

        bytes memory sig = _signAttestation(
            ALICE_PK, evidenceId, alice, fakeRole, MODEL_HASH, XAI_DIGEST, 0, deadline
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                alice,
                fakeRole
            )
        );
        registry.recordAttestationWithSig(
            evidenceId, alice, fakeRole, MODEL_HASH, XAI_DIGEST, 0, deadline, sig
        );
    }

    function test_ADV_22_Direct_Custody_Unauthorized_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                stranger,
                roleCollector
            )
        );
        registry.recordCustodyDID(
            evidenceId,
            EvidenceRegistry.CustodyAction.COLLECTED,
            IEvidenceRegistryDID.ISOStage.COLLECTION,
            roleCollector,
            alice,
            ART_HASH,
            NOTE_HASH,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
    }

    function test_ADV_23_Direct_AnchorForensicEvidence_Unauthorized_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistryDID.UnauthorizedRole.selector,
                stranger,
                roleAnalyst
            )
        );
        registry.anchorForensicEvidence(
            evidenceId,
            MODEL_HASH,
            XAI_DIGEST,
            ZKML_PROOF_HASH,
            ART_HASH,
            NOTE_HASH
        );
    }

    function test_ADV_24_Stranger_Cannot_Grant_Or_Revoke_Role() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.Unauthorized.selector,
                stranger
            )
        );
        registry.grantRole(stranger, roleAnalyst);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.Unauthorized.selector,
                stranger
            )
        );
        registry.revokeRole(alice, roleCollector);
    }

    function test_ADV_25_Stranger_Cannot_Hijack_DID_Identity() public {
        // Stranger attempts to change Alice's DID identity owner
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.Unauthorized.selector,
                stranger
            )
        );
        registry.changeOwner(alice, stranger);

        // Stranger attempts to add delegate for Alice
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.Unauthorized.selector,
                stranger
            )
        );
        registry.addDelegate(alice, keccak256("admin"), stranger, 1 days);
    }

    // =========================================================================
    // Vector 6: Parameter Boundary & Zero-Value Attacks
    // =========================================================================

    function test_ADV_26_Zero_Address_In_Transfer_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);

        // fromCustodian == 0
        vm.expectRevert(EvidenceRegistry.ZeroValue.selector);
        registry.transferCustodyWithSig(evidenceId, address(0), bob, ART_HASH, NOTE_HASH, 0, deadline, sig);

        // toCustodian == 0
        vm.expectRevert(EvidenceRegistry.ZeroValue.selector);
        registry.transferCustodyWithSig(evidenceId, alice, address(0), ART_HASH, NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_27_Zero_Artifact_Hash_Reverts() public {
        uint256 evidenceId = _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(ALICE_PK, evidenceId, alice, bob, bytes32(0), NOTE_HASH, 0, deadline);

        vm.expectRevert(EvidenceRegistry.ZeroValue.selector);
        registry.transferCustodyWithSig(evidenceId, alice, bob, bytes32(0), NOTE_HASH, 0, deadline, sig);
    }

    function test_ADV_28_NonExistent_EvidenceId_Reverts() public {
        _setupCustodiansAndEvidence();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signTransfer(ALICE_PK, 999, alice, bob, ART_HASH, NOTE_HASH, 0, deadline);

        // evidenceId 999 does not exist
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.EvidenceNotFound.selector,
                999
            )
        );
        registry.transferCustodyWithSig(999, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);

        // evidenceId 0
        vm.expectRevert(
            abi.encodeWithSelector(
                EvidenceRegistry.EvidenceNotFound.selector,
                0
            )
        );
        registry.transferCustodyWithSig(0, alice, bob, ART_HASH, NOTE_HASH, 0, deadline, sig);
    }
}
