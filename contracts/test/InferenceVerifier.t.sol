// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/InferenceVerifier.sol";
import "../src/interfaces/IInferenceVerifier.sol";
import "../src/EvidenceRegistryDID.sol";

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
    function getBlockTimestamp() external returns (uint256);
}

/**
 * @title InferenceVerifierTest
 * @notice Complete Foundry Test Suite for InferenceVerifier (Gate T22, AGENT.md §7).
 */
contract InferenceVerifierTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    InferenceVerifier public verifier;
    MockCircuitVerifier public mockCircuit;
    EvidenceRegistryDID public registryDID;

    address public deployer;
    address public alice;
    address public stranger;

    bytes32 constant CANONICAL_MODEL_HASH = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 constant WRONG_MODEL_HASH     = 0x9999999999999999999999999999999999999999999999999999999999999999;
    bytes32 constant INPUT_COMMITMENT     = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant OUTPUT_COMMITMENT    = 0x2222222222222222222222222222222222222222222222222222222222222222;
    string constant RECORD_ID_1           = "INF-RECORD-2026-001";
    string constant RECORD_ID_2           = "INF-RECORD-2026-002";

    bytes validProof;
    bytes alteredProof;
    bytes32 validProofHash;

    // --- Assert Helpers ---
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

    function setUp() public {
        deployer = address(this);
        alice = address(0xA11CE);
        stranger = address(0xBAD);

        // Generate synthetic canonical proof bytes (> 64 bytes)
        validProof = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            validProof[i] = bytes1(uint8(i + 1));
        }
        validProofHash = keccak256(validProof);

        alteredProof = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            alteredProof[i] = bytes1(uint8(i + 1));
        }
        alteredProof[63] = bytes1(0xFF); // Bit flip tamper

        mockCircuit = new MockCircuitVerifier(validProofHash);

        // Deploy InferenceVerifier with strict revertOnFailure = true
        verifier = new InferenceVerifier(
            address(mockCircuit),
            CANONICAL_MODEL_HASH,
            true
        );

        registryDID = new EvidenceRegistryDID();
    }

    // =========================================================================
    // 1. Initial State & Configuration Tests
    // =========================================================================

    function test_InitialState() public view {
        assertEq(verifier.owner(), deployer);
        assertEq(verifier.circuitVerifier(), address(mockCircuit));
        assertEq(verifier.expectedModelCommitment(), CANONICAL_MODEL_HASH);
        assertTrue(verifier.revertOnFailure());
    }

    // =========================================================================
    // 2. Positive Verification Tests (Gate T20, Gate T22)
    // =========================================================================

    function test_Positive_VerifyInferenceProof_Success() public {
        vm.expectEmit(true, true, false, false);
        emit IInferenceVerifier.InferenceVerified(
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1,
            true,
            0
        );

        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );

        assertTrue(success);
        assertTrue(verifier.recordExists(RECORD_ID_1));
        assertTrue(verifier.isProofVerified(validProofHash));

        IInferenceVerifier.VerificationRecord memory rec = verifier.getVerificationRecord(RECORD_ID_1);
        assertEq(rec.modelCommitment, CANONICAL_MODEL_HASH);
        assertEq(rec.inputCommitment, INPUT_COMMITMENT);
        assertEq(rec.outputCommitment, OUTPUT_COMMITMENT);
        assertEq(rec.proofHash, validProofHash);
        assertTrue(rec.isValid);
        assertEq(rec.submitter, deployer);
        assertTrue(rec.gasUsed > 0);
    }

    function test_Positive_VerifyInference_PublicSignals() public {
        uint256[] memory signals = new uint256[](2);
        signals[0] = uint256(INPUT_COMMITMENT);
        signals[1] = uint256(OUTPUT_COMMITMENT);

        bool success = verifier.verifyInference(
            validProof,
            signals,
            CANONICAL_MODEL_HASH,
            RECORD_ID_2
        );

        assertTrue(success);
        assertTrue(verifier.recordExists(RECORD_ID_2));
    }

    function test_Positive_VerifyInference_Bytes32RecordId() public {
        uint256[] memory signals = new uint256[](2);
        signals[0] = uint256(INPUT_COMMITMENT);
        signals[1] = uint256(OUTPUT_COMMITMENT);

        bytes32 b32Id = bytes32("INF-RECORD-B32");
        bool success = verifier.verifyInference(
            validProof,
            signals,
            CANONICAL_MODEL_HASH,
            b32Id
        );

        assertTrue(success);
        assertTrue(verifier.recordExists("INF-RECORD-B32"));
    }

    function test_Positive_AutonomousMode_NoCircuitAttached() public {
        // Deploy standalone verifier without circuit verifier attached
        InferenceVerifier autonomous = new InferenceVerifier(
            address(0),
            CANONICAL_MODEL_HASH,
            true
        );

        bool success = autonomous.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            "AUTO-001"
        );

        assertTrue(success);
        assertTrue(autonomous.recordExists("AUTO-001"));
    }

    // =========================================================================
    // 3. Negative Adversarial Tests (Gate T21, Gate T22)
    // =========================================================================

    function test_Negative_AlteredProofBytes_Reverts() public {
        // Tampered proof bytes cause mock circuit verifier to reject
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "Circuit verifier returned false"
            )
        );

        verifier.verifyInferenceProof(
            alteredProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    function test_Negative_AlteredProofBytes_ReturnsFalse_WhenRevertDisabled() public {
        verifier.setRevertOnFailure(false);

        vm.expectEmit(true, true, false, false);
        emit IInferenceVerifier.InferenceVerified(
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1,
            false,
            0
        );

        bool success = verifier.verifyInferenceProof(
            alteredProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );

        assertFalse(success);
        assertFalse(verifier.recordExists(RECORD_ID_1));
    }

    function test_Negative_MismatchedModelCommitment_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.ModelCommitmentMismatch.selector,
                CANONICAL_MODEL_HASH,
                WRONG_MODEL_HASH
            )
        );

        verifier.verifyInferenceProof(
            validProof,
            WRONG_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    function test_Negative_MismatchedModelCommitment_ReturnsFalse_WhenRevertDisabled() public {
        verifier.setRevertOnFailure(false);

        bool success = verifier.verifyInferenceProof(
            validProof,
            WRONG_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );

        assertFalse(success);
        assertFalse(verifier.recordExists(RECORD_ID_1));
    }

    function test_Negative_ZeroModelCommitment_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "modelCommitment"
            )
        );

        verifier.verifyInferenceProof(
            validProof,
            bytes32(0),
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    function test_Negative_ZeroInputCommitment_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "inputCommitment"
            )
        );

        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            bytes32(0),
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    function test_Negative_ZeroOutputCommitment_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "outputCommitment"
            )
        );

        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            bytes32(0),
            RECORD_ID_1
        );
    }

    function test_Negative_EmptyInferenceRecordId_Reverts() public {
        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);

        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            ""
        );
    }

    function test_Negative_TruncatedProof_Reverts() public {
        bytes memory truncated = hex"12345678"; // 4 bytes < 64 bytes

        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);

        verifier.verifyInferenceProof(
            truncated,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    function test_Negative_CircuitVerifierReverts_CaughtCleanly() public {
        mockCircuit.setBehavior(true, false); // will revert

        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "Mock pairing check failure"
            )
        );

        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
    }

    // =========================================================================
    // 4. Gas Profiling & Budget Enforcement
    // =========================================================================

    function test_GasProfiling_VerifyInferenceProof() public {
        uint256 gStart = gasleft();
        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            "GAS-TEST-001"
        );
        uint256 gTotal = gStart - gasleft();

        assertTrue(success);
        // Total transaction execution gas should be within cold-storage bounds (< 350k gas)
        assertTrue(gTotal < 350000);

        IInferenceVerifier.VerificationRecord memory rec = verifier.getVerificationRecord("GAS-TEST-001");
        assertTrue(rec.gasUsed > 0);
        // Pure computational verification gas strictly within 150k gas limit mandated by DISPATCH
        assertTrue(rec.gasUsed < 150000);
        assertTrue(rec.gasUsed < gTotal);
    }

    // =========================================================================
    // 5. Admin & Ownership Lifecycle Tests
    // =========================================================================

    function test_Admin_OnlyOwnerCanUpdateConfig() public {
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setExpectedModelCommitment(WRONG_MODEL_HASH);

        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setCircuitVerifier(address(0));

        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setRevertOnFailure(false);
    }

    function test_Admin_TwoStepOwnershipTransfer() public {
        verifier.transferOwnership(alice);
        assertEq(verifier.owner(), deployer);

        vm.prank(alice);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), alice);

        // Previous owner is now unauthorized
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setRevertOnFailure(false);

        // New owner succeeds
        vm.prank(alice);
        verifier.setRevertOnFailure(false);
        assertFalse(verifier.revertOnFailure());
    }

    // =========================================================================
    // 6. Chain of Custody Integration with EvidenceRegistryDID
    // =========================================================================

    function test_Integration_EvidenceBinding_With_EvidenceRegistryDID() public {
        // 1. Verify inference on InferenceVerifier
        bool verified = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL_HASH,
            INPUT_COMMITMENT,
            OUTPUT_COMMITMENT,
            RECORD_ID_1
        );
        assertTrue(verified);

        // 2. Fetch binding digest
        (bytes32 bindingHash, bytes32 proofHash) = verifier.getEvidenceBinding(RECORD_ID_1);
        assertEq(proofHash, validProofHash);

        // 3. Register evidence and anchor on EvidenceRegistryDID
        bytes32 caseId = bytes32("CASE-ZKML-2026");
        bytes32 manifestSha256 = 0x3333333333333333333333333333333333333333333333333333333333333333;
        uint256 evidenceId = registryDID.registerEvidence(
            caseId,
            manifestSha256,
            "evidence://case-zkml/manifest.json"
        );

        // 4. Anchor forensic evidence referencing ZKML proof hash and model hash
        bytes32 xaiDigest = 0x4444444444444444444444444444444444444444444444444444444444444444;
        bytes32 noteHash = 0x6666666666666666666666666666666666666666666666666666666666666666;

        registryDID.anchorForensicEvidence(
            evidenceId,
            CANONICAL_MODEL_HASH,
            xaiDigest,
            proofHash,
            bindingHash,
            noteHash
        );

        // 5. Query EvidenceRegistryDID custody history to assert anchoring
        IEvidenceRegistryDID.CustodyRecordDID[] memory records = registryDID.getCustodyHistoryDID(evidenceId);
        assertTrue(records.length > 0);
        IEvidenceRegistryDID.CustodyRecordDID memory lastRec = records[records.length - 1];
        assertEq(lastRec.modelHash, CANONICAL_MODEL_HASH);
        assertEq(lastRec.zkmlProofHash, proofHash);
        assertEq(lastRec.artifactSha256, bindingHash);
    }
}
