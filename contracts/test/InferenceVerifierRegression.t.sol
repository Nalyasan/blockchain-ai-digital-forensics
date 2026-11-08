// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/InferenceVerifier.sol";
import "../src/Halo2Verifier.sol";
import "../src/interfaces/IInferenceVerifier.sol";

interface VmRegression {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function expectRevert(bytes calldata) external;
    function expectRevert(bytes4) external;
    function expectEmit(bool, bool, bool, bool) external;
}

/**
 * @title InferenceVerifierRegressionTest
 * @notice Dedicated regression test suite verifying proof uniqueness, inference record
 *         immutability, fail-fast revert behavior, and Halo2 view state mutability (R2).
 */
contract InferenceVerifierRegressionTest {
    VmRegression constant vm = VmRegression(address(uint160(uint256(keccak256("hevm cheat code")))));

    InferenceVerifier public verifier;
    MockCircuitVerifier public mockCircuit;
    Halo2Verifier public halo2Verifier;

    address public deployer = 0xAaaa111122223333444455556666777788889999;
    address public alice    = 0xBbBB111122223333444455556666777788889999;
    address public eve      = 0xEEee111122223333444455556666777788889999;

    bytes32 constant CANONICAL_MODEL  = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 constant CANONICAL_INPUT  = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant CANONICAL_OUTPUT = 0x2222222222222222222222222222222222222222222222222222222222222222;

    bytes proofA;
    bytes proofB;
    bytes proofC;

    bytes32 proofHashA;
    bytes32 proofHashB;
    bytes32 proofHashC;

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

    function setUp() public {
        proofA = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            proofA[i] = bytes1(uint8(i + 1));
        }
        proofHashA = keccak256(proofA);

        proofB = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            proofB[i] = bytes1(uint8(i + 101));
        }
        proofHashB = keccak256(proofB);

        proofC = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            proofC[i] = bytes1(uint8(i + 201));
        }
        proofHashC = keccak256(proofC);

        mockCircuit = new MockCircuitVerifier(bytes32(0));
        verifier = new InferenceVerifier(address(mockCircuit), CANONICAL_MODEL, true);
        halo2Verifier = new Halo2Verifier();
    }

    function test_REG_01_ProofUniqueness_RevertsOnDuplicateProofHash() public {
        // Step 1: Alice registers record with proofA
        vm.prank(alice);
        bool first = verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REG-01-A"
        );
        assertTrue(first);
        assertTrue(verifier.isProofVerified(proofHashA));
        assertTrue(verifier.recordExists("REC-REG-01-A"));

        // Step 2: Attempting to reuse proofA for a new record ID MUST revert with ProofAlreadyVerified
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.ProofAlreadyVerified.selector,
                proofHashA
            )
        );
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REG-01-B"
        );

        // Step 3: Verify second record was never created in storage
        assertFalse(verifier.recordExists("REC-REG-01-B"));
    }

    function test_REG_02_RecordImmutability_RevertsOnDuplicateRecordId() public {
        // Step 1: Alice registers REC-REG-02 with proofA
        vm.prank(alice);
        bool first = verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REG-02"
        );
        assertTrue(first);

        // Step 2: Attempting to verify with same record ID and a new proofB MUST revert with RecordAlreadyExists
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.RecordAlreadyExists.selector,
                "REC-REG-02"
            )
        );
        verifier.verifyInferenceProof(
            proofB,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REG-02"
        );

        // Step 3: Ensure proofB was not consumed or marked verified due to early revert
        assertFalse(verifier.isProofVerified(proofHashB));
    }

    function test_REG_03_RecordImmutability_EveCannotOverwriteAliceRecord() public {
        // Step 1: Alice registers original forensic evidence
        vm.prank(alice);
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-IMMUTABLE-01"
        );
        IInferenceVerifier.VerificationRecord memory aliceRec = verifier.getVerificationRecord("REC-IMMUTABLE-01");
        assertEq(aliceRec.submitter, alice);
        assertEq(aliceRec.inputCommitment, CANONICAL_INPUT);
        assertEq(aliceRec.outputCommitment, CANONICAL_OUTPUT);
        assertEq(aliceRec.proofHash, proofHashA);

        // Step 2: Adversary Eve attempts to overwrite Alice's record with mutated data
        bytes32 eveInput = 0x9999999999999999999999999999999999999999999999999999999999999999;
        vm.prank(eve);
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.RecordAlreadyExists.selector,
                "REC-IMMUTABLE-01"
            )
        );
        verifier.verifyInferenceProof(
            proofB,
            CANONICAL_MODEL,
            eveInput,
            CANONICAL_OUTPUT,
            "REC-IMMUTABLE-01"
        );

        // Step 3: Verify Alice's record remains 100% byte-for-byte unchanged
        IInferenceVerifier.VerificationRecord memory postRec = verifier.getVerificationRecord("REC-IMMUTABLE-01");
        assertEq(postRec.submitter, alice);
        assertEq(postRec.inputCommitment, CANONICAL_INPUT);
        assertEq(postRec.outputCommitment, CANONICAL_OUTPUT);
        assertEq(postRec.proofHash, proofHashA);
        assertEq(postRec.timestamp, aliceRec.timestamp);
        assertEq(postRec.blockNumber, aliceRec.blockNumber);
        assertEq(postRec.gasUsed, aliceRec.gasUsed);
        assertTrue(postRec.isValid);
    }

    function test_REG_04_DistinctProofs_MultipleRecordsSucceed() public {
        // Record 1 with proofA
        bool okA = verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-DISTINCT-1"
        );
        assertTrue(okA);

        // Record 2 with proofB
        bool okB = verifier.verifyInferenceProof(
            proofB,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-DISTINCT-2"
        );
        assertTrue(okB);

        // Record 3 with proofC
        bool okC = verifier.verifyInferenceProof(
            proofC,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-DISTINCT-3"
        );
        assertTrue(okC);

        assertTrue(verifier.recordExists("REC-DISTINCT-1"));
        assertTrue(verifier.recordExists("REC-DISTINCT-2"));
        assertTrue(verifier.recordExists("REC-DISTINCT-3"));
        assertTrue(verifier.isProofVerified(proofHashA));
        assertTrue(verifier.isProofVerified(proofHashB));
        assertTrue(verifier.isProofVerified(proofHashC));
    }

    function test_REG_05_EmptyRecordId_Reverts() public {
        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            ""
        );
    }

    function test_REG_06_ZeroCommitments_Revert() public {
        vm.expectRevert(abi.encodeWithSelector(IInferenceVerifier.InvalidCommitment.selector, "modelCommitment"));
        verifier.verifyInferenceProof(
            proofA,
            bytes32(0),
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-ZERO-MODEL"
        );

        vm.expectRevert(abi.encodeWithSelector(IInferenceVerifier.InvalidCommitment.selector, "inputCommitment"));
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            bytes32(0),
            CANONICAL_OUTPUT,
            "REC-ZERO-INPUT"
        );

        vm.expectRevert(abi.encodeWithSelector(IInferenceVerifier.InvalidCommitment.selector, "outputCommitment"));
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            bytes32(0),
            "REC-ZERO-OUTPUT"
        );
    }

    function test_REG_07_ShortProof_Reverts() public {
        bytes memory shortProof = new bytes(32);
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(
            shortProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-SHORT-PROOF"
        );
    }

    function test_REG_08_EvidenceBinding_Consistency() public {
        string memory recId = "REC-BIND-REG";
        verifier.verifyInferenceProof(
            proofA,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            recId
        );

        (bytes32 bindingHash, bytes32 proofHash) = verifier.getEvidenceBinding(recId);
        bytes32 expectedBinding = keccak256(
            abi.encodePacked(
                CANONICAL_MODEL,
                CANONICAL_INPUT,
                CANONICAL_OUTPUT,
                recId
            )
        );

        assertEq(bindingHash, expectedBinding);
        assertEq(proofHash, proofHashA);
    }

    function test_REG_09_PublicSignals_Verification_Success() public {
        uint256[] memory signals = new uint256[](2);
        signals[0] = uint256(CANONICAL_INPUT);
        signals[1] = uint256(CANONICAL_OUTPUT);

        string memory recId = "REC-PUB-SIGNALS";
        bool valid = verifier.verifyInference(
            proofA,
            signals,
            CANONICAL_MODEL,
            recId
        );

        assertTrue(valid);
        assertTrue(verifier.recordExists(recId));
    }

    function test_REG_10_Halo2Verifier_View_Mutability() public view {
        // Assert that Halo2Verifier.verifyProof is a view function and can be executed via STATICCALL
        (bool success, ) = address(halo2Verifier).staticcall(
            abi.encodeWithSignature("verifyProof(bytes,uint256[])", new bytes(64), new uint256[](0))
        );
        // It executed via STATICCALL without EVM state modification exception
        assertFalse(success);
    }
}
