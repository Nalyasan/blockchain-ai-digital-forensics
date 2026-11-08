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

// --- Adversarial Auxiliary Mocks ---

contract RevertingCircuitVerifier is ICircuitVerifier {
    function verifyProof(bytes calldata, uint256[] calldata) external pure override returns (bool) {
        revert("CircuitVerifier: Pairing failure in G2");
    }
}

contract PanicCircuitVerifier is ICircuitVerifier {
    function verifyProof(bytes calldata, uint256[] calldata) external pure override returns (bool) {
        assert(false);
        return false;
    }
}

contract MalformedReturnCircuitVerifier {
    fallback() external {
        // Return 0 bytes to trigger ABI decoding failure in caller
    }
}

contract GasBurnerCircuitVerifier is ICircuitVerifier {
    function verifyProof(bytes calldata, uint256[] calldata) external pure override returns (bool) {
        uint256 x = 0;
        for (uint256 i = 0; i < 2000; i++) {
            x += i;
        }
        return true;
    }
}

/**
 * @title AdversarialInferenceVerifierTest
 * @notice Empirical Challenger Adversarial Stress Test Suite for Milestone M3 (Gate T22, AGENT.md §7).
 *         Rigorously probes calldata boundaries, extreme lengths, bit flips, zero values,
 *         unauthorized mutations, circuit exception handling, replay, and record overwrite behaviors.
 */
contract AdversarialInferenceVerifierTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    InferenceVerifier public verifier;
    MockCircuitVerifier public mockCircuit;

    address public deployer;
    address public stranger;
    address public eve;

    bytes32 constant CANONICAL_MODEL = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 constant CANONICAL_INPUT = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant CANONICAL_OUTPUT = 0x2222222222222222222222222222222222222222222222222222222222222222;
    string constant CANONICAL_ID = "INF-ADV-RECORD-001";

    bytes validProof;
    bytes32 validProofHash;

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
        stranger = address(0xBAD);
        eve = address(0xEEE);

        // Standard 128-byte proof
        validProof = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            validProof[i] = bytes1(uint8(i + 1));
        }
        validProofHash = keccak256(validProof);

        mockCircuit = new MockCircuitVerifier(validProofHash);
        mockCircuit.setExpectedCommitments(uint256(CANONICAL_INPUT), uint256(CANONICAL_OUTPUT));

        verifier = new InferenceVerifier(
            address(mockCircuit),
            CANONICAL_MODEL,
            true // revertOnFailure
        );
    }

    // =========================================================================
    // Group 1: Calldata Boundaries & Extreme Lengths
    // =========================================================================

    function test_ADV_01_ZeroLengthProof_Reverts_InvalidProofLength() public {
        bytes memory emptyProof = new bytes(0);
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(
            emptyProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            CANONICAL_ID
        );
    }

    function test_ADV_02_Sub64ByteProof_BoundaryValues() public {
        // Test 1 byte
        bytes memory p1 = hex"AA";
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(p1, CANONICAL_MODEL, CANONICAL_INPUT, CANONICAL_OUTPUT, CANONICAL_ID);

        // Test 32 bytes
        bytes memory p32 = new bytes(32);
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(p32, CANONICAL_MODEL, CANONICAL_INPUT, CANONICAL_OUTPUT, CANONICAL_ID);

        // Test 63 bytes (1 byte below minimum)
        bytes memory p63 = new bytes(63);
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(p63, CANONICAL_MODEL, CANONICAL_INPUT, CANONICAL_OUTPUT, CANONICAL_ID);
    }

    function test_ADV_03_ExactBoundary64ByteProof_ValidLength() public {
        // Exactly 64 bytes satisfies length check
        bytes memory p64 = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            p64[i] = bytes1(uint8(i + 1));
        }
        bytes32 p64Hash = keccak256(p64);

        // Configure mockCircuit to accept this 64-byte proof
        mockCircuit.setExpectedProofHash(p64Hash);

        bool success = verifier.verifyInferenceProof(
            p64,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-64-BYTES"
        );
        assertTrue(success);
        assertTrue(verifier.isProofVerified(p64Hash));
    }

    function test_ADV_04_GiganticProof_64KB_Safety() public {
        // 64 KB proof (65,536 bytes)
        bytes memory bigProof = new bytes(65536);
        bigProof[0] = 0xDE;
        bigProof[65535] = 0xAD;
        bytes32 bigHash = keccak256(bigProof);

        mockCircuit.setExpectedProofHash(bigHash);

        uint256 gasBefore = gasleft();
        bool success = verifier.verifyInferenceProof(
            bigProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-64KB"
        );
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(success);
        assertTrue(verifier.isProofVerified(bigHash));
        // Ensure execution succeeded without EVM stack or memory overflow
        assertTrue(gasUsed > 0);
    }

    function test_ADV_05_GiganticProof_128KB_Safety() public {
        // 128 KB proof (131,072 bytes)
        bytes memory hugeProof = new bytes(131072);
        hugeProof[0] = 0xBE;
        hugeProof[131071] = 0xEF;
        bytes32 hugeHash = keccak256(hugeProof);

        mockCircuit.setExpectedProofHash(hugeHash);

        bool success = verifier.verifyInferenceProof(
            hugeProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-128KB"
        );
        assertTrue(success);
        assertTrue(verifier.isProofVerified(hugeHash));
    }

    function test_ADV_06_Fuzz_ProofLength_Under64_AlwaysReverts(uint8 len) public {
        vm.assume(len < 64);
        bytes memory subProof = new bytes(len);
        vm.expectRevert(IInferenceVerifier.InvalidProofLength.selector);
        verifier.verifyInferenceProof(
            subProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-FUZZ-LEN"
        );
    }

    // =========================================================================
    // Group 2: Commitment & Cryptographic Tampering
    // =========================================================================

    function test_ADV_07_ModelCommitment_1BitFlip_Reverts() public {
        bytes32 corruptedModel = CANONICAL_MODEL ^ bytes32(uint256(1) << 128); // 1-bit flip
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.ModelCommitmentMismatch.selector,
                CANONICAL_MODEL,
                corruptedModel
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            corruptedModel,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            CANONICAL_ID
        );
    }

    function test_ADV_08_ModelCommitment_AllZero_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "modelCommitment"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            bytes32(0),
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            CANONICAL_ID
        );
    }

    function test_ADV_09_InputCommitment_1BitFlip_RejectedByCircuit() public {
        bytes32 corruptedInput = CANONICAL_INPUT ^ bytes32(uint256(1)); // 1-bit flip
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "Circuit verifier returned false"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            corruptedInput,
            CANONICAL_OUTPUT,
            CANONICAL_ID
        );
    }

    function test_ADV_10_InputCommitment_AllZero_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "inputCommitment"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            bytes32(0),
            CANONICAL_OUTPUT,
            CANONICAL_ID
        );
    }

    function test_ADV_11_OutputCommitment_1BitFlip_RejectedByCircuit() public {
        bytes32 corruptedOutput = CANONICAL_OUTPUT ^ bytes32(uint256(1)); // 1-bit flip
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "Circuit verifier returned false"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            corruptedOutput,
            CANONICAL_ID
        );
    }

    function test_ADV_12_OutputCommitment_AllZero_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "outputCommitment"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            bytes32(0),
            CANONICAL_ID
        );
    }

    function test_ADV_13_EmptyString_InferenceRecordId_Reverts() public {
        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            ""
        );
    }

    function test_ADV_14_Whitespace_InferenceRecordId_Behavior() public {
        // Contract checks bytes(id).length == 0. Whitespace strings have bytes.length > 0.
        // Therefore, whitespace string is technically accepted by the contract.
        // We empirically document this observation.
        string memory whitespaceId = "   ";
        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            whitespaceId
        );
        assertTrue(success);
        assertTrue(verifier.recordExists(whitespaceId));
    }

    function test_ADV_15_Bytes32Zero_InferenceRecordId_Reverts() public {
        uint256[] memory signals = new uint256[](2);
        signals[0] = uint256(CANONICAL_INPUT);
        signals[1] = uint256(CANONICAL_OUTPUT);

        // bytes32(0) converts to "" in _bytes32ToString, which triggers EmptyInferenceRecordId()
        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);
        verifier.verifyInference(
            validProof,
            signals,
            CANONICAL_MODEL,
            bytes32(0)
        );
    }

    function test_ADV_16_Bytes32_EmbeddedNull_Truncation() public {
        uint256[] memory signals = new uint256[](2);
        signals[0] = uint256(CANONICAL_INPUT);
        signals[1] = uint256(CANONICAL_OUTPUT);

        // "INF\x00XYZ" will be truncated to "INF" by _bytes32ToString
        bytes32 bWithNull = bytes32(abi.encodePacked("INF", bytes1(0), "XYZ"));
        bool success = verifier.verifyInference(
            validProof,
            signals,
            CANONICAL_MODEL,
            bWithNull
        );
        assertTrue(success);
        // The record was stored under key "INF"
        assertTrue(verifier.recordExists("INF"));
    }

    function test_ADV_17_PublicSignals_EmptyArray_Reverts() public {
        uint256[] memory emptySignals = new uint256[](0);
        // With empty public signals, inputCommitment defaults to 0 -> InvalidCommitment("inputCommitment")
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "inputCommitment"
            )
        );
        verifier.verifyInference(
            validProof,
            emptySignals,
            CANONICAL_MODEL,
            string("SIG-EMPTY")
        );
    }

    function test_ADV_18_PublicSignals_SingleElement_Reverts() public {
        uint256[] memory oneSignal = new uint256[](1);
        oneSignal[0] = uint256(CANONICAL_INPUT);

        // With only 1 signal, outputCommitment defaults to 0 -> InvalidCommitment("outputCommitment")
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.InvalidCommitment.selector,
                "outputCommitment"
            )
        );
        verifier.verifyInference(
            validProof,
            oneSignal,
            CANONICAL_MODEL,
            string("SIG-ONE")
        );
    }

    // =========================================================================
    // Group 3: State & Access Control Stress
    // =========================================================================

    function test_ADV_19_Stranger_Cannot_SetCircuitVerifier() public {
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setCircuitVerifier(address(0x123));
    }

    function test_ADV_20_Stranger_Cannot_SetExpectedModelCommitment() public {
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setExpectedModelCommitment(bytes32(uint256(0x999)));
    }

    function test_ADV_21_Stranger_Cannot_SetRevertOnFailure() public {
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setRevertOnFailure(false);
    }

    function test_ADV_22_Stranger_Cannot_TransferOwnership() public {
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.transferOwnership(stranger);
    }

    function test_ADV_23_Owner_TransferOwnership_ZeroAddress_Reverts() public {
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.transferOwnership(address(0));
    }

    function test_ADV_24_PendingOwner_Stranger_Cannot_AcceptOwnership() public {
        verifier.transferOwnership(eve);
        assertEq(verifier.pendingOwner(), eve);

        // Stranger attempts to accept
        vm.prank(stranger);
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.acceptOwnership();

        // Eve successfully accepts
        vm.prank(eve);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), eve);
        assertEq(verifier.pendingOwner(), address(0));
    }

    function test_ADV_25_PendingOwner_AcceptOwnership_StateTransition() public {
        verifier.transferOwnership(eve);
        vm.prank(eve);
        verifier.acceptOwnership();

        // Previous deployer cannot make admin updates
        vm.expectRevert(IInferenceVerifier.Unauthorized.selector);
        verifier.setRevertOnFailure(false);

        // Eve can make admin updates
        vm.prank(eve);
        verifier.setRevertOnFailure(false);
        assertFalse(verifier.revertOnFailure());
    }

    function test_ADV_26_ZeroAddress_CircuitVerifier_AutonomousMode() public {
        // Owner sets circuit verifier to address(0)
        verifier.setCircuitVerifier(address(0));
        assertEq(verifier.circuitVerifier(), address(0));

        // When circuitVerifier is address(0), proof delegation is bypassed
        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-AUTO-MODE"
        );
        assertTrue(success);
        assertTrue(verifier.recordExists("REC-AUTO-MODE"));
    }

    function test_ADV_27_VerifyBeforeCircuitVerifierSet_SafeFallback() public {
        // Deploy verifier with address(0) from genesis
        InferenceVerifier virginVerifier = new InferenceVerifier(
            address(0),
            CANONICAL_MODEL,
            true
        );
        assertEq(virginVerifier.circuitVerifier(), address(0));

        bool success = virginVerifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-VIRGIN"
        );
        assertTrue(success);
    }

    function test_ADV_28_CircuitVerifier_AddressWithNoCode_EOA_HandledCleanly() public {
        address eoa = address(0xDEADBEEF);
        verifier.setCircuitVerifier(eoa);

        // Calling an address with no code (extcodesize == 0) causes Solidity to revert
        // immediately in the compiler preamble without error data.
        vm.expectRevert();
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-EOA-VERIFIER"
        );
    }

    // =========================================================================
    // Group 4: Circuit Verifier Failure Modes & Stress
    // =========================================================================

    function test_ADV_29_CircuitVerifier_RevertsCustomString_CaughtCleanly() public {
        RevertingCircuitVerifier revertingVerifier = new RevertingCircuitVerifier();
        verifier.setCircuitVerifier(address(revertingVerifier));

        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "CircuitVerifier: Pairing failure in G2"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-CUSTOM-REVERT"
        );
    }

    function test_ADV_30_CircuitVerifier_RevertsPanic_CaughtCleanly() public {
        PanicCircuitVerifier panicVerifier = new PanicCircuitVerifier();
        verifier.setCircuitVerifier(address(panicVerifier));

        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.CircuitVerificationFailed.selector,
                "Circuit verifier reverted"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-PANIC-REVERT"
        );
    }

    function test_ADV_31_CircuitVerifier_MalformedReturn_CaughtCleanly() public {
        MalformedReturnCircuitVerifier malformedVerifier = new MalformedReturnCircuitVerifier();
        verifier.setCircuitVerifier(address(malformedVerifier));

        // When external contract returns 0 bytes instead of 32 bytes bool,
        // caller-side ABI decoding reverts without error data.
        vm.expectRevert();
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-MALFORMED"
        );
    }

    function test_ADV_32_CircuitVerifier_GasBurner_SucceedsWithinBudget() public {
        GasBurnerCircuitVerifier burner = new GasBurnerCircuitVerifier();
        verifier.setCircuitVerifier(address(burner));

        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-GAS-BURNER"
        );
        assertTrue(success);
        IInferenceVerifier.VerificationRecord memory rec = verifier.getVerificationRecord("REC-GAS-BURNER");
        assertTrue(rec.gasUsed > 0);
    }

    function test_ADV_33_RevertOnFailure_False_ReturnsFalse_DoesNotRevert() public {
        verifier.setRevertOnFailure(false);
        mockCircuit.setBehavior(false, true); // returns false

        bool success = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-FALSE-BEHAVIOR"
        );
        assertFalse(success);
        assertFalse(verifier.recordExists("REC-FALSE-BEHAVIOR"));
    }

    // =========================================================================
    // Group 5: Forensic Integrity, Replay & Overwrite Surface
    // =========================================================================

    function test_ADV_34_Replay_SameProof_DifferentRecordId() public {
        // First verification with proof A
        bool first = verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REPLAY-1"
        );
        assertTrue(first);
        assertTrue(verifier.isProofVerified(validProofHash));

        // Reusing same proof A for a second record ID must revert with ProofAlreadyVerified
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.ProofAlreadyVerified.selector,
                validProofHash
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-REPLAY-2"
        );

        // Verify second record was never created
        assertFalse(verifier.recordExists("REC-REPLAY-2"));
    }

    function test_ADV_35_RecordOverwrite_ForensicMutation() public {
        // Investigator Alice records inference record 1
        vm.prank(deployer);
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-OVERWRITE"
        );
        IInferenceVerifier.VerificationRecord memory recOriginal = verifier.getVerificationRecord("REC-OVERWRITE");
        assertEq(recOriginal.submitter, deployer);
        assertEq(recOriginal.inputCommitment, CANONICAL_INPUT);

        // Adversary Eve submits with the SAME record ID
        // Because InferenceVerifier enforces record immutability, this must revert with RecordAlreadyExists
        bytes32 eveInput = 0x3333333333333333333333333333333333333333333333333333333333333333;
        mockCircuit.setExpectedCommitments(uint256(eveInput), uint256(CANONICAL_OUTPUT));

        vm.prank(eve);
        vm.expectRevert(
            abi.encodeWithSelector(
                IInferenceVerifier.RecordAlreadyExists.selector,
                "REC-OVERWRITE"
            )
        );
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            eveInput,
            CANONICAL_OUTPUT,
            "REC-OVERWRITE"
        );

        // Assert Alice's original record remains 100% immutable
        IInferenceVerifier.VerificationRecord memory recAfter = verifier.getVerificationRecord("REC-OVERWRITE");
        assertEq(recAfter.submitter, deployer);
        assertEq(recAfter.inputCommitment, CANONICAL_INPUT);
        assertEq(recAfter.outputCommitment, CANONICAL_OUTPUT);
        assertEq(recAfter.proofHash, validProofHash);
        assertEq(recAfter.timestamp, recOriginal.timestamp);
        assertEq(recAfter.blockNumber, recOriginal.blockNumber);
        assertEq(recAfter.gasUsed, recOriginal.gasUsed);
        assertTrue(recAfter.isValid);
    }

    function test_ADV_36_EvidenceBinding_Consistency() public {
        verifier.verifyInferenceProof(
            validProof,
            CANONICAL_MODEL,
            CANONICAL_INPUT,
            CANONICAL_OUTPUT,
            "REC-BINDING"
        );

        (bytes32 bindingHash, bytes32 proofHash) = verifier.getEvidenceBinding("REC-BINDING");
        bytes32 expectedBinding = keccak256(
            abi.encodePacked(
                CANONICAL_MODEL,
                CANONICAL_INPUT,
                CANONICAL_OUTPUT,
                "REC-BINDING"
            )
        );
        assertEq(bindingHash, expectedBinding);
        assertEq(proofHash, validProofHash);
    }

    function test_ADV_37_NonExistentRecord_Reverts_EmptyInferenceRecordId() public {
        // Contract reuses EmptyInferenceRecordId() error for non-existent records
        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);
        verifier.getVerificationRecord("DOES-NOT-EXIST");

        vm.expectRevert(IInferenceVerifier.EmptyInferenceRecordId.selector);
        verifier.getEvidenceBinding("DOES-NOT-EXIST");
    }
}
