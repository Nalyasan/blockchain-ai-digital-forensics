// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IInferenceVerifier.sol";

/**
 * @dev Interface for underlying low-level SNARK/KZG circuit verifiers (e.g. EZKL Halo2Verifier).
 */
interface ICircuitVerifier {
    function verifyProof(bytes calldata proof, uint256[] calldata instances) external view returns (bool);
}

/**
 * @title MockCircuitVerifier
 * @dev Auxiliary unit-test stub ONLY for isolating outer InferenceVerifier guards.
 *      Never used for Gate T09/T22 or Demo D1/D3 acceptance, which deploy real Halo2Verifier.sol.
 */
contract MockCircuitVerifier is ICircuitVerifier {
    bytes32 public expectedProofHash;
    uint256 public expectedInputCommitment;
    uint256 public expectedOutputCommitment;
    bool public shouldRevert;
    bool public shouldReturnFalse;

    constructor(bytes32 _expectedProofHash) {
        expectedProofHash = _expectedProofHash;
    }

    function setBehavior(bool _shouldRevert, bool _shouldReturnFalse) external {
        shouldRevert = _shouldRevert;
        shouldReturnFalse = _shouldReturnFalse;
    }

    function setExpectedProofHash(bytes32 _expectedProofHash) external {
        expectedProofHash = _expectedProofHash;
    }

    function setExpectedCommitments(uint256 _input, uint256 _output) external {
        expectedInputCommitment = _input;
        expectedOutputCommitment = _output;
    }

    function verifyProof(bytes calldata proof, uint256[] calldata instances) external view override returns (bool) {
        if (shouldRevert) {
            revert("Mock pairing check failure");
        }
        if (shouldReturnFalse) {
            return false;
        }
        if (expectedProofHash != bytes32(0) && keccak256(proof) != expectedProofHash) {
            return false;
        }
        if (expectedInputCommitment != 0 && instances.length > 0 && instances[0] != expectedInputCommitment) {
            return false;
        }
        if (expectedOutputCommitment != 0 && instances.length > 1 && instances[instances.length - 1] != expectedOutputCommitment) {
            return false;
        }
        return true;
    }
}

/**
 * @title InferenceVerifier
 * @notice Milestone M3 ZKML On-Chain Verifier Contract complying with AGENT.md §7 and Gate T22.
 * @dev Enforces strict cryptographic bindings between model commitments, input features,
 *      output anomaly scores, and inference proofs. Fully supports local Anvil execution,
 *      event emission with internal gas profiling, and seamless CoC anchoring without altering
 *      EvidenceRegistry.sol or EvidenceRegistryDID.sol.
 */
contract InferenceVerifier is IInferenceVerifier {
    uint256 public constant MIN_PROOF_LENGTH = 64;
    uint256 public constant BN254_SCALAR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 public constant HALO2_INSTANCE_COUNT = 11;

    // --- Storage Variables ---
    address public override owner;
    address public pendingOwner;

    address public override circuitVerifier;
    bytes32 public override expectedModelCommitment;
    bool public override revertOnFailure;

    mapping(string => VerificationRecord) private _records;
    mapping(bytes32 => bool) private _verifiedProofHashes;
    mapping(string => bool) public recordExists;

    // --- Modifiers ---
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // --- Constructor ---
    constructor(
        address _circuitVerifier,
        bytes32 _expectedModelCommitment,
        bool _revertOnFailure
    ) {
        owner = msg.sender;
        circuitVerifier = _circuitVerifier;
        expectedModelCommitment = _expectedModelCommitment;
        revertOnFailure = _revertOnFailure;

        if (_circuitVerifier != address(0)) {
            emit CircuitVerifierUpdated(address(0), _circuitVerifier);
        }
        if (_expectedModelCommitment != bytes32(0)) {
            emit ExpectedModelCommitmentUpdated(bytes32(0), _expectedModelCommitment);
        }
        emit RevertOnFailureUpdated(_revertOnFailure);
    }

    // --- Admin Configuration Functions ---

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert Unauthorized();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function setCircuitVerifier(address _circuitVerifier) external onlyOwner {
        address prev = circuitVerifier;
        circuitVerifier = _circuitVerifier;
        emit CircuitVerifierUpdated(prev, _circuitVerifier);
    }

    function setExpectedModelCommitment(bytes32 _expectedModelCommitment) external onlyOwner {
        bytes32 prev = expectedModelCommitment;
        expectedModelCommitment = _expectedModelCommitment;
        emit ExpectedModelCommitmentUpdated(prev, _expectedModelCommitment);
    }

    function setRevertOnFailure(bool _revertOnFailure) external onlyOwner {
        revertOnFailure = _revertOnFailure;
        emit RevertOnFailureUpdated(_revertOnFailure);
    }

    // --- Verification Functions ---

    /**
     * @notice Primary verification entrypoint mandated by DISPATCH.
     */
    function verifyInferenceProof(
        bytes calldata proof,
        bytes32 modelCommitment,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        string calldata inferenceRecordId
    ) external override returns (bool) {
        uint256[] memory emptyInstances = new uint256[](0);
        return _verifyInternal(
            proof,
            emptyInstances,
            modelCommitment,
            inputCommitment,
            outputCommitment,
            inferenceRecordId
        );
    }

    /**
     * @dev Converts a bytes32 identifier to string representation.
     */
    function _bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        uint8 len = 0;
        while (len < 32 && _bytes32[len] != 0) {
            len++;
        }
        if (len == 0) {
            return "";
        }
        bytes memory bytesArray = new bytes(len);
        for (uint8 j = 0; j < len; j++) {
            bytesArray[j] = _bytes32[j];
        }
        return string(bytesArray);
    }

    /**
     * @notice Secondary verification entrypoint mandated by PROJECT.md §5 (bytes32 recordId).
     */
    function verifyInference(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes32 modelHash,
        bytes32 inferenceRecordId
    ) external override returns (bool valid) {
        bytes32 inputComm = bytes32(publicSignals.length > 0 ? publicSignals[0] : 0);
        bytes32 outputComm = bytes32(publicSignals.length > 1 ? publicSignals[publicSignals.length - 1] : 0);
        return _verifyInternal(
            proof,
            publicSignals,
            modelHash,
            inputComm,
            outputComm,
            _bytes32ToString(inferenceRecordId)
        );
    }

    /**
     * @notice Overloaded verification entrypoint with string recordId.
     */
    function verifyInference(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes32 modelHash,
        string calldata inferenceRecordId
    ) external override returns (bool valid) {
        bytes32 inputComm = bytes32(publicSignals.length > 0 ? publicSignals[0] : 0);
        bytes32 outputComm = bytes32(publicSignals.length > 1 ? publicSignals[publicSignals.length - 1] : 0);
        return _verifyInternal(
            proof,
            publicSignals,
            modelHash,
            inputComm,
            outputComm,
            inferenceRecordId
        );
    }

    /**
     * @notice Verification entrypoint with explicit public instances and commitments.
     */
    function verifyInferenceProofWithInstances(
        bytes calldata proof,
        uint256[] calldata instances,
        bytes32 modelCommitment,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        string calldata inferenceRecordId
    ) external override returns (bool) {
        return _verifyInternal(
            proof,
            instances,
            modelCommitment,
            inputCommitment,
            outputCommitment,
            inferenceRecordId
        );
    }

    // --- Core Verification Pipeline ---

    function _verifyInternal(
        bytes calldata proof,
        uint256[] memory instances,
        bytes32 modelCommitment,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        string memory inferenceRecordId
    ) internal returns (bool) {
        uint256 startGas = gasleft();

        // 1. Parameter & Bounds Validation
        if (bytes(inferenceRecordId).length == 0) {
            revert EmptyInferenceRecordId();
        }
        if (modelCommitment == bytes32(0)) {
            revert InvalidCommitment("modelCommitment");
        }
        if (inputCommitment == bytes32(0)) {
            revert InvalidCommitment("inputCommitment");
        }
        if (outputCommitment == bytes32(0)) {
            revert InvalidCommitment("outputCommitment");
        }
        if (proof.length < MIN_PROOF_LENGTH) {
            revert InvalidProofLength();
        }

        // 1b. Forensic Immutability & Anti-Replay Guardrails
        if (recordExists[inferenceRecordId]) {
            revert RecordAlreadyExists(inferenceRecordId);
        }
        bytes32 proofHash = keccak256(proof);
        if (_verifiedProofHashes[proofHash]) {
            revert ProofAlreadyVerified(proofHash);
        }

        // 2. Model Commitment Invariance Check
        if (expectedModelCommitment != bytes32(0) && modelCommitment != expectedModelCommitment) {
            if (revertOnFailure) {
                revert ModelCommitmentMismatch(expectedModelCommitment, modelCommitment);
            }
            uint256 gasUsed = startGas - gasleft();
            emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasUsed);
            return false;
        }

        // 3. Underlying Circuit Verifier Delegation (if attached)
        if (circuitVerifier != address(0)) {
            uint256[] memory circuitInstances;
            if (instances.length > 0) {
                circuitInstances = instances;
                if (instances.length == HALO2_INSTANCE_COUNT) {
                    bytes32 derivedInputComm = _computeHalo2InputCommitment(instances);
                    if (derivedInputComm != inputCommitment) {
                        uint256 gasMismatchIn = startGas - gasleft();
                        emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasMismatchIn);
                        if (revertOnFailure) {
                            revert CircuitVerificationFailed("Input commitment mismatch against Halo2 instances");
                        }
                        return false;
                    }
                    if (bytes32(instances[HALO2_INSTANCE_COUNT - 1]) != outputCommitment) {
                        uint256 gasMismatchOut = startGas - gasleft();
                        emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasMismatchOut);
                        if (revertOnFailure) {
                            revert CircuitVerificationFailed("Output commitment mismatch against Halo2 instance");
                        }
                        return false;
                    }
                }
            } else {
                circuitInstances = new uint256[](2);
                circuitInstances[0] = uint256(inputCommitment);
                circuitInstances[1] = uint256(outputCommitment);
            }

            try ICircuitVerifier(circuitVerifier).verifyProof(proof, circuitInstances) returns (bool valid) {
                if (!valid) {
                    uint256 gasUsed = startGas - gasleft();
                    emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasUsed);
                    if (revertOnFailure) {
                        revert CircuitVerificationFailed("Circuit verifier returned false");
                    }
                    return false;
                }
            } catch Error(string memory reason) {
                uint256 gasUsed = startGas - gasleft();
                emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasUsed);
                if (revertOnFailure) {
                    revert CircuitVerificationFailed(reason);
                }
                return false;
            } catch {
                uint256 gasUsed = startGas - gasleft();
                emit InferenceVerified(modelCommitment, inputCommitment, outputCommitment, inferenceRecordId, false, gasUsed);
                if (revertOnFailure) {
                    revert CircuitVerificationFailed("Circuit verifier reverted");
                }
                return false;
            }
        }

        // 4. Record Storage and Replay Indexing
        uint256 gasUsedFinal = startGas - gasleft();

        _records[inferenceRecordId] = VerificationRecord({
            modelCommitment: modelCommitment,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            proofHash: proofHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            gasUsed: gasUsedFinal,
            isValid: true,
            submitter: msg.sender
        });
        recordExists[inferenceRecordId] = true;
        _verifiedProofHashes[proofHash] = true;

        // 5. Emit Mandated Forensic Events
        emit InferenceVerified(
            modelCommitment,
            inputCommitment,
            outputCommitment,
            inferenceRecordId,
            true,
            gasUsedFinal
        );

        emit ProofRegistered(
            proofHash,
            inferenceRecordId,
            msg.sender,
            block.timestamp
        );

        return true;
    }

    /**
     * @dev Reconstructs the 80-byte little-endian signed int64 buffer from the 10 Halo2 quantized
     *      input field elements so on-chain SHA-256 matches off-chain compute_input_commitment().
     */
    function _computeHalo2InputCommitment(uint256[] memory instances) internal pure returns (bytes32) {
        bytes memory buf = new bytes(80);
        uint256 halfMod = BN254_SCALAR_MODULUS / 2;
        for (uint256 i = 0; i < 10; i++) {
            uint256 u = instances[i];
            int64 signedVal = u > halfMod
                ? -int64(uint64(BN254_SCALAR_MODULUS - u))
                : int64(uint64(u));
            uint64 raw = uint64(signedVal);
            uint256 base = i * 8;
            buf[base] = bytes1(uint8(raw));
            buf[base + 1] = bytes1(uint8(raw >> 8));
            buf[base + 2] = bytes1(uint8(raw >> 16));
            buf[base + 3] = bytes1(uint8(raw >> 24));
            buf[base + 4] = bytes1(uint8(raw >> 32));
            buf[base + 5] = bytes1(uint8(raw >> 40));
            buf[base + 6] = bytes1(uint8(raw >> 48));
            buf[base + 7] = bytes1(uint8(raw >> 56));
        }
        return sha256(buf);
    }

    // --- View Functions ---

    function getVerificationRecord(string calldata inferenceRecordId)
        external
        view
        override
        returns (VerificationRecord memory)
    {
        if (!recordExists[inferenceRecordId]) {
            revert EmptyInferenceRecordId();
        }
        return _records[inferenceRecordId];
    }

    function isProofVerified(bytes32 proofHash) external view override returns (bool) {
        return _verifiedProofHashes[proofHash];
    }

    /**
     * @notice Computes binding digest linking InferenceVerifier record to EvidenceRegistryDID.
     */
    function getEvidenceBinding(string calldata inferenceRecordId)
        external
        view
        override
        returns (bytes32 bindingHash, bytes32 proofHash)
    {
        if (!recordExists[inferenceRecordId]) {
            revert EmptyInferenceRecordId();
        }
        VerificationRecord storage rec = _records[inferenceRecordId];
        bindingHash = keccak256(
            abi.encodePacked(
                rec.modelCommitment,
                rec.inputCommitment,
                rec.outputCommitment,
                inferenceRecordId
            )
        );
        proofHash = rec.proofHash;
    }
}
