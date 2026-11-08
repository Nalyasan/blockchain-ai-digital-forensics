// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IInferenceVerifier
 * @notice Standard interface for Milestone M3 ZKML On-Chain Verifier (AGENT.md §7, Gate T22).
 *         Supports Halo2/KZG/EZKL zero-knowledge proof verification, cryptographic
 *         commitment binding (model, input, output), and forensic event emission.
 */
interface IInferenceVerifier {
    // --- Data Structures ---
    struct VerificationRecord {
        bytes32 modelCommitment;
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        bytes32 proofHash;
        uint256 timestamp;
        uint256 blockNumber;
        uint256 gasUsed;
        bool isValid;
        address submitter;
    }

    // --- Events (Mandated by AGENT.md §7.2 & DISPATCH) ---
    event InferenceVerified(
        bytes32 indexed modelCommitment,
        bytes32 indexed inputCommitment,
        bytes32 outputCommitment,
        string inferenceRecordId,
        bool isValid,
        uint256 gasUsed
    );

    event ProofRegistered(
        bytes32 indexed proofHash,
        string indexed inferenceRecordId,
        address indexed caller,
        uint256 timestamp
    );

    event CircuitVerifierUpdated(
        address indexed previousVerifier,
        address indexed newVerifier
    );

    event ExpectedModelCommitmentUpdated(
        bytes32 indexed previousCommitment,
        bytes32 indexed newCommitment
    );

    event RevertOnFailureUpdated(bool revertOnFailure);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // --- Custom Errors ---
    error InvalidProofLength();
    error InvalidCommitment(string field);
    error EmptyInferenceRecordId();
    error ModelCommitmentMismatch(bytes32 expected, bytes32 actual);
    error CircuitVerificationFailed(string reason);
    error ProofAlreadyVerified(bytes32 proofHash);
    error RecordAlreadyExists(string inferenceRecordId);
    error Unauthorized();

    // --- Primary Verification Entrypoint (DISPATCH Mandate) ---
    function verifyInferenceProof(
        bytes calldata proof,
        bytes32 modelCommitment,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        string calldata inferenceRecordId
    ) external returns (bool);

    // --- Secondary Verification Entrypoint with Public Signals (PROJECT.md Mandate) ---
    function verifyInference(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes32 modelHash,
        bytes32 inferenceRecordId
    ) external returns (bool valid);

    function verifyInference(
        bytes calldata proof,
        uint256[] calldata publicSignals,
        bytes32 modelHash,
        string calldata inferenceRecordId
    ) external returns (bool valid);

    // --- Extended Verification Entrypoint with Explicit Instances ---
    function verifyInferenceProofWithInstances(
        bytes calldata proof,
        uint256[] calldata instances,
        bytes32 modelCommitment,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        string calldata inferenceRecordId
    ) external returns (bool);

    // --- View & State Query Functions ---
    function getVerificationRecord(string calldata inferenceRecordId)
        external
        view
        returns (VerificationRecord memory);

    function isProofVerified(bytes32 proofHash) external view returns (bool);

    function getEvidenceBinding(string calldata inferenceRecordId)
        external
        view
        returns (bytes32 bindingHash, bytes32 proofHash);

    function circuitVerifier() external view returns (address);

    function expectedModelCommitment() external view returns (bytes32);

    function revertOnFailure() external view returns (bool);

    function owner() external view returns (address);
}
