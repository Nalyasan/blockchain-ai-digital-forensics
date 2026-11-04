// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../EvidenceRegistry.sol";

/**
 * @title IEvidenceRegistryDID
 * @notice Interface for EvidenceRegistryDID: ERC-1056 DID, granular RBAC, EIP-712 signatures,
 *         and ISO/IEC 27037 digital evidence chain of custody lifecycle tracking.
 */
interface IEvidenceRegistryDID {
    enum ISOStage { IDENTIFICATION, COLLECTION, ACQUISITION, PRESERVATION }

    struct CustodyRecordDID {
        uint256 evidenceId;
        EvidenceRegistry.CustodyAction action;
        ISOStage isoStage;
        bytes32 role;
        address actor;
        address recipient;
        bytes32 artifactSha256;
        bytes32 noteHash;
        bytes32 modelHash;
        bytes32 xaiDigest;
        bytes32 zkmlProofHash;
        uint256 timestamp;
        bytes signature;
    }

    // --- ERC-1056 Decentralized Identity (DID) ---
    function getDID(address account) external pure returns (string memory);
    function identityOwner(address identity) external view returns (address);
    function changeOwner(address identity, address newOwner) external;
    function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity) external;
    function revokeDelegate(address identity, bytes32 delegateType, address delegate) external;
    function validDelegate(address identity, bytes32 delegateType, address delegate) external view returns (bool);
    function setAttribute(address identity, bytes32 name, bytes calldata value, uint256 validity) external;
    function revokeAttribute(address identity, bytes32 name, bytes calldata value) external;
    function changed(address identity) external view returns (uint256);

    // --- Granular Forensic Roles ---
    function grantRole(address account, bytes32 role) external;
    function revokeRole(address account, bytes32 role) external;
    function hasRole(address account, bytes32 role) external view returns (bool);
    function hasForensicRole(address account, bytes32 role) external view returns (bool);

    // --- EIP-712 Typed Signature Custody Transitions ---
    function transferCustodyWithSig(
        uint256 evidenceId,
        address fromCustodian,
        address toCustodian,
        bytes32 artifactSha256,
        bytes32 noteHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external;

    function recordAttestationWithSig(
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external;

    // --- Direct ISO/IEC 27037 Custody & Artifact Anchoring ---
    function recordCustodyDID(
        uint256 evidenceId,
        EvidenceRegistry.CustodyAction action,
        ISOStage isoStage,
        bytes32 role,
        address recipient,
        bytes32 artifactSha256,
        bytes32 noteHash,
        bytes32 modelHash,
        bytes32 xaiDigest,
        bytes32 zkmlProofHash
    ) external;

    function anchorForensicEvidence(
        uint256 evidenceId,
        bytes32 modelHash,
        bytes32 xaiDigest,
        bytes32 zkmlProofHash,
        bytes32 artifactSha256,
        bytes32 noteHash
    ) external;

    // --- View & Pagination ---
    function getCustodyHistoryDID(uint256 evidenceId) external view returns (CustodyRecordDID[] memory);
    function getCustodyHistoryDID(uint256 evidenceId, uint256 offset, uint256 limit) external view returns (CustodyRecordDID[] memory records, uint256 total);
    function getCustodyCountDID(uint256 evidenceId) external view returns (uint256);

    // --- Verification & Nonce Queries ---
    function domainSeparator() external view returns (bytes32);
    function getDomainSeparator() external view returns (bytes32);
    function nonces(address account) external view returns (uint256);
    function executedSignatures(bytes32 sigHash) external view returns (bool);
    function currentCustodians(uint256 evidenceId) external view returns (address);
}
