// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./EvidenceRegistry.sol";
import "./interfaces/IEvidenceRegistryDID.sol";

/**
 * @title EvidenceRegistryDID
 * @notice Phase 3 / P10: Chain of Custody & Decentralized Identity (DID) Contract Extension.
 *         Maintains 100% backward compatibility with EvidenceRegistry ABI and storage layout (slots 0-6 preserved).
 *         Implements W3C / ERC-1056 DID (did:ethr:<address>), granular forensic RBAC,
 *         EIP-712 typed signature verification with anti-replay and EIP-2 malleability rejection,
 *         and ISO/IEC 27037 compliant 4-stage digital evidence lifecycle tracking.
 */
contract EvidenceRegistryDID is EvidenceRegistry, IEvidenceRegistryDID {
    // --- Forensic Role Constants (keccak256) ---
    bytes32 public constant ROLE_COLLECTOR = keccak256("ROLE_COLLECTOR");
    bytes32 public constant ROLE_ANALYST = keccak256("ROLE_ANALYST");
    bytes32 public constant ROLE_FIRST_RESPONDER = keccak256("ROLE_FIRST_RESPONDER");
    bytes32 public constant ROLE_ZKML_VERIFIER = keccak256("ROLE_ZKML_VERIFIER");
    bytes32 public constant ROLE_CUSTODIAN = keccak256("ROLE_CUSTODIAN");

    // --- EIP-712 TypeHashes ---
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant CUSTODY_TRANSFER_TYPEHASH = keccak256(
        "CustodyTransfer(uint256 evidenceId,address fromCustodian,address toCustodian,bytes32 artifactSha256,bytes32 noteHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant FORENSIC_ATTESTATION_TYPEHASH = keccak256(
        "ForensicAttestation(uint256 evidenceId,address attestor,bytes32 role,bytes32 artifactHash,bytes32 statementHash,uint256 nonce,uint256 deadline)"
    );

    // secp256k1 curve order n / 2 (EIP-2 malleability limit)
    uint256 private constant SECP256K1_N_DIV_2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // --- Storage Layout: Starts strictly at Slot 7+ ---
    // Slot 7: ERC-1056 Identity Owners (identity => ownerAddress)
    mapping(address => address) private _didOwners;

    // Slot 8: ERC-1056 Identity Delegates (identity => delegateType => delegate => validTo)
    mapping(address => mapping(bytes32 => mapping(address => uint256))) private _didDelegates;

    // Slot 9: ERC-1056 Event Linkage
    mapping(address => uint256) public override changed;

    // Slot 10: Granular Forensic Roles (account => role => hasRole)
    mapping(address => mapping(bytes32 => bool)) public override hasRole;

    // Slot 11: EIP-712 Nonces for replay protection
    mapping(address => uint256) public override nonces;

    // Slot 12: Executed signature hashes to prevent double-spending
    mapping(bytes32 => bool) public override executedSignatures;

    // Slot 13: Current custodian tracking (evidenceId => custodian address)
    mapping(uint256 => address) public override currentCustodians;

    // Slot 14: Rich DID Custody History (evidenceId => CustodyRecordDID[])
    mapping(uint256 => CustodyRecordDID[]) private _custodyHistoryDID;

    // Slot 15: Role count for granular vs legacy investigator discrimination
    mapping(address => uint256) public roleCount;

    // --- Custom Errors ---
    error UnauthorizedRole(address account, bytes32 role);
    error InvalidSignature();
    error InvalidSignatureS();
    error InvalidSignatureV();
    error SignatureExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidNonce(uint256 expectedNonce, uint256 providedNonce);
    error SignatureAlreadyUsed();
    error SignerMismatch(address expected, address recovered);
    error NotCurrentCustodian(uint256 evidenceId, address caller);

    // --- Events ---
    event DIDOwnerChanged(address indexed identity, address newOwner, uint256 previousChange);
    event DIDDelegateChanged(address indexed identity, bytes32 indexed delegateType, address delegate, uint256 validTo, uint256 previousChange);
    event DIDAttributeChanged(address indexed identity, bytes32 indexed name, bytes value, uint256 validTo, uint256 previousChange);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event CustodyRecordedDID(
        uint256 indexed evidenceId,
        CustodyAction indexed action,
        ISOStage indexed isoStage,
        bytes32 role,
        address actor,
        address recipient,
        bytes32 artifactSha256,
        bytes32 noteHash,
        bytes32 modelHash,
        bytes32 xaiDigest,
        bytes32 zkmlProofHash
    );
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

    constructor() EvidenceRegistry() {
        // Deployer receives all foundational forensic roles
        hasRole[msg.sender][ROLE_COLLECTOR] = true;
        hasRole[msg.sender][ROLE_ANALYST] = true;
        hasRole[msg.sender][ROLE_FIRST_RESPONDER] = true;
        hasRole[msg.sender][ROLE_ZKML_VERIFIER] = true;
        hasRole[msg.sender][ROLE_CUSTODIAN] = true;
        roleCount[msg.sender] = 5;

        emit RoleGranted(ROLE_COLLECTOR, msg.sender, msg.sender);
        emit RoleGranted(ROLE_ANALYST, msg.sender, msg.sender);
        emit RoleGranted(ROLE_FIRST_RESPONDER, msg.sender, msg.sender);
        emit RoleGranted(ROLE_ZKML_VERIFIER, msg.sender, msg.sender);
        emit RoleGranted(ROLE_CUSTODIAN, msg.sender, msg.sender);
    }

    // 1. ERC-1056 Decentralized Identity (DID)

    /// @notice Formats an Ethereum address into a canonical ERC-1056 DID string: "did:ethr:0x<40-hex-chars-lower>".
    function getDID(address account) public pure override returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(51); // "did:ethr:0x" (11) + 40 hex chars = 51
        bytes memory prefix = "did:ethr:0x";
        for (uint256 i = 0; i < 11; i++) {
            str[i] = prefix[i];
        }
        bytes20 data = bytes20(account);
        for (uint256 i = 0; i < 20; i++) {
            str[11 + i * 2] = hexChars[uint8(data[i] >> 4)];
            str[11 + i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    function identityOwner(address identity) public view override returns (address) {
        address currentOwner = _didOwners[identity];
        return currentOwner == address(0) ? identity : currentOwner;
    }

    function changeOwner(address identity, address newOwner) external override {
        if (msg.sender != identityOwner(identity)) revert Unauthorized(msg.sender);
        if (newOwner == address(0)) revert ZeroValue();
        _didOwners[identity] = newOwner;
        emit DIDOwnerChanged(identity, newOwner, changed[identity]);
        changed[identity] = block.number;
    }

    function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity) external override {
        if (msg.sender != identityOwner(identity)) revert Unauthorized(msg.sender);
        if (delegate == address(0)) revert ZeroValue();
        uint256 validTo = block.timestamp + validity;
        _didDelegates[identity][delegateType][delegate] = validTo;
        emit DIDDelegateChanged(identity, delegateType, delegate, validTo, changed[identity]);
        changed[identity] = block.number;
    }

    function revokeDelegate(address identity, bytes32 delegateType, address delegate) external override {
        if (msg.sender != identityOwner(identity)) revert Unauthorized(msg.sender);
        _didDelegates[identity][delegateType][delegate] = block.timestamp;
        emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
        changed[identity] = block.number;
    }

    function validDelegate(address identity, bytes32 delegateType, address delegate) public view override returns (bool) {
        return _didDelegates[identity][delegateType][delegate] > block.timestamp;
    }

    function setAttribute(address identity, bytes32 name, bytes calldata value, uint256 validity) external override {
        if (msg.sender != identityOwner(identity)) revert Unauthorized(msg.sender);
        uint256 validTo = block.timestamp + validity;
        emit DIDAttributeChanged(identity, name, value, validTo, changed[identity]);
        changed[identity] = block.number;
    }

    function revokeAttribute(address identity, bytes32 name, bytes calldata value) external override {
        if (msg.sender != identityOwner(identity)) revert Unauthorized(msg.sender);
        emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);
        changed[identity] = block.number;
    }

    // 2. Granular Forensic Roles & RBAC

    function grantRole(address account, bytes32 role) public override onlyOwner {
        if (account == address(0)) revert ZeroValue();
        if (!hasRole[account][role]) {
            hasRole[account][role] = true;
            roleCount[account]++;
        }

        // Bidirectional synchronization: operational roles synchronize to legacy authorizedInvestigators
        if (role == ROLE_COLLECTOR || role == ROLE_CUSTODIAN || role == ROLE_FIRST_RESPONDER || role == ROLE_ANALYST) {
            authorizedInvestigators[account] = true;
            emit InvestigatorUpdated(account, true);
        }

        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(address account, bytes32 role) public override onlyOwner {
        if (hasRole[account][role]) {
            hasRole[account][role] = false;
            roleCount[account]--;
        }

        // Bidirectional synchronization: clear authorizedInvestigators if no operational roles remain
        if (!hasRole[account][ROLE_COLLECTOR] &&
            !hasRole[account][ROLE_CUSTODIAN] &&
            !hasRole[account][ROLE_FIRST_RESPONDER] &&
            !hasRole[account][ROLE_ANALYST]) {
            authorizedInvestigators[account] = false;
            emit InvestigatorUpdated(account, false);
        }

        emit RoleRevoked(role, account, msg.sender);
    }

    function hasForensicRole(address account, bytes32 role) public view override returns (bool) {
        if (hasRole[account][role]) return true;
        if (account == owner) return true;

        // If the account has explicit DID roles assigned, strictly enforce them
        if (roleCount[account] > 0) {
            return false;
        }

        // Backward compatibility for legacy accounts configured purely via setInvestigator
        if (authorizedInvestigators[account]) {
            if (role == ROLE_COLLECTOR || role == ROLE_ANALYST || role == ROLE_CUSTODIAN || role == ROLE_FIRST_RESPONDER) {
                return true;
            }
        }
        return false;
    }

    // 3. EIP-712 Domain Separator & Signer Recovery

    function domainSeparator() public view override returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("EvidenceRegistryDID")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function getDomainSeparator() external view override returns (bytes32) {
        return domainSeparator();
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Strict EIP-2 canonical lower-s check
        if (uint256(s) > SECP256K1_N_DIV_2) revert InvalidSignatureS();
        if (v != 27 && v != 28) revert InvalidSignatureV();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    // 4. ISO/IEC 27037 Custody Transitions with EIP-712 Signatures

    function transferCustodyWithSig(
        uint256 evidenceId,
        address fromCustodian,
        address toCustodian,
        bytes32 artifactSha256,
        bytes32 noteHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external override {
        if (block.timestamp > deadline) revert SignatureExpired(deadline, block.timestamp);
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        if (artifactSha256 == bytes32(0)) revert ZeroValue();
        if (fromCustodian == address(0) || toCustodian == address(0)) revert ZeroValue();
        if (nonce != nonces[fromCustodian]) revert InvalidNonce(nonces[fromCustodian], nonce);

        // RBAC validation
        if (!hasForensicRole(fromCustodian, ROLE_CUSTODIAN)) revert UnauthorizedRole(fromCustodian, ROLE_CUSTODIAN);
        if (!hasForensicRole(toCustodian, ROLE_CUSTODIAN)) revert UnauthorizedRole(toCustodian, ROLE_CUSTODIAN);

        _verifyCustodianHolding(evidenceId, fromCustodian);

        // Anti-replay: hash the exact signature bytes
        if (executedSignatures[keccak256(signature)]) revert SignatureAlreadyUsed();
        executedSignatures[keccak256(signature)] = true;

        _verifyTransferSignature(
            evidenceId,
            fromCustodian,
            toCustodian,
            artifactSha256,
            noteHash,
            nonce,
            deadline,
            signature
        );

        nonces[fromCustodian]++;
        currentCustodians[evidenceId] = toCustodian;

        _pushTransferRecord(evidenceId, fromCustodian, toCustodian, artifactSha256, noteHash, signature);
    }

    function _verifyCustodianHolding(uint256 evidenceId, address fromCustodian) internal view {
        address current = currentCustodians[evidenceId];
        if (current == address(0)) {
            if (fromCustodian != this.getEvidence(evidenceId).registeredBy) {
                revert NotCurrentCustodian(evidenceId, fromCustodian);
            }
        } else {
            if (fromCustodian != current) {
                revert NotCurrentCustodian(evidenceId, fromCustodian);
            }
        }
    }

    function _verifyTransferSignature(
        uint256 evidenceId,
        address fromCustodian,
        address toCustodian,
        bytes32 artifactSha256,
        bytes32 noteHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) internal view {
        bytes32 structHash = keccak256(
            abi.encode(
                CUSTODY_TRANSFER_TYPEHASH,
                evidenceId,
                fromCustodian,
                toCustodian,
                artifactSha256,
                noteHash,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = _recoverSigner(digest, signature);
        if (recovered != fromCustodian) revert SignerMismatch(fromCustodian, recovered);
    }

    function _pushTransferRecord(
        uint256 evidenceId,
        address fromCustodian,
        address toCustodian,
        bytes32 artifactSha256,
        bytes32 noteHash,
        bytes calldata signature
    ) internal {
        _custodyHistoryDID[evidenceId].push(
            CustodyRecordDID({
                evidenceId: evidenceId,
                action: CustodyAction.TRANSFERRED,
                isoStage: ISOStage.ACQUISITION,
                role: ROLE_CUSTODIAN,
                actor: fromCustodian,
                recipient: toCustodian,
                artifactSha256: artifactSha256,
                noteHash: noteHash,
                modelHash: bytes32(0),
                xaiDigest: bytes32(0),
                zkmlProofHash: bytes32(0),
                timestamp: block.timestamp,
                signature: signature
            })
        );

        emit CustodyRecordedDID(
            evidenceId,
            CustodyAction.TRANSFERRED,
            ISOStage.ACQUISITION,
            ROLE_CUSTODIAN,
            fromCustodian,
            toCustodian,
            artifactSha256,
            noteHash,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
        emit CustodyTransferred(evidenceId, fromCustodian, toCustodian, artifactSha256, noteHash, block.timestamp);
        emit CustodyRecorded(evidenceId, CustodyAction.TRANSFERRED, fromCustodian, artifactSha256, noteHash);
    }

    function recordAttestationWithSig(
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external override {
        if (block.timestamp > deadline) revert SignatureExpired(deadline, block.timestamp);
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        if (artifactHash == bytes32(0)) revert ZeroValue();
        if (attestor == address(0)) revert ZeroValue();
        if (nonce != nonces[attestor]) revert InvalidNonce(nonces[attestor], nonce);

        // RBAC validation
        if (!hasForensicRole(attestor, role)) revert UnauthorizedRole(attestor, role);

        // Anti-replay: signature hash
        if (executedSignatures[keccak256(signature)]) revert SignatureAlreadyUsed();
        executedSignatures[keccak256(signature)] = true;

        _verifyAttestationSignature(
            evidenceId,
            attestor,
            role,
            artifactHash,
            statementHash,
            nonce,
            deadline,
            signature
        );

        nonces[attestor]++;

        _pushAttestationRecord(evidenceId, attestor, role, artifactHash, statementHash, signature);
    }

    function _verifyAttestationSignature(
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) internal view {
        bytes32 structHash = keccak256(
            abi.encode(
                FORENSIC_ATTESTATION_TYPEHASH,
                evidenceId,
                attestor,
                role,
                artifactHash,
                statementHash,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = _recoverSigner(digest, signature);
        if (recovered != attestor) revert SignerMismatch(attestor, recovered);
    }

    function _pushAttestationRecord(
        uint256 evidenceId,
        address attestor,
        bytes32 role,
        bytes32 artifactHash,
        bytes32 statementHash,
        bytes calldata signature
    ) internal {
        CustodyAction action = (role == ROLE_COLLECTOR || role == ROLE_FIRST_RESPONDER)
            ? CustodyAction.COLLECTED
            : CustodyAction.ANALYZED;
        ISOStage stage = (role == ROLE_COLLECTOR || role == ROLE_FIRST_RESPONDER)
            ? ISOStage.COLLECTION
            : ISOStage.PRESERVATION;

        bytes32 modelHash = (role == ROLE_ANALYST) ? artifactHash : bytes32(0);
        bytes32 xaiDigest = (role == ROLE_ANALYST) ? statementHash : bytes32(0);
        bytes32 zkmlProofHash = (role == ROLE_ZKML_VERIFIER) ? artifactHash : bytes32(0);

        _custodyHistoryDID[evidenceId].push(
            CustodyRecordDID({
                evidenceId: evidenceId,
                action: action,
                isoStage: stage,
                role: role,
                actor: attestor,
                recipient: address(0),
                artifactSha256: artifactHash,
                noteHash: statementHash,
                modelHash: modelHash,
                xaiDigest: xaiDigest,
                zkmlProofHash: zkmlProofHash,
                timestamp: block.timestamp,
                signature: signature
            })
        );

        emit CustodyRecordedDID(
            evidenceId,
            action,
            stage,
            role,
            attestor,
            address(0),
            artifactHash,
            statementHash,
            modelHash,
            xaiDigest,
            zkmlProofHash
        );
        emit CustodyRecorded(evidenceId, action, attestor, artifactHash, statementHash);
    }

    // 5. Direct Custody & Artifact Anchoring

    function recordCustodyDID(
        uint256 evidenceId,
        CustodyAction action,
        ISOStage isoStage,
        bytes32 role,
        address recipient,
        bytes32 artifactSha256,
        bytes32 noteHash,
        bytes32 modelHash,
        bytes32 xaiDigest,
        bytes32 zkmlProofHash
    ) external override {
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        if (artifactSha256 == bytes32(0)) revert ZeroValue();
        if (!hasForensicRole(msg.sender, role)) revert UnauthorizedRole(msg.sender, role);

        CustodyRecordDID memory record = CustodyRecordDID({
            evidenceId: evidenceId,
            action: action,
            isoStage: isoStage,
            role: role,
            actor: msg.sender,
            recipient: recipient,
            artifactSha256: artifactSha256,
            noteHash: noteHash,
            modelHash: modelHash,
            xaiDigest: xaiDigest,
            zkmlProofHash: zkmlProofHash,
            timestamp: block.timestamp,
            signature: ""
        });
        _custodyHistoryDID[evidenceId].push(record);

        emit CustodyRecordedDID(
            evidenceId,
            action,
            isoStage,
            role,
            msg.sender,
            recipient,
            artifactSha256,
            noteHash,
            modelHash,
            xaiDigest,
            zkmlProofHash
        );
        emit CustodyRecorded(evidenceId, action, msg.sender, artifactSha256, noteHash);
    }

    function anchorForensicEvidence(
        uint256 evidenceId,
        bytes32 modelHash,
        bytes32 xaiDigest,
        bytes32 zkmlProofHash,
        bytes32 artifactSha256,
        bytes32 noteHash
    ) external override {
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        if (artifactSha256 == bytes32(0)) revert ZeroValue();

        bytes32 assignedRole = hasForensicRole(msg.sender, ROLE_ZKML_VERIFIER) ? ROLE_ZKML_VERIFIER : ROLE_ANALYST;
        if (!hasForensicRole(msg.sender, ROLE_ANALYST) && !hasForensicRole(msg.sender, ROLE_ZKML_VERIFIER)) {
            revert UnauthorizedRole(msg.sender, ROLE_ANALYST);
        }

        CustodyRecordDID memory record = CustodyRecordDID({
            evidenceId: evidenceId,
            action: CustodyAction.ANALYZED,
            isoStage: ISOStage.PRESERVATION,
            role: assignedRole,
            actor: msg.sender,
            recipient: address(0),
            artifactSha256: artifactSha256,
            noteHash: noteHash,
            modelHash: modelHash,
            xaiDigest: xaiDigest,
            zkmlProofHash: zkmlProofHash,
            timestamp: block.timestamp,
            signature: ""
        });
        _custodyHistoryDID[evidenceId].push(record);

        emit CustodyRecordedDID(
            evidenceId,
            CustodyAction.ANALYZED,
            ISOStage.PRESERVATION,
            assignedRole,
            msg.sender,
            address(0),
            artifactSha256,
            noteHash,
            modelHash,
            xaiDigest,
            zkmlProofHash
        );
        emit CustodyRecorded(evidenceId, CustodyAction.ANALYZED, msg.sender, artifactSha256, noteHash);
        emit ForensicEvidenceAnchored(evidenceId, modelHash, xaiDigest, zkmlProofHash, msg.sender);
    }

    // 6. View & Bounded Pagination

    function getCustodyHistoryDID(uint256 evidenceId) external view override returns (CustodyRecordDID[] memory) {
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        return _custodyHistoryDID[evidenceId];
    }

    function getCustodyCountDID(uint256 evidenceId) external view override returns (uint256) {
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);
        return _custodyHistoryDID[evidenceId].length;
    }

    function getCustodyHistoryDID(
        uint256 evidenceId,
        uint256 offset,
        uint256 limit
    ) external view override returns (CustodyRecordDID[] memory records, uint256 total) {
        if (evidenceId == 0 || evidenceId >= nextEvidenceId) revert EvidenceNotFound(evidenceId);

        total = _custodyHistoryDID[evidenceId].length;

        if (limit > MAX_PAGE_SIZE) {
            revert PageSizeTooLarge(limit, MAX_PAGE_SIZE);
        }

        if (limit == 0 || offset >= total) {
            return (new CustodyRecordDID[](0), total);
        }

        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }

        uint256 count = end - offset;
        records = new CustodyRecordDID[](count);
        for (uint256 i = 0; i < count; i++) {
            records[i] = _custodyHistoryDID[evidenceId][offset + i];
        }

        return (records, total);
    }
}
