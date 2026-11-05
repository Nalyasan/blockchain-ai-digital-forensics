# Milestone M3 ZKML On-Chain Verification Report (Gate T22)

- **Execution Time (UTC)**: 2026-11-05T05:02:25.078561+00:00
- **Overall Status**: **PASS**
- **Gate**: Gate T22 (ZKML On-Chain Verification & Anvil Telemetry)
- **Chain ID**: `31337` (Anvil Local Testnet)
- **InferenceVerifier Address**: `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0`
- **CircuitVerifier Address**: `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- **Model Commitment (SHA-256)**: `0xd1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff`
- **Input Commitment**: `7ad33a8edf17ff4f87ef8e6be3501d6be953398c43c139eb79a5d488529bf767`
- **Output Commitment**: `0x0000000000000000000000000000000000000000000000000000000000000080` (Score: 1.0)
- **Proof Size**: `5504 bytes` (Halo2 / KZG on BN254)
- **Proof Keccak-256**: `0x31ad3f6dc03400f3eb55db0240750895f0e76cfa4dd7b5e37811ee980f1ab609`
- **Verification Gas Used**: `366916`
- **Synthetic Tx Hash**: `0x5485ea09f97ac84946bcd008d700ff44392a73f65bcf470ffd1d19c63854be3f (synthetic)`

## Adversarial Live Replay Matrix

| Case ID | Description | Mutation | Expected Rejection | Observed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ADV-LIVE-01 | Bit-Flipped Proof Payload | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-02 | Corrupted Input Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-03 | Corrupted Model Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-04 | Spoofed Output Score Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-05 | Truncated 16-Byte Proof Buffer | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |

## Gate T22 Compliance Certification

- [x] Local Anvil deployment automated and verified (`socket.bind 0` dynamic lifecycle)
- [x] Genuine proof verification returns status 1 with gas logged
- [x] Transaction hashes clearly marked as synthetic (`is_synthetic: true`)
- [x] 5 adversarial replay cases tested and fail-closed rejected
- [x] Zero mock proofs used for acceptance; authentic Halo2 5,504-byte proof transcript verified
- [x] Chain of Custody invariance preserved (`EvidenceRegistry.sol` and `EvidenceRegistryDID.sol` untouched)
