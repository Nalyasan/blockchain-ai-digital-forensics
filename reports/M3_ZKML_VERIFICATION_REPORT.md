# ZKML On-Chain Verification Report (Gate T22)

- **Execution Time (UTC)**: 2026-11-05T11:45:28.104685+00:00
- **Overall Status**: **PASS**
- **Gate**: Gate T22 (ZKML On-Chain Verification & Anvil Telemetry)
- **Chain ID**: `31337` (Anvil Local Testnet)
- **InferenceVerifier Address**: `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`
- **Halo2Verifier Address (BN254 KZG Pairing)**: `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- **Model Commitment (SHA-256)**: `0xd1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff`
- **Input Commitment**: `0x7ad33a8edf17ff4f87ef8e6be3501d6be953398c43c139eb79a5d488529bf767`
- **Output Commitment**: `0x0000000000000000000000000000000000000000000000000000000000000080` (Score: 1.0)
- **Proof Size**: `5504 bytes` (Halo2 / KZG on BN254, 11 public signals)
- **Proof Keccak-256**: `0x3f0620b5345408a34e5e4f196bc9573d135017646ce383646b5e01d535589125`
- **Verification Gas Used**: `1135772`
- **Synthetic Tx Hash**: `0x196567ccbc0871f3f53f573bbf29452d276cd09e6c3a3cba7c99d14d0b1c0189 (synthetic)`

## Adversarial Live Replay Matrix

| Case ID | Description | Mutation | Expected Rejection | Observed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ADV-LIVE-01 | Bit-Flipped Proof Payload | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-02 | Corrupted Input Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-03 | Corrupted Model Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-04 | Spoofed Output Score Commitment | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-05 | Truncated 16-Byte Proof Buffer | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |
| ADV-LIVE-06 | Mutated Public Instance Signal | Injected anomaly | REVERT / Fail | REVERTED | **PASS** |

## Gate T22 Compliance Certification

- [x] Local Anvil deployment automated and verified (`socket.bind 0` dynamic lifecycle)
- [x] Real EZKL-generated `Halo2Verifier.sol` BN254 pairing check verified via EVM precompile `0x08`
- [x] Genuine proof verification returns status 1 with gas logged
- [x] Transaction hashes clearly marked as synthetic (`is_synthetic: true`)
- [x] 6 adversarial replay cases tested and fail-closed rejected
- [x] Zero mock proofs or mock verifiers used for acceptance; authentic Halo2 5,504-byte proof transcript verified
- [x] Chain of Custody invariance preserved (`EvidenceRegistry.sol` and `EvidenceRegistryDID.sol` untouched)
