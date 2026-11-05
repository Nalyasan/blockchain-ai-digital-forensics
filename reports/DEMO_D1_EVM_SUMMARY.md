# Integration Demo D1: EVM Incident Replay Summary

**Timestamp UTC:** `2026-11-05T11:46:25.208744Z`  
**Incident Target:** `EULER` (Blocks 16817990–16818110)  
**Exploit Transaction:** `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`  
**Exploiter Address:** `0x583c21631c48d442b5c0e605d624f54a0b366c72`  
**Overall Status:** **`PASS`**  

---

## 1. Pipeline Execution Stages

| Stage | Name | Verification Method | Status |
|---|---|---|---|
| 1 | ISO/IEC 27037 EVM Acquisition | `original_sha256 == copy_sha256`, manifest generated | **PASS** |
| 2 | Deterministic RuleEngine | Test window alerts with exploit tx in `evidence_refs` | **PASS** |
| 3 | Neural Anomaly Detection | `CompactAnomalyMLP` (321 params), score >= 0.70 | **PASS** |
| 4 | Quantitative XAI & MITRE | Exact Shapley ($R^2 \ge 0.80$, stability $\ge 0.85$), grounded MITRE | **PASS** |
| 5 | Cognitive AI Investigator | Offline FunctionModel, 5-step budget, RefChecker 100% | **PASS** |
| 6 | Real ZKML Halo2 Verification | 5,504-byte Halo2 BN254 pairing proof on Anvil `Halo2Verifier.sol` + `InferenceVerifier.sol` | **PASS** |
| 7 | DID 2-Actor Custody Handover | Alice -> Bob EIP-712 transfer on `EvidenceRegistryDID.sol` | **PASS** |
| 8 | Re-Read Provenance Branch | Smart contract manifest query -> disk read -> RuleEngine alert match | **PASS** |

## 2. Cryptographic Invariance Audit

| Canonical Database | Pre-Execution SHA-256 | Post-Execution SHA-256 | Invariance |
|---|---|---|---|
| `real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | **100% BITWISE INVARIANT** |
| `forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | **100% BITWISE INVARIANT** |
| `benchmark_p6.db` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | **100% BITWISE INVARIANT** |
| `.env` | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` | **100% BITWISE INVARIANT** |

## 3. Forensic Highlights & Gas Consumption

- **ZKML Proof Size:** `5,504` bytes (Halo2 BN254 KZG proof, zero mock).
- **On-Chain Verifier Gas:** `1,137,038` gas.
- **Custody Transfer Gas:** `459,107` gas.
- **RefChecker Concordance:** `100.0%` (0 missing references, 0 mismatched facts).
- **Dual-Read Concordance:** `100.0%` (Re-read data produces identical detection alerts).
