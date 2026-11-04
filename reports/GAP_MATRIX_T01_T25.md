# MA TRẬN KHOẢNG TRỐNG VÀ ĐỐI CHIẾU KIỂM THỬ TOÀN DIỆN T01–T25
# COMPREHENSIVE T01–T25 TECHNICAL GAP MATRIX & ARCHITECTURAL VERIFICATION REPORT

- **Dự án / Project:** Blockchain + AI Digital Forensics System (Academic PoC — Đề tài 8)
- **Tài liệu đặc tả căn cứ / Authoritative Specification:** `C:\Users\Naly\Downloads\AGENT.md` (Phiên bản 6.0, 04/11/2026)
- **Thiết kế & Blueprint:** `D:\Projest\.agents\teamwork\explorer_v6_M0_3\analysis.md`
- **Thời điểm lập báo cáo / Report Timestamp:** 2026-11-05T02:00:00Z (02:00:00+07:00, 05/11/2026)
- **Kiểm toán viên / Auditor:** Worker M0_1 (`worker_v6_M0_1`, Baseline Audit & Specification Setup Worker)
- **Nhánh Git / Active Git Branch:** `integration/p7-p10-dev` (Commit HEAD: `d7145333dcd1f0955e016f66ada78b806c84e581`)
- **Mã tài liệu / Deliverable ID:** `GAP_MATRIX_T01_T25` (Requirement R2 / Milestone M0)
- **Trạng thái kiểm toán / Audit Status:** STRICT HONESTY VERIFIED — ZERO ARTIFICIAL PASSES

---

## 1. TỔNG QUAN VÀ NGUYÊN TẮC KIỂM TOÁN (EXECUTIVE SUMMARY & AUDIT PRINCIPLES)

Báo cáo này thiết lập ma trận khoảng trống kỹ thuật chính thức và toàn diện giữa hiện trạng mã nguồn trong thư mục `Blockchain/` và đặc tả chuẩn duy nhất `AGENT.md v6.0`. Toàn bộ 25 kịch bản kiểm thử (T01 đến T25) cùng 12 thành phần chức năng được rà soát độc lập trên tinh thần trung thực học thuật tuyệt đối:
- **Nguyên tắc không ngụy tạo (No Fabrication):** Các kịch bản chưa hoàn thiện, bị bỏ qua (SKIP), hoặc chỉ chạy mock/fixture trên bộ nhớ được ghi nhận chính xác là `PARTIAL` hoặc `NOT_STARTED`. Tuyệt đối không tính SKIP thành PASS.
- **Phân định ranh giới rạch ròi:** Rule Engine $\ne$ Machine Learning; LLM Verbal Explanation $\ne$ XAI Quantitative Metric; Blacklist $\ne$ Ground Truth; SKIP $\ne$ PASS.
- **Bảo tồn tài sản bất biến:** Toàn bộ 4 tài sản dữ liệu chuẩn (`data/real_p4.db`, `data/forensics.db`, `data/benchmark_p6.db`, `.env`) được kiểm chứng khớp 100% mã băm SHA-256.

### Thống kê phân loại hiện trạng 25 kịch bản (T01–T25 Status Distribution):
- **HOÀN THÀNH (DONE):** **16 / 25 kịch bản (64.0%)** — T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, T13, T18, T20, T21, T24.
- **HOÀN THÀNH MỘT PHẦN (PARTIAL):** **6 / 25 kịch bản (24.0%)** — T12, T14, T15, T16, T17, T19.
- **CHƯA TRIỂN KHAI (NOT_STARTED):** **3 / 25 kịch bản (12.0%)** — T22, T23, T25.
- **BỊ CHẶN / CHƯA XÁC MINH (BLOCKED / NOT_VERIFIED):** **0 / 25 kịch bản (0.0%)**.

---

## 2. CHUẨN HÓA TÊN GỌI 12 THÀNH PHẦN CHỨC NĂNG (SYSTEM ARCHITECTURE ALIGNMENT)

Tuân thủ nghiêm ngặt Yêu cầu **R4**, hệ thống loại bỏ triệt để các nhãn giai đoạn tuần tự P1–P12 khỏi tài liệu, giao diện, sơ đồ và tên thành phần, chuẩn hóa thành 12 thành phần chức năng:

```text
+---------------------------------------------------------------------------------------------------+
|                                        DATA INGESTION                                             |
|  [C01: Blockchain Collector] (EVM blocks/txs/logs, reorg handling, RPC failover)                  |
|  [C07: Endpoint Acquisition] (ISO/IEC 27037, osquery/WMI, static EVTX/JSONL, acquisition_manifest)|
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                        EVIDENCE STORE                                             |
|  [C02: Evidence Store] (SQLite tamper-evident stores, SHA-256 payload digests, append-only)       |
|  - data/real_p4.db (canonical immutable), data/forensics.db, data/endpoint_evidence.db           |
+-------------------------------------------------+-------------------------------------------------+
                         |                                                |
                         v                                                v
+-------------------------------------------------+  +----------------------------------------------+
|             DETERMINISTIC DETECTION             |  |               MACHINE LEARNING               |
|  [C04: Rule Engine]                             |  |  [C08: ML/XAI]                               |
|  - Heuristics: Burst, Fan-In/Out, Pass-Through, |  |  - Chronological train/val/test split        |
|    Approval Poisoning                           |  |  - Decoupled labels (no rule-engine leak)    |
|  - Output: alerts with evidence_refs            |  |  - Unit-safe normalized asset amounts        |
|                                                 |  |  - Compact MLP Anomaly Detector (ONNX sync)  |
|                                                 |  |  - Local XAI (SHAP fidelity & stability)     |
|                                                 |  |  - MITRE ATT&CK with required evidence &     |
|                                                 |  |    NOT_MAPPED / abstain mechanism             |
+-------------------------------------------------+  +----------------------------------------------+
                         \                                                /
                          \                                              /
                           v                                            v
+---------------------------------------------------------------------------------------------------+
|                                  COGNITIVE INVESTIGATION & SAFETY                                 |
|  [C06: Threat Intelligence] (Known attacker sets, honeypots, contract signatures, MITRE base)     |
|  [C05: AI Investigator] (Pydantic AI agent, 5-layer read-only SQLite, 38-pattern injection filter, |
|    5-step budget, Ref Checker verifying ObservedFact vs ExternalThreatLabel)                      |
+-------------------------------------------------+-------------------------------------------------+
                         |                                                |
                         v                                                v
+-------------------------------------------------+  +----------------------------------------------+
|              VERIFIABLE COMPUTATION             |  |             EVIDENCE PACKAGING               |
|  [C09: ZKML]                                    |  |  [C03: Evidence Package]                     |
|  - PyTorch -> ONNX export                       |  |  - RFC 6962 Merkle tree commitments          |
|  - Halo2 arithmetic circuit with KZG commitment |  |  - Evidence manifest with SHA-256 digests    |
|  - Real EZKL witness & proof generation (no mock)  - Dual-read validation from Custody store      |
|  - Cryptographic binding (model/circuit/proof)  +----------------------------------------------+
|  - On-Chain Anvil Verifier (InferenceVerifier)  |
+-------------------------------------------------+
                         \                                                /
                          \                                              /
                           v                                            v
+---------------------------------------------------------------------------------------------------+
|                                    CHAIN OF CUSTODY & IDENTITY                                    |
|  [C10: Identity & Custody]                                                                        |
|  - EvidenceRegistry.sol & EvidenceRegistryDID.sol (Solidity 0.8.24)                                |
|  - W3C DID Core 1.0 (did:ethr / did:key), Granular RBAC (Collector, Analyst, Custodian, ZKML)    |
|  - EIP-712 typed off-chain signatures, anti-replay, nonce tracking, receipt reconciliation       |
|  - ISO/IEC 27037 compliant 2-actor transfer demonstration                                         |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                   EVALUATION & PORTABLE RELEASE                                   |
|  [C11: Integration & Evaluation] (D1 EVM Replay, D2 Host Replay, D3 Multi-Gateway Adversarial)     |
|  [C12: Portable Release] (Standalone Windows bundle, wheelhouse, SHA256SUMS, zero hardcoded paths)  |
+---------------------------------------------------------------------------------------------------+
```

### Bảng đối chiếu 12 Thành phần chức năng chuẩn hóa (Component Mapping Table)

| STT | Tên thành phần chức năng chuẩn hóa | Nhãn cũ | Mục AGENT v6.0 | Đường dẫn module chính | Trạng thái hiện tại | Trách nhiệm chức năng cốt lõi |
|:---:|---|:---:|:---:|---|:---:|---|
| **C01** | **Blockchain Collector** | P1 | §4 (P1), §11 | `forensics/collector/` | **DONE** | Thu thập khối, giao dịch, biên nhận EVM; bộ gỡ reorg 12 block; checkpoint nguyên tử. |
| **C02** | **Evidence Store** | P2 | §4 (P2), §11 | `forensics/store/` | **DONE** | Kho lưu trữ chứng cứ SQLite append-only; bảo vệ 5 tầng chỉ đọc; tính bất biến mã băm SHA-256. |
| **C03** | **Evidence Package** | P2/P3 | §4 (P2), §11 | `forensics/package/` | **PARTIAL** | Cây Merkle RFC 6962; xuất manifest.json; kiểm tra tính toàn vẹn 3 tầng (local, rpc, on-chain). |
| **C04** | **Rule Engine** | P4 | §4 (P4), §11 | `forensics/rules/` | **DONE** | Phát hiện bất thường tất định qua 4 luật R1–R4; phân định cửa sổ calibration/evaluation. |
| **C05** | **AI Investigator** | P5 | §4 (P5), §11 | `forensics/ai/` | **DONE** | Điều tra viên AI chỉ đọc; lọc 38 mẫu Prompt Injection; ngân sách 5 bước; RefChecker 2 tầng. |
| **C06** | **Threat Intelligence** | P6 | §4 (P6), §11 | `forensics/threat_intel/` | **DONE** | Nạp dữ liệu Forta, PTXPhish, MEW; chống chèn công thức CSV; phân định ObservedFact vs ExternalLabel. |
| **C07** | **Endpoint Acquisition** | P7 | §5 (P7), §11 | `forensics/endpoint/` | **PARTIAL** | Thu thập log hệ điều hành chuẩn ISO/IEC 27037; AI First Responder với giới hạn chính sách an toàn. |
| **C08** | **ML/XAI** | P8 | §6 (P8), §11 | `forensics/ml/` | **PARTIAL** | Mô hình Compact MLP; xuất ONNX; giải thích SHAP tất định; ánh xạ MITRE ATT&CK có căn cứ. |
| **C09** | **ZKML** | P9 | §7 (P9), §11 | `forensics/zkml/` | **PARTIAL** | Khả chứng suy luận Halo2 BN254 KZG thật; hợp đồng verifier trên Anvil (T22); liên kết mật mã học. |
| **C10** | **Identity & Custody** | P3/P10 | §4 (P3), §8 (P10) | `contracts/src/` | **PARTIAL** | Chuỗi hành trình chứng cứ; định danh W3C DID (ERC-1056); chữ ký EIP-712; demo chuyển giao 2 tác nhân. |
| **C11** | **Integration & Evaluation** | P11 | §9 (P11), §11 | `forensics/evaluation/` | **NOT_STARTED** | D1 (EVM Replay), D2 (Host Replay), D3 (Adversarial Replay); xuất báo cáo điều tra có thể truy vết. |
| **C12** | **Portable Release** | P12 | §10 (P12), §11 | `portable/`, root scripts | **NOT_STARTED** | Gói phân phối độc lập; script PowerShell tự động hóa; wheelhouse ngoại tuyến; kiểm thử thư mục sạch. |

---

## 3. BẢNG MA TRẬN ĐỐI CHIẾU KIỂM THỬ TOÀN DIỆN T01–T25 (COMPREHENSIVE TEST MATRIX)

Dưới đây là ma trận kiểm toán 10 cột toàn diện của 25 kịch bản kiểm thử theo `AGENT.md v6.0 §11`:

| Test ID | Test Scenario Name | Functional Component | AGENT.md v6.0 § | Status | Code / Test Reference | Verified Output / Artifact Hash | Remaining Technical Gaps | Remediation Milestone | Priority |
|:---:|---|:---:|:---:|:---:|---|---|---|:---:|:---:|
| **T01** | Collector Backfill & Continuous Ingestion | Blockchain Collector | §4 (P1), §11 | **DONE** | `collector.py:200-450`, `test_collector_erc20.py` | Ingests ETH blocks, txs, receipts, ERC-20 logs; atomic SQLite checkpoints; zero duplicate rows inserted on repeat. | Deprecate P1 naming in test files and scripts. | M1 | P3 |
| **T02** | RPC Resilience, Receipts Fallback & 429 Rate Limit | Blockchain Collector | §4 (P1), §11 | **DONE** | `collector.py:92-150`, `test_onchain_blockers.py` | Exponential backoff on HTTP 429; single receipt fallback; RPS rate throttling verified. | Clean code conventions and docstrings. | M1 | P3 |
| **T03** | Chain Reorg Handling & Orphaned Block Rollback | Blockchain Collector | §4 (P1), §11 | **DONE** | `collector.py:500-600`, `test_onchain_blockers.py` | Unwinds local chain $\le 12$ blocks on parentHash divergence; marks blocks `orphaned`; rewinds checkpoints. | Link canonical block status check to ML feature extraction pipeline. | M2 | P2 |
| **T04** | Dual Asset Heuristic Detection (ETH & ERC-20) | Rule Engine | §4 (P4), §11 | **DONE** | `forensics/rules/*.py`, `tests/test_rules.py` (32 tests) | R1–R4 rules execute over `asset_transfers` in `real_p4.db` (172 alerts generated with evidence_refs). | Enforce that Rule Engine alerts are NOT used as ML ground truth labels. | M2 | P3 |
| **T05** | Multi-Layer Evidence Verification (3-Tier) | Evidence Store & Package | §4 (P2), §11 | **DONE** | `forensics/integrity.py`, `tests/test_integrity_2a.py` | Tier 1 (local columns), Tier 2 (RPC diff), Tier 3 (on-chain hash) detect corruption. | Align package manifest schema with Endpoint Acquisition manifest format. | M4 | P2 |
| **T06** | Duplicate Registration Rejection & Custody Log | Identity & Custody | §4 (P3), §8, §11 | **DONE** | `contracts/src/EvidenceRegistry.sol`, `EvidenceRegistry.t.sol` | First registration emits `EvidenceRegistered`; duplicate reverts with `DuplicateManifestHash`. | Preserved in `EvidenceRegistryDID.sol`. | M1 | P3 |
| **T07** | Access Control & RBAC Authorization Enforcement | Identity & Custody | §4 (P3), §8, §11 | **DONE** | `EvidenceRegistryDID.sol`, `EvidenceRegistryDID.t.sol` (28 tests) | Non-permitted caller reverts with custom error `Unauthorized(address)`; 5 roles enforced. | Complete Python client integration test. | M4 | P3 |
| **T08** | Key Safety Guardrails & Anvil Key Blocker | Identity & Custody | §4 (P3), §8, §11 | **DONE** | `forensics/onchain.py:100-200`, `test_onchain_guard.py` | Fail-closed guard aborts signing if default Anvil key used on `chain_id != 31337`; zero keys logged. | Rename module and clean comments. | M1 | P3 |
| **T09** | AI Investigator Prompt Injection Sanitization | AI Investigator | §4 (P5), §11 | **DONE** | `forensics/ai/sanitizer.py`, `test_ai_security.py` | 38 injection patterns neutralized; strips control chars; encloses untrusted text in `<untrusted_onchain_data>`. | Refactor test filenames to functional naming. | M1 | P3 |
| **T10** | Two-Stage Reference & Content Checker | AI Investigator | §4 (P5), §11 | **DONE** | `forensics/ai/ref_checker.py`, `test_ai_investigator.py` | Stage 1 checks tx existence; Stage 2 checks field values; flags `CONTENT_MISMATCH` on hallucinated facts. | Synchronize imports post-renaming. | M1 | P3 |
| **T11** | Tool Whitelist & Maximum Step Budget Enforcement | AI Investigator | §4 (P5), §11 | **DONE** | `forensics/ai/tools.py`, `test_ai_tools.py` | Capped at `MAX_AI_TOOL_STEPS = 5`; 14 read-only tools whitelisted; 5-layer SQLite read-only access. | Clean legacy comments. | M1 | P3 |
| **T12** | Dual-Source Acquisition (EVM + Host Log) | Endpoint Acquisition | §5 (P7), §11 | **PARTIAL** | `forensics/endpoint/daemon.py`, `test_p7_endpoint.py` | Live osquery & WMI/PowerShell fallback queries run; dedicated `endpoint_evidence.db` operational. | Missing `EvidenceSourceAdapter`, `consent_scope`, `original/copy_sha256`, static JSONL/EVTX ingestion, manifest. | M4 | P1 |
| **T13** | AI First Responder Trigger & Policy Gates | Endpoint Acquisition | §5 (P7), §11 | **DONE** | `first_responder.py`, `test_p7_first_responder_safety.py` | 5 non-destructive playbooks pass; `SafetyGuard` blocks 100% of 5 forbidden actions (shell, log delete, ACL, net, sign). | Standardize naming and remove P-labels. | M1 | P3 |
| **T14** | Deterministic ML Inference & Model Registry | ML/XAI | §6 (P8), §11 | **PARTIAL** | `forensics/ml/model.py`, `models/anomaly_detector_v1.onnx` | Compact MLP (321 params) forward pass deterministic; ONNX weights match metadata hash. | Raw asset decimals summed directly; feature extraction ignores reorgs; missing dataset manifest. | M2 | P1 |
| **T15** | ML Anti-Leakage & Independent Ground Truth | ML/XAI | §6 (P8), §11 | **PARTIAL** | `forensics/ml/features.py:212-280`, `dataset.py` | Chronological train/val/test splitting logic implemented. | **CRITICAL DEFECT**: Labels derived from Rule alerts table; address grouping labels all historical windows; scaler fit leaks test. | M2 | P0 |
| **T16** | XAI Local Attribution & Quantitative Metrics | ML/XAI | §6 (P8), §11 | **PARTIAL** | `forensics/ml/xai.py`, `test_p8_xai_corroboration.py` | `ExactShapleyExplainer` calculates 1024 coalitions for 10 features, satisfying efficiency in <5ms. | Missing quantitative fidelity & stability metric calculations; missing `NOT_EXPLAINABLE` fallback. | M2 | P1 |
| **T17** | MITRE ATT&CK Grounded Mapping with Abstain | ML/XAI | §6 (P8), §11 | **PARTIAL** | `forensics/ml/mitre.py`, `test_p8_mitre_ai_integration.py` | Evidence refs enforced for mapped techniques (`T1565.001`, `T1566.002`, `T1027`, `T1048.003`, `T1499.004`). | Missing `tactic_id`, `mapping_rule`, `required_evidence`, `analyst_review_status`, versioning, and formal `NOT_MAPPED`/abstain. | M2 | P1 |
| **T18** | DID ↔ Signer Binding & Replay Rejection | Identity & Custody | §8 (P10), §11 | **DONE** | `EvidenceRegistryDID.sol`, `ChallengerDIDAdversarial.t.sol` | W3C/ERC-1056 DID parsing; EIP-712 domain separator; nonce tracking; high-$s$ malleability rejection. | Clean comments and standardize Python wrapper. | M4 | P3 |
| **T19** | CoC Multi-Actor Handover & Reconciliation | Identity & Custody | §8 (P10), §11 | **PARTIAL** | `EvidenceRegistryDID.t.sol`, `test_p10_custody.py:446-466` | Smart contract functions pass Foundry tests; `DIDClient` signs EIP-712 structured payloads. | Missing live Anvil 2-actor custody handover demo script with receipt reconciliation and hash concordance. | M4 | P1 |
| **T20** | Real Local Halo2/EZKL Positive Proof | ZKML | §7 (P9), §11 | **DONE** | `forensics/zkml/prover.py`, `tests/test_p9_zkml.py` | Halo2 BN254 KZG proof ($\pi$, 5,504 bytes); fixed-point scale $S=7$; offline verifier confirms `valid == True`. | Relocate circuit artifacts from scratch/ to permanent circuits/ directory. | M1 | P3 |
| **T21** | ZKML Adversarial Tampering Rejection | ZKML | §7 (P9), §11 | **DONE** | `forensics/zkml/verifier.py`, `test_p9_adversarial_challenger.py` | 100% rejection across $\ge 4$ test cases (bit-flipped bytes, truncated proofs, tampered commitments, forged scores). | Standardize test names and imports. | M1 | P3 |
| **T22** | On-Chain Anvil Smart Contract Verifier Execution | ZKML | §7 (P9), §11 | **NOT_STARTED** | Missing `InferenceVerifier.sol`, `test_p9_zkml.py:407-442` | None. Previous tests only recorded Solc compilation failure without `--via-ir`. | Generate `InferenceVerifier.sol`, compile with `--via-ir`, deploy on Anvil, submit proof calldata, log gas/receipts. | M3 | P0 |
| **T23** | Full Case Replay Across Demos D1 & D2 | Integration & Evaluation | §9 (P11), §11 | **NOT_STARTED** | Missing `scripts/demo_d1_evm.py`, `scripts/demo_d2_host.py` | None. Only a synthetic hybrid test fixture exists in `test_p1_p10_integration.py`. | Implement standalone runnable demo scripts for D1 (EVM) and D2 (Host log); build end-to-end traceable forensic report generator. | M5 | P1 |
| **T24** | Privacy Invariant, Adversarial & Zero Leakage | Integration & Evaluation | §8, §9, §11 | **DONE** | `sanitizer.py`, `artifacts.py`, `test_p10_custody.py` | Canary zero-leakage scanner confirms 0 private keys or PII written to smart contracts or logs. | Build automated multi-gateway adversarial demo D3 script. | M5 | P3 |
| **T25** | Clean Directory Extraction & Offline Repro | Portable Release | §10 (P12), §11 | **NOT_STARTED** | `scripts/portable.py`, `test_evaluation_portable.py` | None. Current script strips `.md` files; tests fail in fresh directory due to hardcoded paths. | Author `.ps1` automation scripts, add missing wheelhouse deps, author required docs, eliminate hardcoded paths, test clean extraction. | M6 | P1 |

---

## 4. PHÂN TÍCH CHI TIẾT 6 KHOẢNG TRỐNG KỸ THUẬT TRỌNG YẾU (DETAILED TECHNICAL GAPS)

### Khoảng trống 1: Endpoint Acquisition (Chuẩn hóa ISO/IEC 27037)
- **Thành phần mục tiêu:** `C07: Endpoint Acquisition` (`forensics/endpoint/`)
- **Căn cứ đặc tả AGENT.md v6.0:** §5.1 lines 135–139, §11 (Gate T12)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Thiếu Interface `EvidenceSourceAdapter`:* AGENT.md v6.0 quy định lớp cơ sở trừu tượng adapter chuẩn cho việc thu thập chứng cứ với các trường `source_type`, `source_id`, `acquisition_method`, `operator_or_agent_did`, `collection_time_utc`, `original_sha256`, `copy_sha256`, `chain_of_custody_case`, và `consent_scope`. Hiện tại chưa có giao diện này.
  2. *Thiếu `consent_scope` và cặp mã băm toàn vẹn:* Theo ISO/IEC 27037, thu thập chứng cứ số bắt buộc phải ghi nhận phạm vi được phép (`consent_scope`) và kiểm chứng tính toàn vẹn bit-stream qua cặp mã băm `original_sha256` (tệp nguồn) và `copy_sha256` (bản sao lưu). `forensics/endpoint/schemas.py` hiện chưa có các trường này.
  3. *Thiếu bộ nạp tệp nhật ký bảo mật tĩnh:* `forensics/endpoint/daemon.py` chỉ có query trực tiếp trên hệ điều hành đang chạy (osquery/WMI). Chưa có adapter nạp các tệp log tĩnh xuất ra từ Sysmon (`.jsonl`) hoặc Windows Event Log (`.evtx`).
  4. *Thiếu `acquisition_manifest.json`:* Chưa có hàm sinh biên bản thu giữ chuẩn hóa theo ISO/IEC 27037 ghi nhận công cụ, phiên bản, DID điều tra viên, thời gian UTC và mã băm.
  5. *Phân định dữ liệu thật và dữ liệu giả lập:* Khi chạy kiểm thử ngoại tuyến không có daemon thật, các bản ghi phải được gắn cờ `synthetic=true`, không được tuyên bố chạy daemon thật.
- **Biện pháp khắc phục (Milestone M4):**
  - Xây dựng `forensics/endpoint/adapter.py` định nghĩa `EvidenceSourceAdapter` và các adapter cụ thể (`EVMCollectorAdapter`, `HostLogFileAdapter`, `OsqueryLiveAdapter`).
  - Bổ sung `consent_scope`, `original_sha256`, `copy_sha256` vào `schemas.py`.
  - Triển khai bộ phân tích log tĩnh trong `forensics/endpoint/static_logs.py`.
  - Triển khai sinh `acquisition_manifest.json` trong `forensics/endpoint/manifest.py`.

### Khoảng trống 2: Machine Learning & Explainable AI (ML/XAI)
- **Thành phần mục tiêu:** `C08: ML/XAI` (`forensics/ml/`)
- **Căn cứ đặc tả AGENT.md v6.0:** §6.1 lines 154–165, §6.2 lines 167–176, §6.3 lines 178–184, §11 (Gates T14, T15, T16, T17)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Ô nhiễm nhãn Ground Truth (Circular Training):* Trong `forensics/ml/features.py:212-233`, pipeline trích xuất đặc trưng gán nhãn dựa trên bảng `alerts` của Rule Engine (`label = 1 if entity_addr in alerted_entities else 0`). Điều này vi phạm nghiêm trọng nguyên tắc độc lập giữa học máy và luật heuristic.
  2. *Rò rỉ thời gian do gom địa chỉ toàn cục:* `alerted_entities` tại `features.py:279` là tập hợp không chia cửa sổ. Một địa chỉ có cảnh báo ở cửa sổ 10 khiến toàn bộ cửa sổ lịch sử (0 đến 9) của nó bị gán nhãn 1, làm sai lệch hành vi bình thường trong quá khứ.
  3. *Cộng dồn số lượng raw thô không an toàn đơn vị:* `v_in_raw += int(t.get("amount_raw", 0))` tại `features.py:104-125` cộng trực tiếp số nguyên của các tài sản khác nhau. 1 ETH ($10^{18}$ wei) và 1 USDC ($10^6$ units) bị cộng gộp, khiến ETH lấn át USDC tới $10^{12}$ lần.
  4. *Rò rỉ tiền xử lý qua Scaler:* Scaler chỉ được fit trên tập huấn luyện ($\mu_{train}, \sigma_{train}$) rồi mới biến đổi sang val/test. Hiện tại chưa có cơ chế cô lập chặt chẽ.
  5. *Bỏ qua trạng thái canonical reorg:* Pipeline trích xuất đặc trưng cần kiểm tra trạng thái canonical do Collector xác nhận.
  6. *Thiếu chỉ số định lượng cho XAI:* `forensics/ml/xai.py` tính Shapley nhưng thiếu chỉ số độ tin cậy định lượng: Fidelity (độ nhạy khi loại bỏ đặc trưng) và Stability (độ ổn định trước nhiễu $\epsilon$), đồng thời thiếu cơ chế fallback `NOT_EXPLAINABLE`.
  7. *Lược đồ MITRE ATT&CK chưa đầy đủ:* `forensics/ml/mitre.py` thiếu `tactic_id`, `mapping_rule`, `required_evidence`, `analyst_review_status`, và trả về `[]` thay vì bản ghi rõ ràng `NOT_MAPPED`/abstain.
- **Biện pháp khắc phục (Milestone M2):**
  - Tách nhãn: Xây dựng nhãn ground truth độc lập không phụ thuộc bảng alerts của Rule Engine.
  - Sửa gom địa chỉ: Giới hạn nhãn cảnh báo trong đúng phạm vi cửa sổ $[T_{start}, T_{end})$.
  - Chuẩn hóa số thập phân tài sản: `normalized_amount = raw_amount / (10 ** token_decimals)`.
  - Bổ sung tính toán Fidelity và Stability trong `forensics/ml/xai.py`.
  - Hoàn thiện schema và cơ chế `NOT_MAPPED`/abstain trong `forensics/ml/mitre.py`.

### Khoảng trống 3: Zero-Knowledge Machine Learning (ZKML On-Chain Verifier T22)
- **Thành phần mục tiêu:** `C09: ZKML` (`forensics/zkml/`, `contracts/src/`)
- **Căn cứ đặc tả AGENT.md v6.0:** §7.1 lines 186–188, §7.2 lines 190–191, §11 (Gates T20, T21, T22)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Chưa có hợp đồng xác thực trên chuỗi (Gate T22):* `InferenceVerifier.sol` chưa tồn tại trong `contracts/src/`. Trong `tests/test_p9_zkml.py:407-442`, test chỉ ghi nhận lỗi biên dịch "Stack too deep" khi thiếu `--via-ir` và coi như hoàn thành mà không triển khai lên Anvil.
  2. *Thiếu đo lường gas và biên nhận giao dịch:* Chưa có script hay test gửi calldata proof thực tế lên smart contract, đo gas và lưu biên nhận với tx hash trên Anvil.
  3. *Thiếu liên kết mật mã học đầy đủ:* Registry chấp nhận `zkmlProofHash` nhưng chưa ràng buộc chặt chẽ chuỗi `model_hash || circuit_version || input_commitment || output_commitment || inference_record_id`.
- **Biện pháp khắc phục (Milestone M3):**
  - Xuất `InferenceVerifier.sol` từ EZKL và bật `--via-ir` trong cấu hình `foundry.toml`.
  - Tạo `contracts/src/InferenceVerifier.sol` và `IInferenceVerifier.sol`.
  - Viết bộ kiểm thử Foundry và triển khai lên Anvil cục bộ (`http://127.0.0.1:8545`, `chain_id = 31337`).
  - Gửi calldata proof thực, đo gas, ghi nhận biên nhận và xác minh tự động từ chối khi can thiệp proof bytes hoặc public signals.

### Khoảng trống 4: Identity & Chain of Custody (Chữ ký EIP-712 & Demo 2 Tác nhân)
- **Thành phần mục tiêu:** `C10: Identity & Custody` (`contracts/src/EvidenceRegistryDID.sol`, `forensics/custody/`)
- **Căn cứ đặc tả AGENT.md v6.0:** §8.1 lines 193–204, §8.2 lines 206–212, §11 (Gates T06, T07, T18, T19)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Thiếu kịch bản chạy thực tế chuyển giao 2 tác nhân:* `EvidenceRegistryDID.sol` đã có đủ logic phân quyền và chống replay, nhưng test Python client mới chỉ kiểm tra deploy hợp đồng và cấp quyền.
  2. *Thiếu script tự động hóa đối soát biên nhận:* Chưa có kịch bản chạy thực nghiệm:
     `Actor A (Collector DID) -> Đăng ký Package -> Actor B (Analyst DID) -> Ký nhận EIP-712 -> Gửi lên Anvil -> Lấy biên nhận -> Đối soát mã băm Package`.
- **Biện pháp khắc phục (Milestone M4):**
  - Viết `forensics/custody/handover.py` điều phối quy trình chuyển giao 2 tác nhân hoàn chỉnh.
  - Thực thi kiểm thử chạy thật trên Anvil với việc ký EIP-712 của Collector và Analyst.
  - Xác thực biên nhận và đối soát mã băm giữa SQLite và smart contract logs.
  - Kiểm thử từ chối đóng kín khi sai vai trò, sai chain ID, replay chữ ký hoặc xung đột mã băm.

### Khoảng trống 5: Integration & Evaluation (D1, D2, D3 & Báo cáo Truy vết)
- **Thành phần mục tiêu:** `C11: Integration & Evaluation` (`scripts/`, `forensics/evaluation/`)
- **Căn cứ đặc tả AGENT.md v6.0:** §9.1 lines 214–221, §9.2 lines 223–229, §11 (Gates T23, T24)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Thiếu 3 script demo thực nghiệm độc lập:*
     - **D1 (EVM Replay):** Ingests EVM incident -> Evidence Store -> Rule/ML -> XAI -> Investigator -> Package -> Custody DID trên Anvil -> ZKML verifier.
     - **D2 (Host Log Replay):** Ingests log máy chủ -> mã băm bảo toàn -> anomaly trigger -> MITRE -> Investigator -> Custody.
     - **D3 (Adversarial Replay):** Tấn công đa tầng kiểm chứng từ chối đóng kín ở mọi lớp.
     Hiện tại mới chỉ có một fixture lai tổng hợp trong `test_p1_p10_integration.py`.
  2. *Thiếu bộ sinh báo cáo pháp chứng truy vết xuyên suốt:* Chưa có module tổng hợp báo cáo nối kết `evidence_id -> alert_id -> ML/XAI digest -> AI finding -> custody tx receipt -> ZKML proof digest`.
  3. *Nhập nhằng số liệu đánh giá:* Cần tách bạch rõ ràng giữa kiểm thử chức năng, chỉ số ML, chỉ số XAI, tính toàn vẹn CoC, kiểm chứng ZKML và khả năng tái lập.
- **Biện pháp khắc phục (Milestone M5):**
  - Xây dựng `scripts/demo_d1_evm.py`, `scripts/demo_d2_host.py`, `scripts/demo_d3_adversarial.py`.
  - Xây dựng `forensics/evaluation/report_generator.py` xuất báo cáo pháp chứng truy vết đầy đủ.

### Khoảng trống 6: Portable Release & Triệt tiêu Đường dẫn Cố định
- **Thành phần mục tiêu:** `C12: Portable Release` (`portable/`, root package)
- **Căn cứ đặc tả AGENT.md v6.0:** §10 lines 231–245, §11 (Gate T25)
- **Khoảng trống và khuyết tật hiện tại:**
  1. *Script đóng gói loại bỏ tài liệu Markdown:* `scripts/portable.py:67-68` loại trừ toàn bộ `.md`, làm mất `AGENT.md`, `README_SETUP.md`, `PORTABILITY_TEST_REPORT.md`, `LICENSES_AND_DATA_RIGHTS.md`.
  2. *Thiếu dependencies trong `requirements.txt`:* Thiếu `ezkl`, `torch`, `onnx`, `numpy`.
  3. *Thiếu 4 script PowerShell tự động hóa bắt buộc:* Chưa có `setup.ps1`, `smoke_test.ps1`, `run_full_tests.ps1`, `verify_integrity.ps1`.
  4. *Thiếu `SHA256SUMS.txt`:* Chưa có tệp tổng kiểm tra mã băm cho toàn bộ gói phát hành.
  5. *Đường dẫn hardcoded vào môi trường gốc:* Còn tồn tại các chuỗi `D:/Projest/...` hoặc `C:/Users/Naly/...` khiến kiểm thử tại thư mục mới bị thất bại.
- **Biện pháp khắc phục (Milestone M6):**
  - Sửa `scripts/portable.py` để giữ lại các tài liệu bắt buộc.
  - Bổ sung dependencies và xác thực kho wheelhouse ngoại tuyến.
  - Tạo 4 script PowerShell tự động hóa.
  - Biên soạn `README_SETUP.md`, `PORTABILITY_TEST_REPORT.md`, `LICENSES_AND_DATA_RIGHTS.md`.
  - Sinh `SHA256SUMS.txt` và kiểm thử giải nén sạch trong thư mục mới (Gate T25).

---

## 5. DANH MỤC TẬP TIN CẦN ĐỔI TÊN VÀ ĐỒNG BỘ HÓA (REFACTORING CATALOG)

Trong **Milestone M1**, các tệp sau sẽ được đổi tên để xóa bỏ hoàn toàn nhãn P1–P12:

### 5.1 Các tệp kiểm thử cần đổi tên:
1. `tests/test_p1_p10_integration.py` $\longrightarrow$ `tests/test_integration_lifecycle.py`
2. `tests/test_evidence_p2.py` $\longrightarrow$ `tests/test_evidence_store.py`
3. `tests/test_p3_p4_flow.py` $\longrightarrow$ `tests/test_custody_rules_flow.py`
4. `tests/test_p3_group5_security_qa.py` $\longrightarrow$ `tests/test_custody_security_qa.py`
5. `tests/p4_fixtures.py` $\longrightarrow$ `tests/rule_fixtures.py`
6. `tests/test_p4_anchored_package.py` $\longrightarrow$ `tests/test_evidence_package_anchoring.py`
7. `tests/test_p5_real_incidents.py` $\longrightarrow$ `tests/test_ai_investigator_incidents.py`
8. `tests/test_p6_adapters.py` $\longrightarrow$ `tests/test_threat_intel_adapters.py`
9. `tests/test_p6_screening.py` $\longrightarrow$ `tests/test_threat_intel_screening.py`
10. `tests/test_adversarial_p6_screening.py` $\longrightarrow$ `tests/test_adversarial_screening.py`
11. `tests/test_p7_endpoint.py` $\longrightarrow$ `tests/test_endpoint_acquisition.py`
12. `tests/test_p7_first_responder_safety.py` $\longrightarrow$ `tests/test_first_responder_safety.py`
13. `tests/test_p7_adversarial_challenger.py` $\longrightarrow$ `tests/test_first_responder_adversarial.py`
14. `tests/test_p8_ml_foundations.py` $\longrightarrow$ `tests/test_ml_foundations.py`
15. `tests/test_p8_xai_corroboration.py` $\longrightarrow$ `tests/test_xai_corroboration.py`
16. `tests/test_p8_mitre_ai_integration.py` $\longrightarrow$ `tests/test_mitre_mapping.py`
17. `tests/test_p9_zkml.py` $\longrightarrow$ `tests/test_zkml_verification.py`
18. `tests/test_p9_adversarial_challenger.py` $\longrightarrow$ `tests/test_zkml_adversarial.py`
19. `tests/test_p10_custody.py` $\longrightarrow$ `tests/test_identity_custody.py`

### 5.2 Các script vận hành cần đổi tên:
1. `scripts/train_p8_model.py` $\longrightarrow$ `scripts/train_anomaly_model.py`
2. `scripts/run_p4_smoke.py` $\longrightarrow$ `scripts/run_rules_smoke.py`
3. `scripts/run_p1_anvil_test.py` $\longrightarrow$ `scripts/run_collector_anvil_test.py`
4. `scripts/run_p3_anvil_test.py` $\longrightarrow$ `scripts/run_custody_anvil_test.py`

### 5.3 Quy ước code sạch (Clean Code Conventions):
- Loại bỏ các comment thừa chỉ mô tả lại cú pháp hoặc nhãn giai đoạn (như `// Phase 4 rule execution`).
- Giữ nguyên các chú thích liên quan đến ràng buộc an toàn, quyết định thiết kế và thuật toán quan trọng.
- Cập nhật đồng bộ các import và CLI tương ứng.

---

## 6. LỘ TRÌNH KHẮC PHỤC KHOẢNG TRỐNG KỸ THUẬT (REMEDIATION ROADMAP M1–M6)

- **M1 (Đổi tên & Quy chuẩn Code sạch):** Đổi tên các tệp test/script P1–P12; chuẩn hóa import; xóa chú thích thừa; xác minh 112 contract tests và 1.521 tests pass 100%.
- **M2 (Khắc phục ML/XAI):** Tách nhãn độc lập khỏi bảng alerts; sửa gom địa chỉ cửa sổ; chuẩn hóa đơn vị token; đo fidelity/stability; hoàn thiện MITRE abstain (T14, T15, T16, T17).
- **M3 (ZKML On-Chain Verifier & Gate T22):** Biên dịch `InferenceVerifier.sol` với `--via-ir`; triển khai Anvil; đo gas và biên nhận; xác minh Gate T22.
- **M4 (Endpoint & Custody DID):** Cài đặt `EvidenceSourceAdapter`; nạp log tĩnh JSONL/EVTX; sinh `acquisition_manifest.json`; chạy demo 2 tác nhân trên Anvil (T12, T19).
- **M5 (Kịch bản Demo D1, D2, D3 & Báo cáo Truy vết):** Xây dựng `demo_d1_evm.py`, `demo_d2_host.py`, `demo_d3_adversarial.py`; xuất báo cáo truy vết đầu cuối (T23).
- **M6 (Dọn dẹp an toàn & Đóng gói Portable):** Lập `cleanup_manifest`; đóng gói offline bundle; tạo 4 script `.ps1` và `SHA256SUMS.txt`; kiểm thử thư mục sạch (Gate T25).

---

## 7. BIÊN BẢN KIỂM CHỨNG TÍNH BẤT BIẾN CƠ SỞ DỮ LIỆU GỐC (INVARIANCE AUDIT)

| Đường dẫn tệp | SHA-256 Dự kiến (Authoritative Baseline) | SHA-256 Thực tế trên Đĩa | Kết luận |
|---|---|---|:---:|
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | **KHỚP 100% BITWISE** |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | **KHỚP 100% BITWISE** |
| `data/benchmark_p6.db` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | **KHỚP 100% BITWISE** |
| `.env` | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` | **KHỚP 100% BITWISE** |
