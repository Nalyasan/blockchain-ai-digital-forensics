# Ma trận đối chiếu T01–T25 sau khắc phục (AGENT.md v6.0)

- **Đặc tả:** `AGENT.md` v6.0 (SHA-256 `DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E`)
- **Nhánh:** `integration/p7-p10-dev`; chuỗi commit khắc phục `24a52ad` (M0) → `17a9a25` (M5) → commit M6 (xem `git log`).
- **Bản trước khắc phục (M0):** 16 DONE / 6 PARTIAL / 3 NOT_STARTED — lưu trong lịch sử Git của chính file này (`git show 24a52ad:reports/GAP_MATRIX_T01_T25.md`).
- **Quy tắc trạng thái:** chỉ `DONE` khi có lệnh chạy, log/test, commit và artifact/hash. `SKIP`, mock hay báo cáo “100%” không được tính là `DONE`.

## 1. Tóm tắt

| Trạng thái | Số gate | Gate |
|---|:---:|---|
| DONE | 25 | T01–T25 (T25 = kiểm thử giải nén sạch trên thư mục mới của máy nguồn) |
| NOT_VERIFIED | 1 hạng mục riêng | T25-B: chạy trên **máy Windows vật lý thứ hai** |
| NOT_VERIFIED | 1 hạng mục học thuật | Xác nhận của giảng viên về mức bắt buộc ZKML (§12, §16.4) |

Kết quả hồi quy toàn bộ cuối M6: xem §4.

## 2. Ánh xạ thành phần chức năng

| Thành phần | Gate | Module chính | Trạng thái |
|---|---|---|:---:|
| Blockchain Collector | T01–T03 | `collector.py`, `forensics/real_data_ingest.py` | DONE |
| Evidence Store | T05 | `forensics/evidence.py`, `forensics/schemas.py`, `forensics/integrity.py` | DONE |
| Evidence Package | T05, T19 | `forensics/evidence.py` (export/manifest), `forensics/rules/anchored.py` | DONE |
| Rule Engine | T04 | `forensics/rules/` | DONE |
| AI Investigator | T09–T11 | `forensics/ai/` | DONE |
| Threat Intelligence | (P6 baseline), T24 | `forensics/adapters/` | DONE |
| Endpoint Acquisition | T12–T13 | `forensics/endpoint/` | DONE |
| ML/XAI | T14–T17 | `forensics/ml/`, `models/` | DONE |
| ZKML | T20–T22 | `forensics/zkml/`, `circuits/anomaly_detector_v1/`, `contracts/src/Halo2Verifier.sol`, `contracts/src/InferenceVerifier.sol` | DONE |
| Identity & Custody | T06–T08, T18–T19 | `contracts/src/EvidenceRegistry.sol`, `contracts/src/EvidenceRegistryDID.sol`, `forensics/did/`, `forensics/onchain.py` | DONE |
| Integration & Evaluation | T23–T24 | `scripts/demo_d1_evm.py`, `scripts/demo_d2_host.py`, `scripts/demo_d3_adversarial.py`, `forensics/evaluation/report_generator.py` | DONE |
| Portable Release | T25 | `scripts/portable.py`, `setup.ps1`, `smoke_test.ps1`, `run_full_tests.ps1`, `verify_integrity.ps1` | DONE (cùng máy) / NOT_VERIFIED (máy thứ hai) |

## 3. Ma trận T01–T25

| Gate | Yêu cầu | Trạng thái | Bằng chứng | Giới hạn / còn lại |
|:---:|---|:---:|---|---|
| T01 | Collector backfill/continuous | DONE | `tests/test_collector_erc20.py`, `scripts/test_continuous_anvil.py` | — |
| T02 | RPC resilience, 429, receipts fallback | DONE | `tests/test_onchain_blockers.py`, `tests/test_receipt_patch.py` | — |
| T03 | Reorg | DONE | `tests/test_onchain_blockers.py` | Feature extraction ML chỉ dùng block `canonical` (`forensics/ml/features.py`) |
| T04 | Rule R1–R4 ETH/ERC-20 | DONE | `tests/test_rules.py`, `tests/test_real_data_rules.py` | Alert không dùng làm ground truth ML |
| T05 | Verify 3 tầng | DONE | `tests/test_integrity_2a.py`, `tests/test_evidence_package.py` | — |
| T06 | Smart contract register/duplicate | DONE | `contracts/test/EvidenceRegistry.t.sol`, `EvidenceRegistry_Group4.t.sol` | ABI P3 giữ nguyên |
| T07 | Phân quyền | DONE | `contracts/test/EvidenceRegistryDID.t.sol` (28 test) | — |
| T08 | Key Safety Guard | DONE | `tests/test_onchain_guard.py`, `tests/test_onchain_group1.py`, `tests/test_onchain_group1b.py` (Anvil thật) | M6 sửa hồi quy rò rỉ stderr của `cast` (xem §5) |
| T09 | Prompt injection | DONE | `tests/test_ai_security.py` | — |
| T10 | Ref checker tồn tại + nội dung | DONE | `tests/test_ai_investigator.py`, `tests/test_investigator_real_incidents.py` | — |
| T11 | Tool whitelist, `MAX_AI_TOOL_STEPS=5` | DONE | `tests/test_ai_tools.py`, `tests/test_ai_tools_adversarial.py` | — |
| T12 | Acquisition EVM + host log | DONE | `forensics/endpoint/` adapters + `acquisition_manifest.json`; `tests/test_endpoint_acquisition.py`; `reports/DEMO_D2_HOST_SUMMARY.md` (original/copy SHA-256 `d3a264f7…fbf1`) | Host log trong demo là fixture `synthetic=true`, không phải daemon thật |
| T13 | First Responder trigger/policy gate | DONE | `tests/test_first_responder_guardrails.py`, `tests/test_first_responder_safety.py`, `tests/test_empirical_challenger_iter2.py` | — |
| T14 | ML inference tái lập | DONE | `models/anomaly_detector_v1.onnx` (`d1b9ce82…aeff`), `models/dataset_manifest.json`, `tests/test_ml_m2_remediation.py`, `tests/test_challenger_m2_empirical.py` (1000 vector PyTorch↔ONNX) | — |
| T15 | Anti-leakage + nhãn | DONE | `forensics/ml/ground_truth.py` (nhãn theo cửa sổ sự cố, không lấy bảng `alerts`), scaler fit trên train; `tests/test_challenger_m2_adversarial_deep.py` | Ground truth chỉ 12 cửa sổ dương tính / 5.265 → số liệu precision/recall có độ bất định lớn |
| T16 | XAI fidelity/evidence | DONE | `forensics/ml/xai.py` (Exact Shapley, `fidelity_r2`, `stability_score`, `NOT_EXPLAINABLE`); `tests/test_xai_corroboration.py` | — |
| T17 | MITRE grounded + abstain | DONE | `forensics/ml/mitre.py` (`required_evidence`, `NOT_MAPPED`/`TA0000`); `tests/test_mitre_ai_integration.py` | Ánh xạ là gợi ý máy, cần người rà soát |
| T18 | DID ↔ signer | DONE | `contracts/test/ChallengerDIDAdversarial.t.sol`, `tests/test_adversarial_did.py` | — |
| T19 | CoC 2 actor end-to-end | DONE | `scripts/run_custody_handover_demo.py`, `tests/test_custody_transfer_flow.py`, `tests/test_did_custody_handover.py` (Anvil thật) | Tx hash Anvil là synthetic |
| T20 | ZKML proof local thật | DONE | `forensics/zkml/`, `circuits/anomaly_detector_v1/` (proof 5.504 byte), `tests/test_zkml_verifiable_inference.py` | — |
| T21 | ZKML tampering | DONE | `tests/test_adversarial_zkml.py`, `tests/test_challenger_m3_zkml_stress.py`, `Halo2RealVerifier.t.sol` (5 ca đột biến revert) | — |
| T22 | Verifier on-chain Anvil | DONE | `contracts/src/Halo2Verifier.sol` (pairing BN254 KZG thật) ← `InferenceVerifier.sol`; `scripts/verify_m3_zkml_anvil.py`; gas 1.135.772–1.137.038 | Chỉ Anvil cục bộ |
| T23 | Full case replay D1/D2 | DONE | `reports/DEMO_D1_EVM_REPORT.json`, `reports/DEMO_D2_HOST_REPORT.json`, `reports/DEMO_EVALUATION_REPORT.md`; `tests/test_demo_d1_evm.py`, `tests/test_demo_d2_host.py` | D2 không có ZKML: ghi `ARCHITECTURAL_LIMITATION` (không mock) |
| T24 | Privacy / injection / tamper | DONE | `scripts/demo_d3_adversarial.py` (35/35 vector bị chặn, 6 cổng), `tests/test_demo_d3_adversarial.py` | — |
| T25 | Portable clean-extract | DONE (cùng máy) | `PORTABILITY_TEST_REPORT.md`, `results/verification/m6_portable_verification.json` | **T25-B máy thứ hai: NOT_VERIFIED** |

## 4. Kết quả hồi quy cuối M6

Xem `results/verification/m6_full_regression_junit.xml` và mục “Kết quả kiểm thử” trong `reports/FINAL_ACCEPTANCE_REPORT_v6.md`.

## 5. Lỗi phát hiện và sửa trong M6

| Lỗi | Nguyên nhân | Sửa |
|---|---|---|
| `test_onchain_group1.py` (3 FAIL) + `test_onchain_group1b.py` (69 ERROR, `SECRET_LEAK_DETECTED`) | Commit `039a26b` đưa `stderr` của `cast` vào thông báo `CAST_EXIT_*` → có thể lộ mật khẩu/khóa/URL RPC | Khôi phục thông báo đã che trong `forensics/onchain.py` |
| `test_evidence_identity.py::test_note_hash_no_filesystem_probing` | Thay đường dẫn cứng ở M6 dùng `Path` chưa import | Dùng `pathlib.Path` |
| `test_empirical_challenger_iter2.py::test_nested_none_and_numbers` | Xung đột với schema nghiêm ngặt `extra="forbid"` (M4) | Kiểm tra lớp regex không báo nhầm + tham số hợp lệ được chấp nhận + khóa lạ vẫn bị từ chối (không nới lỏng chính sách) |
| `smoke_test.ps1` trên bản giải nén: so sánh `.env` | `.env` gốc (chứa khóa) không được phân phối; `setup.ps1` tạo `.env` từ `.env.example` | `forensics.paths.accepted_env_sha256()` chấp nhận đúng 2 digest; 3 DB vẫn khóa cứng 1 digest |

## 6. Hạng mục còn mở

1. T25-B — chạy ZIP trên máy Windows vật lý thứ hai: **NOT_VERIFIED**.
2. Xác nhận học thuật về mức ZKML / DL-GNN (§16.4): **NOT_VERIFIED**. DL/GNN: `OPTIONAL_RESEARCH`.
3. Wheelhouse chưa chứa 12 gói ML/ZKML mở rộng (`torch`, `ezkl`, `onnx`, …); đã khóa phiên bản trong `requirements-ml-zkml.lock.txt`. Không ảnh hưởng smoke test và suy luận/kiểm chứng.
4. Còn một số file test/script mang tên lịch sử (`test_p7_*.py`, `run_p3_*.py`, …) chưa đổi tên; giữ lại để không phá tham chiếu trong log nghiệm thu lịch sử.
