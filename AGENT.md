# AGENT.md — BLOCKCHAIN + AI DIGITAL FORENSICS (ĐỀ TÀI 8)

> **Phiên bản đặc tả:** 6.1 — phạm vi P1–P11, loại yêu cầu đóng gói portable Windows theo quyết định của chủ dự án ngày 05/11/2026.  
> **Loại tài liệu:** Yêu cầu sản phẩm, kiến trúc, quy tắc thực thi và tiêu chí nghiệm thu cho Coding Agent.  
> **Nguồn yêu cầu học thuật:** *Ứng dụng blockchain trong ATTT — Hướng dẫn các chủ đề các nhóm K18 ATTT*, mục **“Đề tài 8: Điều tra số kết hợp Blockchain và AI”**, trang 10–12.  
> **Kế thừa:** `AGENT.md v5.1` (tài liệu người dùng cung cấp) và các kết quả P1–P6 đã báo cáo; **KHÔNG** viết lại hoặc mặc nhiên hủy những phần đã được kiểm thử.  
> **Trạng thái:** Đây là **đặc tả mục tiêu cập nhật**, không phải tuyên bố những chức năng mới đã có trong mã nguồn. Mọi tính năng phải được kiểm tra trên repository thật trước khi gắn nhãn `DONE`.
> **Phạm vi:** P1–P11; ưu tiên vận hành bằng Terminal và dữ liệu thật được phép sử dụng. Không yêu cầu đóng gói portable Windows hoặc kiểm thử clean-extract trên máy thứ hai; hướng dẫn cài đặt và vận hành nằm trong `README.md`. Yêu cầu tạo **gói chứng cứ**, sao lưu, kiểm thử hồi quy và xác minh SHA-256 vẫn giữ nguyên.

---

## 0. Quy tắc đọc và áp dụng đặc tả

1. **Đúng Đề tài 8:** Hệ thống cần thể hiện ba trụ cột của hướng dẫn: **(A) AI Agents thu thập/phân tích dấu vết và Explainable AI (XAI); (B) Smart Contract quản lý Chain of Custody; (C) kiểm chứng tính toàn vẹn suy luận bằng Zero-Knowledge Machine Learning (ZKML)**. Phần Ethereum/EVM là môi trường thí điểm, không phải toàn bộ khái niệm điều tra số.
2. **Giữ tài sản hiện có:** P1–P6 được coi là baseline báo cáo, **không phải** tự động được nghiệm thu lại. Chỉ bổ sung có kiểm soát vào code đang chạy; kiểm thử hồi quy để phát hiện phá vỡ tính năng cũ.
3. **Phân biệt nguồn yêu cầu:** Hướng dẫn của thầy là tài liệu định hướng nghiên cứu, trong đó có các đề xuất tham vọng (DL, GNN, ZKML). Tài liệu này chuyển chúng thành những *deliverable* cụ thể với mức tối thiểu/ mở rộng. Không khẳng định thầy yêu cầu nhất thiết mọi kỹ thuật đều phải triển khai production khi chưa có xác nhận riêng.
4. **Không bịa tiến độ:** Phải ghi `DONE / PARTIAL / NOT_STARTED / BLOCKED / NOT_VERIFIED` dựa trên commit, log, test và bằng chứng. Không xem `SKIP` là `PASS`; không suy diễn test suite xanh là toàn bộ hệ thống đã vận hành với dữ liệu thật.
5. **Nguồn sự thật theo thứ tự:** hướng dẫn Đề tài 8 → đặc tả này → code + tests + dữ liệu thực tế tại commit đã đối chiếu → báo cáo đã có. Khi mâu thuẫn, **nêu khác biệt và báo người phụ trách**, không tự ý sửa lịch sử.
6. **Thay đổi có giới hạn:** trước khi chạm nguồn phải ghi repo, branch, HEAD, Git status, file có thay đổi chưa commit; sao lưu an toàn. Không reset/rebase/force-push/merge/xóa file dữ liệu nếu chưa được yêu cầu rõ ràng.

## 1. Đầu ra cuối cùng và phạm vi nghiên cứu

**Tên đề tài:** *Điều tra số kết hợp Blockchain và AI (Blockchain + AI Digital Forensics)*.

**Bài toán:** Tự động nhận biết dấu hiệu bất thường từ nguồn dữ liệu số, thu thập và bảo quản chứng cứ có thể đối chiếu, hỗ trợ điều tra bằng AI với giải thích kiểm chứng được, đồng thời dùng Smart Contract và cơ chế chứng minh mật mã để củng cố tính toàn vẹn của **chứng cứ** và **quá trình suy luận**.

**Luồng minh chứng tối thiểu phải chạy được từ đầu đến cuối trên máy kiểm thử offline:**

1. Nhập sự kiện/dấu vết đã được cho phép sử dụng (ít nhất **EVM logs/transactions** và **một nguồn không phải blockchain**, ví dụ Windows Event Log xuất JSON/EVTX đã được chuẩn hóa, Sysmon export hoặc IoT JSONL fixture).
2. Thu thập **nguyên bản**, đánh dấu nguồn và thời điểm, tính SHA-256, quản lý snapshot bất biến và audit trail theo nguyên tắc ISO/IEC 27037.
3. Rule Engine **và** mô hình ML phát hiện/gợi ý bất thường; mỗi cảnh báo dẫn đến chứng cứ gốc. ML không được thay thế ngầm bằng rule hoặc output LLM.
4. Một **AI First-Responder/Investigator** có quyền giới hạn thực hiện chuỗi tác vụ xác định: chọn cảnh báo, truy xuất chứng cứ, đề xuất thu thập bổ sung được phê chuẩn, phân tích và xuất báo cáo.
5. Có **XAI** giải thích dự đoán của **mô hình ML** bằng đặc trưng, ảnh hưởng/độ quan trọng, giới hạn, dẫn chứng và **MITRE ATT&CK** nếu ánh xạ được từ chứng cứ.
6. Tạo gói chứng cứ gồm dữ liệu thô + manifest + hash; đăng ký trên **Anvil cục bộ**, ghi và xác minh các sự kiện **Chain of Custody** và người thực hiện.
7. Chứng minh suy luận bằng **ZKML proof of concept thực** (không mock), gắn proof với mô hình/đầu vào/đầu ra; xác minh proof offline và qua verifier smart contract trên Anvil khi toolchain cho phép. Nếu điều kiện chưa đáp ứng, phải để trạng thái `NOT_DONE`, không thay bằng SHA-256/chữ ký rồi gọi ZKML.
8. Cung cấp hướng dẫn chạy các thành phần thật qua Terminal (`README.md`), ghi rõ phụ thuộc và cấu hình trên hệ điều hành được hỗ trợ; sinh báo cáo thực nghiệm, log và bằng chứng kiểm chứng. Không bắt buộc tạo gói portable hay kiểm thử chuyển máy.

**Giới hạn phạm vi thực thi:** PoC phục vụ học thuật, không phải nền tảng SOC quy mô sản xuất hay hệ thống bảo đảm giá trị chứng cứ trước tòa. Không đòi hỏi can thiệp kernel, tự động dump RAM của máy khác hoặc giám sát trái phép. Những ví dụ IoT/5G/cloud trong đề bài được thể hiện bằng adapter nguồn dữ liệu có quyền và case study giới hạn; không được khẳng định đã hỗ trợ toàn hạ tầng nếu chỉ chạy fixture.

## 2. Bản đồ đối chiếu trực tiếp Đề tài 8

| Trọng tâm từ tài liệu thầy (tr. 10–12) | Yêu cầu phần mềm tối thiểu | Baseline P1–P6 (dựa trên báo cáo) | Công việc bổ sung |
|---|---|---|---|
| AI Agents làm “First Responder”, thu thập IoC và dấu vết | Workflow agent giới hạn quyền, có trigger, provenance, lưu chứng cứ và audit | Collector P1 + Rule P4 + AI Investigator P5 | Tích hợp pipeline tự động, bổ sung tối thiểu 1 nguồn dấu vết ngoài EVM |
| ML/DL/GNN phát hiện bất thường | Ít nhất 1 mô hình ML có train/infer/evaluate thực; ghi dataset, model hash, kết quả | P4 chủ yếu quy tắc, P5 chủ yếu AI investigator | Mô hình ML độc lập; DL/GNN là mở rộng nghiên cứu có đánh giá |
| Explainable AI và MITRE ATT&CK | Lý giải dự đoán mô hình, trích dẫn chứng cứ, ánh xạ kỹ thuật nếu đủ căn cứ | Ref checker và giải thích rule đã có một phần | XAI thực sự cho mô hình ML, mapping có cơ sở và cơ chế abstain |
| CoC bằng Smart Contract, chữ ký, dấu thời gian, DID | Neo hash, ghi sự kiện chuyển giao, ký/xác minh, ràng buộc actor với DID | P2/P3 EvidenceRegistry và custody | DID tối thiểu ở lớp ứng dụng, xác thực ánh xạ DID↔địa chỉ ký |
| ZKML: xác nhận suy luận AI không bị thay đổi | Mô hình nhỏ + public/private input rõ ràng + prove/verify thật | Chưa có bằng chứng triển khai ZKML | Prototype prover/verifier, kiểm thử sai model/input/output phải fail |
| Minh bạch, tái lập, nghiên cứu pháp chứng | Log nguồn, metrics có methodology, báo cáo giới hạn | P6 có benchmark và integrity tests | Đánh giá AI/XAI/ZKML riêng, hướng dẫn tái lập các lệnh CLI và hash đầu ra |

**Không được tráo khái niệm:** `Rule Engine ≠ Machine Learning`; `LLM giải thích bằng lời ≠ XAI kiểm chứng cho mô hình ML`; `SHA-256/chữ ký số ≠ ZKML`; `địa chỉ Ethereum ≠ DID`; `blacklist screening ≠ đo chất lượng phát hiện on-chain`.

## 3. Kiến trúc đích (bảo toàn baseline)

```text
Nguồn chứng cứ được phép
  ├─ Ethereum/EVM: block, tx, receipt, logs, asset_transfers (P1)
  └─ Host/IoT/cloud export: JSONL/CSV/EVTX đã chuẩn hóa (bổ sung)
                    |
            Collect & Acquire + SHA-256 + provenance
                    |
             Evidence Store bất biến (P2) ----> Evidence Package/Manifest
                    |                                     |
         +----------+----------+                          |
         |                     |                          |
      Rule Engine P4      ML Anomaly Model (mới)           |
         |                     |                          |
         +------ Alert --------+                          |
                    |                                    |
            AI First Responder / P5 Investigator          |
          [tool whitelist, consent gate, audit log]       |
                    |                                    |
      XAI + MITRE ATT&CK + Ref Checker (mới)              |
                    |                                    |
       Inference Record: model/input/output digests       |
                    |                                    |
            ZKML Prover ---> Proof/Verifier (mới)         |
                    |                                    |
                    +----------------+-------------------+
                                     |
                     EvidenceRegistry / CoC / DID (P3 + mở rộng)
                                     |
                         Audit + Report + Replay + Terminal CLI
```

**Ranh giới tin cậy:** chứng cứ thô và nhãn CTI là dữ liệu không tin cậy; LLM không có quyền tùy ý thực thi shell/SQL/ký giao dịch. Model ML, XAI và ZKML phải ghi phiên bản/commit/hash độc lập. Blockchain chỉ chứa thông tin tối thiểu (hash/commitment, id giả danh, sự kiện), **không** chứa raw logs, PII, mật khẩu, khóa hoặc prompt.

## 4. Bảo toàn các chức năng P1–P6 đã triển khai

### P1 — Blockchain Collector và parser

Giữ backfill/continuous, `eth_getBlockReceipts` với fallback, retry/backoff và HTTP 429, checkpoint nguyên tử, chain reorg, xác minh RPC, `raw_json` và `raw_sha256`, chuẩn hóa ETH và ERC-20 vào `asset_transfers`. Cờ `synthetic` phải phân biệt block Anvil mới tạo, block fork lịch sử và giao dịch thật. Nội bộ smart contract chỉ thấy nếu có trace API; không suy diễn từ receipt/logs thông thường.

### P2 — Evidence / forensic integrity

Giữ SQLite migrations không phá hủy, `audit_events`, xuất chứng cứ (`raw_blocks.jsonl`, `asset_transfers.csv`, `timeline.csv`, `manifest.json`, các file log/audit phù hợp) và ba tầng xác minh: local, RPC, on-chain. Mỗi file chứng cứ có hash và thông tin truy xuất. Không sửa dữ liệu lịch sử để làm test xanh. Mã băm ở cùng một DB không tự nó chống người có toàn quyền sửa DB; cần kết hợp đối chứng off-chain/on-chain.

### P3 — Smart Contract / Chain of Custody

Giữ `EvidenceRegistry.sol`, Foundry/Anvil smoke tests, register/record/verify, phân quyền investigators, chống duplicate, lưu vết `(chain_id, contract_address, tx_hash, log_index)`, nhật ký append-only, journal idempotency/reconcile, check signature, Key Safety Guard. `caseId` được hash; không ghi case name/PII/note gốc lên chain. Giao dịch lên Sepolia/mainnet bị **khóa mặc định**; chỉ mở khi có lệnh phê duyệt riêng bằng văn bản và ví testnet phù hợp.

### P4 — Rule Engine cho asset transfers

Giữ đúng định nghĩa trong AGENT v5.1 và mã nguồn đã nghiệm thu; kiểm tra tên thực trong code, không lấy theo bảng nhầm ở P6 handoff:

- **R1 `large_transfer`**: ngưỡng theo asset, `p99` nếu đủ mẫu; fallback 10 ETH với NATIVE.
- **R2 `high_frequency`**: mặc định ≥10 chuyển giao / 300 giây.
- **R3 `fan_in_out`**: ≥8 đối tác / 900 giây theo cùng asset.
- **R4 `rapid_pass_through`**: chuyển tiếp trong 5 block, tỷ lệ 0.80–1.05, tối thiểu 1 ETH hoặc p90 ERC-20 có căn cứ.

Không cộng lượng ETH với token ERC-20 khác nhau; không quy tội từ alert. Tách calibration/test window trước khi đo hiệu năng.

### P5 — AI Investigator và ref checker

Giữ sanitizer cho untrusted on-chain content, schema đầu ra, `ref_checker` kiểm tra cả sự tồn tại và giá trị nội dung (`tx_hash`, block, amount, addresses, asset), tool whitelist và ngân sách mặc định `MAX_AI_TOOL_STEPS=5`. `collect_missing_range` là **ngoại lệ có tác dụng ghi** thông qua Collector; bắt buộc audit/consent và giới hạn tối đa 20 block/lần, 2 lần/phiên nếu tiếp tục hỗ trợ. Không tạo đặc quyền shell/SQL/contract send cho LLM. Hỗ trợ offline deterministic/test provider và chế độ không AI.

### P6 — Real-data / public dataset benchmark

Giữ pipeline công khai Forta/PTXPhish/MEW, adapter CSV/XLSX/JSON, provenance, chống CSV formula injection, screening, phân biệt `ObservedFact` và `ExternalThreatLabel`, G5-02 append-only. Tập P6 có **34.841 bản ghi theo báo cáo** (Forta 15.259, PTXPhish 18.867, MEW 715); **không phải mọi bản ghi đều có nhãn độc hại** vì PTXPhish chứa benign controls. Theo báo cáo P6: **1.015 passed, 70 skipped, 0 failed**, 77/77 bài chuyên biệt P6 đạt; đây không thay bằng xác minh thực tế trên máy mới. 2.972 lượt địa chỉ từ Euler (2.852) và Curve (120), nhưng 2.953 địa chỉ duy nhất; zero blacklist match **không chứng minh** địa chỉ là benign hoặc mô hình ML có độ chính xác 100%.

### Baseline / Git cần giữ

| Khoảng | Nhận dạng báo cáo (phải xác minh bằng Git thật) |
|---|---|
| Master lịch sử | `D:\Projest\Blockchain` tại `9bed49a` |
| P4/P5 integrated baseline | `55003fd` |
| P6 feature | `D:\Projest\p6_public_benchmark\repo`, branch `feature/p6-public-dataset-benchmark`, HEAD `50f457f` |
| P4/P5 audit cũ | 922 pass, 70 skip, trạng thái PARTIAL tại thời điểm kiểm toán; phải xác định thay đổi 14 file đã có trong baseline hay chưa |

**Mọi giai đoạn mới phải bắt đầu bằng `git status --short`, `git rev-parse HEAD`, kiểm tra commit ancestry, SHA-256 các DB chứng cứ canonical đang được bảo vệ và trạng thái test baseline.** Không xem kết quả chạy demo, log cũ hoặc việc có README là bằng chứng tương đương kiểm chứng mã nguồn và dữ liệu thực tế.

## 5. P7 — AI First Responder & đa nguồn pháp chứng (mới)

### P7.1 — Thu thập có kiểm soát theo ISO/IEC 27037

- Tạo interface `EvidenceSourceAdapter` với `source_type`, `source_id`, `acquisition_method`, `operator_or_agent_did`, `collection_time_utc`, `original_sha256`, `copy_sha256`, `chain_of_custody_case`, `consent_scope`.
- Có ít nhất hai adapter chạy end-to-end: **EVM adapter** dùng P1 hiện tại, và **host/security log adapter** cho log xuất bởi chủ máy được phép (ví dụ Sysmon/Windows Event JSON/JSONL). IoT/cloud/5G adapters có thể là thiết kế mở rộng, không mạo nhận hỗ trợ nếu chỉ có demo.
- Thực hiện các bước **Identification → Collection → Acquisition → Preservation**, ghi `acquisition_manifest.json` chứa nguồn, phạm vi, công cụ/phiên bản, hash, người vận hành, mốc thời gian UTC, copy path. Nếu nguồn bất biến/không thể sửa, ghi rõ điều kiện đọc.
- Không âm thầm thu thập file cá nhân, dump RAM, gửi dữ liệu qua mạng ngoài, không tự cách ly hệ thống/tiến trình. Mọi tác vụ ảnh hưởng máy thật phải có người xác nhận; demo chỉ dùng fixture hoặc thao tác đọc được phép.
- Phát hiện mất log/gap/đảo thời gian/định dạng sai → `AUDIT_WARNING` hoặc `BLOCKED`, không tự bù record bịa đặt.

### P7.2 — Agent workflow có kiểm soát

- Workflow có thể kích hoạt bởi cảnh báo P4, kết quả ML, hoặc lệnh người dùng. Ghi `investigation_id`, trigger, allowlist, kế hoạch hành động, từng tool call, output hash và lý do dừng.
- LLM/agent chỉ đề xuất; hành động thu thập bổ sung phải qua **policy gate** và có giới hạn phạm vi. Việc đóng gói/neo chứng cứ là một bước tường minh do workflow controller được ủy quyền thực hiện, không do LLM sở hữu khóa.
- Cảnh báo từ nguồn log không EVM không được ép thành transaction on-chain giả. Phải có namespace và `evidence_refs` riêng.
- T01–T11 baseline tiếp tục PASS trong phạm vi test không bị skip do policy.

**P7 nghiệm thu:** Chạy một ca điều tra từ nguồn EVM và một ca từ host log với đầy đủ acquisition manifest/hash/audit, không phát sinh hành động vượt allowlist và có thể tái hiện bằng lệnh, cấu hình và đầu vào được ghi nhận.

## 6. P8 — Machine Learning, XAI và MITRE ATT&CK (mới)

### P8.1 — Mô hình ML thực, có quy trình thực nghiệm

- Tạo tối thiểu **một mô hình ML** train/infer được (ví dụ Isolation Forest cho hành vi bất thường hoặc mô hình phân loại có nhãn) sử dụng dữ liệu có nguồn gốc rõ. Dùng feature extractor độc lập: transaction count, in/out degree, amount distribution, temporal burst; log ngoài EVM có features phù hợp riêng. Không tạo nhãn malicious từ cùng rule rồi đo độ chính xác như thể có ground truth độc lập.
- Lưu `dataset_manifest`, train/validation/test split, seed, preprocessor, feature schema và model hash. Split theo thời gian/sự cố hoặc theo nhóm để tránh rò rỉ địa chỉ/tương quan giữa tập train/test. Tránh dữ liệu đánh giá chồng vào calibration.
- Đầu ra mỗi dự đoán: `model_id`, `model_sha256`, `feature_schema_version`, `input_evidence_refs`, `input_digest`, `prediction`, `confidence_or_score`, `threshold`, `inference_time`, `source_is_synthetic`, `ground_truth_status`.
- `RuleAlert`, `MLPrediction`, `ExternalThreatLabel`, `ObservedFact` phải là các schema tách biệt; không tự nâng prediction thành factual finding.
- **Deep Learning / GNN:** Nếu chọn triển khai mở rộng thì nêu lý do, dữ liệu đồ thị và kiểm thử so sánh với baseline ML; nếu chưa làm, ghi `OPTIONAL_RESEARCH`, không tuyên bố đạt GNN.

### P8.2 — XAI kiểm chứng được

- Với chính mô hình ML sử dụng trong pipeline, tạo giải thích **local** (ví dụ ảnh hưởng features bằng phương pháp phù hợp loại model, SHAP nếu môi trường cho phép, hoặc counterfactual/surrogate được giải thích đúng giới hạn). Kèm ít nhất `top_features`, values, contribution/direction nếu tính được, baseline/reference, model/input hashes và liên kết chứng cứ.
- Đo và báo cáo **fidelity/stability** hoặc tiêu chí kiểm tra thích hợp; không chỉ dùng LLM viết một đoạn văn tự nhận là “XAI”. Nếu thuật toán không cung cấp giải thích đáng tin cậy, trả `NOT_EXPLAINABLE` và lý do.
- Không phát ngôn “nguyên nhân tấn công đã được chứng minh” chỉ từ feature importance; phân biệt correlation, cảnh báo và chứng cứ.

### P8.3 — MITRE ATT&CK có căn cứ

- Dùng phiên bản ATT&CK được ghi rõ ngày/nguồn; bảng mapping có `technique_id`, `tactic_id`, `mapping_rule`, `required_evidence`, `confidence`, `analyst_review_status`.
- Chỉ gắn mã ATT&CK khi sự kiện có đủ dữ kiện; không gán tùy tiện mọi phishing address hoặc chuyển tiền lớn thành một kỹ thuật. Với giao dịch EVM thuần túy, kỹ thuật Enterprise ATT&CK có thể không khớp → **abstain**, ghi `NOT_MAPPED` thay vì bịa mã.
- Tách **máy gợi ý**, **người rà soát**, và **evidence-backed conclusion**. Báo cáo link tài liệu ATT&CK và mapping phiên bản.

**P8 nghiệm thu:** Có thể load model từ artifact, tái tạo inference trên test set, giải thích cùng model/input và chứng minh test sai hash/thiếu evidence bị chặn; benchmark ML có cỡ mẫu, methodology, số liệu chỉ phát sinh từ script. Có biểu đồ và bảng ATT&CK chứa các mục gắn được và ví dụ abstain.

## 7. P9 — ZKML Proof of Concept có kiểm chứng thật (mới)

**Mục tiêu học thuật:** chứng minh một phép suy luận của mô hình đã cố định được thực hiện theo đúng mạch/tính toán đối với đầu vào được cam kết, **không** khẳng định mô hình đúng về mặt điều tra, không chứng minh dữ liệu ban đầu là thật, và không bảo đảm ẩn danh tuyệt đối nếu lộ metadata.

### P9.1 — Thiết kế proof statement

- Chọn một **mô hình nhỏ có thể chuyển thành mạch** (ví dụ logistic regression / MLP cực nhỏ, fixed-point quantized) để làm PoC; không đòi chứng minh toàn bộ LLM hay GNN lớn.
- Public inputs tối thiểu: `model_commitment`, `input_commitment`, `output_commitment` (hoặc giá trị kết quả công khai nếu được phép), `circuit_version`, `proof_id`. Private witness gồm feature vector và thành phần bí mật nếu thiết kế yêu cầu. Phải làm rõ kiểu hash/commitment dùng trong mạch và ngoài mạch, tính nhất quán encoding/quantization.
- Xác định rõ **model version**, **feature extraction provenance**, **circuit artifact digest**, **proving/verification key digests**, **verifier version**, `inference_record_id`.
- Dữ liệu thô/PII không đưa vào proof public inputs hoặc on-chain calldata; chỉ định danh hash/commitment cần thiết.

### P9.2 — Prove/verify và kiểm thử đối kháng

- Tích hợp prover/verifier thật của một stack ZK khả thi (ví dụ EZKL/Halo2 hoặc công cụ phù hợp được đánh giá), ghim chính xác phiên bản, không dùng dummy verifier/mocked proof trong test nghiệm thu.
- Thực hiện proof generation và verification **offline/local**; có ít nhất một `proof.json` hoặc artifact proof thực, log cùng đường dẫn tái tạo, không sửa tay JSON đầu ra để đánh PASS.
- Chạy thử biến đổi **input**, **model**, **output**, public commitment và proof bytes: verifier phải từ chối tương ứng; thử lại đúng dữ liệu phải PASS.
- Tích hợp verifier smart contract trên **Anvil local** để xác minh proof (nếu stack hỗ trợ EVM verifier) và kiểm thử gas, success/failure events; ghi tx hash của Anvil là **synthetic**. Nếu chỉ có off-chain verifier, đánh dấu `PARTIAL`, **không đạt** tiêu chí on-chain của bản đặc tả này.
- Smart contract lưu xác nhận proof hoặc commitment nhưng không thay đổi ngầm ABI/ý nghĩa của `EvidenceRegistry.sol` đã nghiệm thu. Dùng verifier adapter hoặc contract riêng, thiết kế rõ liên hệ `evidence_id` ↔ `inference_record_id` ↔ `proof_id`.

### P9.3 — Giới hạn trung thực

- Proof chỉ bảo đảm tính nhất quán toán học của mạch đã xác nhận; **không** chứng minh dataset/nhãn đúng, AI suy luận công bằng, XAI trung thực, hay chứng cứ gốc không bị khai man lúc thu thập.
- Chỉ tuyên bố privacy nếu có mô tả chính xác public/private signals và thử rò rỉ; không gọi việc băm PII thành “đã ẩn danh tuyệt đối”.
- Nếu proof stack không cài được trên máy Windows mục tiêu, cần cung cấp phương án WSL/container đã kiểm thử hoặc báo `BLOCKED`, không giả lập để vượt gate.

**P9 nghiệm thu:** ≥1 successful real proof + ≥4 adversarial failures + verifier on-chain trên local Anvil + artifact/provenance/hashes + hướng dẫn tái hiện offline. Kết quả benchmark gồm thời gian prove/verify, kích thước proof, memory và gas (nếu applicable); không so sánh vô căn cứ với mô hình không cùng quy mô.

## 8. P10 — Chain of Custody nâng cao với DID và chữ ký số (mới)

- Giữ ABI và tính bất biến bản P3 đã được kiểm thử. Bổ sung một **lớp DID resolver/identity binding**: PoC có thể dùng `did:key` và chữ ký xác minh off-chain; nếu dùng `did:ethr`, phải nêu network, resolver và kiểm thử thực. **DID không đồng nhất** với địa chỉ ví; cần tài liệu/chứng thực ràng buộc DID của actor ↔ public key ↔ địa chỉ Ethereum được phép.
- Chuỗi chuyển giao: actor identity, role, action, case/evidence hash, timestamp UTC cùng on-chain block time, chữ ký/transaction receipt, previous event reference và quyền truy cập. Sự kiện immutable; không cho overwrite/`INSERT OR REPLACE` của lịch sử custody.
- Thực hiện `COLLECTED → ANALYZED → TRANSFERRED → EXPORTED` khi đúng quy trình kiểm thử; không sửa lịch sử để ép thứ tự. Nếu hợp đồng không enforce order, workflow controller phải kiểm tra và nêu rõ ranh giới.
- `transferCustody()` trong tài liệu thầy là ví dụ về thao tác nghiệp vụ. **Không tự đổi chữ ký hàm của contract P3** nếu `recordCustody(..., TRANSFERRED, ...)` đã biểu đạt đúng; ghi mapping API/ABI.
- Kịch bản sai chữ ký, actor chưa cấp quyền, tái phát sự kiện, xung đột hash, thiếu receipt hoặc sai chain ID phải fail-closed. Không neo chứng cứ `synthetic=true` lên public chain.
- Lưu PII gốc, log nhạy cảm, file điều tra ở off-chain có kiểm soát. Mã băm và địa chỉ ví trên chain vẫn có thể là dữ liệu có thể liên kết; tài liệu phải nêu giới hạn về riêng tư/GDPR, không tuyên bố tự động tuân thủ pháp luật.

**P10 nghiệm thu:** Hai actor thử nghiệm có DID độc lập, xác minh chữ ký và chain-of-custody từ khởi tạo tới chuyển giao bằng Anvil, test sai DID/key/role/receipt bị từ chối, có export/verifier và hash đối chiếu end-to-end.

## 9. P11 — Tích hợp, thực nghiệm, bảo mật và báo cáo (mới)

### P11.1 — Kịch bản demo tích hợp bắt buộc

**D1 — EVM forensic case:** replay dữ liệu EVM được xác minh nguồn → Collector → Evidence Store → P4 rule → ML prediction → XAI → AI Investigator/ref checker → gói chứng cứ → P3 custody + DID → ZKML verification → final report.

**D2 — Host/IoT forensic case:** nhập log xuất hợp lệ → tính hash/bảo quản → trigger bất thường → ML/XAI/MITRE khi có căn cứ → investigator → custody → proof hoặc đánh dấu giới hạn kiến trúc nếu model chưa hỗ trợ. Không tự nhận hai ca đều có ZKML nếu mới proof được một model.

**D3 — Adversarial replay:** sửa raw evidence, sửa inferred result/model commitment, đổi actor/DID hoặc thay proof → hệ thống phải chỉ rõ gate thất bại; chứng cứ gốc và DB canonical giữ nguyên hash.

### P11.2 — Nguyên tắc đo lường

- Tách **test chức năng**, **ML metrics**, **XAI metrics**, **CoC integrity**, **ZKML correctness/performance** và **khả năng tái lập bằng lệnh CLI** thành các báo cáo riêng.
- ML: dùng Precision/Recall/F1/AUPRC khi có ground truth thích hợp; nếu thiếu nhãn, chỉ báo cáo anomaly score distribution, hit counts, case study và limitation. Tuyệt đối không coi `0 blacklist matches` là `0 false positives` trong tập không có nhãn chuẩn.
- XAI: fidelity và stability (định nghĩa cụ thể, script sinh số), số record giải thích được/abstain, độ phủ evidence_refs.
- AI Investigator: tỷ lệ trích dẫn tồn tại và khớp nội dung, số tool calls, ngân sách, prompt-injection defenses.
- ZKML: prove time, verify time, proof size, verification gas, tỉ lệ reject trên test bị sửa.
- CoC: hash concordance, signature valid rate, event order, receipt verification, quyền/định danh, số lỗi bảo mật được chặn.
- Báo cáo tổng thể phải chứa `run_id`, commit, OS, Python, deps/versions, seed, input hashes, exit codes, PASS/FAIL/SKIP/ERROR, phương pháp và giới hạn; artifacts do script sinh.

### P11.3 — Chấp nhận công khai và an toàn

- Mặc định chạy offline + Anvil; không gọi Gemini Live/paid API, không dùng khóa riêng thật, không RPC mainnet/Sepolia để broadcast. Muốn live cần phê duyệt riêng, phương án bảo vệ khóa và giám sát dữ liệu.
- Rà soát quyền dùng Forta/MEW và PTXPhish; dữ liệu PTXPhish thuộc artifact nghiên cứu có điều kiện, **không** tự đóng gói để phân phối thương mại hoặc tải lên paid/cloud API.
- Không sửa NTFS ACL và không làm thất bại test bằng cách làm yếu cơ chế bảo mật; ghi rõ các test bị SKIP theo policy.

## 10. Ma trận kiểm thử và acceptance gates

**Giữ T01–T11 của AGENT v5.1** (Collector, RPC resilience, reorg, rules, verify layers, smart contract, guards, replay, ref checker, prompt injection). Không đổi/giảm assertion chỉ để đạt PASS. Bổ sung:

| Gate | Bài kiểm tra bắt buộc | Điều kiện đạt |
|---|---|---|
| T12 | Acquisition từ hai loại nguồn (EVM + log ngoài EVM) | Raw hash, manifest, UTC, consent, audit đầy đủ |
| T13 | AI First Responder trigger/policy gate | Không vượt tool whitelist/step budget; mọi ghi/thu thập có audit |
| T14 | ML inference reproducibility | Model/input hash cố định, kết quả tái tạo với pipeline/seed thích hợp |
| T15 | ML anti-leakage + dataset labels | Train/test tách đúng, không lấy rule làm ground truth giả |
| T16 | XAI fidelity/evidence | Explanation gắn đúng model/input và nguồn, lỗi lệch hash bị chặn |
| T17 | MITRE mapping | Có grounded mapping và trường hợp abstain rõ ràng |
| T18 | DID ↔ signer binding | Sai key/DID/role/replay bị từ chối, actor hợp lệ được ghi nhận |
| T19 | CoC end-to-end | Hash package/receipt/chain event khớp, 2 actor chuyển giao đúng |
| T20 | ZKML local positive proof | Prover + verifier thực PASS, lưu circuit/model/input/output digests |
| T21 | ZKML tampering | Đổi model/input/output/public signal/proof bytes → FAIL |
| T22 | ZKML local Anvil verify | Smart contract verify đúng/sai và log gas/tx hash synthetic |
| T23 | Full case replay D1/D2 | Báo cáo cuối nối được evidence → alert → analysis → custody/proof |
| T24 | Privacy/prompt injection/data tamper | Zero secrets/PII on chain; fail-closed; negative tests PASS |

**Trạng thái gate:** chỉ `PASS` khi lệnh thực thi, log, commit, artifact/hash được ghi lại. `DESIGN_ONLY`, `MOCK_ONLY`, `NOT_RUN`, `SKIP`, `PARTIAL`, `BLOCKED` không thể quy đổi thành `PASS`.

## 11. Lộ trình và điều kiện không được nhảy giai đoạn

| Phase | Công việc | Điều kiện hoàn thành |
|---|---|---|
| P1–P3 (legacy) | Collector, Evidence, Chain of Custody | Có kiểm thử/hồ sơ nghiệm thu hiện có; chạy lại hồi quy trên baseline trước phát triển mới |
| P4–P6 (legacy) | Rule, AI Investigator, benchmark nguồn mở | Đối chiếu baseline, xác định 70 SKIP và giới hạn tái lập; không viết lại thống kê |
| **P7** | AI First Responder + nguồn log ngoài EVM | T12–T13 PASS |
| **P8** | ML + XAI + ATT&CK | T14–T17 PASS |
| **P9** | ZKML proof + verifier | T20–T22 PASS, không mock |
| **P10** | DID + custody signatures | T18–T19 PASS |
| **P11** | End-to-end/security/evaluation | T23–T24 PASS, báo cáo methodology và giới hạn |

*Các số P7–P11 là tên nhóm công việc mở rộng của đặc tả này; không suy ra thời gian thực hiện hoặc cam kết hoàn thành nếu thiếu toolchain, thiết bị hoặc quyền sử dụng dữ liệu.*

### Tiêu chí nghiệm thu cuối Đề tài 8

- [ ] Demo thu thập đúng **hai nhóm nguồn**, tạo chứng cứ thô và acquisition manifest theo quy trình nhận diện/thu thập/sao lưu/bảo quản.
- [ ] Có AI workflow được giới hạn quyền, có sự kiện kích hoạt và xử lý một vụ việc từ đầu đến cuối.
- [ ] Có **mô hình ML thật** (không chỉ rules/LLM), train/infer/eval có provenance, báo cáo phương pháp.
- [ ] Có **XAI thực cho ML** và ánh xạ MITRE ATT&CK có chứng cứ/abstain.
- [ ] Có **Smart Contract CoC** liên kết hash, identity/DID, chữ ký/actor, timestamp và chuyển giao có thể xác minh.
- [ ] Có **ZKML proof thật** và verifier offline/on-chain Anvil, âm tính khi input/model/output/proof bị sửa.
- [ ] Không suy diễn AI đúng tuyệt đối, không bịa số liệu, giữ nguyên DB canonical và tính bảo mật khóa/PII.
- [ ] Có kiểm tra tích hợp D1/D2/D3, log/test/hash và tài liệu kiến trúc/giới hạn. Việc trình bày demo thuộc báo cáo học thuật, không thay thế quy trình chạy thật bằng Terminal.
- [ ] Giảng viên/người phụ trách xác nhận phạm vi triển khai bắt buộc của phần ZKML (mức thiết kế/PoC hay triển khai đầy đủ) trước khi tuyên bố đáp ứng toàn bộ yêu cầu học thuật.

## 12. Cấu trúc mã nguồn đề xuất (chỉ tạo khi thật sự triển khai)

```text
blockchain-forensics/
├── AGENT.md                         # Đặc tả phạm vi P1–P11 v6.1
├── README.md / .env.example         # Không kèm secrets
├── collector.py / forensics/        # Mã P1–P6 hiện có, KHÔNG di chuyển vô cớ
│   ├── adapters/                    # P6 threat intel hiện có
│   ├── rules/                       # R1–R4 hiện có
│   ├── ai/                          # P5, bổ sung policy + agent workflow
│   ├── acquisition/                 # [MỚI P7] sources, manifest, ISO27037 workflow
│   ├── ml/                          # [MỚI P8] features, train, infer, registry
│   ├── xai/                         # [MỚI P8] explainers, MITRE mapping, fidelity
│   ├── identity/                    # [MỚI P10] DID resolver, signature verifier
│   └── zkml/                        # [MỚI P9] codec, commitments, prove, verify
├── contracts/
│   ├── src/EvidenceRegistry.sol     # Giữ P3 hiện có
│   └── src/InferenceVerifier.sol    # [MỚI] nếu chứng minh được EVM verification
├── scripts/                         # CLI/repro/integration/benchmark
├── tests/                           # Legacy + T12–T24
├── models/                          # Model được version + SHA-256, không chứa PII
├── circuits/                        # Circuit & keys kiểm thử (không chứa bí mật thật)
├── docs/
│   ├── architecture.md
│   ├── requirements_traceability.md
│   ├── limitations.md
│   ├── threat_model.md
│   └── iso27037_mapping.md
├── results/                         # Sinh từ script, có run manifest
└── audit/                           # Hash/provenance/acceptance logs
```

Không làm sai import tương đối, không đổi module path trên repo thật chỉ để cây đẹp. Thư mục `[MỚI]` ở trên là **đề xuất**, chưa được chứng thực có trong repository.

## 13. Báo cáo định kỳ Coding Agent và quy tắc kiểm toán

**Trước mỗi milestone:**

1. Đọc AGENT.md v6.1 và code/tests/report của milestone; chụp `git status`, HEAD, hash dữ liệu gốc, danh sách artifact bảo vệ.
2. Viết kế hoạch nhỏ, tiêu chí gate, rủi ro, đường dẫn thay đổi. Không chạy lệnh ghi vào master hoặc DB chứng cứ canonical.
3. Chỉ thay đổi trong branch/worktree cách ly; kiểm tra quyền, license và tài nguyên có sẵn. Cài dependencies hoặc dùng dịch vụ ngoài cần có phê duyệt rõ ràng.
4. Chạy kiểm thử có bằng chứng **trước/sau** (output thô, exit code, pytest junit, Foundry log, model/proof hashes), phân biệt `PASS`, `FAIL`, `ERROR`, `SKIP`, `NOT_RUN`.
5. So sánh nguồn và DB bảo vệ SHA-256; ghi chênh lệch nếu có, **không tự sửa hash tham chiếu**.
6. Cập nhật `PROJECT_HANDOFF.md` và `reports/Px_ACCEPTANCE.md` bằng số liệu thật, tóm tắt next action.

**Mẫu báo cáo ngắn (không thay thế log):**

```text
[PHASE] [REPOSITORY] [BRANCH] [HEAD]
[SCOPE_DONE] [SCOPE_NOT_DONE] [FILE_CHANGES]
[DATA_PROVENANCE] [CODE_HASHES] [PROTECTED_DB_HASHES]
[TESTS_PASS] [TESTS_FAIL] [TESTS_ERROR] [TESTS_SKIP] [TESTS_NOT_RUN]
[SECURITY_CHECKS] [KNOWN_LIMITATIONS] [ARTIFACT_PATHS]
[REVIEW_REQUIRED] [NEXT_STEP]
```

## 14. An toàn vận hành và giới hạn pháp chứng

- Không tự động tấn công/khai thác/chiếm quyền, không giám sát thiết bị không có sự đồng ý. Mọi host log, memory artifact, IoT sample phải do chủ sở hữu cung cấp/cho phép.
- Không phát giao dịch lên blockchain công khai khi chưa có phê duyệt tường minh. Không cung cấp API key/seed/private key cho LLM, Git, log hoặc zip; dùng keystore thử nghiệm nếu cần trên Anvil.
- Không chạy shell tùy ý, SQL tùy ý, bỏ qua xác thực chữ ký, giảm quyền/đổi NTFS ACL, xóa lịch sử hoặc thay kết quả để xanh test.
- Không gọi Gemini Live/paid API khi chế độ offline, không upload dữ liệu nghiên cứu có giới hạn phân phối.
- Các khái niệm “bằng chứng có giá trị trước tòa”, “tuân thủ GDPR”, “XAI giải thích hoàn toàn”, “ZKML chứng minh AI đúng” đều cần giới hạn và không được tuyên bố tuyệt đối.
- Vấn đề bảo toàn **dữ liệu** khác bảo toàn **suy luận**: P3/manifest giải quyết chứng cứ, P9 proof giải quyết đúng phép tính với mạch/model đã cam kết; cả hai không thay thế xác minh provenance từ nguồn.

## 15. Tài liệu nguồn và điều cần xác nhận với thầy

1. **Tài liệu người dùng tải lên:** `sv Ứng dụng blockchain trong ATTT Hướng Dẫn Các chủ đề các nhóm K18 ATTT.docx`, Đề tài 8, trang 10–12: *AI Agents & XAI / MITRE ATT&CK*; *Smart Contract Chain of Custody / DID & chữ ký*; *ZKML proof of inference*.
2. **Đặc tả tiền nhiệm:** `agent(3).md` (AGENT v5.1) và AGENT v6.0. Đây là nền chi tiết P1–P6 và các mở rộng P7–P11; bản v6.1 giữ nguyên yêu cầu bảo toàn dữ liệu, kiểm thử hồi quy, AI/XAI, DID/CoC và ZKML, và chuyển hướng triển khai sang Terminal, không yêu cầu phát hành portable Windows.
3. **Hồ sơ nghiệm thu do người dùng cung cấp:** `P6_05_ACCEPTANCE.md`, `P6_HANDOFF.md`, báo cáo P3/P4/P5. Dữ liệu/commit/test trong các báo cáo là **thông tin được báo cáo**, chưa thể thay kết quả chạy lại repository thực tế.
4. **Cần xác nhận học thuật:** Mức bắt buộc **ZKML** (thực thi on-chain hoặc prototype); mức bắt buộc DL/GNN so với ML baseline; mức tích hợp dữ liệu ngoài EVM; tiêu chuẩn bảo quản chứng cứ cần chứng minh trong demo. Trước khi có phản hồi, thực hiện theo các gate của tài liệu này, nhưng không tuyên bố đó là những điều kiện thầy đã ký xác nhận.

---

**Nguyên tắc cuối:** Đúng đề tài không chỉ là có chữ “Blockchain” và “AI”. Bản nghiệm thu phải chứng minh được **thu thập chứng cứ → phân tích ML/XAI có căn cứ → chuỗi hành trình bất biến → kiểm chứng suy luận ZKML**, với code, log, dữ liệu và giới hạn rõ ràng. **Không hy sinh những phần P1–P6 đã làm để tạo một dự án mới giả dạng hoàn thiện.**
