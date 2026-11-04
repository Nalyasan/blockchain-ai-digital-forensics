# P5 ACCEPTANCE REPORT — PYDANTIC AI + GOOGLE GEMINI FLASH INVESTIGATOR

**Project**: Blockchain + AI Digital Forensics  
**Phase**: P5 — AI Investigator (Pydantic AI + Google Gemini Flash)  
**Branch**: `feature/p5-pydantic-gemini`  
**Isolated Worktree**: `D:\Projest\worktrees\p5_pydantic_gemini`  
**Accepted P1–P4 Baseline Commit**: `9bed49a7e83a37790013c3e328ae0a41e091bfa1`  
**P4-08 Real-Data Integration Reference**: `feat/p4-real-integration` (`e38dff61a6f99985148b927d1ff2c6fddf438650`)  
**Overall P5 Status**: **PASS (Offline Deterministic, Security T10/T11 & Real-Data CLI Verified; Live Gemini API Smoke Test PENDING API Key)**

---

## 1. Executive Summary & Architectural Guarantees

P5 implements a production-grade, strictly bounded **AI Forensic Investigator** built on **Pydantic AI** (`pydantic-ai==2.64.0`, `pydantic-ai-slim==2.64.0`, `pydantic==2.14.2`, `google-genai==2.34.0`) and **Google Gemini Flash** (`GoogleModel` / `GoogleProvider`, default `gemini-3.8-flash` with fallback verification).

### Key Forensic & Security Guarantees Enforced
1. **Strict Evidence Immutability (5-Layer Read-Only SQLite)**:
   - All five query tools (`get_alerts`, `get_tx`, `get_address_history`, `get_counterparties`, `get_timeline`) and the independent Reference Checker (`ref_checker.py`) connect exclusively via `forensics/ai/db_readonly.py`.
   - Enforces:
     1. Pre-existence validation (`FileNotFoundError` / `sqlite3.OperationalError` before connection).
     2. URI `file:<posix_path>?mode=ro&immutable=1`.
     3. `PRAGMA query_only = ON`.
     4. SQLite C-level authorizer callback (`readonly_authorizer`) denying all write, DDL, transaction, `ATTACH`, `DETACH`, and `VACUUM` opcodes.
     5. Guarded `ReadOnlyConnection` and `ReadOnlyCursor` wrappers blocking mutating SQL patterns before parser execution.
2. **Exactly Six Authorized Tools & Bounded Execution Budget**:
   - Explicitly whitelisted in `AUTHORIZED_TOOLS`:
     - `get_alerts` (read-only)
     - `get_tx` (read-only)
     - `get_address_history` (read-only)
     - `get_counterparties` (read-only)
     - `get_timeline` (read-only)
     - `collect_missing_range` (isolated staging collector only)
   - Enforces `MAX_AI_TOOL_STEPS = 5` attempted calls per session (`ToolBudgetExceeded`) and `AI_REQUEST_LIMIT = 8` via Pydantic AI `UsageLimits`.
   - `budget_exhausted` is `False` when an investigation completes within the 5-step ceiling, and `True` only when a 6th tool call is attempted and rejected by `ToolBudgetExceeded` or `UsageLimitExceeded`.
   - `collect_missing_range` is strictly limited to `<= 20` inclusive blocks (`RangeLimitExceeded` on 21+ blocks), max 2 calls per session, and explicitly blocked from writing to canonical/production evidence databases (`ProductionDatabaseMutationError`).
3. **Distinction Between Synthetic `TestModel` and Deterministic Offline Forensic `FunctionModel`**:
   - **Synthetic `TestModel` (`create_test_model`)**: Used strictly in unit tests that pass explicit `custom_output_args` or custom `call_tools` sequences (e.g., testing 6-call budget overflow or intentional `+1 wei` hallucination rejection).
   - **Deterministic Offline Forensic Model (`create_offline_forensic_model`)**: Powered by Pydantic AI `FunctionModel`. Used automatically when `--provider test`, `--provider offline`, or default offline fallback is invoked without synthetic mock overrides. Executes a real multi-turn tool workflow (`get_alerts` -> `get_timeline` -> `get_address_history` -> `get_tx` -> `get_counterparties`) within the 5-step budget against the SQLite evidence database and synthesizes verified `ObservedFact`, `RuleDetection`, and `chronological_timeline` records grounded directly in canonical SQLite rows.
   - **Case ID Preservation**: `ForensicInvestigator.investigate` enforces that `output.case_id` always preserves the requested `case_id`.
4. **T11 Prompt Injection Isolation (`forensics/ai/sanitizer.py`)**:
   - Truncates untrusted on-chain strings (`calldata`, revert reasons, ERC-20 symbols, memo strings) to 256 characters, strips control/bidi characters, wraps untrusted strings in `<untrusted_onchain_data>...</untrusted_onchain_data>` tags, and flags injection payloads without deleting underlying transaction evidence.
5. **T10 Independent Reference Checker (`forensics/ai/ref_checker.py`) & Zero-Fact `NOT_EVALUATED` Enforcement**:
   - Deterministic, non-AI Python/SQLite verifier inspecting every `ObservedFact` against canonical `asset_transfers`, `transactions`, and `alerts` (`alerts.evidence_refs`).
   - **Zero-Fact Protection**: When `len(observed_facts) == 0`, the Reference Checker returns `status = "NOT_EVALUATED"`, `is_valid = False`, `content_match_ratio = 0.0`, and `existence_ref_ratio = 0.0` (never reporting a vacuous `1.0` / `PASS`). Under `--strict-ref-check` (`strict_ref_checker=True`), both `CONTENT_MISMATCH` and `NOT_EVALUATED` raise `ContentMismatchError` and cause the CLI to exit non-zero (`1`).
6. **G5-02 Append-Only / Idempotent Persistence Compliance**:
   - Zero occurrences of `INSERT OR REPLACE`, `REPLACE INTO`, or `INSERT OR IGNORE` across all `forensics/**/*.py` modules.

---

## 2. Installed Environment & Dependency Versions

| Package | Installed Version | Purpose |
| :--- | :--- | :--- |
| `Python` | `3.13.14` | Runtime environment |
| `pydantic-ai` | `2.64.0` | Agent orchestration, `FunctionModel`, `TestModel`, `UsageLimits` |
| `pydantic-ai-slim` | `2.64.0` | Core Pydantic AI Google/Gemini model bindings |
| `pydantic` | `2.14.2` | Strict structured forensic output validation |
| `google-genai` | `2.34.0` | Official Google Gemini SDK backend |

---

## 3. Independent Verification of P4-08 Real-Data Database & Schema

Before running P5 investigations, `D:\Projest\worktrees\p4_real_integration\data\real_p4.db` (from branch `feat/p4-real-integration`, commit `e38dff61a6f99985148b927d1ff2c6fddf438650`) was independently verified via read-only connection:

- **Database Path**: `D:\Projest\worktrees\p4_real_integration\data\real_p4.db`
- **SHA-256 Checksum (Before & After All Tests)**: `6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97`
- **Verified Schema & Canonical Row Counts**:
  - `asset_transfers`: **7,032** (`6,520` in Euler block window `16816001..16818110`; `512` in Curve block window `17700536..17851003`)
  - `alerts`: **172**
  - `transactions`: **18**
  - `blocks`: **1,789**
  - `rule_calibrations`: **224**
  - **Evidence References**: **498** embedded JSON objects inside `alerts.evidence_refs` (there is no separate `evidence_references` table).
  - **Canonical Rule IDs in `alerts`**:
    - `large_transfer`: **82** alerts
    - `rapid_pass_through`: **71** alerts
    - `high_frequency`: **11** alerts
    - `fan_in_out`: **8** alerts

---

## 4. Mandatory Real-Data CLI Acceptance Verification (Euler & Curve)

Isolated, byte-identical copies of `real_p4.db` (`SHA-256: 6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97`) were created and tested via the actual CLI entry point `python -m forensics.cli investigate`.

### Case A — Euler Finance Incident
- **Actual Command**:
  ```powershell
  python -m forensics.cli investigate `
    --case-id "euler-finance" `
    --db "D:\Projest\worktrees\p5_pydantic_gemini\results\p5\euler_real_p4_copy.db" `
    --query "Investigate Euler Finance Ethereum exploit and address 0xb66cd966670d962c227b3eaba30a872dbfb995db. Retrieve on-chain evidence and verify observed facts." `
    --provider test `
    --max-steps 5 `
    --strict-ref-check `
    --out "D:\Projest\worktrees\p5_pydantic_gemini\results\p5\euler_investigation.json"
  ```
- **Exit Code**: `0`
- **Requested / Returned `case_id`**: `"euler-finance"` / `"euler-finance"`
- **Count of `observed_facts`**: `10` (including transfer `6367` of `34186225919500945938720264` DAI to `0xb66cd966670d962c227b3eaba30a872dbfb995db` in block `16818102` tx `0x298bde3f9e53f7a5d870f7f5d56ee2f5e41fa25e6eb5e74611ac97025405db55` and 9 DAI transfers in block `16817996` tx `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`)
- **Count of `rule_detections`**: `15` (including alert `db6f40776586b5e33158c6d0ffe5a38a91ebc0e83d0fd4f74f22619267b3f408` for `0xb66cd966670d962c227b3eaba30a872dbfb995db` and alert `1ba703a159d38ebf21b5c6d4123c7e5d3d8e75e000b3990dd41f983094b96b38` for `0xc310a0af...`)
- **Count of Referenced Canonical Transactions**: `13`
- **Reference-Check Status & Checked-Fact Count**: `status = "PASS"`, `checked_facts_count = 10`, `content_match_ratio = 1.0`, `existence_ref_ratio = 1.0`, `has_content_mismatch = false`
- **Attempted Tool Calls & Budget Status**: `attempted_steps = 5`, `successful_steps = 5`, `failed_steps = 0`, `budget_exhausted = false`
- **Output File Path**: `D:\Projest\worktrees\p5_pydantic_gemini\results\p5\euler_investigation.json`
- **SHA-256 of Original `real_p4.db` (Before & After)**: `6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97`

### Case B — Curve / Alchemix Incident
- **Actual Command**:
  ```powershell
  python -m forensics.cli investigate `
    --case-id "curve-alchemix" `
    --db "D:\Projest\worktrees\p5_pydantic_gemini\results\p5\curve_real_p4_copy.db" `
    --query "Investigate Curve Alchemix Vyper reentrancy exploit and address 0xdce5d6b41c32f578f875efffc0d422c57a75d7d8. Retrieve on-chain evidence and verify observed facts." `
    --provider test `
    --max-steps 5 `
    --strict-ref-check `
    --out "D:\Projest\worktrees\p5_pydantic_gemini\results\p5\curve_investigation.json"
  ```
- **Exit Code**: `0`
- **Requested / Returned `case_id`**: `"curve-alchemix"` / `"curve-alchemix"`
- **Count of `observed_facts`**: `10` (including transfer `7029` of `7258701569350004501158` wei `NATIVE` ETH from `0x30fb95794a2051abe30a67892b3a1fa73947aee5` to `0xdce5d6b41c32f578f875efffc0d422c57a75d7d8` in block `17806772` tx `0xb676d789bb8b66a08105c844a49c2bcffb400e5c1cfabd4bc30cca4bff3c9801`)
- **Count of `rule_detections`**: `15` (including alert `e6bbfab35ec6327ef77bcdd812b4722700cdf6372672da5837bf0ef0e9438729`)
- **Count of Referenced Canonical Transactions**: `20`
- **Reference-Check Status & Checked-Fact Count**: `status = "PASS"`, `checked_facts_count = 10`, `content_match_ratio = 1.0`, `existence_ref_ratio = 1.0`, `has_content_mismatch = false`
- **Attempted Tool Calls & Budget Status**: `attempted_steps = 5`, `successful_steps = 5`, `failed_steps = 0`, `budget_exhausted = false`
- **Output File Path**: `D:\Projest\worktrees\p5_pydantic_gemini\results\p5\curve_investigation.json`
- **SHA-256 of Original `real_p4.db` (Before & After)**: `6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97`

---

## 5. Test Execution Summary & Commands

### 5.1 P5 AI Investigator Test Suites (10 Suites)
```powershell
python -m pytest tests/test_ai_db_readonly.py tests/test_ai_db_readonly_adversarial.py tests/test_adversarial_db_concurrency.py tests/test_ai_provider.py tests/test_ai_tools.py tests/test_ai_tools_adversarial.py tests/test_adversarial_m2.py tests/test_ai_security.py tests/test_ai_investigator.py tests/test_p5_real_incidents.py -v --basetemp="D:\Projest\worktrees\.pytest_tmp_p5"
```
- **Exit Code**: `0`
- **Results**: **329 passed, 1 skipped** (live Gemini API smoke test skipped when `GOOGLE_API_KEY` / `GEMINI_API_KEY` is unset).

### 5.2 Foundry Smart Contract Regression Suite
```powershell
Set-Location "D:\Projest\worktrees\p5_pydantic_gemini\contracts"
forge test -v
```
- **Exit Code**: `0`
- **Results**: **56 passed, 0 failed, 0 skipped**.

### 5.3 Full Repository Python Regression Suite (`pytest tests/`)
```powershell
$env:Path = "$env:USERPROFILE\.foundry\bin;$env:Path"
Set-Location "D:\Projest\worktrees\p5_pydantic_gemini"
python -m pytest tests/ -q --basetemp="D:\Projest\worktrees\.pytest_tmp_p5"
```
- **Exit Code**: `0`
- **Results**: **941 passed, 1 skipped, 0 failed**.

---

## 6. Live Gemini Provider Status

- **Status**: **PENDING (No API key configured in current execution environment)**
- **Details**: `GOOGLE_API_KEY` and `GEMINI_API_KEY` are unset in the environment. Per strict P5 instructions, no paid billing or unauthorized external calls were attempted, and `TestLiveGeminiSmokeConditional::test_live_gemini_flash_smoke` is recorded as `SKIPPED` / `PENDING` until an API key is supplied.
