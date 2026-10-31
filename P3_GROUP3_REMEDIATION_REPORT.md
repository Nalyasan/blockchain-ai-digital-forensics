# Phase 3 Group 3 — Controlled Remediation Report

**Date:** 2026-10-31  
**Lead Software Engineer & Orchestrator:** Antigravity  
**Repository:** `D:\Projest\Blockchain`  
**Baseline P3:** `713ad068348cab75046e10d52332f0d850ef93f5`  
**Candidate Audited:** `67bba6866a59f5c7549893eb68a8c06b5bade553`  
**Governing Standard:** `P3_GROUP3_PLAN_v2.md`  
**Final Status:** **ALL 17 ACCEPTANCE GATES PASS (17/17 — 100%)**

---

## 1. Executive Summary

Following independent gate reconciliation in `P3_GROUP3_FINAL_EVIDENCE_REVIEW.md`, 13 gates were confirmed **PASS** and 4 gates were classified **PARTIAL**:
- **G3-05 (Note Hash):** `note_hash_bytes32()` invoked `strip()`, stripping leading/trailing whitespace instead of hashing verbatim UTF-8 bytes.
- **G3-07 (Legacy Downgrade):** `forensics/onchain.py` contained an automatic silent downgrade to legacy verification without requiring explicit `--legacy-case-encoding`, returning reason `OK` instead of `LEGACY_PUBLIC_CASE_ID`.
- **G3-11 (SQLite Migration):** Test fixture only tested a clean 1-row database; lacked coverage for duplicate legacy events (NULL `log_index`), legacy text notes, pre-verified rows, logical snapshot comparisons, rollback simulation, and rerun idempotency.
- **G3-14 (Export No-Clobber):** `forensics/exporter.py` hardcoded the legacy storage URI `evidence://{case_id}/manifest.json` instead of the canonical `evidence://sha256/<case_digest>/<manifest_hash>/manifest.json`; lacked explicit test for collision no-clobber.

In addition, an in-depth security and concurrency audit of candidate `67bba6866a59f5c7549893eb68a8c06b5bade553` identified and remediated critical risk areas:
- **G3-03 / G3-04 (Verification Bypass Elimination):** `persist_verified_event()` allowed callers to pass self-declared `block_number`, `topic0`, and `receipt_status` when `receipt` was omitted. This bypass was eliminated: authentic transaction receipts are strictly required, and full cross-validation against contract address, actor address, tx_hash, block number, and event topic is strictly enforced.
- **G3-16 (Real Send Concurrency on Anvil):** Real dual-process contention using OS-level `multiprocessing` (spawn) on an actual SQLite disk database with real local Anvil RPC broadcasting: exactly one process wins `can_send=True` and executes a real transaction (nonce +1, mined receipt), while the losing process (`can_send=False`) sends 0 transactions.
- **G3-17 (Real Hard-Kill Crash Recovery):** Real child OS process hard-killed (`process.kill()`) at the failpoint immediately after `COMMIT SEND_STARTED`. Upon restart, resend is strictly denied (`can_send=False`), and reconciliation performs read-only checks without broadcasting any transactions (nonce unchanged).

A surgical, controlled remediation was executed addressing these areas while preserving all existing passing controls. Full acceptance test suites were re-executed on the final source tree:

| Metric | Result | Status |
| :--- | :--- | :--- |
| **Acceptance Gates (Plan v2)** | **17 / 17 Gates PASS** | **100% PASS** |
| **Pytest Full Suite** | **521 / 521 Tests PASS** (0 failed, 0 skipped) | **PASS** |
| **Foundry Contract Suite** | **31 / 31 Tests PASS** (0 failed, 18.02ms) | **PASS** |
| **Anvil Group 3 Smoke Suite** | **10 / 10 Real Checks PASS** (exit code 0) | **PASS** |
| **Anvil Group 1b Smoke Suite** | **55 / 55 Checks PASS** (exit code 0) | **PASS** |
| **Anvil Group 2b Smoke Suite** | **9 / 9 Checks PASS** (exit code 0) | **PASS** |
| **Canary & Secret Leakage Scan** | **0 Leaks Found** across all tables, logs, sidecars | **PASS** |

---

## 2. Root Cause Analysis & Remediation Details

### 2.1 Gate G3-05 — Note SHA-256 Hashing & No File Probing

- **Deficiency Identified:** `forensics/evidence_identity.py:note_hash_bytes32()` conflated input validation with hash payload computation by doing `clean_note = note.strip()` and returning `0x + sha256_utf8(clean_note)`. Furthermore, `forensics/onchain.py:568` called `note_hash_bytes32(clean_note)`. This stripped leading and trailing whitespace contrary to Plan v2 §3.1 ("kể cả khoảng trắng đầu/cuối nếu note không rỗng").
- **Remediation Applied:**
  1. **Strict Input Validation vs. Hash Separation:**
     ```python
     if not isinstance(note, str):
         raise ValueError("Invalid note: must be a string")
     if not note.strip():
         raise ValueError("Invalid note: cannot be empty or whitespace-only")
     return "0x" + sha256_utf8(note)
     ```
  2. **Caller Alignment in `forensics/onchain.py`:** Line 565 preserves original `note` verbatim: `note_b32 = note_hash_bytes32(note)`.
  3. **In-Memory Guarantee:** Strictly zero filesystem calls (`os.path.exists`, `os.stat`, `open`, `Path.exists`, `Path.stat` patched to forbidden).
  4. **Comprehensive Test Suite in `tests/test_evidence_identity.py`:**
     - `test_note_hash_whitespace_verbatim_preservation`: Asserts `hash_base != hash_padded` and confirms both match exact `sha256(raw_bytes)`.
     - `test_note_hash_unicode_multibyte`: Accented Vietnamese, Japanese kanji/kana, unicode emojis (`🔒📦`), mathematical symbols.
     - `test_note_hash_long_content`: Lengths 512, 1024, 2048, and 8192 characters.
     - `test_note_hash_same_prefix_different_suffix`: Confirms distinct hashes for identical prefixes with varying suffixes or whitespace.
     - `test_note_hash_zero_leakage_in_exceptions`: Confirms raw note content is never echoed in exception messages or logs.

---

### 2.2 Gate G3-07 — Legacy Read-Only Verification Compatibility & Anti-Downgrade

- **Deficiency Identified:** In `forensics/onchain.py:762-764`, `verify_onchain_evidence` silently downgraded verification to legacy mode if onchain `state['case']` matched the unhashed string, returning reason `OK`. In addition, `check_registered_state` and `extract_evidence_id_from_receipt` allowed legacy fallbacks even when `legacy_case_encoding=False`.
- **Remediation Applied:**
  1. **Removed Silent Downgrade:** Lines 762-764 removed completely. Default verification strictly checks the canonical privacy profile (SHA-256 case ID digest and canonical storage URI).
  2. **Explicit Flag Enforcement:** Historical evidence anchored prior to Group 3 can only be verified when `legacy_case_encoding=True` (CLI flag `--legacy-case-encoding`) is explicitly passed by the operator.
  3. **Distinct Reason Code:** Legacy verification returns `OnchainVerification(status='MATCH', reason_code='LEGACY_PUBLIC_CASE_ID', details=details)` (exit code 0), distinguishing it from canonical verification which returns `reason_code='OK'`.
  4. **Anti-Mixed-Profile Enforcement:**
     - In `check_registered_state()`: Enforces exact matching for `state['case'] == case_hash` and `state['uri'] == uri`. Mixed profiles (e.g. legacy case + canonical URI or canonical case + legacy URI) strictly fail with `REGISTRY_MISMATCH`.
     - In `extract_evidence_id_from_receipt()`: Enforces `topics[2] == can_topic` and `uri == can_uri` when `legacy_case_encoding=False`; enforces `topics[2] == leg_topic` and `uri == leg_uri` when `legacy_case_encoding=True`.
  5. **Write Mode Immutability:** Write operations (`anchor_evidence`, `record_custody_action`) have no legacy flag and strictly prohibit creating plaintext/unhashed records on-chain.
  6. **Unit Tests Added:**
     - `test_check_registered_state_no_silent_downgrade`: Legacy state fails with `REGISTRY_MISMATCH` under canonical parameters.
     - `test_mixed_profile_strictly_rejected`: Both permutations of mixed profiles raise `REGISTRY_MISMATCH`.
     - `test_extract_evidence_id_no_silent_downgrade`: Legacy receipt fails without explicit flag; canonical receipt fails with legacy flag.

---

### 2.3 Gate G3-11 — SQLite Additive Migration Integrity & Pre-Send Fail-Fast

- **Deficiency Identified:** Previous tests only validated migration on a single pre-existing row; lacked tests for legacy duplicate `tx_hash` rows (NULL `log_index`), legacy raw text notes, pre-verified rows, logical snapshot hashing, rollback error simulation, and rerun idempotency.
- **Remediation Applied:**
  1. **Realistic Legacy Database Testing (`test_migration_with_duplicate_and_text_note_legacy_rows`):**
     - Populated legacy database containing duplicate `tx_hash` events from the same transaction (which in legacy schema lacked `log_index`).
     - Included raw text notes without hex formatting, `verified=0` rows, and `verified=1` rows.
     - Pre-migration logical snapshot captured across all tables (`blocks`, `transactions`, `evidence_exports`, `custody_events`) and hashed with SHA-256.
     - Migration executed: `migrate_group3(conn)`.
     - Confirmed 100% byte-for-byte data preservation for all historical columns.
     - Confirmed new columns (`log_index`, `event_type`) remain NULL on legacy rows (zero backfilling).
     - Confirmed `idx_custody_event_identity` permits multiple historical NULL `log_index` rows while strictly preventing duplicate non-NULL `log_index` tuples.
     - Confirmed `PRAGMA integrity_check == ok` and `PRAGMA foreign_key_check == []`.
  2. **Rollback & Rerun Resilience (`test_migration_rollback_error_simulation_and_rerun_resilience`):**
     - Simulated failure during migration transaction.
     - Verified transaction rollback restored original schema safely without database corruption.
     - Re-ran `migrate_group3(conn)` successfully to completion.
     - Verified re-running `migrate_group3(conn)` a second time is fully idempotent.
  3. **WAL Mode Compatibility (`test_wal_journal_mode_and_safe_fixture_isolation`):**
     - Verified additive migration succeeds under WAL journal mode (`PRAGMA journal_mode=WAL`).
     - Verified all migration tests operate strictly within isolated temporary directories (`tmp_path`) with zero modifications to production `data/forensics.db`.

---

### 2.4 Gate G3-14 — Export No-Clobber, Canonical URI & Retention on DB Failure

- **Deficiency Identified:** `forensics/exporter.py:274` hardcoded the legacy storage URI `evidence://{case_id}/manifest.json` into `evidence_exports` instead of canonical `evidence://sha256/<case_digest>/<manifest_hash>/manifest.json`. Lacked collision no-clobber and dual-manifest URI distinction unit tests.
- **Remediation Applied:**
  1. **Synchronized Canonical Storage URI in Exporter:**
     ```python
     from forensics.evidence_identity import case_id_digest, canonical_storage_uri
     ...
     case_dig = case_id_digest(case_id)
     storage_uri = canonical_storage_uri(case_dig, manifest_hash)
     with contextlib.closing(init_db(str(db_file))) as conn:
         with conn:
             conn.execute(
                 'INSERT INTO evidence_exports(export_id,case_id,manifest_path,manifest_sha256,storage_uri,created_at,operator,onchain_evidence_id) '
                 'VALUES(?,?,?,?,?,?,?,NULL)',
                 (export_id, case_id, 'manifest.json', manifest_hash, storage_uri, m['exported_at'], m['operator'])
             )
     ```
  2. **Zero Self-Referential Cycle:** The canonical storage URI is recorded strictly in database metadata (`evidence_exports`), outside `manifest.json`. The manifest hash is derived strictly from the exact manifest file bytes on disk.
  3. **Zero Case ID Leakage:** Raw `case_id` never appears in the public storage URI.
  4. **Comprehensive Test Suite in `tests/test_onchain_store.py`:**
     - `test_export_evidence_creates_canonical_storage_uri_in_db`: Asserts `storage_uri` matches `evidence://sha256/<case_digest>/<manifest_hash>/manifest.json` (exact 161 chars) and does not leak raw case ID.
     - `test_export_evidence_collision_no_clobber`: Asserts that exporting to an existing target directory raises `FileExistsError("DESTINATION_EXISTS")` and preserves all existing files untouched.
     - `test_export_evidence_two_manifests_distinct_canonical_uris`: Asserts that exporting two distinct packages for the same case ID generates distinct manifest hashes and distinct canonical storage URIs in `evidence_exports`.
     - `test_export_evidence_db_failure_retains_published_package`: Asserts that if the database write fails post-publish, `RuntimeError("EXPORT_IO_OR_DB_ERROR: published package, if present, is retained")` is raised and the published package on disk remains completely valid and intact.

---

### 2.5 Gate G3-03 / G3-04 — Receipt Bypass Elimination & Multi-Coordinate Cross-Validation

- **Deficiency Identified:** In `forensics/onchain_store.py:persist_verified_event()`, if the caller omitted `receipt`, an `else:` branch permitted callers to supply unverified `receipt_status=1`, `block_number`, and `topic0`. Furthermore, `onchain_ops.py` maintained a duplicate version of `persist_verified_event` with weak validation.
- **Remediation Applied:**
  1. **Strict Receipt Requirement:** Removed the bypass branch completely. If `receipt` is `None` or not a dictionary, `persist_verified_event()` immediately raises `RuntimeError("VERIFICATION_FAILED: valid transaction receipt is strictly required")`.
  2. **Multi-Coordinate Cross-Validation in `verify_receipt_and_event`:**
     - Enforces `receipt["status"] == 1`.
     - Enforces presence and validity of `blockNumber`.
     - Enforces transaction hash identity (`receipt["transactionHash"] == tx_hash`).
     - Enforces contract address identity (`receipt["to"] == contract_address`).
     - Enforces actor address normalized match (Solidity 32-byte topic normalized with `.removeprefix("0x")[-40:].zfill(40)`).
     - Enforces event topic matching against canonical keccak256 topics for `EvidenceRegistered` or `CustodyRecorded`.
     - Validates payload coordinates (`evidence_id`, `manifest_sha256`, `case_digest`, `action`, `note_hash`).
  3. **Unified Operation Delegate:** Refactored `forensics/onchain_ops.py:persist_verified_event` to delegate directly to `forensics/onchain_store.py:persist_verified_event`, preventing divergent code paths.
  4. **Targeted Regression Tests in `tests/test_onchain_store.py`:**
     - `test_persist_verified_event_strictly_requires_receipt_dictionary`
     - `test_persist_verified_event_rejects_self_declared_receipt_bypass`
     - `test_persist_verified_event_rejects_contract_mismatch`
     - `test_persist_verified_event_rejects_tx_hash_mismatch`
     - `test_persist_verified_event_rejects_actor_mismatch`

---

### 2.6 Gate G3-16 & G3-17 — Real Multiprocessing Concurrency with Real Anvil Broadcast & Hard Kill Recovery

- **Deficiency Identified:** Previous concurrency and crash tests relied on simulated in-process barriers or state inspection without proving real OS process contention and real transaction broadcast behavior on a live EVM node.
- **Remediation Applied:**
  1. **Real Dual-Process Anvil Send Concurrency (`test_real_dual_process_concurrency_with_real_anvil_send`):**
     - Launched a real unforked loopback Anvil instance (chain 31337) and deployed `EvidenceRegistry.sol`.
     - Spawned two real OS processes (`multiprocessing.get_context("spawn")`) sharing a real SQLite disk database file.
     - Synchronized processes using `multiprocessing.Barrier(2)` right before calling `claim_send()`.
     - Atomic `BEGIN IMMEDIATE` + conditional state update ensured exactly one process acquired `can_send=True` (`winner_sends=1`), while the loser process was denied (`can_send=False`, `loser_sends=0`).
     - Winner process broadcast a real transaction to Anvil. Asserted that Anvil account nonce incremented by exactly 1, transaction was mined in a block, and receipt status was 1.
  2. **Real Hard-Kill Process Crash Recovery (`test_real_child_process_kill_after_send_started_and_restart_reconcile`):**
     - Spawned a child OS worker that executed `claim_send()`, transitioned operation to `SEND_STARTED`, and committed to disk.
     - Worker signaled parent via an IPC queue at the failpoint before any RPC broadcast and was immediately hard-killed via `child.kill()`.
     - Verified child terminated abnormally (`exitcode != 0`).
     - Restarted runner process attempted `claim_send()` with the same operation ID: strictly refused with `can_send=False`.
     - Runner executed `reconcile_operation()`: performed read-only checks, verified transaction was never broadcast, updated state to `UNKNOWN`.
     - Asserted that zero transactions were submitted to Anvil throughout the entire crash and recovery lifecycle (Anvil nonce strictly unchanged).

---

## 3. Complete 17-Gate Acceptance Matrix

| Gate ID | Original Requirement (Plan v2) | Test IDs | Status | Evidence Path |
| :--- | :--- | :--- | :---: | :--- |
| **G3-01** | Multi-Manifest Same Case Linkage | `test_onchain_store.py::TestGate3_01_*` (3 tests) + Smoke | **PASS** | `forensics/schemas.py:35-43`, composite PK `(chain_id, contract_address, manifest_sha256)` |
| **G3-02** | Custody Event Identity & Collision | `test_onchain_store.py::TestGate3_02_*` (3 tests) | **PASS** | `forensics/schemas.py:53-56`, unique index `(chain_id, contract_address, tx_hash, log_index)` |
| **G3-03** | Strict Verification Before verified=1 | `test_onchain_store.py::TestGate3_04_*` (10 tests), `TestGate3_03_*` (2 tests), `TestGate3_14_*` (2 tests) | **PASS** | `forensics/onchain_store.py:257-370`, authentic receipt strictly required, multi-coordinate cross-validation, zero INSERT OR REPLACE |
| **G3-04** | Fail-Fast DB Checks Before Send | `test_onchain_store.py::TestGate3_11_*` (3 tests), `TestGate3_14::test_package_retention_*`, `test_onchain_group3.py::TestRecoverySidecar` (2 tests) | **PASS** | `forensics/onchain_store.py:177-224`, `pre_send_db_check` refuses missing/read-only/unmigrated DB |
| **G3-05** | Note SHA-256 & No File Probing | `test_evidence_identity.py::TestGate3_05_*` (9 tests) | **PASS** | `forensics/evidence_identity.py:85-110`, verbatim UTF-8 bytes hashed; non-empty validation; in-memory |
| **G3-06** | Case ID SHA-256 & Zero Leakage | `test_evidence_identity.py::TestGate3_06_*` (4 tests) + Smoke | **PASS** | `forensics/evidence_identity.py:38-73`, length 1..64, anchor `\A...\Z`, SHA-256 digest |
| **G3-07** | Legacy Read-Only Compatibility | `test_evidence_identity.py::TestGate3_07_*` (9 tests), `test_onchain_guard.py` | **PASS** | `forensics/onchain.py:755-805`, zero silent downgrade; explicit `--legacy-case-encoding` returning `LEGACY_PUBLIC_CASE_ID`; mixed profiles rejected |
| **G3-08** | Canonical Immutable Intent | `test_onchain_group3.py::TestGate3_08_*` (4 tests) | **PASS** | `forensics/onchain_store.py:64-125`, deterministic JSON with sorted keys, deterministic SHA-256 |
| **G3-09** | Operation Journal & State Transitions | `test_onchain_group3.py::TestGate3_09_*` (3 tests), `TestGate3_17_*` | **PASS** | `forensics/onchain_store.py:640-724`, `onchain_operation_events` tracks complete lifecycle |
| **G3-10** | Read-Only Reconcile Mechanism | `test_onchain_group3.py::TestGate3_10_*` (5 tests) + Smoke | **PASS** | `forensics/onchain_store.py:840-970`, read-only RPC, zero broadcast, idempotent updates |
| **G3-11** | SQLite Additive Migration Integrity | `test_onchain_store.py::TestGate3_11_*` (8 tests) | **PASS** | `forensics/schemas.py:143-176`, 100% snapshot preservation on diverse legacy rows, rollback/rerun resilience |
| **G3-12** | Canary Privacy & Secret Guardrails | `test_evidence_identity.py::TestGate3_12_*` (5 tests), `test_onchain_group3.py::TestRecoverySidecar` (3 tests) + Smoke | **PASS** | `forensics/evidence_identity.py:244-307`, longest-match redaction, sidecar recursive secret rejection |
| **G3-13** | Regression Preservation (1b/2A/2B/D1) | 221 regression tests across 8 test suites | **PASS** | Full regression suites pass 100% without weakening existing controls; 521 total pytest pass |
| **G3-14** | Export No-Clobber & Canonical URI | `test_onchain_store.py::TestGate3_14_*` (7 tests), `forensics/exporter.py` | **PASS** | `forensics/exporter.py:260-285`, canonical storage URI in DB metadata, no-clobber, dual-manifest distinction, retention on DB failure |
| **G3-15** | Canonical Storage URI Format | `test_evidence_identity.py::TestGate3_15_*` (8 tests) + Smoke | **PASS** | `forensics/evidence_identity.py:110-155`, exact 161 printable ASCII bytes, self-referential cycle detection |
| **G3-16** | Real Dual-Process Concurrency | `test_onchain_group3.py::TestGate3_16_*` (3 tests) + Smoke | **PASS** | `tests/test_onchain_group3.py:534-620`, multiprocessing spawn, atomic CAS `BEGIN IMMEDIATE` + conditional update, exactly 1 send on Anvil |
| **G3-17** | Fail-Closed Crash Recovery | `test_onchain_group3.py::TestGate3_17_*` (4 tests) | **PASS** | `tests/test_onchain_group3.py:621-720`, real child `kill()`, crash after `SEND_STARTED` refuses resend on restart, read-only reconcile zero send |

---

## 4. Verification Evidence & Execution Telemetry

### 4.1 Pytest Full Test Suite Execution
- **Command:** `python -m pytest tests/ -q`
- **Exit Code:** `0`
- **Output:**
  ```text
  521 passed in 168.04s (0:02:48)
  ```
- **Breakdown of Passing Tests:**
  - `tests/test_evidence_identity.py`: 36 tests PASS
  - `tests/test_onchain_store.py`: 33 tests PASS
  - `tests/test_onchain_group3.py`: 26 tests PASS
  - `tests/test_onchain_group3_smoke.py`: 7 tests PASS
  - `tests/test_onchain_2b.py`: 73 tests PASS
  - `tests/test_onchain_guard.py`: 10 tests PASS
  - `tests/test_onchain_group1.py`: 43 tests PASS
  - `tests/test_onchain_group1b.py`: 9 tests PASS
  - `tests/test_onchain_d1.py`: 4 tests PASS
  - `tests/test_group2b_smoke.py`: 1 test (9 Anvil checks) PASS
  - `tests/test_integrity_2a.py`: 48 tests PASS
  - `tests/test_provenance_2a.py`: 8 tests PASS
  - Pre-existing Phase 1 & 2 tests: 223 tests PASS
  - **Total:** 521 / 521 PASS (100%)

### 4.2 Foundry Contract Suite Execution
- **Command:** `forge test --root contracts`
- **Exit Code:** `0`
- **Output:**
  ```text
  Ran 1 test suite in 18.02ms (17.04ms CPU time): 31 tests passed, 0 failed, 0 skipped (31 total tests)
  ```
- **Fuzzing & Invariants:** Fuzz tests ran 256 iterations (`testFuzz_RegisterEvidence`). 100% property and access control verification passed.

### 4.3 Anvil Group 3 End-to-End Smoke Test
- **Command:** `python scripts/run_p3_group3_smoke.py`
- **Exit Code:** `0`
- **Telemetry:**
  ```json
  {
    "suite": "P3-Group3-Smoke",
    "status": "PASS",
    "chain_id": 31337,
    "checks": [
      {"name": "anvil_online", "status": "PASS"},
      {"name": "deploy_evidence_registry", "status": "PASS"},
      {"name": "export_dual_manifest_packages", "status": "PASS"},
      {"name": "anchor_evidence_1_canonical_identity", "status": "PASS"},
      {"name": "multi_manifest_anchor_links_created", "status": "PASS"},
      {"name": "record_custody_sha256_note_hash", "status": "PASS"},
      {"name": "verify_onchain_python_and_cli", "status": "MATCH", "code": "OK"},
      {"name": "read_only_reconciliation", "status": "PASS"},
      {"name": "fail_closed_idempotency_no_broadcast", "status": "PASS"},
      {"name": "zero_raw_data_leakage_asserted", "status": "PASS"}
    ],
    "leaks_found": []
  }
  ```

### 4.4 Anvil Group 1b Smoke Test
- **Command:** `python scripts/run_p3_group1b_smoke.py`
- **Exit Code:** `0`
- **Telemetry:** 55 checks PASS across real keystore signers, unlocked Anvil accounts, RPC redaction, and chain mismatch guards.

### 4.5 Anvil Group 2b Smoke Test
- **Command:** `python scripts/run_p3_group2b_smoke.py --output-dir <temp_dir> --protected-root forensics --protected-root contracts`
- **Exit Code:** `0`
- **Telemetry:** 9 checks PASS across collect, export, anchor, custody, and verify-without-keystore.

---

## 5. Security, Canary & Privacy Audit

1. **Canary Strings Tested:**
   - Case ID canary: `CANARY_CASE_XYZ_SECRET`
   - Note text canary: `CANARY_NOTE_CONFIDENTIAL_ABC`
   - Private key hex canary: `0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d`
   - Mnemonic phrase canary: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
2. **Leakage Verification Surfaces:**
   - Smart contract calldata and transaction payloads: **0 leaks** (SHA-256 digests used exclusively).
   - Smart contract events (`EvidenceRegistered`, `CustodyRecorded`): **0 leaks**.
   - Public storage URIs (`evidence://sha256/<case>/<man>/manifest.json`): **0 leaks**.
   - CLI stdout and stderr: **0 leaks**.
   - Log output (`sanitize_log_text()`): **0 leaks** (longest-match redaction).
   - SQLite tables (`custody_events`, `onchain_operations`, `onchain_operation_events`, `anchor_links`, `audit_events`, `receipts`): **0 leaks**.
   - Recovery sidecar files (`<db_path>.recovery.jsonl`): **0 leaks** (sensitive keys rejected/redacted).

---

## 6. Operational Guidance & Known Limitations

1. **Verifying Historical Evidence Anchored Prior to Group 3:**
   - Operators verifying packages created before Phase 3 Group 3 must explicitly supply the `--legacy-case-encoding` CLI flag or pass `legacy_case_encoding=True` to `verify_onchain_evidence()`.
   - Successful legacy verification returns status `MATCH` with reason code `LEGACY_PUBLIC_CASE_ID` (exit code 0).
   - Canonical packages verified without the flag return status `MATCH` with reason code `OK` (exit code 0).
2. **Database Migration Policy:**
   - Production SQLite databases (`data/forensics.db`) are automatically checked prior to write operations. Additive migration is executed safely inside short transactions without rewriting historical custody records.
   - Operations never perform `INSERT OR REPLACE` or backfill legacy rows.
3. **Recovery Procedures:**
   - Operations that encounter network timeouts or process terminations transition to `UNKNOWN`.
   - Operators should inspect `<db_path>.recovery.jsonl` and execute `python -m forensics.cli reconcile --operation-id <id>` in read-only mode to synchronize onchain confirmation without risking duplicate transaction submission.

---

## 7. Audit Handover Package

The independent audit package has been generated and validated:
- **Archive Path:** `D:\Projest\p3_group3_remediation_handover.zip`
- **Checksum Manifest:** `SHA256SUMS.json` inside archive
- **Verification Script:** `verify_archive.py` inside archive
- **Self-Verification:** Validated via automated CRC-32 and SHA-256 integrity inspection (`verify_archive.py: 27 verified OK, 0 failures`).

Antigravity now stands down and awaits official user acceptance.

