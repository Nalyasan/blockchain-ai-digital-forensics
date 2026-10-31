# Project: P3 Group 3 — Blockchain + AI Digital Forensics

## Architecture
- **Layer 1: Identity & Privacy Layer (`forensics/evidence_identity.py`)**
  * Hashing: SHA-256 UTF-8 of `case_id` and `note` (no filesystem probing).
  * Canonical URI format: `evidence://sha256/<case_hash>/<manifest_hash>/manifest.json` (exact 161 bytes, max 256 bytes).
  * Manifest hash: calculated from verified manifest bytes without self-referential cycles.
  * Privacy guardrails: zero raw `case_id` or `note` exposure in chain events, logs, CLI output, or sidecar files.
  * Legacy read-only verification: strictly opt-in via `--legacy-case-encoding` or `legacy_uri=True`.

- **Layer 2: SQLite Persistence & Custody Layer (`forensics/schemas.py`, `forensics/onchain_store.py`)**
  * Additive schema migrations: `anchor_links`, `onchain_operations`, `onchain_operation_events`.
  * Event identity tuple: `(chain_id, contract_address, tx_hash, log_index)`.
  * Complete prohibition of `INSERT OR REPLACE` (prevents history clobbering).
  * Pure insert and atomic verification update: `verified=1` only after verifying receipt, event log, and state.
  * Fail-fast: pre-send DB readiness check refuses transaction dispatch if DB missing or read-only.

- **Layer 3: Idempotency & Recovery Layer (`forensics/onchain_store.py`)**
  * Canonical immutable intent and fingerprinting.
  * Atomic send claim: `BEGIN IMMEDIATE` + CAS `UPDATE onchain_operations SET state='SEND_STARTED' WHERE operation_id=? AND state='READY' AND tx_hash IS NULL` verifying `cur.rowcount == 1`.
  * Zero automatic retries: on timeout, crash, or UNKNOWN state, marks UNKNOWN and writes redacted sidecar without retrying.
  * Read-only reconciliation: synchronizes state by querying blockchain receipt and updating DB.

- **Layer 4: Integration & CLI Layer (`forensics/onchain.py`, `forensics/cli.py`)**
  * Re-exports `compute_file_sha256` and `init_db` to fix regressions.
  * Refactors `anchor_evidence` and `record_custody_action` to consume `evidence_identity` and `onchain_store`.
  * CLI integration: supports `--legacy-case-encoding`, `reconcile` command, and sanitizes output.
  * Smoke test harnesses: P3 1b, P3 2A, P3 2B, and P3 Group 3 (`scripts/run_p3_group3_smoke.py`).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Gate 0 Checkpoint & Recovery | Read-only git audit, leftover state preservation, external checkpoint, recovery report | M0 (Gate 0) | R1 / Plan v2 |
| 2 | Case ID UTF-8 SHA-256 Hashing | SHA-256 UTF-8 hash for case ID; bytes32 representation; zero raw case ID leakage | M1 (Worker A) | R2 / G3-05, G3-06 |
| 3 | Note UTF-8 SHA-256 Hashing | SHA-256 UTF-8 note hash; non-empty validation; zero filesystem probing | M1 (Worker A) | R2 / G3-06 |
| 4 | Canonical Storage URI | Format `evidence://sha256/<case_hash>/<manifest_hash>/manifest.json` (<= 256 bytes) | M1 (Worker A) | R2 / G3-07, G3-15 |
| 5 | Legacy Read-Only Verification | Explicit opt-in verification of historical unhashed case IDs and legacy URIs | M1 (Worker A) | R2 / G3-07, G3-12 |
| 6 | Privacy Guardrails & Sanitization | Prevent raw case_id or note in logs, CLI, exceptions, and sidecar files | M1 (Worker A) | R2 / G3-12, G3-15 |
| 7 | Additive SQLite Migration | `GROUP3_SCHEMA` creating `anchor_links`, operations, journal tables without data loss | M2 (Worker B) | R3 / G3-01, G3-11 |
| 8 | Event Identity & Collision Prevention | Unique index on `(chain_id, contract_address, tx_hash, log_index)` | M2 (Worker B) | R3 / G3-02 |
| 9 | Zero INSERT OR REPLACE | Eliminate all `INSERT OR REPLACE` in `custody_events` and store operations | M2 (Worker B) | R3 / G3-03 |
| 10 | Strict Verification Pre-verified=1 | Mark `verified=1` only after verifying receipt, event topic, and block number | M2 (Worker B) | R3 / G3-03, G3-04 |
| 11 | Pre-send Fail-Fast DB Check | Refuse transaction send if DB missing, locked, or read-only | M2 (Worker B) | R3 / G3-04, G3-11 |
| 12 | Event Distinction | Clearly distinguish `EvidenceRegistered` vs `CustodyRecorded` by event signature | M2 (Worker B) | R3 / G3-14 |
| 13 | Canonical Immutable Intent | Canonical JSON serialization and SHA-256 intent fingerprinting | M3 (Worker C) | R4 / G3-08 |
| 14 | Operation Journal & Transitions | Track `READY` -> `SEND_STARTED` -> `BROADCAST` -> `CONFIRMED`/`UNKNOWN`/`FAILED` | M3 (Worker C) | R4 / G3-09 |
| 15 | Atomic Send Claim (CAS) | `BEGIN IMMEDIATE` + conditional UPDATE with `rowcount==1` check; dual-process lock | M3 (Worker C) | R4 / G3-10, G3-16 |
| 16 | Zero Automatic Retries | On timeout/crash/exception, fail-closed to UNKNOWN; never resend | M3 (Worker C) | R4 / G3-09, G3-17 |
| 17 | Read-only Reconcile | Verify transaction on-chain and sync DB state without resending | M3 (Worker C) | R4 / G3-10 |
| 18 | Redacted Recovery Sidecar | Write `.recovery.jsonl` on DB failure, strictly excluding credentials & raw secrets | M3 (Worker C) | R4 / G3-12 |
| 19 | Onchain Integration & Import Fix | Re-export `compute_file_sha256` and `init_db` in `onchain.py`; fix 161 test errors | M4 (Lead Agent) | R5 / G3-13 |
| 20 | Custody Routine Refactoring | Refactor `record_custody_action` to use `onchain_store` and eliminate `INSERT OR REPLACE` | M4 (Lead Agent) | R5 / G3-02, G3-03 |
| 21 | CLI & Exporter Integration | Add `--legacy-case-encoding` and `reconcile` subcommands to `forensics/cli.py` | M4 (Lead Agent) | R5 / G3-13 |
| 22 | Smoke Test Suite Group 3 | Create `scripts/run_p3_group3_smoke.py` and `tests/test_onchain_group3_smoke.py` | M4 (Lead Agent) | R5 / G3-13 |
| 23 | Full 17 Gates Acceptance & Regression | Run and pass all 17 gates G3-01..G3-17, full pytest suite, forge test, regression | M5 (Final Gates) | Acceptance Criteria |
| 24 | Final Deliverables & Reporting | Author `P3_GROUP3_REPORT.md` and commit with clean audit trail | M6 (Deliverables) | R5 / Deliverables |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M0 | Gate 0 Recovery & Checkpoint | Git audit, backup checkpoint outside repo, `P3_GROUP3_HANDOFF_RECOVERY.md` | none | DONE |
| M1 | H6/M5 Identity & Privacy | `forensics/evidence_identity.py`, `tests/test_evidence_identity.py` (G3-05, G3-06, G3-07, G3-12, G3-15) | M0 | DONE |
| M2 | H5 SQLite & Custody | `forensics/schemas.py`, `forensics/onchain_store.py`, `tests/test_onchain_store.py` (G3-01..G3-04, G3-11, G3-14) | M0 | DONE |
| M3 | M4 Idempotency & Recovery | `forensics/onchain_store.py`, `tests/test_onchain_group3.py` (G3-08..G3-10, G3-16, G3-17) | M2 | DONE |
| M4 | Lead Integration & Regression | `forensics/onchain.py`, `forensics/cli.py`, smoke scripts, full test fixes | M1, M2, M3 | DONE |
| M5 | Final Acceptance & Adversarial Hardening | Full 17 gates (G3-01..G3-17) validation, adversarial verification, forensic audit | M4 | DONE |
| M6 | Deliverables & Handoff | `P3_GROUP3_REPORT.md`, git commit, victory report | M5 | DONE |

## Interface Contracts
### `forensics/evidence_identity.py`
- `sha256_utf8(text: str) -> str`: Returns 64-char hex SHA-256 digest of UTF-8 encoded string.
- `case_id_digest(case_id: str) -> str`: Validates `case_id` format and returns 64-char hex SHA-256 digest.
- `case_id_hash_bytes32(case_id: str) -> str`: Returns `0x` + 64-hex digest.
- `note_hash_bytes32(note: str) -> str`: Validates non-empty note and returns `0x` + 64-hex digest of UTF-8 note.
- `canonical_storage_uri(case_digest: str, manifest_digest: str) -> str`: Returns `evidence://sha256/<case_digest>/<manifest_digest>/manifest.json` (exact 161 bytes). Validates ASCII and length <= 256 bytes.
- `identity_for_verify(case_id: str, manifest_sha256: str, legacy_case_encoding: bool = False) -> tuple[str, str]`: Returns `(case_id_b32, storage_uri)`. If `legacy_case_encoding=True`, returns legacy `(string_to_bytes32_hex(case_id), f"evidence://{case_id}/manifest.json")`.

### `forensics/onchain_store.py`
- `open_existing_rw(db_path: Path | str, migrate_before_send: bool = False) -> sqlite3.Connection`: Connects with `?mode=rw` and verifies `group3_schema_present`.
- `register_intent(db_path: Path | str, intent: dict) -> str`: Inserts intent with state `READY` if not present; returns `operation_id`.
- `claim_send(db_path: Path | str, intent: dict) -> tuple[str, bool, str]`: Executes `BEGIN IMMEDIATE`, atomic CAS update `state='SEND_STARTED' WHERE operation_id=? AND state='READY' AND tx_hash IS NULL`. Returns `(operation_id, can_send, current_state)`.
- `record_broadcast(db_path: Path | str, operation_id: str, tx_hash: str) -> None`: Updates state to `BROADCAST`.
- `persist_verified_event(db_path: Path | str, operation_id: str, event_data: dict) -> None`: Inserts into `custody_events` and `anchor_links`, updates state to `CONFIRMED`, commits atomically.
- `mark_unknown(db_path: Path | str, operation_id: str, code: str) -> None`: Transitions operation to `UNKNOWN` or writes sidecar on DB error.
- `write_sidecar(db_path: Path | str, payload: dict) -> None`: Writes to `.recovery.jsonl`, strictly sanitizing sensitive keys.
- `reconcile_operation(db_path: Path | str, operation_id: str, rpc_client) -> dict`: Read-only queries blockchain for tx receipt and events; updates DB state accordingly.

## Code Layout
```
forensics/
├── evidence_identity.py       # [Worker A] Case ID/Note SHA-256, canonical URI, legacy verification router
├── schemas.py                 # [Worker B] GROUP3_SCHEMA, additive migration, index
├── onchain_store.py           # [Worker B & C] Unified store: open_rw, persist, claim_send, journal, reconcile
├── onchain.py                 # [Lead Agent] Orchestrates send, verification, re-exports compute_file_sha256
├── cli.py                     # [Lead Agent] CLI commands: anchor, custody, verify-onchain, reconcile
tests/
├── test_evidence_identity.py  # [Worker A] Tests G3-05, G3-06, G3-07, G3-12, G3-15
├── test_onchain_store.py      # [Worker B] Tests G3-01, G3-02, G3-03, G3-04, G3-11, G3-14
├── test_onchain_group3.py     # [Worker C] Tests G3-08, G3-09, G3-10, G3-16 (multiprocess), G3-17 (crash recovery)
├── test_onchain_group3_smoke.py # [Lead Agent] Smoke integration test
scripts/
└── run_p3_group3_smoke.py     # [Lead Agent] Standalone smoke test runner
```
