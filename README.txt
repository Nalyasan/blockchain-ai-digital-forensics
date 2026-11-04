===============================================================================
Blockchain + AI Digital Forensics: Operational Academic Proof of Concept
Authoritative Specification: AGENT.md v6.0 (Topic 8: Blockchain + AI Forensics)
Release Version: v2.0.0 (Academic PoC)
Git Checkpoint:  checkpoint-p1-p10-final / integration/p7-p10-dev
===============================================================================

1. OVERVIEW
-----------
This distribution contains the complete, verified, academic Proof of Concept (PoC)
for an end-to-end verifiable digital forensics system under Topic 8 (Đề tài 8:
Điều tra số kết hợp Blockchain và AI), strictly compliant with AGENT.md v6.0.

In strict adherence to Requirement R4, all sequential phase labels (P1-P12)
have been eradicated across maintained documentation, diagrams, interfaces,
and components in favor of 12 descriptive functional components:

[DATA INGESTION]
- [C01] Blockchain Collector: EVM RPC client (ETH & ERC-20), reorg unwinder,
  atomic checkpointing, raw SHA-256 preservation.
- [C07] Endpoint Acquisition: ISO/IEC 27037 multi-source ingestion, live daemons
  (osquery/WMI), static JSONL/EVTX, acquisition manifests, AI First Responder.

[STORAGE & PACKAGING]
- [C02] Evidence Store: Tamper-evident SQLite persistence, append-only journals,
  canonical data stores, provenance and audit tracking.
- [C03] Evidence Package: RFC 6962 Merkle tree commitments, canonical storage
  URIs (evidence://sha256/...), cryptographically sealed manifests.

[DETECTION & HEURISTICS]
- [C04] Rule Engine: Deterministic heuristic rules (R1 Large Transfer, R2 High
  Frequency, R3 Fan-In/Out, R4 Rapid Pass-Through) with evidence_refs.
- [C08] Machine Learning & XAI: Compact MLP anomaly detector (ONNX sync),
  decoupled ground truth, local SHAP attribution, grounded MITRE ATT&CK.

[COGNITIVE INVESTIGATION & INTEL]
- [C06] Threat Intelligence: Open-source threat intelligence adapters (Forta,
  PTXPhish, MEW), Open World Assumption (OWA) screening, CSV anti-injection.
- [C05] AI Investigator: Bounded Pydantic AI agent, 5-layer read-only SQLite,
  38-pattern prompt injection sanitizer, 5-step budget, Ref Checker.

[VERIFIABLE COMPUTATION & CUSTODY]
- [C09] ZKML Verifiable Inference: Halo2 arithmetic circuits, KZG commitments,
  real EZKL proofs (no mocks), 5-part binding digest, on-chain Anvil verifier.
- [C10] Identity & Custody: Solidity 0.8.24 registry (EvidenceRegistryDID.sol),
  W3C DID Core 1.0 (did:ethr/did:key), EIP-712 signatures, 2-actor handover.

[EVALUATION & PORTABLE RELEASE]
- [C11] Integration & Evaluation: D1 (EVM Replay), D2 (Host Replay per ISO 27037),
  D3 (Multi-Gateway Adversarial Replay), end-to-end traceable forensic reports.
- [C12] Portable Release: Standalone offline Windows distribution, PowerShell
  automation, wheelhouse dependencies, SHA256SUMS.txt integrity verification.

All technical specifications, architectural designs, and cross-reference tables
are available in the docs/ directory:
- docs/naming_cross_reference.md (Complete 12-component mapping to AGENT.md v6.0)
- docs/architecture.md (Comprehensive system architecture and data flows)

2. DIRECTORY STRUCTURE
----------------------
.
|-- AGENT.md                  # Authoritative primary specification v6.0
|-- README.txt                # This distribution overview and operational manual
|-- PROJECT.txt               # Architecture, inventory, and milestone specifications
|-- pytest.ini                # Pytest test discovery and execution configuration
|-- requirements.txt          # Pinned Python dependencies
|-- setup_env.bat             # Automated offline virtual environment installer
|-- run_tests.bat             # Standalone test runner (Foundry + Pytest)
|-- run_evaluation.bat        # Standalone empirical evaluation runner
|-- collector.py              # Multi-chain transaction collector CLI
|-- mock_rpc.py               # Local synthetic EVM RPC test harness
|-- contracts/                # Smart contracts and Foundry test suites
|   |-- src/
|   |   |-- EvidenceRegistry.sol      # Core chain of custody registry
|   |   |-- EvidenceRegistryDID.sol   # ERC-1056 DID & EIP-712 custody extension
|   |   `-- InferenceVerifier.sol     # ZKML on-chain verifier contract
|   `-- test/                         # 112 Foundry forge smart contract tests
|-- data/                     # Canonical immutable & operational databases
|   |-- real_p4.db            # Canonical immutable ground truth (PROTECTED)
|   |-- forensics.db          # Canonical evidence store (PROTECTED)
|   |-- benchmark_p6.db       # Canonical public benchmark (PROTECTED)
|   `-- endpoint_evidence.db  # Dedicated endpoint evidence store
|-- docs/                     # Project documentation & architecture specifications
|   |-- architecture.md       # Comprehensive system architecture & data flows
|   |-- naming_cross_reference.md # 12-component naming cross-reference table
|   |-- limitations.txt       # Technical system limitations record
|   `-- legacy/               # Preserved historical specifications (agent_v5.1.txt)
|-- forensics/                # Core forensic Python modules
|   |-- ai/                   # AI Investigator, sanitizer, and ref checker
|   |-- adapters/             # Threat intelligence feeds and benchmark runner
|   |-- did/                  # W3C DID Core 1.0 resolver and EIP-712 client
|   |-- endpoint/             # Endpoint acquisition, daemons, and first responder
|   |-- ml/                   # ML anomaly detector, features, and local SHAP XAI
|   |-- rules/                # Heuristic Rule Engine (R1-R4) and anchored bridge
|   `-- zkml/                 # Real Halo2 / EZKL proving and verification engine
|-- models/                   # Serialized ML models, ONNX graphs, and ZK circuits
|-- reports/                  # Formal technical reports and baseline audits
|-- scripts/                  # Operational, demo, and packaging CLI scripts
|   |-- evaluate.py           # Threat intelligence and CTI evaluation CLI
|   |-- portable.py           # Standalone release packager and verifier
|   `-- verify_protected_hashes.py # Canonical database integrity verifier
|-- tests/                    # 1,521 Pytest test cases across 55 test files
`-- tools/foundry/            # Bundled Foundry binaries (forge, cast, anvil)

3. SYSTEM PREREQUISITES
-----------------------
- Operating System: Microsoft Windows 10 or Windows 11 (64-bit AMD64)
- Python Runtime:   Python 3.13 (64-bit) installed and accessible via PATH
- Disk Space:       ~1.5 GB (package extraction + virtual environment + models)

4. QUICK START INSTRUCTIONS
---------------------------
Step 1: Setup Offline Virtual Environment
  Execute setup_env.bat in Command Prompt or PowerShell:
    .\setup_env.bat
  This creates a local 'venv' and installs all pinned packages from the local
  wheelhouse without requiring an active internet connection.

Step 2: Activate Environment
  PowerShell:
    .\venv\Scripts\Activate.ps1
  Command Prompt:
    venv\Scripts\activate.bat

Step 3: Run Full Test Suite
  Execute run_tests.bat:
    .\run_tests.bat
  This executes:
  - 112 Foundry smart contract tests via forge.exe (100% pass)
  - 1,521 Pytest regression and unit test cases (100% pass)

Step 4: Verify Canonical Database Integrity
  Verify that protected canonical databases have not been tampered with:
    python scripts\verify_protected_hashes.py

Step 5: Run Empirical Demos & Evaluation
  Execute run_evaluation.bat:
    .\run_evaluation.bat
  This executes:
  - Demo D1: EVM Incident Case Replay
  - Demo D2: Endpoint Host Log Replay per ISO/IEC 27037
  - Demo D3: Multi-Gateway Adversarial Replay

5. CANONICAL DATABASE CHECKSUMS (SHA-256)
----------------------------------------
The SQLite databases in data/ are cryptographically sealed. Verify with Get-FileHash:
- data/forensics.db:
  3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001
- data/real_p4.db:
  6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97
- data/benchmark_p6.db:
  C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507
- .env:
  C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C

6. INTEGRITY VERIFICATION & PORTABLE BUNDLING
---------------------------------------------
To verify the complete package integrity or bundle a new standalone release:
  python scripts\portable.py verify <path_to_zip>
  python scripts\portable.py bundle --output dist\

7. DOCUMENTED ACCEPTANCE PREREQUISITES & SAFETY BOUNDS (RULES 5 & 13)
---------------------------------------------------------------------
MANDATORY INTEGRITY QUALIFICATION:
The system is certified as 100% OFFLINE_VERIFIED. In strict compliance with
academic honesty rules, 100% test pass rate confirms offline functional
correctness but does NOT constitute live public production deployment readiness.

Safety Invariants:
1. Public Network Broadcast Disabled: Transactions are executed strictly on local
    Anvil loopback (http://127.0.0.1:8545). Public chain broadcasts are blocked.
2. Privacy & Key Safety: Zero private keys, raw PII, or internal prompts are
    stored on-chain or leaked into logs.
3. Scientific Honesty: Zero mock proofs are accepted for ZKML verification.
===============================================================================
