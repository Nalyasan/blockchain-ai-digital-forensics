===============================================================================
Blockchain + AI Digital Forensics P1-P6: Standalone Portable Distribution
Release Version: v1.0.0
Git Checkpoint:  checkpoint-g6c-verified / v1.0.0 (Release Candidate)
===============================================================================

1. OVERVIEW
-----------
This standalone portable distribution contains the complete, production-ready
Blockchain + AI Digital Forensics codebase (P1-P6):
- Collector (P1): RPC collector, ETH/ERC-20 normalizer, checkpoint, 12-block reorg unwinder.
- Evidence Integrity (P2): SHA-256 packaging, Merkle commitment, append-only SQLite store.
- Smart Contracts (P3): EvidenceRegistry.sol (custody, idempotent registration, access control).
- Rule Engine (P4): Heuristic detection rules R1-R4 on real Ethereum Mainnet datasets.
- AI Investigator (P5): Bounded Pydantic AI investigator with 5-layer read-only SQLite,
  sanitizer, reference validation (ref_checker), and offline deterministic FunctionModel.
- Threat Intelligence & Evaluation (P6): Forta, MEW, and PTXPhish adapters, entity screening,
  and multi-unit empirical evaluation engine (tx_unit, address_window_unit).

All project guides, technical specifications, and historical reports are provided
as clean, standalone plain text files (.txt) with zero external Markdown dependencies.

2. DIRECTORY STRUCTURE
----------------------
.
|-- collector.py              # Multi-chain transaction collector CLI
|-- mock_rpc.py               # Local synthetic EVM RPC test harness
|-- pytest.ini                # Pytest test discovery & execution configuration
|-- requirements.txt          # 101 pinned Python dependencies
|-- setup_env.bat             # Automated offline virtual environment installer
|-- run_tests.bat             # Standalone test runner (Foundry + Pytest)
|-- run_evaluation.bat        # Standalone empirical evaluation runner
|-- README.txt                # This distribution documentation
|-- PROJECT.txt               # Architecture, inventory, and milestone specifications
|-- agent.txt                 # Technical forensic agent specification & manual
|-- COMPLETION_REPORT.txt     # Authoritative engineering completion & acceptance report
|-- P1_P6_STATUS_MATRIX.csv   # Traceability matrix mapping all P1-P6 and G0-G6 features
|-- BACKUP_RESTORATION.txt    # Backup verification & disaster recovery manual
|-- MANIFEST_SHA256.txt       # SHA-256 checksum manifest of all bundled files
|-- MANIFEST_INFO.json        # Package build metadata, git commit, and provenance
|-- contracts/                # Foundry smart contracts (EvidenceRegistry.sol, tests)
|-- docs/                     # Technical documentation (limitations.txt, P4_P3_BRIDGE.txt)
|-- forensics/                # Core forensic analysis, rule engine, and AI pipelines
|-- scripts/                  # Standalone CLI tools (evaluate.py, portable.py, etc.)
|-- tests/                    # 41 pytest test suites (1,119 tests)
|-- tools/foundry/            # Bundled Foundry binaries (forge.exe, cast.exe, anvil.exe)
|-- data/                     # Canonical SQLite databases (forensics.db, real_p4.db, benchmark_p6.db)
`-- wheels/                   # 101 pre-downloaded offline Python wheels (CPython 3.13)

3. SYSTEM PREREQUISITES
-----------------------
- Operating System: Microsoft Windows 10 or Windows 11 (64-bit AMD64)
- Python Runtime:   Python 3.13 (64-bit) installed and accessible via PATH
- Disk Space:       ~1.2 GB (package extraction + virtual environment)

4. QUICK START INSTRUCTIONS
---------------------------
Step 1: Setup Offline Virtual Environment
  Execute setup_env.bat in Command Prompt or PowerShell:
    .\setup_env.bat
  This creates a local 'venv' and installs all 101 pinned packages from the 'wheels/' directory
  without requiring an internet connection.

Step 2: Activate Environment
  Command Prompt:
    venv\Scripts\activate.bat
  PowerShell:
    .\venv\Scripts\Activate.ps1

Step 3: Run Full Test Suite
  Execute run_tests.bat:
    .\run_tests.bat
  This executes:
  - 56 Foundry smart contract tests via bundled tools\foundry\forge.exe (100% pass)
  - 1,119 Pytest regression tests in isolated environment (1,119 passed, 1 authorized skip)

Step 4: Run Empirical Evaluation
  Execute run_evaluation.bat:
    .\run_evaluation.bat
  This replays:
  - Euler Finance DAI incident evaluation
  - Curve alETH incident evaluation
  - Synthetic benchmark regression evaluation
  Outputs are saved to results\evaluation\

Step 5: Run Multi-Chain Collector
  python collector.py --help
  python collector.py healthcheck
  python collector.py verify

5. CANONICAL DATABASE CHECKSUMS (SHA-256)
----------------------------------------
The SQLite databases in data/ are cryptographically sealed. Verify with Get-FileHash:
- data/forensics.db:
  3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001
- data/real_p4.db:
  6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97
- data/benchmark_p6.db:
  C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507

6. INTEGRITY VERIFICATION
-------------------------
To verify the complete package integrity against MANIFEST_SHA256.txt:
  python scripts\portable.py verify <path_to_zip>

7. DOCUMENTED ACCEPTANCE PREREQUISITES & PRODUCTION READINESS (RULES 5 & 13)
----------------------------------------------------------------------------
MANDATORY INTEGRITY QUALIFICATION:
In strict compliance with Rule 5, 100% test pass rate confirms offline functional
correctness of P1-P6 modules but does NOT constitute live production deployment readiness.
Untested live network components are NOT declared production-ready solely based on unit tests.

The system is certified as 100% OFFLINE_VERIFIED. To transition this verified codebase
into live public network operations, the operating organization must fulfill the following
documented acceptance prerequisites:
1. Google Gemini API Credentials:
   - Environment Variable: GOOGLE_API_KEY or GEMINI_API_KEY
   - Purpose: Required for live LLM reasoning in the AI Investigator.
   - Offline Behavior: Operates against deterministic offline FunctionModel mock.
2. Live Ethereum Execution RPC Endpoint:
   - Environment Variable: RPC_URL or SEPOLIA_RPC_URL (e.g., Alchemy / Infura HTTPS/WSS)
   - Purpose: Real-time transaction ingestion and block reorg tracking in collector.py.
   - Offline Behavior: Operates against local Anvil loopback or mock_rpc.py.
3. Etherscan API Key:
   - Environment Variable: ETHERSCAN_API_KEY
   - Purpose: Dynamic contract ABI retrieval and verified contract source validation.
   - Offline Behavior: Operates against pre-compiled local ABI cache.
4. Deployed Smart Contract Address:
   - Environment Variable: EVIDENCE_REGISTRY_ADDRESS
   - Purpose: Contract address of EvidenceRegistry.sol deployed on Ethereum Mainnet or Sepolia.
   - Offline Behavior: Deploys ephemeral registry instances on local Anvil testnet.
5. Funded Custodial Private Key:
   - Environment Variable: ETH_PRIVATE_KEY or encrypted Cast keystore path
   - Purpose: Authorizing and paying gas fees for on-chain cryptographic evidence custody.
   - Offline Behavior: Uses standard Foundry pre-funded mnemonic accounts.
===============================================================================
