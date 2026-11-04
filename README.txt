===============================================================================
Blockchain + AI Digital Forensics P1-P6: Standalone Portable Distribution
Release Version: v1.0.0
Git Checkpoint:  5f24c09 (checkpoint-g5-tested)
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

2. DIRECTORY STRUCTURE
----------------------
.
|-- collector.py              # Multi-chain transaction collector CLI
|-- pytest.ini                # Pytest test discovery & execution configuration
|-- requirements.txt          # 101 pinned Python dependencies
|-- setup_env.bat             # Automated offline virtual environment installer
|-- run_tests.bat             # Standalone test runner (Foundry + Pytest)
|-- run_evaluation.bat        # Standalone empirical evaluation runner
|-- README.txt                # This distribution documentation
|-- MANIFEST_SHA256.txt       # SHA-256 checksum manifest of all bundled files
|-- MANIFEST_INFO.json        # Package build metadata and provenance
|-- contracts/                # Foundry smart contracts (EvidenceRegistry.sol, tests)
|-- forensics/                # Core forensic analysis, rule engine, and AI pipelines
|-- scripts/                  # Standalone CLI tools (evaluate.py, portable.py, etc.)
|-- tests/                    # 39 pytest test suites (>1,104 tests)
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
  - 1,104 Pytest regression tests in isolated environment (100% runnable pass, 1 authorized skip)

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
===============================================================================
