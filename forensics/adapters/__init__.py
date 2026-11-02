"""Threat intelligence data adapters and screening benchmark engine for Phase 6."""

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    compute_file_sha256,
    compute_payload_sha256,
    is_valid_eth_address,
    is_valid_tx_hash,
    normalize_eth_address,
    normalize_tx_hash,
    sanitize_formula_injection,
)
from forensics.adapters.benchmark_runner import (
    parse_all_authentic_datasets,
    run_full_benchmark_suite,
)
from forensics.adapters.csv_adapter import parse_csv_file, parse_forta_csv
from forensics.adapters.json_adapter import parse_json_file, parse_mew_darklist_json
from forensics.adapters.persistence_benchmark import (
    DEFAULT_BENCHMARK_DB_PATH,
    EvidenceConflictError,
    assert_database_isolation,
    init_benchmark_db,
    insert_intel_batch,
    insert_intel_record,
)
from forensics.adapters.screening import (
    ScreeningMatch,
    ScreeningSummary,
    extract_incident_counterparties,
    get_readonly_p4_connection,
    persist_screening_matches,
    run_incident_screening,
    screen_addresses,
    screen_single_address,
)
from forensics.adapters.xlsx_adapter import parse_ptxphish_xlsx, parse_xlsx_file

__all__ = [
    "ThreatIntelRecord",
    "ThreatIntelBatch",
    "compute_file_sha256",
    "compute_payload_sha256",
    "is_valid_eth_address",
    "is_valid_tx_hash",
    "normalize_eth_address",
    "normalize_tx_hash",
    "sanitize_formula_injection",
    "parse_forta_csv",
    "parse_csv_file",
    "parse_ptxphish_xlsx",
    "parse_xlsx_file",
    "parse_mew_darklist_json",
    "parse_json_file",
    "init_benchmark_db",
    "insert_intel_record",
    "insert_intel_batch",
    "assert_database_isolation",
    "EvidenceConflictError",
    "DEFAULT_BENCHMARK_DB_PATH",
    "ScreeningMatch",
    "ScreeningSummary",
    "get_readonly_p4_connection",
    "extract_incident_counterparties",
    "screen_addresses",
    "screen_single_address",
    "persist_screening_matches",
    "run_incident_screening",
    "parse_all_authentic_datasets",
    "run_full_benchmark_suite",
]
