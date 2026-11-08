"""Forensic Evidence Ingestion Package (forensics/ingestion).

Provides an 8-step evidence ingestion pipeline with multi-format adapters:
- Blockchain transactions (JSON / JSONL)
- Blockchain transactions (CSV)
- SQLite database (strictly read-only mode)
- Authorized host / Sysmon logs

Strictly enforces read-only safety, anti-traversal security, and canonical database invariance.
"""

from forensics.ingestion.adapters import (
    AdapterError,
    AuthorizedHostLogsAdapter,
    BlockchainTxJsonAdapter,
    CorruptedFileError,
    FormatError,
    IngestionError,
    SchemaCompatibilityError,
    SecurityError,
    SqliteEvidenceAdapter,
    TransactionCsvAdapter,
    get_adapter_for_format,
)
from forensics.ingestion.pipeline import (
    EvidenceIngestionPipeline,
    IngestionRecord,
    IngestionResult,
)

__all__ = [
    "AdapterError",
    "AuthorizedHostLogsAdapter",
    "BlockchainTxJsonAdapter",
    "CorruptedFileError",
    "EvidenceIngestionPipeline",
    "FormatError",
    "IngestionError",
    "IngestionRecord",
    "IngestionResult",
    "SchemaCompatibilityError",
    "SecurityError",
    "SqliteEvidenceAdapter",
    "TransactionCsvAdapter",
    "get_adapter_for_format",
]
