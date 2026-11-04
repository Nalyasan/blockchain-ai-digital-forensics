"""P7 Endpoint Telemetry Ingestion and AI First Responder Package.

Standardized digital evidence acquisition from Windows endpoints, osquery daemons,
CIM/PowerShell fallback, dedicated isolated evidence storage, and automated
non-destructive incident triage playbooks with hardcoded safety boundaries.
"""

from forensics.endpoint.daemon import (
    MockTelemetryProvider,
    OsqueryProvider,
    TelemetryProvider,
    WMIPowerShellFallbackProvider,
    get_default_provider,
    query_endpoint,
)
from forensics.endpoint.first_responder import (
    ActionBlockedResult,
    AIFirstResponder,
    DangerousActionError,
    FirstResponseError,
    ForbiddenActionCategory,
    HashVerificationResult,
    IsolationRecommendation,
    PersistenceIndicator,
    PlaybookExecutionError,
    ProcessTelemetry,
    SafetyGuard,
    SocketTelemetry,
    TriageExecutionResult,
    TriagePlaybookType,
    triage_active_network_connections,
    triage_hash_verification,
    triage_persistence_indicators,
    triage_recent_system_events,
    triage_running_processes,
)
from forensics.endpoint.schemas import (
    BaseEndpointRecord,
    EventRecord,
    ProcessRecord,
    SocketRecord,
    SystemInfoRecord,
    canonical_json,
    compute_payload_sha256,
    create_endpoint_record,
    generate_record_id,
)
from forensics.endpoint.store import (
    EndpointEvidenceStore,
    get_readonly_endpoint_connection,
    init_endpoint_db,
)

__all__ = [
    # Schemas
    "BaseEndpointRecord",
    "ProcessRecord",
    "SocketRecord",
    "EventRecord",
    "SystemInfoRecord",
    "canonical_json",
    "compute_payload_sha256",
    "generate_record_id",
    "create_endpoint_record",
    # Daemon & Providers
    "TelemetryProvider",
    "OsqueryProvider",
    "WMIPowerShellFallbackProvider",
    "MockTelemetryProvider",
    "get_default_provider",
    "query_endpoint",
    "EndpointEvidenceStore",
    "get_readonly_endpoint_connection",
    "init_endpoint_db",
    # First Responder & Safety
    "ForbiddenActionCategory",
    "TriagePlaybookType",
    "FirstResponseError",
    "DangerousActionError",
    "PlaybookExecutionError",
    "ActionBlockedResult",
    "TriageExecutionResult",
    "IsolationRecommendation",
    "SocketTelemetry",
    "ProcessTelemetry",
    "PersistenceIndicator",
    "HashVerificationResult",
    "SafetyGuard",
    "AIFirstResponder",
    # Playbooks
    "triage_active_network_connections",
    "triage_running_processes",
    "triage_recent_system_events",
    "triage_persistence_indicators",
    "triage_hash_verification",
]
