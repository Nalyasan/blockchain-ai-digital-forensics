"""P7 Endpoint Telemetry Ingestion and AI First Responder Package.

Standardized digital evidence acquisition from Windows endpoints, osquery daemons,
CIM/PowerShell fallback, dedicated isolated evidence storage, ISO/IEC 27037:2012 manifests,
polymorphic source adapters, and automated non-destructive incident triage playbooks with
hardcoded safety boundaries.
"""

from forensics.endpoint.adapter import (
    ALLOWED_CONSENT_SCOPES,
    ConsentScopeViolation,
    EVMCollectorAdapter,
    EvidenceSourceAdapter,
    EvtxLogAdapter,
    ForensicIntegrityError,
    JsonlLogAdapter,
)
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
    HashVerificationParams,
    HashVerificationResult,
    IsolationRecommendation,
    NetworkConnectionsParams,
    ParameterBoundaryViolation,
    PersistenceIndicator,
    PersistenceIndicatorsParams,
    PlaybookExecutionError,
    ProcessTelemetry,
    RunningProcessesParams,
    SafetyGuard,
    SecurityBoundaryViolation,
    SocketTelemetry,
    SystemEventsParams,
    TriageExecutionResult,
    TriagePlaybookType,
    UnauthorizedActionError,
    triage_active_network_connections,
    triage_hash_verification,
    triage_persistence_indicators,
    triage_recent_system_events,
    triage_running_processes,
)
from forensics.endpoint.manifest import (
    generate_acquisition_manifest,
    verify_acquisition_manifest,
)
from forensics.endpoint.schemas import (
    AcquisitionManifest,
    AcquisitionResult,
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
from forensics.endpoint.static_logs import (
    parse_evtx_log,
    parse_jsonl_log,
)
from forensics.endpoint.store import (
    EndpointEvidenceStore,
    get_readonly_endpoint_connection,
    init_endpoint_db,
)

__all__ = [
    # Schemas & Manifests
    "BaseEndpointRecord",
    "ProcessRecord",
    "SocketRecord",
    "EventRecord",
    "SystemInfoRecord",
    "AcquisitionResult",
    "AcquisitionManifest",
    "canonical_json",
    "compute_payload_sha256",
    "generate_record_id",
    "create_endpoint_record",
    "generate_acquisition_manifest",
    "verify_acquisition_manifest",
    # Adapters & Parsers
    "EvidenceSourceAdapter",
    "JsonlLogAdapter",
    "EvtxLogAdapter",
    "EVMCollectorAdapter",
    "ForensicIntegrityError",
    "ConsentScopeViolation",
    "ALLOWED_CONSENT_SCOPES",
    "parse_jsonl_log",
    "parse_evtx_log",
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
    "SecurityBoundaryViolation",
    "DangerousActionError",
    "UnauthorizedActionError",
    "ParameterBoundaryViolation",
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
    # Parameter Models
    "NetworkConnectionsParams",
    "RunningProcessesParams",
    "SystemEventsParams",
    "PersistenceIndicatorsParams",
    "HashVerificationParams",
    # Playbooks
    "triage_active_network_connections",
    "triage_running_processes",
    "triage_recent_system_events",
    "triage_persistence_indicators",
    "triage_hash_verification",
]
