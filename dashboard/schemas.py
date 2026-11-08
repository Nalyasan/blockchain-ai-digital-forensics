"""Pydantic schemas for FastAPI Dashboard (dashboard/schemas.py)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class LaunchInvestigationRequest(BaseModel):
    """Payload to launch a new forensic investigation or demo replay."""
    case_id: str = Field(..., description="Case identifier (must match ^[A-Za-z0-9_-]{1,64}$)")
    case_name: Optional[str] = Field(default=None, description="Optional descriptive case name")
    investigator_id: Optional[str] = Field(default=None, description="Optional investigator identifier")
    continue_case: bool = Field(default=False, description="Explicit confirmation to continue an existing case with a new run")
    mode: str = Field(default="MODE_B", description="Operating mode: 'MODE_A' (Demo/Replay) or 'MODE_B' (Real Investigation)")
    demo_target: Optional[str] = Field(default="D1", description="For Mode A: 'D1' (EVM), 'D2' (Host), 'D3' (Adversarial), or 'ALL'")
    db_path: Optional[str] = Field(default=None, description="Path to target evidence database (defaults to real_p4.db)")
    ai_provider: str = Field(default="ollama", description="AI Provider: ollama, openai, anthropic, google, custom, deterministic_fallback")
    ai_model: str = Field(default="qwen3:8b", description="AI model name")
    ai_api_key: Optional[str] = Field(default=None, description="Optional API key for cloud providers")
    ai_base_url: Optional[str] = Field(default=None, description="Custom base URL for Ollama or custom provider")
    ai_consent: bool = Field(default=False, description="Explicit user consent for cloud API transmission")
    enable_onchain_write: bool = Field(default=False, description="Enable live custody transaction anchoring to local Anvil")
    is_mock: bool = Field(default=False, description="Use deterministic mock testing for cloud providers when offline")

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Mã vụ việc (Case ID) không được để trống.")
        v = v.strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", v):
            raise ValueError("Mã vụ việc chỉ được chứa ký tự chữ cái, số, gạch nối (-) và gạch dưới (_), độ dài 1-64 ký tự.")
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Mã vụ việc không được chứa ký tự đường dẫn nguy hiểm.")
        return v


class JobStatusResponse(BaseModel):
    """Detailed status response for an investigation job."""
    run_id: str
    case_id: str
    mode: str
    status: str
    vietnamese_status: str
    progress_percent: int
    current_phase: Optional[str] = None
    current_phase_name: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    phase_status: Dict[str, str] = Field(default_factory=dict)
    phase_metrics: Dict[str, Any] = Field(default_factory=dict)
    artifacts: Dict[str, str] = Field(default_factory=dict)
    errors: List[Dict[str, str]] = Field(default_factory=list)


class CancelJobResponse(BaseModel):
    """Response when requesting cancellation of a job."""
    success: bool
    run_id: str
    message: str


class SystemStatusResponse(BaseModel):
    """Overall system and environment health status."""
    is_busy: bool
    active_job_id: Optional[str] = None
    canonical_databases: Dict[str, Dict[str, Any]]
    ai_configuration: Dict[str, Any]
    foundry_toolchain: Dict[str, Any]
    server_time_utc: str
