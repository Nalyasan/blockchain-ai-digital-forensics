"""Forensic Output Schemas for Milestone 3 (P5 AI Investigator).

Provides validated Pydantic models for structured investigation outputs with:
- Strict field separation: observed blockchain facts vs. rule detections vs.
  external labels vs. analyst interpretations vs. conclusions.
- Exact non-negative integer string representation for `amount_raw` to prevent
  EVM 256-bit precision loss or floating point conversions.
- Structural prevention of hallucinated model hypotheses passing as verified facts.
- Full compatibility with Pydantic AI v2 structured output agents.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# Regular expression patterns for EVM forensic data types
HEX_TX_HASH_REGEX = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX_ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
EVIDENCE_REF_REGEX = re.compile(
    r"^(tx:0x[0-9a-fA-F]{64}|block:\d+|alert:[a-zA-Z0-9_\-]+|transfer:\d+|address:0x[0-9a-fA-F]{40}|log:0x[0-9a-fA-F]{64}:\d+)$"
)

# Words indicating subjective speculation or interpretation rather than objective physical on-chain fact
SPECULATIVE_WORDS = {
    # Subjective/Analyst Speculation
    "suspect",
    "suspected",
    "suspects",
    "alleged",
    "allegedly",
    "probably",
    "likely",
    "might",
    "could",
    "hypothesis",
    "theorize",
    "theorized",
    "assumed",
    "believed",
    "attacker",
    "exploit",
    "exploited",
    "hacker",
    "victim",
    "stolen",
    "malicious",
    # ML & MITRE Interpretations (Field Separation Protection)
    "anomaly",
    "anomalous",
    "predicted",
    "prediction",
    "probability",
    "mitre",
    "t1027",
    "t1566",
    "t1048",
    "t1499",
    "t1565",
    "shap",
    "phishing",
    "exfiltration",
    "obfuscation",
}


class ObservedFact(BaseModel):
    """Objective verified blockchain fact observed in canonical evidence.
    
    Strict Forensic Invariant:
    ObservedFact models physical, deterministic state transitions directly verifiable
    in blocks, transactions, receipts, or logs. Model hypotheses, subjective attributions,
    or speculative narratives MUST NOT be stored in ObservedFact.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    statement: str = Field(
        default="Observed on-chain transfer event",
        description="Objective factual statement describing the observed on-chain state transition (no hypotheses or speculations).",
        min_length=5,
        max_length=500,
    )
    tx_hash: str = Field(
        ...,
        description="Canonical transaction hash formatted as 0x followed by 64 hex characters.",
    )
    block_number: int = Field(
        ...,
        description="Non-negative block number containing the transaction.",
        ge=0,
    )
    from_addr: str = Field(
        ...,
        description="Sender address formatted as 0x followed by 40 hex characters.",
    )
    to_addr: str = Field(
        ...,
        description="Recipient address or contract address formatted as 0x followed by 40 hex characters.",
    )
    asset_id: str = Field(
        ...,
        description="Asset identifier ('NATIVE', 'ETH', or ERC-20 contract address).",
        min_length=1,
        max_length=64,
    )
    amount_raw: str = Field(
        ...,
        description="Exact non-negative integer decimal string representing wei or token base units (e.g. '1000000000000000000'). Never float, decimal, or scientific notation.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="List of verifiable canonical evidence references supporting this fact (e.g. ['tx:0x...', 'block:123']).",
    )

    @field_validator("tx_hash")
    @classmethod
    def validate_tx_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if not HEX_TX_HASH_REGEX.match(v):
            raise ValueError(
                f"Invalid tx_hash format: {v!r}. Must be 0x followed by 64 hexadecimal characters."
            )
        return v

    @field_validator("from_addr", "to_addr")
    @classmethod
    def validate_address(cls, v: str) -> str:
        v = v.strip().lower()
        if not HEX_ADDRESS_REGEX.match(v):
            raise ValueError(
                f"Invalid address format: {v!r}. Must be 0x followed by 40 hexadecimal characters."
            )
        return v

    @field_validator("amount_raw", mode="before")
    @classmethod
    def validate_amount_raw(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError(
                f"amount_raw must be a string, got {type(v).__name__}"
            )
        v = v.strip()
        if not v.isdigit():
            raise ValueError(
                f"amount_raw must be an exact non-negative integer decimal string without decimal points, signs, or exponents: {v!r}"
            )
        return v

    @field_validator("statement")
    @classmethod
    def validate_factual_purity(cls, v: str) -> str:
        """Enforces field separation: prevents subjective speculation from polluting facts."""
        v_lower = v.lower()
        words = set(re.findall(r"\b[a-z0-9]+\b", v_lower))
        found_speculative = words.intersection(SPECULATIVE_WORDS)
        if found_speculative:
            raise ValueError(
                f"Field separation violation: ObservedFact.statement contains speculative/interpretive vocabulary: {sorted(found_speculative)}. Hypotheses and behavioral attributions must be placed in AnalystInterpretation, MLAnomalyDetection, or MitreAttackMapping."
            )
        return v.strip()

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, v: list[str]) -> list[str]:
        cleaned = []
        for ref in v:
            ref_str = str(ref).strip()
            if not ref_str:
                continue
            cleaned.append(ref_str)
        return cleaned


class RuleDetection(BaseModel):
    """Deterministic detection generated by Rule Engine (P2/P4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(
        ...,
        description="Identifier of the rule (e.g. 'large_transfer', 'high_frequency', 'fan_in_out', 'rapid_pass_through').",
        min_length=1,
        max_length=64,
    )
    alert_id: str = Field(
        ...,
        description="Unique identifier of the alert from the alerts database.",
        min_length=1,
        max_length=128,
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ...,
        description="Severity level assigned to the alert.",
    )
    score: float = Field(
        ...,
        description="Normalized anomaly score (>= 0.0).",
        ge=0.0,
    )
    reason: str = Field(
        ...,
        description="Deterministic reason description explaining why the rule triggered.",
        min_length=1,
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Canonical evidence references associated with the alert.",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.strip().lower()
        return v


class ExternalLabel(BaseModel):
    """External label or third-party intelligence claim.
    
    Separates third-party claims (e.g. from Etherscan, Arkham, Chainalysis)
    from verified on-chain ground truth.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(
        ...,
        description="Intelligence provider or source name (e.g. 'Etherscan', 'Arkham', 'OFAC', 'Euler Advisory').",
        min_length=1,
        max_length=128,
    )
    address_or_tx: str = Field(
        ...,
        description="Subject address or transaction hash.",
        min_length=42,
        max_length=66,
    )
    category: str = Field(
        ...,
        description="Label category (e.g. 'exploit', 'sanctioned', 'exchange', 'mixer', 'victim', 'phishing').",
        min_length=1,
        max_length=64,
    )
    entity_name: str | None = Field(
        default=None,
        description="Identified entity or project name, if known.",
        max_length=128,
    )
    source_url: str | None = Field(
        default=None,
        description="Authoritative reference URL or document citation.",
        max_length=512,
    )
    is_verified: bool = Field(
        default=False,
        description="Whether this external label has been independently verified against on-chain evidence.",
    )
    notes: str | None = Field(
        default=None,
        description="Additional context regarding provenance or confidence.",
        max_length=1000,
    )


class AnalystInterpretation(BaseModel):
    """Analytical hypothesis, behavioral attribution, or exploit reconstruction.
    
    Model-generated reasoning must reside here. Each hypothesis can reference
    supporting fact indices to create an explicit traceable evidence chain.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str = Field(
        ...,
        description="Unique identifier for the hypothesis (e.g. 'HYP-01', 'HYP-02').",
        min_length=1,
        max_length=64,
    )
    interpretation: str = Field(
        ...,
        description="Detailed analytical assessment, behavioral attribution, or attack narrative.",
        min_length=10,
    )
    confidence: float = Field(
        ...,
        description="Confidence level in this interpretation between 0.0 (unsupported) and 1.0 (certain).",
        ge=0.0,
        le=1.0,
    )
    supporting_fact_indices: list[int] = Field(
        default_factory=list,
        description="0-based indices into observed_facts that directly support this hypothesis.",
    )
    competing_hypotheses: list[str] = Field(
        default_factory=list,
        description="Alternative interpretations or competing explanations considered.",
    )


class MLAnomalyDetection(BaseModel):
    """Machine learning anomaly detection output with quantitative explainability."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str = Field(..., description="Unique model identifier, e.g. 'anomaly_detector_v1'")
    model_sha256: str = Field(..., description="SHA-256 hash of the model weights artifact")
    entity_address: str = Field(..., description="Target address evaluated")
    score: float = Field(..., ge=0.0, le=1.0, description="Normalized anomaly score")
    classification: Literal["normal", "suspicious", "anomalous"] = Field(
        ..., description="Discrete classification bucket"
    )
    top_features: list[str] = Field(default_factory=list, description="Top feature drivers from XAI")
    xai_attributions: dict[str, float] = Field(
        default_factory=dict, description="SHAP feature attribution values"
    )
    mitre_techniques: list[str] = Field(
        default_factory=list, description="Associated MITRE technique IDs"
    )
    evidence_refs: list[str] = Field(
        default_factory=list, description="Canonical evidence references supporting this detection"
    )

    @field_validator("entity_address")
    @classmethod
    def validate_entity_address(cls, v: str) -> str:
        v = v.strip().lower()
        if not HEX_ADDRESS_REGEX.match(v):
            raise ValueError(f"Invalid entity_address: {v!r}. Must be 0x followed by 40 hex characters.")
        return v


class MitreAttackMapping(BaseModel):
    """Formal MITRE ATT&CK mapping with mandatory documented evidence citations."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(..., description="e.g. 'T1027', 'T1566.002', 'T1048.003', 'T1499.004'")
    technique_name: str = Field(..., description="Descriptive name of the technique")
    tactic: str = Field(..., description="e.g. 'Defense Evasion', 'Initial Access', 'Exfiltration', 'Impact'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    evidence_refs: list[str] = Field(
        ..., min_length=1, description="Must cite at least 1 verified canonical on-chain evidence reference"
    )
    rationale: str = Field(..., min_length=10, description="Technical rationale grounded in evidence")

    @field_validator("evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("MitreAttackMapping must cite at least 1 evidence reference.")
        cleaned = [str(r).strip() for r in v if str(r).strip()]
        if not cleaned:
            raise ValueError("MitreAttackMapping must cite at least 1 non-empty evidence reference.")
        return cleaned


class ForensicInvestigationOutput(BaseModel):
    """Complete structured forensic investigation output schema for P5 AI Investigator.
    
    Strictly distinguishes:
    1. `observed_facts`: Ground truth verifiable on-chain facts.
    2. `rule_detections`: Deterministic Rule Engine triggers.
    3. `external_labels`: Third-party intelligence claims.
    4. `analyst_interpretations`: Model-generated analytical hypotheses.
    5. `ml_detections`: Machine learning anomaly detections with quantitative XAI attributions.
    6. `mitre_mappings`: Formal MITRE ATT&CK taxonomy mappings substantiated by evidence refs.
    7. `chronological_timeline`: Ordered event summaries grounded in evidence.
    8. `investigative_observations`: General factual observations from tool queries.
    9. `conclusions`: Synthesized case findings supported by evidence.
    10. `uncertainty_and_limitations`: Explicit boundaries and missing evidence warnings.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(
        ...,
        description="Case or investigation identifier (e.g. 'euler-finance', 'curve-alchemix', 'case-2026-001').",
        min_length=1,
        max_length=128,
    )
    observed_facts: list[ObservedFact] = Field(
        default_factory=list,
        description="List of verified, objective on-chain facts (transfers, txs, blocks).",
    )
    rule_detections: list[RuleDetection] = Field(
        default_factory=list,
        description="List of Rule Engine detections and alerts retrieved from the evidence database.",
    )
    external_labels: list[ExternalLabel] = Field(
        default_factory=list,
        description="Third-party intelligence claims, clearly delineated from ground truth facts.",
    )
    analyst_interpretations: list[AnalystInterpretation] = Field(
        default_factory=list,
        description="Model analytical hypotheses and behavioral explanations with explicit confidence scores.",
    )
    ml_detections: list[MLAnomalyDetection] = Field(
        default_factory=list,
        description="Machine learning anomaly detections with quantitative XAI attributions.",
    )
    mitre_mappings: list[MitreAttackMapping] = Field(
        default_factory=list,
        description="Formal MITRE ATT&CK taxonomy mappings substantiated by canonical evidence refs.",
    )
    chronological_timeline: list[Union[dict[str, Any], str]] = Field(
        default_factory=list,
        description="Chronological event summaries reconstructed from on-chain evidence.",
    )
    investigative_observations: list[str] = Field(
        default_factory=list,
        description="General investigative observations grounded in tool outputs.",
    )
    conclusions: list[str] = Field(
        default_factory=list,
        description="High-level forensic findings supported by observed facts and detections.",
    )
    uncertainty_and_limitations: list[str] = Field(
        default_factory=list,
        description="Explicit documentation of data gaps, missing ranges, unverified assumptions, or analysis boundaries.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Investigation run metadata (timestamp, model, provider, tool step counts).",
    )

    @model_validator(mode="after")
    def validate_hypothesis_fact_references(self) -> ForensicInvestigationOutput:
        """Validates that supporting_fact_indices reference valid observed_facts elements."""
        num_facts = len(self.observed_facts)
        for interp in self.analyst_interpretations:
            for idx in interp.supporting_fact_indices:
                if idx < 0 or idx >= num_facts:
                    raise ValueError(
                        f"AnalystInterpretation {interp.hypothesis_id!r} references non-existent fact index {idx}. Valid range is 0 to {num_facts - 1}."
                    )
        return self

    def get_verified_volume_by_asset(self) -> dict[str, int]:
        """Calculates total integer volume transferred per asset strictly from observed facts."""
        volumes: dict[str, int] = {}
        for fact in self.observed_facts:
            asset = fact.asset_id
            amt = int(fact.amount_raw)
            volumes[asset] = volumes.get(asset, 0) + amt
        return volumes
