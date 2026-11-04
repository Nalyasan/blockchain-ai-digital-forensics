"""Machine Learning & Explainable AI (P8) Package for Blockchain Forensics."""

from forensics.ml.features import (
    FEATURE_NAMES,
    extract_address_features,
    extract_single_address_features,
)
from forensics.ml.dataset import (
    DataLeakageError,
    DatasetSplit,
    RobustFeatureScaler,
    chronological_split,
    validate_no_data_leakage,
)
from forensics.ml.model import (
    CompactAnomalyMLP,
    load_default_model,
)
from forensics.ml.registry import (
    compute_file_sha256,
    export_to_onnx,
    load_model_metadata,
    save_model,
    verify_model_integrity,
)
from forensics.ml.xai import (
    ExactShapleyExplainer,
    XAIExplanation,
    explain_instance,
)
from forensics.ml.corroboration import (
    CorroboratedDetection,
    DualEngineCorroborator,
)
from forensics.ml.mitre import (
    MitreAttackMapping,
    MitreMappingEngine,
    UnsubstantiatedMappingError,
)

__all__ = [
    "FEATURE_NAMES",
    "extract_address_features",
    "extract_single_address_features",
    "DataLeakageError",
    "DatasetSplit",
    "RobustFeatureScaler",
    "chronological_split",
    "validate_no_data_leakage",
    "CompactAnomalyMLP",
    "load_default_model",
    "compute_file_sha256",
    "export_to_onnx",
    "load_model_metadata",
    "save_model",
    "verify_model_integrity",
    "ExactShapleyExplainer",
    "XAIExplanation",
    "explain_instance",
    "CorroboratedDetection",
    "DualEngineCorroborator",
    "MitreAttackMapping",
    "MitreMappingEngine",
    "UnsubstantiatedMappingError",
]
