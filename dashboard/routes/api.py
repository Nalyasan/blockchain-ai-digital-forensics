"""API Routes for Forensic Dashboard (dashboard/routes/api.py).

Provides REST endpoints for:
- Job submission & lifecycle (start, poll, cancel, logs, history)
- Artifact download & preview (report.html, report.json, evidence_manifest.json, custody_receipts.json, execution_log.txt)
- Canonical database integrity verification
- AI, ML, ZKML, and Blockchain status queries

Zero arbitrary shell, SQL, or transaction execution endpoints.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import logging
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


from dashboard.schemas import (
    CancelJobResponse,
    JobStatusResponse,
    LaunchInvestigationRequest,
    SystemStatusResponse,
)
from dashboard.services.job_manager import JobConflictError, get_job_manager
from forensics.paths import (
    get_benchmark_db,
    get_circuits_dir,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_models_dir,
    get_real_p4_db,
    get_rpc_url,
    resolve_foundry_binary,
)
from forensics.service import (
    InvestigationConfig,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_RUNNING,
    STATUS_STOPPED,
    VIETNAMESE_STATUS_MAP,
    compute_sha256,
)
from forensics.ingestion import (
    CorruptedFileError,
    EvidenceIngestionPipeline,
    FormatError,
    IngestionError,
    SchemaCompatibilityError,
    SecurityError,
)
from forensics.rpc_guard import (
    ReadOnlyViolationError,
    RpcAllowlistError,
    RpcConnectionError,
    SSRFSecurityError,
)
from forensics.live_collector import (
    LiveInvestigationRequest,
    LiveInvestigationResult,
    LiveRpcCollector,
)

logger = logging.getLogger("dashboard.routes.api")
CASE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RpcPreflightRequest(BaseModel):
    rpc_url: str = Field(..., description="Target JSON-RPC URL endpoint")
    allow_local: bool = Field(default=False, description="Allow local loopback for Anvil testing")
    custom_allowlist: Optional[List[str]] = Field(default=None, description="Optional custom allowlist entries")


class RpcInvestigationRequest(BaseModel):
    case_id: str = Field(..., description="Target Case ID")
    rpc_url: str = Field(..., description="Target JSON-RPC URL endpoint")
    network_name: Optional[str] = Field(default=None, description="Optional network name")
    block_range: Optional[Tuple[int, int]] = Field(default=None, description="Block range [start_block, end_block]")
    tx_hashes: List[str] = Field(default_factory=list, description="Transaction hashes to investigate")
    addresses: List[str] = Field(default_factory=list, description="Addresses to investigate")
    contract_addresses: List[str] = Field(default_factory=list, description="Contract addresses to investigate")
    max_blocks: int = Field(default=50, ge=1, le=500, description="Maximum blocks to query")
    limit_requests: int = Field(default=150, ge=1, le=500, description="Maximum RPC requests allowed")
    timeout: int = Field(default=30, ge=5, le=120, description="Network timeout in seconds")
    allow_local: bool = Field(default=False, description="Allow local loopback for Anvil testing")
    continue_case: bool = Field(default=False, description="Continue existing case flag")
    run_id: Optional[str] = Field(default=None, description="Optional custom run ID")


RpcPreflightRequest.model_rebuild()
RpcInvestigationRequest.model_rebuild()




def _validate_case_id(case_id: str) -> str:
    """Validates case_id against regex and path traversal attacks."""
    if not case_id or not isinstance(case_id, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Mã vụ việc (Case ID) không được để trống.",
        )
    cid = case_id.strip()
    if not CASE_ID_REGEX.fullmatch(cid):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Mã vụ việc '{case_id}' không hợp lệ. Chỉ chấp nhận ký tự chữ cái, số, gạch nối (-) và gạch dưới (_), độ dài 1-64 ký tự.",
        )
    if ".." in cid or "/" in cid or "\\" in cid or "\x00" in cid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Mã vụ việc không được chứa ký tự đường dẫn nguy hiểm.",
        )
    return cid

router = APIRouter(prefix="/api", tags=["api"])


@router.post("/investigations", response_model=JobStatusResponse, status_code=status.HTTP_201_CREATED)
def launch_investigation(req: LaunchInvestigationRequest) -> Any:
    """Launches a new forensic investigation or demo replay session."""
    jm = get_job_manager()

    # Enforce duplicate checking: if case_id exists and user didn't specify continue_case, reject with 409
    existing_jobs = jm.list_jobs(limit=1000)
    existing_case_ids = {j.get("case_id") for j in existing_jobs if j.get("case_id")}
    if req.case_id in existing_case_ids and not req.continue_case:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Mã vụ việc '{req.case_id}' đã tồn tại trong hệ thống. Vui lòng chọn mã khác hoặc chuyển sang chức năng 'Tiếp tục điều tra'.",
        )

    try:
        cfg = InvestigationConfig(
            case_id=req.case_id,
            mode=req.mode,
            demo_target=req.demo_target,
            db_path=Path(req.db_path) if req.db_path else None,
            ai_provider=req.ai_provider,
            ai_model=req.ai_model,
            ai_api_key=req.ai_api_key,
            ai_base_url=req.ai_base_url,
            ai_consent=req.ai_consent,
            enable_onchain_write=req.enable_onchain_write,
            is_mock=req.is_mock,
        )
        job = jm.submit_job(cfg)
        return job
    except JobConflictError as jce:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(jce),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi khởi động phiên điều tra: {e}",
        )


@router.get("/investigations", response_model=List[JobStatusResponse])
def list_investigations(limit: int = Query(default=50, ge=1, le=200)) -> Any:
    """Lists recent investigation sessions."""
    jm = get_job_manager()
    return jm.list_jobs(limit=limit)


@router.get("/investigations/{run_id}", response_model=JobStatusResponse)
def get_investigation(run_id: str) -> Any:
    """Retrieves status and results for a specific investigation run."""
    jm = get_job_manager()
    job = jm.get_job(run_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy phiên điều tra: {run_id}",
        )
    return job


@router.post("/investigations/{run_id}/cancel", response_model=CancelJobResponse)
def cancel_investigation(run_id: str) -> Any:
    """Cooperatively cancels an ongoing investigation."""
    jm = get_job_manager()
    success = jm.cancel_job(run_id)
    if not success:
        job = jm.get_job(run_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Không tìm thấy phiên điều tra: {run_id}",
            )
        return CancelJobResponse(
            success=False,
            run_id=run_id,
            message=f"Phiên điều tra {run_id} không ở trạng thái đang xử lý (trạng thái: {job.get('vietnamese_status')}).",
        )
    return CancelJobResponse(
        success=True,
        run_id=run_id,
        message=f"Đã gửi tín hiệu dừng an toàn tới phiên {run_id}.",
    )


@router.get("/investigations/{run_id}/logs")
def get_investigation_logs(run_id: str, offset: int = Query(default=0, ge=0)) -> Any:
    """Retrieves log lines for a specific job starting from line offset."""
    jm = get_job_manager()
    logs, total = jm.get_logs(run_id, offset=offset)
    return {
        "run_id": run_id,
        "offset": offset,
        "count": len(logs),
        "total": total,
        "logs": logs,
    }


@router.get("/investigations/{run_id}/artifacts/{artifact_name}")
def get_investigation_artifact(run_id: str, artifact_name: str) -> Any:
    """Downloads or previews one of the session artifacts."""
    jm = get_job_manager()
    job = jm.get_job(run_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy phiên điều tra: {run_id}",
        )

    artifacts = job.get("artifacts", {})
    clean_name = artifact_name.replace(".json", "").replace(".html", "").replace(".txt", "").replace(".csv", "")

    # Look up by key or exact filename
    target_path_str = artifacts.get(clean_name) or artifacts.get(artifact_name)
    if not target_path_str:
        # Check files in session folder
        for k, v in artifacts.items():
            if Path(v).name == artifact_name:
                target_path_str = v
                break
        # Fallback between investigation_report.html and report.html
        if not target_path_str and artifact_name in ("investigation_report.html", "report.html"):
            for alt in ("investigation_report.html", "report.html"):
                for k, v in artifacts.items():
                    alt_path = Path(v).parent / alt
                    if alt_path.is_file():
                        target_path_str = str(alt_path)
                        break
                if target_path_str:
                    break
            if not target_path_str and "report_html" in artifacts and Path(artifacts["report_html"]).is_file():
                target_path_str = artifacts["report_html"]

    if not target_path_str or not Path(target_path_str).is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy hiện vật '{artifact_name}' trong phiên {run_id}.",
        )

    file_path = Path(target_path_str)
    media_type = "text/plain"
    if file_path.suffix == ".html":
        media_type = "text/html"
    elif file_path.suffix == ".json":
        media_type = "application/json"
    elif file_path.suffix == ".csv":
        media_type = "text/csv"

    return FileResponse(file_path, media_type=media_type, filename=file_path.name)


@router.get("/cases")
def list_cases() -> Any:
    """Lists distinct case IDs and their associated runs."""
    jm = get_job_manager()
    jobs = jm.list_jobs(limit=1000)
    cases: Dict[str, List[Dict[str, Any]]] = {}
    for j in jobs:
        cid = j.get("case_id") or "unspecified"
        if cid not in cases:
            cases[cid] = []
        cases[cid].append({
            "run_id": j.get("run_id"),
            "status": j.get("status"),
            "vietnamese_status": j.get("vietnamese_status"),
            "start_time": j.get("start_time"),
        })
    return cases


@router.post("/cases/{case_id}/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_evidence_file(
    case_id: str,
    file: UploadFile = File(...),
    source_type: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
) -> Any:
    """Ingests, validates, normalizes, analyzes, and archives an evidence file into the case vault."""
    valid_case_id = _validate_case_id(case_id)

    # Validate filename to reject path traversal in uploaded name
    original_name = file.filename or "evidence.dat"
    if ".." in original_name or "/" in original_name or "\\" in original_name or "\x00" in original_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Tên tệp '{original_name}' không hợp lệ hoặc chứa ký tự đường dẫn nguy hiểm.",
        )

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Không thể đọc nội dung tệp tải lên: {e}",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tệp tải lên rỗng (0 bytes). Vui lòng chọn tệp chứng cứ hợp lệ.",
        )

    pipeline = EvidenceIngestionPipeline()
    try:
        result = pipeline.ingest_bytes(
            case_id=valid_case_id,
            file_bytes=content,
            original_filename=original_name,
            source_type=source_type,
            description=description,
        )
        return {
            "evidence_id": result.evidence_id,
            "sha256": result.sha256,
            "original_filename": result.original_filename,
            "source_type": result.source_type,
            "records_count": result.records_count,
            "run_id": result.run_id,
            "anomalies_count": result.anomalies_count,
            "statistics": result.statistics,
            "status": "completed",
            "message": "Nhập tệp chứng cứ thành công và đã hoàn tất phân tích qua adapter.",
        }
    except FormatError as fe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(fe))
    except CorruptedFileError as cfe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(cfe))
    except SchemaCompatibilityError as sce:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(sce))
    except SecurityError as se:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(se))
    except IngestionError as ie:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ie))
    except Exception as e:
        logger.exception("Unexpected error during evidence ingestion: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi không xác định trong quá trình phân tích chứng cứ: {e}",
        )


@router.get("/cases/{case_id}/evidence")
def list_case_evidence(case_id: str) -> Any:
    """Lists all ingested evidence files and their metadata for a given case."""
    valid_case_id = _validate_case_id(case_id)
    pipeline = EvidenceIngestionPipeline()
    index_file = pipeline.cases_dir / valid_case_id / "evidence" / "evidence_index.json"
    if not index_file.is_file():
        return []
    try:
        with open(index_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.warning("Error reading case evidence index: %s", e)
        return []


@router.get("/cases/{case_id}/evidence/{evidence_id}")
def get_case_evidence_detail(case_id: str, evidence_id: str) -> Any:
    """Retrieves metadata and normalized preview for a specific ingested evidence file."""
    valid_case_id = _validate_case_id(case_id)
    clean_ev_id = "".join(c for c in evidence_id if c.isalnum() or c in "-_")
    if not clean_ev_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mã chứng cứ không hợp lệ.")

    pipeline = EvidenceIngestionPipeline()
    vault_dir = pipeline.cases_dir / valid_case_id / "evidence"
    index_file = vault_dir / "evidence_index.json"

    found_meta = None
    if index_file.is_file():
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                items = json.load(f)
                for item in items:
                    if item.get("evidence_id") == clean_ev_id:
                        found_meta = item
                        break
        except Exception:
            pass

    if not found_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy chứng cứ '{clean_ev_id}' trong vụ việc '{valid_case_id}'.",
        )

    # Load preview of normalized records if available
    normalized_file = vault_dir / f"{clean_ev_id}_normalized.json"
    records_preview: List[Dict[str, Any]] = []
    if normalized_file.is_file():
        try:
            with open(normalized_file, "r", encoding="utf-8") as f:
                all_records = json.load(f)
                records_preview = all_records[:50] if isinstance(all_records, list) else []
        except Exception:
            pass

    return {
        "metadata": found_meta,
        "sample_records": records_preview,
    }


@router.get("/system/status", response_model=SystemStatusResponse)
def get_system_status() -> Any:
    """Returns system status, active job, and canonical database hashes."""
    jm = get_job_manager()
    active_job = jm.get_active_job()

    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }

    db_info: Dict[str, Dict[str, Any]] = {}
    for name, path in dbs.items():
        if path.is_file():
            db_info[name] = {
                "exists": True,
                "size_bytes": path.stat().st_size,
                "sha256": compute_sha256(path),
                "path": str(path),
            }
        else:
            db_info[name] = {"exists": False}

    return SystemStatusResponse(
        is_busy=jm.is_busy(),
        active_job_id=active_job.get("run_id") if active_job else None,
        canonical_databases=db_info,
        ai_configuration={
            "default_provider": "ollama",
            "default_model": "qwen3:8b",
            "supported_providers": ["ollama", "openai", "anthropic", "google", "custom", "deterministic_fallback"],
            "air_gap_enabled": True,
        },
        foundry_toolchain={
            "anvil": resolve_foundry_binary("anvil"),
            "cast": resolve_foundry_binary("cast"),
            "forge": resolve_foundry_binary("forge"),
        },
        server_time_utc=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/evidence/canonical")
def get_canonical_evidence_summary() -> Any:
    """Summarizes canonical SQLite evidence tables and record counts."""
    real_db = get_real_p4_db()
    if not real_db.is_file():
        raise HTTPException(status_code=500, detail="real_p4.db missing")

    uri = f"{real_db.as_uri()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        counts = {}
        for t in tables:
            try:
                cnt = conn.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
                counts[t] = cnt
            except Exception:
                pass

        return {
            "database": "real_p4.db",
            "path": str(real_db),
            "sha256": compute_sha256(real_db),
            "table_counts": counts,
        }
    finally:
        conn.close()


@router.get("/ml/model")
def get_ml_model_details() -> Any:
    """Returns P8 ML CompactAnomalyMLP details, frozen weights status, and XAI feature schema."""
    onnx_file = get_models_dir() / "anomaly_detector_v1.onnx"
    meta_file = get_models_dir() / "anomaly_detector_v1_meta.json"

    meta_content = {}
    if meta_file.is_file():
        try:
            meta_content = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {
        "model_id": "anomaly_detector_v1",
        "architecture": "CompactMLP (10 features, 3 layers, 321 parameters)",
        "model_sha256": compute_sha256(onnx_file) if onnx_file.is_file() else "",
        "frozen": True,
        "xai_explainer": "Exact Shapley Explainer (1,024 coalitions)",
        "metadata": meta_content,
        "positive_labels_reconciliation": {
            "heuristic_cooccurrence_labels": 979,
            "ground_truth_attack_labels": 12,
            "total_samples": 5265,
            "auroc": 0.4776,
            "freeze_rationale": "Bảo toàn mạch ZKML Halo2 và mã bytecode hợp đồng thông minh InferenceVerifier.sol",
        },
    }


@router.get("/zkml/proof")
def get_zkml_proof_details() -> Any:
    """Returns P9 Halo2 ZKML proof verification metadata."""
    circuits_dir = get_circuits_dir() / "anomaly_detector_v1"
    proof_file = circuits_dir / "baseline_proof.json"
    vk_file = circuits_dir / "vk.key"
    srs_file = circuits_dir / "kzg.srs"

    return {
        "circuit": "anomaly_detector_v1",
        "system": "Halo2 BN254 KZG via EZKL",
        "proof_file": str(proof_file),
        "proof_sha256": compute_sha256(proof_file) if proof_file.is_file() else "",
        "vk_file": str(vk_file),
        "vk_sha256": compute_sha256(vk_file) if vk_file.is_file() else "",
        "srs_file": str(srs_file),
        "srs_sha256": compute_sha256(srs_file) if srs_file.is_file() else "",
        "onchain_verifiers": [
            "InferenceVerifier.sol (Chống phát lại ProofAlreadyVerified, Bất biến RecordAlreadyExists)",
            "Halo2Verifier.sol (Hàm verifyProof thuần view)",
        ],
    }


@router.get("/blockchain/status")
def get_blockchain_status() -> Any:
    """Returns local Anvil RPC connectivity and Chain of Custody contract details."""
    rpc_url = get_rpc_url()
    is_connected = False
    chain_id = None
    try:
        from forensics.did.client import rpc_read
        raw = rpc_read(rpc_url, "eth_chainId", [])
        chain_id = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") else int(raw)
        is_connected = (chain_id == 31337)
    except Exception:
        pass

    return {
        "rpc_url": rpc_url,
        "connected": is_connected,
        "chain_id": chain_id,
        "standard": "ERC-1056 W3C DID & EIP-712 Custody Attestation",
        "read_only_default": True,
    }


@router.post("/rpc/preflight")
def rpc_preflight_check(req: RpcPreflightRequest) -> Any:
    """Pre-validates RPC endpoint against Anti-SSRF rules, verifies connectivity,
    fetches chain ID and latest block, and returns an environmental safety report."""
    collector = LiveRpcCollector()
    try:
        report = collector.preflight_check(
            rpc_url=req.rpc_url,
            allow_local=req.allow_local,
            custom_allowlist=req.custom_allowlist,
        )
        return report
    except (SSRFSecurityError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Vi phạm chốt chặn an toàn Anti-SSRF hoặc URL không hợp lệ: {e}",
        )
    except RpcAllowlistError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"RPC Endpoint không nằm trong danh sách cấp quyền: {e}",
        )
    except ReadOnlyViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Thao tác thay đổi trạng thái bị nghiêm cấm: {e}",
        )
    except RpcConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Không thể kết nối hoặc nhận phản hồi từ node RPC: {e}",
        )
    except Exception as e:
        logger.exception("Unexpected error during RPC preflight: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi kiểm tra node RPC: {e}",
        )


@router.post("/rpc/investigate", status_code=status.HTTP_201_CREATED)
def rpc_investigate(req: RpcInvestigationRequest) -> Any:
    """Initiates bounded safe live blockchain RPC data collection and analysis
    in isolated case storage, generating standalone forensic reports."""
    valid_case_id = _validate_case_id(req.case_id)

    # Validate Anti-SSRF and allowlist upfront
    from forensics.rpc_guard import validate_rpc_url
    try:
        validate_rpc_url(req.rpc_url, allow_local=req.allow_local, raise_on_error=True)
    except (SSRFSecurityError, ValueError) as se:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Vi phạm chốt chặn an toàn Anti-SSRF hoặc URL không hợp lệ: {se}",
        )
    except RpcAllowlistError as ae:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"RPC Endpoint không nằm trong danh sách cấp quyền: {ae}",
        )

    # Check duplicate case ID unless continue_case is True
    jm = get_job_manager()
    existing_jobs = jm.list_jobs(limit=1000)
    existing_case_ids = {j.get("case_id") for j in existing_jobs if j.get("case_id")}
    if valid_case_id in existing_case_ids and not req.continue_case:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Mã vụ việc '{valid_case_id}' đã tồn tại trong hệ thống. Vui lòng chọn mã khác hoặc xác nhận tiếp tục điều tra.",
        )


    collector = LiveRpcCollector()
    live_req = LiveInvestigationRequest(
        case_id=valid_case_id,
        rpc_url=req.rpc_url,
        network_name=req.network_name,
        block_range=req.block_range,
        tx_hashes=req.tx_hashes,
        addresses=req.addresses,
        contract_addresses=req.contract_addresses,
        max_blocks=req.max_blocks,
        limit_requests=req.limit_requests,
        timeout_seconds=req.timeout,
        allow_local=req.allow_local,
        run_id=req.run_id,
    )

    try:
        result = collector.collect_and_investigate(live_req)
        return {
            "run_id": result.run_id,
            "case_id": result.case_id,
            "rpc_url": result.rpc_url,
            "chain_id": result.chain_id,
            "network_name": result.network_name,
            "is_synthetic": result.is_synthetic,
            "start_block": result.start_block,
            "end_block": result.end_block,
            "blocks_collected": result.blocks_collected,
            "transactions_collected": result.transactions_collected,
            "logs_collected": result.logs_collected,
            "anomalies_count": result.anomalies_count,
            "sha256": result.sha256,
            "output_dir": result.output_dir,
            "report_html_path": result.report_html_path,
            "address_guardrail_notes": result.address_guardrail_notes,
            "status": result.status,
            "message": "Điều tra chuỗi khối trực tiếp hoàn tất thành công.",
        }
    except (SSRFSecurityError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Vi phạm chốt chặn an toàn Anti-SSRF hoặc tham số không hợp lệ: {e}",
        )
    except RpcAllowlistError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"RPC Endpoint không nằm trong danh sách cấp quyền: {e}",
        )
    except ReadOnlyViolationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Thao tác thay đổi trạng thái bị nghiêm cấm: {e}",
        )
    except RpcConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Lỗi kết nối node RPC trong quá trình thu thập: {e}",
        )
    except Exception as e:
        logger.exception("Unexpected error during RPC investigation: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi thực thi điều tra chuỗi khối trực tiếp: {e}",
        )

