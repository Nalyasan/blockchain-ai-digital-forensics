"""HTML Page Routes for Forensic Dashboard (dashboard/routes/pages.py).

Serves all 11 forensic dashboard pages with Jinja2 templates:
1. Overview (/ or /overview)
2. Investigation Launcher (/launcher or /investigate)
3. Live Progress (/progress or /progress/{run_id})
4. Evidence Manager (/evidence)
5. AI Investigator (/ai)
6. ML & XAI (/ml-xai)
7. Blockchain & CoC (/blockchain)
8. ZKML Verification (/zkml)
9. Demo Center (/demo-center)
10. Reports Hub (/reports or /reports/{run_id})
11. Settings (/settings)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import urllib.request

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dashboard.services.job_manager import get_job_manager
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_host,
    get_models_dir,
    get_ollama_url,
    get_output_dir,
    get_port,
    get_project_root,
    get_real_p4_db,
    get_rpc_url,
    resolve_foundry_binary,
)
from forensics.service import compute_sha256, VIETNAMESE_STATUS_MAP

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(include_in_schema=False)

STAGE_DEFINITIONS = [
    ("S1", "Tiếp nhận dữ liệu"),
    ("S2", "Kiểm tra tính toàn vẹn"),
    ("S3", "Trích xuất và chuẩn hóa chứng cứ"),
    ("S4", "Phát hiện dấu hiệu bất thường"),
    ("S5", "Phân tích AI và giải thích kết quả"),
    ("S6", "Đối chiếu dữ kiện"),
    ("S7", "Xác minh và bảo quản chứng cứ"),
    ("S8", "Tổng hợp báo cáo điều tra"),
]


def _get_canonical_dbs() -> Dict[str, Dict[str, Any]]:
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    res = {}
    for name, p in dbs.items():
        if p.is_file():
            res[name] = {
                "path": str(p),
                "size_bytes": p.stat().st_size,
                "sha256": compute_sha256(p),
            }
        else:
            res[name] = {"path": str(p), "size_bytes": 0, "sha256": "N/A"}
    return res


def get_8_stages_for_job(job: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps job execution into the 8 standardized forensic investigation stages."""
    stages = []
    if not job:
        for idx, (sid, sname) in enumerate(STAGE_DEFINITIONS, start=1):
            stages.append({
                "stage_id": sid,
                "number": idx,
                "name": sname,
                "status": "not_started",
                "vietnamese_status": "Chưa chạy",
            })
        return stages

    stage_status = job.get("stage_status") or {}
    phase_status = job.get("phase_status") or {}
    job_status = job.get("status")

    mapping = {
        "S1": ["P1"],
        "S2": ["P2"],
        "S3": ["P3"],
        "S4": ["P4"],
        "S5": ["P5", "P8"],
        "S6": ["P6", "P7"],
        "S7": ["P9", "P10"],
        "S8": ["P11"],
    }

    for idx, (sid, sname) in enumerate(STAGE_DEFINITIONS, start=1):
        if sid in stage_status and stage_status[sid] != "not_started":
            st = stage_status[sid]
        elif sid in stage_status and job_status in ("completed", "completed_with_warnings"):
            st = stage_status[sid]
        else:
            target_phases = mapping.get(sid, [])
            statuses = [phase_status.get(p, "not_started") for p in target_phases]
            if any(s == "failed" for s in statuses):
                st = "failed"
            elif any(s == "running" for s in statuses):
                st = "running"
            elif all(s == "not_applicable" for s in statuses) and len(statuses) > 0:
                st = "not_applicable"
            elif all(s in ("completed", "completed_with_warnings", "not_applicable") for s in statuses) and any(s in ("completed", "completed_with_warnings") for s in statuses):
                st = "completed"
            elif any(s == "completed" for s in statuses):
                st = "completed"
            elif sid in stage_status:
                st = stage_status[sid]
            else:
                st = "not_started"

        # Never overwrite not_applicable with completed
        if job_status in ("completed", "completed_with_warnings") and st == "not_started":
            st = "completed"

        v_st = VIETNAMESE_STATUS_MAP.get(st, st)
        if st == "not_applicable":
            v_st = "Không áp dụng"

        stages.append({
            "stage_id": sid,
            "number": idx,
            "name": sname,
            "status": st,
            "vietnamese_status": v_st,
        })
    return stages


def probe_system_health() -> Dict[str, Any]:
    """Performs live connectivity and integrity probes for all 6 core system dependencies."""
    # 1. CSDL
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    db_ok_count = sum(1 for p in dbs.values() if p.is_file())
    db_status = {
        "status": "ready" if db_ok_count == 4 else "degraded",
        "detail": f"{db_ok_count}/4 CSDL sẵn sàng (Chỉ đọc, Bitwise SHA-256)",
        "count": db_ok_count,
    }

    # 2. AI Provider (Ollama Local)
    ollama_url = get_ollama_url()
    ollama_ok = False
    ollama_detail = f"Chưa kết nối ({ollama_url})"
    try:
        req = urllib.request.Request(f"{ollama_url}/api/version", headers={"User-Agent": "ForensicsDashboard/1.0"})
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                ollama_ok = True
                ollama_detail = f"Sẵn sàng (v{data.get('version', 'unknown')})"
    except Exception:
        ollama_ok = False
        ollama_detail = f"Không thể kết nối ({ollama_url})"

    ai_status = {
        "status": "ready" if ollama_ok else "offline",
        "detail": ollama_detail,
        "provider": "Ollama Cục bộ (127.0.0.1:11434)",
        "fallback": "Động cơ Quy tắc Tất định Sẵn sàng",
    }

    # 3. RPC Node
    rpc_url = get_rpc_url()
    rpc_ok = False
    rpc_detail = f"Chưa kết nối ({rpc_url})"
    try:
        from forensics.did.client import rpc_read
        chain_id_hex = rpc_read(rpc_url, "eth_chainId", [])
        cid = int(chain_id_hex, 16) if isinstance(chain_id_hex, str) and chain_id_hex.startswith("0x") else int(chain_id_hex)
        rpc_ok = True
        rpc_detail = f"Kết nối tốt (Chain ID: {cid})"
    except Exception:
        rpc_ok = False
        rpc_detail = f"Chưa kết nối ({rpc_url})"

    rpc_status = {
        "status": "ready" if rpc_ok else "offline",
        "detail": rpc_detail,
        "url": rpc_url,
    }

    # 4. Anvil Toolchain
    anvil_bin = resolve_foundry_binary("anvil")
    anvil_status = {
        "status": "ready" if anvil_bin else "missing",
        "detail": f"Khả dụng ({Path(anvil_bin).name})" if anvil_bin else "Chưa cài đặt Foundry",
        "path": anvil_bin or "N/A",
    }

    # 5. ML Model
    onnx_file = get_models_dir() / "anomaly_detector_v1.onnx"
    ml_ok = onnx_file.is_file()
    ml_status = {
        "status": "ready" if ml_ok else "missing",
        "detail": "CompactAnomalyMLP (10 đặc trưng, 321 tham số, ONNX)" if ml_ok else "Thiếu file ONNX",
        "file": str(onnx_file),
    }

    # 6. Report Service
    reports_dir = get_output_dir()
    reports_ok = False
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        probe_file = reports_dir / ".write_probe"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink()
        reports_ok = True
        reports_detail = "Thư mục reports/ sẵn sàng ghi, Trình xuất HTML Ngoại tuyến Sẵn sàng"
    except Exception as e:
        reports_detail = f"Lỗi ghi thư mục: {e}"

    report_status = {
        "status": "ready" if reports_ok else "error",
        "detail": reports_detail,
    }

    return {
        "database": db_status,
        "ai_provider": ai_status,
        "rpc": rpc_status,
        "anvil": anvil_status,
        "ml_model": ml_status,
        "report_service": report_status,
    }


def _get_base_context(
    request: Request,
    case_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs shared context with Case & Run isolation for all business pages."""
    jm = get_job_manager()
    all_jobs = jm.list_jobs(limit=500)

    # Group runs by case_id
    available_cases: Dict[str, List[Dict[str, Any]]] = {}
    for j in all_jobs:
        cid = j.get("case_id") or "unspecified"
        if cid not in available_cases:
            available_cases[cid] = []
        available_cases[cid].append(j)

    # Determine query params if not explicitly passed
    q_case = request.query_params.get("case_id")
    q_run = request.query_params.get("run_id")
    case_id = case_id or q_case
    run_id = run_id or q_run

    selected_job = None
    if run_id:
        selected_job = jm.get_job(run_id)
        if selected_job:
            case_id = selected_job.get("case_id")
    elif case_id:
        runs_for_case = available_cases.get(case_id, [])
        if runs_for_case:
            selected_job = runs_for_case[0]
            run_id = selected_job.get("run_id")
    else:
        # Fallback to active running job, or most recent job
        selected_job = jm.get_active_job()
        if selected_job:
            run_id = selected_job.get("run_id")
            case_id = selected_job.get("case_id")
        elif all_jobs:
            selected_job = all_jobs[0]
            run_id = selected_job.get("run_id")
            case_id = selected_job.get("case_id")

    current_runs = available_cases.get(case_id, []) if case_id else []

    return {
        "project_title": "Blockchain Ai Aigital Forensics",
        "current_case_id": case_id,
        "current_run_id": run_id,
        "selected_job": selected_job,
        "available_cases": available_cases,
        "available_runs": current_runs,
    }


# 1. Overview Page (Redesigned into 4 Functional Areas)
@router.get("/", response_class=HTMLResponse)
@router.get("/overview", response_class=HTMLResponse)
def page_overview(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    jm = get_job_manager()
    active_job = jm.get_active_job()
    recent_jobs = jm.list_jobs(limit=15)
    health_probes = probe_system_health()

    active_stages = get_8_stages_for_job(active_job) if active_job else []

    ctx.update({
        "active_page": "overview",
        "total_jobs": len(jm.list_jobs(limit=1000)),
        "active_job": active_job,
        "active_stages": active_stages,
        "recent_jobs": recent_jobs,
        "canonical_dbs": _get_canonical_dbs(),
        "health_probes": health_probes,
    })
    return templates.TemplateResponse(request=request, name="overview.html", context=ctx)


# 2. Investigation Launcher Page
@router.get("/launcher", response_class=HTMLResponse)
@router.get("/investigate", response_class=HTMLResponse)
def page_launcher(
    request: Request,
    mode: Optional[str] = "MODE_B",
    continue_case: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=continue_case)
    ctx.update({
        "active_page": "launcher",
        "initial_mode": mode.upper() if mode else "MODE_B",
        "continue_case": continue_case,
        "action_mode": action or "new_case",
    })
    return templates.TemplateResponse(request=request, name="launcher.html", context=ctx)


# 3. Live Progress Page
@router.get("/progress", response_class=HTMLResponse)
@router.get("/progress/{run_id}", response_class=HTMLResponse)
def page_progress(request: Request, run_id: Optional[str] = None) -> Any:
    ctx = _get_base_context(request, run_id=run_id)
    current_job = ctx.get("selected_job")
    stages = get_8_stages_for_job(current_job)

    ctx.update({
        "active_page": "progress",
        "current_job": current_job,
        "stages_8": stages,
    })
    return templates.TemplateResponse(request=request, name="progress.html", context=ctx)


# 4. Evidence Manager Page
@router.get("/evidence", response_class=HTMLResponse)
def page_evidence(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    ctx.update({
        "active_page": "evidence",
        "canonical_dbs": _get_canonical_dbs(),
    })
    return templates.TemplateResponse(request=request, name="evidence.html", context=ctx)


# 5. AI Investigator Page
@router.get("/ai", response_class=HTMLResponse)
def page_ai(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    selected_job = ctx.get("selected_job")

    # Probe live Ollama provider
    health = probe_system_health()
    ai_health = health.get("ai_provider", {})

    # Extract AI details for selected job
    ai_sub_tasks = []
    citations = []
    p5_metrics = {}
    if selected_job:
        p5_metrics = selected_job.get("phase_metrics", {}).get("P5", {})
        citations = p5_metrics.get("citations", [])
        ai_sub_tasks = selected_job.get("ai_sub_tasks", [])

    if not ai_sub_tasks:
        from dashboard.services.job_manager import AI_SUB_TASKS_DEFINITIONS
        is_job_done = selected_job and selected_job.get("status") in ("completed", "completed_with_warnings")
        ai_sub_tasks = [
            {
                "id": tid,
                "name": tname,
                "status": "completed" if is_job_done else "not_started",
                "details": {},
            }
            for tid, tname in AI_SUB_TASKS_DEFINITIONS
        ]

    ctx.update({
        "active_page": "ai",
        "ai_health": ai_health,
        "ai_sub_tasks": ai_sub_tasks,
        "citations": citations,
        "p5_metrics": p5_metrics,
    })
    return templates.TemplateResponse(request=request, name="ai.html", context=ctx)


# 6. ML & XAI Page
@router.get("/ml-xai", response_class=HTMLResponse)
def page_ml_xai(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    ctx.update({
        "active_page": "ml_xai",
    })
    return templates.TemplateResponse(request=request, name="ml_xai.html", context=ctx)


# 7. Blockchain & CoC Page
@router.get("/blockchain", response_class=HTMLResponse)
def page_blockchain(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    ctx.update({
        "active_page": "blockchain",
    })
    return templates.TemplateResponse(request=request, name="blockchain.html", context=ctx)


# 8. ZKML Verification Page
@router.get("/zkml", response_class=HTMLResponse)
def page_zkml(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    ctx.update({
        "active_page": "zkml",
    })
    return templates.TemplateResponse(request=request, name="zkml.html", context=ctx)


# 9. Demo Center Page (Khu vực Quản trị & Thực nghiệm)
@router.get("/demo-center", response_class=HTMLResponse)
def page_demo_center(request: Request) -> Any:
    ctx = _get_base_context(request)
    ctx.update({
        "active_page": "demo_center",
    })
    return templates.TemplateResponse(request=request, name="demo_center.html", context=ctx)


# 10. Reports Hub & Detail Page
@router.get("/reports", response_class=HTMLResponse)
def page_reports(
    request: Request,
    case_id: Optional[str] = Query(default=None),
    run_id: Optional[str] = Query(default=None),
) -> Any:
    ctx = _get_base_context(request, case_id=case_id, run_id=run_id)
    jm = get_job_manager()
    all_jobs = jm.list_jobs(limit=100)
    filtered_jobs = all_jobs
    if ctx.get("current_case_id"):
        filtered_jobs = [j for j in all_jobs if j.get("case_id") == ctx.get("current_case_id")]

    ctx.update({
        "active_page": "reports",
        "jobs": filtered_jobs,
        "all_jobs": all_jobs,
    })
    return templates.TemplateResponse(request=request, name="reports.html", context=ctx)


@router.get("/reports/{run_id}", response_class=HTMLResponse)
def page_report_detail(request: Request, run_id: str) -> Any:
    ctx = _get_base_context(request, run_id=run_id)
    jm = get_job_manager()
    job = jm.get_job(run_id)
    if not job:
        raise HTTPException(status_code=404, detail="Không tìm thấy phiên điều tra")

    ctx.update({
        "active_page": "reports",
        "job": job,
    })
    return templates.TemplateResponse(request=request, name="report_detail.html", context=ctx)


# 11. Settings Page
@router.get("/settings", response_class=HTMLResponse)
def page_settings(request: Request) -> Any:
    ctx = _get_base_context(request)
    sys_info = {
        "python_version": sys.version.split()[0],
        "project_root": str(get_project_root()),
        "output_dir": str(get_output_dir()),
        "rpc_url": get_rpc_url(),
        "ollama_url": get_ollama_url(),
        "host": get_host(),
        "port": get_port(),
        "anvil_path": resolve_foundry_binary("anvil"),
        "cast_path": resolve_foundry_binary("cast"),
        "forge_path": resolve_foundry_binary("forge"),
    }
    ctx.update({
        "active_page": "settings",
        "sys_info": sys_info,
    })
    return templates.TemplateResponse(request=request, name="settings.html", context=ctx)
