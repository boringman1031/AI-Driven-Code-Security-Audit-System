import asyncio
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator

from backend.config import get_settings
from backend.analyzer.base import Finding
from backend.analyzer.openai_analyzer import OpenAIAnalyzer
from backend.analyzer.ollama_analyzer import OllamaAnalyzer
from backend.rag.vector_store import VectorStore
from backend.rag.retriever import Retriever
from backend.input_handler.file_reader import read_uploaded_bytes
from backend.input_handler.directory_walker import walk_directory
from backend.input_handler.github_fetcher import fetch_github_repo
from backend.reporter.html_report import generate_report

router = APIRouter(prefix="/api", tags=["scan"])

_MAX_SNIPPET = 50_000

# ── 目錄掃描任務狀態儲存（記憶體中） ─────────────────────────────────
# 格式: { scan_id: { status, files_total, files_done, findings, error } }
_scan_tasks: dict[str, dict] = {}


class ScanRequest(BaseModel):
    input_type: Literal["snippet", "github"]
    content: str = ""
    filename: str = "code_snippet"
    url: str = ""
    backend: Literal["openai", "ollama"] = "openai"

    @field_validator("content")
    @classmethod
    def check_content_length(cls, v: str) -> str:
        if len(v) > _MAX_SNIPPET:
            raise ValueError(f"程式碼長度超過上限 ({_MAX_SNIPPET:,} 字元)")
        return v


class DirectoryScanRequest(BaseModel):
    directory: str
    backend: Literal["openai", "ollama"] = "openai"


# ── 工廠函數 ──────────────────────────────────────────────────────────


def _make_analyzer(backend: str):
    if backend == "ollama":
        return OllamaAnalyzer()
    return OpenAIAnalyzer()


def _make_retriever() -> Retriever:
    settings = get_settings()
    return Retriever(VectorStore(settings.chroma_dir))


def _build_result(findings: list[Finding], scan_id: str, files_scanned: int) -> dict:
    counts = Counter(f.severity for f in findings)
    return {
        "scan_id": scan_id,
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "summary": {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
        },
        "findings": [f.to_dict() for f in findings],
        "report_url": f"/api/reports/{scan_id}",
    }


def _run_directory_scan(scan_id: str, directory: str, backend: str) -> None:
    """背景執行目錄掃描，更新 _scan_tasks 狀態。"""
    task = _scan_tasks[scan_id]
    try:
        code_files = walk_directory(directory)
        task["files_total"] = len(code_files)

        if not code_files:
            task["status"] = "completed"
            task["findings"] = []
            generate_report([], {"input_type": "directory", "directory": directory, "backend": backend}, scan_id)
            return

        analyzer = _make_analyzer(backend)
        retriever = _make_retriever()
        all_findings: list[Finding] = []

        for cf in code_files:
            ctx = retriever.get_context(cf.content)
            all_findings.extend(analyzer.analyze(cf.content, cf.filename, ctx))
            task["files_done"] += 1

        meta = {"input_type": "directory", "directory": directory, "backend": backend}
        generate_report(all_findings, meta, scan_id)
        task["findings"] = [f.to_dict() for f in all_findings]
        task["status"] = "completed"

    except Exception as exc:  # noqa: BLE001
        task["status"] = "error"
        task["error"] = str(exc)


# ── 端點 ──────────────────────────────────────────────────────────────


@router.post("/scan")
async def scan_text(req: ScanRequest):
    """掃描貼上的程式碼片段或 GitHub Repository。"""
    scan_id = str(uuid.uuid4())
    analyzer = _make_analyzer(req.backend)
    retriever = _make_retriever()

    try:
        if req.input_type == "snippet":
            if not req.content.strip():
                raise HTTPException(status_code=400, detail="程式碼內容不得為空")
            ctx = retriever.get_context(req.content)
            findings = analyzer.analyze(req.content, req.filename, ctx)
            files_scanned = 1
            meta = {"input_type": "snippet", "filename": req.filename, "backend": req.backend}

        else:  # github
            if not req.url.strip():
                raise HTTPException(status_code=400, detail="GitHub URL 不得為空")
            code_files = fetch_github_repo(req.url)
            if not code_files:
                raise HTTPException(
                    status_code=404,
                    detail="未在該 Repository 找到可掃描的程式碼檔案",
                )
            findings = []
            for cf in code_files:
                ctx = retriever.get_context(cf.content)
                findings.extend(analyzer.analyze(cf.content, cf.filename, ctx))
            files_scanned = len(code_files)
            meta = {"input_type": "github", "url": req.url, "backend": req.backend}

    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=422, detail=str(e))

    generate_report(findings, meta, scan_id)
    return _build_result(findings, scan_id, files_scanned)


@router.post("/scan/upload")
async def scan_upload(
    file: UploadFile = File(...),
    backend: str = Form("openai"),
):
    """上傳單一程式碼檔案進行掃描。"""
    if backend not in ("openai", "ollama"):
        raise HTTPException(status_code=400, detail="backend 必須為 openai 或 ollama")

    content_bytes = await file.read()
    try:
        code_file = read_uploaded_bytes(file.filename or "uploaded_file", content_bytes)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))

    scan_id = str(uuid.uuid4())
    analyzer = _make_analyzer(backend)
    retriever = _make_retriever()

    ctx = retriever.get_context(code_file.content)
    findings = analyzer.analyze(code_file.content, code_file.filename, ctx)
    meta = {"input_type": "file", "filename": code_file.filename, "backend": backend}
    generate_report(findings, meta, scan_id)
    return _build_result(findings, scan_id, 1)


@router.post("/scan/directory")
async def scan_directory(req: DirectoryScanRequest, background_tasks: BackgroundTasks):
    """提交目錄掃描任務，立即回傳 scan_id 供前端輪詢進度。"""
    # 驗證目錄路徑（防止路徑穿越）
    try:
        target = Path(req.directory).resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="無效的目錄路徑")

    if not target.is_dir():
        raise HTTPException(status_code=404, detail=f"目錄不存在: {req.directory}")

    scan_id = str(uuid.uuid4())
    _scan_tasks[scan_id] = {
        "status": "running",
        "files_total": 0,
        "files_done": 0,
        "findings": [],
        "error": None,
        "directory": str(target),
        "backend": req.backend,
    }

    background_tasks.add_task(_run_directory_scan, scan_id, str(target), req.backend)
    return {"scan_id": scan_id, "status": "running", "directory": str(target)}


@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """查詢目錄掃描進度。"""
    if not all(c.isalnum() or c == "-" for c in scan_id):
        raise HTTPException(status_code=400, detail="無效的 scan_id 格式")

    task = _scan_tasks.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail="找不到該掃描任務")

    resp: dict = {
        "scan_id": scan_id,
        "status": task["status"],
        "files_total": task["files_total"],
        "files_done": task["files_done"],
    }

    if task["status"] == "error":
        resp["error"] = task["error"]
    elif task["status"] == "completed":
        counts = Counter(f["severity"] for f in task["findings"])
        resp["total_findings"] = len(task["findings"])
        resp["summary"] = {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
        }
        resp["findings"] = task["findings"]
        resp["report_url"] = f"/api/reports/{scan_id}"

    return resp


@router.get("/reports")
async def list_reports():
    """列出所有已完成的掃描報告。"""
    settings = get_settings()
    reports_dir = Path(settings.reports_dir)
    if not reports_dir.is_dir():
        return {"reports": []}

    reports = []
    for html_file in sorted(reports_dir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True):
        stat = html_file.stat()
        scan_id = html_file.stem
        # scan_id 格式驗證（UUID）
        if not all(c.isalnum() or c == "-" for c in scan_id):
            continue
        reports.append({
            "scan_id": scan_id,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "size_bytes": stat.st_size,
            "report_url": f"/api/reports/{scan_id}",
        })

    return {"reports": reports}


@router.get("/reports/{scan_id}", include_in_schema=False)
async def get_report(scan_id: str):
    """取得指定掃描的 HTML 報告。"""
    # 防止路徑穿越攻擊：scan_id 只能包含英數字與連字號
    if not all(c.isalnum() or c == "-" for c in scan_id):
        raise HTTPException(status_code=400, detail="無效的 scan_id 格式")

    settings = get_settings()
    report_path = Path(settings.reports_dir) / f"{scan_id}.html"
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="找不到該報告")

    return FileResponse(str(report_path), media_type="text/html")
