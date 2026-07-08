"""Investigation lifecycle endpoints."""

from datetime import datetime
from pathlib import Path
import shutil
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app_context import OUTPUT_DIR, session_store
from routers.auth import get_current_user
from services.llm_service import get_ready_provider_snapshot
from services.orchestrator_service import run_investigation_pipeline
from services.report_pdf_service import ReportPdfError, render_html_report_pdf


PUBLIC_ERROR_MESSAGE = "Investigation failed. Check backend logs for details."


router = APIRouter(prefix="/api", tags=["investigation"])


class RenameSessionPayload(BaseModel):
    title: str = Field(min_length=1, max_length=120)


class ReportPdfPayload(BaseModel):
    html: str = Field(min_length=1, max_length=5_000_000)
    filename: str = Field(default="report.pdf", min_length=1, max_length=160)


def _safe_child_path(base_dir: Path, child_name: str) -> Path:
    base_path = base_dir.resolve()
    child_path = (base_path / child_name).resolve()

    if child_path.parent != base_path:
        raise HTTPException(status_code=400, detail="Invalid session id")

    return child_path


def _safe_export_path(session_id: str, export_path: str) -> Path:
    base_export_dir = (OUTPUT_DIR / session_id / "exports").resolve()
    path_obj = Path(export_path).resolve()
    if base_export_dir not in path_obj.parents:
        raise HTTPException(status_code=400, detail="Invalid export path")
    if not path_obj.exists() or not path_obj.is_file():
        raise HTTPException(status_code=404, detail="Export artifact not found")
    return path_obj


def _session_sort_key(item: dict[str, Any]) -> str:
    return (
        item.get("last_update")
        or item.get("completion_time")
        or item.get("upload_time")
        or item.get("session_id")
        or ""
    )


def _session_history_item(session_id: str, session: dict[str, Any]) -> dict[str, Any]:
    raw_report = session.get("report")
    report = raw_report if isinstance(raw_report, dict) else {}
    raw_metadata = report.get("metadata")
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}

    return {
        "session_id": session_id,
        "title": session.get("title"),
        "file_name": session.get("file_name"),
        "status": session.get("status", "pending"),
        "stage": session.get("stage", "pending"),
        "progress": session.get("progress", 0),
        "current_message": session.get("current_message", ""),
        "upload_time": session.get("upload_time"),
        "last_update": session.get("last_update"),
        "completion_time": session.get("completion_time"),
        "report_id": metadata.get("report_id"),
        "severity": metadata.get("severity"),
        "user_profile": session.get("user_profile"),
        "summary": {
            "parsed_logs": session.get("parsed_logs_count"),
            "templates": session.get("templates_count"),
            "anomalies": session.get("anomalies_count"),
        },
    }


def _get_owned_session(
    session_id: str,
    current_user: dict[str, Any],
    *,
    touch: bool = False,
) -> dict[str, Any]:
    session = session_store.get_session(session_id, touch=touch)
    if session is None or session.get("user_id") != current_user.get("id"):
        raise HTTPException(status_code=404, detail="Session not found")
    return session


def _sanitize_public_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).replace("\r", "").strip("\n")
    if len(cleaned) > 1200:
        return f"{cleaned[:1200]}..."
    return cleaned


def _safe_download_filename(value: str, fallback: str = "report.pdf") -> str:
    cleaned = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in str(value or "")
    ).strip(".-")
    if not cleaned:
        cleaned = fallback
    if not cleaned.lower().endswith(".pdf"):
        cleaned = f"{cleaned}.pdf"
    return cleaned[:160]


def _public_activity_events(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Return sanitized activity events safe for the frontend terminal."""
    events = session.get("activity_events")
    if not isinstance(events, list):
        return []

    public_events = []
    for event in events:
        if not isinstance(event, dict):
            continue
        public_events.append(
            {
                "sequence": event.get("sequence"),
                "timestamp": event.get("timestamp"),
                "stage": event.get("stage"),
                "action": event.get("action"),
                "level": event.get("level"),
                "line": _sanitize_public_text(event.get("line")),
                "message": _sanitize_public_text(event.get("message")),
                "progress": event.get("progress"),
            }
        )

    return public_events


@router.get("/sessions")
async def list_sessions(current_user: dict[str, Any] = Depends(get_current_user)):
    """List persisted investigation sessions for ChatGPT-style history."""
    sessions = []

    for session_id in session_store:
        session = session_store.get_session(session_id, touch=False)
        if not isinstance(session, dict):
            continue
        if session.get("user_id") != current_user.get("id"):
            continue
        sessions.append(_session_history_item(session_id, session))

    sessions.sort(key=_session_sort_key, reverse=True)
    return {"sessions": sessions}


@router.patch("/sessions/{session_id}")
async def rename_session(
    session_id: str,
    payload: RenameSessionPayload,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Rename a persisted investigation session in the history list."""
    _ = _get_owned_session(session_id, current_user, touch=False)

    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title cannot be empty")

    updated_session = session_store.update_session(session_id, {
        "title": title,
        "last_update": datetime.now().isoformat(),
    })
    if updated_session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    return _session_history_item(session_id, updated_session)


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Delete a session and remove its persisted raw logs/reports."""
    _ = _get_owned_session(session_id, current_user, touch=False)

    raw_session_dir = _safe_child_path(session_store.raw_logs_dir, session_id)
    output_session_dir = _safe_child_path(OUTPUT_DIR, session_id)

    session_store.delete_session(session_id)
    shutil.rmtree(raw_session_dir, ignore_errors=True)
    shutil.rmtree(output_session_dir, ignore_errors=True)

    return {"session_id": session_id, "deleted": True}


@router.post("/investigate/{session_id}")
async def start_investigation(
    session_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Start the full investigation pipeline in the background."""
    session = _get_owned_session(session_id, current_user, touch=True)

    try:
        from modules.llm_provider import LLMProviderError

        try:
            provider_snapshot, provider_status = get_ready_provider_snapshot()
        except LLMProviderError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        session["status"] = "processing"
        session["stage"] = "pending"
        session["progress"] = 0
        session["current_message"] = "Investigation akan segera dimulai..."
        session["activity_events"] = []
        session["error"] = None
        session["llm_provider"] = provider_snapshot.get("provider")
        session["llm_model"] = provider_snapshot.get("model")
        session["llm_provider_status"] = provider_status
        session.pop("report", None)
        session.pop("report_path", None)
        session.pop("completion_time", None)
        session_store.set_session(session_id, session)

        background_tasks.add_task(run_investigation_pipeline, session_id)

        return {
            "session_id": session_id,
            "status": "processing",
            "message": "Investigation started in background. Check /api/status/{session_id} for progress.",
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=PUBLIC_ERROR_MESSAGE) from exc


@router.get("/status/{session_id}")
async def get_investigation_status(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Get current status of investigation."""
    session = _get_owned_session(session_id, current_user, touch=True)

    return {
        "session_id": session_id,
        "status": session.get("status", "pending"),
        "stage": session.get("stage", "pending"),
        "progress": session.get("progress", 0),
        "current_message": _sanitize_public_text(session.get("current_message", "")) or "",
        "activity_events": _public_activity_events(session),
        "error": PUBLIC_ERROR_MESSAGE if session.get("error") else None,
        "last_update": session.get("last_update"),
        "file_name": session.get("file_name"),
        "summary": {
            "parsed_logs": session.get("parsed_logs_count"),
            "templates": session.get("templates_count"),
            "anomalies": session.get("anomalies_count"),
        },
    }


@router.get("/report/{session_id}")
async def get_report(
    session_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Retrieve final investigation report."""
    session = _get_owned_session(session_id, current_user, touch=True)

    if session.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Investigation not completed yet")

    report = session.get("report", {})
    if report and isinstance(report, dict):
        return report

    return {
        "metadata": {
            "session_id": session_id,
            "timestamp": session.get("completion_time"),
        },
        "executive_summary": "Report not available",
    }


@router.post("/report-export/pdf")
async def export_report_pdf(
    payload: ReportPdfPayload,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Render a styled, selectable report PDF from trusted frontend HTML."""
    _ = current_user
    try:
        pdf_bytes = render_html_report_pdf(payload.html)
    except ReportPdfError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    filename = _safe_download_filename(payload.filename)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/export/{session_id}")
async def export_parsed_logs(
    session_id: str,
    format: str = Query(default="manifest"),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Download parsed-log export artifacts for downstream visualization pipelines."""
    session = _get_owned_session(session_id, current_user, touch=False)

    format_key = str(format or "manifest").strip().lower()
    supported_formats = {"manifest", "jsonl", "ndjson", "csv"}
    if format_key not in supported_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported export format. Use one of: {', '.join(sorted(supported_formats))}",
        )

    session_key_map = {
        "manifest": "parsed_export_manifest_path",
        "jsonl": "parsed_export_jsonl_path",
        "ndjson": "parsed_export_ndjson_path",
        "csv": "parsed_export_csv_path",
    }
    media_types = {
        "manifest": "application/json",
        "jsonl": "application/x-ndjson",
        "ndjson": "application/x-ndjson",
        "csv": "text/csv",
    }
    file_names = {
        "manifest": f"{session_id}-export-manifest.json",
        "jsonl": f"{session_id}-parsed-logs.jsonl",
        "ndjson": f"{session_id}-elastic-bulk.ndjson",
        "csv": f"{session_id}-parsed-logs.csv",
    }

    path_value = session.get(session_key_map[format_key])
    if not path_value:
        raise HTTPException(
            status_code=404,
            detail="Export artifact is not available yet for this session",
        )

    safe_path = _safe_export_path(session_id, str(path_value))
    return FileResponse(
        path=str(safe_path),
        media_type=media_types[format_key],
        filename=file_names[format_key],
    )
