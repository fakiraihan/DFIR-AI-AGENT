"""Investigation lifecycle endpoints."""

from datetime import datetime
from pathlib import Path
import shutil
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from app_context import OUTPUT_DIR, session_store
from services.llm_service import get_ready_provider_snapshot
from services.orchestrator_service import run_investigation_pipeline


PUBLIC_ERROR_MESSAGE = "Investigation failed. Check backend logs for details."


router = APIRouter(prefix="/api", tags=["investigation"])


class RenameSessionPayload(BaseModel):
    title: str = Field(min_length=1, max_length=120)


def _safe_child_path(base_dir: Path, child_name: str) -> Path:
    base_path = base_dir.resolve()
    child_path = (base_path / child_name).resolve()

    if child_path.parent != base_path:
        raise HTTPException(status_code=400, detail="Invalid session id")

    return child_path


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
        "summary": {
            "parsed_logs": session.get("parsed_logs_count"),
            "templates": session.get("templates_count"),
            "anomalies": session.get("anomalies_count"),
        },
    }


def _sanitize_public_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).replace("\r", "").strip("\n")
    if len(cleaned) > 1200:
        return f"{cleaned[:1200]}..."
    return cleaned


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
async def list_sessions():
    """List persisted investigation sessions for ChatGPT-style history."""
    sessions = []

    for session_id in session_store:
        session = session_store.get_session(session_id, touch=False)
        if session is None:
            continue
        sessions.append(_session_history_item(session_id, session))

    sessions.sort(key=_session_sort_key, reverse=True)
    return {"sessions": sessions}


@router.patch("/sessions/{session_id}")
async def rename_session(session_id: str, payload: RenameSessionPayload):
    """Rename a persisted investigation session in the history list."""
    session = session_store.get_session(session_id, touch=False)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

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
async def delete_session(session_id: str):
    """Delete a session and remove its persisted raw logs/reports."""
    session = session_store.get_session(session_id, touch=False)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    raw_session_dir = _safe_child_path(session_store.raw_logs_dir, session_id)
    output_session_dir = _safe_child_path(OUTPUT_DIR, session_id)

    session_store.delete_session(session_id)
    shutil.rmtree(raw_session_dir, ignore_errors=True)
    shutil.rmtree(output_session_dir, ignore_errors=True)

    return {"session_id": session_id, "deleted": True}


@router.post("/investigate/{session_id}")
async def start_investigation(session_id: str, background_tasks: BackgroundTasks):
    """Start the full investigation pipeline in the background."""
    session = session_store.get_session(session_id, touch=True)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

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
async def get_investigation_status(session_id: str):
    """Get current status of investigation."""
    session = session_store.get_session(session_id, touch=True)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

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
async def get_report(session_id: str):
    """Retrieve final investigation report."""
    session = session_store.get_session(session_id, touch=True)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

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
