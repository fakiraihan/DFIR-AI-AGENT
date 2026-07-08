"""Upload and quick-analysis endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app_context import session_store
from routers.auth import get_current_user
from services.analyze_service import run_quick_analysis
from services.storage_service import store_uploaded_file


router = APIRouter(prefix="/api", tags=["upload"])


def _build_user_profile(name: str | None, email: str | None) -> dict[str, str] | None:
    clean_name = str(name or "").strip()
    clean_email = str(email or "").strip().lower()
    if not clean_name and not clean_email:
        return None
    return {
        "name": clean_name[:80] or "Registered Analyst",
        "email": clean_email[:160],
    }


@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    user_name: str | None = Form(default=None),
    user_email: str | None = Form(default=None),
    current_user: dict = Depends(get_current_user),
):
    """Upload log file for investigation."""
    try:
        session_id, safe_file_name, file_path, file_size = await store_uploaded_file(
            file, "session"
        )
        _ = (user_name, user_email)
        user_profile = {
            "id": current_user["id"],
            "name": current_user["name"],
            "username": current_user.get("username"),
            "email": current_user["email"],
        }
        session_payload = {
            "user_id": current_user["id"],
            "file_name": safe_file_name,
            "file_path": str(file_path),
            "file_size": file_size,
            "upload_time": datetime.now().isoformat(),
            "status": "uploaded",
            "stage": "pending",
        }
        session_payload["user_profile"] = user_profile

        session_store.set_session(
            session_id,
            session_payload,
        )

        return {
            "session_id": session_id,
            "file_name": safe_file_name,
            "file_size": file_size,
            "user_profile": user_profile,
            "message": "File uploaded successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/analyze")
async def analyze_log_file(
    file: UploadFile = File(...),
    max_lines: int = Form(20000),
    sample_step: int = Form(1),
    anomaly_limit: int = Form(100),
):
    """Run parsing and DeepLog anomaly detection without the full AI agent."""
    return await run_quick_analysis(
        file,
        max_lines=max_lines,
        sample_step=sample_step,
        anomaly_limit=anomaly_limit,
    )
