"""Upload and quick-analysis endpoints."""

from datetime import datetime

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app_context import session_store
from services.analyze_service import run_quick_analysis
from services.storage_service import store_uploaded_file


router = APIRouter(prefix="/api", tags=["upload"])


@router.post("/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """Upload log file for investigation."""
    try:
        session_id, safe_file_name, file_path, file_size = await store_uploaded_file(
            file, "session"
        )

        session_store.set_session(
            session_id,
            {
                "file_name": safe_file_name,
                "file_path": str(file_path),
                "file_size": file_size,
                "upload_time": datetime.now().isoformat(),
                "status": "uploaded",
                "stage": "pending",
            },
        )

        return {
            "session_id": session_id,
            "file_name": safe_file_name,
            "file_size": file_size,
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
