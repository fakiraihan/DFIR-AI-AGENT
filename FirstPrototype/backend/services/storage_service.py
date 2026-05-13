"""Upload storage and validation helpers."""

from datetime import datetime
from pathlib import Path
import re
import shutil
from uuid import uuid4

from fastapi import HTTPException, UploadFile

from app_context import DATA_DIR, settings


UPLOAD_CHUNK_SIZE = 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".evtx", ".log", ".txt", ".csv"}


def generate_session_id(prefix: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}_{uuid4().hex[:12]}"


def sanitize_uploaded_filename(filename: str | None) -> str:
    raw_name = Path(filename or "").name.strip()
    if not raw_name:
        raise HTTPException(status_code=400, detail="Filename is required")

    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name)
    sanitized = sanitized.strip("._")
    if not sanitized:
        raise HTTPException(status_code=400, detail="Filename is invalid")

    if len(sanitized) > 255:
        stem = Path(sanitized).stem[:200]
        suffix = Path(sanitized).suffix[:20]
        sanitized = f"{stem}{suffix}"

    return sanitized


def validate_upload_extension(filename: str) -> str:
    file_ext = Path(filename).suffix.lower()
    if file_ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                "File type not supported. Allowed: "
                + ", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))
            ),
        )
    return file_ext


async def save_upload_file(file: UploadFile, destination: Path) -> int:
    max_upload_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    total_size = 0

    try:
        with open(destination, "wb") as file_obj:
            while True:
                chunk = await file.read(UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > max_upload_size_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "File size exceeds maximum allowed upload size "
                            f"({settings.max_upload_size_mb} MB)"
                        ),
                    )

                file_obj.write(chunk)
    except HTTPException:
        if destination.exists():
            destination.unlink()
        raise
    finally:
        await file.close()

    return total_size


async def store_uploaded_file(
    file: UploadFile, session_prefix: str
) -> tuple[str, str, Path, int]:
    safe_file_name = sanitize_uploaded_filename(file.filename)
    validate_upload_extension(safe_file_name)

    session_id = generate_session_id(session_prefix)
    session_dir = DATA_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)

    file_path = session_dir / safe_file_name
    try:
        file_size = await save_upload_file(file, file_path)
    except Exception:
        if session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
        raise
    return session_id, safe_file_name, file_path, file_size
