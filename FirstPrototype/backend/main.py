"""
AI Agent DFIR - Main FastAPI Application.

This module now only wires application-level concerns. API routes, upload
storage, parsing profile selection, and investigation orchestration live in
dedicated routers/services so checking and audit can focus on smaller units.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from app_context import DATA_DIR, MODELS_DIR, OUTPUT_DIR, session_store, settings
from routers import health, investigation, settings as settings_router, upload
from schemas.llm import LLMSettingsPayload, ProviderSettingsPayload
from services.orchestrator_service import run_investigation_pipeline, update_session_status
from services.parsing_service import parse_with_profile as _parse_with_profile
from services.parsing_service import resolve_config_path as _resolve_config_path
from services.storage_service import save_upload_file as _save_upload_file
from services.storage_service import sanitize_uploaded_filename as _sanitize_uploaded_filename
from services.storage_service import store_uploaded_file as _store_uploaded_file
from services.storage_service import validate_upload_extension as _validate_upload_extension


app = FastAPI(
    title="AI Agent DFIR",
    description="Tool-Augmented LLM untuk Otomatisasi Investigasi Insiden Siber",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(settings_router.router)
app.include_router(upload.router)
app.include_router(investigation.router)


__all__ = [
    "DATA_DIR",
    "LLMSettingsPayload",
    "MODELS_DIR",
    "OUTPUT_DIR",
    "ProviderSettingsPayload",
    "_parse_with_profile",
    "_resolve_config_path",
    "_sanitize_uploaded_filename",
    "_save_upload_file",
    "_store_uploaded_file",
    "_validate_upload_extension",
    "app",
    "run_investigation_pipeline",
    "session_store",
    "settings",
    "update_session_status",
]


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
