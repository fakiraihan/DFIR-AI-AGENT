"""
AI Agent DFIR - Main FastAPI Application
Orchestrates log parsing, anomaly detection, AI agent investigation, and report generation
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
from pathlib import Path
from datetime import datetime
import sys
import re
import shutil
from uuid import uuid4

from config import settings

app = FastAPI(
    title="AI Agent DFIR",
    description="Tool-Augmented LLM untuk Otomatisasi Investigasi Insiden Siber",
    version="1.0.0",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "raw_logs"
OUTPUT_DIR = BASE_DIR / "output"
MODELS_DIR = BASE_DIR / "models"

# Create directories if they don't exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Store active investigation sessions
active_sessions = {}

UPLOAD_CHUNK_SIZE = 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".evtx", ".log", ".txt", ".csv"}


def _generate_session_id(prefix: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}_{uuid4().hex[:12]}"


def _sanitize_uploaded_filename(filename: str | None) -> str:
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


def _validate_upload_extension(filename: str) -> str:
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


async def _save_upload_file(file: UploadFile, destination: Path) -> int:
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


async def _store_uploaded_file(
    file: UploadFile, session_prefix: str
) -> tuple[str, str, Path, int]:
    safe_file_name = _sanitize_uploaded_filename(file.filename)
    _validate_upload_extension(safe_file_name)

    session_id = _generate_session_id(session_prefix)
    session_dir = DATA_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)

    file_path = session_dir / safe_file_name
    try:
        file_size = await _save_upload_file(file, file_path)
    except Exception:
        if session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
        raise
    return session_id, safe_file_name, file_path, file_size


class ProviderSettingsPayload(BaseModel):
    enabled: bool | None = None
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    clear_api_key: bool = False


class LLMSettingsPayload(BaseModel):
    selected_provider: str = Field(pattern="^(ollama|gemini|openrouter)$")
    providers: dict[str, ProviderSettingsPayload] = Field(default_factory=dict)


def _resolve_config_path(raw_path: str) -> Path:
    path_obj = Path(raw_path)
    if path_obj.is_absolute():
        return path_obj
    return (BASE_DIR / path_obj).resolve()


def _build_model_profile(name: str, settings) -> dict:
    if name == "sysmon":
        return {
            "name": "sysmon",
            "model_path": _resolve_config_path(settings.sysmon_deeplog_model_path),
            "vocab_path": _resolve_config_path(settings.sysmon_deeplog_vocab_path),
            "window_size": settings.sysmon_deeplog_window_size,
            "template_strategy": settings.sysmon_parser_template_strategy,
        }

    return {
        "name": "general",
        "model_path": _resolve_config_path(settings.deeplog_model_path),
        "vocab_path": _resolve_config_path(settings.deeplog_vocab_path),
        "window_size": settings.deeplog_window_size,
        "template_strategy": settings.parser_template_strategy,
    }


def _is_sysmon_evtx(file_path: str, parsed_df) -> bool:
    suffix = Path(file_path).suffix.lower()
    if suffix != ".evtx" or parsed_df.empty or "raw_line" not in parsed_df.columns:
        return False

    raw_lines = parsed_df["raw_line"].astype(str)
    sysmon_ratio = raw_lines.str.contains(
        "Microsoft-Windows-Sysmon", regex=False
    ).mean()
    return bool(sysmon_ratio >= 0.5)


def _parse_with_profile(file_path: str, settings, max_lines=None):
    from modules.parsing import parse_log_file

    general_profile = _build_model_profile("general", settings)
    parsed_df, templates = parse_log_file(
        file_path,
        depth=settings.drain_depth,
        sim_threshold=settings.drain_sim_threshold,
        max_children=settings.drain_max_children,
        template_strategy=general_profile["template_strategy"],
        max_lines=max_lines,
    )

    selected_profile = general_profile
    if _is_sysmon_evtx(file_path, parsed_df):
        sysmon_profile = _build_model_profile("sysmon", settings)
        parsed_df, templates = parse_log_file(
            file_path,
            depth=settings.drain_depth,
            sim_threshold=settings.drain_sim_threshold,
            max_children=settings.drain_max_children,
            template_strategy=sysmon_profile["template_strategy"],
            max_lines=max_lines,
        )
        selected_profile = sysmon_profile

    return parsed_df, templates, selected_profile


def update_session_status(session_id: str, stage: str, message: str, progress: int):
    """Update session status with detailed progress"""
    if session_id in active_sessions:
        active_sessions[session_id].update(
            {
                "stage": stage,
                "current_message": message,
                "progress": progress,
                "last_update": datetime.now().isoformat(),
            }
        )
        # Force print to console with flush for real-time visibility
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] [{session_id}] {stage.upper()}: {message}", flush=True)
        sys.stdout.flush()


def run_investigation_pipeline(session_id: str):
    """
    Background task: Run full investigation pipeline
    """
    try:
        session = active_sessions[session_id]
        file_path = session["file_path"]

        print(f"\n{'=' * 80}")
        print(f"STARTING INVESTIGATION: {session_id}")
        print(f"File: {session['file_name']}")
        print(f"{'=' * 80}\n")

        # Import modules
        from modules.anomaly import detect_anomalies_in_logs
        from modules.agent import DFIRAgent
        from modules.llm_provider import build_llm_client, assert_provider_ready
        from modules.llm_settings_store import get_active_provider_snapshot
        from modules.report import ReportGenerator
        from config import settings

        provider_snapshot = get_active_provider_snapshot()
        provider_status = assert_provider_ready(provider_snapshot)
        session["llm_provider"] = provider_snapshot.get("provider")
        session["llm_model"] = provider_snapshot.get("model")
        session["llm_provider_status"] = provider_status

        # Stage 1: Parsing
        update_session_status(session_id, "parsing", "Memuat file log...", 10)
        print(f"\n{'=' * 80}")
        print("STAGE 1: LOG PARSING")
        print(f"{'=' * 80}")

        update_session_status(
            session_id,
            "parsing",
            "Sedang melakukan parsing logs dengan Drain algorithm...",
            15,
        )
        parsed_df, templates, selected_profile = _parse_with_profile(
            file_path,
            settings,
        )
        session["parsed_logs_count"] = len(parsed_df)
        session["templates_count"] = len(templates)
        session["model_profile"] = selected_profile["name"]
        print(
            f"✓ Parsing complete: {len(parsed_df)} events, {len(templates)} templates"
        )
        update_session_status(
            session_id,
            "parsing",
            f"✓ Parsing selesai: {len(parsed_df)} events, {len(templates)} templates",
            25,
        )

        # Stage 2: Anomaly Detection
        update_session_status(
            session_id, "anomaly_detection", "Memuat model DeepLog...", 30
        )
        print(f"\n{'=' * 80}")
        print("STAGE 2: ANOMALY DETECTION")
        print(f"{'=' * 80}")

        model_path = selected_profile["model_path"]
        vocab_path = selected_profile["vocab_path"]

        if not model_path.exists() or not vocab_path.exists():
            raise FileNotFoundError(
                f"DeepLog artifacts not found. model={model_path} vocab={vocab_path}"
            )

        print(f"Loading DeepLog model from: {model_path}")
        update_session_status(
            session_id,
            "anomaly_detection",
            "Sedang melakukan deteksi anomali dengan DeepLog...",
            40,
        )
        results_df, anomalies_df = detect_anomalies_in_logs(
            parsed_df,
            str(model_path),
            str(vocab_path),
            window_size=selected_profile["window_size"],
            step_size=settings.deeplog_step_size,
            topk=settings.deeplog_topk,
            skip_unknown_windows=settings.deeplog_skip_unknown_windows,
            max_unknown_ratio=settings.deeplog_max_unknown_ratio,
        )
        session["anomalies_count"] = len(anomalies_df)
        print(f"✓ DeepLog complete: {len(anomalies_df)} anomalies detected")
        update_session_status(
            session_id,
            "anomaly_detection",
            f"✓ DeepLog selesai: {len(anomalies_df)} anomalies detected",
            45,
        )

        # Stage 2.5: LLM Filtering (Second Gate)
        update_session_status(
            session_id,
            "anomaly_detection",
            "🤖 LLM sedang menjalankan sanity gate batch anomalies...",
            47,
        )
        print(f"\n{'=' * 80}")
        print("STAGE 2.5: LLM ANOMALY FILTERING")
        print(f"{'=' * 80}")

        from modules.llm_filter import LLMAnomalyFilter

        filter_llm = build_llm_client(provider_snapshot, role="filter")
        llm_filter = LLMAnomalyFilter(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=provider_snapshot.get("model", settings.ollama_model),
            llm=filter_llm,
            provider_name=provider_snapshot.get("provider", "ollama"),
        )

        print(
            f"Running batch anomaly gate for {len(anomalies_df)} anomalies with LLM..."
        )
        # Coarse batch-level anomaly gate with one LLM decision
        filtered_anomalies_df = llm_filter.filter_anomalies(anomalies_df, parsed_df)
        session["deeplog_anomalies"] = len(anomalies_df)
        session["llm_filtered_anomalies"] = len(filtered_anomalies_df)
        session["anomalies_count"] = len(filtered_anomalies_df)

        print(
            f"✓ LLM Filter: {len(anomalies_df)} → {len(filtered_anomalies_df)} confirmed anomalies"
        )
        update_session_status(
            session_id,
            "anomaly_detection",
            f"✓ LLM batch gate: {len(anomalies_df)} → {len(filtered_anomalies_df)} retained anomalies",
            50,
        )

        # Use filtered anomalies for investigation
        anomalies_df = filtered_anomalies_df

        # Stage 3: AI Agent Investigation
        update_session_status(
            session_id, "ai_agent", "Menginisialisasi AI Agent...", 55
        )
        print(f"\n{'=' * 80}")
        print("STAGE 3: AI AGENT INVESTIGATION")
        print(f"{'=' * 80}")

        agent_llm = build_llm_client(provider_snapshot, role="agent")
        agent = DFIRAgent(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=provider_snapshot.get("model", settings.ollama_model),
            threat_intel_api_keys={
                "abusech_api_key": settings.abusech_api_key,
                "alienvault_otx_api_key": settings.alienvault_otx_api_key,
                "greynoise_api_key": settings.greynoise_api_key,
                "virustotal_api_key": settings.virustotal_api_key,
            },
            llm=agent_llm,
            provider_name=provider_snapshot.get("provider", "ollama"),
        )

        print("Agent initialized, starting investigation...")
        update_session_status(
            session_id, "ai_agent", "🤖 AI sedang mengekstrak IOCs...", 60
        )
        # Pass session_id to agent for status updates
        investigation_state = agent.investigate(
            anomalies_df, parsed_df, session_id, update_session_status
        )

        # Stage 4: Report Generation
        update_session_status(
            session_id, "report_generation", "Menyusun laporan investigasi...", 85
        )
        print(f"\n{'=' * 80}")
        print("STAGE 4: REPORT GENERATION")
        print(f"{'=' * 80}")

        report_generator = ReportGenerator()

        print("Generating report...")
        report = report_generator.generate_report(
            session_id, session["file_name"], investigation_state
        )

        update_session_status(
            session_id, "report_generation", "Menyimpan laporan investigasi...", 90
        )
        print("Saving report (Markdown and JSON)...")
        report_path = report_generator.save_report(report, str(OUTPUT_DIR / session_id))

        # Update session
        update_session_status(
            session_id,
            "completed",
            "✓ Investigasi selesai! Laporan siap ditinjau.",
            100,
        )
        session["status"] = "completed"
        session["stage"] = "completed"
        session["report"] = report
        session["report_path"] = report_path
        session["completion_time"] = datetime.now().isoformat()

        print(f"\n{'=' * 80}")
        print(f"INVESTIGATION COMPLETED: {session_id}")
        print(f"Report saved to: {report_path}")
        print(f"{'=' * 80}\n")

    except Exception as e:
        import traceback

        session = active_sessions.get(session_id, {})
        session["status"] = "error"
        session["error"] = str(e)
        session["traceback"] = traceback.format_exc()
        print(f"\n{'=' * 80}")
        print(f"ERROR IN INVESTIGATION: {session_id}")
        print(f"{'=' * 80}")
        print(f"Error: {e}")
        print(traceback.format_exc())
        print(f"{'=' * 80}\n")


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "AI Agent DFIR",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/settings/llm")
async def get_llm_settings():
    from modules.llm_settings_store import get_public_llm_settings

    return get_public_llm_settings()


@app.put("/api/settings/llm")
async def update_llm_settings(payload: LLMSettingsPayload):
    from modules.llm_settings_store import update_llm_settings as persist_llm_settings

    return persist_llm_settings(payload.model_dump(exclude_none=True))


@app.get("/api/settings/llm/status")
async def get_llm_provider_status():
    from modules.llm_provider import get_all_provider_health
    from modules.llm_settings_store import get_effective_llm_settings

    effective = get_effective_llm_settings()
    return {
        "selected_provider": effective.get("selected_provider", "ollama"),
        "providers": get_all_provider_health(effective),
    }


@app.post("/api/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """
    Upload log file for investigation
    Supports: .evtx, .log, .txt, .csv
    """
    try:
        session_id, safe_file_name, file_path, file_size = await _store_uploaded_file(
            file, "session"
        )

        active_sessions[session_id] = {
            "file_name": safe_file_name,
            "file_path": str(file_path),
            "file_size": file_size,
            "upload_time": datetime.now().isoformat(),
            "status": "uploaded",
            "stage": "pending",
        }

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


@app.post("/api/analyze")
async def analyze_log_file(
    file: UploadFile = File(...),
    max_lines: int = Form(20000),
    sample_step: int = Form(1),
    anomaly_limit: int = Form(100),
):
    """
    Phase 1 endpoint:
    Upload log then run Drain parsing + DeepLog anomaly detection.
    """
    from modules.anomaly import detect_anomalies_in_logs
    from modules.parsing import parse_log_file

    safe_file_name = _sanitize_uploaded_filename(file.filename)
    _validate_upload_extension(safe_file_name)

    if max_lines <= 0:
        raise HTTPException(status_code=400, detail="max_lines must be > 0")

    if sample_step <= 0:
        raise HTTPException(status_code=400, detail="sample_step must be > 0")

    if anomaly_limit <= 0:
        raise HTTPException(status_code=400, detail="anomaly_limit must be > 0")

    session_id = _generate_session_id("analyze")
    session_dir = DATA_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)

    file_path = session_dir / safe_file_name
    await _save_upload_file(file, file_path)

    parsed_df, templates, selected_profile = _parse_with_profile(
        str(file_path),
        settings,
        max_lines=max_lines,
    )

    effective_sample_step = sample_step
    sampling_applied = False
    if sample_step > 1 and not parsed_df.empty:
        sampled_df = parsed_df.iloc[::sample_step].reset_index(drop=True)
        if len(sampled_df) > selected_profile["window_size"]:
            parsed_df = sampled_df
            parsed_df["line_number"] = range(1, len(parsed_df) + 1)
            parsed_df["event_id"] = range(1, len(parsed_df) + 1)
            sampling_applied = True
        else:
            effective_sample_step = 1

    model_path = selected_profile["model_path"]
    vocab_path = selected_profile["vocab_path"]

    if not model_path.exists() or not vocab_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"DeepLog artifacts not found. model={model_path} vocab={vocab_path}",
        )

    all_results_df, anomalies_df = detect_anomalies_in_logs(
        parsed_df,
        str(model_path),
        str(vocab_path),
        window_size=selected_profile["window_size"],
        step_size=settings.deeplog_step_size,
        topk=settings.deeplog_topk,
        skip_unknown_windows=settings.deeplog_skip_unknown_windows,
        max_unknown_ratio=settings.deeplog_max_unknown_ratio,
    )

    skipped_windows = 0
    strict_anomaly_count = 0
    avg_unknown_ratio = 0.0
    if not all_results_df.empty:
        evaluated_df = all_results_df
        if "evaluation_status" in all_results_df.columns:
            skipped_windows = int(
                (all_results_df["evaluation_status"] != "evaluated").sum()
            )
            evaluated_df = all_results_df[
                all_results_df["evaluation_status"] == "evaluated"
            ]
        if "strict_is_anomaly" in evaluated_df.columns:
            strict_anomaly_count = int(evaluated_df["strict_is_anomaly"].sum())
        if "unknown_ratio" in all_results_df.columns:
            avg_unknown_ratio = float(all_results_df["unknown_ratio"].mean())

    anomaly_records = anomalies_df.to_dict("records")
    truncated = len(anomaly_records) > anomaly_limit
    if truncated:
        anomaly_records = anomaly_records[:anomaly_limit]

    return {
        "session_id": session_id,
        "file_name": safe_file_name,
        "debug": {
            "max_lines": max_lines,
            "sample_step": sample_step,
            "effective_sample_step": effective_sample_step,
            "sampling_applied": sampling_applied,
            "anomaly_limit": anomaly_limit,
            "skip_unknown_windows": settings.deeplog_skip_unknown_windows,
            "max_unknown_ratio": settings.deeplog_max_unknown_ratio,
            "model_profile": selected_profile["name"],
            "window_size": selected_profile["window_size"],
            "parser_template_strategy": selected_profile["template_strategy"],
            "result_truncated": truncated,
        },
        "summary": {
            "parsed_lines": len(parsed_df),
            "template_count": len(templates),
            "window_count": len(all_results_df),
            "anomaly_count": len(anomalies_df),
            "strict_anomaly_count": strict_anomaly_count,
            "skipped_windows": skipped_windows,
            "avg_unknown_ratio": round(avg_unknown_ratio, 4),
        },
        "anomaly_results": anomaly_records,
    }


@app.post("/api/investigate/{session_id}")
async def start_investigation(session_id: str, background_tasks: BackgroundTasks):
    """
    Start full investigation pipeline in background:
    1. Drain parsing
    2. DeepLog anomaly detection
    3. LLM anomaly filtering
    4. AI Agent orchestration with threat intel
    5. Report generation (JSON + Markdown)
    """
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from modules.llm_provider import assert_provider_ready, LLMProviderError
        from modules.llm_settings_store import get_active_provider_snapshot

        provider_snapshot = get_active_provider_snapshot()
        try:
            provider_status = assert_provider_ready(provider_snapshot)
        except LLMProviderError as exc:
            raise HTTPException(
                status_code=400, detail=f"Selected LLM provider is not ready: {exc}"
            ) from exc

        session = active_sessions[session_id]
        session["status"] = "processing"
        session["stage"] = "pending"
        session["progress"] = 0
        session["current_message"] = "Investigation akan segera dimulai..."
        session["llm_provider"] = provider_snapshot.get("provider")
        session["llm_model"] = provider_snapshot.get("model")
        session["llm_provider_status"] = provider_status

        # Run investigation in background
        background_tasks.add_task(run_investigation_pipeline, session_id)

        return {
            "session_id": session_id,
            "status": "processing",
            "message": "Investigation started in background. Check /api/status/{session_id} for progress.",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/status/{session_id}")
async def get_investigation_status(session_id: str):
    """Get current status of investigation"""
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = active_sessions[session_id]
    return {
        "session_id": session_id,
        "status": session.get("status", "pending"),
        "stage": session.get("stage", "pending"),
        "progress": session.get("progress", 0),
        "current_message": session.get("current_message", ""),
        "error": session.get("error"),
        "last_update": session.get("last_update"),
        "file_name": session.get("file_name"),
        "summary": {
            "parsed_logs": session.get("parsed_logs_count"),
            "templates": session.get("templates_count"),
            "anomalies": session.get("anomalies_count"),
        },
    }


@app.get("/api/report/{session_id}")
async def get_report(session_id: str):
    """Retrieve final investigation report"""
    if session_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = active_sessions[session_id]

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


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
