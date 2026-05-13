"""Investigation pipeline orchestration service."""

from datetime import datetime
import sys

from app_context import OUTPUT_DIR, session_store, settings
from services.llm_service import build_role_client, get_ready_provider_snapshot
from services.parsing_service import parse_with_profile, resolve_config_path


def update_session_status(session_id: str, stage: str, message: str, progress: int):
    """Update session status with detailed progress."""
    session = session_store.get_session(session_id, touch=False)
    if session is not None:
        session_store.update_session(
            session_id,
            {
                "stage": stage,
                "current_message": message,
                "progress": progress,
                "last_update": datetime.now().isoformat(),
            },
        )
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] [{session_id}] {stage.upper()}: {message}", flush=True)
        sys.stdout.flush()


def run_investigation_pipeline(session_id: str):
    """Background task: run the full investigation pipeline."""
    try:
        session = session_store.get_session(session_id, touch=True)
        if session is None:
            raise KeyError(f"Session not found: {session_id}")
        file_path = session["file_path"]

        print(f"\n{'=' * 80}")
        print(f"STARTING INVESTIGATION: {session_id}")
        print(f"File: {session['file_name']}")
        print(f"{'=' * 80}\n")

        from modules.anomaly import detect_anomalies_in_logs
        from modules.agent import DFIRAgent
        from modules.gate_observations import append_gate_observations
        from modules.llm_filter import LLMAnomalyFilter
        from modules.report import ReportGenerator

        provider_snapshot, provider_status = get_ready_provider_snapshot()
        session_store.update_session(
            session_id,
            {
                "llm_provider": provider_snapshot.get("provider"),
                "llm_model": provider_snapshot.get("model"),
                "llm_provider_status": provider_status,
            },
        )

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
        parsed_df, templates, selected_profile = parse_with_profile(file_path, settings)
        session_store.update_session(
            session_id,
            {
                "parsed_logs_count": len(parsed_df),
                "templates_count": len(templates),
                "model_profile": selected_profile["name"],
            },
        )
        print(f"✓ Parsing complete: {len(parsed_df)} events, {len(templates)} templates")
        update_session_status(
            session_id,
            "parsing",
            f"✓ Parsing selesai: {len(parsed_df)} events, {len(templates)} templates",
            25,
        )

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
        session_store.update_session(session_id, {"anomalies_count": len(anomalies_df)})
        print(f"✓ DeepLog complete: {len(anomalies_df)} anomalies detected")
        update_session_status(
            session_id,
            "anomaly_detection",
            f"✓ DeepLog selesai: {len(anomalies_df)} anomalies detected",
            45,
        )

        update_session_status(
            session_id,
            "anomaly_detection",
            "🤖 LLM sedang menjalankan sanity gate batch anomalies...",
            47,
        )
        print(f"\n{'=' * 80}")
        print("STAGE 2.5: LLM ANOMALY FILTERING")
        print(f"{'=' * 80}")

        filter_llm = build_role_client(provider_snapshot, role="filter")
        llm_filter = LLMAnomalyFilter(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=provider_snapshot.get("model", settings.ollama_model),
            llm=filter_llm,
            provider_name=provider_snapshot.get("provider", "ollama"),
        )

        print(f"Running batch anomaly gate for {len(anomalies_df)} anomalies with LLM...")
        filtered_anomalies_df = llm_filter.filter_anomalies(anomalies_df, parsed_df)
        gate_policy = _first_dataframe_value(filtered_anomalies_df, "llm_gate_policy")
        gate_active = _first_dataframe_value(filtered_anomalies_df, "llm_gate_active")
        gate_priority_count = _count_dataframe_matches(
            filtered_anomalies_df,
            "llm_gate_priority",
            {"critical_priority", "high_confidence", "needs_more_context"},
        )
        session_store.update_session(
            session_id,
            {
                "deeplog_anomalies": len(anomalies_df),
                "llm_filtered_anomalies": len(filtered_anomalies_df),
                "anomalies_count": len(filtered_anomalies_df),
                "llm_gate_policy": gate_policy,
                "llm_gate_active": bool(gate_active),
                "llm_gate_priority_count": gate_priority_count,
            },
        )

        print(
            f"✓ LLM Filter: {len(anomalies_df)} → {len(filtered_anomalies_df)} confirmed anomalies"
        )
        update_session_status(
            session_id,
            "anomaly_detection",
            f"✓ LLM batch gate: {len(anomalies_df)} → {len(filtered_anomalies_df)} retained anomalies",
            50,
        )

        anomalies_df = filtered_anomalies_df

        update_session_status(
            session_id, "ai_agent", "Menginisialisasi AI Agent...", 55
        )
        print(f"\n{'=' * 80}")
        print("STAGE 3: AI AGENT INVESTIGATION")
        print(f"{'=' * 80}")

        agent_llm = build_role_client(provider_snapshot, role="agent")
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
            procedural_memory_path=str(
                resolve_config_path(settings.procedural_memory_path)
            ),
        )

        print("Agent initialized, starting investigation...")
        update_session_status(
            session_id, "ai_agent", "🤖 AI sedang mengekstrak IOCs...", 60
        )
        investigation_state = agent.investigate(
            anomalies_df, parsed_df, session_id, update_session_status
        )

        gate_observation_count = append_gate_observations(
            resolve_config_path(settings.gate_observations_path),
            session_id=session_id,
            file_name=session["file_name"],
            model_profile=selected_profile["name"],
            initial_anomalies_df=results_df[results_df["is_anomaly"] == True].copy(),
            filtered_anomalies_df=anomalies_df,
            investigation_state=investigation_state,
            llm_provider=provider_snapshot.get("provider"),
            llm_model=provider_snapshot.get("model"),
        )
        session_store.update_session(
            session_id,
            {
                "gate_observation_records": gate_observation_count,
                "gate_observations_path": str(
                    resolve_config_path(settings.gate_observations_path)
                ),
            },
        )

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

        update_session_status(
            session_id,
            "completed",
            "✓ Investigasi selesai! Laporan siap ditinjau.",
            100,
        )
        session_store.update_session(
            session_id,
            {
                "status": "completed",
                "stage": "completed",
                "report": report,
                "report_path": report_path,
                "completion_time": datetime.now().isoformat(),
            },
        )

        print(f"\n{'=' * 80}")
        print(f"INVESTIGATION COMPLETED: {session_id}")
        print(f"Report saved to: {report_path}")
        print(f"{'=' * 80}\n")

    except Exception as e:
        import traceback

        existing_session = session_store.get_session(session_id, default={}, touch=False) or {}
        if existing_session:
            session_store.update_session(
                session_id,
                {
                    "status": "error",
                    "error": str(e),
                },
            )
        else:
            session_store.set_session(
                session_id,
                {
                    "status": "error",
                    "error": str(e),
                },
            )
        print(f"\n{'=' * 80}")
        print(f"ERROR IN INVESTIGATION: {session_id}")
        print(f"{'=' * 80}")
        print(f"Error: {e}")
        print(traceback.format_exc())
        print(f"{'=' * 80}\n")


def _first_dataframe_value(df, column: str):
    if df.empty or column not in df.columns:
        return None
    for value in df[column].tolist():
        if value not in (None, ""):
            return value
    return None


def _count_dataframe_matches(df, column: str, values: set[str]) -> int:
    if df.empty or column not in df.columns:
        return 0
    return sum(1 for value in df[column].tolist() if str(value) in values)
