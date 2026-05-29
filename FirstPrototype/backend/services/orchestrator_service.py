"""Investigation pipeline orchestration service."""

from datetime import datetime
from pathlib import Path
import sys

from app_context import OUTPUT_DIR, session_store, settings
from services.llm_service import build_role_client, get_ready_provider_snapshot
from services.parsing_service import parse_with_profile, resolve_config_path


ANOMALY_STATUS_KEYS = (
    "unknown_template",
    "unknown_template_ratio_exceeded",
    "evtx_heuristic_boost",
    "evtx_sparse_fallback",
    "deeplog_topk_miss",
)

MAX_ACTIVITY_EVENTS = 120
PUBLIC_ERROR_MESSAGE = "Investigation failed. Check backend logs for details."


def _sanitize_terminal_line(line: str) -> str:
    """Keep terminal telemetry compact and safe for the public status API."""
    cleaned = str(line).replace("\r", "").strip("\n")
    if len(cleaned) > 1200:
        return f"{cleaned[:1200]}..."
    return cleaned


def append_session_activity_event(
    session_id: str,
    stage: str,
    line: str,
    *,
    progress: int | None = None,
    action: str = "telemetry",
    level: str = "info",
) -> None:
    """Append a backend-terminal style event for the frontend agent console."""
    session = session_store.get_session(session_id, touch=False)
    if session is None:
        return

    activity_events = session.get("activity_events")
    if not isinstance(activity_events, list):
        activity_events = []

    last_sequence = 0
    for event in reversed(activity_events):
        if not isinstance(event, dict):
            continue
        try:
            last_sequence = int(event.get("sequence") or 0)
            break
        except (TypeError, ValueError):
            continue

    timestamp_iso = datetime.now().isoformat()
    event_progress = progress if progress is not None else session.get("progress", 0)
    activity_events = activity_events[-(MAX_ACTIVITY_EVENTS - 1):]
    activity_events.append(
        {
            "sequence": last_sequence + 1,
            "timestamp": timestamp_iso,
            "stage": stage,
            "action": action,
            "level": level,
            "line": _sanitize_terminal_line(line),
            "message": _sanitize_terminal_line(line),
            "progress": event_progress,
        }
    )

    session_store.update_session(
        session_id,
        {
            "last_update": timestamp_iso,
            "activity_events": activity_events,
        },
    )


def update_session_status(session_id: str, stage: str, message: str, progress: int):
    """Update session status with detailed progress."""
    session = session_store.get_session(session_id, touch=False)
    if session is not None:
        timestamp = datetime.now()
        timestamp_iso = timestamp.isoformat()
        activity_events = session.get("activity_events")
        if not isinstance(activity_events, list):
            activity_events = []

        last_sequence = 0
        for event in reversed(activity_events):
            if not isinstance(event, dict):
                continue
            try:
                last_sequence = int(event.get("sequence") or 0)
                break
            except (TypeError, ValueError):
                continue

        activity_events = activity_events[-(MAX_ACTIVITY_EVENTS - 1):]
        activity_events.append(
            {
                "sequence": last_sequence + 1,
                "timestamp": timestamp_iso,
                "stage": stage,
                "action": "status_update",
                "level": "status",
                "line": _sanitize_terminal_line(message),
                "message": _sanitize_terminal_line(message),
                "progress": progress,
            }
        )

        session_store.update_session(
            session_id,
            {
                "stage": stage,
                "current_message": message,
                "progress": progress,
                "last_update": timestamp_iso,
                "activity_events": activity_events,
            },
        )
        print(f"\n[{timestamp.strftime('%H:%M:%S')}] [{session_id}] {stage.upper()}: {message}", flush=True)
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
        append_session_activity_event(
            session_id,
            "pending",
            f"{'=' * 60}\nSTARTING INVESTIGATION: {session_id}\nFile: {session['file_name']}\n{'=' * 60}",
            progress=0,
            level="system",
        )

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
        append_session_activity_event(
            session_id,
            "parsing",
            f"{'=' * 60}\nSTAGE 1: LOG PARSING\n{'=' * 60}",
            progress=10,
            level="stage",
        )

        update_session_status(
            session_id,
            "parsing",
            "Sedang melakukan parsing logs dengan Drain algorithm...",
            15,
        )
        parsed_df, templates, selected_profile = parse_with_profile(file_path, settings)
        append_session_activity_event(
            session_id,
            "parsing",
            f"Parser profile selected: {selected_profile['name']}",
            progress=20,
        )
        session_store.update_session(
            session_id,
            {
                "parsed_logs_count": len(parsed_df),
                "templates_count": len(templates),
                "model_profile": selected_profile["name"],
            },
        )
        print(f"✓ Parsing complete: {len(parsed_df)} events, {len(templates)} templates")
        append_session_activity_event(
            session_id,
            "parsing",
            f"[OK] Parsing complete: {len(parsed_df)} events, {len(templates)} templates",
            progress=25,
            level="success",
        )
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
        append_session_activity_event(
            session_id,
            "anomaly_detection",
            f"{'=' * 60}\nSTAGE 2: ANOMALY DETECTION\n{'=' * 60}",
            progress=30,
            level="stage",
        )

        model_path = selected_profile["model_path"]
        vocab_path = selected_profile["vocab_path"]

        if not model_path.exists() or not vocab_path.exists():
            raise FileNotFoundError(
                f"DeepLog artifacts not found. model={model_path} vocab={vocab_path}"
            )

        print(f"Loading DeepLog model from: {model_path}")
        append_session_activity_event(
            session_id,
            "anomaly_detection",
            f"Loading DeepLog model from: {model_path.name}",
            progress=35,
        )
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
            topk=selected_profile.get("topk", settings.deeplog_topk),
            skip_unknown_windows=settings.deeplog_skip_unknown_windows,
            max_unknown_ratio=settings.deeplog_max_unknown_ratio,
            unknown_template_mode=settings.deeplog_unknown_template_mode,
            evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled,
            evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold,
            template_similarity_enabled=settings.deeplog_template_similarity_enabled,
            template_similarity_threshold=settings.deeplog_template_similarity_threshold,
            decision_policy=settings.deeplog_decision_policy,
            score_threshold=settings.deeplog_score_threshold,
            medium_score_threshold=settings.deeplog_medium_score_threshold,
            recall_floor=settings.deeplog_target_recall,
            use_bos_context=selected_profile.get("use_bos_context", False),
            bos_token=selected_profile.get("bos_token", "<BOS>"),
            bos_count=selected_profile.get("bos_count"),
        )
        session_store.update_session(
            session_id,
            {
                "anomalies_count": len(anomalies_df),
                "deeplog_evaluation_status_counts": _count_evaluation_statuses(
                    results_df
                ),
            },
        )
        print(f"✓ DeepLog complete: {len(anomalies_df)} anomalies detected")
        append_session_activity_event(
            session_id,
            "anomaly_detection",
            f"[OK] DeepLog complete: {len(results_df)} windows evaluated, {len(anomalies_df)} anomalies detected",
            progress=45,
            level="success",
        )
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
        append_session_activity_event(
            session_id,
            "anomaly_detection",
            f"{'=' * 60}\nLLM ANOMALY GATE (Batch Sanity Check)\n{'=' * 60}\nDeepLog detected: {len(anomalies_df)} anomalies\nRunning one coarse LLM sanity gate for the batch...",
            progress=47,
            level="stage",
        )

        filter_llm = build_role_client(provider_snapshot, role="filter")
        llm_filter = LLMAnomalyFilter(
            ollama_base_url=settings.ollama_base_url,
            ollama_model=provider_snapshot.get("model", settings.ollama_model),
            llm=filter_llm,
            provider_name=provider_snapshot.get("provider", "ollama"),
        )

        print(f"Running batch anomaly gate for {len(anomalies_df)} anomalies with LLM...")
        filtered_anomalies_df = llm_filter.filter_anomalies(anomalies_df, parsed_df)
        recall_preserving_gate = (
            _is_recall_preserving_deeplog_policy(settings.deeplog_decision_policy)
            or str(getattr(settings, "deeplog_llm_filter_mode", "filter")).lower()
            == "annotate"
        )
        if recall_preserving_gate:
            investigation_anomalies_df = _merge_llm_gate_annotations(
                anomalies_df,
                filtered_anomalies_df,
            )
        else:
            investigation_anomalies_df = filtered_anomalies_df
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
                "anomalies_count": len(investigation_anomalies_df),
                "llm_gate_policy": gate_policy,
                "llm_gate_active": bool(gate_active),
                "llm_gate_priority_count": gate_priority_count,
                "llm_gate_mode": "annotate" if recall_preserving_gate else "filter",
            },
        )

        print(
            f"✓ LLM Filter: {len(anomalies_df)} → {len(filtered_anomalies_df)} confirmed anomalies"
        )
        append_session_activity_event(
            session_id,
            "anomaly_detection",
            (
                f"{'=' * 60}\nLLM Batch Gate Results:\n"
                f"  Input: {len(anomalies_df)} anomalies\n"
                f"  Policy: {gate_policy or 'unknown'}\n"
                f"  Output: {len(filtered_anomalies_df)} anomalies\n"
                f"  Priority candidates: {gate_priority_count}\n"
                f"{'=' * 60}"
            ),
            progress=50,
            level="success",
        )
        update_session_status(
            session_id,
            "anomaly_detection",
            f"✓ LLM batch gate: {len(anomalies_df)} → {len(investigation_anomalies_df)} retained anomalies",
            50,
        )

        anomalies_df = investigation_anomalies_df

        update_session_status(
            session_id, "ai_agent", "Menginisialisasi AI Agent...", 55
        )
        print(f"\n{'=' * 80}")
        print("STAGE 3: AI AGENT INVESTIGATION")
        print(f"{'=' * 80}")
        append_session_activity_event(
            session_id,
            "ai_agent",
            f"{'=' * 60}\nSTAGE 3: AI AGENT INVESTIGATION\n{'=' * 60}",
            progress=55,
            level="stage",
        )

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
        append_session_activity_event(
            session_id,
            "ai_agent",
            "Agent initialized, starting investigation...",
            progress=58,
        )
        update_session_status(
            session_id, "ai_agent", "🤖 AI sedang mengekstrak IOCs...", 60
        )
        investigation_state = agent.investigate(
            anomalies_df,
            parsed_df,
            session_id,
            update_session_status,
            append_session_activity_event,
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
        append_session_activity_event(
            session_id,
            "report_generation",
            f"{'=' * 60}\nSTAGE 4: REPORT GENERATION\n{'=' * 60}",
            progress=85,
            level="stage",
        )

        report_generator = ReportGenerator()

        print("Generating report...")
        append_session_activity_event(
            session_id,
            "report_generation",
            "Generating structured DFIR report...",
            progress=87,
        )
        report = report_generator.generate_report(
            session_id, session["file_name"], investigation_state
        )

        update_session_status(
            session_id, "report_generation", "Menyimpan laporan investigasi...", 90
        )
        print("Saving report (Markdown and JSON)...")
        append_session_activity_event(
            session_id,
            "report_generation",
            "Saving report artifacts: Markdown + JSON",
            progress=90,
        )
        report_path = report_generator.save_report(report, str(OUTPUT_DIR / session_id))
        report_artifact = Path(report_path).name

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
        append_session_activity_event(
            session_id,
            "completed",
            f"{'=' * 60}\nINVESTIGATION COMPLETED\nReport artifact ready: {report_artifact}\n{'=' * 60}",
            progress=100,
            level="success",
        )

    except Exception as e:
        import traceback

        existing_session = session_store.get_session(session_id, default={}, touch=False) or {}
        if existing_session:
            try:
                error_progress = int(existing_session.get("progress") or 0)
            except (TypeError, ValueError):
                error_progress = 0
            update_session_status(
                session_id,
                "error",
                "Investigasi gagal. Periksa detail error.",
                error_progress,
            )
            session_store.update_session(
                session_id,
                {
                    "status": "error",
                    "error": PUBLIC_ERROR_MESSAGE,
                },
            )
        else:
            session_store.set_session(
                session_id,
                {
                    "status": "error",
                    "error": PUBLIC_ERROR_MESSAGE,
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


def _is_recall_preserving_deeplog_policy(policy: str | None) -> bool:
    return str(policy or "").strip().lower() in {"f1_constrained_recall"}


def _merge_llm_gate_annotations(candidates_df, filtered_df):
    if candidates_df.empty or filtered_df.empty or "window_id" not in candidates_df.columns:
        return candidates_df
    if "window_id" not in filtered_df.columns:
        return candidates_df

    annotation_columns = [
        column
        for column in filtered_df.columns
        if column.startswith("llm_") or column.startswith("current_llm_")
    ]
    if not annotation_columns:
        return candidates_df

    annotations = filtered_df[["window_id", *annotation_columns]].drop_duplicates(
        subset=["window_id"],
        keep="first",
    )
    merged_df = candidates_df.copy().merge(
        annotations,
        how="left",
        on="window_id",
        suffixes=("", "_llm_gate"),
    )
    if "llm_filtered" in merged_df.columns:
        merged_df["llm_filtered"] = (
            merged_df["llm_filtered"].where(merged_df["llm_filtered"].notna(), False).astype(bool)
        )
    else:
        merged_df["llm_filtered"] = False
    if "llm_gate_priority" in merged_df.columns:
        merged_df["llm_gate_priority"] = merged_df["llm_gate_priority"].fillna(
            "not_retained_by_llm_gate"
        )
    else:
        merged_df["llm_gate_priority"] = "not_retained_by_llm_gate"
    if "llm_gate_priority_rank" in merged_df.columns:
        merged_df["llm_gate_priority_rank"] = merged_df["llm_gate_priority_rank"].fillna(9)
    else:
        merged_df["llm_gate_priority_rank"] = 9
    return merged_df


def _count_evaluation_statuses(df) -> dict[str, int]:
    status_counts = {status: 0 for status in ANOMALY_STATUS_KEYS}
    if df.empty or "evaluation_status" not in df.columns:
        return status_counts

    counts = df["evaluation_status"].value_counts().to_dict()
    return {status: int(counts.get(status, 0)) for status in ANOMALY_STATUS_KEYS}
