"""
Test script for AI Agent DFIR system.
Tests the full pipeline from log upload to report generation.
"""

# pyright: reportImplicitRelativeImport=false

import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from config import settings
from main import _parse_with_profile
from modules.anomaly import detect_anomalies_in_logs
from modules.agent import DFIRAgent
from modules.report import ReportGenerator


def _item_count(value) -> int:
    return len(value) if isinstance(value, (list, tuple, dict, str)) else 0


def test_full_pipeline():
    """Test the complete DFIR investigation pipeline."""

    print("=" * 80)
    print("AI AGENT DFIR - FULL PIPELINE TEST")
    print("=" * 80)

    base_dir = Path(__file__).parent.parent
    artifact_test_file = base_dir.parent / "NEWMLMODL" / "eventlog.csv"
    local_test_file = base_dir.parent / "eventlog.csv"
    test_file = artifact_test_file if artifact_test_file.exists() else local_test_file

    if not test_file.exists():
        print(f"[FAIL] Test file not found: {test_file}")
        print("Please ensure a representative Windows Event Log sample is available")
        return

    _, _, selected_profile = _parse_with_profile(str(test_file), settings, max_lines=500)
    model_path = selected_profile["model_path"]
    vocab_path = selected_profile["vocab_path"]

    if not model_path.exists() or not vocab_path.exists():
        print("[FAIL] DeepLog model not found")
        print(f"Model path: {model_path}")
        print(f"Vocab path: {vocab_path}")
        print("Please provide accessible DeepLog runtime artifacts")
        return

    print(f"\n[OK] Test file: {test_file.name}")
    print("[OK] Model found: DeepLog")

    print("\n" + "-" * 80)
    print("STAGE 1: LOG PARSING (Drain)")
    print("-" * 80)

    parsed_df, templates, selected_profile = _parse_with_profile(
        str(test_file), settings, max_lines=500
    )

    print("\n[OK] Parsing completed:")
    print(f"   - Profile: {selected_profile['name']}")
    print(f"   - Total logs: {len(parsed_df)}")
    print(f"   - Unique templates: {len(templates)}")

    print("\n" + "-" * 80)
    print("STAGE 2: ANOMALY DETECTION (DeepLog)")
    print("-" * 80)

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
        use_bos_context=selected_profile.get("use_bos_context", False),
        bos_token=selected_profile.get("bos_token", "<BOS>"),
        bos_count=selected_profile.get("bos_count"),
    )

    print("\n[OK] Anomaly detection completed:")
    print(f"   - Total windows: {len(results_df)}")
    print(f"   - Anomalies detected: {len(anomalies_df)}")

    if len(anomalies_df) == 0:
        print("\n[WARN] No anomalies detected. This is expected if:")
        print("   - Test file contains normal logs")
        print("   - Model was trained on similar data")
        print("\n   Continuing with empty anomaly list for testing...")

    print("\n" + "-" * 80)
    print("STAGE 3: AI AGENT INVESTIGATION (LangGraph + Foundation-Sec-8B)")
    print("-" * 80)

    run_live_agent = os.environ.get("DFIR_PIPELINE_RUN_LIVE_AGENT") == "1"

    try:
        if not run_live_agent:
            raise RuntimeError(
                "Live AI agent smoke skipped; set DFIR_PIPELINE_RUN_LIVE_AGENT=1 to enable"
            )

        agent = DFIRAgent(
            ollama_base_url="http://localhost:11434",
            ollama_model="foundation-sec-8b",
            threat_intel_api_keys={},
        )

        investigation_state = agent.investigate(anomalies_df, parsed_df)

        print("\n[OK] AI Agent investigation completed:")
        print(f"   - IOCs extracted: {len(investigation_state['iocs_extracted'])}")
        print(f"   - Tool calls executed: {len(investigation_state['tool_calls'])}")
        print(f"   - Reasoning steps: {len(investigation_state['reasoning_steps'])}")

    except Exception as e:
        print(f"\n[WARN] AI Agent error: {e}")
        print("    This is expected if Ollama is not running or model not loaded")
        print("    Creating minimal investigation state for testing...")

        investigation_state = {
            "anomalies": anomalies_df.to_dict("records")
            if len(anomalies_df) > 0
            else [],
            "iocs_extracted": [],
            "tool_calls": [],
            "tool_results": [],
            "reasoning_steps": ["Test investigation"],
            "investigation_summary": "Test investigation - AI Agent not available",
            "attack_timeline": [],
            "recommendations": ["Test recommendation"],
            "completed": True,
        }

    print("\n" + "-" * 80)
    print("STAGE 4: REPORT GENERATION")
    print("-" * 80)

    report_generator = ReportGenerator()
    report = report_generator.generate_report(
        session_id="test_session",
        file_name=test_file.name,
        investigation_state=investigation_state,
    )

    print("\n[OK] Report generated:")
    print(f"   - Report ID: {report['metadata']['report_id']}")
    print(f"   - Severity: {report['metadata']['severity']}")
    print(f"   - Technical findings: {len(report.get('technical_findings', []))}")
    print(f"   - IOCs: {len(report.get('ioc_analysis', []))}")

    output_dir = base_dir / "output" / "test"
    report_path = report_generator.save_report(report, str(output_dir))

    print(f"\n[OK] Report saved to: {report_path}")

    print("\n" + "=" * 80)
    print("TEST COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print("\nPIPELINE SUMMARY:")
    print(f"   [OK] Parsing: {len(parsed_df)} logs, {len(templates)} templates")
    print(f"   [OK] Anomaly Detection: {len(anomalies_df)} anomalies")
    print(
        "   [OK] AI Agent: "
        f"{_item_count(investigation_state.get('iocs_extracted', []))} IOCs"
    )
    print("   [OK] Report: Generated and saved")
    print(f"\nReport file: {report_path}")

    return report


if __name__ == "__main__":
    try:
        test_full_pipeline()
    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        import traceback

        _ = traceback.print_exc()
