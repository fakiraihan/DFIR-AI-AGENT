import sys
from pathlib import Path


EVALUATION_DIR = Path(__file__).resolve().parents[1]
if str(EVALUATION_DIR) not in sys.path:
    sys.path.insert(0, str(EVALUATION_DIR))

from report_geval_evtx_runner import (  # noqa: E402
    EXPECTED_CASE_COUNT,
    preflight_checks,
    run_report_geval_evaluation,
)


def test_evtx_geval_preflight_shape_and_largest_file_selection():
    payload = preflight_checks()

    assert payload["dataset"]["case_count"] == EXPECTED_CASE_COUNT
    assert payload["dataset"]["selection_rule"] == (
        "largest EVTX by byte size per selected MITRE tactic folder; "
        "alphabetical relative path tie-breaker"
    )
    assert payload["dataset"]["all_cases_exist"]
    assert payload["dataset"]["all_cases_largest"]
    assert payload["dataset"]["all_cases_have_runtime_validation"]
    assert payload["dataset"]["all_cases_detected_runtime_like"]
    assert payload["judge"]["env_ready"]


def test_firstprototype_evtx_report_geval_benchmark_runs():
    payload = run_report_geval_evaluation()

    summary = payload["summary"]
    assert summary["total_cases"] == EXPECTED_CASE_COUNT
    assert summary["repetitions_per_case"] >= 3
    assert summary["json_output_runs"] == summary["total_case_runs"]
    assert summary["markdown_output_runs"] == summary["total_case_runs"]
    assert payload["config"]["subject_ollama_model"] == "sec-foundation:8b-gpu"
    assert payload["config"]["judge_model"]
