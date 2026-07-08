import sys
from pathlib import Path


EVALUATION_DIR = Path(__file__).resolve().parents[1]
if str(EVALUATION_DIR) not in sys.path:
    sys.path.insert(0, str(EVALUATION_DIR))

from report_generation_geval_runner import (  # noqa: E402
    EXPECTED_CASE_COUNT,
    build_evidence_brief,
    build_report_generation_metrics,
    default_output_modes_for_preset,
    load_frozen_evidence_payload,
    output_for_report_generation_mode,
    preflight_replay_checks,
    resolve_metric_names,
    run_deterministic_report_checks,
    run_report_generation_geval_evaluation,
)


def test_report_generation_frozen_fixture_contract():
    payload = preflight_replay_checks()

    assert payload["fixture"]["exists"]
    assert payload["fixture"]["case_count"] == EXPECTED_CASE_COUNT
    assert payload["fixture"]["all_cases_have_frozen_state"]
    assert payload["fixture"]["all_cases_have_tool_evidence"]
    assert payload["ollama"]["reachable"]
    assert payload["ollama"]["model_available"]
    assert payload["judge"]["env_ready"]


def test_firstprototype_report_generation_replay_geval_runs():
    payload = run_report_generation_geval_evaluation()

    summary = payload["summary"]
    assert summary["total_cases"] == EXPECTED_CASE_COUNT
    assert summary["repetitions_per_case"] >= 3
    assert summary["json_output_runs"] == summary["total_case_runs"]
    assert summary["markdown_output_runs"] == summary["total_case_runs"]
    assert payload["config"]["subject_ollama_model"] == "sec-foundation:8b-gpu"
    assert payload["config"]["evidence_mode"] == "frozen_replay"


def test_lateral_movement_evidence_brief_contains_calibration_rules():
    fixture = load_frozen_evidence_payload()
    case = next(
        item
        for item in fixture["cases"]
        if item["tactic_folder"] == "Lateral Movement"
    )

    brief = build_evidence_brief(case, case["frozen_state"])

    assert "Lateral Movement" in brief
    assert "EventID 5145" in brief
    assert "remote share" in brief.lower() or "share" in brief.lower()
    assert "private/internal" in brief.lower()
    assert "anomaly count" in brief.lower()
    assert "not equal to compromise count" in brief.lower()


def test_report_generation_metrics_are_dimensional():
    metrics = build_report_generation_metrics(judge_model=None, threshold=0.8)
    names = {metric.name for metric in metrics}

    assert {
        "Evidence Groundedness",
        "Severity Calibration",
        "Tactic Alignment",
        "Recommendation Specificity",
        "Limitation Honesty",
    } == names


def test_metric_presets_support_budget_tiers():
    assert resolve_metric_names("smoke") == ()
    assert resolve_metric_names("core") == (
        "Evidence Groundedness",
        "Severity Calibration",
    )
    assert default_output_modes_for_preset("smoke") == ("summary",)
    assert default_output_modes_for_preset("core") == ("summary",)
    assert default_output_modes_for_preset("full") == (
        "summary",
        "json",
        "markdown",
    )


def test_metric_builder_accepts_dimension_subset():
    metrics = build_report_generation_metrics(
        judge_model=None,
        threshold=0.8,
        metric_names=("Evidence Groundedness",),
    )

    assert [metric.name for metric in metrics] == ["Evidence Groundedness"]


def test_deterministic_precheck_flags_placeholders_and_overclaims():
    fixture = load_frozen_evidence_payload()
    case = next(
        item
        for item in fixture["cases"]
        if item["tactic_folder"] == "Lateral Movement"
    )
    bad_output = (
        "Confirmed C2 compromise and malware exfiltration. "
        "[Action item with specific steps]"
    )

    result = run_deterministic_report_checks(
        case=case,
        output_mode="summary",
        actual_output=bad_output,
    )
    failed_names = {check["name"] for check in result["failed_checks"]}

    assert not result["success"]
    assert "no_template_placeholders" in failed_names
    assert "mentions_primary_event" in failed_names
    assert "avoids_unsupported_confirmed_claims" in failed_names


def test_deterministic_precheck_passes_grounded_lateral_movement_summary():
    fixture = load_frozen_evidence_payload()
    case = next(
        item
        for item in fixture["cases"]
        if item["tactic_folder"] == "Lateral Movement"
    )
    grounded_output = (
        "Lateral Movement review: EventID 5145 from Microsoft-Windows-Security-Auditing "
        "shows remote share access on host PC01.example.corp by user Administrator "
        "from private/internal IP 10.0.2.15. Enrichment returned no malicious or "
        "suspicious result and several no_result/error limitations, so this is "
        "suspicious telemetry rather than confirmed compromise. Recommendation: triage "
        "EventID 5145 share path, user, host, and IP evidence before containment."
    )

    result = run_deterministic_report_checks(
        case=case,
        output_mode="summary",
        actual_output=grounded_output,
    )

    assert result["success"]


def test_summary_output_mode_uses_llm_generation_text():
    run_record = {
        "llm_summary": "Evidence-bound LLM summary",
        "llm_recommendations": ["Review EventID 5145 share access"],
    }

    output = output_for_report_generation_mode(run_record, "summary")

    assert "Evidence-bound LLM summary" in output
    assert "Review EventID 5145 share access" in output
