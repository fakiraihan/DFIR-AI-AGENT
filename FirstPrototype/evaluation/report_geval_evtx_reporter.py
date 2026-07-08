from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any


EVALUATION_DIR = Path(__file__).resolve().parent
LATEST_RESULTS_PATH = EVALUATION_DIR / "results" / "report_geval_evtx_latest.json"
REPORT_PATH = EVALUATION_DIR / "reports" / "report_geval_evtx_eval.md"


def _pct(value: float | int | None) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "n/a"


def _num(value: Any) -> int | None:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def _mean(values: list[float]) -> float:
    return mean(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    return pstdev(values) if len(values) > 1 else 0.0


def _ascii(text: Any, *, max_chars: int | None = None) -> str:
    normalized = unicodedata.normalize("NFKD", str(text or ""))
    normalized = normalized.translate(
        str.maketrans(
            {
                "\u2013": "-",
                "\u2014": "-",
                "\u2018": "'",
                "\u2019": "'",
                "\u201c": '"',
                "\u201d": '"',
                "\u2022": "-",
            }
        )
    )
    ascii_text = normalized.encode("ascii", errors="ignore").decode("ascii")
    ascii_text = re.sub(r"\s+", " ", ascii_text).strip().replace("|", "/")
    if max_chars and len(ascii_text) > max_chars:
        return ascii_text[: max_chars - 3].rstrip() + "..."
    return ascii_text


def _runs_by_case(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in payload.get("runs", []):
        grouped[str(run.get("case_id"))].append(run)
    return grouped


def _outputs_for_case(
    case_runs: list[dict[str, Any]], mode: str | None = None
) -> list[dict[str, Any]]:
    outputs = [
        output
        for run in case_runs
        for output in run.get("output_evaluations", [])
        if mode is None or output.get("output_mode") == mode
    ]
    return outputs


def _score_summary(outputs: list[dict[str, Any]]) -> tuple[float, float]:
    if not outputs:
        return 0.0, 0.0
    scores = [float(output.get("score") or 0.0) for output in outputs]
    pass_rate = sum(1 for output in outputs if output.get("success")) / len(outputs)
    return _mean(scores), pass_rate


def _validation_row_for_case(
    preflight: dict[str, Any], case_id: str
) -> dict[str, Any]:
    for item in preflight.get("dataset", {}).get("cases", []):
        if item.get("case_id") == case_id:
            return item.get("runtime_validation") or {}
    return {}


def _case_check_for_case(preflight: dict[str, Any], case_id: str) -> dict[str, Any]:
    for item in preflight.get("dataset", {}).get("cases", []):
        if item.get("case_id") == case_id:
            return item
    return {}


def _first_pipeline_for_case(case_runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not case_runs:
        return {}
    return case_runs[0].get("pipeline_evidence", {})


def _selected_file_table(payload: dict[str, Any]) -> list[str]:
    rows = [
        "| Case ID | Tactic | Selected EVTX | Size | Profile | Parsed Events | Windows | Anomalies | Detected | Cap Hit |",
        "|---|---|---|---:|---|---:|---:|---:|---|---|",
    ]
    preflight = payload.get("preflight", {})
    grouped = _runs_by_case(payload)
    case_metadata = {
        case.get("case_id"): case for case in payload.get("cases", [])
    }
    selected_cases = preflight.get("dataset", {}).get("cases") or payload.get("cases", [])
    for selected in selected_cases:
        case_id = selected["case_id"]
        case = case_metadata.get(case_id, selected)
        check = _case_check_for_case(preflight, case_id) or selected
        validation = _validation_row_for_case(preflight, case_id)
        pipeline = _first_pipeline_for_case(grouped.get(case_id, []))
        cap_hit = (
            pipeline.get("max_lines_reached")
            if pipeline
            else check.get("max_lines_cap_hit_in_validation")
        )
        rows.append(
            "| {case_id} | {tactic} | `{path}` | {size} | {profile} | {events} | {windows} | {anomalies} | {detected} | {cap_hit} |".format(
                case_id=case_id,
                tactic=_ascii(case.get("tactic_folder")),
                path=_ascii(case.get("relative_path")),
                size=check.get("size_bytes") or case.get("expected_size_bytes"),
                profile=_ascii(validation.get("profile") or case.get("expected_profile")),
                events=validation.get("parsed_events") or "n/a",
                windows=validation.get("windows") or "n/a",
                anomalies=validation.get("anomalies")
                or case.get("expected_runtime_anomalies"),
                detected=validation.get("detected")
                if validation.get("detected") is not None
                else case.get("expected_runtime_detected"),
                cap_hit="yes" if cap_hit else "no",
            )
        )
    return rows


def _model_config_section(payload: dict[str, Any]) -> list[str]:
    config = payload.get("config", {})
    preflight = payload.get("preflight", {})
    live = preflight.get("live_threat_intel", {})
    required = live.get("required", {})
    optional = live.get("optional", {})
    return [
        "## Model and Runtime Configuration",
        "",
        f"- Subject under test: `{config.get('subject_under_test')}`.",
        f"- Subject LLM: `{config.get('subject_llm_provider')}::{config.get('subject_ollama_model')}` at `{config.get('subject_ollama_base_url')}`.",
        f"- Judge model: `{config.get('judge_model')}` through `{config.get('judge_base_url')}`.",
        f"- Threshold: `{config.get('threshold')}`.",
        f"- Repetitions per case: `{config.get('repetitions')}`.",
        f"- Parsing cap: `{config.get('max_lines')}` lines/events (`EVAL_REPORT_GEEVAL_MAX_LINES`).",
        f"- Output modes scored: `{', '.join(config.get('output_modes', []))}`.",
        f"- Live threat-intel required keys ready: `{live.get('required_ready')}`.",
        f"- Core live keys present: `{', '.join(key for key, value in required.items() if value) or 'none'}`.",
        f"- Optional live keys present: `{', '.join(key for key, value in optional.items() if value) or 'none'}`.",
    ]


def _live_enrichment_section(payload: dict[str, Any]) -> list[str]:
    runs = payload.get("runs", [])
    status_counts: Counter[str] = Counter()
    total_iocs = 0
    total_internal_iocs = 0
    total_tool_calls = 0
    total_tool_results = 0
    supporting_evidence = 0
    for run in runs:
        live = run.get("live_enrichment", {})
        total_iocs += int(live.get("iocs_extracted_count") or 0)
        total_internal_iocs += int(live.get("internal_ioc_count") or 0)
        total_tool_calls += int(live.get("tool_calls_count") or 0)
        total_tool_results += int(live.get("tool_results_count") or 0)
        supporting_evidence += int(live.get("supporting_evidence_count") or 0)
        status_counts.update(live.get("tool_result_status_counts") or {})

    status_text = (
        ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items()))
        if status_counts
        else "none"
    )
    return [
        "## Live Enrichment Evidence",
        "",
        "The subject pipeline performs IOC extraction and live threat-intel enrichment before report generation. G-Eval is instructed to treat missing, empty, private, or error-prone enrichment as evidence boundaries rather than as proof of benign or malicious behavior.",
        "",
        f"- Total extracted IOCs across runs: `{total_iocs}`.",
        f"- Internal/private IOC observations across runs: `{total_internal_iocs}`.",
        f"- Tool calls across runs: `{total_tool_calls}`.",
        f"- Tool results across runs: `{total_tool_results}`.",
        f"- Supporting evidence records across runs: `{supporting_evidence}`.",
        f"- Tool result status counts: `{status_text}`.",
    ]


def _aggregate_results_section(payload: dict[str, Any]) -> list[str]:
    summary = payload.get("summary", {})
    lines = [
        "## Aggregate G-Eval Results",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total cases | {summary.get('total_cases', 0)} |",
        f"| Total case runs | {summary.get('total_case_runs', 0)} |",
        f"| Total output evaluations | {summary.get('total_output_evaluations', 0)} |",
        f"| Mean G-Eval score | {float(summary.get('mean_geval_score') or 0.0):.3f} |",
        f"| Pass rate | {_pct(summary.get('pass_rate'))} |",
        "",
        "### JSON vs Markdown",
        "",
        "| Output Mode | Runs | Mean Score | Pass Rate |",
        "|---|---:|---:|---:|",
    ]
    for mode, values in sorted(summary.get("output_mode_summary", {}).items()):
        lines.append(
            "| {mode} | {runs} | {score:.3f} | {pass_rate} |".format(
                mode=mode,
                runs=values.get("runs", 0),
                score=float(values.get("mean_score") or 0.0),
                pass_rate=_pct(values.get("pass_rate")),
            )
        )

    lines.extend(
        [
            "",
            "### Macro Average per Tactic",
            "",
            "| Tactic | Runs | Mean Score | Pass Rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for tactic, values in sorted(summary.get("macro_average_by_tactic", {}).items()):
        lines.append(
            "| {tactic} | {runs} | {score:.3f} | {pass_rate} |".format(
                tactic=_ascii(tactic),
                runs=values.get("runs", 0),
                score=float(values.get("mean_score") or 0.0),
                pass_rate=_pct(values.get("pass_rate")),
            )
        )
    return lines


def _per_case_results_section(payload: dict[str, Any]) -> list[str]:
    grouped = _runs_by_case(payload)
    stability = payload.get("summary", {}).get("case_stability", {})
    lines = [
        "## Per-Case Results and Stability",
        "",
        "| Case ID | Tactic | Runs | JSON Mean | Markdown Mean | Pass Rate | Score StdDev | Unique JSON/MD | Runtime Seconds Mean |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case in payload.get("cases", []):
        case_id = case["case_id"]
        case_runs = grouped.get(case_id, [])
        json_mean, _ = _score_summary(_outputs_for_case(case_runs, "json"))
        md_mean, _ = _score_summary(_outputs_for_case(case_runs, "markdown"))
        all_outputs = _outputs_for_case(case_runs)
        _, pass_rate = _score_summary(all_outputs)
        scores = [float(output.get("score") or 0.0) for output in all_outputs]
        hashes = stability.get(case_id, {}).get("unique_output_hashes_by_mode", {})
        runtime_values = [float(run.get("runtime_seconds") or 0.0) for run in case_runs]
        lines.append(
            "| {case_id} | {tactic} | {runs} | {json_mean:.3f} | {md_mean:.3f} | {pass_rate} | {stddev:.3f} | {unique_json}/{unique_md} | {runtime:.2f} |".format(
                case_id=case_id,
                tactic=_ascii(case.get("tactic_folder")),
                runs=len(case_runs),
                json_mean=json_mean,
                md_mean=md_mean,
                pass_rate=_pct(pass_rate),
                stddev=_stddev(scores),
                unique_json=hashes.get("json", 0),
                unique_md=hashes.get("markdown", 0),
                runtime=_mean(runtime_values),
            )
        )
    return lines


def _failure_analysis_section(payload: dict[str, Any]) -> list[str]:
    failures = []
    threshold = float(payload.get("config", {}).get("threshold") or 0.0)
    for run in payload.get("runs", []):
        for output in run.get("output_evaluations", []):
            score = float(output.get("score") or 0.0)
            if (
                score < threshold
                or not output.get("success")
                or output.get("error")
                or output.get("assertion_error")
            ):
                failures.append((run, output))

    lines = [
        "## Failure Analysis",
        "",
        "| Case ID | Run | Mode | Score | Success | Reason / Error |",
        "|---|---:|---|---:|---|---|",
    ]
    if not failures:
        lines.append(
            "| None | - | - | - | - | All evaluated outputs met the configured threshold. |"
        )
        return lines

    for run, output in failures:
        reason = (
            output.get("reason")
            or output.get("error")
            or output.get("assertion_error")
            or "No judge reason recorded."
        )
        lines.append(
            "| {case_id} | {rep} | {mode} | {score:.3f} | {success} | {reason} |".format(
                case_id=run.get("case_id"),
                rep=run.get("repetition"),
                mode=output.get("output_mode"),
                score=float(output.get("score") or 0.0),
                success=bool(output.get("success")),
                reason=_ascii(reason, max_chars=260),
            )
        )
    return lines


def _methodology_section(payload: dict[str, Any]) -> list[str]:
    config = payload.get("config", {})
    return [
        "## Methodology",
        "",
        "This benchmark evaluates the final FirstPrototype DFIR report generated from EVTX Attack Samples. The subject under test is the full EVTX-to-report path: EVTX parsing, DeepLog anomaly detection, local Ollama LLM filtering, DFIR agent investigation, live threat-intel enrichment, and report rendering.",
        "",
        "The candidate selection rule is deterministic: for each selected MITRE tactic folder, choose the largest `.evtx` file by byte size; if multiple files tie, choose the alphabetically earliest relative path. The v1 strata include only the eight named tactic folders and exclude `AutomatedTestingTools`, `Other`, metadata folders, and the root-level `UACME_59_Sysmon.evtx` file.",
        "",
        "DeepEval `GEval` scores both structured JSON output and rendered Markdown output. The judge receives EVTX runtime context, expected tactic focus, anomaly summary, IOC/tool-result summary, and the final report. The scoring instructions explicitly penalize unsupported compromise claims, malicious labeling of private/internal IOCs without tool evidence, and severity inflation based only on anomaly volume.",
        "",
        "The benchmark repeats each case to estimate stability. Stability is represented by pass rate, score standard deviation, and unique output hashes per output mode.",
        "",
        f"- Runner path: `{payload.get('runner_path')}`.",
        f"- DeepEval test entrypoint: `{payload.get('test_entrypoint')}`.",
        f"- Dataset path: `{payload.get('dataset_path')}`.",
        f"- Results path: `{payload.get('results_path')}`.",
        f"- Runtime artifact directory: `{payload.get('runtime_dir')}`.",
        f"- Selection rule: `{config.get('selection_rule')}`.",
    ]


def _limitations_section(payload: dict[str, Any]) -> list[str]:
    max_lines = payload.get("config", {}).get("max_lines", 20000)
    return [
        "## Limitations",
        "",
        "- EVTX Attack Samples are attack-positive samples, but that does not mean every parsed event is malicious or that the generated report may claim compromise without evidence.",
        "- Largest-file selection improves deterministic coverage of high-volume telemetry, but it can bias the dataset toward noisy samples rather than clinically representative incidents.",
        f"- The parser cap is `{max_lines}`. Large samples, especially the Credential Access PetiPotam EVTX, can hit the cap and must disclose that limitation.",
        "- Live threat-intel APIs are variable over time. Empty, rate-limited, or error responses are part of the evidence boundary and should be reported as limitations.",
        "- Private IPs, `.corp`, `.local`, `.example`, and similar internal identifiers are local telemetry by default; public enrichment absence should not be treated as proof of benign or malicious behavior.",
        "- G-Eval is an LLM-as-judge metric. Repeated runs measure subject-output stability, but judge interpretation can still vary across model versions or provider behavior.",
        "- The evaluation focuses on report quality and evidence alignment, not on proving that the underlying DeepLog anomaly detector is an authoritative attack classifier.",
    ]


def build_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    selected_case_count = (
        payload.get("preflight", {}).get("dataset", {}).get("case_count")
        or summary.get("total_cases", 0)
    )
    lines = [
        "# EVTX Report G-Eval Evaluation Report",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        "This report evaluates whether FirstPrototype produces evidence-grounded final DFIR reports for selected EVTX Attack Samples. The subject LLM is local Ollama `sec-foundation:8b-gpu`; DeepEval G-Eval uses the OpenAI-compatible judge configured in `evaluation/.env`.",
        "",
        f"- Selected EVTX cases in preflight: `{selected_case_count}`.",
        f"- Total cases: `{summary.get('total_cases', 0)}`.",
        f"- Run coverage: `{'full' if summary.get('total_cases', 0) == selected_case_count else 'subset/smoke'}`.",
        f"- Repetitions per case: `{summary.get('repetitions_per_case', 0)}`.",
        f"- Total output evaluations: `{summary.get('total_output_evaluations', 0)}`.",
        f"- Mean G-Eval score: `{float(summary.get('mean_geval_score') or 0.0):.3f}`.",
        f"- Pass rate: `{_pct(summary.get('pass_rate'))}`.",
        "",
    ]
    lines.extend(_methodology_section(payload))
    lines.extend(["", "## Selected EVTX Cases", ""])
    lines.extend(_selected_file_table(payload))
    lines.extend([""])
    lines.extend(_model_config_section(payload))
    lines.extend([""])
    lines.extend(_live_enrichment_section(payload))
    lines.extend([""])
    lines.extend(_aggregate_results_section(payload))
    lines.extend([""])
    lines.extend(_per_case_results_section(payload))
    lines.extend([""])
    lines.extend(_failure_analysis_section(payload))
    lines.extend([""])
    lines.extend(_limitations_section(payload))
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an academic Markdown report for EVTX report G-Eval."
    )
    parser.add_argument("--results", type=Path, default=LATEST_RESULTS_PATH)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    args = parser.parse_args()

    payload = json.loads(args.results.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(payload), encoding="utf-8")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
