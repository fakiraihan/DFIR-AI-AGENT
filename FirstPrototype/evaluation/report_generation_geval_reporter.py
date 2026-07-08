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
LATEST_RESULTS_PATH = EVALUATION_DIR / "results" / "report_generation_geval_latest.json"
REPORT_PATH = EVALUATION_DIR / "reports" / "report_generation_geval_eval.md"


def _pct(value: float | int | None) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "n/a"


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


def _outputs(case_runs: list[dict[str, Any]], mode: str | None = None):
    return [
        output
        for run in case_runs
        for output in run.get("output_evaluations", [])
        if mode is None or output.get("output_mode") == mode
    ]


def _all_outputs(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        output
        for run in payload.get("runs", [])
        for output in run.get("output_evaluations", [])
    ]


def _has_judge_error(output: dict[str, Any]) -> bool:
    return bool(output.get("judge_error")) or any(
        metric.get("error") for metric in output.get("metric_scores", [])
    )


def _score_summary(outputs: list[dict[str, Any]]) -> tuple[float, float]:
    if not outputs:
        return 0.0, 0.0
    scores = [float(output.get("score") or 0.0) for output in outputs]
    pass_rate = sum(1 for output in outputs if output.get("success")) / len(outputs)
    return mean(scores), pass_rate


def _metric_dimension_summary(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from_summary = payload.get("summary", {}).get("metric_dimension_summary")
    if from_summary:
        return from_summary

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in payload.get("runs", []):
        for output in run.get("output_evaluations", []):
            for metric in output.get("metric_scores", []):
                grouped[str(metric.get("name"))].append(metric)

    summary = {}
    for name, rows in grouped.items():
        scores = [float(row.get("score") or 0.0) for row in rows]
        summary[name] = {
            "runs": len(rows),
            "mean_score": mean(scores) if scores else 0.0,
            "pass_rate": (
                sum(1 for row in rows if row.get("success")) / len(rows)
                if rows
                else 0.0
            ),
        }
    return summary


def _evidence_table(payload: dict[str, Any]) -> list[str]:
    rows = [
        "| Case ID | Tactic | EVTX | Profile | Parsed | Anomalies | IOCs | Tool Results | Capture Seconds | Cap Hit |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for case in payload.get("cases", []):
        pipeline = case.get("pipeline_evidence") or {}
        live = case.get("live_enrichment") or {}
        capture = case.get("capture_provenance") or {}
        rows.append(
            "| {case_id} | {tactic} | `{path}` | {profile} | {parsed} | {anomalies} | {iocs} | {tools} | {seconds:.2f} | {cap_hit} |".format(
                case_id=case.get("case_id"),
                tactic=_ascii(case.get("tactic_folder")),
                path=_ascii(case.get("relative_path")),
                profile=_ascii(pipeline.get("validation_profile")),
                parsed=pipeline.get("parsed_events", "n/a"),
                anomalies=pipeline.get("deeplog_anomalies", "n/a"),
                iocs=live.get("iocs_extracted_count", "n/a"),
                tools=live.get("tool_results_count", "n/a"),
                seconds=float(capture.get("capture_runtime_seconds") or 0.0),
                cap_hit="yes" if pipeline.get("max_lines_reached") else "no",
            )
        )
    return rows


def _aggregate_section(payload: dict[str, Any]) -> list[str]:
    summary = payload.get("summary", {})
    all_outputs = _all_outputs(payload)
    judge_error_count = sum(1 for output in all_outputs if _has_judge_error(output))
    quality_outputs = [output for output in all_outputs if not _has_judge_error(output)]
    quality_scores = [float(output.get("score") or 0.0) for output in quality_outputs]
    judge_skipped_count = sum(
        1 for output in all_outputs if output.get("judge_skipped")
    )
    judge_cache_hits = sum(
        1 for output in all_outputs if output.get("judge_cache_hit")
    )
    deterministic_failed = sum(
        1
        for output in all_outputs
        if not (output.get("deterministic_checks") or {}).get("success", True)
    )
    quality_pass_rate = (
        sum(1 for output in quality_outputs if output.get("success"))
        / len(quality_outputs)
        if quality_outputs
        else 0.0
    )
    lines = [
        "## Aggregate Replay Results",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total cases | {summary.get('total_cases', 0)} |",
        f"| Total case runs | {summary.get('total_case_runs', 0)} |",
        f"| Total output evaluations | {summary.get('total_output_evaluations', 0)} |",
        f"| Quality output evaluations | {len(quality_outputs) if all_outputs else summary.get('quality_output_evaluations', summary.get('total_output_evaluations', 0))} |",
        f"| Judge-error output evaluations | {judge_error_count if all_outputs else summary.get('judge_error_output_evaluations', 0)} |",
        f"| Judge-skipped output evaluations | {judge_skipped_count if all_outputs else summary.get('judge_skipped_output_evaluations', 0)} |",
        f"| Judge-cache hits | {judge_cache_hits if all_outputs else summary.get('judge_cache_hit_output_evaluations', 0)} |",
        f"| Deterministic precheck failures | {deterministic_failed if all_outputs else summary.get('deterministic_failed_output_evaluations', 0)} |",
        f"| Mean G-Eval score | {float(summary.get('mean_geval_score') or 0.0):.3f} |",
        f"| Mean quality G-Eval score | {(mean(quality_scores) if quality_scores else float(summary.get('mean_quality_geval_score') or 0.0)):.3f} |",
        f"| Pass rate | {_pct(summary.get('pass_rate'))} |",
        f"| Quality pass rate | {_pct(quality_pass_rate if all_outputs else summary.get('quality_pass_rate', summary.get('pass_rate')))} |",
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
    dimension_summary = _metric_dimension_summary(payload)
    if dimension_summary:
        lines.extend(
            [
                "",
                "### G-Eval Metric Dimensions",
                "",
                "| Dimension | Runs | Mean Score | Pass Rate |",
                "|---|---:|---:|---:|",
            ]
        )
        for name, values in sorted(dimension_summary.items()):
            lines.append(
                "| {name} | {runs} | {score:.3f} | {pass_rate} |".format(
                    name=_ascii(name),
                    runs=values.get("runs", 0),
                    score=float(values.get("mean_score") or 0.0),
                    pass_rate=_pct(values.get("pass_rate")),
                )
            )
    return lines


def _per_case_section(payload: dict[str, Any]) -> list[str]:
    grouped = _runs_by_case(payload)
    stability = payload.get("summary", {}).get("case_stability", {})
    lines = [
        "## Per-Case Replay Stability",
        "",
        "| Case ID | Tactic | Runs | JSON Mean | Markdown Mean | Pass Rate | Score StdDev | Unique JSON/MD | Runtime Seconds Mean |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case in payload.get("cases", []):
        case_id = case.get("case_id")
        runs = grouped.get(case_id, [])
        json_mean, _ = _score_summary(_outputs(runs, "json"))
        md_mean, _ = _score_summary(_outputs(runs, "markdown"))
        all_outputs = _outputs(runs)
        _, pass_rate = _score_summary(all_outputs)
        scores = [float(output.get("score") or 0.0) for output in all_outputs]
        stddev = pstdev(scores) if len(scores) > 1 else 0.0
        hashes = stability.get(case_id, {}).get("unique_output_hashes_by_mode", {})
        runtime_values = [float(run.get("runtime_seconds") or 0.0) for run in runs]
        runtime_mean = mean(runtime_values) if runtime_values else 0.0
        lines.append(
            "| {case_id} | {tactic} | {runs} | {json_mean:.3f} | {md_mean:.3f} | {pass_rate} | {stddev:.3f} | {unique_json}/{unique_md} | {runtime:.2f} |".format(
                case_id=case_id,
                tactic=_ascii(case.get("tactic_folder")),
                runs=len(runs),
                json_mean=json_mean,
                md_mean=md_mean,
                pass_rate=_pct(pass_rate),
                stddev=stddev,
                unique_json=hashes.get("json", 0),
                unique_md=hashes.get("markdown", 0),
                runtime=runtime_mean,
            )
        )
    return lines


def _failure_section(payload: dict[str, Any]) -> list[str]:
    threshold = float(payload.get("config", {}).get("threshold") or 0.0)
    failures = []
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
        "| Case ID | Run | Mode | Score | Success | Judge Error | Reason / Error |",
        "|---|---:|---|---:|---|---|---|",
    ]
    if not failures:
        lines.append(
            "| None | - | - | - | - | - | All evaluated outputs met the configured threshold. |"
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
            "| {case_id} | {rep} | {mode} | {score:.3f} | {success} | {judge_error} | {reason} |".format(
                case_id=run.get("case_id"),
                rep=run.get("repetition"),
                mode=output.get("output_mode"),
                score=float(output.get("score") or 0.0),
                success=bool(output.get("success")),
                judge_error=_has_judge_error(output),
                reason=_ascii(reason, max_chars=260),
            )
        )
    return lines


def _live_evidence_section(payload: dict[str, Any]) -> list[str]:
    status_counts: Counter[str] = Counter()
    total_iocs = 0
    total_tools = 0
    total_internal = 0
    for case in payload.get("cases", []):
        live = case.get("live_enrichment") or {}
        total_iocs += int(live.get("iocs_extracted_count") or 0)
        total_tools += int(live.get("tool_results_count") or 0)
        total_internal += int(live.get("internal_ioc_count") or 0)
        status_counts.update(live.get("tool_result_status_counts") or {})

    status_text = (
        ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items()))
        if status_counts
        else "none"
    )
    return [
        "## Frozen Tool Evidence",
        "",
        "Tool evidence is captured once during evidence capture and replayed unchanged during G-Eval. No live threat-intel API calls are made during replay runs.",
        "",
        f"- Frozen IOC count across selected cases: `{total_iocs}`.",
        f"- Frozen internal/private IOC count: `{total_internal}`.",
        f"- Frozen tool-result count: `{total_tools}`.",
        f"- Frozen tool-result status counts: `{status_text}`.",
    ]


def build_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    config = payload.get("config", {})
    lines = [
        "# Report Generation G-Eval Replay Report",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        "This evaluation isolates FirstPrototype report generation by replaying frozen EVTX evidence. Parsing, DeepLog detection, and live threat-intel enrichment are not repeated during G-Eval runs; only the local Ollama report-generation LLM and deterministic report rendering are exercised.",
        "",
        f"- Evidence mode: `{config.get('evidence_mode')}`.",
        f"- Capture mode: `{config.get('capture_mode')}`.",
        f"- Fixture generated at: `{config.get('fixture_generated_at_utc')}`.",
        f"- Total cases: `{summary.get('total_cases', 0)}`.",
        f"- Repetitions per case: `{summary.get('repetitions_per_case', 0)}`.",
        f"- Mean G-Eval score: `{float(summary.get('mean_geval_score') or 0.0):.3f}`.",
        f"- Pass rate: `{_pct(summary.get('pass_rate'))}`.",
        "",
        "## Methodology",
        "",
        "Phase 1 captures one runtime-like full-pipeline evidence state per EVTX case. The capture uses the runtime-like validation profile, executes threat-intel tools, and stores anomaly, IOC, tool-result, correlation, timeline, and supporting-evidence fields as a fixture.",
        "",
        "Phase 2 repeats report generation from the frozen fixture. Each replay clears prior `investigation_summary` and `recommendations`, injects an evidence brief into the report-generation prompt, invokes local Ollama `sec-foundation:8b-gpu` through `DFIRAgent.generate_summary()`, optionally evaluates the raw LLM `summary` output, renders JSON/Markdown through `ReportGenerator`, and scores outputs with dimensional DeepEval G-Eval using `openai/gpt-5.4` from `evaluation/.env`.",
        "",
        f"- Runner path: `{payload.get('runner_path')}`.",
        f"- Test entrypoint: `{payload.get('test_entrypoint')}`.",
        f"- Fixture path: `{payload.get('fixture_path')}`.",
        f"- Results path: `{payload.get('results_path')}`.",
        f"- Runtime dir: `{payload.get('runtime_dir')}`.",
        f"- Subject LLM: `{config.get('subject_llm_provider')}::{config.get('subject_ollama_model')}` at `{config.get('subject_ollama_base_url')}`.",
        f"- Judge: `{config.get('judge_model')}` at `{config.get('judge_base_url')}`.",
        f"- Prompt strategy: `{config.get('prompt_strategy')}`.",
        f"- G-Eval metric mode: `{config.get('geval_metric_mode')}`.",
        f"- Metric preset: `{config.get('metric_preset')}`.",
        f"- Metric dimensions: `{config.get('metric_dimensions')}`.",
        f"- Judge cache enabled: `{config.get('judge_cache_enabled')}`.",
        f"- Skip judge if deterministic fails: `{config.get('skip_judge_if_deterministic_fails')}`.",
        f"- Live threat-intel per replay: `{config.get('live_threat_intel_per_replay')}`.",
        "",
        "## Frozen Evidence Cases",
        "",
    ]
    lines.extend(_evidence_table(payload))
    lines.extend([""])
    lines.extend(_live_evidence_section(payload))
    lines.extend([""])
    lines.extend(_aggregate_section(payload))
    lines.extend([""])
    lines.extend(_per_case_section(payload))
    lines.extend([""])
    lines.extend(_failure_section(payload))
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- This benchmark evaluates report generation under fixed evidence, not end-to-end detector quality.",
            "- Frozen live-enrichment evidence is timestamped and may differ from future external API responses.",
            "- Replayed report quality can expose prompt/report-generation issues but cannot prove the original anomaly detector is correct.",
            "- Because evidence is fixed, stability reflects local LLM report-generation variance and judge variance rather than parsing or tool API variance.",
            "- Judge endpoint failures such as budget exhaustion are counted separately as judge-error evaluations and should not be interpreted as report-quality failures.",
            "- EVTX Attack Samples are attack-positive samples; generated reports must still avoid unsupported compromise claims.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Markdown report for report-generation G-Eval replay."
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
