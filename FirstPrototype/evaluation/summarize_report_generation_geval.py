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
SOURCE_JSON = EVALUATION_DIR / "results" / "report_generation_geval_latest.json"
SUMMARY_JSON = EVALUATION_DIR / "results" / "report_generation_geval_summary.json"
RESUME_MD = EVALUATION_DIR / "reports" / "report_generation_geval_resume.md"


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


def _pct(value: float | int | None) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "n/a"


def _mean(values: list[float]) -> float:
    return mean(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    return pstdev(values) if len(values) > 1 else 0.0


def outputs_for_run(run: dict[str, Any], mode: str | None = None) -> list[dict[str, Any]]:
    return [
        output
        for output in run.get("output_evaluations", [])
        if mode is None or output.get("output_mode") == mode
    ]


def has_judge_error(output: dict[str, Any]) -> bool:
    return bool(output.get("judge_error")) or any(
        metric.get("error") for metric in output.get("metric_scores", [])
    )


def score_summary(outputs: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [float(output.get("score") or 0.0) for output in outputs]
    return {
        "runs": len(outputs),
        "mean_score": _mean(scores),
        "score_stddev": _stddev(scores),
        "pass_rate": (
            sum(1 for output in outputs if output.get("success")) / len(outputs)
            if outputs
            else 0.0
        ),
        "min_score": min(scores) if scores else 0.0,
        "max_score": max(scores) if scores else 0.0,
    }


def metric_dimension_summary(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from_summary = payload.get("summary", {}).get("metric_dimension_summary")
    if from_summary:
        return from_summary

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in payload.get("runs", []):
        for output in outputs_for_run(run):
            for metric in output.get("metric_scores", []):
                grouped[str(metric.get("name"))].append(metric)

    summary = {}
    for name, rows in grouped.items():
        scores = [float(row.get("score") or 0.0) for row in rows]
        summary[name] = {
            "runs": len(rows),
            "mean_score": _mean(scores),
            "score_stddev": _stddev(scores),
            "pass_rate": (
                sum(1 for row in rows if row.get("success")) / len(rows)
                if rows
                else 0.0
            ),
            "min_score": min(scores) if scores else 0.0,
            "max_score": max(scores) if scores else 0.0,
        }
    return summary


def build_compact_summary(payload: dict[str, Any], source_path: Path) -> dict[str, Any]:
    runs_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in payload.get("runs", []):
        runs_by_case[run.get("case_id")].append(run)

    case_rows = []
    total_iocs = 0
    total_internal_iocs = 0
    total_tool_results = 0
    tool_status_counts: Counter[str] = Counter()

    for case in payload.get("cases", []):
        case_id = case.get("case_id")
        case_runs = runs_by_case.get(case_id, [])
        outputs = [output for run in case_runs for output in outputs_for_run(run)]
        json_outputs = [
            output for run in case_runs for output in outputs_for_run(run, "json")
        ]
        markdown_outputs = [
            output for run in case_runs for output in outputs_for_run(run, "markdown")
        ]
        pipeline = case.get("pipeline_evidence") or {}
        live = case.get("live_enrichment") or {}
        capture = case.get("capture_provenance") or {}
        total_iocs += int(live.get("iocs_extracted_count") or 0)
        total_internal_iocs += int(live.get("internal_ioc_count") or 0)
        total_tool_results += int(live.get("tool_results_count") or 0)
        tool_status_counts.update(live.get("tool_result_status_counts") or {})

        failed_reasons = [
            _ascii(
                output.get("reason")
                or output.get("error")
                or output.get("assertion_error")
                or "",
                max_chars=220,
            )
            for output in outputs
            if not output.get("success")
        ]
        reason_counts = Counter(failed_reasons)
        case_rows.append(
            {
                "case_id": case_id,
                "tactic": case.get("tactic_folder"),
                "relative_path": case.get("relative_path"),
                "runtime_profile": pipeline.get("validation_profile"),
                "parsed_events": pipeline.get("parsed_events"),
                "deeplog_anomalies": pipeline.get("deeplog_anomalies"),
                "iocs": live.get("iocs_extracted_count"),
                "internal_iocs": live.get("internal_ioc_count"),
                "tool_results": live.get("tool_results_count"),
                "capture_runtime_seconds": capture.get("capture_runtime_seconds"),
                "total_output_summary": score_summary(outputs),
                "json_summary": score_summary(json_outputs),
                "markdown_summary": score_summary(markdown_outputs),
                "top_failure_reasons": [
                    {"reason": reason, "count": count}
                    for reason, count in reason_counts.most_common(3)
                    if reason
                ],
            }
        )

    failure_rows = []
    for run in payload.get("runs", []):
        for output in outputs_for_run(run):
            if output.get("success"):
                continue
            failure_rows.append(
                {
                    "case_id": run.get("case_id"),
                    "tactic": run.get("tactic_folder"),
                    "repetition": run.get("repetition"),
                    "output_mode": output.get("output_mode"),
                    "score": output.get("score"),
                    "threshold": output.get("threshold"),
                    "judge_error": has_judge_error(output),
                    "reason": _ascii(
                        output.get("reason")
                        or output.get("error")
                        or output.get("assertion_error")
                        or "",
                        max_chars=300,
                    ),
                }
            )

    weakest_tactics = sorted(
        payload.get("summary", {}).get("macro_average_by_tactic", {}).items(),
        key=lambda item: float(item[1].get("mean_score") or 0.0),
    )
    all_outputs = [
        output for run in payload.get("runs", []) for output in outputs_for_run(run)
    ]
    quality_outputs = [
        output for output in all_outputs if not has_judge_error(output)
    ]
    quality_scores = [float(output.get("score") or 0.0) for output in quality_outputs]
    aggregate = dict(payload.get("summary", {}))
    if all_outputs:
        aggregate["judge_error_output_evaluations"] = sum(
            1 for output in all_outputs if has_judge_error(output)
        )
        aggregate["judge_skipped_output_evaluations"] = sum(
            1 for output in all_outputs if output.get("judge_skipped")
        )
        aggregate["judge_cache_hit_output_evaluations"] = sum(
            1 for output in all_outputs if output.get("judge_cache_hit")
        )
        aggregate["deterministic_failed_output_evaluations"] = sum(
            1
            for output in all_outputs
            if not (output.get("deterministic_checks") or {}).get("success", True)
        )
        aggregate["quality_output_evaluations"] = len(quality_outputs)
        aggregate["mean_quality_geval_score"] = _mean(quality_scores)
        aggregate["quality_pass_rate"] = (
            sum(1 for output in quality_outputs if output.get("success"))
            / len(quality_outputs)
            if quality_outputs
            else 0.0
        )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_json": str(source_path),
        "source_json_size_bytes": source_path.stat().st_size if source_path.exists() else None,
        "source_generated_at_utc": payload.get("generated_at_utc"),
        "partial": payload.get("partial"),
        "config": {
            "evidence_mode": payload.get("config", {}).get("evidence_mode"),
            "capture_mode": payload.get("config", {}).get("capture_mode"),
            "fixture_generated_at_utc": payload.get("config", {}).get(
                "fixture_generated_at_utc"
            ),
            "subject_ollama_model": payload.get("config", {}).get(
                "subject_ollama_model"
            ),
            "judge_model": payload.get("config", {}).get("judge_model"),
            "threshold": payload.get("config", {}).get("threshold"),
            "prompt_strategy": payload.get("config", {}).get("prompt_strategy"),
            "geval_metric_mode": payload.get("config", {}).get("geval_metric_mode"),
            "metric_preset": payload.get("config", {}).get("metric_preset"),
            "metric_dimensions": payload.get("config", {}).get("metric_dimensions"),
            "judge_cache_enabled": payload.get("config", {}).get(
                "judge_cache_enabled"
            ),
            "skip_judge_if_deterministic_fails": payload.get("config", {}).get(
                "skip_judge_if_deterministic_fails"
            ),
            "live_threat_intel_per_replay": payload.get("config", {}).get(
                "live_threat_intel_per_replay"
            ),
        },
        "aggregate": aggregate,
        "metric_dimension_summary": metric_dimension_summary(payload),
        "evidence_totals": {
            "iocs": total_iocs,
            "internal_iocs": total_internal_iocs,
            "tool_results": total_tool_results,
            "tool_result_status_counts": dict(sorted(tool_status_counts.items())),
        },
        "weakest_tactics": [
            {
                "tactic": tactic,
                "mean_score": values.get("mean_score"),
                "pass_rate": values.get("pass_rate"),
                "runs": values.get("runs"),
            }
            for tactic, values in weakest_tactics
        ],
        "case_summaries": case_rows,
        "failures": failure_rows,
        "artifact_paths": {
            "runner_path": payload.get("runner_path"),
            "test_entrypoint": payload.get("test_entrypoint"),
            "fixture_path": payload.get("fixture_path"),
            "results_path": payload.get("results_path"),
            "runtime_dir": payload.get("runtime_dir"),
        },
    }


def build_markdown(summary: dict[str, Any]) -> str:
    aggregate = summary.get("aggregate", {})
    lines = [
        "# Report Generation G-Eval Resume",
        "",
        f"Generated at: {summary.get('generated_at_utc')}",
        "",
        "## High-Level Result",
        "",
        f"- Source JSON: `{summary.get('source_json')}`.",
        f"- Source size: `{summary.get('source_json_size_bytes')}` bytes.",
        f"- Evidence mode: `{summary.get('config', {}).get('evidence_mode')}`.",
        f"- Subject model: `{summary.get('config', {}).get('subject_ollama_model')}`.",
        f"- Judge model: `{summary.get('config', {}).get('judge_model')}`.",
        f"- Prompt strategy: `{summary.get('config', {}).get('prompt_strategy')}`.",
        f"- G-Eval metric mode: `{summary.get('config', {}).get('geval_metric_mode')}`.",
        f"- Metric preset: `{summary.get('config', {}).get('metric_preset')}`.",
        f"- Metric dimensions: `{summary.get('config', {}).get('metric_dimensions')}`.",
        f"- Judge cache enabled: `{summary.get('config', {}).get('judge_cache_enabled')}`.",
        f"- Skip judge if deterministic fails: `{summary.get('config', {}).get('skip_judge_if_deterministic_fails')}`.",
        f"- Total cases: `{aggregate.get('total_cases')}`.",
        f"- Case runs: `{aggregate.get('total_case_runs')}`.",
        f"- Output evaluations: `{aggregate.get('total_output_evaluations')}`.",
        f"- Quality output evaluations: `{aggregate.get('quality_output_evaluations', aggregate.get('total_output_evaluations'))}`.",
        f"- Judge-error output evaluations: `{aggregate.get('judge_error_output_evaluations', 0)}`.",
        f"- Judge-skipped output evaluations: `{aggregate.get('judge_skipped_output_evaluations', 0)}`.",
        f"- Judge-cache hits: `{aggregate.get('judge_cache_hit_output_evaluations', 0)}`.",
        f"- Deterministic precheck failures: `{aggregate.get('deterministic_failed_output_evaluations', 0)}`.",
        f"- Mean G-Eval score: `{float(aggregate.get('mean_geval_score') or 0.0):.3f}`.",
        f"- Mean quality G-Eval score: `{float(aggregate.get('mean_quality_geval_score') or aggregate.get('mean_geval_score') or 0.0):.3f}`.",
        f"- Pass rate: `{_pct(aggregate.get('pass_rate'))}`.",
        f"- Quality pass rate: `{_pct(aggregate.get('quality_pass_rate', aggregate.get('pass_rate')))}`.",
        "",
        "## Evidence Totals",
        "",
        f"- IOCs: `{summary.get('evidence_totals', {}).get('iocs')}`.",
        f"- Internal/private IOCs: `{summary.get('evidence_totals', {}).get('internal_iocs')}`.",
        f"- Tool results: `{summary.get('evidence_totals', {}).get('tool_results')}`.",
        f"- Tool statuses: `{summary.get('evidence_totals', {}).get('tool_result_status_counts')}`.",
        "",
        "## JSON vs Markdown",
        "",
        "| Mode | Runs | Mean Score | Pass Rate |",
        "|---|---:|---:|---:|",
    ]
    for mode, values in sorted(aggregate.get("output_mode_summary", {}).items()):
        lines.append(
            "| {mode} | {runs} | {score:.3f} | {pass_rate} |".format(
                mode=mode,
                runs=values.get("runs"),
                score=float(values.get("mean_score") or 0.0),
                pass_rate=_pct(values.get("pass_rate")),
            )
        )

    dimension_summary = summary.get("metric_dimension_summary") or {}
    if dimension_summary:
        lines.extend(
            [
                "",
                "## Metric Dimensions",
                "",
                "| Dimension | Runs | Mean Score | Pass Rate | Min | Max |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for name, values in sorted(dimension_summary.items()):
            lines.append(
                "| {name} | {runs} | {score:.3f} | {pass_rate} | {min_score:.3f} | {max_score:.3f} |".format(
                    name=_ascii(name),
                    runs=values.get("runs"),
                    score=float(values.get("mean_score") or 0.0),
                    pass_rate=_pct(values.get("pass_rate")),
                    min_score=float(values.get("min_score") or 0.0),
                    max_score=float(values.get("max_score") or 0.0),
                )
            )

    lines.extend(
        [
            "",
            "## Tactic Ranking",
            "",
            "| Tactic | Runs | Mean Score | Pass Rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for row in summary.get("weakest_tactics", []):
        lines.append(
            "| {tactic} | {runs} | {score:.3f} | {pass_rate} |".format(
                tactic=_ascii(row.get("tactic")),
                runs=row.get("runs"),
                score=float(row.get("mean_score") or 0.0),
                pass_rate=_pct(row.get("pass_rate")),
            )
        )

    lines.extend(
        [
            "",
            "## Per-Case Resume",
            "",
            "| Case ID | Tactic | Anomalies | IOCs | Tools | JSON Mean | Markdown Mean | Pass Rate |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for case in summary.get("case_summaries", []):
        lines.append(
            "| {case_id} | {tactic} | {anomalies} | {iocs} | {tools} | {json_mean:.3f} | {markdown_mean:.3f} | {pass_rate} |".format(
                case_id=case.get("case_id"),
                tactic=_ascii(case.get("tactic")),
                anomalies=case.get("deeplog_anomalies"),
                iocs=case.get("iocs"),
                tools=case.get("tool_results"),
                json_mean=float(case.get("json_summary", {}).get("mean_score") or 0.0),
                markdown_mean=float(
                    case.get("markdown_summary", {}).get("mean_score") or 0.0
                ),
                pass_rate=_pct(case.get("total_output_summary", {}).get("pass_rate")),
            )
        )

    lines.extend(
        [
            "",
            "## Main Failure Clusters",
            "",
        ]
    )
    for row in summary.get("weakest_tactics", [])[:3]:
        lines.append(
            "- `{}`: mean `{:.3f}`, pass `{}`.".format(
                _ascii(row.get("tactic")),
                float(row.get("mean_score") or 0.0),
                _pct(row.get("pass_rate")),
            )
        )

    lines.extend(
        [
            "",
            "## Failure Count",
            "",
            f"- Failed output evaluations: `{len(summary.get('failures', []))}`.",
            "- Full reasons are in the compact JSON under `failures`; the original verbose output remains in the source JSON.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create compact resume artifacts from the large report-generation G-Eval JSON."
    )
    parser.add_argument("--source", type=Path, default=SOURCE_JSON)
    parser.add_argument("--summary-json", type=Path, default=SUMMARY_JSON)
    parser.add_argument("--resume-md", type=Path, default=RESUME_MD)
    args = parser.parse_args()

    payload = json.loads(args.source.read_text(encoding="utf-8"))
    summary = build_compact_summary(payload, args.source)
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    args.resume_md.parent.mkdir(parents=True, exist_ok=True)
    args.summary_json.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    args.resume_md.write_text(build_markdown(summary), encoding="utf-8")
    print(f"Summary JSON written to {args.summary_json}")
    print(f"Resume Markdown written to {args.resume_md}")


if __name__ == "__main__":
    main()
