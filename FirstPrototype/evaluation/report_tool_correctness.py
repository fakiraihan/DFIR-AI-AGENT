from __future__ import annotations

import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any


EVALUATION_DIR = Path(__file__).resolve().parent
LATEST_RESULTS_PATH = EVALUATION_DIR / "results" / "tool_correctness_latest.json"
REPORT_PATH = EVALUATION_DIR / "reports" / "tool_correctness_eval.md"


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _tool_list(tools: list[dict[str, Any]]) -> str:
    if not tools:
        return "None"
    return ", ".join(
        f"{tool['tool']}({tool['ioc_type']}:{tool['ioc']})" for tool in tools
    )


def _ascii(text: Any) -> str:
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
    return re.sub(r"\s+", " ", ascii_text).strip().replace("|", "/")


def _case_rows(payload: dict[str, Any]) -> list[str]:
    rows = [
        "| Case ID | Category | Runs | Mean Score | Pass Rate | Stability | Missing Tools | Extra Tools |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ]
    runs_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in payload["runs"]:
        runs_by_case[result["case_id"]].append(result)

    for case in payload["cases"]:
        case_runs = runs_by_case[case["case_id"]]
        stability = payload["summary"]["case_stability"][case["case_id"]]
        missing = []
        extra = []
        for result in case_runs:
            missing.extend(result["missing_tools"])
            extra.extend(result["extra_tools"])
        rows.append(
            "| {case_id} | {category} | {runs} | {score:.3f} | {pass_rate} | {stability_rate} | {missing} | {extra} |".format(
                case_id=case["case_id"],
                category=case["academic_category"],
                runs=len(case_runs),
                score=stability["mean_score"],
                pass_rate=_pct(stability["pass_rate"]),
                stability_rate=_pct(stability["stability_rate"]),
                missing=_tool_list(missing[:6]),
                extra=_tool_list(extra[:6]),
            )
        )
    return rows


def _failure_rows(payload: dict[str, Any]) -> list[str]:
    rows = [
        "| Case ID | Run | Score | Missing Tools | Extra Tools | Argument Mismatches | Reason |",
        "|---|---:|---:|---|---|---:|---|",
    ]
    failures = [
        result
        for result in payload["runs"]
        if not result["success"]
        or result["missing_tools"]
        or result["argument_mismatches"]
    ]
    if not failures:
        rows.append("| None | - | - | None | None | 0 | All runs met the configured threshold and expected input parameters. |")
        return rows

    for result in failures:
        reason = _ascii(result.get("reason")).replace("\n", " ")[:220]
        rows.append(
            "| {case_id} | {rep} | {score:.3f} | {missing} | {extra} | {mismatch_count} | {reason} |".format(
                case_id=result["case_id"],
                rep=result["repetition"],
                score=result["score"],
                missing=_tool_list(result["missing_tools"]),
                extra=_tool_list(result["extra_tools"]),
                mismatch_count=len(result["argument_mismatches"]),
                reason=reason or "No metric reason recorded.",
            )
        )
    return rows


def _dataset_composition(payload: dict[str, Any]) -> list[str]:
    category_counts = Counter(case["academic_category"] for case in payload["cases"])
    ioc_counts = Counter()
    expected_tool_counts = Counter()
    for case in payload["cases"]:
        for ioc in case["iocs_extracted"]:
            ioc_counts[ioc["type"]] += 1
        for tool in case["expected_tools"]:
            expected_tool_counts[tool["tool"]] += 1

    lines = ["### Dataset Composition", ""]
    lines.append("- Cases: {}".format(len(payload["cases"])))
    lines.append("- Total repeated runs: {}".format(payload["summary"]["total_runs"]))
    lines.append(
        "- IOC type coverage: {}".format(
            ", ".join(f"{key}={value}" for key, value in sorted(ioc_counts.items()))
        )
    )
    lines.append(
        "- Academic categories: {}".format(
            ", ".join(
                f"{key}={value}" for key, value in sorted(category_counts.items())
            )
        )
    )
    lines.append(
        "- Expected tool coverage: {}".format(
            ", ".join(
                f"{key}={value}" for key, value in sorted(expected_tool_counts.items())
            )
        )
    )
    return lines


def build_report(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    config = payload["config"]
    case_scores = [
        case_summary["mean_score"]
        for case_summary in summary["case_stability"].values()
    ]
    macro_case_mean = mean(case_scores) if case_scores else 0.0

    lines = [
        "# Tool Use Correctness Evaluation Report",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        "This evaluation measures whether FirstPrototype selects appropriate threat-intelligence tools for extracted IOCs. The subject under test is the local Ollama-backed `DFIRAgent.select_tools()` path, while DeepEval evaluates tool-call correctness using an OpenAI-compatible judge configured in `evaluation/.env`.",
        "",
        f"- Eval runner: `{config.get('subject_under_test')}`",
        f"- Test entrypoint: `{payload['test_entrypoint']}`",
        f"- Dataset: `{payload['dataset_path']}`",
        f"- Subject LLM: `{config['subject_llm_provider']}::{config['subject_ollama_model']}` at `{config['subject_ollama_base_url']}`",
        f"- Judge model: `{config['judge_model']}` at `{config['judge_base_url']}`",
        f"- Total cases: {summary['total_cases']}",
        f"- Repetitions per case: {summary['repetitions_per_case']}",
        f"- Mean ToolCorrectness score: {summary['mean_tool_correctness_score']:.3f}",
        f"- Macro average by case: {macro_case_mean:.3f}",
        f"- Pass rate at threshold {config['threshold']}: {_pct(summary['pass_rate'])}",
        f"- Complete expected-tool coverage rate: {_pct(summary['exact_or_complete_rate'])}",
        "",
        "## Methodology",
        "",
        "Each dataset case supplies a DFIR context, extracted IOCs, and a golden set of expected tool calls. The runner invokes the FirstPrototype agent with a local Ollama client and converts selected `tool_calls` into DeepEval `ToolCall` objects. DeepEval `ToolCorrectnessMetric` compares selected tools against expected tools using input parameters (`ioc`, `ioc_type`) while ignoring ordering because the runtime can execute tools in parallel.",
        "",
        "The benchmark repeats each case three times to estimate selection stability. The report distinguishes score failures from operational analysis fields: missing expected tools, extra selected tools, and argument mismatches.",
        "",
        "## Metric Definition",
        "",
        "- Primary metric: DeepEval `ToolCorrectnessMetric`.",
        "- Evaluation params: `ToolCallParams.INPUT_PARAMETERS`.",
        "- Required match fields: tool name, `ioc`, and `ioc_type`.",
        "- Ordering: not considered.",
        "- Exact match: disabled; extra tools are reported separately rather than automatically failing the DeepEval score.",
        "- Threshold: `{}`.".format(config["threshold"]),
        "",
    ]
    lines.extend(_dataset_composition(payload))
    lines.extend(
        [
            "",
            "## Aggregate Results",
            "",
            "| Category | Runs | Mean Score | Pass Rate |",
            "|---|---:|---:|---:|",
        ]
    )
    for category, values in sorted(summary["macro_average_by_category"].items()):
        lines.append(
            f"| {category} | {values['runs']} | {values['mean_score']:.3f} | {_pct(values['pass_rate'])} |"
        )
    lines.extend(["", "## Per-Case Results", ""])
    lines.extend(_case_rows(payload))
    lines.extend(["", "## Failure and Drift Analysis", ""])
    lines.extend(_failure_rows(payload))
    lines.extend(
        [
            "",
            "## Reproducibility Notes",
            "",
            "- Run the benchmark with `deepeval test run tests\\test_tool_correctness.py` from `evaluation/`.",
            "- Regenerate this report with `python report_tool_correctness.py` from `evaluation/`.",
            "- The subject LLM is local Ollama; judge credentials are loaded only from `evaluation/.env`.",
            "- The result JSON used for this report is `evaluation/results/tool_correctness_latest.json`.",
            "",
            "## Limitations",
            "",
            "- The benchmark evaluates tool selection, not the live correctness of external threat-intelligence API responses.",
            "- Golden labels are expert-authored for representative IOC categories, not a statistically sampled incident corpus.",
            "- The LLM judge can introduce evaluator variance; repeated case runs measure subject stability, not judge calibration.",
            "- Extra tools are reported as potential over-selection but do not automatically reduce the DeepEval non-exact score.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    payload = json.loads(LATEST_RESULTS_PATH.read_text(encoding="utf-8"))
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(build_report(payload), encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
