from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from dotenv import load_dotenv

from deepeval import assert_test
from deepeval.metrics import ToolCorrectnessMetric
from deepeval.models.llms.openai_model import GPTModel
from deepeval.test_case import LLMTestCase, ToolCall, ToolCallParams


EVALUATION_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVALUATION_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend"
DATASET_PATH = EVALUATION_DIR / "datasets" / "tool_correctness_cases.json"
RESULTS_DIR = EVALUATION_DIR / "results"
LATEST_RESULTS_PATH = RESULTS_DIR / "tool_correctness_latest.json"
TEST_ENTRYPOINT = EVALUATION_DIR / "tests" / "test_tool_correctness.py"

SUBJECT_BASE_URL = os.getenv("EVAL_OLLAMA_BASE_URL", "http://localhost:11434")
SUBJECT_MODEL = os.getenv("EVAL_OLLAMA_MODEL", "sec-foundation:8b-gpu")
DEFAULT_REPETITIONS = int(os.getenv("EVAL_REPETITIONS", "3"))
DEFAULT_THRESHOLD = float(os.getenv("EVAL_TOOL_CORRECTNESS_THRESHOLD", "0.8"))


TOOL_DESCRIPTIONS = {
    "abuseipdb_lookup": "Checks IP addresses against AbuseIPDB for abuse-confidence score and abuse report history.",
    "threatfox_lookup": "Checks IPs, domains, URLs, MD5, and SHA256 indicators against ThreatFox malware IOC intelligence.",
    "malwarebazaar_lookup": "Checks MD5 or SHA256 file hashes against MalwareBazaar malware sample intelligence.",
    "urlhaus_lookup": "Checks URLs against URLHaus malware URL and payload hosting intelligence.",
    "alienvault_otx_lookup": "Checks domains, URLs, and file hashes against AlienVault OTX pulses and reputation context.",
    "virustotal_lookup": "Checks IPs, domains, URLs, and file hashes against VirusTotal reputation and detection statistics.",
}


@dataclass
class OllamaInvokeClient:
    base_url: str = SUBJECT_BASE_URL
    model: str = SUBJECT_MODEL
    timeout_seconds: int = 120

    def invoke(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.7,
                "top_k": 20,
                "num_ctx": 16384,
                "num_predict": 2048,
                "repeat_penalty": 1.15,
            },
        }
        response = requests.post(
            f"{self.base_url.rstrip('/')}/api/generate",
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        return str(data.get("response") or "").strip()


def ensure_backend_import_path() -> None:
    backend_path = str(BACKEND_DIR)
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)


def load_cases(path: Path = DATASET_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_state(case: dict[str, Any]) -> dict[str, Any]:
    from modules.agent_modules.state import build_initial_state

    state = build_initial_state(
        anomalies=[],
        parsed_logs_df=pd.DataFrame(),
        max_reflection_rounds=1,
        max_tool_execution_rounds=2,
    )
    state["iocs_extracted"] = list(case["iocs_extracted"])
    return state


def build_case_input(case: dict[str, Any]) -> str:
    ioc_lines = [
        f"- {ioc['type']}: {ioc['value']}" for ioc in case["iocs_extracted"]
    ]
    return (
        f"{case['input_context']}\n\n"
        "Extracted IOCs:\n"
        + "\n".join(ioc_lines)
        + "\n\nSelect the threat-intelligence tools that should be called."
    )


def case_tool_call_to_deepeval(call: dict[str, Any]) -> ToolCall:
    return ToolCall(
        name=str(call["tool"]),
        input_parameters={
            "ioc": str(call["ioc"]),
            "ioc_type": str(call["ioc_type"]).lower(),
        },
        reasoning=str(call.get("selection_reason") or ""),
    )


def available_tools() -> list[ToolCall]:
    return [
        ToolCall(name=name, description=description)
        for name, description in TOOL_DESCRIPTIONS.items()
    ]


def build_judge_model() -> GPTModel:
    load_dotenv(EVALUATION_DIR / ".env")
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL")
    model_name = os.getenv("OPENAI_MODEL_NAME")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is missing from evaluation/.env")
    if not base_url:
        raise RuntimeError("OPENAI_BASE_URL is missing from evaluation/.env")
    if not model_name:
        raise RuntimeError("OPENAI_MODEL_NAME is missing from evaluation/.env")

    return GPTModel(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        cost_per_input_token=0,
        cost_per_output_token=0,
    )


def key_for_tool(call: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(call["tool"]),
        str(call["ioc_type"]).lower(),
        str(call["ioc"]),
    )


def tool_diff(
    expected: list[dict[str, Any]], called: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    expected_keys = {key_for_tool(call) for call in expected}
    called_keys = {key_for_tool(call) for call in called}
    missing_keys = expected_keys - called_keys
    extra_keys = called_keys - expected_keys

    missing = [
        {"tool": tool, "ioc_type": ioc_type, "ioc": ioc}
        for tool, ioc_type, ioc in sorted(missing_keys)
    ]
    extra = [
        {"tool": tool, "ioc_type": ioc_type, "ioc": ioc}
        for tool, ioc_type, ioc in sorted(extra_keys)
    ]
    argument_mismatches = []
    for expected_call in expected:
        expected_key = key_for_tool(expected_call)
        if expected_key in called_keys:
            continue
        same_tool = [
            call
            for call in called
            if str(call["tool"]) == str(expected_call["tool"])
        ]
        for called_call in same_tool:
            if (
                str(called_call.get("ioc")) != str(expected_call.get("ioc"))
                or str(called_call.get("ioc_type")).lower()
                != str(expected_call.get("ioc_type")).lower()
            ):
                argument_mismatches.append(
                    {"expected": expected_call, "called": called_call}
                )
    return {
        "missing_tools": missing,
        "extra_tools": extra,
        "argument_mismatches": argument_mismatches,
    }


def run_single_case(
    *,
    case: dict[str, Any],
    repetition: int,
    agent: Any,
    judge_model: GPTModel,
    threshold: float,
) -> dict[str, Any]:
    state = build_state(case)
    stdout_buffer = io.StringIO()
    with contextlib.redirect_stdout(stdout_buffer):
        selection_result = agent.select_tools(state)

    called_tools = [
        {
            "tool": str(call["tool"]),
            "ioc": str(call["ioc"]),
            "ioc_type": str(call["ioc_type"]).lower(),
            "selection_source": str(call.get("selection_source") or ""),
            "selection_reason": str(call.get("selection_reason") or ""),
            "expected_evidence": str(call.get("expected_evidence") or ""),
        }
        for call in selection_result.get("tool_calls", [])
    ]
    expected_tools = list(case["expected_tools"])
    metric = ToolCorrectnessMetric(
        available_tools=available_tools(),
        threshold=threshold,
        evaluation_params=[ToolCallParams.INPUT_PARAMETERS],
        model=judge_model,
        include_reason=True,
        async_mode=False,
        should_exact_match=False,
        should_consider_ordering=False,
    )
    test_case = LLMTestCase(
        name=f"{case['case_id']}::run_{repetition}",
        input=build_case_input(case),
        tools_called=[case_tool_call_to_deepeval(call) for call in called_tools],
        expected_tools=[
            case_tool_call_to_deepeval(call) for call in expected_tools
        ],
        metadata={
            "case_id": case["case_id"],
            "academic_category": case["academic_category"],
            "repetition": repetition,
            "subject_model": SUBJECT_MODEL,
        },
    )
    assertion_error = None
    try:
        assert_test(test_case, [metric], run_async=False)
    except AssertionError as exc:
        assertion_error = str(exc)

    score = metric.score
    diff = tool_diff(expected_tools, called_tools)

    return {
        "case_id": case["case_id"],
        "academic_category": case["academic_category"],
        "repetition": repetition,
        "score": float(score),
        "success": bool(metric.is_successful()),
        "assertion_error": assertion_error,
        "threshold": threshold,
        "reason": metric.reason,
        "expected_tools": expected_tools,
        "called_tools": called_tools,
        "missing_tools": diff["missing_tools"],
        "extra_tools": diff["extra_tools"],
        "argument_mismatches": diff["argument_mismatches"],
        "selection_trace": selection_result.get("tool_selection_trace", []),
        "reasoning_steps": selection_result.get("reasoning_steps", []),
        "stdout_excerpt": stdout_buffer.getvalue()[-2000:],
    }


def summarize_results(
    cases: list[dict[str, Any]], run_results: list[dict[str, Any]]
) -> dict[str, Any]:
    total_runs = len(run_results)
    score_sum = sum(result["score"] for result in run_results)
    passed = sum(1 for result in run_results if result["success"])
    exact_runs = sum(
        1
        for result in run_results
        if not result["missing_tools"]
        and not result["argument_mismatches"]
    )

    per_category: dict[str, dict[str, Any]] = {}
    for result in run_results:
        category = result["academic_category"]
        bucket = per_category.setdefault(
            category, {"runs": 0, "score_sum": 0.0, "passed": 0}
        )
        bucket["runs"] += 1
        bucket["score_sum"] += result["score"]
        bucket["passed"] += int(result["success"])
    for bucket in per_category.values():
        bucket["mean_score"] = (
            bucket["score_sum"] / bucket["runs"] if bucket["runs"] else 0.0
        )
        bucket["pass_rate"] = (
            bucket["passed"] / bucket["runs"] if bucket["runs"] else 0.0
        )
        del bucket["score_sum"]

    case_stability = {}
    for case in cases:
        case_runs = [
            result for result in run_results if result["case_id"] == case["case_id"]
        ]
        if not case_runs:
            continue
        canonical_outputs = [
            sorted(key_for_tool(call) for call in result["called_tools"])
            for result in case_runs
        ]
        first_output = canonical_outputs[0]
        stable_count = sum(1 for output in canonical_outputs if output == first_output)
        case_stability[case["case_id"]] = {
            "runs": len(case_runs),
            "stable_runs": stable_count,
            "stability_rate": stable_count / len(case_runs),
            "mean_score": sum(result["score"] for result in case_runs)
            / len(case_runs),
            "pass_rate": sum(1 for result in case_runs if result["success"])
            / len(case_runs),
        }

    return {
        "total_cases": len(cases),
        "total_runs": total_runs,
        "repetitions_per_case": total_runs // len(cases) if cases else 0,
        "mean_tool_correctness_score": score_sum / total_runs if total_runs else 0.0,
        "pass_rate": passed / total_runs if total_runs else 0.0,
        "exact_or_complete_rate": exact_runs / total_runs if total_runs else 0.0,
        "macro_average_by_category": per_category,
        "case_stability": case_stability,
    }


def run_tool_correctness_evaluation(
    *,
    repetitions: int = DEFAULT_REPETITIONS,
    threshold: float = DEFAULT_THRESHOLD,
    results_path: Path = LATEST_RESULTS_PATH,
) -> dict[str, Any]:
    ensure_backend_import_path()
    from modules.agent import DFIRAgent

    cases = load_cases()
    judge_model = build_judge_model()
    local_llm = OllamaInvokeClient()
    agent = DFIRAgent(
        llm=local_llm,
        provider_name="ollama",
        ollama_base_url=SUBJECT_BASE_URL,
        ollama_model=SUBJECT_MODEL,
    )

    run_results = []
    for case in cases:
        for repetition in range(1, repetitions + 1):
            run_results.append(
                run_single_case(
                    case=case,
                    repetition=repetition,
                    agent=agent,
                    judge_model=judge_model,
                    threshold=threshold,
                )
            )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "runner_path": str(Path(__file__).resolve()),
        "test_entrypoint": str(TEST_ENTRYPOINT),
        "dataset_path": str(DATASET_PATH),
        "results_path": str(results_path),
        "config": {
            "subject_under_test": "FirstPrototype DFIRAgent.select_tools",
            "subject_llm_provider": "ollama",
            "subject_ollama_base_url": SUBJECT_BASE_URL,
            "subject_ollama_model": SUBJECT_MODEL,
            "judge_provider": "deepeval GPTModel with OpenAI-compatible endpoint",
            "judge_base_url": os.getenv("OPENAI_BASE_URL"),
            "judge_model": os.getenv("OPENAI_MODEL_NAME"),
            "threshold": threshold,
            "evaluation_params": ["input_parameters"],
            "should_exact_match": False,
            "should_consider_ordering": False,
            "repetitions": repetitions,
        },
        "cases": cases,
        "runs": run_results,
        "summary": summarize_results(cases, run_results),
    }

    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def main() -> None:
    payload = run_tool_correctness_evaluation()
    summary = payload["summary"]
    print(json.dumps(summary, indent=2))
    print(f"Results written to {payload['results_path']}")


if __name__ == "__main__":
    main()
