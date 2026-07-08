import sys
from pathlib import Path


EVALUATION_DIR = Path(__file__).resolve().parents[1]
if str(EVALUATION_DIR) not in sys.path:
    sys.path.insert(0, str(EVALUATION_DIR))

from tool_correctness_runner import run_tool_correctness_evaluation


def test_firstprototype_tool_correctness_benchmark_runs():
    payload = run_tool_correctness_evaluation()

    summary = payload["summary"]
    assert summary["total_cases"] >= 6
    assert summary["repetitions_per_case"] >= 3
    assert summary["total_runs"] == summary["total_cases"] * summary["repetitions_per_case"]
    assert payload["config"]["subject_ollama_model"] == "sec-foundation:8b-gpu"
    assert payload["config"]["judge_model"]
