import os
from pathlib import Path

from dotenv import load_dotenv

from deepeval import assert_test
from deepeval.metrics import AnswerRelevancyMetric
from deepeval.models.llms.openai_model import GPTModel
from deepeval.test_case import LLMTestCase


load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def test_koboillm_judge_connects_from_env():
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL")
    model_name = os.getenv("OPENAI_MODEL_NAME")

    assert api_key, "OPENAI_API_KEY is missing from evaluation/.env"
    assert base_url, "OPENAI_BASE_URL is missing from evaluation/.env"
    assert model_name, "OPENAI_MODEL_NAME is missing from evaluation/.env"

    judge = GPTModel(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        cost_per_input_token=0,
        cost_per_output_token=0,
    )
    metric = AnswerRelevancyMetric(threshold=0.1, model=judge)
    test_case = LLMTestCase(
        input="What endpoint is configured for the evaluation judge?",
        actual_output=f"The evaluation judge uses the OpenAI-compatible endpoint at {base_url}.",
    )

    assert_test(test_case, [metric])
