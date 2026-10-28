"""LLM detector: instructions from the Markdown file, one Agent per call, its output."""

from typing import Any

import pytest
from agno.metrics import RunMetrics
from agno.models.deepseek import DeepSeek
from agno.models.google import Gemini
from agno.run.agent import RunOutput

from jev_ids.detectors import chatgpt, llm
from jev_ids.run import sample_examples
from tests.helpers import CONFIG, LLM_PROMPT, make_flow, make_train

CATEGORIES: list[str] = CONFIG["categories"]
FLOW = make_flow(5, "dos", value="2")
TRAIN = make_train(["normal", "dos", "probe"])


def run_output(content: Any, *, with_metrics: bool = True) -> RunOutput:
    metrics = RunMetrics(input_tokens=1000, output_tokens=20, cache_read_tokens=800)
    metrics.duration = 0.9
    return RunOutput(
        content=content,
        metrics=metrics if with_metrics else None,
        model="deepseek-flash-2026",
    )


class FakeAgent:
    """Stands in for `agno.agent.Agent`: records its settings, answers from a queue."""

    outcomes: list[Any] = []
    built: list[dict[str, Any]] = []

    def __init__(self, **settings: Any) -> None:
        FakeAgent.built.append(settings)

    def run(self, message: str) -> RunOutput:
        FakeAgent.built[-1]["message"] = message
        item = FakeAgent.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_agent(monkeypatch: pytest.MonkeyPatch) -> type[FakeAgent]:
    FakeAgent.outcomes = []
    FakeAgent.built = []
    monkeypatch.setattr(llm, "Agent", FakeAgent)
    return FakeAgent


def test_instructions_fill_the_examples_placeholder_or_remove_it() -> None:
    examples = sample_examples(TRAIN, 1, 0, CATEGORIES)
    text = llm.instructions(LLM_PROMPT["text"], examples)
    assert text.startswith("You are given one record")
    assert "- `dos`:" in text
    assert "JSON" in text
    assert text.count(" => ") == 4  # the header line plus three examples
    assert f"{TRAIN[1].attributes_csv} => dos" in text
    assert "{examples}" not in text
    zero_shot = llm.instructions(LLM_PROMPT["text"], [])
    assert "=>" not in zero_shot
    assert "\na,b,c\n\nAnswer only" in zero_shot


def test_the_record_and_the_examples_are_written_as_the_record_says(fake_agent: type[FakeAgent]) -> None:
    judgement = llm.Judgement(verdict="attack", category="dos", p_attack=0.93)
    fake_agent.outcomes = [run_output(judgement), run_output(judgement)]
    flow = make_flow(9, "dos", value="168.86187098953056")
    example = make_flow(1, "normal", value="0.0")
    llm.LLMDetector(LLM_PROMPT, "deepseek").predict(flow, [example])
    llm.LLMDetector(LLM_PROMPT, "deepseek", record="full").predict(flow, [example])
    compact, full = fake_agent.built
    assert compact["message"] == "Record:\n168.9,168.9,168.9"
    assert "0,0,0 => normal" in compact["instructions"]
    assert full["message"] == f"Record:\n{flow.attributes_csv}"
    assert f"{example.attributes_csv} => normal" in full["instructions"]


def test_happy_path_builds_one_agent_per_call_and_keeps_agno_metrics(
    fake_agent: type[FakeAgent],
) -> None:
    judgement = llm.Judgement(verdict="attack", category="dos", p_attack=0.93)
    fake_agent.outcomes = [run_output(judgement), run_output(judgement)]
    detector = llm.LLMDetector(LLM_PROMPT, "deepseek")

    prediction = detector.predict(FLOW, [])
    detector.predict(FLOW, sample_examples(TRAIN, 1, 0, CATEGORIES))

    settings = fake_agent.built[0]
    assert settings["message"] == f"Record:\n{FLOW.attributes_csv}"
    assert (settings["use_json_mode"], settings["retries"]) == (True, 0)
    assert settings["model"] is detector.agno_model
    assert "=> " not in settings["instructions"]
    assert "=> " in fake_agent.built[1]["instructions"]
    assert (prediction["p_attack"], prediction["category_pred"]) == (0.93, "dos")
    assert prediction["usage"] == {
        "input_tokens": 1000,
        "output_tokens": 20,
        "cache_read_tokens": 800,
        "duration": 0.9,
    }
    assert prediction["latency_ms"] > 0
    assert prediction["error"] is None
    assert prediction["raw"] == {
        "content": {"verdict": "attack", "category": "dos", "p_attack": 0.93},
        "model": "deepseek-flash-2026",
    }
    assert (detector.name, detector.model) == ("llm:deepseek", "deepseek-flash")
    assert detector.prompt_hash == "h"


def test_unparsed_content_is_an_error_row_that_keeps_what_was_measured(
    fake_agent: type[FakeAgent],
) -> None:
    fake_agent.outcomes = [run_output("I think it is an attack", with_metrics=False)]
    prediction = llm.LLMDetector(LLM_PROMPT, "deepseek").predict(FLOW, [])
    assert (prediction["p_attack"], prediction["category_pred"]) == (None, None)
    assert prediction["error"] == "parse: I think it is an attack"
    assert prediction["usage"] == {}
    assert prediction["latency_ms"] > 0


def test_provider_errors_are_recorded_not_retried(
    fake_agent: type[FakeAgent],
) -> None:
    fake_agent.outcomes = [RuntimeError("503 busy")]
    prediction = llm.LLMDetector(LLM_PROMPT, "deepseek").predict(FLOW, [])
    assert prediction == {"error": "RuntimeError: 503 busy"}
    assert len(fake_agent.built) == 1


def test_chatgpt_path_uses_strict_schema_and_the_preamble(
    fake_agent: type[FakeAgent],
) -> None:
    judgement = llm.Judgement(verdict="normal", category="normal", p_attack=0.1)
    fake_agent.outcomes = [run_output(judgement)]
    detector = llm.LLMDetector(LLM_PROMPT, "openai", "gpt-5.6-terra")

    prediction = detector.predict(FLOW, [])

    assert (detector.name, detector.model) == ("llm:openai", "gpt-5.6-terra")
    assert isinstance(detector.agno_model, chatgpt.ChatGPTSubscriptionModel)
    assert detector.agno_model.request_params == {"instructions": chatgpt.PREAMBLE}
    assert fake_agent.built[0]["use_json_mode"] is False
    assert prediction["p_attack"] == 0.1


def test_make_model_applies_the_determinism_knobs() -> None:
    deepseek = llm.make_model("deepseek", "deepseek-flash")
    assert isinstance(deepseek, DeepSeek)
    assert (deepseek.temperature, deepseek.use_thinking) == (0.0, False)
    luna = llm.make_model("openai", "gpt-5.6-luna")
    assert isinstance(luna, chatgpt.ChatGPTSubscriptionModel)
    assert luna.reasoning_effort == "none"
    gemini = llm.make_model("gemini", "gemini-3.6-flash")
    assert isinstance(gemini, Gemini)
    assert (gemini.vertexai, gemini.temperature, gemini.thinking_level, gemini.timeout) == (True, 0.0, "low", 120)
    assert llm.LLMDetector(LLM_PROMPT, "gemini").model == "gemini-3.6-flash"
    assert llm.LLMDetector(LLM_PROMPT, "openai").model == "gpt-5.6-luna"
