"""LLM detector: instructions from the Markdown file, one Agent per call, its output and its stop reason."""

from typing import Any

import pytest
from agno.metrics import RunMetrics
from agno.models.message import Message
from agno.run.agent import RunOutput
from anthropic.types import Message as AnthropicMessage

from jev_ids.detectors import llm
from jev_ids.run import sample_examples
from tests.helpers import CONFIG, LLM_PROMPT, make_flow, make_train

CATEGORIES: list[str] = CONFIG["categories"]
FLOW = make_flow(5, "dos", value="2")
TRAIN = make_train(["normal", "dos", "probe"])
JUDGEMENT = llm.Judgement(verdict="attack", category="dos", p_attack=0.93)


def run_output(content: Any, stop: dict[str, Any] | None = None, *, with_metrics: bool = True) -> RunOutput:
    metrics = RunMetrics(input_tokens=1000, output_tokens=20)
    metrics.duration = 0.9
    return RunOutput(
        content=content,
        metrics=metrics if with_metrics else None,
        model="claude-sonnet-5-5",
        messages=[Message(role="assistant", provider_data=stop or {"stop_reason": "end_turn", "stop_details": None})],
    )


class FakeAgent:
    """Stands in for `agno.agent.Agent`, the boundary to the paid API, and answers from a queue while it records its settings."""

    outcomes: list[Any] = []
    built: list[dict[str, Any]] = []

    def __init__(self, **settings: Any) -> None:
        self.settings = settings
        FakeAgent.built.append(settings)

    def run(self, message: str) -> RunOutput:
        self.settings["message"] = message
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
    # Counting the header line plus three examples.
    assert text.count(" => ") == 4
    assert f"{TRAIN[1].attributes_csv} => dos" in text
    assert "{examples}" not in text
    zero_shot = llm.instructions(LLM_PROMPT["text"], [])
    assert "=>" not in zero_shot
    assert "\na,b,c\n\nAnswer only" in zero_shot


def test_the_record_and_the_examples_are_written_as_the_record_says(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [run_output(JUDGEMENT), run_output(JUDGEMENT)]
    flow = make_flow(9, "dos", value="168.86187098953056")
    example = make_flow(1, "normal", value="0.0")
    llm.LLMDetector(LLM_PROMPT).predict(flow, [example])
    llm.LLMDetector(LLM_PROMPT, record="full").predict(flow, [example])
    compact, full = fake_agent.built
    assert compact["message"] == "Record:\n168.9,168.9,168.9"
    assert "0,0,0 => normal" in compact["instructions"]
    assert full["message"] == f"Record:\n{flow.attributes_csv}"
    assert f"{example.attributes_csv} => normal" in full["instructions"]


def test_happy_path_builds_one_agent_per_call_and_keeps_agno_metrics(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [run_output(JUDGEMENT), run_output(JUDGEMENT)]
    detector = llm.LLMDetector(LLM_PROMPT)

    prediction = detector.predict(FLOW, [])
    detector.predict(FLOW, sample_examples(TRAIN, 1, 0, CATEGORIES))

    settings = fake_agent.built[0]
    assert settings["message"] == f"Record:\n{FLOW.attributes_csv}"
    assert (settings["output_schema"], settings["retries"]) == (llm.Judgement, 0)
    assert settings["model"] is detector.agno_model
    assert "=> " not in settings["instructions"]
    assert "=> " in fake_agent.built[1]["instructions"]
    assert (prediction["p_attack"], prediction["category_pred"], prediction["error"]) == (0.93, "dos", None)
    assert prediction["usage"] == {
        "input_tokens": 1000,
        "output_tokens": 20,
        "duration": 0.9,
    }
    assert prediction["latency_ms"] > 0
    assert prediction["raw"] == {
        "content": {
            "verdict": "attack",
            "category": "dos",
            "p_attack": 0.93,
        },
        "model": "claude-sonnet-5-5",
        "stop_reason": "end_turn",
        "stop_details": None,
    }
    assert (detector.name, detector.model, detector.prompt_hash) == ("llm:sonnet", "claude-sonnet-5-5", "h")


def test_refusal_cut_and_unparsed_content_are_error_rows_that_keep_what_was_measured(fake_agent: type[FakeAgent]) -> None:
    refusal = {
        "stop_reason": "refusal",
        "stop_details": {"category": "cyber", "explanation": None, "type": "refusal"},
    }
    fake_agent.outcomes = [
        run_output(None, refusal),
        run_output('{"verdict": "att', {"stop_reason": "max_tokens"}),
        run_output("I think it is an attack", with_metrics=False),
    ]
    detector = llm.LLMDetector(LLM_PROMPT)
    refused, cut, unparsed = (detector.predict(FLOW, []) for _ in range(3))
    assert (refused["p_attack"], refused["error"], refused["raw"]["stop_reason"]) == (None, "refusal: cyber", "refusal")
    assert cut["error"] == "max_tokens"
    assert unparsed["error"] == "parse: I think it is an attack"
    assert unparsed["usage"] == {}
    assert unparsed["latency_ms"] > 0


def test_api_errors_are_recorded_not_retried(fake_agent: type[FakeAgent]) -> None:
    fake_agent.outcomes = [RuntimeError("529 overloaded")]
    prediction = llm.LLMDetector(LLM_PROMPT).predict(FLOW, [])
    assert prediction == {"error": "RuntimeError: 529 overloaded"}
    assert len(fake_agent.built) == 1


def test_the_model_answers_without_thinking_at_low_effort_and_keeps_the_stop_reason() -> None:
    model = llm.make_model("claude-sonnet-5-5")
    assert model.thinking == {"type": "between_tools"}
    assert model.output_config == {"effort": "low"}
    assert (model.temperature, model.max_tokens, model.timeout, model.cache_system_prompt) == (None, llm.MAX_TOKENS, llm.TIMEOUT_S, False)
    response = AnthropicMessage.model_validate(
        {
            "id": "msg",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-5",
            "content": [],
            "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber"},
            "usage": {"input_tokens": 10, "output_tokens": 0},
        }
    )
    parsed = model._parse_provider_response(response)  # pyright: ignore[reportPrivateUsage]  the override under test is Agno's hook
    assert parsed.provider_data["stop_reason"] == "refusal"
    assert parsed.provider_data["stop_details"]["category"] == "cyber"
