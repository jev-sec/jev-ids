"""The LLM baselines through an Agno Agent.

Three providers share this detector: DeepSeek through its own API, an OpenAI GPT-{5,6}.x model through the ChatGPT Codex backend with
OAuth (see `chatgpt.py`), and Google's Gemini through Vertex AI (the project and region come from `GOOGLE_CLOUD_PROJECT` and
`GOOGLE_CLOUD_LOCATION`, the credentials from `gcloud auth application-default login`).

In reading order:

- `Judgement`: the JSON answer every LLM must give (Agno's `output_schema`).
- `LLMDetector`: builds the provider's Agno model once. Its `predict` runs
  one Agent per Flow with the instructions of `prompts/<dataset>/llm.md`.
- `instructions`: that Markdown with the Examples filled in.
- `make_model`: the Agno model of a provider, with its determinism knobs.
- `measurements`: what one run measured, read off Agno's RunOutput.

All providers run at the lowest reasoning available. Each Flow gets one `Agent.run`
and no retries of our own, so a provider error becomes an error row and the run goes on.
"""

import time
from collections.abc import Sequence
from typing import Any, Literal

from agno.agent import Agent
from agno.models.deepseek import DeepSeek
from agno.models.google import Gemini
from agno.run.agent import RunOutput
from pydantic import BaseModel, Field

from jev_ids.dataset import Flow, record_text
from jev_ids.detectors import chatgpt

DEFAULT_MODEL = {
    "deepseek": "deepseek-flash",
    "openai": "gpt-5.6-luna",
    "gemini": "gemini-3.6-flash",
}
# Heading the Examples that replace `{examples}` in the prompt file at k > 0. At k = 0 the placeholder is simply removed.
EXAMPLES_HEADER = "\nLabeled example records (record => category):\n"


class Judgement(BaseModel):
    """The structured answer asked of every LLM.

    `category` is free text in the schema, so the schema names no dataset; the prompt file lists the options.
    """

    verdict: Literal["attack", "normal"]
    category: str
    p_attack: float = Field(ge=0.0, le=1.0)


class LLMDetector:
    """Judges Flows with an LLM through an Agno Agent: one call per Flow, no tools."""

    def __init__(self, prompt: dict[str, Any], provider: str, model_id: str | None = None, record: str = "compact") -> None:
        """Keep the prompt and build the Agno model once.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/llm.md`.
            provider: `deepseek`, `openai` or `gemini`.
            model_id: the provider's model id; None means the provider default.
            record: how the values of the Flow and the Examples are written, one of `dataset.RECORDS`.
        """
        self.template: str = prompt["text"]
        self.record = record
        self.prompt_hash: str = prompt["sha256"]
        self.provider = provider
        self.model = model_id or DEFAULT_MODEL[provider]
        self.name = f"llm:{provider}"
        # Building the model object once, because it holds the HTTP client and,
        # on the ChatGPT path, the OAuth tokens. An Agent is cheap and built per call.
        self.agno_model: Any = make_model(provider, self.model)

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Agent run for one Flow; the Examples travel in the instructions.

        DeepSeek only offers `json_object` mode, so there the schema is enforced by parsing,
        while the OpenAI path keeps Agno's default strict `json_schema`. Agno's own retries and telemetry are off.

        Args:
            flow: the Flow to judge.
            examples: the labeled Examples, written into the instructions.

        Returns:
            The `measurements` of the run, or `error` when the provider call raised.
        """
        # Typing the agent as `Any`, because Agno's `run` overloads are partially untyped for pyright.
        agent: Any = Agent(
            model=self.agno_model,
            instructions=instructions(self.template, examples, self.record),
            output_schema=Judgement,
            use_json_mode=self.provider == "deepseek",
            markdown=False,
            retries=0,
            telemetry=False,
        )
        started = time.perf_counter()
        try:
            run: RunOutput = agent.run(f"Record:\n{record_text(flow, self.record)}")
        # Recording every provider error in the row instead of raising it.
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:500]}
        return measurements(run, (time.perf_counter() - started) * 1000)


def instructions(template: str, examples: Sequence[Flow], record: str = "compact") -> str:
    """The prompt file with `{examples}` filled with the labeled Examples.

    Examples are labeled by Category only, because attack names never reach a model (CONTEXT.md); at k = 0 the placeholder is removed. The
    word "JSON" in the file is required: DeepSeek's `json_object` mode refuses a prompt that does not mention it.

    Args:
        template: the text of `prompts/<dataset>/llm.md`.
        examples: the labeled Examples, which may be empty.
        record: how the values of the Examples are written, one of `dataset.RECORDS`.

    Returns:
        The instructions of the Agent.
    """
    lines = "".join(f"{record_text(example, record)} => {example.category}\n" for example in examples)
    return template.replace("{examples}", EXAMPLES_HEADER + lines if lines else "")


def make_model(provider: str, model_id: str) -> Any:
    """The Agno model of a provider, with its determinism knobs.

    DeepSeek thinks by default and then silently ignores `temperature`, so thinking is off and the temperature is 0. GPT-5.x documents no
    temperature and runs at `reasoning_effort="none"`, the lowest available. Gemini 3.x cannot switch thinking off; `thinking_level="low"`
    is the lowest Agno documents, and the temperature is 0. Its client has no request timeout of its own, and Vertex has held a
    connection open for minutes, freezing the run; two minutes turns such a hang into an error row that `redo-errors` repairs.

    Args:
        provider: `deepseek`, `openai` or `gemini`.
        model_id: the provider's model id.

    Returns:
        A `DeepSeek`, `Gemini` or `chatgpt.ChatGPTSubscriptionModel`, by provider.
    """
    if provider == "deepseek":
        return DeepSeek(id=model_id, temperature=0.0, use_thinking=False)
    if provider == "gemini":
        return Gemini(id=model_id, vertexai=True, temperature=0.0, thinking_level="low", timeout=120)
    return chatgpt.ChatGPTSubscriptionModel(id=model_id, reasoning_effort="none")


def measurements(run: RunOutput, latency_ms: float) -> dict[str, Any]:
    """What one run measured: the Judgement, the wall-clock latency, Agno's metrics.

    Agno returns a Judgement when the model answered valid JSON for the schema; anything else is a parse error row with the first 200
    characters of the text (an error row, not a crash). `usage` is `RunMetrics.to_dict()`, whatever the provider filled: tokens, cache
    reads, reasoning tokens, Agno's own duration and time to first token; the metrics price it offline.

    Args:
        run: Agno's output of the Agent run.
        latency_ms: the wall-clock time of `Agent.run`, in milliseconds.

    Returns:
        The row fields `p_attack`, `category_pred`, `error`, `latency_ms`, `usage` and `raw`.
    """
    content: Any = run.content
    judged = isinstance(content, Judgement)
    return {
        "p_attack": content.p_attack if judged else None,
        "category_pred": content.category if judged else None,
        "error": None if judged else f"parse: {str(content)[:200]}",
        "latency_ms": latency_ms,
        "usage": run.metrics.to_dict() if run.metrics else {},
        "raw": {
            "content": content.model_dump() if judged else str(content),
            "model": run.model,
        },
    }
