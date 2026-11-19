"""The LLM baseline: Claude Sonnet 5.5 through an Agno Agent and the Anthropic API.

The key comes from `ANTHROPIC_API_KEY`, which the CLI loads from the `.env` file at the project root.

In reading order:

- `Judgement`: the JSON answer the model must give, sent as Anthropic's native structured output (`output_config.format`).
- `LLMDetector`: builds the Agno model once. Its `predict` runs one Agent per Flow with the instructions of `prompts/<dataset>/llm.md`.
- `instructions`: that Markdown with the Examples filled in.
- `StopReasonClaude`: Agno's `Claude` model, plus the `stop_reason` of each response, so a refusal is told apart from a parse error.
- `make_model`: the Agno model with the settings of the baseline.
- `measurements`: what one run measured, read off Agno's RunOutput.

Each Flow gets one `Agent.run` and no retries of our own, so an API error becomes an error row and the run goes on.
"""

import time
from collections.abc import Sequence
from typing import Any, Literal

from agno.agent import Agent
from agno.models.anthropic import Claude
from agno.run.agent import RunOutput
from pydantic import BaseModel, Field

from jev_ids.dataset import Flow, record_text

DEFAULT_MODEL = "claude-sonnet-5-5"
# Heading the Examples that replace `{examples}` in the prompt file at k > 0. At k = 0 the placeholder is simply removed.
EXAMPLES_HEADER = "\nLabeled example records (record => category):\n"
# Bounding the answer. A Judgement takes about 30 tokens and thinking is off, so a cut at this size means a runaway answer.
MAX_TOKENS = 1024
# Seconds before a request becomes an error row that `redo-errors` repairs, instead of a hang that freezes the run.
TIMEOUT_S = 120.0


class Judgement(BaseModel):
    """The structured answer asked of the LLM.

    `category` is free text in the schema, so the schema names no dataset; the prompt file lists the options.
    """

    verdict: Literal["attack", "normal"]
    category: str
    p_attack: float = Field(ge=0.0, le=1.0)


class LLMDetector:
    """Judges Flows with Claude through an Agno Agent, with one call per Flow and no tools."""

    name = "llm:sonnet"

    def __init__(self, prompt: dict[str, Any], model_id: str | None = None, record: str = "compact") -> None:
        """Keep the prompt and build the Agno model once.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/llm.md`.
            model_id: the Anthropic model id, or None for `DEFAULT_MODEL`.
            record: one of `dataset.RECORDS`, as for `JevDetector`.
        """
        self.model = model_id or DEFAULT_MODEL
        self.template: str = prompt["text"]
        self.prompt_hash: str = prompt["sha256"]
        self.record = record
        # Building the model object once, because it holds the HTTP client. An Agent is cheap and built per call.
        self.agno_model = make_model(self.model)

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One Agent run for one Flow; the Examples travel in the instructions.

        Args:
            flow: the Flow to judge.
            examples: the labeled Examples, written into the instructions.

        Returns:
            The `measurements` of the run, or `error` when the API call raised.
        """
        # Typing the agent as `Any`, because Agno's `run` overloads are partially untyped for pyright.
        agent: Any = Agent(
            model=self.agno_model,
            instructions=instructions(self.template, examples, self.record),
            output_schema=Judgement,
            markdown=False,
            retries=0,
            telemetry=False,
        )
        started = time.perf_counter()
        try:
            run: RunOutput = agent.run(f"Record:\n{record_text(flow, self.record)}")
        # Recording every API error in the row instead of raising it.
        except Exception as exc:  # noqa: BLE001  Agno re-raises the SDK's errors under its own types, and a stream run cannot resume after a crash
            return {"error": f"{type(exc).__name__}: {exc}"[:500]}
        return measurements(run, (time.perf_counter() - started) * 1000)


def instructions(template: str, examples: Sequence[Flow], record: str = "compact") -> str:
    """The prompt file with `{examples}` filled with the labeled Examples.

    Examples are labeled by Category only, because attack names never reach a model (CONTEXT.md). At k = 0 the placeholder is removed.

    Args:
        template: the text of `prompts/<dataset>/llm.md`.
        examples: the labeled Examples, which may be empty.
        record: how the values of the Examples are written, one of `dataset.RECORDS`.

    Returns:
        The instructions of the Agent.
    """
    lines = "".join(f"{record_text(example, record)} => {example.category}\n" for example in examples)
    return template.replace("{examples}", EXAMPLES_HEADER + lines if lines else "")


class StopReasonClaude(Claude):
    """Agno's `Claude`, which also keeps the `stop_reason` and `stop_details` of each response in the message's `provider_data`.

    Sonnet 5.5 declines some requests with an HTTP 200 whose `stop_reason` is `refusal`. Agno drops that field, and the empty answer would
    otherwise read as a parse error.
    """

    def _parse_provider_response(self, response: Any, response_format: Any = None, **kwargs: Any) -> Any:
        """Agno's parse, plus the stop reason of the response."""
        model_response = super()._parse_provider_response(response, response_format=response_format, **kwargs)  # pyright: ignore[reportUnknownMemberType]  Agno annotates response_format with a bare Dict
        details = response.stop_details.model_dump() if getattr(response, "stop_details", None) else None
        model_response.provider_data = {
            **(model_response.provider_data or {}),
            "stop_reason": response.stop_reason,
            "stop_details": details,
        }
        return model_response


def make_model(model_id: str) -> StopReasonClaude:
    """The Agno model of the baseline.

    Sonnet 5.5 rejects `thinking: {"type": "disabled"}` with a 400, and `between_tools` is its documented way
    to answer without thinking. The model takes no sampling parameter, so no temperature is set and the structured
    output is the only constraint. Effort is `low`, the lowest level. Prompt caching is off, because the Examples
    change with every Flow.

    Args:
        model_id: the Anthropic model id.

    Returns:
        One model object, shared by every Agent of the run.
    """
    return StopReasonClaude(
        id=model_id,
        max_tokens=MAX_TOKENS,
        thinking={"type": "between_tools"},
        output_config={"effort": "low"},
        timeout=TIMEOUT_S,
    )


def stop_of(run: RunOutput) -> dict[str, Any]:
    """The `stop_reason` and `stop_details` of the last assistant message, or an empty dict when Agno kept none."""
    for message in reversed(run.messages or []):
        if message.role == "assistant":
            return {key: value for key, value in (message.provider_data or {}).items() if key in ("stop_reason", "stop_details")}
    return {}


def error_of(content: Any, stop: dict[str, Any]) -> str | None:
    """The error of a run: None for a Judgement, else the refusal category, the cut at `max_tokens` or the unparsed text."""
    if isinstance(content, Judgement):
        return None
    if stop.get("stop_reason") == "refusal":
        details: dict[str, Any] = stop.get("stop_details") or {}
        return f"refusal: {details.get('category')}"
    if stop.get("stop_reason") == "max_tokens":
        return "max_tokens"
    return f"parse: {str(content)[:200]}"


def measurements(run: RunOutput, latency_ms: float) -> dict[str, Any]:
    """What one run measured: the Judgement, the wall-clock latency, Agno's metrics and the stop reason.

    Agno returns a Judgement when the model answered valid JSON for the schema. Anything else is an error row (`error_of`).
    `usage` is `RunMetrics.to_dict()`: tokens, cache reads, Agno's own duration and time to first token. The metrics price it offline.

    Args:
        run: Agno's output of the Agent run.
        latency_ms: the wall-clock time of `Agent.run`, in milliseconds.

    Returns:
        The row fields `p_attack`, `category_pred`, `error`, `latency_ms`, `usage` and `raw`.
    """
    content: Any = run.content
    judged = isinstance(content, Judgement)
    stop = stop_of(run)
    return {
        "p_attack": content.p_attack if judged else None,
        "category_pred": content.category if judged else None,
        "error": error_of(content, stop),
        "latency_ms": latency_ms,
        "usage": run.metrics.to_dict() if run.metrics else {},
        "raw": {
            "content": content.model_dump() if judged else str(content),
            "model": run.model,
            **stop,
        },
    }
