"""Jev, TypeSafe's System One Model, through the official Python SDK.

In reading order:

- `JevDetector`: holds the request template of `prompts/<dataset>/jev.json` and
  the SDK client, built on the first call. Its `predict` judges one Flow per request.
- `request_body`: the template with the Flow and the Examples in its `state`.
- `attempt` and `post`: one request, retried when TypeSafe is rate-limited or overloaded.
- `measurements`: what one successful answer measured.

The template is the whole conversation with Jev, made of a `state` (the instructions, the column header, the Category descriptions)
and two questions that point at state paths in backticks. `is_attack` is a `noul` whose answer is a probability
and becomes `p_attack`. `category` is a `choice` over the Categories whose answer is the Category with a confidence.
Python adds only what changes per call, the Flow under test at `flows.under_test` and the labeled `examples`, their values written
as the run's `record` says (`dataset.record_text`). One request judges one Flow (B = 1). The SDK sends the template's `state`,
`model` and `questions` exactly as the file has them, so the file still describes the request byte for byte.
"""

import json
import time
from collections.abc import Sequence
from typing import Any

from typesafe_sdk import RetryPolicy, SystemOneResponse, TypeSafeAPIConnectionError, TypeSafeAPIError, TypeSafeClient

from jev_ids.dataset import Flow, record_text

# Naming the variable that holds the API key, which the SDK reads by itself.
API_KEY_VAR = "TYPESAFE_API_KEY"
# Allowing five attempts with exponential backoff on rate limits (429), overload (529), server errors and network failures. Any other 4xx
# fails at once. A failure ends as a row with `error`, never as an exception, so the run continues. The SDK's own retries stay off, because
# a retry it made silently would hide inside `latency_ms` and escape `retries`. The run measures the successful attempt alone and counts the
# failed ones. The runs up to 2026-09-21 went through the Vercel AI Gateway, which rate-limited 1,350 of the 1,800 pilot rows at least once.
MAX_ATTEMPTS = 5
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 60
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})
NO_RETRY = RetryPolicy(max_retries=0, timeout=None)


class JevDetector:
    """Judges one Flow per request to TypeSafe, retrying when the API is rate-limited or overloaded."""

    name = "jev"

    def __init__(self, prompt: dict[str, Any], record: str = "compact") -> None:
        """Keep the template; the client waits for the first call, so nothing needs the key until then.

        Args:
            prompt: `run.load_prompt` of `prompts/<dataset>/jev.json`, the request body without the Flow and the Examples.
            record: how the values of the Flow and the Examples are written, one of `dataset.RECORDS`.
        """
        self.template: str = prompt["text"]
        self.record = record
        self.prompt_hash: str = prompt["sha256"]
        # Reading the model id from the template, which names a versioned id (`jev-1.13.0`),
        # never the moving alias `jev-latest`, so every run pins the version it was made with.
        # The answer also reports the version that produced it, and `measurements` writes that one into the row.
        self.model: str = json.loads(self.template)["model"]
        self.client: TypeSafeClient | None = None

    def predict(self, flow: Flow, examples: Sequence[Flow]) -> dict[str, Any]:
        """One request for one Flow: what it measured, or `error` and `retries`."""
        if self.client is None:
            # Leaving `TYPESAFE_API_KEY` to the SDK, which reads it on its own and refuses to start without it.
            self.client = TypeSafeClient(retry=NO_RETRY, timeout=TIMEOUT_SECONDS)
        return post(self.client, request_body(self.template, flow, examples, self.record))


def request_body(template: str, flow: Flow, examples: Sequence[Flow], record: str = "compact") -> dict[str, Any]:
    """The template with the Flow at `flows.under_test` and the Examples, if any.

    Examples are labeled by Category only, because attack names never reach a model (CONTEXT.md). The Category question grades against the
    descriptions the state already holds, so its `criteria` rubric is copied from `state.categories` here and the file states them once.

    Args:
        template: the text of `prompts/<dataset>/jev.json`, the request body without the Flow and the Examples.
        flow: the Flow under test.
        examples: the labeled Examples, which may be empty.
        record: how the values of the Flow and the Examples are written, one of `dataset.RECORDS`.

    Returns:
        The request body, with the Flow, the Examples and the Category `criteria` filled in.
    """
    body: dict[str, Any] = json.loads(template)
    body["state"]["flows"] = {"under_test": record_text(flow, record)}
    if examples:
        body["state"]["examples"] = [
            {
                "record": record_text(example, record),
                "category": example.category,
            }
            for example in examples
        ]
    body["questions"]["category"]["criteria"] = body["state"]["categories"]
    return body


def attempt(client: TypeSafeClient, body: dict[str, Any]) -> dict[str, Any]:
    """One request: the measurements on success, else `error` and `retryable`."""
    started = time.perf_counter()
    try:
        response: SystemOneResponse = client.system_one(  # pyright: ignore[reportUnknownMemberType]  the SDK leaves a TypeVar unsolved
            body["state"], body["questions"], model=body["model"]
        )
    # Catching network failures and timeouts, which the SDK raises as one family.
    except TypeSafeAPIConnectionError as exc:
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "retryable": True,
        }
    # Catching an HTTP status the API answered with.
    except TypeSafeAPIError as exc:
        return {
            "error": f"HTTP {exc.status}: {str(exc)[:200]}",
            "retryable": exc.status in RETRYABLE_STATUS,
        }
    return measurements(response.raw_http_response.json(), (time.perf_counter() - started) * 1000)


def post(client: TypeSafeClient, body: dict[str, Any]) -> dict[str, Any]:
    """Up to MAX_ATTEMPTS attempts with exponential backoff.

    Only a retryable failure earns another attempt.

    Args:
        client: the TypeSafe client.
        body: the request body, sent unchanged on every attempt.

    Returns:
        The last attempt's result plus `retries`, the failed attempts before it. `latency_ms` measures the successful attempt alone.
    """
    result = attempt(client, body)
    retries = 0
    while result.get("retryable") and retries < MAX_ATTEMPTS - 1:
        time.sleep(BACKOFF_SECONDS * 2**retries)
        result = attempt(client, body)
        retries += 1
    result.pop("retryable", None)
    return {
        **result,
        "retries": retries,
    }


def measurements(body: dict[str, Any], latency_ms: float) -> dict[str, Any]:
    """What one answer measured, plus the whole body as `raw` for responses.jsonl.

    `p_attack` is the `noul` answer, and the Category and the recorded confidence come from the `choice` answer.
    `usage` is TypeSafe's own token report (`input_tokens`, `output_tokens`), which the metrics price offline against prices.json.
    `model` is the version that answered, kept in the row so the pin survives even if a template ever names an alias.

    Args:
        body: the JSON body of TypeSafe's answer.
        latency_ms: the wall-clock time of the request, in milliseconds.

    Returns:
        The row fields `model`, `p_attack`, `category_pred`, `confidence`, `latency_ms`, `usage` and `raw`.
    """
    answers = body["answers"]
    return {
        "model": body.get("model"),
        "p_attack": answers["is_attack"].get("noul"),
        "category_pred": answers["category"].get("choice"),
        "confidence": answers["category"].get("confidence"),
        "latency_ms": latency_ms,
        "usage": body.get("usage", {}),
        "raw": body,
    }
