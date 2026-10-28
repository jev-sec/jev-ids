"""Jev detector: request body, answer parsing and the retry policy, through the SDK over a mock transport."""

import json
from typing import Any

import httpx2
import pytest
from typesafe_sdk import TypeSafeError

from jev_ids.detectors import jev
from jev_ids.run import sample_examples
from tests.helpers import CONFIG, JEV_PROMPT, make_flow, make_train, no_sleep

# The answer shape of docs.typesafe.ai/api (read on 2026-09-21) with the numbers of a pilot row (warezmaster, 2026-09-20).
BODY: dict[str, Any] = {
    "model": "jev-1.13.0",
    "answers": {
        "is_attack": {"type": "noul", "noul": 0.78},
        "category": {
            "type": "choice",
            "choice": "r2l",
            "confidence": 0.8,
            "probabilities": {"r2l": 0.84, "probe": 0.02, "normal": 0.14},
        },
    },
    "usage": {"input_tokens": 1606, "output_tokens": 79},
}
FLOW = make_flow(9, "r2l", value="1")
TRAIN = make_train(["normal", "dos", "probe"])


def serving(*responses: httpx2.Response | Exception, sent: list[dict[str, Any]] | None = None) -> jev.TypeSafeClient:
    """A client with no network: its transport answers from the queue, in order, and records what was sent."""
    queue = list(responses)

    def handler(request: httpx2.Request) -> httpx2.Response:
        if sent is not None:
            sent.append(json.loads(request.content))
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return jev.TypeSafeClient(api_key="test-key", transport=httpx2.MockTransport(handler), retry=jev.NO_RETRY)


@pytest.fixture
def detector(monkeypatch: pytest.MonkeyPatch) -> jev.JevDetector:
    """A detector whose backoff does not wait; each test plugs in the client it needs."""
    monkeypatch.setattr(jev.time, "sleep", no_sleep)
    return jev.JevDetector(JEV_PROMPT)


def test_detector_reads_the_model_and_the_hash_off_the_template(detector: jev.JevDetector) -> None:
    assert (detector.name, detector.model) == ("jev", "jev-1.13.0")
    assert detector.prompt_hash == "h"
    assert detector.client is None  # built on the first call


def test_request_body_adds_the_flow_the_examples_and_the_rubric(detector: jev.JevDetector) -> None:
    examples = sample_examples(TRAIN, 1, 0, CONFIG["categories"])
    body = jev.request_body(detector.template, FLOW, examples)
    state = body["state"]
    assert body["model"] == "jev-1.13.0"
    assert state["flows"] == {"under_test": FLOW.attributes_csv}
    assert state["instructions"].startswith("You are given one record")
    assert state["columns"] == "a,b,c"
    assert len(state["examples"]) == 3
    assert state["examples"][0].keys() == {"record", "category"}
    assert set(body["questions"]) == {"is_attack", "category"}
    assert body["questions"]["category"]["criteria"] == state["categories"]
    # The template itself is untouched: every call starts from the file again.
    assert "flows" not in json.loads(detector.template)["state"]
    assert "examples" not in jev.request_body(detector.template, FLOW, [])["state"]


def test_request_body_writes_the_flow_and_the_examples_as_the_record_says(detector: jev.JevDetector) -> None:
    flow = make_flow(9, "dos", value="25160.418777440053")
    example = make_flow(1, "normal", value="0.0")
    compact = jev.request_body(detector.template, flow, [example])["state"]
    assert compact["flows"] == {"under_test": "25160,25160,25160"}
    assert compact["examples"] == [{"record": "0,0,0", "category": "normal"}]
    full = jev.request_body(detector.template, flow, [example], "full")["state"]
    assert full["flows"] == {"under_test": flow.attributes_csv}
    assert full["examples"][0]["record"] == example.attributes_csv
    assert (detector.record, jev.JevDetector(JEV_PROMPT, "full").record) == ("compact", "full")


def test_predict_sends_the_body_as_is_and_reads_the_answer_and_the_version(detector: jev.JevDetector) -> None:
    sent: list[dict[str, Any]] = []
    detector.client = serving(httpx2.Response(200, json=BODY), sent=sent)
    prediction = detector.predict(FLOW, [])
    # The SDK adds nothing to the template's request and drops nothing from it.
    assert sent == [jev.request_body(detector.template, FLOW, [])]
    assert prediction["p_attack"] == 0.78
    assert prediction["model"] == "jev-1.13.0"
    assert prediction["category_pred"] == "r2l"
    assert prediction["confidence"] == 0.8
    assert prediction["usage"] == {"input_tokens": 1606, "output_tokens": 79}
    assert prediction["latency_ms"] > 0
    assert prediction["retries"] == 0
    assert prediction["raw"] == BODY
    assert "error" not in prediction


def test_retries_on_429_then_succeeds(detector: jev.JevDetector) -> None:
    detector.client = serving(httpx2.Response(429, json={"error": "rate"}), httpx2.Response(200, json=BODY))
    prediction = detector.predict(FLOW, [])
    assert prediction["retries"] == 1
    assert prediction["p_attack"] == 0.78


def test_client_errors_fail_without_retry(detector: jev.JevDetector) -> None:
    detector.client = serving(httpx2.Response(400, json={"error": "bad"}))
    prediction = detector.predict(FLOW, [])
    assert prediction["error"].startswith("HTTP 400")
    assert prediction["retries"] == 0
    assert "p_attack" not in prediction  # nothing measured, nothing written


def test_network_errors_give_up_after_five_attempts(detector: jev.JevDetector) -> None:
    detector.client = serving(*[httpx2.ConnectError("down") for _ in range(jev.MAX_ATTEMPTS)])
    prediction = detector.predict(FLOW, [])
    assert prediction["error"].startswith("TypeSafeAPIConnectionError")
    assert prediction["retries"] == jev.MAX_ATTEMPTS - 1
    assert "p_attack" not in prediction


def test_missing_api_key_is_an_error(detector: jev.JevDetector, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(jev.API_KEY_VAR, raising=False)
    with pytest.raises(TypeSafeError, match="TYPESAFE_API_KEY"):
        detector.predict(FLOW, [])
