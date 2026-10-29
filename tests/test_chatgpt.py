"""OAuth token store and the Codex-backend model adapter."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import requests
from agno.metrics import MessageMetrics
from agno.models.message import Message
from agno.models.openai.responses import OpenAIResponses
from agno.models.response import ModelResponse

from jev_ids.detectors import chatgpt
from tests.helpers import FakeResponse


def jwt_with_exp(exp: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=")
    return "h." + payload.decode() + ".s"


def store_at(tmp_path: Path, expires_at: float) -> chatgpt.TokenStore:
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                "access_token": "old",
                "refresh_token": "r1",
                "expires_at": expires_at,
            }
        )
    )
    return chatgpt.TokenStore(path)


def test_jwt_expiry_reads_the_claim_and_tolerates_garbage() -> None:
    assert chatgpt.jwt_expiry(jwt_with_exp(1_800_000_000)) == 1_800_000_000.0
    assert chatgpt.jwt_expiry("not-a-jwt") is None
    assert chatgpt.jwt_expiry("a.###.c") is None


def test_missing_token_file_points_to_the_login(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="log in once"):
        chatgpt.TokenStore(tmp_path / "none.json").access_token()


def test_valid_token_is_returned_without_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("no refresh expected")

    monkeypatch.setattr(requests, "post", forbidden)
    store = store_at(tmp_path, expires_at=9_999_999_999)
    assert store.access_token() == "old"


def test_expired_token_is_refreshed_and_saved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    new_token = jwt_with_exp(1_900_000_000)
    seen: list[dict[str, Any]] = []

    def fake_post(_url: str, *, data: dict[str, Any], headers: dict[str, str], timeout: int) -> FakeResponse:
        seen.append(
            {
                "data": data,
                "headers": headers,
                "timeout": timeout,
            }
        )
        tokens = {
            "access_token": new_token,
            "refresh_token": "r2",
        }
        return FakeResponse(200, tokens)

    monkeypatch.setenv(chatgpt.CLIENT_ID_VAR, "client-123")
    monkeypatch.setattr(requests, "post", fake_post)
    store = store_at(tmp_path, expires_at=1.0)

    assert store.access_token() == new_token

    assert seen[0]["data"]["grant_type"] == "refresh_token"
    assert seen[0]["data"]["client_id"] == "client-123"
    saved = json.loads(store.path.read_text())
    assert saved["refresh_token"] == "r2"  # noqa: S105  a fake token made up by this test
    assert saved["expires_at"] == 1_900_000_000.0
    assert oct(store.path.stat().st_mode & 0o777) == "0o600"


def unauthorized(*_args: object, **_kwargs: object) -> FakeResponse:
    return FakeResponse(401, {"error": "bad"})


def test_refresh_needs_the_client_id_and_a_good_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = store_at(tmp_path, expires_at=1.0)
    monkeypatch.delenv(chatgpt.CLIENT_ID_VAR, raising=False)
    with pytest.raises(RuntimeError, match=chatgpt.CLIENT_ID_VAR):
        store.access_token()
    monkeypatch.setenv(chatgpt.CLIENT_ID_VAR, "client-123")
    monkeypatch.setattr(requests, "post", unauthorized)
    with pytest.raises(RuntimeError, match="HTTP 401"):
        store.access_token()


def test_model_injects_the_preamble_and_the_token(tmp_path: Path) -> None:
    store = store_at(tmp_path, expires_at=9_999_999_999)
    model = chatgpt.ChatGPTSubscriptionModel(id="gpt-5.6-luna", reasoning_effort="none", token_store=store)

    assert model.base_url == chatgpt.BACKEND_BASE_URL
    assert model.store is False
    assert model.include == ["reasoning.encrypted_content"]
    assert model.request_params == {"instructions": chatgpt.PREAMBLE}
    params = model._get_client_params()  # pyright: ignore[reportPrivateUsage]  the hook Agno calls by its private name
    assert params["api_key"] == "old"
    assert params["base_url"] == chatgpt.BACKEND_BASE_URL


def test_invoke_aggregates_the_forced_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_stream(_self: object, **_kwargs: object) -> Any:
        first = ModelResponse()
        first.content = '{"verdict": '
        second = ModelResponse()
        second.content = '"attack"}'
        second.reasoning_content = "thinking"
        second.response_usage = MessageMetrics(input_tokens=12)
        second.provider_data = {"response_id": "resp_1"}
        yield first
        yield second

    monkeypatch.setattr(OpenAIResponses, "invoke_stream", fake_stream)
    model = chatgpt.ChatGPTSubscriptionModel(token_store=store_at(tmp_path, expires_at=9_999_999_999))

    merged = model.invoke([Message(role="user", content="hi")], Message(role="assistant"))

    assert merged.content == '{"verdict": "attack"}'
    assert merged.reasoning_content == "thinking"
    assert merged.response_usage is not None
    assert merged.response_usage.input_tokens == 12
    assert merged.provider_data == {"response_id": "resp_1"}
