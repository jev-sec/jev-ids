"""OpenAI GPT-5.x through the ChatGPT Codex backend, with the Codex OAuth tokens.

In reading order:

- `jwt_expiry` and `TokenStore`: the OAuth tokens on disk, read and refreshed through the Codex client id.
- `ChatGPTSubscriptionModel`: Agno's `OpenAIResponses` routed to the backend,
  signed with the token and carrying the `instructions` preamble.
- `aggregate`: the backend only streams, so the deltas are merged back into one response.

This is the minimal, typed re-implementation of the user's original `ChatGPTSubscriptionModel`.
It reads the same environment variables and token file, so a login done there is reused here.
The browser login stays in the original module, so run it once there if the refresh token expires.
"""

import base64
import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from agno.models.message import Message
from agno.models.openai.responses import OpenAIResponses
from agno.models.response import ModelResponse
from agno.run.agent import RunOutput
from pydantic import BaseModel

OAUTH_REFRESH_URL = "https://auth.openai.com/oauth/token"
BACKEND_BASE_URL = "https://chatgpt.com/backend-api/codex"
CLIENT_ID_VAR = "CHATGPT_CLIENT_ID"
OAUTH_FILE_VAR = "CHATGPT_TOKEN_PATH"
DEFAULT_OAUTH_FILE = Path.home() / ".chatgpt_oauth" / "tokens.json"
# Renewing a token this long before it expires, so it never dies in the middle of a call that was started while it was still valid.
REFRESH_MARGIN_SECONDS = 300.0
JWT_PARTS = 3
# Sending the preamble as `instructions` with every request, since the backend requires the field. Fixed after 1,685 calls accepted it.
PREAMBLE = (
    "You are a classifier for network intrusion detection. Follow the developer instructions and answer only in the requested JSON format."
)


def jwt_expiry(token: str) -> float | None:
    """The `exp` claim of a JWT, read without verifying the signature.

    The token is only inspected to know when to refresh it, never trusted for anything else, so the signature does not matter here.

    Args:
        token: the access token, a JWT.

    Returns:
        The expiry in Unix seconds, or `None` when the token is malformed or has no `exp` claim.
    """
    parts = token.split(".")
    if len(parts) != JWT_PARTS:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    exp = claims.get("exp")
    return None if exp is None else float(exp)


class TokenStore:
    """The OAuth tokens on disk, refreshed through the Codex client id.

    The file is the one the original module writes, so both modules stay compatible and a login done there is reused here.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Remember where the tokens live; nothing is read until they are needed."""
        # Choosing `CHATGPT_TOKEN_PATH` when it is set, otherwise the path the original module writes to.
        default = Path(os.environ.get(OAUTH_FILE_VAR, str(DEFAULT_OAUTH_FILE))).expanduser()
        self.path = default if path is None else path
        self.tokens: dict[str, Any] = {}

    def save(self) -> None:
        """Write the tokens back, readable by the owner only: they are bearer tokens."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.tokens, indent=2), encoding="utf-8")
        self.path.chmod(0o600)

    def access_token(self) -> str:
        """A valid access token, reading the file and refreshing it as needed.

        The file is read the first time a token is asked for, and a missing one points at the login that creates it.
        A token that expires within `REFRESH_MARGIN_SECONDS` is renewed before it is handed out,
        so it never dies in the middle of a call that was started while it was still valid.

        Returns:
            The access token, refreshed first when it was due.
        """
        if not self.tokens:
            if not self.path.exists():
                raise FileNotFoundError(f"no OAuth tokens at {self.path}; log in once with the original module")
            self.tokens = json.loads(self.path.read_text(encoding="utf-8"))
        if time.time() + REFRESH_MARGIN_SECONDS >= float(self.tokens.get("expires_at", 0.0)):
            self.refresh()
        return str(self.tokens["access_token"])

    def refresh(self) -> None:
        """Exchange the refresh token for a new access token and save the file."""
        client_id = os.environ.get(CLIENT_ID_VAR)
        if not client_id:
            raise RuntimeError(f"{CLIENT_ID_VAR} is not set")
        response = requests.post(
            OAUTH_REFRESH_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.tokens["refresh_token"],
                "client_id": client_id,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if not response.ok:
            detail = response.text[:200]
            raise RuntimeError(f"token refresh failed: HTTP {response.status_code} {detail}")
        data: dict[str, Any] = response.json()
        access = str(data["access_token"])
        self.tokens["access_token"] = access
        # Taking the expiry from the JWT, or assuming one hour when it has no readable claim.
        self.tokens["expires_at"] = jwt_expiry(access) or time.time() + 3600
        if "refresh_token" in data:
            self.tokens["refresh_token"] = data["refresh_token"]
        self.save()


# Declaring a dataclass because Agno's model classes are dataclasses
# and this one adds fields to `OpenAIResponses`. It is the only place where that is required.
@dataclass
class ChatGPTSubscriptionModel(OpenAIResponses):
    """Agno model routed to the ChatGPT Codex backend with an OAuth token."""

    id: str = "gpt-5.6-luna"
    name: str = "ChatGPTSubscription"
    provider: str = "ChatGPT-Subscription"
    preamble: str = PREAMBLE
    token_store: TokenStore = field(default_factory=TokenStore)
    _last_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Apply what the Codex backend requires of every request."""
        super().__post_init__()
        self.base_url = BACKEND_BASE_URL
        self.store = False
        self.include = ["reasoning.encrypted_content"]
        self.reasoning_summary = "auto"
        # Putting the preamble in `instructions`, a field the backend requires.
        params: dict[str, Any] = dict(self.request_params or {})
        params["instructions"] = self.preamble
        self.request_params = params

    def _get_client_params(self) -> dict[str, Any]:
        """Agno's hook for the OpenAI client settings: here the token is the key.

        A refreshed token invalidates the cached clients so the next request is signed with the new one.

        Returns:
            The OpenAI client's keyword arguments, with the token as `api_key` and the backend as `base_url`,
            plus the parent's optional settings and `client_params`.
        """
        token = self.token_store.access_token()
        if token != self._last_token:
            self._last_token = token
            self.client = None
            self.async_client = None
        params: dict[str, Any] = {
            "api_key": token,
            "base_url": self.base_url,
        }
        # Passing the parent's optional client settings through only when they are set.
        for name in ("timeout", "max_retries", "default_headers", "default_query"):
            value = getattr(self, name)
            if value is not None:
                params[name] = value
        if self.client_params:
            params.update(self.client_params)
        return params

    def invoke(  # noqa: PLR0913, PLR0917  the parent's signature
        self,
        messages: Sequence[Message],
        assistant_message: Message,
        response_format: dict[str, Any] | type[BaseModel] | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        run_response: RunOutput | None = None,
        compress_tool_results: bool = False,
    ) -> ModelResponse:
        """The backend only streams; collect the deltas into one response."""
        parent: Any = super()
        deltas = parent.invoke_stream(
            messages=list(messages),
            assistant_message=assistant_message,
            response_format=response_format,
            tools=tools,
            tool_choice=tool_choice,
            run_response=run_response,
            compress_tool_results=compress_tool_results,
        )
        return aggregate(deltas)


def aggregate(deltas: Any) -> ModelResponse:
    """Merge the streamed deltas: text, reasoning, usage and provider data."""
    merged = ModelResponse()
    merged.role = "assistant"
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    for delta in deltas:
        # Collecting text and reasoning, which arrive in pieces, to join them at the end. The usage report is resent whole,
        # so the last one seen wins, and the provider fields accumulate across the stream.
        if delta.content is not None:
            content_parts.append(delta.content)
        if delta.reasoning_content is not None:
            reasoning_parts.append(delta.reasoning_content)
        if delta.response_usage is not None:
            merged.response_usage = delta.response_usage
        if delta.provider_data is not None:
            merged.provider_data = {
                **(merged.provider_data or {}),
                **delta.provider_data,
            }
    if content_parts:
        merged.content = "".join(content_parts)
    if reasoning_parts:
        merged.reasoning_content = "".join(reasoning_parts)
    return merged
