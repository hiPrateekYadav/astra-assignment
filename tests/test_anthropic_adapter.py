from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from vulnscan.config import ProviderSettings, RetrySettings, RoleSettings
from vulnscan.models.anthropic_messages import AnthropicClient
from vulnscan.models.base import (
    ADAPTERS,
    CompletionRequest,
    InvalidOutputError,
    ModelError,
    RateLimitError,
    TransientModelError,
    TruncatedOutputError,
)

REQUEST = CompletionRequest("system text", "user text", json_mode=True)


def message(text: str | None = "ok", stop_reason: str = "end_turn"):
    content = [SimpleNamespace(type="thinking", thinking="")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=11, output_tokens=7),
    )


class FakeMessages:
    """Stands in for client.messages, replaying one reply or raising one error."""

    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.kwargs: dict = {}

    def stream(self, **kwargs):
        self.kwargs = kwargs
        return self

    def __enter__(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self

    def __exit__(self, *_) -> None:
        pass

    def get_final_message(self):
        return self.outcome


def make_client(outcome, **role) -> tuple[AnthropicClient, FakeMessages]:
    client = AnthropicClient(
        RoleSettings(provider="anthropic", model="claude-test", max_output_tokens=100, **role),
        ProviderSettings(adapter="anthropic", base_url="https://example.test", api_key_env="KEY"),
        "key",
        RetrySettings(max_attempts=1),
    )
    fake = FakeMessages(outcome)
    client._client = SimpleNamespace(messages=fake, beta=SimpleNamespace(messages=fake))
    return client, fake


def status_error(kind: type[anthropic.APIStatusError], status: int, headers: dict | None = None):
    response = httpx2.Response(status, headers=headers, request=httpx2.Request("POST", "https://example.test"))
    return kind("failure", response=response, body=None)


def test_adapter_is_selectable_from_config():
    assert ADAPTERS["anthropic"] is AnthropicClient


def test_reply_text_and_usage_are_returned_without_thinking_blocks():
    client, _ = make_client(message("hello"))
    result = client._send(REQUEST)
    assert (result.text, result.input_tokens, result.output_tokens) == ("hello", 11, 7)


def test_request_uses_the_system_field_and_never_sends_temperature():
    client, fake = make_client(message())
    client._send(REQUEST)
    assert fake.kwargs["system"] == "system text"
    assert fake.kwargs["messages"] == [{"role": "user", "content": "user text"}]
    assert fake.kwargs["max_tokens"] == 100
    assert "temperature" not in fake.kwargs


def test_extra_params_are_passed_to_the_call():
    client, fake = make_client(message(), extra_params={"betas": ["x"], "fallbacks": "default"})
    client._send(REQUEST)
    assert fake.kwargs["fallbacks"] == "default"


def test_max_tokens_stop_reason_maps_to_truncation():
    client, _ = make_client(message("{", stop_reason="max_tokens"))
    assert client._send(REQUEST).finish_reason == "length"


def test_truncation_before_any_text_is_reported():
    client, _ = make_client(message(None, stop_reason="max_tokens"))
    with pytest.raises(TruncatedOutputError):
        client._send(REQUEST)


def test_refusal_is_a_permanent_error():
    client, _ = make_client(message(None, stop_reason="refusal"))
    with pytest.raises(ModelError, match="declined"):
        client._send(REQUEST)


def test_empty_reply_is_invalid_output():
    client, _ = make_client(message(None))
    with pytest.raises(InvalidOutputError):
        client._send(REQUEST)


def test_rate_limit_keeps_retry_after():
    client, _ = make_client(status_error(anthropic.RateLimitError, 429, {"retry-after": "7"}))
    with pytest.raises(RateLimitError) as caught:
        client._send(REQUEST)
    assert caught.value.retry_after == 7


def test_server_error_is_transient():
    client, _ = make_client(status_error(anthropic.InternalServerError, 529))
    with pytest.raises(TransientModelError):
        client._send(REQUEST)


def test_bad_request_is_permanent():
    client, _ = make_client(status_error(anthropic.BadRequestError, 400))
    with pytest.raises(ModelError) as caught:
        client._send(REQUEST)
    assert not isinstance(caught.value, TransientModelError)
