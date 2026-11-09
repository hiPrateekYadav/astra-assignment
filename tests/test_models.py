import httpx
import pytest
from pydantic import BaseModel

from vulnscan.config import ProviderSettings, RetrySettings, RoleSettings
from vulnscan.models import base
from vulnscan.models.base import (
    ADAPTERS,
    CompletionRequest,
    CompletionResult,
    InvalidOutputError,
    ModelClient,
    ModelError,
    RateLimitError,
    TransientModelError,
    TruncatedOutputError,
    extract_json,
    register_adapter,
)
from vulnscan.models.openai_compatible import OpenAICompatibleClient

ROLE = RoleSettings(provider="fake", model="fake-model")
PROVIDER = ProviderSettings(adapter="fake", base_url="https://example.test/v1", api_key_env="KEY")
RETRY = RetrySettings(max_attempts=3, base_delay_seconds=1, max_delay_seconds=30)


class Answer(BaseModel):
    value: int


class FakeClient(ModelClient):
    """Plays back a script of results and errors."""

    def __init__(self, script: list) -> None:
        super().__init__(ROLE, PROVIDER, "key", RETRY)
        self.script = list(script)
        self.requests: list[CompletionRequest] = []

    def _send(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr(base.time, "sleep", recorded.append)
    return recorded


def test_rate_limit_is_retried_honouring_retry_after(sleeps):
    client = FakeClient([RateLimitError("slow down", retry_after=7), CompletionResult("ok")])
    assert client.complete(CompletionRequest("s", "u")).text == "ok"
    assert sleeps == [7]


def test_backoff_doubles_without_retry_after(sleeps):
    client = FakeClient([TransientModelError("x"), TransientModelError("x"), CompletionResult("ok")])
    client.complete(CompletionRequest("s", "u"))
    assert sleeps == [1, 2]


def test_gives_up_after_max_attempts(sleeps):
    client = FakeClient([TransientModelError("x")] * 3)
    with pytest.raises(TransientModelError):
        client.complete(CompletionRequest("s", "u"))
    assert len(client.requests) == 3


def test_wait_beyond_limit_fails_without_sleeping(sleeps):
    client = FakeClient([RateLimitError("daily quota", retry_after=3600)])
    with pytest.raises(RateLimitError):
        client.complete(CompletionRequest("s", "u"))
    assert sleeps == []


def test_permanent_error_is_not_retried(sleeps):
    client = FakeClient([ModelError("bad request")])
    with pytest.raises(ModelError):
        client.complete(CompletionRequest("s", "u"))
    assert len(client.requests) == 1


def test_invalid_json_is_repaired_once():
    client = FakeClient([CompletionResult("not json"), CompletionResult('{"value": 3}')])
    assert client.complete_structured("s", "u", Answer).value == 3
    assert "rejected" in client.requests[1].user


def test_schema_mismatch_is_repaired_once():
    client = FakeClient([CompletionResult('{"value": "x"}'), CompletionResult('{"value": 3}')])
    assert client.complete_structured("s", "u", Answer).value == 3


def test_provider_json_rejection_is_repaired_once():
    client = FakeClient([InvalidOutputError("rejected"), CompletionResult('{"value": 3}')])
    assert client.complete_structured("s", "u", Answer).value == 3


def test_structured_call_gives_up_after_repair():
    client = FakeClient([CompletionResult("no"), CompletionResult("still no")])
    with pytest.raises(InvalidOutputError, match="no valid Answer"):
        client.complete_structured("s", "u", Answer)


def test_truncated_reply_fails_without_a_pointless_repair():
    client = FakeClient([CompletionResult('{"value":', finish_reason="length")])
    with pytest.raises(TruncatedOutputError, match="max_output_tokens"):
        client.complete_structured("s", "u", Answer)
    assert len(client.requests) == 1


def test_structured_call_puts_schema_in_system_prompt():
    client = FakeClient([CompletionResult('{"value": 1}')])
    client.complete_structured("s", "u", Answer)
    assert "value" in client.requests[0].system
    assert client.requests[0].json_mode


def test_usage_counts_every_completed_call():
    client = FakeClient([CompletionResult("no", 10, 2), CompletionResult('{"value": 1}', 12, 3)])
    client.complete_structured("s", "u", Answer)
    assert (client.usage.input_tokens, client.usage.output_tokens, client.usage.calls) == (22, 5, 2)


@pytest.mark.parametrize(
    "text",
    ['{"value": 1}', '```json\n{"value": 1}\n```', '<think>{no}</think>{"value": 1}', 'Sure: {"value": 1}'],
)
def test_extract_json_handles_wrapped_replies(text):
    assert Answer.model_validate_json(extract_json(text)).value == 1


def test_register_adapter_adds_to_registry():
    @register_adapter("test_adapter")
    class Adapter(FakeClient):
        pass

    assert ADAPTERS.pop("test_adapter") is Adapter


def client_with(handler) -> OpenAICompatibleClient:
    client = OpenAICompatibleClient(ROLE, PROVIDER, "key", RETRY)
    client._http = httpx.Client(
        base_url="https://example.test/v1/", transport=httpx.MockTransport(handler)
    )
    return client


def test_adapter_parses_a_completion():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 1},
            },
        )

    result = client_with(handler)._send(CompletionRequest("s", "u"))
    assert (result.text, result.input_tokens, result.output_tokens) == ("hi", 5, 1)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx.Response(429, headers={"retry-after": "9"}), RateLimitError),
        (httpx.Response(503, text="down"), TransientModelError),
        (httpx.Response(401, text="bad key"), ModelError),
        (httpx.Response(400, json={"error": {"code": "json_validate_failed"}}), InvalidOutputError),
        (httpx.Response(200, json={"choices": [{"message": {}, "finish_reason": "length"}]}), TruncatedOutputError),
        (httpx.Response(200, json={"choices": [{"message": {}, "finish_reason": "stop"}]}), InvalidOutputError),
        (httpx.Response(200, json={"error": "odd"}), ModelError),
    ],
)
def test_adapter_maps_failures(response, expected):
    with pytest.raises(expected):
        client_with(lambda request: response)._send(CompletionRequest("s", "u"))


def test_adapter_reads_retry_after_header():
    response = httpx.Response(429, headers={"retry-after": "9"})
    with pytest.raises(RateLimitError) as caught:
        client_with(lambda request: response)._send(CompletionRequest("s", "u"))
    assert caught.value.retry_after == 9


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"details": [{"retryDelay": "56020s"}]}', 56020),
        ("Quota exceeded. Please retry in 15h33m40.5s.", 56020.5),
        ("Rate limit reached. Please try again in 7.66s.", 7.66),
        ("Please try again in 2m30s.", 150),
        ("slow down", None),
    ],
)
def test_adapter_reads_wait_time_from_error_body(body, expected):
    with pytest.raises(RateLimitError) as caught:
        client_with(lambda request: httpx.Response(429, text=body))._send(CompletionRequest("s", "u"))
    assert caught.value.retry_after == pytest.approx(expected) if expected else caught.value.retry_after is None


def test_daily_quota_in_error_body_is_not_retried(sleeps):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, text="Quota exceeded. Please retry in 15h33m40s.")

    with pytest.raises(RateLimitError):
        client_with(handler).complete(CompletionRequest("s", "u"))
    assert len(calls) == 1
    assert sleeps == []


def test_adapter_treats_transport_errors_as_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    with pytest.raises(TransientModelError):
        client_with(handler)._send(CompletionRequest("s", "u"))


def test_adapter_sends_role_extra_params():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    client = client_with(handler)
    client.role = ROLE.model_copy(update={"extra_params": {"reasoning_effort": "low"}})
    client._send(CompletionRequest("s", "u"))
    assert b'"reasoning_effort":"low"' in seen["body"].replace(b" ", b"")


def test_adapter_honours_custom_max_tokens_param():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    client = client_with(handler)
    client.provider = PROVIDER.model_copy(update={"max_tokens_param": "max_completion_tokens"})
    client._send(CompletionRequest("s", "u"))
    assert b"max_completion_tokens" in seen["body"]


def test_extract_json_skips_echoed_schema_and_reasoning():
    from vulnscan.models.base import extract_json

    reply = '{"properties": {"status": {}}} let me answer <thought>use ok</thought>{"status": "ok"}'
    assert extract_json(reply) == '{"status": "ok"}'
    assert extract_json('<think>{x}</think>```json\n{"a": {"b": 1}}\n```') == '{"a": {"b": 1}}'
