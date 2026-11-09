"""Adapter for any API that speaks the OpenAI chat completions format."""

import re

import httpx

from vulnscan.config import ProviderSettings, RetrySettings, RoleSettings
from vulnscan.models.base import (
    MAX_ERROR_CHARS,
    TRUNCATED_FINISH_REASON,
    CompletionRequest,
    CompletionResult,
    InvalidOutputError,
    ModelClient,
    ModelError,
    RateLimitError,
    TransientModelError,
    TruncatedOutputError,
    register_adapter,
)

JSON_REJECTED_CODE = "json_validate_failed"  # Groq's 400 when JSON mode output fails to parse
_RETRY_DELAY_FIELD = re.compile(r'"retryDelay":\s*"([\d.]+)s"')
_RETRY_DELAY_TEXT = re.compile(
    r"(?:retry|try again) in (?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", re.IGNORECASE
)


@register_adapter("openai_compatible")
class OpenAICompatibleClient(ModelClient):
    def __init__(
        self,
        role: RoleSettings,
        provider: ProviderSettings,
        api_key: str | None,
        retry: RetrySettings,
    ) -> None:
        super().__init__(role, provider, api_key, retry)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = httpx.Client(
            base_url=provider.base_url.rstrip("/") + "/",
            headers=headers,
            timeout=provider.timeout_seconds,
        )

    def _send(self, request: CompletionRequest) -> CompletionResult:
        payload: dict = {
            "model": self.role.model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            self.provider.max_tokens_param: self.role.max_output_tokens,
        }
        if self.role.temperature is not None:
            payload["temperature"] = self.role.temperature
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        payload |= self.role.extra_params

        body = self._request("POST", "chat/completions", json=payload).json()
        try:
            choice = body["choices"][0]
        except (KeyError, IndexError) as error:
            raise ModelError(f"unexpected response shape: {str(body)[:MAX_ERROR_CHARS]}") from error

        finish_reason = choice.get("finish_reason")
        text = (choice.get("message") or {}).get("content")
        if not text and finish_reason == TRUNCATED_FINISH_REASON:
            # Reasoning models can spend the whole output budget before answering.
            raise TruncatedOutputError(
                f"{self.role.model} used all {self.role.max_output_tokens} output tokens "
                "before answering; raise max_output_tokens or lower reasoning effort"
            )
        if not text:
            raise InvalidOutputError(f"empty reply (finish_reason={finish_reason})")

        usage = body.get("usage") or {}
        return CompletionResult(
            text=text,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            finish_reason=finish_reason,
        )

    def list_models(self) -> list[str]:
        body = self._request("GET", "models").json()
        return sorted(model["id"] for model in body.get("data", []))

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Send an HTTP request, mapping failures onto the ModelError hierarchy."""
        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.TransportError as error:
            raise TransientModelError(f"transport error: {error!r}") from error

        if response.is_success:
            return response

        detail = f"HTTP {response.status_code}: {response.text[:MAX_ERROR_CHARS]}"
        if response.status_code == 429:
            raise RateLimitError(detail, _retry_after(response))
        if response.status_code >= 500:
            raise TransientModelError(detail, _retry_after(response))
        if JSON_REJECTED_CODE in response.text:
            raise InvalidOutputError(detail)
        raise ModelError(detail)


def _retry_after(response: httpx.Response) -> float | None:
    """Find how long the provider asked us to wait, from the header or the error body."""
    try:
        return float(response.headers["retry-after"])
    except (KeyError, ValueError):
        pass  # absent, or the HTTP-date form

    if match := _RETRY_DELAY_FIELD.search(response.text):
        return float(match.group(1))
    if (match := _RETRY_DELAY_TEXT.search(response.text)) and any(match.groups()):
        hours, minutes, seconds = (float(group or 0) for group in match.groups())
        return hours * 3600 + minutes * 60 + seconds
    return None
