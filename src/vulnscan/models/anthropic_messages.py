"""Adapter for Claude, through the official Anthropic SDK."""

import anthropic

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

MAX_TOKENS_STOP_REASON = "max_tokens"
REFUSAL_STOP_REASON = "refusal"


def _retry_after(error: anthropic.APIStatusError) -> float | None:
    try:
        return float(error.response.headers["retry-after"])
    except (KeyError, ValueError):
        return None


@register_adapter("anthropic")
class AnthropicClient(ModelClient):
    """Claude over the Messages API. Temperature is not sent because current models reject it.
    Retries are left to ModelClient, so the SDK's own are off."""

    def __init__(
        self,
        role: RoleSettings,
        provider: ProviderSettings,
        api_key: str | None,
        retry: RetrySettings,
    ) -> None:
        super().__init__(role, provider, api_key, retry)
        self._client = anthropic.Anthropic(
            api_key=api_key,
            base_url=provider.base_url,
            timeout=provider.timeout_seconds,
            max_retries=0,
        )

    def _send(self, request: CompletionRequest) -> CompletionResult:
        params = dict(self.role.extra_params)
        # Beta features such as fallbacks are opted into per role through extra_params.
        messages = self._client.beta.messages if "betas" in params else self._client.messages
        try:
            with messages.stream(
                model=self.role.model,
                max_tokens=self.role.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                **params,
            ) as stream:
                message = stream.get_final_message()
        except anthropic.RateLimitError as error:
            raise RateLimitError(_detail(error), _retry_after(error)) from error
        except anthropic.APIStatusError as error:
            if error.status_code >= 500:
                raise TransientModelError(_detail(error), _retry_after(error)) from error
            raise ModelError(_detail(error)) from error
        except anthropic.APIConnectionError as error:
            raise TransientModelError(f"transport error: {error!r}") from error

        if message.stop_reason == REFUSAL_STOP_REASON:
            raise ModelError(f"{self.role.model} declined the request (stop_reason=refusal)")

        text = "".join(block.text for block in message.content if block.type == "text")
        truncated = message.stop_reason == MAX_TOKENS_STOP_REASON
        if not text and truncated:
            raise TruncatedOutputError(
                f"{self.role.model} used all {self.role.max_output_tokens} output tokens "
                "before answering; raise max_output_tokens"
            )
        if not text:
            raise InvalidOutputError(f"empty reply (stop_reason={message.stop_reason})")

        return CompletionResult(
            text=text,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
            finish_reason=TRUNCATED_FINISH_REASON if truncated else message.stop_reason,
        )

    def list_models(self) -> list[str]:
        try:
            return sorted(model.id for model in self._client.models.list())
        except anthropic.APIError as error:
            raise ModelError(f"cannot list models: {str(error)[:MAX_ERROR_CHARS]}") from error


def _detail(error: anthropic.APIStatusError) -> str:
    return f"HTTP {error.status_code}: {str(error)[:MAX_ERROR_CHARS]}"
