"""Provider-neutral model interface. Adapters implement only _send."""

import json
import logging
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from vulnscan.config import ProviderSettings, RetrySettings, RoleSettings

logger = logging.getLogger(__name__)

SchemaT = TypeVar("SchemaT", bound=BaseModel)
ClientT = TypeVar("ClientT", bound="ModelClient")

MAX_STRUCTURED_ATTEMPTS = 2  # the first reply plus one repair
MAX_ERROR_CHARS = 500
TRUNCATED_FINISH_REASON = "length"


class ModelError(Exception):
    """A provider call failed and retrying will not help."""


class TransientModelError(ModelError):
    """A provider call failed in a way that may succeed on retry."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RateLimitError(TransientModelError):
    """The provider returned HTTP 429."""


class InvalidOutputError(ModelError):
    """The model replied, but not with usable output for the requested schema."""


class TruncatedOutputError(ModelError):
    """The reply hit the output limit. Repeating the request would only be cut off again."""


@dataclass(frozen=True)
class CompletionRequest:
    system: str
    user: str
    json_mode: bool = False


@dataclass(frozen=True)
class CompletionResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str | None = None


@dataclass
class TokenUsage:
    """Running totals for a client, including attempts that failed validation."""

    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def add(self, result: CompletionResult) -> None:
        self.input_tokens += result.input_tokens
        self.output_tokens += result.output_tokens
        self.calls += 1


class ModelClient(ABC):
    def __init__(
        self,
        role: RoleSettings,
        provider: ProviderSettings,
        api_key: str | None,
        retry: RetrySettings,
    ) -> None:
        self.role = role
        self.provider = provider
        self.api_key = api_key
        self.retry = retry
        self.usage = TokenUsage()

    @abstractmethod
    def _send(self, request: CompletionRequest) -> CompletionResult:
        """Make one provider call. Raise RateLimitError or TransientModelError if a retry may help,
        InvalidOutputError for unusable replies, and ModelError otherwise."""

    def list_models(self) -> list[str]:
        """Return model IDs the provider offers, if it can list them."""
        return []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        """Call the provider, backing off on transient failures."""
        attempt = 1
        while True:
            try:
                result = self._send(request)
            except TransientModelError as error:
                delay = error.retry_after or self.retry.base_delay_seconds * 2 ** (attempt - 1)
                if attempt >= self.retry.max_attempts or delay > self.retry.max_delay_seconds:
                    raise
                logger.warning("%s: retrying in %.1fs (%s)", self.role.model, delay, error)
                time.sleep(delay)
                attempt += 1
            else:
                self.usage.add(result)
                return result

    def complete_structured(self, system: str, user: str, schema: type[SchemaT]) -> SchemaT:
        """Return a reply validated against schema, repairing invalid output once."""
        full_system = (
            f"{system}\n\nReply with a single JSON object and nothing else. "
            f"It must conform to this JSON schema:\n{json.dumps(schema.model_json_schema())}"
        )
        prompt = user
        for _ in range(MAX_STRUCTURED_ATTEMPTS):
            try:
                result = self.complete(CompletionRequest(full_system, prompt, json_mode=True))
                if result.finish_reason == TRUNCATED_FINISH_REASON:
                    raise TruncatedOutputError(
                        f"{self.role.model} reply was cut off; raise max_output_tokens "
                        f"(now {self.role.max_output_tokens}) or lower max_chunk_tokens"
                    )
                return schema.model_validate_json(extract_json(result.text))
            except (InvalidOutputError, ValidationError) as error:
                failure = str(error)[:MAX_ERROR_CHARS]
                logger.warning("%s: invalid structured output: %s", self.role.model, failure)
                prompt = (
                    f"{user}\n\nYour previous reply was rejected: {failure}\n"
                    "Reply again with only JSON that conforms to the schema."
                )
        raise InvalidOutputError(
            f"{self.role.model} gave no valid {schema.__name__} "
            f"in {MAX_STRUCTURED_ATTEMPTS} attempts: {failure}"
        )


_REASONING_TAGS = re.compile(r"<(think|thinking|thought)>.*?</\1>", flags=re.DOTALL)


def extract_json(text: str) -> str:
    """Isolate the JSON object from reasoning tags, code fences or surrounding prose.
    If the outermost braces do not parse, the last complete top-level object is the answer."""
    text = _REASONING_TAGS.sub("", text)
    start, end = text.find("{"), text.rfind("}")
    if not 0 <= start < end:
        return text
    candidate = text[start : end + 1]
    try:
        json.loads(candidate)
        return candidate
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    last, position = None, start
    while (position := text.find("{", position)) != -1:
        try:
            _, stop = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            position += 1
            continue
        last, position = text[position:stop], stop
    return last or candidate


ADAPTERS: dict[str, type[ModelClient]] = {}


def register_adapter(name: str) -> Callable[[type[ClientT]], type[ClientT]]:
    """Make an adapter class selectable through `adapter: <name>` in config."""

    def decorator(adapter: type[ClientT]) -> type[ClientT]:
        ADAPTERS[name] = adapter
        return adapter

    return decorator
