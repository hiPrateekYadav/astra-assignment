"""Model layer. Callers use create_client and never name a provider."""

import os

from vulnscan.config import ConfigError, Settings
from vulnscan.models import anthropic_messages, openai_compatible  # noqa: F401  register the adapters
from vulnscan.models.base import ADAPTERS, ModelClient, register_adapter

__all__ = ["ModelClient", "create_client", "register_adapter"]


def create_client(role_name: str, settings: Settings) -> ModelClient:
    """Build the client configured for a role such as 'teacher' or 'student'."""
    try:
        role = settings.roles[role_name]
    except KeyError:
        raise ConfigError(f"unknown role '{role_name}'") from None

    provider = settings.providers[role.provider]
    try:
        adapter = ADAPTERS[provider.adapter]
    except KeyError:
        known = ", ".join(sorted(ADAPTERS))
        raise ConfigError(f"unknown adapter '{provider.adapter}' (known: {known})") from None

    api_key = None
    if provider.api_key_env:
        api_key = os.environ.get(provider.api_key_env)
        if not api_key:
            raise ConfigError(f"{provider.api_key_env} is not set; add it to .env")

    return adapter(role, provider, api_key, settings.retry)
