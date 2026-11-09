from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from vulnscan.config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, ConfigError, load_settings
from vulnscan.models import create_client


def write_config(tmp_path: Path, **overrides) -> Path:
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text()) | overrides
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_default_config_loads():
    settings = load_settings()
    assert settings.roles.keys() >= {"teacher", "student"}
    assert settings.app.path.is_absolute()


def test_app_override_replaces_configured_path(tmp_path):
    assert load_settings(app_path=tmp_path).app.path == tmp_path


def test_relative_app_path_resolves_from_project_root(tmp_path):
    settings = load_settings(write_config(tmp_path, app={"path": "some-app"}))
    assert settings.app.path == PROJECT_ROOT / "some-app"


def test_unknown_provider_is_rejected(tmp_path):
    roles = {
        "teacher": {"provider": "missing", "model": "m"},
        "student": {"provider": "groq", "model": "m"},
    }
    with pytest.raises(ValidationError, match="unknown provider 'missing'"):
        load_settings(write_config(tmp_path, roles=roles))


def test_missing_role_is_rejected(tmp_path):
    with pytest.raises(ValidationError, match="missing roles: student"):
        load_settings(write_config(tmp_path, roles={"teacher": {"provider": "groq", "model": "m"}}))


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ValidationError):
        load_settings(write_config(tmp_path, retries={"max_attempts": 1}))


def test_missing_api_key_fails_only_when_client_is_built(monkeypatch):
    settings = load_settings()
    env_name = settings.providers[settings.roles["student"].provider].api_key_env
    monkeypatch.delenv(env_name, raising=False)
    with pytest.raises(ConfigError, match=env_name):
        create_client("student", settings)


def test_unknown_adapter_is_rejected():
    settings = load_settings()
    settings.providers[settings.roles["student"].provider].adapter = "missing"
    with pytest.raises(ConfigError, match="unknown adapter"):
        create_client("student", settings)


def test_source_contains_no_app_specific_strings():
    offenders = [
        path
        for path in (PROJECT_ROOT / "src").rglob("*.py")
        if "insecureshop" in path.read_text().lower()
    ]
    assert offenders == []
