"""Typed settings loaded from config/config.yaml and .env."""

from pathlib import Path
from typing import Any, Self

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, model_validator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
REQUIRED_ROLES = ("teacher", "student")


class ConfigError(Exception):
    """The configuration or environment cannot support the requested run."""


class StrictModel(BaseModel):
    """Rejects unknown keys so that a config typo fails instead of being ignored."""

    model_config = ConfigDict(extra="forbid")


class AppSettings(StrictModel):
    path: Path
    ground_truth: Path | None = None


class ProviderSettings(StrictModel):
    adapter: str
    base_url: str
    api_key_env: str | None = None  # None for local servers that need no key
    timeout_seconds: float = Field(default=120, gt=0)
    max_tokens_param: str = "max_tokens"


class RoleSettings(StrictModel):
    provider: str
    model: str
    temperature: float | None = 0  # None omits it for models that reject the parameter
    max_output_tokens: int = Field(default=4096, gt=0)
    max_chunk_tokens: int | None = Field(default=None, gt=0)  # overrides scan.max_chunk_tokens
    extra_params: dict[str, Any] = {}  # sent as-is, e.g. reasoning_effort


class RetrySettings(StrictModel):
    max_attempts: int = Field(default=5, ge=1)
    base_delay_seconds: float = Field(default=2, ge=0)
    max_delay_seconds: float = Field(default=120, ge=0)


class IngestSettings(StrictModel):
    jadx_command: str = "jadx"
    jadx_timeout_seconds: float = Field(default=900, gt=0)
    decompiled_dir: Path = Path("data/runs/decompiled")
    first_party_prefixes: list[str] = []
    library_prefixes: list[str] = []
    generated_patterns: list[str] = []
    library_string_prefixes: list[str] = []
    library_resource_patterns: list[str] = []
    text_asset_suffixes: list[str] = []
    max_asset_bytes: int = Field(default=100_000, gt=0)


class ScanSettings(StrictModel):
    taxonomy: Path = Path("config/taxonomy.yaml")
    output_dir: Path = Path("data/runs")
    max_chunk_tokens: int = Field(default=4000, gt=0)
    overlap_lines: int = Field(default=20, ge=0)
    max_total_tokens: int = Field(default=200_000, gt=0)
    require_verified_evidence: bool = True
    priority_patterns: list[str] = []
    max_failed_chunk_ratio: float = Field(default=0.1, ge=0, le=1)  # share that may fail in a scored run
    max_digest_tokens: int = Field(default=1500, gt=0)  # above this, chunks get a digest scoped to their code


class MatchSettings(StrictModel):
    line_window: int = Field(default=15, ge=0)  # finding-vs-finding: lines apart that still match
    require_anchor: bool = True  # ground truth: an anchor token must appear at the reported code
    anchor_window_lines: int = Field(default=8, ge=0)  # code around the verified line; 0 = evidence only


class LessonSettings(StrictModel):
    max_lessons: int = Field(default=15, gt=0)
    reject_app_specific: bool = True  # drop lessons that name the app's classes, packages or literals


class Settings(StrictModel):
    app: AppSettings
    ingest: IngestSettings = IngestSettings()
    scan: ScanSettings = ScanSettings()
    match: MatchSettings = MatchSettings()
    lessons: LessonSettings = LessonSettings()
    providers: dict[str, ProviderSettings]
    roles: dict[str, RoleSettings]
    retry: RetrySettings = RetrySettings()

    @model_validator(mode="after")
    def check_roles(self) -> Self:
        missing = [name for name in REQUIRED_ROLES if name not in self.roles]
        if missing:
            raise ValueError(f"missing roles: {', '.join(missing)}")
        for name, role in self.roles.items():
            if role.provider not in self.providers:
                raise ValueError(f"role '{name}' uses unknown provider '{role.provider}'")
        return self


def _from_project_root(path: Path) -> Path:
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_settings(
    config_path: Path = DEFAULT_CONFIG_PATH,
    app_path: Path | None = None,
    ground_truth: Path | None = None,
) -> Settings:
    """Load settings and .env. Path overrides are relative to the working directory."""
    load_dotenv(PROJECT_ROOT / ".env")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigError(f"cannot read config: {error}") from error

    settings = Settings.model_validate(raw)
    settings.app.path = app_path.resolve() if app_path else _from_project_root(settings.app.path)
    if ground_truth:
        settings.app.ground_truth = ground_truth.resolve()
    elif settings.app.ground_truth:
        settings.app.ground_truth = _from_project_root(settings.app.ground_truth)
    settings.ingest.decompiled_dir = _from_project_root(settings.ingest.decompiled_dir)
    settings.scan.taxonomy = _from_project_root(settings.scan.taxonomy)
    settings.scan.output_dir = _from_project_root(settings.scan.output_dir)
    return settings
