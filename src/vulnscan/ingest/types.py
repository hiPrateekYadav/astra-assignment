"""Data passed from ingest to the rest of the pipeline."""

from dataclasses import dataclass, field
from enum import StrEnum

from vulnscan.ingest.manifest import ManifestInfo

CHARS_PER_TOKEN = 4  # rough, good enough for budgeting prompts


class IngestError(Exception):
    """The input cannot be loaded as a decompiled Android app."""


class FileKind(StrEnum):
    MANIFEST = "manifest"
    CODE = "code"
    STRINGS = "strings"
    XML_CONFIG = "xml_config"
    ASSET = "asset"
    LIBRARIES = "libraries"


@dataclass(frozen=True)
class SourceFile:
    """A scan unit with a logical path (com/acme/Foo.java); lines keep their original numbers."""

    path: str
    kind: FileKind
    lines: tuple[tuple[int, str], ...]

    @property
    def text(self) -> str:
        return "\n".join(line for _, line in self.lines)

    @property
    def numbered_text(self) -> str:
        return "\n".join(f"{number}: {line}" for number, line in self.lines)


@dataclass(frozen=True)
class Library:
    name: str
    version: str | None
    source: str


@dataclass
class IngestStats:
    source_files_total: int = 0
    first_party_files: int = 0
    generated_files_skipped: int = 0
    unattributed_files: int = 0  # outside the app's packages and every known library; not scanned
    used_fallback: bool = False
    code_chars_before_cleaning: int = 0
    code_chars_after_cleaning: int = 0
    total_chars: int = 0

    @property
    def estimated_tokens(self) -> int:
        return self.total_chars // CHARS_PER_TOKEN


@dataclass
class AppBundle:
    package: str
    manifest: ManifestInfo
    first_party_roots: tuple[str, ...]
    files: list[SourceFile] = field(default_factory=list)
    libraries: list[Library] = field(default_factory=list)
    stats: IngestStats = field(default_factory=IngestStats)
