"""Plan what to scan and split it into chunks that fit a model's context."""

import re
from dataclasses import dataclass

from vulnscan.config import ScanSettings
from vulnscan.ingest import AppBundle, FileKind, SourceFile
from vulnscan.ingest.types import CHARS_PER_TOKEN


@dataclass(frozen=True)
class Chunk:
    id: str
    files: tuple[SourceFile, ...]

    @property
    def paths(self) -> list[str]:
        return [file.path for file in self.files]

    def render(self) -> str:
        return "\n".join(
            f'<file path="{file.path}">\n{file.numbered_text}\n</file>' for file in self.files
        )


def _tokens(file: SourceFile) -> int:
    return len(file.numbered_text) // CHARS_PER_TOKEN


def _split(file: SourceFile, max_tokens: int, overlap_lines: int) -> list[SourceFile]:
    """Split an oversized file by lines, overlapping so a flaw at a seam is seen whole."""
    pieces: list[SourceFile] = []
    current: list[tuple[int, str]] = []
    size = 0
    for line in file.lines:
        line_tokens = (len(line[1]) + 8) // CHARS_PER_TOKEN + 1
        if current and size + line_tokens > max_tokens:
            pieces.append(SourceFile(file.path, file.kind, tuple(current)))
            current = current[-overlap_lines:] if overlap_lines else []
            size = sum((len(text) + 8) // CHARS_PER_TOKEN + 1 for _, text in current)
        current.append(line)
        size += line_tokens
    pieces.append(SourceFile(file.path, file.kind, tuple(current)))
    return pieces


def select_files(
    bundle: AppBundle, settings: ScanSettings
) -> tuple[list[SourceFile], list[str]]:
    """Apply the token budget, taking non-code files first and then the riskiest code.
    Returns the files to scan and the paths left out."""
    always = [file for file in bundle.files if file.kind is not FileKind.CODE]
    code = [file for file in bundle.files if file.kind is FileKind.CODE]
    patterns = [re.compile(pattern) for pattern in settings.priority_patterns]

    def risk(file: SourceFile) -> int:
        return sum(len(pattern.findall(file.text)) for pattern in patterns)

    budget = settings.max_total_tokens - sum(_tokens(file) for file in always)
    selected: list[SourceFile] = list(always)
    skipped: list[str] = []
    for file in sorted(code, key=lambda item: (-risk(item), item.path)):
        cost = _tokens(file)
        if cost <= budget:
            selected.append(file)
            budget -= cost
        else:
            skipped.append(file.path)
    return selected, sorted(skipped)


def build_chunks(
    files: list[SourceFile], settings: ScanSettings, max_chunk_tokens: int | None = None
) -> list[Chunk]:
    """Pack files in path order, which keeps related code side by side."""
    limit = max_chunk_tokens or settings.max_chunk_tokens
    pieces: list[SourceFile] = []
    for file in sorted(files, key=lambda item: item.path):
        if _tokens(file) > limit:
            pieces += _split(file, limit, settings.overlap_lines)
        else:
            pieces.append(file)

    groups: list[list[SourceFile]] = []
    size = 0
    for piece in pieces:
        if groups and size + _tokens(piece) <= limit:
            groups[-1].append(piece)
            size += _tokens(piece)
        else:
            groups.append([piece])
            size = _tokens(piece)

    return [Chunk(f"chunk-{index:03d}", tuple(group)) for index, group in enumerate(groups, start=1)]
