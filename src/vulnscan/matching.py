"""Decide whether a finding counts as a hit on a reference item (ground truth or teacher findings).
Pairing is one-to-one, so one finding never earns two hits and duplicates cannot pad recall."""

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel

from vulnscan.config import MatchSettings
from vulnscan.ingest import SourceFile
from vulnscan.scan import normalize_code
from vulnscan.schemas import Finding

FROZEN_FILE = "FROZEN.sha256"


class GroundTruthError(Exception):
    """The ground-truth file is unreadable or has changed since it was frozen."""


class GroundTruthEntry(BaseModel):
    id: int
    title: str
    files: list[str]
    types: list[str]
    anchors: list[str] = []


class GroundTruth(BaseModel):
    entries: list[GroundTruthEntry]


@dataclass(frozen=True)
class ReferenceItem:
    id: str
    label: str
    matches: Callable[[Finding], bool]


def _check_frozen(path: Path) -> None:
    """Refuse a ground truth whose hash no longer matches the one recorded beside it."""
    frozen = path.parent / FROZEN_FILE
    if not frozen.is_file():
        return
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    for line in frozen.read_text(encoding="utf-8").splitlines():
        expected, _, name = line.partition("  ")
        if Path(name.strip()).name == path.name and expected != actual:
            raise GroundTruthError(f"{path.name} changed after it was frozen (see {frozen})")


def load_ground_truth(path: Path) -> GroundTruth:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise GroundTruthError(f"cannot read ground truth: {error}") from error
    _check_frozen(path)
    return GroundTruth.model_validate(raw)


def path_matches(reported: str, expected: str) -> bool:
    return reported == expected or reported.endswith(f"/{expected}")


def anchor_context(finding: Finding, files: Mapping[str, SourceFile], window: int) -> str:
    """The evidence plus the code around its verified location, so short quotes are not penalised."""
    file = files.get(finding.file)
    if not window or file is None or not finding.evidence_verified or finding.line is None:
        return finding.evidence
    nearby = (line for number, line in file.lines if abs(number - finding.line) <= window)
    return "\n".join((finding.evidence, *nearby))


def matches_entry(finding: Finding, entry: GroundTruthEntry, settings: MatchSettings, context: str) -> bool:
    """Right file, an accepted type and, when required, an anchor at the reported code.
    Titles and rationales are never searched: a model can fill them with keywords."""
    if finding.type not in entry.types:
        return False
    if not any(path_matches(finding.file, expected) for expected in entry.files):
        return False
    if not settings.require_anchor or not entry.anchors:
        return True
    context = context.lower()
    return any(anchor.lower() in context for anchor in entry.anchors)


def matches_finding(candidate: Finding, reference: Finding, settings: MatchSettings) -> bool:
    """Same file and type, and either nearby lines or overlapping quoted code."""
    if candidate.file != reference.file or candidate.type != reference.type:
        return False
    if candidate.line is not None and reference.line is not None:
        if abs(candidate.line - reference.line) <= settings.line_window:
            return True
    ours, theirs = normalize_code(candidate.evidence), normalize_code(reference.evidence)
    return bool(ours and theirs) and (ours in theirs or theirs in ours)


def reference_from_ground_truth(
    truth: GroundTruth, settings: MatchSettings, files: Mapping[str, SourceFile] | None = None
) -> list[ReferenceItem]:
    files = files or {}

    def predicate(entry: GroundTruthEntry) -> Callable[[Finding], bool]:
        def matches(finding: Finding) -> bool:
            context = anchor_context(finding, files, settings.anchor_window_lines)
            return matches_entry(finding, entry, settings, context)
        return matches

    return [ReferenceItem(str(entry.id), entry.title, predicate(entry)) for entry in truth.entries]


def reference_from_findings(findings: Sequence[Finding], settings: MatchSettings) -> list[ReferenceItem]:
    return [
        ReferenceItem(
            id=f"{finding.file}:{finding.line}:{finding.type}",
            label=finding.title,
            matches=lambda candidate, finding=finding: matches_finding(candidate, finding, settings),
        )
        for finding in findings
    ]


def assign(findings: Sequence[Finding], reference: Sequence[ReferenceItem]) -> dict[int, int]:
    """Pair findings with reference items one-to-one, maximising pairs (Kuhn's algorithm).
    Returns {reference index: finding index}."""
    edges = [
        [index for index, finding in enumerate(findings) if item.matches(finding)]
        for item in reference
    ]
    owner: dict[int, int] = {}  # finding index -> reference index

    def augment(item: int, visited: set[int]) -> bool:
        for finding in edges[item]:
            if finding in visited:
                continue
            visited.add(finding)
            if finding not in owner or augment(owner[finding], visited):
                owner[finding] = item
                return True
        return False

    for item in range(len(reference)):
        augment(item, set())
    return {item: finding for finding, item in owner.items()}
