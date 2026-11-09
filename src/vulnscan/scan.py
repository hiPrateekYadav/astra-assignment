"""Run one model over an app and return grounded, structured findings."""

import logging
import re
from bisect import bisect_right
from collections.abc import Sequence

from vulnscan.cache import ResponseCache
from vulnscan.chunking import Chunk, build_chunks, select_files
from vulnscan.config import ScanSettings
from vulnscan.ingest import AppBundle, FileKind, SourceFile
from vulnscan.ingest.types import CHARS_PER_TOKEN
from vulnscan.models import ModelClient
from vulnscan.models.base import ModelError, RateLimitError
from vulnscan.prompts import scan_system_prompt, scan_user_prompt
from vulnscan.schemas import (
    ChunkFailure,
    DroppedFinding,
    Finding,
    ModelFinding,
    ScanReport,
    ScanResponse,
)
from vulnscan.taxonomy import OTHER_TYPE, Taxonomy

logger = logging.getLogger(__name__)

MIN_EVIDENCE_CHARS = 8  # shorter quotes match too much code to prove anything
_LINE_NUMBER_PREFIX = re.compile(r"^\s*\d+:\s?")
_DIGEST_ATTRIBUTE = re.compile(r"(\w+)=(\w+)")
MANIFEST_PATH = "AndroidManifest.xml"
CONTEXT_TAG = "app_context"


def normalize_code(text: str) -> str:
    """Compare code ignoring layout and case, which models often change when quoting."""
    return re.sub(r"\s+", "", text).lower()


def _evidence_lines(evidence: str) -> list[str]:
    lines = (_LINE_NUMBER_PREFIX.sub("", line) for line in evidence.splitlines())
    return [line for line in map(normalize_code, lines) if len(line) >= MIN_EVIDENCE_CHARS]


def locate_evidence(evidence: str, file: SourceFile) -> int | None:
    """Return the original line where the quote starts, or None if it is not in the file.
    Matching ignores only layout and case, so invented code cannot pass."""
    quotes = _evidence_lines(evidence)
    if file.kind is FileKind.MANIFEST:
        # The digest writes flag=value where the manifest has flag="value".
        quotes += [normalize_code(f'{key}="{value}"') for key, value in _DIGEST_ATTRIBUTE.findall(evidence)]

    offsets: list[int] = []
    numbers: list[int] = []
    joined = ""
    for number, line in file.lines:
        offsets.append(len(joined))
        numbers.append(number)
        joined += normalize_code(line)

    for quote in quotes:
        position = joined.find(quote)
        if position >= 0:
            return numbers[bisect_right(offsets, position) - 1]
    return None


def resolve_path(reported: str, paths: dict[str, SourceFile]) -> SourceFile | None:
    """Accept an exact path, a unique suffix, or the digest tag, which means the manifest."""
    cleaned = reported.strip().lstrip("./")
    if cleaned.strip("<>") == CONTEXT_TAG:
        cleaned = MANIFEST_PATH
    if cleaned in paths:
        return paths[cleaned]
    candidates = [path for path in paths if path.endswith(f"/{cleaned}")]
    return paths[candidates[0]] if len(candidates) == 1 else None


class _FindingProcessor:
    """Checks model output against the app. Applied equally to every model."""

    def __init__(self, bundle: AppBundle, taxonomy: Taxonomy, settings: ScanSettings) -> None:
        self.paths = {file.path: file for file in bundle.files}
        self.digest = normalize_code(bundle.manifest.digest())
        self.taxonomy_ids = taxonomy.ids
        self.settings = settings
        self.seen: set[tuple] = set()

    def _in_digest(self, finding: ModelFinding, file: SourceFile) -> bool:
        """Models may fairly quote the manifest summary when reporting on the manifest."""
        if file.path != MANIFEST_PATH:
            return False
        return any(quote in self.digest for quote in _evidence_lines(finding.evidence))

    def process(self, raw: ModelFinding, chunk_id: str, report: ScanReport) -> None:
        file = resolve_path(raw.file, self.paths)
        if file is None:
            report.dropped.append(DroppedFinding(reason="unknown_file", chunk_id=chunk_id, finding=raw))
            return

        line = locate_evidence(raw.evidence, file)
        verified = line is not None or self._in_digest(raw, file)
        if not verified and self.settings.require_verified_evidence:
            report.dropped.append(
                DroppedFinding(reason="unverified_evidence", chunk_id=chunk_id, finding=raw)
            )
            return

        finding_type = raw.type
        if finding_type not in self.taxonomy_ids:
            finding_type = OTHER_TYPE
            report.retyped_as_other += 1

        key = (file.path, finding_type, line if line is not None else normalize_code(raw.evidence))
        if key in self.seen:
            report.duplicates_removed += 1
            return
        self.seen.add(key)

        report.findings.append(
            Finding(
                **raw.model_dump(exclude={"type", "file", "line"}),
                type=finding_type,
                file=file.path,
                line=line if line is not None else raw.line,
                evidence_verified=verified,
                chunk_id=chunk_id,
            )
        )


def _scoped_digest(bundle: AppBundle, chunk: Chunk) -> str:
    """The digest with only the components whose classes are in this chunk."""
    classes = {
        file.path.removesuffix(".java").replace("/", ".")
        for file in chunk.files
        if file.kind is FileKind.CODE
    }
    return bundle.manifest.digest(only_classes=classes)


def run_scan(
    bundle: AppBundle,
    client: ModelClient,
    role: str,
    settings: ScanSettings,
    taxonomy: Taxonomy,
    cache: ResponseCache,
    lessons: Sequence[str] = (),
    repeat: int = 0,
) -> ScanReport:
    """Scan every chunk, recording a failed chunk rather than ending the run.
    repeat separates identical runs in the cache, so variance can be measured."""
    files, skipped = select_files(bundle, settings)
    chunks = build_chunks(files, settings, client.role.max_chunk_tokens)
    system = scan_system_prompt(taxonomy, lessons)
    digest = bundle.manifest.digest()
    scope_digest = len(digest) // CHARS_PER_TOKEN > settings.max_digest_tokens
    processor = _FindingProcessor(bundle, taxonomy, settings)
    report = ScanReport(
        package=bundle.package,
        role=role,
        model=client.role.model,
        repeat=repeat,
        lessons=list(lessons),
        chunks_total=len(chunks),
        skipped_files=skipped,
    )
    if skipped:
        logger.warning("Token budget left %d files unscanned", len(skipped))

    calls_before = client.usage.calls
    tokens_in_before = client.usage.input_tokens
    tokens_out_before = client.usage.output_tokens
    for index, chunk in enumerate(chunks, start=1):
        user = scan_user_prompt(chunk, _scoped_digest(bundle, chunk) if scope_digest else digest)
        key =[client.role.model, client.role.temperature, system, user, repeat]
        if client.role.extra_params:
            key.append(client.role.extra_params)  # these change the answer, so must not share entries
        response = cache.get(key, ScanResponse)
        if response is not None:
            report.usage.cached_chunks += 1
        else:
            logger.info("[%d/%d] %s: %s", index, len(chunks), role, ", ".join(chunk.paths)[:100])
            try:
                response = client.complete_structured(system, user, ScanResponse)
            except RateLimitError as error:
                # Retries are spent or the wait is too long, so more calls only burn
                # quota. Stop here; a rerun resumes from the cache.
                logger.error("Stopping scan, rate limited: %s", str(error)[:300])
                report.stopped_early = True
                report.failed_chunks += [
                    ChunkFailure(chunk_id=item.id, paths=item.paths, error="not attempted: rate limited")
                    for item in chunks[index - 1 :]
                ]
                break
            except ModelError as error:
                logger.error("%s failed: %s", chunk.id, str(error)[:300])
                report.failed_chunks.append(
                    ChunkFailure(chunk_id=chunk.id, paths=chunk.paths, error=str(error)[:500])
                )
                continue
            cache.put(key, response)
        for raw in response.findings:
            processor.process(raw, chunk.id, report)

    report.usage.calls = client.usage.calls - calls_before
    report.usage.input_tokens = client.usage.input_tokens - tokens_in_before
    report.usage.output_tokens = client.usage.output_tokens - tokens_out_before
    return report
