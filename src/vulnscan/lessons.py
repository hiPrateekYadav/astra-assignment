"""Turn the teacher's findings into general lessons in one call, rejecting any that name this app.
The ground truth is never shown: labels feeding the lessons would make the lift meaningless."""

import json
import re
from collections.abc import Sequence

from vulnscan.cache import ResponseCache
from vulnscan.config import LessonSettings, MatchSettings
from vulnscan.ingest import AppBundle, FileKind
from vulnscan.matching import assign, reference_from_findings
from vulnscan.models import ModelClient
from vulnscan.prompts import lesson_system_prompt, lesson_user_prompt
from vulnscan.schemas import Lesson, LessonReport, LessonResponse, RejectedLesson, ScanReport
from vulnscan.taxonomy import Taxonomy

MIN_TERM_CHARS = 4  # shorter names (R, Foo) collide with ordinary words
MIN_LITERAL_CHARS = 5
# Names an app shares with every Android app, so mentioning them is not specific.
GENERIC_NAMES = {"BuildConfig", "MainActivity", "Application", "Constants", "Utils", "Util"}
GENERIC_PACKAGE_SEGMENTS = {
    "com", "org", "net", "io", "app", "apps", "android", "mobile", "java", "kotlin",
    "main", "util", "utils", "data", "model", "ui", "core", "common", "base",
}
PLATFORM_LITERAL_PREFIXES = ("android.", "java.", "javax.", "kotlin.")
_QUOTED = re.compile(r'"([^"\n]{%d,})"' % MIN_LITERAL_CHARS)
_RESOURCE_NAME = re.compile(r'\bname="([^"]+)"')
# Patterns that are instance-specific whatever the app.
_SPECIFIC_PATTERNS = (
    re.compile(r"\b[\w$]+\.(?:java|kt|smali)\b"),
    re.compile(r"\blines?\s+\d+\b", re.IGNORECASE),
)


def _is_distinctive(term: str) -> bool:
    """Whether a key or literal is identifier-like (aws_pool_ID, s3cr3t) and so belongs to the app,
    rather than a plain word any lesson would use (webview, password)."""
    return bool(term) and not (term.isalpha() and term.islower())


def app_specific_terms(bundle: AppBundle, findings: Sequence) -> set[str]:
    """Names and literals that belong to this app rather than to Android."""
    terms: set[str] = set()
    for file in bundle.files:
        if file.kind is FileKind.CODE:
            terms.add(file.path.rsplit("/", 1)[-1].split(".")[0])
        elif file.kind is FileKind.STRINGS:
            terms.update(filter(_is_distinctive, _RESOURCE_NAME.findall(file.text)))
    for component in bundle.manifest.components:
        # Library components (a support FileProvider, say) are Android vocabulary, not the app's.
        if component.name.startswith(tuple(f"{root}." for root in bundle.first_party_roots)):
            terms.add(component.name.rsplit(".", 1)[-1])
    for package in (bundle.package, *bundle.first_party_roots):
        terms.update(package.split("."))
    for finding in findings:
        terms.update(
            literal.strip() for literal in _QUOTED.findall(finding.evidence)
            if not literal.startswith(PLATFORM_LITERAL_PREFIXES) and _is_distinctive(literal.strip())
        )
    return {
        term for term in terms
        if len(term) >= MIN_TERM_CHARS
        and term not in GENERIC_NAMES
        and term.lower() not in GENERIC_PACKAGE_SEGMENTS
    }


def find_specific_terms(lesson: Lesson, terms: set[str]) -> list[str]:
    """Return what makes a lesson instance-specific; empty means it is general."""
    text = f"{lesson.rule}\n{lesson.look_for}"
    found = [term for term in sorted(terms) if _mentions(text, term)]
    found += [match.group(0) for pattern in _SPECIFIC_PATTERNS for match in pattern.finditer(text)]
    return found


def _mentions(text: str, term: str) -> bool:
    """Whole-word match: lowercase terms ignore case, CamelCase class names match as written."""
    if not term.isidentifier():
        return term in text
    flags = re.IGNORECASE if term.islower() else 0
    return re.search(rf"(?<![\w$]){re.escape(term)}(?![\w$])", text, flags) is not None


def _findings_for_teacher(
    teacher: ScanReport, students: Sequence[ScanReport], settings: MatchSettings
) -> list[dict]:
    """Teacher findings, each marked with whether any student baseline run found it."""
    reference = reference_from_findings(teacher.findings, settings)
    caught: set[int] = set()
    for student in students:
        caught.update(assign(student.findings, reference))
    return [
        {
            "type": finding.type,
            "severity": finding.severity,
            "file": finding.file,
            "evidence": finding.evidence,
            "rationale": finding.rationale,
            "caught_by_reviewer": index in caught,
        }
        for index, finding in enumerate(teacher.findings)
    ]


def generate_lessons(
    bundle: AppBundle,
    teacher: ScanReport,
    students: Sequence[ScanReport],
    client: ModelClient,
    taxonomy: Taxonomy,
    cache: ResponseCache,
    lesson_settings: LessonSettings,
    match_settings: MatchSettings,
) -> LessonReport:
    findings = _findings_for_teacher(teacher, students, match_settings)
    system = lesson_system_prompt(taxonomy, lesson_settings.max_lessons)
    user = lesson_user_prompt(json.dumps(findings, indent=1))

    key = ["lessons", client.role.model, client.role.temperature, system, user]
    if client.role.extra_params:
        key.append(client.role.extra_params)
    calls_before, in_before, out_before = (
        client.usage.calls, client.usage.input_tokens, client.usage.output_tokens
    )
    response = cache.get(key, LessonResponse)
    cached = response is not None
    if response is None:
        response = client.complete_structured(system, user, LessonResponse)
        cache.put(key, response)

    report = LessonReport(
        package=bundle.package,
        model=client.role.model,
        findings_taught=len(findings),
        findings_missed_by_student=sum(not item["caught_by_reviewer"] for item in findings),
    )
    terms = app_specific_terms(bundle, teacher.findings)
    for lesson in response.lessons[: lesson_settings.max_lessons]:
        lesson = lesson.model_copy(update={"types": [t for t in lesson.types if t in taxonomy.ids]})
        leaks = find_specific_terms(lesson, terms)
        if leaks and lesson_settings.reject_app_specific:
            report.rejected.append(RejectedLesson(lesson=lesson, app_specific_terms=leaks))
        else:
            report.lessons.append(lesson)

    report.usage.cached_chunks = int(cached)
    report.usage.calls = client.usage.calls - calls_before
    report.usage.input_tokens = client.usage.input_tokens - in_before
    report.usage.output_tokens = client.usage.output_tokens - out_before
    return report
