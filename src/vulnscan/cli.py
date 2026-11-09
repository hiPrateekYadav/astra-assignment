"""Command-line entry point."""

import argparse
import logging
import re
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ValidationError

from vulnscan.cache import ResponseCache
from vulnscan.config import DEFAULT_CONFIG_PATH, REQUIRED_ROLES, ConfigError, Settings, load_settings
from vulnscan.evaluate import compare, render_markdown
from vulnscan.ingest import AppBundle, FileKind, IngestError, load_app
from vulnscan.lessons import generate_lessons
from vulnscan.matching import (
    GroundTruthError,
    load_ground_truth,
    reference_from_findings,
    reference_from_ground_truth,
)
from vulnscan.models import create_client
from vulnscan.models.base import ModelError
from vulnscan.scan import run_scan
from vulnscan.schemas import LessonReport, ScanReport
from vulnscan.taxonomy import load_taxonomy


class PipelineError(Exception):
    """A step cannot run because an earlier step's output is missing or empty."""


class HealthCheck(BaseModel):
    status: str


def check_models(settings: Settings, show_all: bool) -> int:
    """Confirm each role's model is offered and can return structured output."""
    failures = 0
    for role_name in REQUIRED_ROLES:
        role = settings.roles[role_name]
        print(f"{role_name}: {role.provider} / {role.model}")
        try:
            client = create_client(role_name, settings)
            available = client.list_models()
            if show_all:
                print("\n".join(f"  {model_id}" for model_id in available))
            listed = any(model_id.endswith(role.model) for model_id in available)
            print(f"  listed by provider: {listed} ({len(available)} models)")
            reply = client.complete_structured(
                "You are a health check.", 'Set status to "ok".', HealthCheck
            )
            print(f"  structured call: {reply.status} ({client.usage.input_tokens} tokens in, "
                  f"{client.usage.output_tokens} out)")
        except (ConfigError, ModelError) as error:
            failures += 1
            print(f"  FAILED: {error}")
    return 1 if failures else 0


def ingest_app(settings: Settings, show_digest: bool) -> int:
    """Load the configured app and report what would be scanned."""
    try:
        bundle = load_app(settings.app.path, settings.ingest)
    except IngestError as error:
        print(f"Ingest failed: {error}", file=sys.stderr)
        return 1

    stats = bundle.stats
    counts = Counter(file.kind for file in bundle.files)
    print(f"package: {bundle.package}")
    print(f"first-party roots: {', '.join(bundle.first_party_roots)}")
    if stats.used_fallback:
        print("warning: no code found under those roots; used all non-library packages")
    print(f"code files: {stats.first_party_files} of {stats.source_files_total} "
          f"({stats.generated_files_skipped} generated skipped)")
    print("scan units: " + ", ".join(f"{counts[kind]} {kind}" for kind in FileKind if counts[kind]))
    if stats.unattributed_files:
        print(f"not scanned: {stats.unattributed_files} code files outside the app's packages and known "
              "libraries (add app code to ingest.first_party_prefixes)")
    print(f"libraries: {len(bundle.libraries)} "
          f"({sum(1 for library in bundle.libraries if library.version)} with versions)")
    print(f"code chars: {stats.code_chars_before_cleaning:,} -> "
          f"{stats.code_chars_after_cleaning:,} after cleaning")
    print(f"all scan units: {stats.total_chars:,} chars (~{stats.estimated_tokens:,} tokens)")
    if show_digest:
        print(f"\n{bundle.manifest.digest()}")
    return 0


def print_scan_summary(report: ScanReport, path: Path) -> None:
    usage = report.usage
    print(f"\n{report.role} ({report.model}), repeat {report.repeat}: {len(report.findings)} findings")
    for finding_type, count in Counter(f.type for f in report.findings).most_common():
        print(f"  {count:3} {finding_type}")
    reasons = Counter(item.reason for item in report.dropped)
    print(f"dropped: {dict(reasons) or 'none'}; duplicates removed: {report.duplicates_removed}; "
          f"retyped as other: {report.retyped_as_other}")
    print(f"chunks: {report.chunks_total} ({usage.cached_chunks} from cache, "
          f"{len(report.failed_chunks)} failed); skipped files: {len(report.skipped_files)}")
    print(f"tokens: {usage.input_tokens:,} in, {usage.output_tokens:,} out, {usage.calls} calls")
    if report.stopped_early:
        print("WARNING: the scan stopped on a rate limit. Rerun to resume from cache.")
    elif not report.complete:
        print(f"WARNING: partial coverage: {len(report.skipped_files)} files over scan.max_total_tokens, "
              f"{len(report.failed_chunks)} chunks failed.")
    for failure in report.failed_chunks[:1]:
        print(f"  first failure: {failure.error[:200]}")
    print(f"report: {path}")


BASELINE_LABEL = "baseline"
LESSONS_LABEL = "lessons"


def _run_dir(settings: Settings, bundle: AppBundle) -> Path:
    run_dir = settings.scan.output_dir / bundle.package
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _cache(settings: Settings, use_cache: bool) -> ResponseCache:
    return ResponseCache(settings.scan.output_dir / "cache", enabled=use_cache)


def _report_name(role: str, model: str, label: str, repeat: int) -> str:
    # The model is in the name so switching a role's model never mixes or overwrites runs.
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", model).strip("-")
    return f"{role}-{slug}-{label}-r{repeat}.json"


def _saved_reports(
    run_dir: Path, settings: Settings, role: str, label: str
) -> list[tuple[str, ScanReport]]:
    """Reports for the role's currently configured model only."""
    pattern = _report_name(role, settings.roles[role].model, label, 0).replace("-r0.json", "-r*.json")
    paths = sorted(run_dir.glob(pattern))
    return [(path.name, ScanReport.model_validate_json(path.read_text("utf-8"))) for path in paths]


def _usable_reports(
    reports: list[tuple[str, ScanReport]], settings: Settings
) -> list[tuple[str, ScanReport]]:
    return [item for item in reports if item[1].usable(settings.scan.max_failed_chunk_ratio)]


def _latest_lesson_runs(
    run_dir: Path, reports: list[tuple[str, ScanReport]]
) -> tuple[list[tuple[str, ScanReport]], list[str]]:
    """Keep the rescans that used the newest lessons, so two lesson sets are never averaged."""
    if not reports:
        return [], []
    newest = max(reports, key=lambda item: (run_dir / item[0]).stat().st_mtime)[1].lessons
    kept = [item for item in reports if item[1].lessons == newest]
    stale = [
        f"{name} used an older set of lessons and is excluded"
        for name, report in reports if report.lessons != newest
    ]
    return kept, stale


def _scan_and_write(
    bundle: AppBundle,
    settings: Settings,
    role: str,
    repeats: int,
    use_cache: bool,
    lessons: Sequence[str] = (),
) -> int:
    """Scan with one role, writing <role>-<baseline|lessons>-r<n>.json per repeat."""
    client = create_client(role, settings)
    taxonomy = load_taxonomy(settings.scan.taxonomy)
    label = LESSONS_LABEL if lessons else BASELINE_LABEL
    run_dir = _run_dir(settings, bundle)
    exit_code = 0
    for repeat in range(repeats):
        report = run_scan(
            bundle, client, role, settings.scan, taxonomy, _cache(settings, use_cache),
            lessons=lessons, repeat=repeat,
        )
        path = run_dir / _report_name(role, client.role.model, label, repeat)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print_scan_summary(report, path)
        exit_code = exit_code or (0 if report.usable(settings.scan.max_failed_chunk_ratio) else 1)
    return exit_code


def scan_app(
    settings: Settings, role: str, repeats: int, use_cache: bool, lessons_path: Path | None
) -> int:
    """Scan the app with one role, optionally applying a saved lesson file."""
    lessons: list[str] = []
    if lessons_path:
        lessons = LessonReport.model_validate_json(lessons_path.read_text("utf-8")).rendered
    bundle = load_app(settings.app.path, settings.ingest)
    return _scan_and_write(bundle, settings, role, repeats, use_cache, lessons)


def make_lessons(settings: Settings, bundle: AppBundle, use_cache: bool) -> LessonReport:
    """Have the teacher turn its baseline findings into lessons, in one call."""
    run_dir = _run_dir(settings, bundle)
    teachers = _usable_reports(_saved_reports(run_dir, settings, "teacher", BASELINE_LABEL), settings)
    # An unfinished baseline would mark findings as missed that were simply never scanned.
    students = _usable_reports(_saved_reports(run_dir, settings, "student", BASELINE_LABEL), settings)
    if not teachers:
        raise PipelineError(f"no finished teacher baseline in {run_dir}; run `scan --role teacher` first")
    teacher_name, teacher = teachers[0]

    report = generate_lessons(
        bundle,
        teacher,
        [student for _, student in students],
        create_client("teacher", settings),
        load_taxonomy(settings.scan.taxonomy),
        _cache(settings, use_cache),
        settings.lessons,
        settings.match,
    )
    report.teacher_report = teacher_name
    report.student_reports = [name for name, _ in students]
    path = run_dir / f"lessons-{settings.roles['student'].model.replace('/', '-')}.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    print(f"\nlessons from {report.findings_taught} teacher findings "
          f"({report.findings_missed_by_student} missed by the student baseline):")
    for lesson in report.lessons:
        print(f"  - {lesson.rule}")
    for rejected in report.rejected:
        print(f"  REJECTED (names {', '.join(rejected.app_specific_terms)}): {rejected.lesson.rule}")
    print(f"lessons: {path}")
    return report


def evaluate_runs(settings: Settings, bundle: AppBundle) -> int:
    """Score every saved report for the app and write results.json and results.md."""
    run_dir = _run_dir(settings, bundle)
    teacher = _saved_reports(run_dir, settings, "teacher", BASELINE_LABEL)
    if settings.app.ground_truth:
        reference = reference_from_ground_truth(
            load_ground_truth(settings.app.ground_truth),
            settings.match,
            {file.path: file for file in bundle.files},
        )
        reference_name = f"ground truth {settings.app.ground_truth.name}"
    elif finished := _usable_reports(teacher, settings):
        # No labels: the teacher's findings are the reference, so the teacher is not scored.
        name, report = finished[0]
        reference = reference_from_findings(report.findings, settings.match)
        reference_name = f"teacher findings in {name} (no ground truth configured)"
        teacher = []
    else:
        raise PipelineError("nothing to measure against: set app.ground_truth or finish the teacher scan")

    with_lessons, stale = _latest_lesson_runs(
        run_dir, _saved_reports(run_dir, settings, "student", LESSONS_LABEL)
    )
    comparison = compare(
        reference,
        reference_name,
        teacher,
        _saved_reports(run_dir, settings, "student", BASELINE_LABEL),
        with_lessons,
        settings.scan.max_failed_chunk_ratio,
        stale,
    )
    # Scores against labels and against the teacher answer different questions; keep both.
    stem = "results" if settings.app.ground_truth else "results-vs-teacher"
    stem += "-" + settings.roles["student"].model.replace("/", "-")
    markdown = render_markdown(comparison)
    (run_dir / f"{stem}.json").write_text(comparison.model_dump_json(indent=2), encoding="utf-8")
    (run_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    print(f"\n{markdown}\nresults: {run_dir / f'{stem}.md'}")
    return 0


def run_loop(settings: Settings, repeats: int, use_cache: bool) -> int:
    """Teacher scan, student baseline, lessons, student rescan, then measure."""
    bundle = load_app(settings.app.path, settings.ingest)

    def scan_or_stop(role: str, runs: int, lessons: Sequence[str] = ()) -> None:
        # Later steps would only burn quota on failures and score empty reports.
        if _scan_and_write(bundle, settings, role, runs, use_cache, lessons):
            raise PipelineError(
                f"{role} scan stopped early or too many chunks failed (see the report); "
                "rerun the same command to resume from cache"
            )

    scan_or_stop("teacher", 1)
    scan_or_stop("student", repeats)
    lessons = make_lessons(settings, bundle, use_cache)
    if not lessons.lessons:
        raise PipelineError("the teacher produced no usable lessons; see the lessons file in the run directory")
    scan_or_stop("student", repeats, lessons.rendered)
    return evaluate_runs(settings, bundle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnscan", description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--app", type=Path, help="decompiled app directory or .apk; overrides config")
    parser.add_argument("--ground-truth", type=Path, help="labelled vulnerabilities; overrides config")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-models", help="verify configured models respond")
    check.add_argument("--list", action="store_true", help="print every model each provider offers")

    ingest = commands.add_parser("ingest", help="load the app and report what would be scanned")
    ingest.add_argument("--digest", action="store_true", help="print the manifest digest")

    scan = commands.add_parser("scan", help="scan the app with one model")
    scan.add_argument("--role", choices=REQUIRED_ROLES, required=True)
    scan.add_argument("--repeat", type=int, default=1, help="independent runs, to measure variance")
    scan.add_argument("--lessons", type=Path, help="lessons.json to apply (writes *-lessons-r*.json)")
    scan.add_argument("--no-cache", action="store_true", help="ignore cached responses")

    lessons = commands.add_parser("lessons", help="teacher turns its findings into general lessons")
    lessons.add_argument("--no-cache", action="store_true", help="ignore cached responses")

    commands.add_parser("evaluate", help="score saved reports and measure the recall lift")

    loop = commands.add_parser("loop", help="teacher scan, student scan, lessons, rescan, evaluate")
    loop.add_argument("--repeat", type=int, default=1, help="student runs per side, to measure variance")
    loop.add_argument("--no-cache", action="store_true", help="ignore cached responses")
    return parser


def dispatch(args: argparse.Namespace, settings: Settings) -> int:
    if args.command == "check-models":
        return check_models(settings, args.list)
    if args.command == "ingest":
        return ingest_app(settings, args.digest)
    if args.command == "scan":
        return scan_app(settings, args.role, args.repeat, not args.no_cache, args.lessons)
    if args.command == "loop":
        return run_loop(settings, args.repeat, not args.no_cache)
    bundle = load_app(settings.app.path, settings.ingest)
    if args.command == "lessons":
        make_lessons(settings, bundle, not args.no_cache)
        return 0
    return evaluate_runs(settings, bundle)


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request logs add noise, not signal
    try:
        settings = load_settings(args.config, args.app, args.ground_truth)
    except (ConfigError, ValidationError) as error:
        print(f"Invalid configuration: {error}", file=sys.stderr)
        return 2
    try:
        return dispatch(args, settings)
    except (IngestError, ConfigError, ModelError, GroundTruthError, PipelineError) as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
