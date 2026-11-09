"""Score scan reports against a reference and measure the student's lift from lessons."""

from collections.abc import Sequence
from statistics import mean

from pydantic import BaseModel

from vulnscan.matching import ReferenceItem, assign
from vulnscan.schemas import ScanReport


class Score(BaseModel):
    report: str
    model: str
    repeat: int
    complete: bool
    findings: int
    matched_ids: list[str]
    recall: float
    precision: float  # findings that matched a reference item; unmatched are unlabelled, not wrong


class Summary(BaseModel):
    runs: int
    recall_mean: float
    recall_min: float
    recall_max: float
    findings_mean: float
    precision_mean: float


class Comparison(BaseModel):
    reference: str
    reference_size: int
    labels: dict[str, str]
    teacher: list[Score]
    baseline: list[Score]
    with_lessons: list[Score]
    baseline_summary: Summary | None
    lessons_summary: Summary | None
    teacher_summary: Summary | None
    lift: float | None
    hit_rates: dict[str, tuple[float | None, float | None]]  # id -> share of runs that found it
    lessons_used: int
    warnings: list[str]


def score(report: ScanReport, reference: Sequence[ReferenceItem], name: str) -> Score:
    pairs = assign(report.findings, reference)
    findings = len(report.findings)
    return Score(
        report=name,
        model=report.model,
        repeat=report.repeat,
        complete=report.complete,
        findings=findings,
        matched_ids=[reference[index].id for index in sorted(pairs)],
        recall=len(pairs) / len(reference) if reference else 0.0,
        precision=len(pairs) / findings if findings else 0.0,
    )


def summarize(scores: Sequence[Score]) -> Summary | None:
    if not scores:
        return None
    recalls = [item.recall for item in scores]
    return Summary(
        runs=len(scores),
        recall_mean=mean(recalls),
        recall_min=min(recalls),
        recall_max=max(recalls),
        findings_mean=mean(item.findings for item in scores),
        precision_mean=mean(item.precision for item in scores),
    )


def _hit_rate(item_id: str, scores: Sequence[Score]) -> float | None:
    if not scores:
        return None
    return sum(item_id in item.matched_ids for item in scores) / len(scores)


def compare(
    reference: Sequence[ReferenceItem],
    reference_name: str,
    teacher: Sequence[tuple[str, ScanReport]],
    baseline: Sequence[tuple[str, ScanReport]],
    with_lessons: Sequence[tuple[str, ScanReport]],
    max_failed_chunk_ratio: float = 0.1,
    notes: Sequence[str] = (),
) -> Comparison:
    warnings = list(notes)
    for name, report in (*teacher, *baseline, *with_lessons):
        if not report.usable(max_failed_chunk_ratio):
            warnings.append(f"{name} is unfinished or has too many failed chunks, so it is excluded; rerun to resume it from cache")
        elif not report.complete:
            warnings.append(
                f"{name} covers part of the app: {len(report.skipped_files)} files over the token budget, "
                f"{len(report.failed_chunks)} of {report.chunks_total} chunks failed"
            )

    def scores(reports: Sequence[tuple[str, ScanReport]]) -> list[Score]:
        # A run that stopped partway would fake a drop in recall.
        return [
            score(report, reference, name) for name, report in reports
            if report.usable(max_failed_chunk_ratio)
        ]

    teacher_scores = scores(teacher)
    baseline_scores = scores(baseline)
    lesson_scores = scores(with_lessons)
    before, after = summarize(baseline_scores), summarize(lesson_scores)

    lift = after.recall_mean - before.recall_mean if before and after else None
    if lift is not None and before.runs > 1 and after.runs > 1:
        spread = max(before.recall_max - before.recall_min, after.recall_max - after.recall_min)
        if abs(lift) <= spread:
            warnings.append(f"lift {lift * 100:+.1f} points is within run-to-run spread ({spread * 100:.1f} points): a signal, not proof; use more --repeat runs")
    elif lift is not None:
        warnings.append("one run per side; run-to-run variance is not measured (use --repeat)")
    if after and before and after.findings_mean > 1.5 * before.findings_mean:
        warnings.append("student reports many more findings with lessons; check precision")

    lessons_used = len(with_lessons[0][1].lessons) if with_lessons else 0  # same lessons in every run
    return Comparison(
        reference=reference_name,
        reference_size=len(reference),
        labels={item.id: item.label for item in reference},
        teacher=teacher_scores,
        baseline=baseline_scores,
        with_lessons=lesson_scores,
        teacher_summary=summarize(teacher_scores),
        baseline_summary=before,
        lessons_summary=after,
        lift=lift,
        hit_rates={
            item.id: (_hit_rate(item.id, baseline_scores), _hit_rate(item.id, lesson_scores))
            for item in reference
        },
        lessons_used=lessons_used,
        warnings=warnings,
    )


def _recall_row(name: str, summary: Summary | None, model: str) -> str:
    if summary is None:
        return f"| {name} | {model} | - | - |"
    spread = f"{summary.recall_min:.0%}–{summary.recall_max:.0%}" if summary.runs > 1 else "1 run"
    return f"| {name} | {model} | **{summary.recall_mean:.1%}** | {spread} |"


def _hits(rate: float | None, runs: int) -> str:
    return "-" if rate is None else f"{round(rate * runs)}/{runs}"


def render_markdown(comparison: Comparison) -> str:
    """A short report: three recall numbers, the lift, then one row per reference item."""

    def model_of(scores: list[Score]) -> str:
        return scores[0].model if scores else "-"

    before, after = comparison.baseline_summary, comparison.lessons_summary
    lines = [
        f"# Results vs {comparison.reference} ({comparison.reference_size} items)",
        "",
        "| | Model | Recall (average) | Range over runs |",
        "|---|---|---|---|",
        _recall_row("Teacher", comparison.teacher_summary, model_of(comparison.teacher)),
        _recall_row("Student before lessons", before, model_of(comparison.baseline)),
        _recall_row(f"Student after {comparison.lessons_used} lessons", after,
                    model_of(comparison.with_lessons)),
        "",
    ]
    if comparison.lift is not None:
        lines += [
            f"**Lift: {comparison.lift * 100:+.1f} points.** "
            f"Findings per run {before.findings_mean:.1f} → {after.findings_mean:.1f}; "
            f"share matching a known item {before.precision_mean:.0%} → {after.precision_mean:.0%}.",
            "",
        ]

    runs_before = before.runs if before else 0
    runs_after = after.runs if after else 0
    teacher_hits = set(comparison.teacher[0].matched_ids) if comparison.teacher else None
    lines += ["| # | Item | Teacher | Before | After |", "|---|---|---|---|---|"]
    for item_id, label in comparison.labels.items():
        rate_before, rate_after = comparison.hit_rates[item_id]
        marker = ""
        if rate_before is not None and rate_after is not None:
            marker = " ▲" if rate_after > rate_before else " ▼" if rate_after < rate_before else ""
        teacher = "-" if teacher_hits is None else ("✅" if item_id in teacher_hits else "❌")
        lines.append(
            f"| {item_id} | {label} | {teacher} | {_hits(rate_before, runs_before)} "
            f"| {_hits(rate_after, runs_after)}{marker} |"
        )
    if comparison.warnings:
        lines += ["", *(f"> ⚠ {warning}" for warning in comparison.warnings)]
    return "\n".join(lines) + "\n"
