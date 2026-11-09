import pytest

from vulnscan.evaluate import compare, render_markdown, score
from vulnscan.matching import ReferenceItem
from vulnscan.schemas import ChunkFailure, ScanReport

from test_matching import finding


def report(*lines: int, repeat: int = 0, lessons: list[str] | None = None) -> ScanReport:
    return ScanReport(
        package="com.acme", role="student", model="m", repeat=repeat, chunks_total=1,
        lessons=lessons or [], findings=[finding(line=line) for line in lines],
    )


REFERENCE = [
    ReferenceItem(str(line), f"item {line}", lambda f, line=line: f.line == line) for line in (1, 2, 3, 4)
]


def test_score_reports_recall_and_matched_share():
    result = score(report(1, 2, 99), REFERENCE, "r0")
    assert result.recall == 0.5
    assert result.precision == pytest.approx(2 / 3)
    assert result.matched_ids == ["1", "2"]


def test_lift_is_the_difference_of_mean_recall_over_repeats():
    baseline = [("b0", report(1)), ("b1", report(1, 2))]
    lessons = [("l0", report(1, 2, 3, lessons=["x"])), ("l1", report(1, 2, 3, 4, lessons=["x"]))]
    comparison = compare(REFERENCE, "ref", [], baseline, lessons)
    assert comparison.baseline_summary.recall_mean == pytest.approx(0.375)
    assert comparison.lessons_summary.recall_mean == pytest.approx(0.875)
    assert comparison.lift == pytest.approx(0.5)
    assert comparison.hit_rates["2"] == (0.5, 1.0)
    assert comparison.lessons_used == 1


def test_lift_within_run_to_run_spread_is_flagged():
    baseline = [("b0", report(1)), ("b1", report(1, 2, 3))]
    lessons = [("l0", report(1, 2)), ("l1", report(1, 2))]
    comparison = compare(REFERENCE, "ref", [], baseline, lessons)
    assert any("spread" in warning for warning in comparison.warnings)


def test_single_runs_are_flagged():
    comparison = compare(REFERENCE, "ref", [], [("b0", report(1))], [("l0", report(1, 2))])
    assert any("--repeat" in warning for warning in comparison.warnings)


def test_stopped_reports_are_excluded_not_scored_as_misses():
    stopped = report()
    stopped.stopped_early = True
    comparison = compare(REFERENCE, "ref", [], [("b0", report(1, 2)), ("b1", stopped)], [])
    assert comparison.baseline_summary.runs == 1
    assert comparison.baseline_summary.recall_mean == 0.5
    assert any("b1 is unfinished" in warning for warning in comparison.warnings)


def test_budget_skips_are_scored_with_a_warning():
    partial = report(1, 2)
    partial.skipped_files = ["a.java"]
    comparison = compare(REFERENCE, "ref", [], [("b0", partial)], [])
    assert comparison.baseline_summary.runs == 1
    assert any("1 files over the token budget" in warning for warning in comparison.warnings)


def failed_chunks(count: int, total: int) -> ScanReport:
    result = report(1)
    result.chunks_total = total
    result.failed_chunks = [ChunkFailure(chunk_id=str(i), paths=[], error="x") for i in range(count)]
    return result


def test_failed_chunks_are_tolerated_up_to_the_configured_share():
    within, beyond = failed_chunks(1, 10), failed_chunks(2, 10)
    comparison = compare(REFERENCE, "ref", [], [("in", within), ("out", beyond)], [], max_failed_chunk_ratio=0.1)
    assert [item.report for item in comparison.baseline] == ["in"]


def test_markdown_shows_no_change_marker_without_lesson_runs():
    markdown = render_markdown(compare(REFERENCE, "ref", [], [("b0", report(1))], []))
    assert "▼" not in markdown and "▲" not in markdown
    assert "Lift:" not in markdown
