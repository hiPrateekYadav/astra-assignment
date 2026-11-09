import os

from vulnscan import cli
from vulnscan.config import load_settings
from vulnscan.models.base import CompletionRequest, CompletionResult, ModelClient
from vulnscan.schemas import Lesson, LessonResponse, ScanReport, ScanResponse

from test_scan import ACTIVITY, APP, bundle_of, finding_json, source


class PipelineClient(ModelClient):
    """Teacher always finds the bug; the student finds it only once it has lessons."""

    def __init__(self, role_name: str, settings) -> None:
        provider = settings.providers[settings.roles[role_name].provider]
        super().__init__(settings.roles[role_name], provider, None, settings.retry)
        self.role_name = role_name

    def _send(self, request: CompletionRequest) -> CompletionResult:
        if request.user.rstrip().endswith("Write the lessons."):
            lesson = Lesson(rule="Validate URLs before loading them.", types=["webview_url_loading"], look_for="x")
            return CompletionResult(LessonResponse(lessons=[lesson]).model_dump_json(), 1, 1)
        found = self.role_name == "teacher" or "Lessons from an expert" in request.system
        findings = [finding_json()] if found and ACTIVITY in request.user else []
        return CompletionResult(ScanResponse(findings=findings).model_dump_json(), 1, 1)


def test_loop_finishes_and_scores_when_the_budget_skips_files(tmp_path, monkeypatch, capsys):
    settings = load_settings()
    settings.scan.output_dir = tmp_path
    settings.scan.max_total_tokens = 40  # room for the risky file, not the dull one
    bundle = bundle_of(APP, source("com/acme/Dull.java", "x" * 800))
    monkeypatch.setattr(cli, "load_app", lambda *_: bundle)
    monkeypatch.setattr(cli, "create_client", PipelineClient)

    assert cli.run_loop(settings, repeats=2, use_cache=True) == 0

    output = capsys.readouterr().out
    assert "**Lift: +100.0 points.**" in output
    assert "files over the token budget" in output


def write_report(directory, name: str, lessons: list[str], mtime: int) -> tuple[str, ScanReport]:
    report = ScanReport(package="p", role="student", model="m", repeat=0, chunks_total=1, lessons=lessons)
    path = directory / name
    path.write_text(report.model_dump_json(), encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return name, report


def test_rescans_from_an_older_lesson_set_are_not_mixed_in(tmp_path):
    old = write_report(tmp_path, "r0.json", ["old lesson"], 100)
    new = write_report(tmp_path, "r1.json", ["new lesson"], 200)
    kept, notes = cli._latest_lesson_runs(tmp_path, [old, new])
    assert kept == [new]
    assert notes == ["r0.json used an older set of lessons and is excluded"]
