"""Structured data exchanged with models and written to run reports."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]


class ModelFinding(BaseModel):
    """A finding as a model reports it, before it is checked against the app."""

    type: str = Field(description="A type ID from the list provided")
    title: str = Field(description="One-line summary of the issue")
    severity: Severity
    file: str = Field(description="The path exactly as shown in the file tag")
    line: int | None = Field(default=None, description="The number at the start of the line")
    evidence: str = Field(description="Code copied verbatim from the file, without its line number")
    rationale: str = Field(description="How an attacker reaches and exploits this")

    @field_validator("severity", mode="before")
    @classmethod
    def lowercase_severity(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value


class ScanResponse(BaseModel):
    findings: list[ModelFinding] = []


class Finding(ModelFinding):
    """A finding whose location was resolved and whose evidence was looked up in the file."""

    model_config = ConfigDict(frozen=True)

    evidence_verified: bool
    chunk_id: str


class DroppedFinding(BaseModel):
    reason: Literal["unknown_file", "unverified_evidence"]
    chunk_id: str
    finding: ModelFinding


class ChunkFailure(BaseModel):
    chunk_id: str
    paths: list[str]
    error: str


class ScanUsage(BaseModel):
    calls: int = 0
    cached_chunks: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


class ScanReport(BaseModel):
    package: str
    role: str
    model: str
    repeat: int
    lessons: list[str] = []
    chunks_total: int
    skipped_files: list[str] = []
    failed_chunks: list[ChunkFailure] = []
    stopped_early: bool = False  # a rate limit ended the scan; a rerun resumes from the cache
    duplicates_removed: int = 0
    retyped_as_other: int = 0
    findings: list[Finding] = []
    dropped: list[DroppedFinding] = []
    usage: ScanUsage = ScanUsage()

    @property
    def complete(self) -> bool:
        """False when any code went unscanned, which can understate recall."""
        return not self.failed_chunks and not self.skipped_files

    def usable(self, max_failed_chunk_ratio: float) -> bool:
        """Whether the run can be scored: not stopped early, and failed chunks within the allowed share.
        Budget skips do not count, because they repeat on every rerun and apply to every model."""
        if self.stopped_early:
            return False
        return len(self.failed_chunks) <= max_failed_chunk_ratio * self.chunks_total


class Lesson(BaseModel):
    """A general detection rule the teacher writes for the student."""

    rule: str = Field(description="A general rule about Android APIs, manifest settings or data flow")
    types: list[str] = Field(description="Type IDs from the list provided that this rule helps find")
    look_for: str = Field(description="Signals in code or manifest that indicate the flaw, and what makes it safe")

    def render(self) -> str:
        return f"{self.rule} Look for: {self.look_for} (types: {', '.join(self.types)})"


class LessonResponse(BaseModel):
    lessons: list[Lesson] = []


class RejectedLesson(BaseModel):
    lesson: Lesson
    app_specific_terms: list[str]


class LessonReport(BaseModel):
    package: str
    model: str
    teacher_report: str = ""
    student_reports: list[str] = []
    findings_taught: int
    findings_missed_by_student: int
    lessons: list[Lesson] = []
    rejected: list[RejectedLesson] = []
    usage: ScanUsage = ScanUsage()

    @property
    def rendered(self) -> list[str]:
        return [lesson.render() for lesson in self.lessons]
