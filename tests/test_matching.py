import hashlib

import pytest

from vulnscan.config import MatchSettings
from vulnscan.ingest import FileKind, SourceFile
from vulnscan.matching import (
    GroundTruth,
    GroundTruthEntry,
    GroundTruthError,
    assign,
    load_ground_truth,
    reference_from_findings,
    reference_from_ground_truth,
)
from vulnscan.schemas import Finding

WEB = "com/acme/WebActivity.java"


def finding(evidence: str = "web.loadUrl(url);", line: int | None = 10, **overrides) -> Finding:
    return Finding(
        **{
            "type": "webview_url_loading",
            "title": "t",
            "severity": "high",
            "file": WEB,
            "line": line,
            "evidence": evidence,
            "rationale": "r",
            "evidence_verified": True,
            "chunk_id": "c1",
        }
        | overrides
    )


def entry(id: int = 1, anchors: list[str] | None = None, **overrides) -> GroundTruthEntry:
    return GroundTruthEntry(
        **{"id": id, "title": f"e{id}", "files": [WEB], "types": ["webview_url_loading"],
           "anchors": anchors or []} | overrides
    )


def recall(findings, truth: GroundTruth, settings=MatchSettings(), files=None) -> int:
    return len(assign(findings, reference_from_ground_truth(truth, settings, files)))


def test_file_type_and_anchor_must_all_agree():
    truth = GroundTruth(entries=[entry(anchors=["loadUrl"])])
    assert recall([finding()], truth) == 1
    assert recall([finding(type="sql_injection")], truth) == 0
    assert recall([finding(file="com/acme/Other.java")], truth) == 0
    assert recall([finding(evidence="web.reload();")], truth) == 0


def test_any_listed_type_is_accepted():
    truth = GroundTruth(entries=[entry(types=["sql_injection", "webview_url_loading"])])
    assert recall([finding()], truth) == 1


def test_ground_truth_path_may_be_a_suffix_of_the_reported_path():
    truth = GroundTruth(entries=[entry(files=["WebActivity.java"])])
    assert recall([finding()], truth) == 1
    assert recall([finding(file="com/acme/NotWebActivity.java")], truth) == 0


def test_title_keywords_do_not_satisfy_an_anchor():
    truth = GroundTruth(entries=[entry(anchors=["endsWith"])])
    assert recall([finding(title="weak endsWith host check")], truth) == 0


def test_anchor_may_sit_near_the_verified_line():
    code = SourceFile(WEB, FileKind.CODE, ((5, 'String url = extras.getString("web_url");'),
                                           (10, "web.loadUrl(url);")))
    truth = GroundTruth(entries=[entry(anchors=["web_url"])])
    files = {WEB: code}
    assert recall([finding()], truth, MatchSettings(anchor_window_lines=8), files) == 1
    assert recall([finding()], truth, MatchSettings(anchor_window_lines=3), files) == 0
    assert recall([finding()], truth, MatchSettings(anchor_window_lines=0), files) == 0


def test_unverified_findings_get_no_window():
    code = SourceFile(WEB, FileKind.CODE, ((10, 'load("web_url")'),))
    truth = GroundTruth(entries=[entry(anchors=["web_url"])])
    assert recall([finding(evidence_verified=False)], truth, files={WEB: code}) == 0


def test_one_finding_earns_at_most_one_entry():
    truth = GroundTruth(entries=[entry(1), entry(2)])
    assert recall([finding()], truth) == 1
    assert recall([finding(), finding(line=20)], truth) == 2


def test_assignment_is_maximal_not_greedy():
    # The first finding fits both entries, the second only entry 1. Greedy would give
    # entry 1 to the first finding and strand entry 2.
    truth = GroundTruth(entries=[entry(1, anchors=["loadUrl"]), entry(2, anchors=["endsWith"])])
    both = finding("if (u.endsWith(h)) web.loadUrl(u);")
    only_first = finding("web.loadUrl(url);", line=30)
    assert recall([both, only_first], truth) == 2


def test_duplicates_cannot_pad_recall():
    truth = GroundTruth(entries=[entry()])
    assert recall([finding(), finding(), finding()], truth) == 1


def test_finding_matches_reference_finding_within_line_window():
    reference = reference_from_findings([finding(line=100)], MatchSettings(line_window=5))
    assert len(assign([finding(line=104)], reference)) == 1
    assert len(assign([finding(line=110, evidence="other();")], reference)) == 0


def test_finding_matches_reference_finding_by_quoted_code_when_far_apart():
    reference = reference_from_findings([finding(line=100)], MatchSettings(line_window=5))
    assert len(assign([finding(line=None, evidence="web.loadUrl( url );")], reference)) == 1


def test_finding_match_needs_same_type_and_file():
    reference = reference_from_findings([finding()], MatchSettings())
    assert not assign([finding(type="sql_injection")], reference)
    assert not assign([finding(file="com/acme/B.java")], reference)


def test_frozen_ground_truth_detects_edits(tmp_path):
    path = tmp_path / "app.yaml"
    path.write_text("entries: []\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "FROZEN.sha256").write_text(f"{digest}  data/ground_truth/app.yaml\n")
    assert load_ground_truth(path).entries == []
    path.write_text("entries: []\n# edited\n")
    with pytest.raises(GroundTruthError):
        load_ground_truth(path)


def test_shipped_ground_truth_is_unchanged():
    from vulnscan.config import PROJECT_ROOT

    truth = load_ground_truth(PROJECT_ROOT / "data/ground_truth/insecureshop.yaml")
    assert len(truth.entries) == 19
