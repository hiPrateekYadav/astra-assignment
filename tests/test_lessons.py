from vulnscan.cache import ResponseCache
from vulnscan.config import LessonSettings, MatchSettings
from vulnscan.ingest import FileKind
from vulnscan.lessons import app_specific_terms, find_specific_terms, generate_lessons
from vulnscan.models.base import CompletionResult
from vulnscan.schemas import Lesson, LessonResponse, ScanReport
from vulnscan.taxonomy import Taxonomy, VulnerabilityType

from test_matching import finding
from test_scan import ScriptedClient, bundle_of, source

TAXONOMY = Taxonomy(types=[VulnerabilityType(id="webview_url_loading", description="d")])
BUNDLE = bundle_of(
    source("com/acme/shopkeeper/CheckoutActivity.java", "class CheckoutActivity {}"),
    source("res/values/strings.xml", '<string name="aws_pool_id">x</string>', kind=FileKind.STRINGS),
)
GENERAL = Lesson(
    rule="An exported activity that loads a URL from intent data into a WebView without an allowlist lets other apps load arbitrary pages.",
    types=["webview_url_loading", "made_up"],
    look_for="getIntent().getData() reaching WebView.loadUrl; safe if the host is compared exactly.",
)


class LessonClient(ScriptedClient):
    def _send(self, request):
        self.requests.append(request)
        return CompletionResult(LessonResponse(lessons=self.replies.pop(0)).model_dump_json(), 10, 5)


def teacher_report(*findings) -> ScanReport:
    return ScanReport(package="com.acme", role="teacher", model="t", repeat=0, chunks_total=1,
                      findings=list(findings))


def lesson(rule: str) -> Lesson:
    return Lesson(rule=rule, types=["webview_url_loading"], look_for="loadUrl")


def test_terms_cover_classes_packages_resources_and_literals():
    terms = app_specific_terms(BUNDLE, [finding(evidence='login("shop_user1", pass);')])
    assert {"CheckoutActivity", "acme", "aws_pool_id", "shop_user1"} <= terms
    # Subpackage names are often Android words (contentProvider, broadcast), so they stay allowed.
    assert "com" not in terms and "shopkeeper" not in terms


def test_plain_word_resources_and_literals_are_not_app_specific():
    bundle = bundle_of(source("res/values/strings.xml", '<string name="webview">x</string>', kind=FileKind.STRINGS))
    terms = app_specific_terms(bundle, [finding(evidence='Log.d("password", password);')])
    assert "webview" not in terms and "password" not in terms
    general = lesson("Logging a password or loading untrusted URLs into a WebView is risky.")
    assert find_specific_terms(general, terms) == []


def test_platform_literals_are_not_app_specific():
    terms = app_specific_terms(BUNDLE, [finding(evidence='getParcelableExtra("android.intent.extra.STREAM")')])
    assert "android.intent.extra.STREAM" not in terms


def test_general_lesson_passes_and_specific_ones_are_caught():
    terms = app_specific_terms(BUNDLE, [])
    assert find_specific_terms(GENERAL, terms) == []
    assert find_specific_terms(lesson("Check CheckoutActivity for loadUrl."), terms) == ["CheckoutActivity"]
    assert find_specific_terms(lesson("See line 12 of Foo.java."), terms) == ["Foo.java", "line 12"]


def test_identifier_match_is_whole_word():
    terms = {"Prefs"}
    assert find_specific_terms(lesson("Secrets in SharedPreferences are readable on rooted devices."), terms) == []


def test_lowercase_terms_match_any_case_but_class_names_match_as_written():
    terms = {"acmeshop", "Settings"}
    assert find_specific_terms(lesson("AcmeShop stores tokens."), terms) == ["acmeshop"]
    assert find_specific_terms(lesson("Insecure WebView settings widen the attack surface."), terms) == []


def test_generate_lessons_rejects_specific_lessons_and_unknown_types(tmp_path):
    client = LessonClient([[GENERAL, lesson("CheckoutActivity loads any URL.")]])
    report = generate_lessons(
        BUNDLE, teacher_report(finding()), [], client, TAXONOMY, ResponseCache(tmp_path),
        LessonSettings(), MatchSettings(),
    )
    assert [item.rule for item in report.lessons] == [GENERAL.rule]
    assert report.lessons[0].types == ["webview_url_loading"]
    assert report.rejected[0].app_specific_terms == ["CheckoutActivity"]
    assert report.usage.calls == 1


def test_teacher_sees_which_findings_the_student_missed_but_never_ground_truth(tmp_path):
    client = LessonClient([[GENERAL]])
    caught, missed = finding(line=10), finding(line=200, evidence="web.evaluateJavascript(js, null);")
    report = generate_lessons(
        BUNDLE, teacher_report(caught, missed), [teacher_report(finding(line=11))], client, TAXONOMY,
        ResponseCache(tmp_path), LessonSettings(), MatchSettings(),
    )
    assert report.findings_taught == 2 and report.findings_missed_by_student == 1
    prompt = client.requests[0].user
    assert '"caught_by_reviewer": true' in prompt and '"caught_by_reviewer": false' in prompt


def test_lessons_are_cached_and_capped(tmp_path):
    cache = ResponseCache(tmp_path)
    settings = LessonSettings(max_lessons=1)
    first = generate_lessons(BUNDLE, teacher_report(finding()), [], LessonClient([[GENERAL, GENERAL]]),
                             TAXONOMY, cache, settings, MatchSettings())
    again = LessonClient([])
    second = generate_lessons(BUNDLE, teacher_report(finding()), [], again, TAXONOMY, cache, settings,
                              MatchSettings())
    assert len(first.lessons) == 1 and second.lessons == first.lessons
    assert again.requests == [] and second.usage.cached_chunks == 1
