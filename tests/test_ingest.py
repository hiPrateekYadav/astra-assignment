import stat
from pathlib import Path

import pytest

from vulnscan.config import IngestSettings, load_settings
from vulnscan.ingest import FileKind, IngestError, load_app
from vulnscan.ingest.cleaning import clean_code, clean_strings
from vulnscan.ingest.layout import find_layout
from vulnscan.ingest.manifest import parse_manifest

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.notes">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <permission android:name="com.acme.notes.READ"/>
    <permission android:name="com.acme.notes.ADMIN" android:protectionLevel="signature"/>
    <application android:name=".NotesApp" android:debuggable="true" android:allowBackup="false">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.acme.feature.ShareActivity" android:exported="true"/>
        <activity android:name=".PrivateActivity" android:exported="false">
            <intent-filter><action android:name="com.acme.OPEN"/></intent-filter>
        </activity>
        <activity android:name=".PlainActivity"/>
        <provider android:name=".DataProvider" android:authorities="com.acme.data"/>
        <service android:name="org.vendor.sync.SyncService" android:exported="true"/>
    </application>
</manifest>
"""
STRINGS = """<resources>
    <string name="abc_action_bar_home">Home</string>
    <string name="api_token">secret-value</string>
</resources>
"""
CODE = "package {package};\n\npublic class {name} {{\n}}\n"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_class(source_root: Path, package: str, name: str) -> None:
    write(source_root / package.replace(".", "/") / f"{name}.java", CODE.format(package=package, name=name))


def write_app(root: Path, source_root: Path, resources: Path, manifest: str = MANIFEST) -> Path:
    write(resources / "AndroidManifest.xml", manifest)
    write(resources / "res/values/strings.xml", STRINGS)
    write(resources / "res/xml/network_security_config.xml", "<network-security-config/>\n")
    write(resources / "res/xml/standalone_badge.xml", "<badge/>\n")
    write(resources / "assets/config.json", '{"endpoint": "http://example.test"}\n')
    write(resources / "assets/logo.png", "binary")
    write(resources / "assets/huge.json", "x" * 2000)
    write(resources / "META-INF/androidx.core_core.version", "1.2.0\n")
    write_class(source_root, "com.acme.notes", "MainActivity")
    write_class(source_root, "com.acme.notes", "R")
    write_class(source_root, "com.acme.notes.databinding", "MainBinding")
    write_class(source_root, "com.acme.util", "Helper")
    write_class(source_root, "com.acme.feature", "ShareActivity")
    write_class(source_root, "androidx.core.app", "Thing")
    write_class(source_root, "org.vendor.sync", "SyncService")
    write(
        source_root / "org/vendor/sync/BuildConfig.java",
        'package org.vendor.sync;\nclass BuildConfig { static final String VERSION_NAME = "2.1.0"; }\n',
    )
    write(
        source_root / "com/acme/notes/BuildConfig.java",
        'package com.acme.notes;\nclass BuildConfig { static final String API_KEY = "k"; }\n',
    )
    return root


@pytest.fixture
def settings() -> IngestSettings:
    return load_settings().ingest.model_copy(update={"max_asset_bytes": 1000})


@pytest.fixture(params=["jadx_default", "gradle_export"])
def app(request, tmp_path) -> Path:
    if request.param == "jadx_default":
        return write_app(tmp_path, tmp_path / "sources", tmp_path / "resources")
    main = tmp_path / "app/src/main"
    return write_app(tmp_path, main / "java", main)


def paths(bundle, kind: FileKind) -> set[str]:
    return {file.path for file in bundle.files if file.kind is kind}


def test_both_layouts_give_the_same_logical_units(app, settings):
    bundle = load_app(app, settings)
    assert paths(bundle, FileKind.CODE) == {
        "com/acme/notes/MainActivity.java",
        "com/acme/notes/BuildConfig.java",
        "com/acme/util/Helper.java",
        "com/acme/feature/ShareActivity.java",
    }
    assert paths(bundle, FileKind.MANIFEST) == {"AndroidManifest.xml"}
    assert paths(bundle, FileKind.STRINGS) == {"res/values/strings.xml"}
    assert paths(bundle, FileKind.ASSET) == {"assets/config.json"}


def test_generated_and_library_files_are_excluded_and_counted(app, settings):
    stats = load_app(app, settings).stats
    assert stats.source_files_total == 9
    assert stats.first_party_files == 4
    assert stats.generated_files_skipped == 2


def test_root_widens_to_same_vendor_components(app, settings):
    assert load_app(app, settings).first_party_roots == ("com.acme",)


def test_library_strings_and_resources_are_excluded(app, settings):
    bundle = load_app(app, settings)
    strings = next(file for file in bundle.files if file.kind is FileKind.STRINGS).text
    assert "api_token" in strings and "abc_action_bar_home" not in strings
    assert paths(bundle, FileKind.XML_CONFIG) == {"res/xml/network_security_config.xml"}


def test_library_inventory_collects_versions(app, settings):
    libraries = {library.name: library.version for library in load_app(app, settings).libraries}
    assert libraries["androidx.core:core"] == "1.2.0"
    assert libraries["org.vendor.sync"] == "2.1.0"
    assert "com.acme" not in " ".join(libraries)


def test_code_outside_the_vendor_is_found_through_the_launcher(tmp_path, settings):
    manifest = MANIFEST.replace('android:name=".MainActivity"', 'android:name="org.real.code.Main"')
    root = write_app(tmp_path, tmp_path / "sources", tmp_path / "resources", manifest)
    write_class(root / "sources", "org.real.code", "Main")
    assert "org/real/code/Main.java" in paths(load_app(root, settings), FileKind.CODE)


def test_vendor_app_is_not_treated_as_a_library(tmp_path, settings):
    manifest = MANIFEST.replace('package="com.acme.notes"', 'package="com.facebook.notes"')
    root = tmp_path
    write(root / "resources/AndroidManifest.xml", manifest)
    write_class(root / "sources", "com.facebook.notes", "Main")
    assert "com/facebook/notes/Main.java" in paths(load_app(root, settings), FileKind.CODE)


def test_obfuscated_app_falls_back_to_non_library_code(tmp_path, settings):
    root = tmp_path
    write(root / "resources/AndroidManifest.xml", MANIFEST)
    write_class(root / "sources", "a.b", "c")
    write_class(root / "sources", "androidx.core", "d")
    bundle = load_app(root, settings)
    assert bundle.stats.used_fallback
    assert paths(bundle, FileKind.CODE) == {"a/b/c.java"}


def test_manifest_digest_describes_the_attack_surface(app):
    manifest = parse_manifest(find_layout(app).manifest)
    digest = manifest.digest()
    assert "debuggable=true" in digest and "allowBackup=false" in digest
    assert "com.acme.notes.READ [normal (default)]" in digest
    assert "com.acme.notes.ADMIN [signature]" in digest
    assert "activity com.acme.notes.MainActivity (exported implicitly)" in digest
    assert "activity com.acme.feature.ShareActivity\n" in digest
    assert "service org.vendor.sync.SyncService" in digest
    exported, _, rest = digest.partition("Non-exported components")
    assert "PrivateActivity" not in exported and "PrivateActivity" in rest
    assert "Other non-exported components: " in digest and "PlainActivity" in digest


@pytest.mark.parametrize(
    ("target", "exported"),
    [("16", True), ("17", False), ("@integer/target", False)],
)
def test_provider_export_default_depends_on_target_sdk(tmp_path, target, exported):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(MANIFEST.replace('android:targetSdkVersion="30"', f'android:targetSdkVersion="{target}"'))
    provider = next(c for c in parse_manifest(path).components if c.kind == "provider")
    assert provider.exported is exported


def test_directory_without_a_manifest_is_rejected(tmp_path, settings):
    with pytest.raises(IngestError, match="no AndroidManifest.xml"):
        load_app(tmp_path, settings)


def test_undecoded_binary_manifest_is_rejected(tmp_path, settings):
    write(tmp_path / "resources/AndroidManifest.xml", "\x03\x00\x08\x00")
    write_class(tmp_path / "sources", "com.acme", "A")
    with pytest.raises(IngestError, match="cannot parse"):
        load_app(tmp_path, settings)


def test_app_without_sources_is_rejected(tmp_path, settings):
    write(tmp_path / "AndroidManifest.xml", MANIFEST)
    with pytest.raises(IngestError, match="no Java or Kotlin"):
        load_app(tmp_path, settings)


def test_cleaning_removes_noise_and_keeps_line_numbers():
    source = "\n".join(
        [
            "package com.acme;",
            "",
            "/* JADX INFO: loaded from: classes.dex */",
            '@Metadata(bv = {1, 0, 3}, d1 = {"x"}, k = 1)',
            "public class A {",
            "    private HashMap _$_findViewCache;",
            "    public View _$_findCachedViewById(int i) {",
            "        if (x) {",
            "            return y;",
            "        }",
            "    }",
            "    @Override // androidx.Base, android.app.Activity",
            "    void run(String url) {",
            '        Intrinsics.checkParameterIsNotNull(url, "url");',
            "        web.loadUrl(url);",
            "    }",
            "}",
        ]
    )
    assert clean_code(source) == (
        (1, "package com.acme;"),
        (5, "public class A {"),
        (12, "    @Override"),
        (13, "    void run(String url) {"),
        (15, "        web.loadUrl(url);"),
        (16, "    }"),
        (17, "}"),
    )


def test_null_check_wrapping_a_real_call_is_kept():
    line = '        Intrinsics.checkExpressionValueIsNotNull(loader.loadClass("x"), "y");'
    assert clean_code(line) == ((1, line),)


def test_jadx_warnings_are_kept():
    line = "    /* JADX WARN: Method not decompiled */"
    assert clean_code(line) == ((1, line),)


def test_strings_are_unfiltered_without_prefixes():
    assert len(clean_strings(STRINGS, ())) == 4


def fake_jadx(tmp_path: Path, script_body: str) -> str:
    path = tmp_path / "fake-jadx"
    path.write_text(f"#!/bin/sh\n{script_body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def apk_settings(settings: IngestSettings, tmp_path: Path, command: str, **extra) -> IngestSettings:
    return settings.model_copy(
        update={"jadx_command": command, "decompiled_dir": tmp_path / "decompiled", **extra}
    )


def populate_script() -> str:
    """Stand in for jadx: write a minimal app to --output-dir ($2), then fail as jadx can."""
    package_dir = "$2/sources/com/acme/notes"
    return (
        f'mkdir -p "$2/resources" "{package_dir}"\n'
        "printf '%s' '<manifest package=\"com.acme.notes\"/>' > \"$2/resources/AndroidManifest.xml\"\n"
        f"printf 'class A {{}}' > \"{package_dir}/A.java\"\n"
        'echo run >> "$0.calls"\n'
        "exit 1"
    )


def test_apk_is_decompiled_despite_a_nonzero_exit_and_reused(tmp_path, settings):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    command = fake_jadx(tmp_path, populate_script())
    configured = apk_settings(settings, tmp_path, command)

    assert load_app(apk, configured).package == "com.acme.notes"
    assert load_app(apk, configured).package == "com.acme.notes"
    assert Path(f"{command}.calls").read_text().count("run") == 1


def test_missing_jadx_explains_the_alternative(tmp_path, settings):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    with pytest.raises(IngestError, match="decompile the APK"):
        load_app(apk, apk_settings(settings, tmp_path, "no-such-jadx"))


def test_timed_out_decompile_leaves_nothing_reusable(tmp_path, settings):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    command = fake_jadx(tmp_path, 'mkdir -p "$2"; touch "$2/partial"; exec sleep 5')
    configured = apk_settings(settings, tmp_path, command, jadx_timeout_seconds=0.2)
    with pytest.raises(IngestError, match="timed out"):
        load_app(apk, configured)
    assert not any((tmp_path / "decompiled").iterdir())


def test_killed_decompile_leaves_nothing_reusable(tmp_path, settings):
    """An out-of-memory kill leaves real but partial output that must not pass as a full app."""
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    command = fake_jadx(tmp_path, f'{populate_script().removesuffix("exit 1")}kill -9 $$')
    with pytest.raises(IngestError, match="out of memory"):
        load_app(apk, apk_settings(settings, tmp_path, command))
    assert not any((tmp_path / "decompiled").iterdir())


def test_code_outside_the_app_and_known_libraries_is_reported(tmp_path, settings, caplog):
    source_root = tmp_path / "sources"
    app = write_app(tmp_path, source_root, tmp_path / "resources")
    for index in range(30):
        write_class(source_root, "a.b", f"C{index}")
    stats = load_app(app, settings).stats
    assert not stats.used_fallback
    assert stats.unattributed_files >= 30
    assert "first_party_prefixes" in caplog.text


def test_decompile_with_no_output_reports_why(tmp_path, settings):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    command = fake_jadx(tmp_path, 'echo "unsupported dex version" >&2; exit 1')
    with pytest.raises(IngestError, match="unsupported dex version"):
        load_app(apk, apk_settings(settings, tmp_path, command))
