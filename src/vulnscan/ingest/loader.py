"""Assemble an AppBundle from a decompiled directory or an APK."""

import logging
from pathlib import Path

from vulnscan.config import IngestSettings
from vulnscan.ingest.cleaning import clean_code, clean_strings, plain_lines
from vulnscan.ingest.decompile import DecompileError, decompile_apk
from vulnscan.ingest.filters import (
    applicable_library_prefixes,
    find_first_party_roots,
    is_generated,
    is_under_any,
)
from vulnscan.ingest.layout import AppLayout, LayoutError, find_layout
from vulnscan.ingest.libraries import find_libraries, render_inventory
from vulnscan.ingest.manifest import ManifestError, parse_manifest
from vulnscan.ingest.types import AppBundle, FileKind, IngestError, IngestStats, SourceFile

logger = logging.getLogger(__name__)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_code(
    layout: AppLayout, settings: IngestSettings, roots: tuple[str, ...], library_prefixes: tuple[str, ...]
) -> tuple[list[SourceFile], dict[Path, str], IngestStats]:
    stats = IngestStats()
    packages_by_file: dict[Path, str] = {}
    selected: list[tuple[Path, Path]] = []
    for source_root, path in layout.code_files():
        relative = path.relative_to(source_root)
        packages_by_file[path] = ".".join(relative.parts[:-1])
        selected.append((source_root, path))
    stats.source_files_total = len(selected)

    def owned(path: Path) -> bool:
        package = packages_by_file[path]
        return is_under_any(package, roots) and not is_under_any(package, library_prefixes)

    chosen = [item for item in selected if owned(item[1])]
    if not chosen:
        # Obfuscated apps can leave nothing under the manifest package. Scanning everything
        # that is not a known library costs more, but it beats silently scanning nothing.
        logger.warning("No code under %s; falling back to all non-library packages", roots)
        stats.used_fallback = True
        chosen = [
            item for item in selected if not is_under_any(packages_by_file[item[1]], library_prefixes)
        ]
    else:
        stats.unattributed_files = sum(
            not owned(path) and not is_under_any(packages_by_file[path], library_prefixes)
            for _, path in selected
        )
        if stats.unattributed_files > len(chosen):
            # Typical of partly obfuscated apps: named activities, with the logic in a.b.c.
            logger.warning(
                "%d code files are outside the app's packages and the known libraries, against %d "
                "inside, and will not be scanned. If they are app code, list their packages in "
                "ingest.first_party_prefixes.",
                stats.unattributed_files,
                len(chosen),
            )

    files = []
    for source_root, path in chosen:
        relative = path.relative_to(source_root)
        if is_generated(relative, settings.generated_patterns):
            stats.generated_files_skipped += 1
            continue
        text = _read(path)
        source_file = SourceFile(relative.as_posix(), FileKind.CODE, clean_code(text))
        stats.code_chars_before_cleaning += len(text)
        stats.code_chars_after_cleaning += len(source_file.text)
        files.append(source_file)
    stats.first_party_files = len(files)
    return files, packages_by_file, stats


def _load_resources(layout: AppLayout, settings: IngestSettings) -> list[SourceFile]:
    files = []
    res = layout.resources / "res"

    strings = res / "values" / "strings.xml"
    if strings.is_file():
        lines = clean_strings(_read(strings), tuple(settings.library_string_prefixes))
        files.append(SourceFile("res/values/strings.xml", FileKind.STRINGS, lines))

    for path in sorted((res / "xml").glob("*.xml")):
        relative = path.relative_to(layout.resources)
        if not is_generated(relative, settings.library_resource_patterns):
            files.append(SourceFile(relative.as_posix(), FileKind.XML_CONFIG, plain_lines(_read(path))))

    # Bundled config, secrets and WebView content often sit here rather than in code.
    for directory in (layout.resources / "assets", res / "raw"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if (
                path.is_file()
                and path.suffix.lower() in settings.text_asset_suffixes
                and path.stat().st_size <= settings.max_asset_bytes
            ):
                relative = path.relative_to(layout.resources)
                files.append(SourceFile(relative.as_posix(), FileKind.ASSET, plain_lines(_read(path))))
    return files


def load_app(path: Path, settings: IngestSettings) -> AppBundle:
    """Load a decompiled app, decompiling first if given an APK."""
    try:
        directory = decompile_apk(path, settings) if path.suffix.lower() == ".apk" else path
        layout = find_layout(directory)
        manifest = parse_manifest(layout.manifest)
    except (DecompileError, LayoutError, ManifestError) as error:
        raise IngestError(str(error)) from error

    library_prefixes = applicable_library_prefixes(manifest.package, settings.library_prefixes)
    roots = find_first_party_roots(manifest, library_prefixes, settings.first_party_prefixes)
    code, packages_by_file, stats = _load_code(layout, settings, roots, library_prefixes)
    if not code:
        raise IngestError(f"no first-party code found under {directory}")

    libraries = find_libraries(layout, packages_by_file, roots)
    files = [
        SourceFile("AndroidManifest.xml", FileKind.MANIFEST, plain_lines(_read(layout.manifest))),
        *code,
        *_load_resources(layout, settings),
    ]
    if inventory := render_inventory(libraries):
        files.append(inventory)
    stats.total_chars = sum(len(file.text) for file in files)

    return AppBundle(manifest.package, manifest, roots, files, libraries, stats)
