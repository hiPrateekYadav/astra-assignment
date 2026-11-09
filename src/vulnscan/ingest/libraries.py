"""Inventory bundled libraries. The code is not scanned, but its versions matter."""

import re
from collections import defaultdict
from pathlib import Path

from vulnscan.ingest.filters import is_under, is_under_any
from vulnscan.ingest.layout import AppLayout
from vulnscan.ingest.types import FileKind, Library, SourceFile

_VERSION_NAME = re.compile(r'VERSION_NAME\s*=\s*"([^"]+)"')
REVERSE_DNS_PREFIXES = {"com", "org", "net", "io", "edu", "gov", "de", "uk", "fr", "jp", "cn"}
REVERSE_DNS_DEPTH = 3
INVENTORY_PATH = "libraries.txt"


def _maven_libraries(layout: AppLayout) -> list[Library]:
    """Read AndroidX-style META-INF/<group>_<artifact>.version files."""
    libraries = []
    for path in sorted((layout.resources / "META-INF").glob("*.version")):
        name = path.stem.replace("_", ":", 1)
        version = path.read_text(encoding="utf-8", errors="replace").strip()
        libraries.append(Library(name, version or None, path.name))
    return libraries


def _package_key(package: str) -> str:
    segments = package.split(".")
    depth = REVERSE_DNS_DEPTH if segments[0] in REVERSE_DNS_PREFIXES else 1
    return ".".join(segments[:depth])


def find_libraries(
    layout: AppLayout, packages_by_file: dict[Path, str], first_party_roots: tuple[str, ...]
) -> list[Library]:
    """Combine Maven metadata, library BuildConfig versions and package names."""
    libraries = _maven_libraries(layout)

    third_party = defaultdict(int)
    versioned: dict[str, str] = {}
    for path, package in packages_by_file.items():
        if not package or is_under_any(package, first_party_roots):
            continue
        third_party[_package_key(package)] += 1
        if path.name == "BuildConfig.java":
            text = path.read_text(encoding="utf-8", errors="replace")
            if match := _VERSION_NAME.search(text):
                versioned[package] = match.group(1)

    libraries += [
        Library(package, version, "BuildConfig.java") for package, version in sorted(versioned.items())
    ]
    libraries += [
        Library(key, None, f"package with {count} classes")
        for key, count in sorted(third_party.items())
        if not any(is_under(package, key) for package in versioned)
    ]
    return libraries


def render_inventory(libraries: list[Library]) -> SourceFile | None:
    if not libraries:
        return None
    lines = [
        f"{library.name} {library.version or 'version unknown'} ({library.source})"
        for library in libraries
    ]
    return SourceFile(INVENTORY_PATH, FileKind.LIBRARIES, tuple(enumerate(lines, start=1)))
