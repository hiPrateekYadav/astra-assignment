"""Find the parts of a decompiled app, whichever layout jadx produced."""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

CODE_SUFFIXES = (".java", ".kt")
SOURCE_DIR_NAMES = ("java", "kotlin")


class LayoutError(Exception):
    """The directory does not look like decompiled Android output."""


@dataclass(frozen=True)
class AppLayout:
    root: Path
    manifest: Path
    resources: Path  # holds res/, assets/ and META-INF/
    source_roots: tuple[Path, ...]

    def code_files(self) -> Iterator[tuple[Path, Path]]:
        """Yield (source root, file) for every Java and Kotlin file."""
        for source_root in self.source_roots:
            for path in sorted(source_root.rglob("*")):
                if path.suffix in CODE_SUFFIXES and path.is_file():
                    yield source_root, path


def _has_code(directory: Path) -> bool:
    return any(next(directory.rglob(f"*{suffix}"), None) for suffix in CODE_SUFFIXES)


def find_layout(root: Path) -> AppLayout:
    """Support jadx's default output (sources/, resources/) and its Gradle export."""
    if not root.is_dir():
        raise LayoutError(f"app path is not a directory: {root}")

    manifests = sorted(root.rglob("AndroidManifest.xml"), key=lambda path: len(path.parts))
    if not manifests:
        raise LayoutError(f"no AndroidManifest.xml under {root}")
    manifest = manifests[0]
    resources = manifest.parent

    candidates = [root / "sources", *(resources / name for name in SOURCE_DIR_NAMES)]
    source_roots = tuple(path for path in candidates if path.is_dir() and _has_code(path))
    if not source_roots:
        raise LayoutError(f"no Java or Kotlin sources under {root}")
    return AppLayout(root, manifest, resources, source_roots)
