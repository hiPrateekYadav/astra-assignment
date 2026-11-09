"""Decide which packages and files belong to the app."""

from collections.abc import Iterable
from fnmatch import fnmatch
from pathlib import PurePath

from vulnscan.ingest.manifest import ManifestInfo

MIN_SHARED_SEGMENTS = 2  # com.acme.app and com.acme.core are one vendor; com.other is not


def is_under(package: str, prefix: str) -> bool:
    return package == prefix or package.startswith(prefix + ".")


def is_under_any(package: str, prefixes: Iterable[str]) -> bool:
    return any(is_under(package, prefix) for prefix in prefixes)


def package_of(class_name: str) -> str:
    return class_name.rpartition(".")[0]


def applicable_library_prefixes(package: str, prefixes: Iterable[str]) -> tuple[str, ...]:
    """Drop any prefix that covers the app, so a vendor's own app is not called a library."""
    return tuple(prefix for prefix in prefixes if not is_under(package, prefix))


def _common_package(packages: list[str]) -> str:
    split = [package.split(".") for package in packages]
    shared = []
    for segments in zip(*split):
        if len(set(segments)) > 1:
            break
        shared.append(segments[0])
    return ".".join(shared)


def find_first_party_roots(
    manifest: ManifestInfo, library_prefixes: tuple[str, ...], extra_roots: Iterable[str]
) -> tuple[str, ...]:
    """Infer the app's packages: the manifest package widened to same-vendor components,
    plus the Application and launcher classes wherever they live."""
    vendor = manifest.package.split(".")[:MIN_SHARED_SEGMENTS]
    app_classes = [
        package_of(component.name)
        for component in manifest.components
        if not is_under_any(component.name, library_prefixes)
    ]
    same_vendor = [
        package for package in app_classes if package.split(".")[:MIN_SHARED_SEGMENTS] == vendor
    ]

    entry_points = [c.name for c in manifest.components if c.is_launcher]
    if manifest.application_class:
        entry_points.append(manifest.application_class)
    entry_packages = [
        package_of(name) for name in entry_points if not is_under_any(name, library_prefixes)
    ]

    roots = {_common_package([manifest.package, *same_vendor]), *entry_packages, *extra_roots} - {""}
    outermost = (
        root for root in roots if not any(root != other and is_under(root, other) for other in roots)
    )
    return tuple(sorted(outermost))


def is_generated(relative_path: PurePath, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch(relative_path.as_posix(), pattern) or fnmatch(relative_path.name, pattern)
        for pattern in patterns
    )
