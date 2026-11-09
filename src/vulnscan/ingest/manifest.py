"""Parse AndroidManifest.xml into a digest for each chunk, since reachability depends on it."""

import xml.etree.ElementTree as ET
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
RISKY_APPLICATION_FLAGS = (
    "debuggable",
    "allowBackup",
    "usesCleartextTraffic",
    "networkSecurityConfig",
    "testOnly",
    "requestLegacyExternalStorage",
)
PROVIDER_EXPORT_DEFAULT_MAX_SDK = 16  # providers default to exported at or below this target
GUARD_ATTRIBUTES = ("permission", "readPermission", "writePermission")
PROVIDER_ATTRIBUTES = ("authorities", "grantUriPermissions")
DATA_ATTRIBUTES = ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")


class ManifestError(Exception):
    """The manifest is missing or cannot be parsed as XML."""


def _attr(element: ET.Element, name: str) -> str | None:
    return element.get(f"{ANDROID_NS}{name}")


@dataclass(frozen=True)
class IntentFilter:
    actions: tuple[str, ...]
    categories: tuple[str, ...]
    data: tuple[str, ...]

    def render(self) -> str:
        parts = [f"actions={list(self.actions)}"] if self.actions else []
        if self.categories:
            parts.append(f"categories={list(self.categories)}")
        if self.data:
            parts.append(f"data={list(self.data)}")
        return "intent-filter " + " ".join(parts)


@dataclass(frozen=True)
class Component:
    kind: str
    name: str
    exported: bool
    exported_explicitly: bool
    attributes: tuple[tuple[str, str], ...]
    intent_filters: tuple[IntentFilter, ...]
    metadata: tuple[tuple[str, str], ...]

    @property
    def is_launcher(self) -> bool:
        return any(
            "android.intent.category.LAUNCHER" in intent_filter.categories
            for intent_filter in self.intent_filters
        )

    def render(self) -> str:
        details = [f"{key}={value}" for key, value in self.attributes]
        details += [f"meta-data {key}={value}" for key, value in self.metadata]
        if self.exported and not self.exported_explicitly:
            details.append("exported implicitly")
        suffix = f" ({', '.join(details)})" if details else ""
        lines = [f"- {self.kind} {self.name}{suffix}"]
        lines += [f"    {intent_filter.render()}" for intent_filter in self.intent_filters]
        return "\n".join(lines)


@dataclass(frozen=True)
class ManifestInfo:
    package: str
    min_sdk: str | None
    target_sdk: str | None
    application_class: str | None
    application_flags: tuple[tuple[str, str], ...]
    requested_permissions: tuple[str, ...]
    declared_permissions: tuple[tuple[str, str], ...]
    components: tuple[Component, ...]

    def digest(self, only_classes: Collection[str] | None = None) -> str:
        """Render a compact summary, attack surface first; only_classes limits the components."""
        flags =", ".join(f"{key}={value}" for key, value in self.application_flags) or "none"
        sections = [
            f"Package: {self.package} (minSdk {self.min_sdk}, targetSdk {self.target_sdk})",
            f"Application class: {self.application_class}",
            f"Application flags: {flags}",
            f"Requested permissions: {', '.join(self.requested_permissions) or 'none'}",
        ]
        if self.declared_permissions:
            declared = ", ".join(f"{name} [{level}]" for name, level in self.declared_permissions)
            sections.append(f"Declared permissions: {declared}")

        components = self.components
        if only_classes is not None:
            components = tuple(c for c in self.components if c.name in only_classes)
            if omitted := len(self.components) - len(components):
                sections.append(f"({omitted} components unrelated to these files are not listed)")

        exported = [c for c in components if c.exported]
        detailed = [c for c in components if not c.exported and (c.intent_filters or c.attributes)]
        plain = [c for c in components if not c.exported and c not in detailed]
        if exported:
            sections.append("Exported components:\n" + "\n".join(c.render() for c in exported))
        if detailed:
            sections.append(
                "Non-exported components with filters or attributes:\n"
                + "\n".join(c.render() for c in detailed)
            )
        if plain:
            sections.append("Other non-exported components: " + ", ".join(c.name for c in plain))
        return "\n".join(sections)


def _resolve_class(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    return name if "." in name else f"{package}.{name}"


def _parse_intent_filter(element: ET.Element) -> IntentFilter:
    data = []
    for item in element.findall("data"):
        values = [f"{key}={_attr(item, key)}" for key in DATA_ATTRIBUTES if _attr(item, key)]
        if values:
            data.append(" ".join(values))
    return IntentFilter(
        actions=tuple(_attr(item, "name") or "" for item in element.findall("action")),
        categories=tuple(_attr(item, "name") or "" for item in element.findall("category")),
        data=tuple(data),
    )


def _is_exported(kind: str, explicit: str | None, has_filters: bool, target_sdk: str | None) -> bool:
    if explicit is not None:
        return explicit == "true"
    if kind == "provider":
        # A resource reference such as @integer/target cannot be resolved here.
        return (
            target_sdk is not None
            and target_sdk.isdigit()
            and int(target_sdk) <= PROVIDER_EXPORT_DEFAULT_MAX_SDK
        )
    return has_filters


def _parse_component(element: ET.Element, package: str, target_sdk: str | None) -> Component:
    filters = tuple(_parse_intent_filter(item) for item in element.findall("intent-filter"))
    explicit = _attr(element, "exported")
    attribute_names = GUARD_ATTRIBUTES + (PROVIDER_ATTRIBUTES if element.tag == "provider" else ())
    return Component(
        kind=element.tag,
        name=_resolve_class(_attr(element, "name") or "", package),
        exported=_is_exported(element.tag, explicit, bool(filters), target_sdk),
        exported_explicitly=explicit is not None,
        attributes=tuple((key, _attr(element, key)) for key in attribute_names if _attr(element, key)),
        intent_filters=filters,
        metadata=tuple(
            (_attr(item, "name") or "", _attr(item, "resource") or _attr(item, "value") or "")
            for item in element.findall("meta-data")
        ),
    )


def parse_manifest(path: Path) -> ManifestInfo:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise ManifestError(f"cannot parse {path}: {error}") from error

    package = root.get("package")
    if not package:
        raise ManifestError(f"{path} has no package attribute")

    sdk = root.find("uses-sdk")
    target_sdk = _attr(sdk, "targetSdkVersion") if sdk is not None else None
    application = root.find("application")
    if application is None:
        application = ET.Element("application")

    application_class = _attr(application, "name")
    return ManifestInfo(
        package=package,
        min_sdk=_attr(sdk, "minSdkVersion") if sdk is not None else None,
        target_sdk=target_sdk,
        application_class=_resolve_class(application_class, package) if application_class else None,
        application_flags=tuple(
            (key, _attr(application, key))
            for key in RISKY_APPLICATION_FLAGS
            if _attr(application, key)
        ),
        requested_permissions=tuple(
            _attr(item, "name") or "" for item in root.findall("uses-permission")
        ),
        declared_permissions=tuple(
            (_attr(item, "name") or "", _attr(item, "protectionLevel") or "normal (default)")
            for item in root.findall("permission")
        ),
        components=tuple(
            _parse_component(element, package, target_sdk)
            for element in application
            if element.tag in COMPONENT_TAGS
        ),
    )
