"""Remove decompiler noise while keeping every surviving line's original number."""

import re

Line = tuple[int, str]

_KOTLIN_METADATA = re.compile(r"^\s*@(kotlin\.)?Metadata\(.*\)\s*$")
_JADX_ORIGIN_COMMENT = re.compile(r"^\s*/\* JADX INFO: (compiled from|loaded from):.*\*/\s*$")
# Plain variables only: jadx can inline a real call into this argument.
_NULL_CHECK = re.compile(
    r'^\s*(kotlin\.jvm\.internal\.)?Intrinsics\.check\w+\(\s*[\w.$]+\s*,\s*"(?:[^"\\]|\\.)*"\s*\);\s*$'
)
_VIEW_CACHE_FIELD = re.compile(r"^\s*private HashMap _\$_findViewCache;\s*$")
_VIEW_CACHE_METHOD = re.compile(
    r"^\s*(public|private|protected)?\s*[\w<>\[\]]+\s+_\$_(clearFindViewByIdCache|findCachedViewById)\(.*\{\s*$"
)
_OVERRIDE_COMMENT = re.compile(r"^(\s*@Override)\s*//.*$")


def _is_noise(line: str) -> bool:
    return (
        not line.strip()
        or _KOTLIN_METADATA.match(line) is not None
        or _JADX_ORIGIN_COMMENT.match(line) is not None
        or _NULL_CHECK.match(line) is not None
        or _VIEW_CACHE_FIELD.match(line) is not None
    )


def clean_code(text: str) -> tuple[Line, ...]:
    kept: list[Line] = []
    skip_depth = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if skip_depth:
            skip_depth += line.count("{") - line.count("}")
        elif _VIEW_CACHE_METHOD.match(line):
            skip_depth = line.count("{") - line.count("}")
        elif not _is_noise(line):
            kept.append((number, _OVERRIDE_COMMENT.sub(r"\1", line)))
    return tuple(kept)


def clean_strings(text: str, excluded_prefixes: tuple[str, ...]) -> tuple[Line, ...]:
    """Drop strings that belong to bundled UI libraries, keeping the app's own."""
    pattern = re.compile(r'<string[^>]*\sname="(' + "|".join(map(re.escape, excluded_prefixes)) + ")")
    return tuple(
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not (excluded_prefixes and pattern.search(line))
    )


def plain_lines(text: str) -> tuple[Line, ...]:
    return tuple((number, line) for number, line in enumerate(text.splitlines(), start=1) if line.strip())
