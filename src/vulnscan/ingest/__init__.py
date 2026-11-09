"""Turn a decompiled app into the units a model scans."""

from vulnscan.ingest.loader import load_app
from vulnscan.ingest.types import AppBundle, FileKind, IngestError, IngestStats, Library, SourceFile

__all__ = [
    "AppBundle",
    "FileKind",
    "IngestError",
    "IngestStats",
    "Library",
    "SourceFile",
    "load_app",
]
