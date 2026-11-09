"""Decompile an APK with jadx, reusing earlier output for the same file."""

import hashlib
import logging
import shutil
import subprocess
from pathlib import Path

from vulnscan.config import IngestSettings

logger = logging.getLogger(__name__)

HASH_PREFIX_CHARS = 12
STDERR_TAIL_CHARS = 500


class DecompileError(Exception):
    """jadx is unavailable, was killed, or produced no output."""


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:HASH_PREFIX_CHARS]


def decompile_apk(apk: Path, settings: IngestSettings) -> Path:
    output = settings.decompiled_dir / f"{apk.stem}-{_fingerprint(apk)}"
    if output.is_dir() and any(output.iterdir()):
        logger.info("Reusing decompiled output at %s", output)
        return output

    if shutil.which(settings.jadx_command) is None:
        raise DecompileError(
            f"'{settings.jadx_command}' not found. Install jadx, or decompile the APK "
            "yourself and pass the output directory instead."
        )

    logger.info("Decompiling %s", apk)
    try:
        # jadx exits non-zero if any method fails, so success means the output exists.
        # A kill signal is the exception: the output then stops wherever jadx did.
        result = subprocess.run(
            [settings.jadx_command, "--output-dir", str(output), str(apk)],
            capture_output=True,
            timeout=settings.jadx_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        shutil.rmtree(output, ignore_errors=True)  # partial output must not look reusable
        raise DecompileError(f"jadx timed out on {apk}") from error

    if result.returncode < 0:
        shutil.rmtree(output, ignore_errors=True)
        raise DecompileError(
            f"jadx was killed by signal {-result.returncode} on {apk}. In a container this "
            "usually means it ran out of memory; raise the Docker memory limit and retry."
        )
    if not output.is_dir() or not any(output.iterdir()):
        stderr = result.stderr.decode(errors="replace").strip()[-STDERR_TAIL_CHARS:]
        raise DecompileError(f"jadx produced no output for {apk}: {stderr}")
    return output
