"""Path normalization that preserves observed spelling outside destination checks."""

import re
from pathlib import Path


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def normalize_relative_path(path: str | Path) -> str:
    """Return a safe slash-separated relative destination for *path*."""

    observed = str(path)
    if "\x00" in observed:
        raise ValueError("path contains a NUL byte")
    candidate = observed.replace("\\", "/")
    if candidate.startswith("/") or _DRIVE_PREFIX.match(candidate):
        raise ValueError(f"path must be relative: {observed!r}")
    parts = candidate.split("/")
    if any(part == ".." for part in parts):
        raise ValueError(f"path may not contain '..': {observed!r}")
    normalized_parts = [part for part in parts if part not in ("", ".")]
    if not normalized_parts:
        raise ValueError("path normalizes to an empty destination")
    return "/".join(normalized_parts)
