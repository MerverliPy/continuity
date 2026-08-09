"""Stable manifest construction and inventory comparison."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .hashing import inventory_tree
from .models import PackageStatus
from .paths import normalize_relative_path


@dataclass(frozen=True)
class ManifestDiff:
    """Differences between a baseline manifest and an observed manifest."""

    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    changed: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "changed": list(self.changed),
        }


def build_manifest(
    root: Path,
    package_id: str,
    status: PackageStatus,
    lineage_roots: tuple[str, ...],
) -> dict[str, object]:
    """Build the deterministic v1 file inventory for a package root."""

    records = inventory_tree(root, source_id=package_id)
    return {
        "schema": "continuity.package/v1",
        "package_id": package_id,
        "status": status.value,
        "lineage_roots": sorted(lineage_roots),
        "files": [
            {
                "path": record.normalized_path,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
            }
            for record in records
        ],
    }


def compare_manifests(left: Mapping[str, object], right: Mapping[str, object]) -> ManifestDiff:
    """Report sorted missing, unexpected, and changed paths without conflation."""

    left_files = _files_by_normalized_path(left)
    right_files = _files_by_normalized_path(right)
    shared = left_files.keys() & right_files.keys()
    return ManifestDiff(
        missing=tuple(sorted(left_files.keys() - right_files.keys())),
        unexpected=tuple(sorted(right_files.keys() - left_files.keys())),
        changed=tuple(
            sorted(
                path
                for path in shared
                if (
                    left_files[path]["sha256"],
                    left_files[path]["size_bytes"],
                )
                != (
                    right_files[path]["sha256"],
                    right_files[path]["size_bytes"],
                )
            )
        ),
    )


def _files_by_normalized_path(manifest: Mapping[str, object]) -> dict[str, dict[str, object]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("manifest files must be a list")
    normalized: dict[str, dict[str, object]] = {}
    for entry in files:
        if not isinstance(entry, Mapping):
            raise ValueError("manifest file entry must be an object")
        path = entry.get("path")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if not isinstance(path, str) or not isinstance(sha256, str) or not isinstance(size_bytes, int):
            raise ValueError("manifest file entry is missing path, sha256, or size_bytes")
        normalized_path = normalize_relative_path(path)
        if normalized_path in normalized:
            raise ValueError(f"duplicate normalized path: {normalized_path}")
        normalized[normalized_path] = {"sha256": sha256, "size_bytes": size_bytes}
    return normalized
