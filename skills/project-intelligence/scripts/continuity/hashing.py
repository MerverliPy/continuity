"""Deterministic hashing and checksum-sidecar verification."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .models import ArtifactRecord, EvidenceState, VerificationFinding, VerificationReport
from .paths import normalize_relative_path


_CHUNK_SIZE = 1024 * 1024
_CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")
_CHECKSUM_NAME = "SHA256SUMS.txt"


def sha256_file(path: Path) -> str:
    """Calculate a file's SHA-256 by streaming a regular, non-symlink file."""

    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_tree(root: Path, source_id: str) -> tuple[ArtifactRecord, ...]:
    """Inventory regular files under *root* without traversing symlinks."""

    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError(f"root is not a directory: {root}")
    records: list[ArtifactRecord] = []
    _inventory_directory(root, root, source_id, records)
    records.sort(key=lambda record: record.normalized_path)
    _reject_duplicate_normalized_paths(records)
    return tuple(records)


def _inventory_directory(
    root: Path,
    directory: Path,
    source_id: str,
    records: list[ArtifactRecord],
) -> None:
    with os.scandir(directory) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            relative = entry.path[len(str(root)) + 1 :]
            observed_path = relative.replace(os.sep, "/")
            normalized_path = normalize_relative_path(observed_path)
            if entry.is_dir(follow_symlinks=False):
                _inventory_directory(root, Path(entry.path), source_id, records)
            elif entry.is_file(follow_symlinks=False) and normalized_path != _CHECKSUM_NAME:
                records.append(
                    ArtifactRecord(
                        source_id=source_id,
                        observed_path=observed_path,
                        normalized_path=normalized_path,
                        sha256=sha256_file(Path(entry.path)),
                        size_bytes=entry.stat(follow_symlinks=False).st_size,
                        evidence_state=EvidenceState.VERIFIED,
                    )
                )


def _reject_duplicate_normalized_paths(records: list[ArtifactRecord]) -> None:
    previous: str | None = None
    for record in records:
        if record.normalized_path == previous:
            raise ValueError(f"duplicate normalized path: {record.normalized_path}")
        previous = record.normalized_path


def write_sha256s(root: Path, destination: Path) -> None:
    """Write a deterministic checksum sidecar, excluding the sidecar itself."""

    root = Path(root).absolute()
    destination = Path(destination).absolute()
    relative_destination = _safe_checksum_destination(root, destination)
    records = inventory_tree(root, source_id="checksum-inventory")
    destination_path = normalize_relative_path(relative_destination)
    if destination_path is not None:
        records = tuple(record for record in records if record.normalized_path != destination_path)
    lines = [f"{record.sha256}  {record.normalized_path}" for record in records]
    _write_new_checksum(root, relative_destination, "\n".join(lines) + ("\n" if lines else ""))


def verify_sha256s(root: Path, checksum_file: Path) -> VerificationReport:
    """Compare a checksum sidecar with a current non-symlink inventory."""

    root = Path(root).absolute()
    checksum_file = Path(checksum_file).absolute()
    records = inventory_tree(root, source_id="verification-inventory")
    checksum_path = _relative_destination(root, checksum_file)
    if checksum_path is not None:
        records = tuple(record for record in records if record.normalized_path != checksum_path)
    observed = {record.normalized_path: record for record in records}
    if not checksum_file.is_file() or stat.S_ISLNK(checksum_file.lstat().st_mode):
        return VerificationReport(
            tuple(
                VerificationFinding(
                    normalized_path=record.normalized_path,
                    expected_sha256=None,
                    observed_sha256=record.sha256,
                    evidence_state=EvidenceState.UNRESOLVED,
                )
                for record in records
            ),
            checksum_present=False,
        )

    expected = _read_checksum_file(checksum_file)
    findings: list[VerificationFinding] = []
    for normalized_path in sorted(expected):
        expected_hash = expected[normalized_path]
        record = observed.pop(normalized_path, None)
        if record is None:
            findings.append(
                VerificationFinding(normalized_path, expected_hash, None, EvidenceState.MISSING)
            )
        elif record.sha256 == expected_hash:
            findings.append(
                VerificationFinding(normalized_path, expected_hash, record.sha256, EvidenceState.VERIFIED)
            )
        else:
            findings.append(
                VerificationFinding(normalized_path, expected_hash, record.sha256, EvidenceState.CONTRADICTED)
            )
    findings.extend(
        VerificationFinding(record.normalized_path, None, record.sha256, EvidenceState.UNRESOLVED)
        for record in observed.values()
    )
    findings.sort(key=lambda finding: finding.normalized_path)
    return VerificationReport(tuple(findings))


def _relative_destination(root: Path, destination: Path) -> str | None:
    try:
        return normalize_relative_path(destination.relative_to(root))
    except ValueError:
        return None


def _safe_checksum_destination(root: Path, destination: Path) -> Path:
    """Validate a new checksum path without resolving or following symlinks."""

    try:
        relative_destination = destination.relative_to(root)
    except ValueError as error:
        raise ValueError("checksum destination must be inside root") from error
    if not relative_destination.parts:
        raise ValueError("checksum destination must name a file inside root")

    current = root
    for component in relative_destination.parts[:-1]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as error:
            raise FileNotFoundError(f"checksum parent does not exist: {current}") from error
        if stat.S_ISLNK(mode):
            raise ValueError(f"checksum destination parent may not be a symlink: {current}")
        if not stat.S_ISDIR(mode):
            raise NotADirectoryError(f"checksum destination parent is not a directory: {current}")

    try:
        destination.lstat()
    except FileNotFoundError:
        return relative_destination
    raise FileExistsError(f"checksum destination already exists: {destination}")


def _write_new_checksum(root: Path, relative_destination: Path, text: str) -> None:
    """Create one UTF-8 checksum file exclusively beneath an already-safe root."""

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(root, directory_flags)
    directory_descriptor = root_descriptor
    try:
        for component in relative_destination.parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(relative_destination.name, file_flags, 0o644, dir_fd=directory_descriptor)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as checksum_file:
            checksum_file.write(text)
    finally:
        os.close(directory_descriptor)


def _read_checksum_file(checksum_file: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line_number, line in enumerate(checksum_file.read_text(encoding="utf-8").splitlines(), start=1):
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid checksum line {line_number} in {checksum_file}")
        normalized_path = normalize_relative_path(match.group(2))
        if normalized_path in expected:
            raise ValueError(f"duplicate normalized path: {normalized_path}")
        expected[normalized_path] = match.group(1).lower()
    return expected
