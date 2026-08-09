"""Read-only ZIP inspection and atomic extraction for untrusted evidence."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from .paths import normalize_relative_path


_COPY_CHUNK_SIZE = 1024 * 1024
_MALFORMED_FILENAME_VIOLATION = "malformed ZIP filename encoding"
_UNIX_FILE_TYPE_NAMES = {
    stat.S_IFIFO: "fifo",
    stat.S_IFCHR: "character-device",
    stat.S_IFBLK: "block-device",
    stat.S_IFLNK: "symbolic-link",
    stat.S_IFSOCK: "socket",
}


@dataclass(frozen=True)
class ArchivePolicy:
    """Resource and portability limits applied before a ZIP is extracted."""

    max_entries: int = 10_000
    max_file_size: int = 256 * 1024 * 1024
    max_total_size: int = 1024 * 1024 * 1024
    max_compression_ratio: float = 100.0
    portable_paths: bool = True


@dataclass(frozen=True)
class ArchiveEntry:
    """Central-directory facts for one normalized archive member."""

    observed_path: str
    normalized_path: str
    compressed_size: int
    uncompressed_size: int
    is_directory: bool


@dataclass(frozen=True)
class ArchiveInspection:
    """The immutable result of validating an archive against a policy."""

    safe: bool
    entries: tuple[ArchiveEntry, ...]
    violations: tuple[str, ...]


class _Violations:
    """Preserve discovery order while reporting every violation only once."""

    def __init__(self) -> None:
        self._items: dict[str, None] = {}

    def add(self, message: str) -> None:
        self._items.setdefault(message, None)

    def as_tuple(self) -> tuple[str, ...]:
        return tuple(self._items)


def inspect_zip(path: Path, policy: ArchivePolicy = ArchivePolicy()) -> ArchiveInspection:
    """Inspect ZIP metadata and member bytes without modifying the source."""

    try:
        with zipfile.ZipFile(Path(path), "r") as archive:
            return _inspect_open_zip(archive, policy)
    except UnicodeDecodeError:
        return _malformed_filename_inspection()
    except (zipfile.BadZipFile, EOFError) as error:
        return _corrupt_inspection(error)


def safe_extract_zip(
    path: Path,
    destination: Path,
    policy: ArchivePolicy = ArchivePolicy(),
) -> ArchiveInspection:
    """Inspect *path* fully, then atomically publish it at a new destination."""

    destination = Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(f"archive destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"archive destination parent does not exist: {destination.parent}")

    try:
        with zipfile.ZipFile(Path(path), "r") as archive:
            inspection = _inspect_open_zip(archive, policy)
            if not inspection.safe:
                return inspection
            _extract_open_zip(archive, destination, policy)
            return inspection
    except UnicodeDecodeError:
        return _malformed_filename_inspection()
    except (zipfile.BadZipFile, EOFError) as error:
        return _corrupt_inspection(error)


def _inspect_open_zip(archive: zipfile.ZipFile, policy: ArchivePolicy) -> ArchiveInspection:
    violations = _Violations()
    infos = archive.infolist()
    entries: list[ArchiveEntry] = []
    normalized_seen: dict[str, str] = {}
    portable_seen: dict[str, str] = {}
    path_kinds: dict[str, bool] = {}

    if len(infos) > policy.max_entries:
        violations.add(f"entry limit exceeded: {len(infos)} > {policy.max_entries}")

    total_size = sum(info.file_size for info in infos)
    if total_size > policy.max_total_size:
        violations.add(f"total size limit exceeded: {total_size} > {policy.max_total_size}")

    expansion_safe = len(infos) <= policy.max_entries and total_size <= policy.max_total_size
    for info in infos:
        observed_path = info.filename
        try:
            normalized_path = normalize_relative_path(observed_path)
        except ValueError as error:
            violations.add(f"unsafe path {observed_path!r}: {error}")
            normalized_path = None

        if info.file_size > policy.max_file_size:
            violations.add(
                f"per-file size limit exceeded for {observed_path!r}: "
                f"{info.file_size} > {policy.max_file_size}"
            )
            expansion_safe = False

        ratio = _compression_ratio(info)
        if ratio > policy.max_compression_ratio:
            violations.add(
                f"compression ratio limit exceeded for {observed_path!r}: "
                f"{ratio!r} > {policy.max_compression_ratio}"
            )
            expansion_safe = False

        if info.flag_bits & 1:
            violations.add(f"encrypted entry is not allowed: {observed_path!r}")

        if info.is_dir() and info.file_size != 0:
            violations.add(f"directory entry has nonzero payload: {observed_path!r}")

        unsupported_unix_type = _unsupported_unix_file_type(info)
        if unsupported_unix_type is not None:
            file_type, type_name = unsupported_unix_type
            if file_type == stat.S_IFLNK:
                violations.add(f"symbolic link entry is not allowed: {observed_path!r}")
            else:
                violations.add(
                    "archive.unsupported-unix-file-type: "
                    f"{type_name} entry {observed_path!r} is not allowed"
                )

        if normalized_path is None:
            continue

        if normalized_path in normalized_seen:
            violations.add(
                f"duplicate normalized path {normalized_path!r}: "
                f"{normalized_seen[normalized_path]!r} and {observed_path!r}"
            )
        else:
            normalized_seen[normalized_path] = observed_path

        portable_key = normalized_path.casefold()
        prior_portable = portable_seen.get(portable_key)
        if policy.portable_paths and prior_portable is not None and prior_portable != normalized_path:
            violations.add(
                f"portable path collision: {prior_portable!r} and {normalized_path!r}"
            )
        else:
            portable_seen.setdefault(portable_key, normalized_path)

        is_directory = info.is_dir()
        prior_kind = path_kinds.get(normalized_path)
        if prior_kind is not None and prior_kind != is_directory:
            violations.add(f"file and directory share destination {normalized_path!r}")
        else:
            path_kinds.setdefault(normalized_path, is_directory)

        entries.append(
            ArchiveEntry(
                observed_path=observed_path,
                normalized_path=normalized_path,
                compressed_size=info.compress_size,
                uncompressed_size=info.file_size,
                is_directory=is_directory,
            )
        )

    _find_parent_file_conflicts(path_kinds, violations)

    if expansion_safe:
        for info in infos:
            if info.flag_bits & 1 or _unsupported_unix_file_type(info) is not None:
                continue
            _verify_member_bytes(archive, info, violations)

    reported = violations.as_tuple()
    return ArchiveInspection(safe=not reported, entries=tuple(entries), violations=reported)


def _compression_ratio(info: zipfile.ZipInfo) -> float:
    if info.file_size == 0:
        return 0.0
    if info.compress_size == 0:
        return float("inf")
    return info.file_size / info.compress_size


def _unsupported_unix_file_type(info: zipfile.ZipInfo) -> tuple[int, str] | None:
    if info.create_system != 3:
        return None
    file_type = stat.S_IFMT(info.external_attr >> 16)
    if file_type in (0, stat.S_IFREG, stat.S_IFDIR):
        return None
    type_name = _UNIX_FILE_TYPE_NAMES.get(file_type, f"type-0o{file_type:o}")
    return file_type, type_name


def _find_parent_file_conflicts(path_kinds: dict[str, bool], violations: _Violations) -> None:
    for normalized_path in path_kinds:
        parts = normalized_path.split("/")
        for depth in range(1, len(parts)):
            parent = "/".join(parts[:depth])
            if path_kinds.get(parent) is False:
                violations.add(
                    f"file destination {parent!r} is a parent of {normalized_path!r}"
                )


def _verify_member_bytes(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    violations: _Violations,
) -> None:
    actual_size = 0
    try:
        with archive.open(info, "r") as source:
            while chunk := source.read(_COPY_CHUNK_SIZE):
                actual_size += len(chunk)
    except UnicodeDecodeError:
        violations.add(_MALFORMED_FILENAME_VIOLATION)
        return
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, zlib.error) as error:
        violations.add(f"corrupt member {info.filename!r}: {error}")
        return
    if actual_size != info.file_size:
        violations.add(
            f"corrupt member {info.filename!r}: expected {info.file_size} bytes, read {actual_size}"
        )


def _extract_open_zip(
    archive: zipfile.ZipFile,
    destination: Path,
    policy: ArchivePolicy,
) -> None:
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.continuity-", dir=destination.parent)
    )
    published = False
    try:
        resolved_root = temporary.resolve(strict=True)
        total_written = 0
        for info in archive.infolist():
            normalized_path = normalize_relative_path(info.filename)
            target = temporary.joinpath(*normalized_path.split("/"))
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                _require_inside_root(target.resolve(strict=True), resolved_root)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            _require_inside_root(target.parent.resolve(strict=True), resolved_root)
            file_written = 0
            with archive.open(info, "r") as source, target.open("xb") as output:
                while chunk := source.read(_COPY_CHUNK_SIZE):
                    file_written += len(chunk)
                    total_written += len(chunk)
                    if file_written > policy.max_file_size or file_written > info.file_size:
                        raise ValueError(f"member exceeded inspected size: {info.filename!r}")
                    if total_written > policy.max_total_size:
                        raise ValueError("archive exceeded inspected total size")
                    output.write(chunk)
            if file_written != info.file_size:
                raise zipfile.BadZipFile(
                    f"member size changed during extraction: {info.filename!r}"
                )

        if os.path.lexists(destination):
            raise FileExistsError(f"archive destination already exists: {destination}")
        temporary.rename(destination)
        published = True
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def _require_inside_root(candidate: Path, root: Path) -> None:
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"archive destination escaped temporary root: {candidate}") from error


def _corrupt_inspection(error: BaseException) -> ArchiveInspection:
    return ArchiveInspection(
        safe=False,
        entries=(),
        violations=(f"corrupt or truncated ZIP archive: {error}",),
    )


def _malformed_filename_inspection() -> ArchiveInspection:
    return ArchiveInspection(
        safe=False,
        entries=(),
        violations=(_MALFORMED_FILENAME_VIOLATION,),
    )
