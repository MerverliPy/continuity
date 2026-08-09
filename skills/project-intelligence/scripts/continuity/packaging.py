"""Atomic, reproducible construction and approval-gated promotion of handoffs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ctypes
from dataclasses import dataclass
from datetime import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from .hashing import inventory_tree, sha256_file, verify_sha256s, write_sha256s
from .models import ApprovalRecord, EvidenceState, PackageStatus, ReadinessStatus
from .paths import normalize_relative_path
from .reconciliation import ReconciliationReport
from .redaction import redact_text


_DOCUMENT_PATHS = (
    "HANDOFF_README.md",
    "CANONICAL_STATE.md",
    "AUTHORITY_LEDGER.md",
    "CONFLICT_RESOLUTIONS.md",
    "UNRESOLVED.md",
    "NEXT_THREAD_PROMPT.txt",
    "SUPERPOWERS_PREFLIGHT.md",
)
_REQUIRED_DIRECTORIES = ("canonical", "evidence", "lineage", "receipts")
_REQUIRED_FILES = frozenset(
    {
        *_DOCUMENT_PATHS,
        "lineage/LINEAGE.json",
        "evidence/INDEX.json",
        "receipts/RECONCILIATION.json",
        "MANIFEST.json",
        "SHA256SUMS.txt",
    }
)
_ALLOWED_ROOT_ENTRIES = frozenset(
    {*_DOCUMENT_PATHS, *_REQUIRED_DIRECTORIES, "MANIFEST.json", "SHA256SUMS.txt"}
)
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_CHUNK_SIZE = 1024 * 1024
_APPROVED_DECISIONS = frozenset({"allow", "allowed", "approve", "approved"})
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


@dataclass(frozen=True)
class CandidateBuildRequest:
    """All explicit, normalized inputs needed to build one portable handoff."""

    package_id: str
    project_id: str
    created_at: str
    selected_source_hashes: Mapping[str, str]
    approved_reconciliation_report: ReconciliationReport
    canonical_files: Mapping[str, Path]
    rendered_documents: Mapping[str, str]
    lineage_data: Mapping[str, object]
    evidence_index: Mapping[str, object]
    secure_handling_approvals: Sequence[ApprovalRecord]
    output: Path
    readiness: ReadinessStatus = ReadinessStatus.READY
    allow_conditional_promotion: bool = False


@dataclass(frozen=True)
class CandidateResult:
    release: Path
    root: Path
    zip_path: Path
    package_id: str
    status: PackageStatus
    package_sha256: str


@dataclass(frozen=True)
class PackageValidation:
    valid: bool
    violations: tuple[str, ...]
    package_id: str | None = None
    status: PackageStatus | None = None
    readiness: ReadinessStatus | None = None


@dataclass(frozen=True)
class PromotionResult:
    release: Path
    root: Path
    zip_path: Path
    package_id: str
    status: PackageStatus
    package_sha256: str


def build_candidate(request: CandidateBuildRequest) -> CandidateResult:
    """Build, validate, and atomically publish a candidate or blocked package."""

    output = _validate_output_path(request.output)
    _validate_request(request)
    status = (
        PackageStatus.BLOCKED
        if request.approved_reconciliation_report.blocking_conflicts
        or request.readiness is ReadinessStatus.BLOCKED
        else PackageStatus.CANDIDATE
    )
    readiness = (
        ReadinessStatus.BLOCKED
        if status is PackageStatus.BLOCKED
        else request.readiness
    )
    workspace = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.continuity-build-", dir=output.parent)
    )
    package_root = workspace / "package"
    temporary_zip = workspace / f"{request.package_id}.zip"
    try:
        package_root.mkdir()
        for directory in _REQUIRED_DIRECTORIES:
            (package_root / directory).mkdir()
        for path in _DOCUMENT_PATHS:
            _write_bytes_new(package_root / path, request.rendered_documents[path].encode("utf-8"))

        _copy_canonical_files(
            request.canonical_files,
            package_root / "canonical",
            request.secure_handling_approvals,
        )
        lineage = dict(request.lineage_data)
        lineage["status"] = status.value
        lineage["readiness"] = readiness.value
        _write_json_new(package_root / "lineage/LINEAGE.json", lineage)
        _write_json_new(package_root / "evidence/INDEX.json", request.evidence_index)
        _write_json_new(
            package_root / "receipts/RECONCILIATION.json",
            request.approved_reconciliation_report.to_dict(),
        )
        _write_manifest(
            package_root,
            package_id=request.package_id,
            project_id=request.project_id,
            created_at=request.created_at,
            status=status,
            readiness=readiness,
            selected_source_hashes=request.selected_source_hashes,
            lineage_roots=_lineage_roots(request.lineage_data),
            allow_conditional_promotion=request.allow_conditional_promotion,
        )
        write_sha256s(package_root, package_root / "SHA256SUMS.txt")
        validation = validate_package(package_root)
        if not validation.valid:
            raise ValueError("constructed package is invalid: " + "; ".join(validation.violations))
        _write_reproducible_zip(package_root, temporary_zip)
        package_sha256 = _package_sha256(package_root)
        _publish_release_no_replace(workspace, output)
        return CandidateResult(
            release=output,
            root=output / "package",
            zip_path=output / f"{request.package_id}.zip",
            package_id=request.package_id,
            status=status,
            package_sha256=package_sha256,
        )
    finally:
        if workspace.exists():
            shutil.rmtree(workspace)


def validate_package(root: Path) -> PackageValidation:
    """Independently verify structure, lifecycle, manifest, and checksum bytes."""

    root = Path(root)
    violations: list[str] = []
    manifest: dict[str, object] | None = None
    package_id: str | None = None
    status: PackageStatus | None = None
    readiness: ReadinessStatus | None = None
    try:
        mode = root.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            return PackageValidation(False, ("package root must be a non-symlink directory",))
    except FileNotFoundError:
        return PackageValidation(False, ("package root does not exist",))

    _validate_tree_types(root, violations)
    observed_root = {entry.name for entry in os.scandir(root)}
    missing_root = sorted(_ALLOWED_ROOT_ENTRIES - observed_root)
    unexpected_root = sorted(observed_root - _ALLOWED_ROOT_ENTRIES)
    if missing_root:
        violations.append("missing required root entries: " + ", ".join(missing_root))
    if unexpected_root:
        violations.append("unexpected root entries: " + ", ".join(unexpected_root))
    for directory in _REQUIRED_DIRECTORIES:
        path = root / directory
        if not _is_regular_directory(path):
            violations.append(f"required directory is absent or unsafe: {directory}")
    for path in _DOCUMENT_PATHS:
        artifact = root / path
        if not _is_regular_file(artifact):
            violations.append(f"required document is absent or unsafe: {path}")
        elif artifact.stat(follow_symlinks=False).st_size == 0:
            violations.append(f"required document is empty: {path}")

    lineage = _read_json_object(root / "lineage/LINEAGE.json", "lineage/LINEAGE.json", violations)
    evidence_index = _read_json_object(
        root / "evidence/INDEX.json", "evidence/INDEX.json", violations
    )
    reconciliation = _read_json_object(
        root / "receipts/RECONCILIATION.json",
        "receipts/RECONCILIATION.json",
        violations,
    )
    manifest = _read_json_object(root / "MANIFEST.json", "MANIFEST.json", violations)
    if manifest is not None:
        package_id = _nonempty_string(manifest.get("package_id"), "manifest package_id", violations)
        project_id = _nonempty_string(
            manifest.get("project_id"), "manifest project_id", violations
        )
        created_at = _rfc3339_value(
            manifest.get("created_at"), "manifest created_at", violations
        )
        status = _enum_value(PackageStatus, manifest.get("status"), "manifest status", violations)
        readiness = _enum_value(
            ReadinessStatus, manifest.get("readiness"), "manifest readiness", violations
        )
        if manifest.get("schema") != "continuity.package/v1":
            violations.append("manifest schema must be continuity.package/v1")
        _validate_string_list(manifest.get("lineage_roots"), "manifest lineage_roots", violations)
        if not isinstance(manifest.get("allow_conditional_promotion"), bool):
            violations.append("manifest allow_conditional_promotion must be boolean")
        _validate_source_hashes(
            manifest.get("selected_source_hashes"),
            "manifest selected_source_hashes",
            violations,
        )
        _validate_manifest_inventory(root, manifest, violations)
        if not _valid_lifecycle_pair(status, readiness):
            violations.append("manifest lifecycle/readiness pair is inconsistent")
    else:
        project_id = None
        created_at = None

    if lineage is not None:
        _validate_lineage_structure(lineage, violations)
    if evidence_index is not None:
        _validate_evidence_structure(evidence_index, violations)
    if reconciliation is not None:
        _validate_reconciliation_structure(reconciliation, violations)
    if (
        reconciliation is not None
        and reconciliation.get("blocking_conflict_ids")
        and status in {PackageStatus.CANDIDATE, PackageStatus.CANONICAL}
    ):
        violations.append("blocking reconciliation cannot carry Candidate or Canonical status")

    if lineage is not None and package_id is not None and lineage.get("package_id") != package_id:
        violations.append("lineage package_id does not match manifest")
    if lineage is not None and manifest is not None:
        if lineage.get("project_id") != project_id:
            violations.append("lineage project_id does not match manifest")
        if lineage.get("created_at") != created_at:
            violations.append("lineage created_at does not match manifest")
        if lineage.get("status") != manifest.get("status"):
            violations.append("lineage status does not match manifest")
        if lineage.get("readiness") != manifest.get("readiness"):
            violations.append("lineage readiness does not match manifest")
        if lineage.get("source_hashes") != manifest.get("selected_source_hashes"):
            violations.append("lineage source hashes do not match manifest selected sources")
        if sorted(lineage.get("parent_ids", [])) != manifest.get("lineage_roots"):
            violations.append("lineage parents do not match manifest lineage_roots")

    if status is PackageStatus.CANONICAL:
        promotion = _read_json_object(
            root / "receipts/PROMOTION.json", "receipts/PROMOTION.json", violations
        )
        if promotion is not None:
            _validate_promotion_receipt(promotion, package_id, violations)

    checksum_path = root / "SHA256SUMS.txt"
    if not _is_regular_file(checksum_path):
        violations.append("SHA256SUMS.txt is absent or unsafe")
    else:
        try:
            verification = verify_sha256s(root, checksum_path)
            if not verification.verified:
                violations.append("checksum inventory does not match package bytes")
        except (OSError, UnicodeError, ValueError) as error:
            violations.append(f"invalid checksum inventory: {error}")

    return PackageValidation(
        valid=not violations,
        violations=tuple(sorted(set(violations))),
        package_id=package_id,
        status=status,
        readiness=readiness,
    )


def promote_candidate(
    candidate: Path,
    output: Path,
    approval: ApprovalRecord | None,
    successor_created_at: str,
) -> PromotionResult:
    """Create a separately validated canonical successor without editing its candidate."""

    candidate = Path(candidate)
    validation = validate_package(candidate)
    if not validation.valid:
        raise ValueError("candidate package is invalid: " + "; ".join(validation.violations))
    if validation.status is not PackageStatus.CANDIDATE:
        raise ValueError("only a Candidate package can be promoted")
    manifest = json.loads((candidate / "MANIFEST.json").read_text(encoding="utf-8"))
    conditional_allowed = manifest.get("allow_conditional_promotion") is True
    if validation.readiness is ReadinessStatus.CONDITIONAL and not conditional_allowed:
        raise ValueError("Conditional readiness is not approved for promotion")
    if validation.readiness not in {ReadinessStatus.READY, ReadinessStatus.CONDITIONAL}:
        raise ValueError("candidate readiness does not permit promotion")
    if validation.package_id is None or not _exact_promotion_approval(approval, validation.package_id):
        raise ValueError("exact promote-candidate approval scoped to the candidate package is required")
    if not _is_rfc3339(successor_created_at):
        raise ValueError("successor_created_at must be deterministic RFC3339 text")

    output = _validate_output_path(output)
    successor_id = output.name
    if not _is_package_id(successor_id) or successor_id == validation.package_id:
        raise ValueError("canonical successor must have a new package ID")
    candidate_sha256 = _package_sha256(candidate)
    workspace = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.continuity-promote-", dir=output.parent)
    )
    successor_root = workspace / "package"
    temporary_zip = workspace / f"{successor_id}.zip"
    try:
        successor_root.mkdir()
        _copy_tree_streaming(candidate, successor_root)
        (successor_root / "MANIFEST.json").unlink()
        (successor_root / "SHA256SUMS.txt").unlink()
        promotion_path = successor_root / "receipts/PROMOTION.json"
        if promotion_path.exists():
            raise ValueError("candidate already contains a promotion receipt")
        _write_json_new(
            promotion_path,
            {
                "schema": "continuity.promotion-receipt/v1",
                "candidate_package_id": validation.package_id,
                "candidate_sha256": candidate_sha256,
                "canonical_package_id": successor_id,
                "approval": _approval_to_dict(approval),
            },
        )
        _update_successor_lineage(
            successor_root / "lineage/LINEAGE.json",
            successor_id,
            validation.package_id,
            successor_created_at,
            validation.readiness,
        )
        successor_lineage = json.loads(
            (successor_root / "lineage/LINEAGE.json").read_text(encoding="utf-8")
        )
        _write_manifest(
            successor_root,
            package_id=successor_id,
            project_id=str(manifest["project_id"]),
            created_at=successor_created_at,
            status=PackageStatus.CANONICAL,
            readiness=validation.readiness,
            selected_source_hashes=_string_mapping(manifest.get("selected_source_hashes")),
            lineage_roots=_lineage_roots(successor_lineage),
            allow_conditional_promotion=conditional_allowed,
            predecessor_package_id=validation.package_id,
        )
        write_sha256s(successor_root, successor_root / "SHA256SUMS.txt")
        successor_validation = validate_package(successor_root)
        if not successor_validation.valid:
            raise ValueError(
                "promoted package is invalid: " + "; ".join(successor_validation.violations)
            )
        _write_reproducible_zip(successor_root, temporary_zip)
        package_sha256 = _package_sha256(successor_root)
        _publish_release_no_replace(workspace, output)
        return PromotionResult(
            release=output,
            root=output / "package",
            zip_path=output / f"{successor_id}.zip",
            package_id=successor_id,
            status=PackageStatus.CANONICAL,
            package_sha256=package_sha256,
        )
    finally:
        if workspace.exists():
            shutil.rmtree(workspace)


def _validate_request(request: CandidateBuildRequest) -> None:
    if (
        not _is_package_id(request.package_id)
        or not isinstance(request.project_id, str)
        or not request.project_id.strip()
    ):
        raise ValueError("package_id must be a portable single path component and project_id non-empty")
    if not _is_rfc3339(request.created_at):
        raise ValueError("created_at must be deterministic RFC3339 text")
    if set(request.rendered_documents) != set(_DOCUMENT_PATHS):
        raise ValueError("rendered documents must contain exactly the v1 document paths")
    if any(not isinstance(text, str) or not text.strip() for text in request.rendered_documents.values()):
        raise ValueError("rendered documents must be non-empty text")
    if not isinstance(request.readiness, ReadinessStatus):
        raise ValueError("readiness must be a ReadinessStatus")
    if not isinstance(request.allow_conditional_promotion, bool):
        raise ValueError("allow_conditional_promotion must be boolean")
    source_violations: list[str] = []
    _validate_source_hashes(
        request.selected_source_hashes, "selected source hashes", source_violations
    )
    if source_violations:
        raise ValueError(source_violations[0])
    if not isinstance(request.lineage_data, Mapping) or not isinstance(request.evidence_index, Mapping):
        raise ValueError("lineage data and evidence index must be objects")
    if request.lineage_data.get("source_hashes") != dict(request.selected_source_hashes):
        raise ValueError("lineage source hashes must match selected source hashes")
    lineage_violations: list[str] = []
    _validate_lineage_structure(request.lineage_data, lineage_violations)
    if request.lineage_data.get("package_id") != request.package_id:
        lineage_violations.append("lineage package_id must match request package_id")
    if request.lineage_data.get("project_id") != request.project_id:
        lineage_violations.append("lineage project_id must match request project_id")
    if request.lineage_data.get("created_at") != request.created_at:
        lineage_violations.append("lineage created_at must match request created_at")
    if request.lineage_data.get("status") != PackageStatus.CANDIDATE.value:
        lineage_violations.append("lineage status must be Candidate in a build request")
    if request.lineage_data.get("readiness") != request.readiness.value:
        lineage_violations.append("lineage readiness must match request readiness")
    if lineage_violations:
        raise ValueError(lineage_violations[0])
    evidence_violations: list[str] = []
    _validate_evidence_structure(request.evidence_index, evidence_violations)
    if evidence_violations:
        raise ValueError(evidence_violations[0])
    try:
        json.dumps(request.lineage_data)
        json.dumps(request.evidence_index)
        json.dumps(request.approved_reconciliation_report.to_dict())
    except (TypeError, ValueError) as error:
        raise ValueError("structured package inputs must be JSON serializable") from error


def _validate_output_path(output: Path) -> Path:
    output = Path(output)
    if not output.name:
        raise ValueError("output must name a package directory")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"output parent does not exist: {output.parent}")
    if os.path.lexists(output):
        raise FileExistsError("release output already exists")
    return output


def _publish_release_no_replace(temporary_release: Path, destination: Path) -> None:
    """Atomically publish one release directory without replacing a racing path."""

    if os.name != "posix":
        raise RuntimeError("atomic no-replace release publication is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RuntimeError("atomic no-replace release publication is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(temporary_release),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise RuntimeError("atomic no-replace release publication is unavailable")
    raise OSError(error_number, os.strerror(error_number), destination)


def _copy_canonical_files(
    mappings: Mapping[str, Path],
    canonical_root: Path,
    approvals: Sequence[ApprovalRecord],
) -> None:
    normalized: dict[str, Path] = {}
    portable: dict[str, str] = {}
    for destination, source in mappings.items():
        normalized_path = normalize_relative_path(destination)
        if normalized_path != destination.replace("\\", "/"):
            raise ValueError(f"canonical destination is not normalized: {destination!r}")
        portable_key = normalized_path.casefold()
        if normalized_path in normalized or (
            portable_key in portable and portable[portable_key] != normalized_path
        ):
            raise ValueError(f"duplicate portable canonical destination: {destination!r}")
        normalized[normalized_path] = Path(source)
        portable[portable_key] = normalized_path

    for destination, source in sorted(normalized.items()):
        _require_regular_source(source)
        target = canonical_root.joinpath(*destination.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_file_streaming(source, target)
        _require_secret_approval(target, destination, approvals)


def _require_regular_source(source: Path) -> None:
    try:
        mode = source.lstat().st_mode
    except FileNotFoundError:
        raise FileNotFoundError(f"canonical source does not exist: {source.name}") from None
    if stat.S_ISLNK(mode):
        raise ValueError(f"canonical source may not be a symlink: {source.name}")
    if not stat.S_ISREG(mode):
        raise ValueError(f"canonical source must be a regular file: {source.name}")


def _require_secret_approval(
    source: Path, destination: str, approvals: Sequence[ApprovalRecord]
) -> None:
    try:
        text = source.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    if not redact_text(text).findings:
        return
    approved_path = f"canonical/{destination}"
    exact = any(
        approval.action == "secure-handling"
        and _normalize(approval.decision) in _APPROVED_DECISIONS
        and bool(approval.approval_id.strip())
        and bool(approval.source_id.strip())
        and bool(approval.source_ref.strip())
        and _is_rfc3339(approval.approved_at)
        and approved_path in approval.scope
        and all(_is_exact_normalized_package_path(path) for path in approval.scope)
        for approval in approvals
    )
    if not exact:
        raise ValueError(f"secret-bearing path requires exact secure-handling approval: {destination}")


def _copy_file_streaming(source: Path, target: Path) -> None:
    read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, read_flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"copy source changed or is not regular: {source.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as input_file, target.open("xb") as output_file:
            while chunk := input_file.read(_CHUNK_SIZE):
                output_file.write(chunk)
    finally:
        os.close(descriptor)


def _copy_tree_streaming(source_root: Path, target_root: Path) -> None:
    for entry in sorted(os.scandir(source_root), key=lambda item: item.name):
        target = target_root / entry.name
        if entry.is_dir(follow_symlinks=False):
            target.mkdir()
            _copy_tree_streaming(Path(entry.path), target)
        elif entry.is_file(follow_symlinks=False):
            _copy_file_streaming(Path(entry.path), target)
        else:
            raise ValueError(f"package contains a symlink or special file: {entry.name}")


def _write_manifest(
    root: Path,
    *,
    package_id: str,
    project_id: str,
    created_at: str,
    status: PackageStatus,
    readiness: ReadinessStatus,
    selected_source_hashes: Mapping[str, str],
    lineage_roots: tuple[str, ...],
    allow_conditional_promotion: bool,
    predecessor_package_id: str | None = None,
) -> None:
    records = inventory_tree(root, source_id=package_id)
    records = tuple(record for record in records if record.normalized_path != "MANIFEST.json")
    files = [
        {"path": record.normalized_path, "sha256": record.sha256, "size_bytes": record.size_bytes}
        for record in records
    ]
    manifest: dict[str, object] = {
        "schema": "continuity.package/v1",
        "package_id": package_id,
        "project_id": project_id,
        "created_at": created_at,
        "status": status.value,
        "readiness": readiness.value,
        "allow_conditional_promotion": allow_conditional_promotion,
        "lineage_roots": sorted(lineage_roots),
        "selected_source_hashes": dict(sorted(selected_source_hashes.items())),
        "files": files,
    }
    if predecessor_package_id is not None:
        manifest["predecessor_package_id"] = predecessor_package_id
    files.sort(key=lambda item: str(item["path"]))
    _write_bytes_new(root / "MANIFEST.json", _json_bytes(manifest))


def _validate_manifest_inventory(
    root: Path, manifest: Mapping[str, object], violations: list[str]
) -> None:
    files = manifest.get("files")
    if not isinstance(files, list):
        violations.append("manifest files must be a list")
        return
    entries: dict[str, Mapping[str, object]] = {}
    for item in files:
        if not isinstance(item, Mapping):
            violations.append("manifest file entry must be an object")
            continue
        path = item.get("path")
        if not isinstance(path, str):
            violations.append("manifest file entry path must be text")
            continue
        try:
            normalized = normalize_relative_path(path)
        except ValueError:
            violations.append(f"unsafe manifest path: {path}")
            continue
        if normalized != path or path in entries:
            violations.append(f"duplicate or non-normalized manifest path: {path}")
            continue
        entries[path] = item
    try:
        records = inventory_tree(root, source_id="package-validation")
    except (OSError, ValueError) as error:
        violations.append(f"could not inventory package: {error}")
        return
    observed = {record.normalized_path: record for record in records}
    observed.pop("MANIFEST.json", None)
    if set(entries) != set(observed):
        missing = sorted(set(observed) - set(entries))
        unexpected = sorted(set(entries) - set(observed))
        if missing:
            violations.append("manifest omits regular files: " + ", ".join(missing))
        if unexpected:
            violations.append("manifest names absent files: " + ", ".join(unexpected))
    for path in sorted(set(entries) & set(observed)):
        entry = entries[path]
        record = observed[path]
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if not isinstance(digest, str) or not _is_sha256(digest) or not isinstance(size, int):
            violations.append(f"manifest metadata is invalid for {path}")
            continue
        if size != record.size_bytes:
            violations.append(f"manifest size differs for {path}")
        if digest != record.sha256:
            violations.append(f"manifest digest differs for {path}")


def _write_reproducible_zip(root: Path, destination: Path) -> None:
    entries: list[tuple[str, Path | None]] = []
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        directory_path = Path(directory)
        for name in directories:
            path = directory_path / name
            if path.is_symlink():
                raise ValueError("package ZIP source contains a symlink")
            entries.append((path.relative_to(root).as_posix() + "/", None))
        for name in files:
            path = directory_path / name
            _require_regular_source(path)
            entries.append((path.relative_to(root).as_posix(), path))
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED) as archive:
        for archive_path, source in sorted(entries):
            info = zipfile.ZipInfo(archive_path, date_time=_ZIP_TIMESTAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            if source is None:
                info.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10
                archive.writestr(info, b"")
                continue
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with archive.open(info, "w") as output_file:
                read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(source, read_flags)
                try:
                    with os.fdopen(descriptor, "rb", closefd=False) as input_file:
                        while chunk := input_file.read(_CHUNK_SIZE):
                            output_file.write(chunk)
                finally:
                    os.close(descriptor)


def _update_successor_lineage(
    path: Path,
    successor_id: str,
    candidate_id: str,
    successor_created_at: str,
    readiness: ReadinessStatus,
) -> None:
    lineage = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(lineage, dict):
        raise ValueError("lineage data must be an object")
    existing = lineage.get("parent_ids", [])
    if not isinstance(existing, list) or any(not isinstance(item, str) for item in existing):
        raise ValueError("lineage parent_ids must be a string list")
    lineage["package_id"] = successor_id
    lineage["created_at"] = successor_created_at
    lineage["status"] = PackageStatus.CANONICAL.value
    lineage["readiness"] = readiness.value
    lineage["parent_ids"] = sorted(set(existing) | {candidate_id})
    path.unlink()
    _write_json_new(path, lineage)


def _package_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for record in inventory_tree(root, source_id="package-sha256"):
        digest.update(record.normalized_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(record.sha256))
    checksum = root / "SHA256SUMS.txt"
    if _is_regular_file(checksum):
        digest.update(b"SHA256SUMS.txt\0")
        digest.update(bytes.fromhex(sha256_file(checksum)))
    return digest.hexdigest()


def _lineage_roots(lineage: Mapping[str, object]) -> tuple[str, ...]:
    roots = lineage.get("root_package_ids", ())
    if isinstance(roots, list) and all(isinstance(item, str) for item in roots):
        return tuple(sorted(roots))
    parents = lineage.get("parent_ids", ())
    if isinstance(parents, list) and all(isinstance(item, str) for item in parents):
        return tuple(sorted(parents))
    return ()


def _validate_tree_types(root: Path, violations: list[str]) -> None:
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                violations.append(f"package contains a symlink: {path.relative_to(root).as_posix()}")
            elif not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                violations.append(f"package contains a special file: {path.relative_to(root).as_posix()}")


def _read_json_object(
    path: Path, display_path: str, violations: list[str]
) -> dict[str, object] | None:
    if not _is_regular_file(path):
        violations.append(f"required JSON artifact is absent or unsafe: {display_path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        violations.append(f"required JSON artifact is invalid: {display_path}")
        return None
    if not isinstance(value, dict):
        violations.append(f"required JSON artifact must be an object: {display_path}")
        return None
    return value


def _write_json_new(path: Path, value: Mapping[str, object]) -> None:
    _write_bytes_new(path, _json_bytes(value))


def _write_bytes_new(path: Path, content: bytes) -> None:
    with path.open("xb") as output:
        output.write(content)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _approval_to_dict(approval: ApprovalRecord) -> dict[str, object]:
    return {
        "approval_id": approval.approval_id,
        "action": approval.action,
        "scope": list(approval.scope),
        "decision": approval.decision,
        "source_id": approval.source_id,
        "source_ref": approval.source_ref,
        "approved_at": approval.approved_at,
    }


def _exact_promotion_approval(approval: ApprovalRecord | None, package_id: str) -> bool:
    return bool(
        approval is not None
        and approval.action == "promote-candidate"
        and approval.scope == (package_id,)
        and _normalize(approval.decision) in _APPROVED_DECISIONS
        and approval.approval_id.strip()
        and approval.source_id.strip()
        and approval.source_ref.strip()
        and _is_rfc3339(approval.approved_at)
    )


def _is_regular_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _is_regular_directory(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _is_package_id(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value.strip()
        and value == value.strip()
        and value not in {".", ".."}
        and not any(character in value for character in "/\\\x00")
    )


def _enum_value(enum: type, value: object, label: str, violations: list[str]):
    try:
        return enum(value)
    except (TypeError, ValueError):
        violations.append(f"{label} is invalid")
        return None


def _nonempty_string(value: object, label: str, violations: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        violations.append(f"{label} must be non-empty text")
        return None
    return value


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError("selected_source_hashes must be a string mapping")
    return dict(value)


def _validate_lineage_structure(
    lineage: Mapping[str, object], violations: list[str]
) -> None:
    if lineage.get("schema") != "continuity.lineage/v1":
        violations.append("lineage schema must be continuity.lineage/v1")
    _nonempty_string(lineage.get("package_id"), "lineage package_id", violations)
    _nonempty_string(lineage.get("project_id"), "lineage project_id", violations)
    _rfc3339_value(lineage.get("created_at"), "lineage created_at", violations)
    _enum_value(PackageStatus, lineage.get("status"), "lineage status", violations)
    _enum_value(ReadinessStatus, lineage.get("readiness"), "lineage readiness", violations)
    _validate_string_list(lineage.get("parent_ids"), "lineage parent_ids", violations)
    _validate_source_hashes(lineage.get("source_hashes"), "lineage source_hashes", violations)


def _validate_evidence_structure(
    evidence: Mapping[str, object], violations: list[str]
) -> None:
    if evidence.get("schema") != "continuity.evidence-index/v1":
        violations.append("evidence schema must be continuity.evidence-index/v1")
    items = evidence.get("items")
    if not isinstance(items, list) or not items:
        violations.append("evidence items must be a non-empty list")
        return
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            violations.append(f"evidence item {index} must be an object")
            continue
        _nonempty_string(item.get("source_id"), f"evidence item {index} source_id", violations)
        _nonempty_string(item.get("reference"), f"evidence item {index} reference", violations)
        _enum_value(EvidenceState, item.get("state"), f"evidence item {index} state", violations)


def _validate_reconciliation_structure(
    reconciliation: Mapping[str, object], violations: list[str]
) -> None:
    list_fields = (
        "claims",
        "conflicts",
        "findings",
        "approvals",
        "selected_claim_ids",
        "blocking_conflict_ids",
        "notes",
    )
    for field in list_fields:
        if not isinstance(reconciliation.get(field), list):
            violations.append(f"reconciliation {field} must be a list")
    if isinstance(reconciliation.get("findings"), list) and not reconciliation["findings"]:
        violations.append("reconciliation findings must be non-empty")


def _validate_promotion_receipt(
    receipt: Mapping[str, object], package_id: str | None, violations: list[str]
) -> None:
    if receipt.get("schema") != "continuity.promotion-receipt/v1":
        violations.append("promotion receipt schema is invalid")
    _nonempty_string(
        receipt.get("candidate_package_id"),
        "promotion receipt candidate_package_id",
        violations,
    )
    candidate_hash = receipt.get("candidate_sha256")
    if not _is_sha256(candidate_hash):
        violations.append("promotion receipt candidate_sha256 is invalid")
    if receipt.get("canonical_package_id") != package_id:
        violations.append("promotion receipt canonical_package_id does not match manifest")
    approval = receipt.get("approval")
    if not isinstance(approval, Mapping):
        violations.append("promotion receipt approval must be an object")
        return
    for field in ("approval_id", "source_id", "source_ref"):
        _nonempty_string(approval.get(field), f"promotion approval {field}", violations)
    _rfc3339_value(approval.get("approved_at"), "promotion approval approved_at", violations)
    if approval.get("action") != "promote-candidate":
        violations.append("promotion approval action is invalid")
    scope = approval.get("scope")
    if not isinstance(scope, list) or len(scope) != 1 or scope[0] != receipt.get(
        "candidate_package_id"
    ):
        violations.append("promotion approval scope is invalid")
    if not isinstance(approval.get("decision"), str) or _normalize(
        approval["decision"]
    ) not in _APPROVED_DECISIONS:
        violations.append("promotion approval decision is invalid")


def _validate_source_hashes(value: object, label: str, violations: list[str]) -> None:
    if not isinstance(value, Mapping) or not value:
        violations.append(f"{label} must be a non-empty mapping")
        return
    for source_id, digest in value.items():
        if not isinstance(source_id, str) or not source_id.strip() or not _is_sha256(digest):
            violations.append(f"{label} must map non-empty source IDs to SHA-256 values")
            return


def _validate_string_list(value: object, label: str, violations: list[str]) -> None:
    if not isinstance(value, list):
        violations.append(f"{label} must be a list")
        return
    if any(not isinstance(item, str) or not item.strip() for item in value):
        violations.append(f"{label} must contain non-empty text")
    elif len(value) != len(set(value)) or value != sorted(value):
        violations.append(f"{label} must be unique and sorted")


def _valid_lifecycle_pair(
    status: PackageStatus | None, readiness: ReadinessStatus | None
) -> bool:
    allowed = {
        PackageStatus.CANDIDATE: {ReadinessStatus.READY, ReadinessStatus.CONDITIONAL},
        PackageStatus.BLOCKED: {ReadinessStatus.BLOCKED},
        PackageStatus.CANONICAL: {ReadinessStatus.READY, ReadinessStatus.CONDITIONAL},
        PackageStatus.SUPERSEDED: {ReadinessStatus.BLOCKED},
    }
    return status in allowed and readiness in allowed[status]


def _rfc3339_value(value: object, label: str, violations: list[str]) -> str | None:
    if not _is_rfc3339(value):
        violations.append(f"{label} must be deterministic RFC3339 text")
        return None
    return value


def _is_rfc3339(value: object) -> bool:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _is_exact_normalized_package_path(value: object) -> bool:
    if not isinstance(value, str) or any(character in value for character in "*?[]"):
        return False
    try:
        return normalize_relative_path(value) == value
    except ValueError:
        return False


def _normalize(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").casefold().split())
