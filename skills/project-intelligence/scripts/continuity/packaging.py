"""Atomic, reproducible construction and approval-gated promotion of handoffs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import zipfile

from .hashing import inventory_tree, sha256_file, verify_sha256s, write_sha256s
from .models import ApprovalRecord, PackageStatus, ReadinessStatus
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
_ZERO_SHA256 = "0" * 64
_APPROVED_DECISIONS = frozenset({"allow", "allowed", "approve", "approved"})


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
    root: Path
    zip_path: Path
    package_id: str
    status: PackageStatus
    package_sha256: str


def build_candidate(request: CandidateBuildRequest) -> CandidateResult:
    """Build, validate, and atomically publish a candidate or blocked package."""

    output, zip_output = _validate_output_paths(request.output)
    _validate_request(request)
    status = (
        PackageStatus.BLOCKED
        if request.approved_reconciliation_report.blocking_conflicts
        or request.readiness is ReadinessStatus.BLOCKED
        else PackageStatus.CANDIDATE
    )
    workspace = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.continuity-build-", dir=output.parent)
    )
    package_root = workspace / "package"
    temporary_zip = workspace / "package.zip"
    published_root = False
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
        _write_json_new(package_root / "lineage/LINEAGE.json", request.lineage_data)
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
            readiness=request.readiness,
            selected_source_hashes=request.selected_source_hashes,
            lineage_roots=_lineage_roots(request.lineage_data),
            allow_conditional_promotion=request.allow_conditional_promotion,
        )
        write_sha256s(package_root, package_root / "SHA256SUMS.txt")
        validation = validate_package(package_root)
        if not validation.valid:
            raise ValueError("constructed package is invalid: " + "; ".join(validation.violations))
        _write_reproducible_zip(package_root, temporary_zip)
        os.replace(package_root, output)
        published_root = True
        os.replace(temporary_zip, zip_output)
        return CandidateResult(
            root=output,
            zip_path=zip_output,
            package_id=request.package_id,
            status=status,
            package_sha256=_package_sha256(output),
        )
    except Exception:
        if published_root:
            shutil.rmtree(output)
        if zip_output.exists():
            zip_output.unlink()
        raise
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


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

    for path in ("lineage/LINEAGE.json", "evidence/INDEX.json", "receipts/RECONCILIATION.json"):
        _read_json_object(root / path, path, violations)
    manifest = _read_json_object(root / "MANIFEST.json", "MANIFEST.json", violations)
    if manifest is not None:
        package_id = _nonempty_string(manifest.get("package_id"), "manifest package_id", violations)
        status = _enum_value(PackageStatus, manifest.get("status"), "manifest status", violations)
        readiness = _enum_value(
            ReadinessStatus, manifest.get("readiness"), "manifest readiness", violations
        )
        if manifest.get("schema") != "continuity.package/v1":
            violations.append("manifest schema must be continuity.package/v1")
        _validate_manifest_inventory(root, manifest, violations)
        if status in {PackageStatus.CANDIDATE, PackageStatus.CANONICAL} and readiness is ReadinessStatus.BLOCKED:
            violations.append("blocked readiness cannot carry Candidate or Canonical status")

    reconciliation = _read_json_object(
        root / "receipts/RECONCILIATION.json", "receipts/RECONCILIATION.json", []
    )
    if (
        reconciliation is not None
        and reconciliation.get("blocking_conflict_ids")
        and status in {PackageStatus.CANDIDATE, PackageStatus.CANONICAL}
    ):
        violations.append("blocking reconciliation cannot carry Candidate or Canonical status")

    lineage = _read_json_object(root / "lineage/LINEAGE.json", "lineage/LINEAGE.json", [])
    if lineage is not None and package_id is not None and lineage.get("package_id") != package_id:
        violations.append("lineage package_id does not match manifest")
    if lineage is not None and manifest is not None:
        if lineage.get("source_hashes") != manifest.get("selected_source_hashes"):
            violations.append("lineage source hashes do not match manifest selected sources")

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

    output, zip_output = _validate_output_paths(output)
    successor_id = output.name
    if not successor_id or successor_id == validation.package_id:
        raise ValueError("canonical successor must have a new package ID")
    candidate_sha256 = _package_sha256(candidate)
    workspace = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.continuity-promote-", dir=output.parent)
    )
    successor_root = workspace / "package"
    temporary_zip = workspace / "package.zip"
    published_root = False
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
            successor_root / "lineage/LINEAGE.json", successor_id, validation.package_id
        )
        _write_manifest(
            successor_root,
            package_id=successor_id,
            project_id=str(manifest["project_id"]),
            created_at=str(manifest["created_at"]),
            status=PackageStatus.CANONICAL,
            readiness=validation.readiness,
            selected_source_hashes=_string_mapping(manifest.get("selected_source_hashes")),
            lineage_roots=tuple(str(item) for item in manifest.get("lineage_roots", ())),
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
        os.replace(successor_root, output)
        published_root = True
        os.replace(temporary_zip, zip_output)
        return PromotionResult(
            root=output,
            zip_path=zip_output,
            package_id=successor_id,
            status=PackageStatus.CANONICAL,
            package_sha256=_package_sha256(output),
        )
    except Exception:
        if published_root:
            shutil.rmtree(output)
        if zip_output.exists():
            zip_output.unlink()
        raise
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _validate_request(request: CandidateBuildRequest) -> None:
    if not request.package_id.strip() or not request.project_id.strip() or not request.created_at.strip():
        raise ValueError("package_id, project_id, and created_at must be non-empty")
    if set(request.rendered_documents) != set(_DOCUMENT_PATHS):
        raise ValueError("rendered documents must contain exactly the v1 document paths")
    if any(not isinstance(text, str) or not text.strip() for text in request.rendered_documents.values()):
        raise ValueError("rendered documents must be non-empty text")
    if not isinstance(request.readiness, ReadinessStatus):
        raise ValueError("readiness must be a ReadinessStatus")
    if not request.selected_source_hashes:
        raise ValueError("selected source hashes must not be empty")
    for source_id, digest in request.selected_source_hashes.items():
        if not source_id.strip() or not _is_sha256(digest):
            raise ValueError("selected source hashes must map non-empty IDs to SHA-256 values")
    if not isinstance(request.lineage_data, Mapping) or not isinstance(request.evidence_index, Mapping):
        raise ValueError("lineage data and evidence index must be objects")
    if request.lineage_data.get("source_hashes") != dict(request.selected_source_hashes):
        raise ValueError("lineage source hashes must match selected source hashes")
    try:
        json.dumps(request.lineage_data)
        json.dumps(request.evidence_index)
        json.dumps(request.approved_reconciliation_report.to_dict())
    except (TypeError, ValueError) as error:
        raise ValueError("structured package inputs must be JSON serializable") from error


def _validate_output_paths(output: Path) -> tuple[Path, Path]:
    output = Path(output)
    if not output.name:
        raise ValueError("output must name a package directory")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"output parent does not exist: {output.parent}")
    zip_output = output.with_suffix(".zip")
    if os.path.lexists(output) or os.path.lexists(zip_output):
        raise FileExistsError("package output or ZIP already exists")
    return output, zip_output


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
    accepted_paths = {destination, f"canonical/{destination}"}
    exact = any(
        _normalize(approval.action) == "secure handling"
        and _normalize(approval.decision) in _APPROVED_DECISIONS
        and any(path in accepted_paths for path in approval.scope)
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
    self_entry = {"path": "MANIFEST.json", "sha256": _ZERO_SHA256, "size_bytes": 0}
    files.append(self_entry)
    files.sort(key=lambda item: str(item["path"]))
    for _ in range(8):
        self_entry["sha256"] = _manifest_self_digest(manifest)
        encoded = _json_bytes(manifest)
        if self_entry["size_bytes"] == len(encoded):
            break
        self_entry["size_bytes"] = len(encoded)
    self_entry["sha256"] = _manifest_self_digest(manifest)
    encoded = _json_bytes(manifest)
    if self_entry["size_bytes"] != len(encoded):
        raise ValueError("manifest size did not stabilize")
    _write_bytes_new(root / "MANIFEST.json", encoded)


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
        expected_digest = (
            _manifest_self_digest(manifest) if path == "MANIFEST.json" else record.sha256
        )
        if digest != expected_digest:
            violations.append(f"manifest digest differs for {path}")


def _manifest_self_digest(manifest: Mapping[str, object]) -> str:
    normalized = json.loads(json.dumps(manifest))
    files = normalized.get("files", [])
    for item in files:
        if isinstance(item, dict) and item.get("path") == "MANIFEST.json":
            item["sha256"] = _ZERO_SHA256
    return hashlib.sha256(_json_bytes(normalized)).hexdigest()


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


def _update_successor_lineage(path: Path, successor_id: str, candidate_id: str) -> None:
    lineage = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(lineage, dict):
        raise ValueError("lineage data must be an object")
    existing = lineage.get("parent_ids", [])
    if not isinstance(existing, list) or any(not isinstance(item, str) for item in existing):
        raise ValueError("lineage parent_ids must be a string list")
    lineage["package_id"] = successor_id
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
        and approval.approved_at.strip()
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


def _normalize(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").casefold().split())
