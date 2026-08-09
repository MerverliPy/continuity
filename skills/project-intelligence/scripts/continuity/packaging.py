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
from .models import (
    ApprovalRecord,
    ClaimRecord,
    ConflictRecord,
    EvidenceState,
    PackageStatus,
    PreflightRecord,
    ReadinessStatus,
)
from .paths import normalize_relative_path
from .reconciliation import IntegrityFinding, ReconciliationReport
from .redaction import redact_text
from .readiness import classify_readiness


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
        "receipts/PREFLIGHT.json",
        "receipts/DOCUMENT_INPUTS.json",
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
_ASSETS_ROOT = Path(__file__).resolve().parents[2] / "assets"
_SCHEMA_PATHS = {
    "manifest": _ASSETS_ROOT / "schemas/manifest.schema.json",
    "lineage": _ASSETS_ROOT / "schemas/lineage.schema.json",
    "evidence": _ASSETS_ROOT / "schemas/evidence-index.schema.json",
    "reconciliation": _ASSETS_ROOT / "schemas/reconciliation.schema.json",
    "preflight": _ASSETS_ROOT / "schemas/preflight.schema.json",
    "document-inputs": _ASSETS_ROOT / "schemas/document-inputs.schema.json",
}
_TEMPLATE_ROOT = _ASSETS_ROOT / "templates"
_TEMPLATE_TOKEN_CONTENT = re.compile(r"\s*([a-z][a-z0-9_]*)\s*")


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
    preflight_decision: PreflightRecord
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
    rendered_documents = _render_documents(request, status, readiness)
    document_inputs = _document_inputs(request.rendered_documents)
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
            _write_bytes_new(package_root / path, rendered_documents[path].encode("utf-8"))

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
        _write_json_new(
            package_root / "receipts/PREFLIGHT.json",
            request.preflight_decision.to_dict(),
        )
        _write_json_new(
            package_root / "receipts/DOCUMENT_INPUTS.json",
            document_inputs,
        )
        artifact_violations: list[str] = []
        _validate_json_artifacts(package_root, artifact_violations, include_manifest=False)
        if artifact_violations:
            raise ValueError(
                "structured package artifacts are invalid: "
                + "; ".join(artifact_violations)
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
        artifact_violations = []
        _validate_json_artifacts(package_root, artifact_violations, include_manifest=True)
        if not artifact_violations:
            _validate_completed_documents(package_root, artifact_violations)
        if artifact_violations:
            raise ValueError(
                "structured package artifacts are invalid: "
                + "; ".join(artifact_violations)
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
    """Independently verify a package without leaking structural exceptions."""

    try:
        return _validate_package(Path(root))
    except (KeyError, TypeError, ValueError):
        return PackageValidation(
            False,
            ("package structured validation failed",),
        )


def _validate_package(root: Path) -> PackageValidation:
    """Verify structure, lifecycle, structured authority, and checksum bytes."""

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
    preflight = _read_json_object(
        root / "receipts/PREFLIGHT.json",
        "receipts/PREFLIGHT.json",
        violations,
    )
    document_inputs = _read_json_object(
        root / "receipts/DOCUMENT_INPUTS.json",
        "receipts/DOCUMENT_INPUTS.json",
        violations,
    )
    manifest = _read_json_object(root / "MANIFEST.json", "MANIFEST.json", violations)
    schema_violations: list[str] = []
    for artifact, schema_name, label in (
        (lineage, "lineage", "lineage"),
        (evidence_index, "evidence", "evidence"),
        (reconciliation, "reconciliation", "reconciliation"),
        (preflight, "preflight", "preflight"),
        (document_inputs, "document-inputs", "document inputs"),
        (manifest, "manifest", "manifest"),
    ):
        if artifact is not None:
            _validate_against_schema(
                artifact, schema_name, label, schema_violations
            )
    violations.extend(schema_violations)
    structured_artifacts_are_valid = not schema_violations and all(
        artifact is not None
        for artifact in (
            lineage,
            evidence_index,
            reconciliation,
            preflight,
            document_inputs,
            manifest,
        )
    )
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
        successor_created_at = manifest.get("successor_created_at")
        if status in {PackageStatus.CANONICAL, PackageStatus.SUPERSEDED}:
            _rfc3339_value(
                successor_created_at,
                "manifest successor_created_at",
                violations,
            )
            _nonempty_string(
                manifest.get("predecessor_package_id"),
                "manifest predecessor_package_id",
                violations,
            )
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
        _validate_selected_project_identity(reconciliation, project_id, violations)
    if preflight is not None and manifest is not None:
        if preflight.get("project_id") != project_id:
            violations.append("preflight project_id does not match manifest")
        if preflight.get("package_id") != package_id:
            violations.append("preflight package_id does not match manifest")
        if preflight.get("status") != manifest.get("readiness"):
            violations.append("preflight readiness does not match manifest")
    if (
        structured_artifacts_are_valid
        and reconciliation is not None
        and preflight is not None
    ):
        if not _serialized_preflight_matches_report(preflight, reconciliation):
            violations.append("preflight authority does not match reconciliation")
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
        if lineage.get("root_package_ids") != manifest.get("lineage_roots"):
            violations.append("lineage roots do not match manifest lineage_roots")
        if lineage.get("successor_created_at") != manifest.get("successor_created_at"):
            violations.append(
                "lineage successor_created_at does not match manifest successor_created_at"
            )

    if status is PackageStatus.CANONICAL:
        promotion = _read_json_object(
            root / "receipts/PROMOTION.json", "receipts/PROMOTION.json", violations
        )
        if promotion is not None:
            _validate_promotion_receipt(promotion, package_id, violations)

    if (
        structured_artifacts_are_valid
        and manifest is not None
        and reconciliation is not None
        and preflight is not None
        and document_inputs is not None
    ):
        _validate_document_reproduction(
            root,
            manifest,
            reconciliation,
            preflight,
            document_inputs,
            violations,
        )

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
        _update_successor_preflight(
            successor_root / "receipts/PREFLIGHT.json",
            candidate_id=validation.package_id,
            successor_id=successor_id,
        )
        successor_lineage = json.loads(
            (successor_root / "lineage/LINEAGE.json").read_text(encoding="utf-8")
        )
        _rerender_documents_from_package(
            successor_root,
            {
                "package_id": successor_id,
                "project_id": str(manifest["project_id"]),
                "created_at": successor_created_at,
                "status": PackageStatus.CANONICAL.value,
                "readiness": validation.readiness.value,
            },
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
            successor_created_at=successor_created_at,
        )
        artifact_violations: list[str] = []
        _validate_json_artifacts(successor_root, artifact_violations, include_manifest=True)
        if not artifact_violations:
            _validate_completed_documents(successor_root, artifact_violations)
        if artifact_violations:
            raise ValueError(
                "promoted structured artifacts are invalid: "
                + "; ".join(artifact_violations)
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
    if not isinstance(request.preflight_decision, PreflightRecord):
        raise ValueError("preflight_decision must be a PreflightRecord")
    if request.preflight_decision.project_id != request.project_id:
        raise ValueError("preflight project_id must match request project_id")
    if request.preflight_decision.package_id != request.package_id:
        raise ValueError("preflight package_id must match request package_id")
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
    if request.lineage_data.get("status") != PackageStatus.CANDIDATE.value:
        raise ValueError("lineage status must be Candidate in a build request")
    lineage_violations: list[str] = []
    _validate_lineage_structure(request.lineage_data, lineage_violations)
    if request.lineage_data.get("package_id") != request.package_id:
        lineage_violations.append("lineage package_id must match request package_id")
    if request.lineage_data.get("project_id") != request.project_id:
        lineage_violations.append("lineage project_id must match request project_id")
    if request.lineage_data.get("created_at") != request.created_at:
        lineage_violations.append("lineage created_at must match request created_at")
    if request.lineage_data.get("readiness") != request.readiness.value:
        lineage_violations.append("lineage readiness must match request readiness")
    if lineage_violations:
        raise ValueError(lineage_violations[0])
    evidence_violations: list[str] = []
    _validate_evidence_structure(request.evidence_index, evidence_violations)
    if evidence_violations:
        raise ValueError(evidence_violations[0])
    try:
        reconciliation = request.approved_reconciliation_report.to_dict()
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("reconciliation report is not structurally valid") from error
    reconciliation_violations: list[str] = []
    _validate_reconciliation_structure(reconciliation, reconciliation_violations)
    _validate_selected_project_identity(
        reconciliation, request.project_id, reconciliation_violations
    )
    if reconciliation_violations:
        raise ValueError(reconciliation_violations[0])
    effective_readiness = (
        ReadinessStatus.BLOCKED
        if request.approved_reconciliation_report.blocking_conflicts
        else request.readiness
    )
    if request.preflight_decision.status is not effective_readiness:
        raise ValueError("preflight status must match request readiness")
    preflight_violations = validate_preflight_record(request.preflight_decision)
    if preflight_violations:
        raise ValueError(preflight_violations[0])
    if not _preflight_matches_report(
        request.preflight_decision,
        request.approved_reconciliation_report,
    ):
        raise ValueError("preflight_decision does not match reconciliation authority")
    try:
        json.dumps(request.lineage_data)
        json.dumps(request.evidence_index)
        json.dumps(reconciliation)
    except (TypeError, ValueError) as error:
        raise ValueError("structured package inputs must be JSON serializable") from error
    for artifact, schema_name, label in (
        (request.lineage_data, "lineage", "lineage"),
        (request.evidence_index, "evidence", "evidence"),
        (reconciliation, "reconciliation", "reconciliation"),
        (
            _document_inputs(request.rendered_documents),
            "document-inputs",
            "document inputs",
        ),
    ):
        schema_violations: list[str] = []
        _validate_against_schema(artifact, schema_name, label, schema_violations)
        if schema_violations:
            raise ValueError(schema_violations[0])


def _render_documents(
    request: CandidateBuildRequest,
    status: PackageStatus,
    readiness: ReadinessStatus,
) -> dict[str, str]:
    identity = {
        "package_id": request.package_id,
        "project_id": request.project_id,
        "created_at": request.created_at,
        "status": status.value,
        "readiness": readiness.value,
    }
    return _render_documents_from_structured_inputs(
        identity,
        request.approved_reconciliation_report.to_dict(),
        request.preflight_decision.to_dict(),
        _document_inputs(request.rendered_documents),
    )


def _document_inputs(narratives: Mapping[str, str]) -> dict[str, object]:
    return {
        "schema": "continuity.document-inputs/v1",
        "supplemental_narrative": dict(narratives),
    }


def _render_documents_from_structured_inputs(
    identity: Mapping[str, object],
    report: Mapping[str, object],
    preflight: Mapping[str, object],
    document_inputs: Mapping[str, object],
) -> dict[str, str]:
    narratives = document_inputs["supplemental_narrative"]
    if not isinstance(narratives, Mapping):
        raise ValueError("document supplemental_narrative must be an object")
    claim_rows = _selected_claim_rows(report)
    approval_rows = _approval_rows(report)
    conflict_rows = _conflict_rows(report)
    unresolved_rows = _unresolved_rows(report, preflight)
    package_id = str(identity["package_id"])
    project_id = str(identity["project_id"])
    created_at = str(identity["created_at"])
    status = str(identity["status"])
    readiness = str(identity["readiness"])
    exact_next_action = preflight.get("exact_next_action")
    companion = preflight.get("companion_skill_or_stage")
    lifecycle_notice = {
        PackageStatus.CANONICAL.value: (
            "> Promotion record: This package is Canonical. Its Candidate predecessor "
            "was not Canonical before exact, scoped approval."
        ),
        PackageStatus.BLOCKED.value: (
            "> Current package: This package is Blocked and cannot be routed to execution."
        ),
    }.get(
        status,
        "> Current package: This Candidate is not Canonical and is not authoritative.",
    )
    token_values = {
        "HANDOFF_README.md": {
            "package_id": package_id,
            "project_id": project_id,
            "created_at": created_at,
            "status": status,
            "readiness": readiness,
            "lifecycle_notice": lifecycle_notice,
            "supplemental_narrative": _supplemental_narrative(
                narratives["HANDOFF_README.md"]
            ),
        },
        "CANONICAL_STATE.md": {
            "selected_claim_records": "\n".join(claim_rows),
            "supplemental_narrative": _supplemental_narrative(
                narratives["CANONICAL_STATE.md"]
            ),
        },
        "AUTHORITY_LEDGER.md": {
            "approval_records": "\n".join(approval_rows),
            "allowed_actions": _markdown_list(
                _preflight_value(preflight, "authorized_actions")
            ),
            "prohibited_actions": _markdown_list(
                _preflight_value(preflight, "prohibited_actions")
            ),
            "unresolved_actions": _markdown_list(
                _preflight_value(preflight, "unresolved_actions")
            ),
            "supplemental_narrative": _supplemental_narrative(
                narratives["AUTHORITY_LEDGER.md"]
            ),
        },
        "CONFLICT_RESOLUTIONS.md": {
            "conflict_records": "\n".join(conflict_rows),
            "supplemental_narrative": _supplemental_narrative(
                narratives["CONFLICT_RESOLUTIONS.md"]
            ),
        },
        "UNRESOLVED.md": {
            "unresolved_records": "\n".join(unresolved_rows),
            "unresolved_summary": _unresolved_summary(report, preflight),
            "supplemental_narrative": _supplemental_narrative(
                narratives["UNRESOLVED.md"]
            ),
        },
        "NEXT_THREAD_PROMPT.txt": {
            "project_id": project_id,
            "package_id": package_id,
            "readiness": readiness,
            "exact_next_action": _display_optional(
                exact_next_action if isinstance(exact_next_action, str) else None
            ),
            "supplemental_narrative": _supplemental_narrative(
                narratives["NEXT_THREAD_PROMPT.txt"]
            ),
        },
        "SUPERPOWERS_PREFLIGHT.md": {
            "project_id": project_id,
            "package_id": package_id,
            "readiness": readiness,
            "exact_next_action": _display_optional(
                exact_next_action if isinstance(exact_next_action, str) else None
            ),
            "companion_skill_or_stage": _display_optional(
                companion if isinstance(companion, str) else None
            ),
            "reasons": _markdown_list(_preflight_value(preflight, "reasons")),
            "conditions": _markdown_list(_preflight_value(preflight, "conditions")),
            "authorized_actions": _markdown_list(
                _preflight_value(preflight, "authorized_actions")
            ),
            "prohibited_actions": _markdown_list(
                _preflight_value(preflight, "prohibited_actions")
            ),
            "unresolved_actions": _markdown_list(
                _preflight_value(preflight, "unresolved_actions")
            ),
            "evidence_references": _markdown_list(
                _preflight_value(preflight, "evidence_references")
            ),
            "supplemental_narrative": _supplemental_narrative(
                narratives["SUPERPOWERS_PREFLIGHT.md"]
            ),
        },
    }
    rendered: dict[str, str] = {}
    for document_path in _DOCUMENT_PATHS:
        template = _read_asset_text(_TEMPLATE_ROOT / document_path, "template")
        rendered[document_path] = _render_template(template, token_values[document_path])
        if not rendered[document_path].strip():
            raise ValueError(f"rendered template is empty: {document_path}")
    return rendered


def _supplemental_narrative(value: object) -> str:
    """Keep caller prose visibly quoted and outside governing Markdown sections."""

    lines = str(value).splitlines()
    return "\n".join(f"> {line}" if line else ">" for line in lines) or ">"


def _selected_claim_rows(report: ReconciliationReport | Mapping[str, object]) -> list[str]:
    claims, selected = _report_claims_and_selected(report)
    rows = [
        "| "
        + " | ".join(
            (
                _markdown_text(claim["field"]),
                _markdown_value(claim["value"]),
                _markdown_text(claim["evidence_state"]),
                _markdown_text(
                    f'{claim["source_id"]} — {claim["source_ref"]}'
                ),
                _markdown_text(claim["claim_id"]),
            )
        )
        + " |"
        for claim in claims
        if claim.get("claim_id") in selected
    ]
    return rows or [
        "| No selected claims | null | Missing | "
        "receipts/RECONCILIATION.json | selected-claims-missing |"
    ]


def _approval_rows(report: ReconciliationReport | Mapping[str, object]) -> list[str]:
    approvals = _report_records(report, "approvals")
    rows = [
        "| "
        + " | ".join(
            (
                _markdown_text(f'{item["action"]}: {item["decision"]}'),
                _markdown_value(item["scope"]),
                EvidenceState.ASSERTED.value,
                _markdown_text(f'{item["source_id"]} — {item["source_ref"]}'),
                _markdown_text(item["approval_id"]),
            )
        )
        + " |"
        for item in approvals
    ]
    return rows or [
        "| No approvals recorded | [] | Missing | "
        "receipts/RECONCILIATION.json | approvals-missing |"
    ]


def _conflict_rows(report: ReconciliationReport | Mapping[str, object]) -> list[str]:
    conflicts = _report_records(report, "conflicts")
    approvals = {
        item.get("approval_id"): item for item in _report_records(report, "approvals")
    }
    rows: list[str] = []
    for item in conflicts:
        resolution_id = item.get("resolution_approval_id")
        approval = approvals.get(resolution_id)
        source = (
            f'{approval["source_id"]} — {approval["source_ref"]}'
            if approval is not None
            else "receipts/RECONCILIATION.json"
        )
        state = "Resolved" if resolution_id is not None else "Unresolved"
        rows.append(
            "| "
            + " | ".join(
                (
                    _markdown_text(item["field"]),
                    _markdown_value(item["claim_ids"]),
                    state if item.get("material") is True else "Non-material",
                    _markdown_text(resolution_id or "Unresolved"),
                    _markdown_text(source),
                    _markdown_text(item["conflict_id"]),
                )
            )
            + " |"
        )
    return rows or [
        "| No conflicts recorded | [] | Non-material | Unresolved | "
        "receipts/RECONCILIATION.json | conflicts-none |"
    ]


def _unresolved_rows(
    report: ReconciliationReport | Mapping[str, object],
    preflight: PreflightRecord | Mapping[str, object],
) -> list[str]:
    rows: list[str] = []
    for claim in _report_records(report, "claims"):
        state = claim.get("evidence_state")
        if state not in {
            EvidenceState.UNRESOLVED.value,
            EvidenceState.CONTRADICTED.value,
            EvidenceState.MISSING.value,
        }:
            continue
        rows.append(
            _unresolved_row(
                claim.get("field"),
                "May change an authorized next action",
                state,
                f'{claim.get("source_id")} — {claim.get("source_ref")}',
                claim.get("claim_id"),
            )
        )
    for finding in _report_records(report, "findings"):
        if _finding_permits_automatic_selection(finding):
            continue
        rows.append(
            _unresolved_row(
                finding.get("detail") or "integrity finding",
                "Blocks trusted package use",
                finding.get("evidence_state"),
                f'{finding.get("source_id")} — receipts/RECONCILIATION.json',
                finding.get("finding_id"),
            )
        )
    for conflict in _report_records(report, "conflicts"):
        if conflict.get("material") is True and conflict.get(
            "resolution_approval_id"
        ) is None:
            rows.append(
                _unresolved_row(
                    conflict.get("field"),
                    "Blocks promotion and execution",
                    EvidenceState.UNRESOLVED.value,
                    "receipts/RECONCILIATION.json",
                    conflict.get("conflict_id"),
                )
            )
    for index, action in enumerate(_preflight_value(preflight, "unresolved_actions")):
        rows.append(
            _unresolved_row(
                action,
                "Requires readiness clarification",
                EvidenceState.UNRESOLVED.value,
                "receipts/PREFLIGHT.json",
                f"preflight-unresolved-{index + 1}",
            )
        )
    return rows or [
        "| No unresolved records | No known impact | Verified | "
        "receipts/RECONCILIATION.json | unresolved-none |"
    ]


def _finding_permits_automatic_selection(finding: Mapping[str, object]) -> bool:
    state_verified = finding.get("evidence_state") == EvidenceState.VERIFIED.value
    structurally_valid = finding.get("structurally_valid")
    structural_gate = (
        state_verified if structurally_valid is None else structurally_valid is True
    )
    lineage_valid = finding.get("lineage_valid")
    lineage_required = finding.get("lineage_required") is True
    lineage_gate = lineage_valid is not False and (
        not lineage_required or lineage_valid is True
    )
    return state_verified and structural_gate and lineage_gate


def _unresolved_row(
    description: object,
    impact: object,
    state: object,
    source: object,
    record_id: object,
) -> str:
    return "| " + " | ".join(
        _markdown_text(value)
        for value in (description, impact, state, source, record_id)
    ) + " |"


def _unresolved_summary(
    report: ReconciliationReport | Mapping[str, object],
    preflight: PreflightRecord | Mapping[str, object],
) -> str:
    record_ids = [
        row.rsplit(" | ", 2)[1]
        for row in _unresolved_rows(report, preflight)
        if "unresolved-none" not in row
    ]
    return _markdown_list(record_ids)


def _markdown_list(values: Sequence[object]) -> str:
    return "\n".join(f"- {_markdown_text(value)}" for value in values) or "- None."


def _markdown_text(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _markdown_value(value: object) -> str:
    return _markdown_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


def _display_optional(value: str | None) -> str:
    return value if value is not None else "null"


def _report_mapping(
    report: ReconciliationReport | Mapping[str, object],
) -> Mapping[str, object]:
    return report.to_dict() if isinstance(report, ReconciliationReport) else report


def _report_records(
    report: ReconciliationReport | Mapping[str, object], field: str
) -> list[Mapping[str, object]]:
    value = _report_mapping(report).get(field)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _report_claims_and_selected(
    report: ReconciliationReport | Mapping[str, object],
) -> tuple[list[Mapping[str, object]], set[object]]:
    mapping = _report_mapping(report)
    selected = mapping.get("selected_claim_ids")
    return (
        _report_records(mapping, "claims"),
        set(selected) if isinstance(selected, list) else set(),
    )


def _preflight_mapping(
    preflight: PreflightRecord | Mapping[str, object],
) -> Mapping[str, object]:
    return preflight.to_dict() if isinstance(preflight, PreflightRecord) else preflight


def _preflight_value(
    preflight: PreflightRecord | Mapping[str, object], field: str
) -> list[object]:
    value = _preflight_mapping(preflight).get(field)
    return list(value) if isinstance(value, list) else []


def _preflight_matches_report(
    record: PreflightRecord,
    report: ReconciliationReport,
) -> bool:
    candidate_actions: tuple[str, ...]
    if record.exact_next_action is not None:
        candidate_actions = (record.exact_next_action,)
    else:
        candidate_actions = (*record.prohibited_actions, "")
    return any(
        PreflightRecord.from_decision(
            classify_readiness(report, action),
            record.project_id,
            record.package_id,
        )
        == record
        for action in candidate_actions
    )


def _serialized_preflight_matches_report(
    preflight: Mapping[str, object], reconciliation: Mapping[str, object]
) -> bool:
    """Reapply readiness gates during independent package validation."""

    try:
        report = ReconciliationReport(
            claims=tuple(
                ClaimRecord(
                    claim_id=str(item["claim_id"]),
                    field=str(item["field"]),
                    value=item.get("value"),
                    source_id=str(item["source_id"]),
                    source_ref=str(item["source_ref"]),
                    evidence_state=EvidenceState(str(item["evidence_state"])),
                    recorded_at=(
                        str(item["recorded_at"])
                        if item.get("recorded_at") is not None
                        else None
                    ),
                )
                for item in _report_records(reconciliation, "claims")
            ),
            approvals=tuple(
                ApprovalRecord(
                    approval_id=str(item["approval_id"]),
                    action=str(item["action"]),
                    scope=tuple(str(value) for value in item["scope"]),
                    decision=str(item["decision"]),
                    source_id=str(item["source_id"]),
                    source_ref=str(item["source_ref"]),
                    approved_at=str(item["approved_at"]),
                )
                for item in _report_records(reconciliation, "approvals")
            ),
            findings=tuple(
                IntegrityFinding(
                    finding_id=str(item["finding_id"]),
                    source_id=str(item["source_id"]),
                    evidence_state=EvidenceState(str(item["evidence_state"])),
                    detail=str(item["detail"]),
                    structurally_valid=item.get("structurally_valid"),
                    lineage_valid=item.get("lineage_valid"),
                    lineage_required=item.get("lineage_required") is True,
                    expected_sha256=(
                        str(item["expected_sha256"])
                        if item.get("expected_sha256") is not None
                        else None
                    ),
                    observed_sha256=(
                        str(item["observed_sha256"])
                        if item.get("observed_sha256") is not None
                        else None
                    ),
                )
                for item in _report_records(reconciliation, "findings")
            ),
            conflicts=tuple(
                ConflictRecord(
                    conflict_id=str(item["conflict_id"]),
                    field=str(item["field"]),
                    material=item["material"] is True,
                    claim_ids=tuple(str(value) for value in item["claim_ids"]),
                    resolution_approval_id=(
                        str(item["resolution_approval_id"])
                        if item.get("resolution_approval_id") is not None
                        else None
                    ),
                )
                for item in _report_records(reconciliation, "conflicts")
            ),
            selected_claim_ids=tuple(
                str(value) for value in reconciliation["selected_claim_ids"]
            ),
            notes=tuple(str(value) for value in reconciliation["notes"]),
        )
        record = PreflightRecord(
            project_id=str(preflight["project_id"]),
            package_id=str(preflight["package_id"]),
            status=ReadinessStatus(str(preflight["status"])),
            reasons=tuple(str(value) for value in preflight["reasons"]),
            conditions=tuple(str(value) for value in preflight["conditions"]),
            authorized_actions=tuple(
                str(value) for value in preflight["authorized_actions"]
            ),
            prohibited_actions=tuple(
                str(value) for value in preflight["prohibited_actions"]
            ),
            unresolved_actions=tuple(
                str(value) for value in preflight["unresolved_actions"]
            ),
            exact_next_action=(
                str(preflight["exact_next_action"])
                if preflight.get("exact_next_action") is not None
                else None
            ),
            companion_skill_or_stage=(
                str(preflight["companion_skill_or_stage"])
                if preflight.get("companion_skill_or_stage") is not None
                else None
            ),
            evidence_references=tuple(
                str(value) for value in preflight["evidence_references"]
            ),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return _preflight_matches_report(record, report)


def _render_template(template: str, values: Mapping[str, str]) -> str:
    """Render one explicit-token template and reject incomplete token contracts."""

    if not isinstance(template, str):
        raise ValueError("template must be text")
    if not isinstance(values, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in values.items()
    ):
        raise ValueError("template values must map token names to text")
    tokens, spans = _scan_template_tokens(template)
    missing = sorted(tokens - set(values))
    unused = sorted(set(values) - tokens)
    if missing:
        raise ValueError("missing template tokens: " + ", ".join(missing))
    if unused:
        raise ValueError("unused template tokens: " + ", ".join(unused))
    rendered: list[str] = []
    position = 0
    for start, end, token in spans:
        rendered.append(template[position:start])
        rendered.append(values[token])
        position = end
    rendered.append(template[position:])
    return "".join(rendered)


def _scan_template_tokens(
    template: str,
) -> tuple[set[str], list[tuple[int, int, str]]]:
    tokens: set[str] = set()
    spans: list[tuple[int, int, str]] = []
    position = 0
    while position < len(template):
        if template.startswith("{{", position):
            end = template.find("}}", position + 2)
            if end < 0:
                raise ValueError("template contains invalid token syntax")
            content = template[position + 2 : end]
            match = _TEMPLATE_TOKEN_CONTENT.fullmatch(content)
            if match is None:
                raise ValueError("template contains invalid token syntax")
            token = match.group(1)
            tokens.add(token)
            spans.append((position, end + 2, token))
            position = end + 2
            continue
        if template[position] in "{}":
            raise ValueError("template contains invalid token syntax")
        position += 1
    return tokens, spans


def _read_asset_text(path: Path, label: str) -> str:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError(f"bundled {label} is missing: {path.name}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ValueError(f"bundled {label} is unsafe: {path.name}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"bundled {label} is unreadable: {path.name}") from error


def _validate_json_artifacts(
    root: Path,
    violations: list[str],
    *,
    include_manifest: bool,
) -> None:
    artifacts = [
        ("lineage/LINEAGE.json", "lineage", "lineage"),
        ("evidence/INDEX.json", "evidence", "evidence"),
        ("receipts/RECONCILIATION.json", "reconciliation", "reconciliation"),
        ("receipts/PREFLIGHT.json", "preflight", "preflight"),
        (
            "receipts/DOCUMENT_INPUTS.json",
            "document-inputs",
            "document inputs",
        ),
    ]
    if include_manifest:
        artifacts.append(("MANIFEST.json", "manifest", "manifest"))
    for relative, schema_name, label in artifacts:
        value = _read_json_object(root / relative, relative, violations)
        if value is not None:
            _validate_against_schema(value, schema_name, label, violations)


def _validate_completed_documents(root: Path, violations: list[str]) -> None:
    """Reproduce rendered bytes before checksums or publication are attempted."""

    manifest = _read_json_object(root / "MANIFEST.json", "MANIFEST.json", violations)
    reconciliation = _read_json_object(
        root / "receipts/RECONCILIATION.json",
        "receipts/RECONCILIATION.json",
        violations,
    )
    preflight = _read_json_object(
        root / "receipts/PREFLIGHT.json", "receipts/PREFLIGHT.json", violations
    )
    document_inputs = _read_json_object(
        root / "receipts/DOCUMENT_INPUTS.json",
        "receipts/DOCUMENT_INPUTS.json",
        violations,
    )
    if all(
        artifact is not None
        for artifact in (manifest, reconciliation, preflight, document_inputs)
    ):
        _validate_document_reproduction(
            root,
            manifest,  # type: ignore[arg-type]
            reconciliation,  # type: ignore[arg-type]
            preflight,  # type: ignore[arg-type]
            document_inputs,  # type: ignore[arg-type]
            violations,
        )


def _validate_document_reproduction(
    root: Path,
    manifest: Mapping[str, object],
    reconciliation: Mapping[str, object],
    preflight: Mapping[str, object],
    document_inputs: Mapping[str, object],
    violations: list[str],
) -> None:
    identity = {
        key: manifest[key]
        for key in ("package_id", "project_id", "created_at", "status", "readiness")
    }
    expected_documents = _render_documents_from_structured_inputs(
        identity, reconciliation, preflight, document_inputs
    )
    for document, expected in expected_documents.items():
        path = root / document
        if not _is_regular_file(path):
            continue
        try:
            observed = path.read_bytes()
        except OSError:
            violations.append(f"document bytes are unreadable: {document}")
            continue
        if observed != expected.encode("utf-8"):
            violations.append(
                f"document bytes do not match structured rendering: {document}"
            )


def _rerender_documents_from_package(
    root: Path, identity: Mapping[str, object]
) -> None:
    """Replace all presentation bytes from the successor's structured records."""

    violations: list[str] = []
    reconciliation = _read_json_object(
        root / "receipts/RECONCILIATION.json",
        "receipts/RECONCILIATION.json",
        violations,
    )
    preflight = _read_json_object(
        root / "receipts/PREFLIGHT.json", "receipts/PREFLIGHT.json", violations
    )
    document_inputs = _read_json_object(
        root / "receipts/DOCUMENT_INPUTS.json",
        "receipts/DOCUMENT_INPUTS.json",
        violations,
    )
    if violations or any(
        artifact is None
        for artifact in (reconciliation, preflight, document_inputs)
    ):
        raise ValueError("successor rendering inputs are invalid")
    rendered = _render_documents_from_structured_inputs(
        identity,
        reconciliation,  # type: ignore[arg-type]
        preflight,  # type: ignore[arg-type]
        document_inputs,  # type: ignore[arg-type]
    )
    for document, text in rendered.items():
        path = root / document
        path.unlink()
        _write_bytes_new(path, text.encode("utf-8"))


def _validate_against_schema(
    instance: object,
    schema_name: str,
    label: str,
    violations: list[str],
) -> None:
    schema_path = _SCHEMA_PATHS[schema_name]
    try:
        schema_value = json.loads(_read_asset_text(schema_path, "schema"))
    except json.JSONDecodeError:
        violations.append(f"{label} schema is not valid JSON")
        return
    if not isinstance(schema_value, dict):
        violations.append(f"{label} schema root must be an object")
        return
    schema_violations: list[str] = []
    _validate_schema_node(instance, schema_value, schema_value, "$", schema_violations)
    violations.extend(f"{label} schema violation: {item}" for item in schema_violations)


def validate_preflight_record(record: PreflightRecord) -> tuple[str, ...]:
    """Validate the exact portable preflight object against its bundled schema."""

    if not isinstance(record, PreflightRecord):
        return ("preflight record must be a PreflightRecord",)
    violations: list[str] = []
    _validate_against_schema(record.to_dict(), "preflight", "preflight", violations)
    return tuple(violations)


def _validate_schema_node(
    instance: object,
    schema: object,
    root_schema: Mapping[str, object],
    path: str,
    violations: list[str],
) -> None:
    if schema is True:
        return
    if schema is False:
        violations.append(f"{path} is prohibited")
        return
    if not isinstance(schema, Mapping):
        violations.append(f"{path} has an invalid bundled schema rule")
        return

    reference = schema.get("$ref")
    if reference is not None:
        target = _local_schema_reference(root_schema, reference)
        if target is None:
            violations.append(f"{path} uses an unresolved bundled schema reference")
            return
        _validate_schema_node(instance, target, root_schema, path, violations)

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        if not any(
            not _schema_branch_violations(instance, branch, root_schema, path)
            for branch in any_of
        ):
            violations.append(f"{path} does not match any allowed schema shape")
        return

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_json_type(instance, expected_type):
        violations.append(f"{path} has the wrong JSON type")
        return
    if "const" in schema and instance != schema["const"]:
        violations.append(f"{path} does not match the required constant")
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        violations.append(f"{path} is not an allowed value")

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for branch in all_of:
            _validate_schema_node(instance, branch, root_schema, path, violations)
    condition = schema.get("if")
    if condition is not None:
        condition_matches = not _schema_branch_violations(
            instance, condition, root_schema, path
        )
        selected = schema.get("then") if condition_matches else schema.get("else")
        if selected is not None:
            _validate_schema_node(instance, selected, root_schema, path, violations)
    if "not" in schema and not _schema_branch_violations(
        instance, schema["not"], root_schema, path
    ):
        violations.append(f"{path} matches a prohibited schema shape")

    if isinstance(instance, Mapping):
        minimum_properties = schema.get("minProperties")
        if isinstance(minimum_properties, int) and len(instance) < minimum_properties:
            violations.append(f"{path} has too few properties")
        required = schema.get("required")
        if isinstance(required, list):
            missing = sorted(
                name for name in required if isinstance(name, str) and name not in instance
            )
            if missing:
                violations.append(f"{path} is missing required fields: {', '.join(missing)}")
        properties = schema.get("properties")
        declared = properties if isinstance(properties, Mapping) else {}
        for name, child_schema in declared.items():
            if name in instance:
                _validate_schema_node(
                    instance[name], child_schema, root_schema, f"{path}.{name}", violations
                )
        property_names = schema.get("propertyNames")
        if property_names is not None:
            for name in instance:
                _validate_schema_node(
                    name, property_names, root_schema, f"{path}.<property>", violations
                )
        undeclared = sorted(str(name) for name in set(instance) - set(declared))
        additional = schema.get("additionalProperties", True)
        if additional is False and undeclared:
            violations.append(f"{path} has undeclared fields: {', '.join(undeclared)}")
        elif isinstance(additional, Mapping) or isinstance(additional, bool):
            if additional is not True and additional is not False:
                for name in set(instance) - set(declared):
                    _validate_schema_node(
                        instance[name],
                        additional,
                        root_schema,
                        f"{path}.{name}",
                        violations,
                    )

    if isinstance(instance, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(instance) < minimum_items:
            violations.append(f"{path} has too few items")
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(instance) > maximum_items:
            violations.append(f"{path} has too many items")
        if schema.get("uniqueItems") is True:
            serialized = [
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for item in instance
            ]
            if len(serialized) != len(set(serialized)):
                violations.append(f"{path} contains duplicate items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                _validate_schema_node(
                    item, item_schema, root_schema, f"{path}[{index}]", violations
                )

    if isinstance(instance, str):
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(instance) < minimum_length:
            violations.append(f"{path} is shorter than allowed")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, instance) is None:
            violations.append(f"{path} does not match the required pattern")
        if schema.get("format") == "date-time" and not _is_rfc3339(instance):
            violations.append(f"{path} is not deterministic RFC3339 text")

    minimum = schema.get("minimum")
    if (
        isinstance(minimum, (int, float))
        and isinstance(instance, (int, float))
        and not isinstance(instance, bool)
        and instance < minimum
    ):
        violations.append(f"{path} is below the allowed minimum")


def _schema_branch_violations(
    instance: object,
    schema: object,
    root_schema: Mapping[str, object],
    path: str,
) -> list[str]:
    branch: list[str] = []
    _validate_schema_node(instance, schema, root_schema, path, branch)
    return branch


def _local_schema_reference(
    root_schema: Mapping[str, object], reference: object
) -> object | None:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    current: object = root_schema
    for component in reference[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    return current


def _matches_json_type(instance: object, expected: object) -> bool:
    if isinstance(expected, list):
        return any(_matches_json_type(instance, item) for item in expected)
    checks = {
        "object": lambda value: isinstance(value, Mapping),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda value: isinstance(value, (int, float))
        and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
        "null": lambda value: value is None,
    }
    check = checks.get(expected)
    return bool(check and check(instance))


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
    successor_created_at: str | None = None,
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
    if successor_created_at is not None:
        manifest["successor_created_at"] = successor_created_at
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
    lineage["successor_created_at"] = successor_created_at
    lineage["status"] = PackageStatus.CANONICAL.value
    lineage["readiness"] = readiness.value
    lineage["parent_ids"] = [candidate_id]
    path.unlink()
    _write_json_new(path, lineage)


def _update_successor_preflight(
    receipt_path: Path,
    *,
    candidate_id: str,
    successor_id: str,
) -> None:
    preflight = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(preflight, dict) or preflight.get("package_id") != candidate_id:
        raise ValueError("candidate preflight identity does not match its manifest")
    preflight["package_id"] = successor_id
    receipt_path.unlink()
    _write_json_new(receipt_path, preflight)


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
    roots = lineage.get("root_package_ids")
    if isinstance(roots, list) and all(isinstance(item, str) for item in roots):
        return tuple(sorted(roots))
    raise ValueError("lineage root_package_ids must be a string list")


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
    status = _enum_value(PackageStatus, lineage.get("status"), "lineage status", violations)
    _enum_value(ReadinessStatus, lineage.get("readiness"), "lineage readiness", violations)
    if status in {PackageStatus.CANONICAL, PackageStatus.SUPERSEDED}:
        _rfc3339_value(
            lineage.get("successor_created_at"),
            "lineage successor_created_at",
            violations,
        )
    _validate_string_list(lineage.get("parent_ids"), "lineage parent_ids", violations)
    _validate_string_list(
        lineage.get("root_package_ids"), "lineage root_package_ids", violations
    )
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
    claims = _object_list(reconciliation, "claims", violations)
    claim_ids: set[str] = set()
    for index, claim in enumerate(claims):
        label = f"reconciliation claim {index}"
        claim_id = _record_id(claim, "claim_id", label, claim_ids, violations)
        for field in ("field", "source_id", "source_ref"):
            _nonempty_string(claim.get(field), f"{label} {field}", violations)
        _enum_value(
            EvidenceState,
            claim.get("evidence_state"),
            f"{label} evidence_state",
            violations,
        )
        _validate_optional_timestamp(claim.get("recorded_at"), f"{label} recorded_at", violations)
        if claim_id is None:
            continue

    approvals = _object_list(reconciliation, "approvals", violations)
    approval_ids: set[str] = set()
    approvals_by_id: dict[str, Mapping[str, object]] = {}
    for index, approval in enumerate(approvals):
        label = f"reconciliation approval {index}"
        approval_id = _record_id(
            approval, "approval_id", label, approval_ids, violations
        )
        for field in ("action", "decision", "source_id", "source_ref"):
            _nonempty_string(approval.get(field), f"{label} {field}", violations)
        _validate_exact_string_list(approval.get("scope"), f"{label} scope", violations)
        _rfc3339_value(approval.get("approved_at"), f"{label} approved_at", violations)
        if approval_id is not None:
            approvals_by_id[approval_id] = approval

    conflicts = _object_list(reconciliation, "conflicts", violations)
    conflict_ids: set[str] = set()
    unresolved_material: set[str] = set()
    conflicts_by_id: dict[str, Mapping[str, object]] = {}
    for index, conflict in enumerate(conflicts):
        label = f"reconciliation conflict {index}"
        conflict_id = _record_id(
            conflict, "conflict_id", label, conflict_ids, violations
        )
        _nonempty_string(conflict.get("field"), f"{label} field", violations)
        material = conflict.get("material")
        if not isinstance(material, bool):
            violations.append(f"{label} material must be boolean")
        referenced_claims = _validate_exact_string_list(
            conflict.get("claim_ids"), f"{label} claim_ids", violations, nonempty=True
        )
        for claim_id in referenced_claims:
            if claim_id not in claim_ids:
                violations.append(f"{label} references absent claim {claim_id}")
        resolution_id = conflict.get("resolution_approval_id")
        if resolution_id is not None and (
            not isinstance(resolution_id, str) or not resolution_id.strip()
        ):
            violations.append(f"{label} resolution_approval_id must be null or non-empty text")
        if conflict_id is not None:
            conflicts_by_id[conflict_id] = conflict
            if material is True and resolution_id is None:
                unresolved_material.add(conflict_id)
        if isinstance(resolution_id, str) and resolution_id.strip():
            approval = approvals_by_id.get(resolution_id)
            if approval is None:
                violations.append(f"{label} references absent resolution approval")
            elif (
                approval.get("action") != "resolve-conflict"
                or approval.get("scope") != [conflict_id]
                or approval.get("decision") not in referenced_claims
            ):
                violations.append(f"{label} resolution approval is not exact")

    findings = _object_list(reconciliation, "findings", violations)
    if not findings:
        violations.append("reconciliation findings must be non-empty")
    finding_ids: set[str] = set()
    for index, finding in enumerate(findings):
        label = f"reconciliation finding {index}"
        _record_id(finding, "finding_id", label, finding_ids, violations)
        _nonempty_string(finding.get("source_id"), f"{label} source_id", violations)
        _enum_value(
            EvidenceState,
            finding.get("evidence_state"),
            f"{label} evidence_state",
            violations,
        )
        if not isinstance(finding.get("detail"), str):
            violations.append(f"{label} detail must be text")
        for field in ("structurally_valid", "lineage_valid"):
            if finding.get(field) is not None and not isinstance(finding.get(field), bool):
                violations.append(f"{label} {field} must be boolean or null")
        if not isinstance(finding.get("lineage_required"), bool):
            violations.append(f"{label} lineage_required must be boolean")
        for field in ("expected_sha256", "observed_sha256"):
            value = finding.get(field)
            if value is not None and not _is_sha256(value):
                violations.append(f"{label} {field} must be null or SHA-256")

    selected = _validate_exact_string_list(
        reconciliation.get("selected_claim_ids"),
        "reconciliation selected_claim_ids",
        violations,
    )
    for claim_id in selected:
        if claim_id not in claim_ids:
            violations.append(
                f"reconciliation selected_claim_ids references absent claim {claim_id}"
            )
    selected_set = set(selected)
    for conflict_id, conflict in conflicts_by_id.items():
        disputed = conflict.get("claim_ids")
        if not isinstance(disputed, list) or any(
            not isinstance(claim_id, str) for claim_id in disputed
        ):
            continue
        selected_disputed = selected_set & set(disputed)
        resolution_id = conflict.get("resolution_approval_id")
        if isinstance(resolution_id, str) and resolution_id.strip():
            approval = approvals_by_id.get(resolution_id)
            decision = approval.get("decision") if approval is not None else None
            expected = {decision} if isinstance(decision, str) else set()
            if selected_disputed != expected:
                violations.append(
                    f"reconciliation conflict {conflict_id} must select exactly the "
                    "approved disputed claim"
                )
        elif conflict.get("material") is True and selected_disputed:
            violations.append(
                f"reconciliation conflict {conflict_id} selects an unresolved disputed claim"
            )

    blocking = _validate_exact_string_list(
        reconciliation.get("blocking_conflict_ids"),
        "reconciliation blocking_conflict_ids",
        violations,
    )
    for conflict_id in blocking:
        conflict = conflicts_by_id.get(conflict_id)
        if (
            conflict is None
            or conflict.get("material") is not True
            or conflict.get("resolution_approval_id") is not None
        ):
            violations.append(
                "reconciliation blocking_conflict_ids must reference material unresolved conflicts"
            )
    if set(blocking) != unresolved_material:
        violations.append(
            "reconciliation blocking_conflict_ids must equal material unresolved conflicts"
        )

    notes = reconciliation.get("notes")
    if not isinstance(notes, list) or any(not isinstance(note, str) for note in notes):
        violations.append("reconciliation notes must be a string list")


def _validate_selected_project_identity(
    reconciliation: Mapping[str, object],
    project_id: object,
    violations: list[str],
) -> None:
    claims = reconciliation.get("claims")
    selected = reconciliation.get("selected_claim_ids")
    if not isinstance(claims, list) or not isinstance(selected, list):
        return
    selected_set = {item for item in selected if isinstance(item, str)}
    project_claims = [
        claim
        for claim in claims
        if isinstance(claim, Mapping)
        and _normalize_claim_field(claim.get("field")) == "project id"
        and claim.get("claim_id") in selected_set
    ]
    if len(project_claims) != 1:
        violations.append("reconciliation must select exactly one project_id claim")
        return
    if project_claims[0].get("value") != project_id:
        violations.append("reconciliation selected project_id does not match active project")


def _object_list(
    value: Mapping[str, object], field: str, violations: list[str]
) -> list[Mapping[str, object]]:
    items = value.get(field)
    if not isinstance(items, list):
        violations.append(f"reconciliation {field} must be a list")
        return []
    objects: list[Mapping[str, object]] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            violations.append(f"reconciliation {field} item {index} must be an object")
        else:
            objects.append(item)
    return objects


def _record_id(
    record: Mapping[str, object],
    field: str,
    label: str,
    seen: set[str],
    violations: list[str],
) -> str | None:
    value = _nonempty_string(record.get(field), f"{label} {field}", violations)
    if value is None:
        return None
    if value in seen:
        violations.append(f"{label} {field} must be unique")
    seen.add(value)
    return value


def _validate_optional_timestamp(
    value: object, label: str, violations: list[str]
) -> None:
    if value is not None:
        _rfc3339_value(value, label, violations)


def _validate_exact_string_list(
    value: object,
    label: str,
    violations: list[str],
    *,
    nonempty: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        violations.append(f"{label} must be a string list")
        return []
    if nonempty and not value:
        violations.append(f"{label} must be non-empty")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        violations.append(f"{label} must contain non-empty text")
        return []
    if len(value) != len(set(value)):
        violations.append(f"{label} must not contain duplicates")
    return value


def _normalize_claim_field(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return _normalize(value)


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
