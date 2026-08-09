"""Deterministic JSON command-line adapters for Continuity v1 operations."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Callable, Mapping, Sequence

from .archives import inspect_zip, safe_extract_zip
from .hashing import inventory_tree, sha256_file, verify_sha256s
from .models import (
    ApprovalRecord,
    ClaimRecord,
    ConflictRecord,
    EvidenceState,
    PackageStatus,
    PreflightRecord,
    ReadinessStatus,
)
from .packaging import (
    CandidateBuildRequest,
    build_candidate,
    promote_candidate,
    validate_preflight_record,
    validate_package,
)
from .readiness import classify_readiness
from .reconciliation import IntegrityFinding, ReconciliationReport, reconcile_sources


_CLAIM_FIELDS = frozenset(
    {"claim_id", "field", "value", "source_id", "source_ref", "evidence_state", "recorded_at"}
)
_APPROVAL_FIELDS = frozenset(
    {"approval_id", "action", "scope", "decision", "source_id", "source_ref", "approved_at"}
)
_INTEGRITY_FIELDS = frozenset(
    {
        "finding_id",
        "source_id",
        "evidence_state",
        "detail",
        "structurally_valid",
        "lineage_valid",
        "lineage_required",
        "expected_sha256",
        "observed_sha256",
    }
)
_CONFLICT_FIELDS = frozenset(
    {"conflict_id", "field", "material", "claim_ids", "resolution_approval_id"}
)
_REPORT_FIELDS = frozenset(
    {
        "claims",
        "conflicts",
        "findings",
        "approvals",
        "selected_claim_ids",
        "blocking_conflict_ids",
        "notes",
    }
)
_BUILD_FIELDS = frozenset(
    {
        "package_id",
        "project_id",
        "created_at",
        "selected_source_hashes",
        "reconciliation_report",
        "canonical_files",
        "rendered_documents",
        "preflight_decision",
        "lineage_data",
        "evidence_index",
        "secure_handling_approvals",
        "readiness",
        "allow_conditional_promotion",
    }
)
_PREFLIGHT_FIELDS = frozenset(
    {
        "schema",
        "project_id",
        "package_id",
        "status",
        "reasons",
        "conditions",
        "authorized_actions",
        "prohibited_actions",
        "unresolved_actions",
        "exact_next_action",
        "companion_skill_or_stage",
        "evidence_references",
    }
)


class CliInputError(ValueError):
    """A user-controlled input violated the public CLI contract."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CliInputError("invalid command arguments")


@dataclass(frozen=True)
class _CommandResult:
    payload: dict[str, object]
    exit_code: int = 0


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="continuity_cli.py")
    commands = parser.add_subparsers(dest="operation", required=True)

    inspect_command = commands.add_parser("inspect")
    inspect_command.add_argument("source")
    inspect_command.add_argument("--output", dest="json_output", required=True)
    inspect_command.set_defaults(handler=_inspect_command)

    reconcile_command = commands.add_parser("reconcile")
    reconcile_command.add_argument("--claims", required=True)
    reconcile_command.add_argument("--approvals", required=True)
    reconcile_command.add_argument("--integrity", required=True)
    reconcile_command.add_argument("--output", dest="json_output", required=True)
    reconcile_command.set_defaults(handler=_reconcile_command)

    build_command = commands.add_parser("build")
    build_command.add_argument("--request", required=True)
    build_command.add_argument("--output-dir", required=True)
    build_command.set_defaults(handler=_build_command)

    validate_command = commands.add_parser("validate")
    validate_command.add_argument("package")
    validate_command.add_argument("--output", dest="json_output", required=True)
    validate_command.set_defaults(handler=_validate_command)

    promote_command = commands.add_parser("promote")
    promote_command.add_argument("candidate")
    promote_command.add_argument("--approval")
    promote_command.add_argument("--created-at", required=True)
    promote_command.add_argument("--output", required=True)
    promote_command.set_defaults(handler=_promote_command)

    preflight_command = commands.add_parser("preflight")
    preflight_command.add_argument("--reconciliation", required=True)
    preflight_command.add_argument("--project-id", required=True)
    preflight_command.add_argument("--package-id", required=True)
    preflight_command.add_argument("--requested-action", required=True)
    preflight_command.add_argument("--output", dest="json_output", required=True)
    preflight_command.set_defaults(handler=_preflight_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI operation, emitting exactly one stable JSON document."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    output: Path | None = None
    try:
        namespace = _parser().parse_args(arguments)
        output = _validated_json_output(namespace)
        handler: Callable[[argparse.Namespace], _CommandResult] = namespace.handler
        result = handler(namespace)
        if output is None:
            _emit_stdout(result.payload)
        else:
            _emit(result.payload, output)
        return result.exit_code
    except CliInputError as error:
        payload = _error(str(error))
        _emit_best_effort(payload, output)
        return 1
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        payload = _error("operation failed validation or could not be completed")
        _emit_best_effort(payload, output)
        return 1


def _inspect_command(namespace: argparse.Namespace) -> _CommandResult:
    source = Path(namespace.source)
    source_id = _required_text(
        source.stem if source.suffix.casefold() == ".zip" else source.name,
        "source_id",
    )
    try:
        mode = source.lstat().st_mode
    except OSError as error:
        raise CliInputError("source is unavailable") from error
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        return _inspect_directory(source, source_id)
    if stat.S_ISREG(mode) and not stat.S_ISLNK(mode) and source.suffix.casefold() == ".zip":
        return _inspect_archive(source, source_id)
    raise CliInputError("source must be a non-symlink directory or ZIP")


def _inspect_directory(source: Path, source_id: str) -> _CommandResult:
    records = inventory_tree(source, source_id)
    root_hash = _directory_sha256(source)
    manifest_present = _regular_file(source / "MANIFEST.json")
    checksum = source / "SHA256SUMS.txt"
    checksum_present = _regular_file(checksum)
    checksum_verified = False
    if checksum_present:
        try:
            checksum_verified = verify_sha256s(source, checksum).verified
        except (OSError, UnicodeError, ValueError):
            checksum_verified = False
    if manifest_present and checksum_verified:
        state = EvidenceState.VERIFIED
        detail = "manifest and checksum inventory verified"
    elif not manifest_present or not checksum_present:
        state = EvidenceState.MISSING
        detail = "required manifest or checksum inventory is missing"
    else:
        state = EvidenceState.CONTRADICTED
        detail = "checksum inventory does not match source bytes"
    integrity = IntegrityFinding(
        finding_id=_finding_id(source_id),
        source_id=source_id,
        evidence_state=state,
        detail=detail,
        structurally_valid=state is EvidenceState.VERIFIED,
        lineage_valid=None,
        lineage_required=False,
    )
    return _CommandResult(
        {
            "ok": True,
            "operation": "inspect",
            "source": {"kind": "directory", "sha256": root_hash, "source_id": source_id},
            "artifacts": [
                {
                    "evidence_state": record.evidence_state.value,
                    "normalized_path": record.normalized_path,
                    "observed_path": record.observed_path,
                    "sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "source_id": record.source_id,
                }
                for record in records
            ],
            "integrity": integrity.to_dict(),
        }
    )


def _inspect_archive(source: Path, source_id: str) -> _CommandResult:
    inspection = inspect_zip(source)
    categories: tuple[str, ...]
    if not inspection.safe:
        state = EvidenceState.CONTRADICTED
        code = "archive-safety-failed"
        categories = _validation_categories(inspection.violations)
        violation_count = len(inspection.violations)
    else:
        with tempfile.TemporaryDirectory(prefix="continuity-inspect-") as temporary:
            extracted = Path(temporary) / "package"
            extracted_inspection = safe_extract_zip(source, extracted)
            if not extracted_inspection.safe:
                state = EvidenceState.CONTRADICTED
                code = "archive-safety-failed"
                categories = _validation_categories(extracted_inspection.violations)
                violation_count = len(extracted_inspection.violations)
            else:
                package_root = _package_root(extracted)
                manifest_present = _regular_file(package_root / "MANIFEST.json")
                checksum_present = _regular_file(package_root / "SHA256SUMS.txt")
                if manifest_present and checksum_present:
                    validation = validate_package(package_root)
                    if validation.valid:
                        state = EvidenceState.VERIFIED
                        code = "package-verified"
                        categories = ()
                        violation_count = 0
                    else:
                        state = EvidenceState.CONTRADICTED
                        code = "package-validation-failed"
                        categories = _validation_categories(validation.violations)
                        violation_count = len(validation.violations)
                else:
                    state = EvidenceState.UNRESOLVED
                    code = "package-integrity-evidence-incomplete"
                    categories = ("missing-package-integrity",)
                    violation_count = 1
    integrity = IntegrityFinding(
        finding_id=_finding_id(source_id),
        source_id=source_id,
        evidence_state=state,
        detail=code,
        structurally_valid=state is EvidenceState.VERIFIED,
        lineage_valid=None,
        lineage_required=False,
    )
    return _CommandResult(
        {
            "ok": True,
            "operation": "inspect",
            "source": {"kind": "zip", "sha256": sha256_file(source), "source_id": source_id},
            "artifacts": {
                "directory_count": sum(entry.is_directory for entry in inspection.entries),
                "entry_count": len(inspection.entries),
                "file_count": sum(not entry.is_directory for entry in inspection.entries),
            },
            "archive": {
                "categories": list(categories),
                "code": code,
                "safe": inspection.safe,
                "violation_count": violation_count,
            },
            "integrity": integrity.to_dict(),
        }
    )


def _reconcile_command(namespace: argparse.Namespace) -> _CommandResult:
    claims = tuple(
        _parse_claim(item)
        for item in _read_object_list(Path(namespace.claims), "claims")
    )
    approvals = tuple(
        _parse_approval(item)
        for item in _read_object_list(Path(namespace.approvals), "approvals")
    )
    integrity = tuple(
        _parse_integrity(item)
        for item in _read_object_list(Path(namespace.integrity), "integrity")
    )
    report = reconcile_sources(claims, approvals, integrity)
    blocked = bool(report.blocking_conflicts)
    return _CommandResult(
        {"ok": True, "operation": "reconcile", "report": report.to_dict()},
        2 if blocked else 0,
    )


def _build_command(namespace: argparse.Namespace) -> _CommandResult:
    value = _read_object(Path(namespace.request), "build input")
    _exact_fields(value, _BUILD_FIELDS, "build input")
    source_hashes = _string_mapping(value.get("selected_source_hashes"), "selected_source_hashes")
    canonical_files = _string_mapping(value.get("canonical_files"), "canonical_files")
    documents = _string_mapping(value.get("rendered_documents"), "rendered_documents")
    lineage = _mapping(value.get("lineage_data"), "lineage_data")
    evidence = _mapping(value.get("evidence_index"), "evidence_index")
    approvals = tuple(
        _parse_approval(item)
        for item in _object_sequence(
            value.get("secure_handling_approvals"), "secure_handling_approvals"
        )
    )
    _validate_build_output(
        Path(namespace.output_dir), tuple(Path(source) for source in canonical_files.values())
    )
    request = CandidateBuildRequest(
        package_id=_required_text(value.get("package_id"), "package_id"),
        project_id=_required_text(value.get("project_id"), "project_id"),
        created_at=_required_text(value.get("created_at"), "created_at"),
        selected_source_hashes=source_hashes,
        approved_reconciliation_report=_parse_report(
            _mapping(value.get("reconciliation_report"), "reconciliation_report")
        ),
        canonical_files={path: Path(source) for path, source in canonical_files.items()},
        rendered_documents=documents,
        preflight_decision=_parse_preflight_record(
            _mapping(value.get("preflight_decision"), "preflight_decision")
        ),
        lineage_data=lineage,
        evidence_index=evidence,
        secure_handling_approvals=approvals,
        output=Path(namespace.output_dir),
        readiness=_enum(ReadinessStatus, value.get("readiness"), "readiness"),
        allow_conditional_promotion=_boolean(
            value.get("allow_conditional_promotion"), "allow_conditional_promotion"
        ),
    )
    result = build_candidate(request)
    return _CommandResult(
        {
            "ok": True,
            "operation": "build",
            "package": {
                "package_id": result.package_id,
                "package_sha256": result.package_sha256,
                "status": result.status.value,
            },
        },
        2 if result.status is PackageStatus.BLOCKED else 0,
    )


def _validate_command(namespace: argparse.Namespace) -> _CommandResult:
    package = Path(namespace.package)
    try:
        mode = package.lstat().st_mode
    except OSError as error:
        raise CliInputError("package is unavailable") from error
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        root = _package_root(package)
        validation = validate_package(root)
    elif stat.S_ISREG(mode) and not stat.S_ISLNK(mode) and package.suffix.casefold() == ".zip":
        with tempfile.TemporaryDirectory(prefix="continuity-validate-") as temporary:
            extracted = Path(temporary) / "package"
            inspection = safe_extract_zip(package, extracted)
            if not inspection.safe:
                return _validation_result(False, inspection.violations)
            validation = validate_package(_package_root(extracted))
    else:
        raise CliInputError("package must be a non-symlink directory or ZIP")
    return _validation_result(
        validation.valid,
        validation.violations,
        package_id=validation.package_id,
        status=validation.status,
        readiness=validation.readiness,
    )


def _validation_result(
    valid: bool,
    violations: Sequence[str],
    *,
    package_id: str | None = None,
    status: PackageStatus | None = None,
    readiness: ReadinessStatus | None = None,
) -> _CommandResult:
    categories = _validation_categories(violations)
    payload = {
        "ok": valid,
        "operation": "validate",
        "validation": {
            "package_id": package_id,
            "readiness": readiness.value if readiness is not None else None,
            "status": status.value if status is not None else None,
            "valid": valid,
            "violation_count": len(violations),
            "violations": list(categories),
        },
    }
    exit_code = 0 if valid and status is not PackageStatus.BLOCKED else 2 if valid else 1
    return _CommandResult(payload, exit_code)


def _validation_categories(violations: Sequence[str]) -> tuple[str, ...]:
    categories: set[str] = set()
    for violation in violations:
        normalized = violation.casefold()
        if any(term in normalized for term in ("checksum", "digest", "sha256", "manifest")):
            categories.add("package-integrity")
        elif any(term in normalized for term in ("claim", "approval", "reconciliation", "authority")):
            categories.add("package-authority")
        elif any(term in normalized for term in ("status", "readiness", "lifecycle", "promotion")):
            categories.add("package-lifecycle")
        elif any(term in normalized for term in ("json", "schema", "lineage", "evidence")):
            categories.add("package-metadata")
        elif any(term in normalized for term in ("archive", "zip", "path", "entry", "symlink")):
            categories.add("archive-safety")
        else:
            categories.add("package-structure")
    return tuple(sorted(categories))


def _promote_command(namespace: argparse.Namespace) -> _CommandResult:
    if namespace.approval is None:
        raise CliInputError("promotion requires an exact approval record")
    approval = _parse_approval(_read_object(Path(namespace.approval), "approval record"))
    candidate = _package_root(Path(namespace.candidate))
    _validate_promotion_output(Path(namespace.output), Path(namespace.candidate), candidate)
    result = promote_candidate(
        candidate,
        Path(namespace.output),
        approval,
        _required_text(namespace.created_at, "created_at"),
    )
    return _CommandResult(
        {
            "ok": True,
            "operation": "promote",
            "package": {
                "package_id": result.package_id,
                "package_sha256": result.package_sha256,
                "status": result.status.value,
            },
        }
    )


def _preflight_command(namespace: argparse.Namespace) -> _CommandResult:
    report = _parse_report(
        _read_object(Path(namespace.reconciliation), "reconciliation report")
    )
    project_id = _required_text(namespace.project_id, "project_id")
    _bind_preflight_project(report, project_id)
    decision = classify_readiness(
        report, _required_text(namespace.requested_action, "requested_action")
    )
    record = PreflightRecord.from_decision(
        decision,
        project_id,
        _required_text(namespace.package_id, "package_id"),
    )
    violations = validate_preflight_record(record)
    if violations:
        raise ValueError("generated preflight is invalid: " + "; ".join(violations))
    return _CommandResult(
        record.to_dict(),
        2 if decision.status is ReadinessStatus.BLOCKED else 0,
    )


def _bind_preflight_project(report: ReconciliationReport, project_id: str) -> None:
    selected = set(report.selected_claim_ids)
    project_claims = tuple(
        claim
        for claim in report.claims
        if claim.claim_id in selected
        and _normalize_record_field(claim.field) == "project id"
    )
    if len(project_claims) != 1:
        raise CliInputError(
            "preflight requires exactly one selected project_id claim"
        )
    if project_claims[0].value != project_id:
        raise CliInputError(
            "preflight project_id does not match selected project identity"
        )


def _normalize_record_field(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").casefold().split())


def _parse_report(value: Mapping[str, object]) -> ReconciliationReport:
    _exact_fields(value, _REPORT_FIELDS, "reconciliation report")
    report = ReconciliationReport(
        claims=tuple(_parse_claim(item) for item in _object_sequence(value.get("claims"), "claims")),
        approvals=tuple(
            _parse_approval(item) for item in _object_sequence(value.get("approvals"), "approvals")
        ),
        findings=tuple(
            _parse_integrity(item) for item in _object_sequence(value.get("findings"), "findings")
        ),
        conflicts=tuple(
            _parse_conflict(item) for item in _object_sequence(value.get("conflicts"), "conflicts")
        ),
        selected_claim_ids=_string_tuple(value.get("selected_claim_ids"), "selected_claim_ids"),
        notes=_string_tuple(value.get("notes"), "notes"),
    )
    supplied_blocking = _string_tuple(value.get("blocking_conflict_ids"), "blocking_conflict_ids")
    actual_blocking = tuple(sorted(conflict.conflict_id for conflict in report.blocking_conflicts))
    if tuple(sorted(supplied_blocking)) != actual_blocking:
        raise CliInputError("reconciliation report blocking conflicts are inconsistent")
    return report


def _parse_preflight_record(value: Mapping[str, object]) -> PreflightRecord:
    _exact_fields(value, _PREFLIGHT_FIELDS, "preflight_decision")
    if value.get("schema") != "continuity.preflight/v1":
        raise CliInputError("preflight_decision schema is unsupported")
    record = PreflightRecord(
        project_id=_required_text(value.get("project_id"), "preflight project_id"),
        package_id=_required_text(value.get("package_id"), "preflight package_id"),
        status=_enum(ReadinessStatus, value.get("status"), "preflight status"),
        reasons=_string_tuple(value.get("reasons"), "preflight reasons"),
        conditions=_string_tuple(value.get("conditions"), "preflight conditions"),
        authorized_actions=_string_tuple(
            value.get("authorized_actions"), "preflight authorized_actions"
        ),
        prohibited_actions=_string_tuple(
            value.get("prohibited_actions"), "preflight prohibited_actions"
        ),
        unresolved_actions=_string_tuple(
            value.get("unresolved_actions"), "preflight unresolved_actions"
        ),
        exact_next_action=_optional_text(
            value.get("exact_next_action"), "preflight exact_next_action"
        ),
        companion_skill_or_stage=_optional_text(
            value.get("companion_skill_or_stage"),
            "preflight companion_skill_or_stage",
        ),
        evidence_references=_string_tuple(
            value.get("evidence_references"), "preflight evidence_references"
        ),
    )
    violations = validate_preflight_record(record)
    if violations:
        raise CliInputError(violations[0])
    return record


def _parse_claim(value: Mapping[str, object]) -> ClaimRecord:
    _exact_fields(value, _CLAIM_FIELDS, "claim record")
    recorded_at = value.get("recorded_at")
    if recorded_at is not None and not isinstance(recorded_at, str):
        raise CliInputError("claim recorded_at must be text or null")
    return ClaimRecord(
        claim_id=_required_text(value.get("claim_id"), "claim_id"),
        field=_required_text(value.get("field"), "claim field"),
        value=value.get("value"),
        source_id=_required_text(value.get("source_id"), "claim source_id"),
        source_ref=_required_text(value.get("source_ref"), "claim source_ref"),
        evidence_state=_enum(EvidenceState, value.get("evidence_state"), "claim evidence_state"),
        recorded_at=recorded_at,
    )


def _parse_approval(value: Mapping[str, object]) -> ApprovalRecord:
    _exact_fields(value, _APPROVAL_FIELDS, "approval record")
    return ApprovalRecord(
        approval_id=_required_text(value.get("approval_id"), "approval_id"),
        action=_required_text(value.get("action"), "approval action"),
        scope=_string_tuple(value.get("scope"), "approval scope"),
        decision=_required_text(value.get("decision"), "approval decision"),
        source_id=_required_text(value.get("source_id"), "approval source_id"),
        source_ref=_required_text(value.get("source_ref"), "approval source_ref"),
        approved_at=_required_text(value.get("approved_at"), "approved_at"),
    )


def _parse_integrity(value: Mapping[str, object]) -> IntegrityFinding:
    _exact_fields(value, _INTEGRITY_FIELDS, "integrity record")
    return IntegrityFinding(
        finding_id=_required_text(value.get("finding_id"), "finding_id"),
        source_id=_required_text(value.get("source_id"), "integrity source_id"),
        evidence_state=_enum(
            EvidenceState, value.get("evidence_state"), "integrity evidence_state"
        ),
        detail=_text(value.get("detail"), "integrity detail"),
        structurally_valid=_optional_boolean(
            value.get("structurally_valid"), "structurally_valid"
        ),
        lineage_valid=_optional_boolean(value.get("lineage_valid"), "lineage_valid"),
        lineage_required=_boolean(value.get("lineage_required"), "lineage_required"),
        expected_sha256=_optional_text(value.get("expected_sha256"), "expected_sha256"),
        observed_sha256=_optional_text(value.get("observed_sha256"), "observed_sha256"),
    )


def _parse_conflict(value: Mapping[str, object]) -> ConflictRecord:
    _exact_fields(value, _CONFLICT_FIELDS, "conflict record")
    resolution = value.get("resolution_approval_id")
    if resolution is not None and not isinstance(resolution, str):
        raise CliInputError("conflict resolution_approval_id must be text or null")
    return ConflictRecord(
        conflict_id=_required_text(value.get("conflict_id"), "conflict_id"),
        field=_required_text(value.get("field"), "conflict field"),
        material=_boolean(value.get("material"), "conflict material"),
        claim_ids=_string_tuple(value.get("claim_ids"), "conflict claim_ids"),
        resolution_approval_id=resolution,
    )


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            raise CliInputError(f"{label} must be a regular JSON file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except CliInputError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CliInputError(f"{label} could not be read as JSON") from error
    if not isinstance(value, dict):
        raise CliInputError(f"{label} must be a JSON object")
    return value


def _read_object_list(path: Path, label: str) -> tuple[dict[str, object], ...]:
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            raise CliInputError(f"{label} must be a regular JSON file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except CliInputError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CliInputError(f"{label} could not be read as JSON") from error
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CliInputError(f"{label} must be a JSON list of objects")
    return tuple(value)


def _exact_fields(value: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    fields = set(value)
    if fields != expected:
        raise CliInputError(f"{label} has missing or unknown fields")


def _object_sequence(value: object, label: str) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CliInputError(f"{label} must be a list of objects")
    return tuple(value)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CliInputError(f"{label} must be an object")
    return dict(value)


def _string_mapping(value: object, label: str) -> dict[str, str]:
    mapping = _mapping(value, label)
    if any(not isinstance(item, str) for item in mapping.values()):
        raise CliInputError(f"{label} must map text keys to text values")
    return {key: item for key, item in mapping.items() if isinstance(item, str)}


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CliInputError(f"{label} must be a list of text values")
    return tuple(value)


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CliInputError(f"{label} must be non-empty text")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CliInputError(f"{label} must be text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise CliInputError(f"{label} must be text or null")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise CliInputError(f"{label} must be boolean")
    return value


def _optional_boolean(value: object, label: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise CliInputError(f"{label} must be boolean or null")
    return value


def _enum(enum_type: type, value: object, label: str):
    if not isinstance(value, str):
        raise CliInputError(f"{label} must be a supported text value")
    try:
        return enum_type(value)
    except ValueError as error:
        raise CliInputError(f"{label} must be a supported text value") from error


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode) and not stat.S_ISLNK(path.lstat().st_mode)
    except OSError:
        return False


def _package_root(path: Path) -> Path:
    if _regular_file(path / "MANIFEST.json"):
        return path
    nested = path / "package"
    if _regular_file(nested / "MANIFEST.json"):
        return nested
    return path


def _directory_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        directory_path = Path(directory)
        for name in (*directories, *files):
            path = directory_path / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise CliInputError("source contains a symlink or special file")
        for name in files:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def _finding_id(source_id: str) -> str:
    digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:16]
    return f"integrity-{digest}"


def _validated_json_output(namespace: argparse.Namespace) -> Path | None:
    value = getattr(namespace, "json_output", None)
    if value is None:
        return None
    output = Path(value)
    operation = namespace.operation
    if operation == "inspect":
        inputs = (Path(namespace.source),)
    elif operation == "reconcile":
        inputs = (
            Path(namespace.claims),
            Path(namespace.approvals),
            Path(namespace.integrity),
        )
    elif operation == "validate":
        inputs = (Path(namespace.package),)
    else:
        inputs = (Path(namespace.reconciliation),)
    _validate_write_destination(output)
    output_path = _resolved_path(output)
    for input_path in inputs:
        protected = _resolved_path(input_path)
        if output_path == protected or (
            input_path.is_dir() and _is_within(output_path, protected)
        ):
            raise CliInputError("output overlaps read-only input evidence")
    return output


def _validate_build_output(output: Path, canonical_sources: Sequence[Path]) -> None:
    _validate_write_destination(output)
    output_path = _resolved_path(output)
    resolved_sources: list[Path] = []
    for source in canonical_sources:
        if _has_symlink_component(source):
            raise CliInputError("canonical source path may not traverse a symlink")
        source_path = _resolved_path(source)
        resolved_sources.append(source_path)
        if _paths_overlap(output_path, source_path):
            raise CliInputError("release output overlaps canonical source evidence")
    if not resolved_sources:
        return
    common_text = os.path.commonpath([str(source.parent) for source in resolved_sources])
    common_root = Path(common_text)
    if common_root == Path(common_root.anchor):
        raise CliInputError("canonical sources do not identify one project root")
    if output_path == common_root or _is_within(output_path, common_root):
        raise CliInputError("release output overlaps canonical source tree")


def _validate_promotion_output(output: Path, candidate: Path, package_root: Path) -> None:
    _validate_write_destination(output)
    output_path = _resolved_path(output)
    protected = {_resolved_path(candidate), _resolved_path(package_root)}
    if package_root.name == "package":
        protected.add(_resolved_path(package_root.parent))
    if any(output_path == path or _is_within(output_path, path) for path in protected):
        raise CliInputError("promotion output overlaps candidate evidence")


def _validate_write_destination(output: Path) -> None:
    if _has_symlink_component(output):
        raise CliInputError("output path may not traverse a symlink")
    if not output.parent.is_dir():
        raise CliInputError("output parent does not exist")


def _has_symlink_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            return True
    return False


def _resolved_path(path: Path) -> Path:
    return path.resolve(strict=False)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or _is_within(left, right) or _is_within(right, left)


def _error(message: str) -> dict[str, object]:
    return {
        "ok": False,
        "error": {"code": "invalid_input", "message": message, "details": []},
    }


def _emit(payload: Mapping[str, object], output: Path) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    _atomic_write(output, rendered)
    sys.stdout.write(rendered)


def _emit_stdout(payload: Mapping[str, object]) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    sys.stdout.write(rendered)


def _emit_best_effort(payload: Mapping[str, object], output: Path | None) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    if output is not None:
        try:
            _atomic_write(output, rendered)
        except (CliInputError, OSError):
            pass
    sys.stdout.write(rendered)


def _atomic_write(output: Path, rendered: str) -> None:
    if not output.parent.is_dir():
        raise CliInputError("output parent does not exist")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.continuity-", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as target:
            target.write(rendered)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
