import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from continuity.hashing import sha256_file
from continuity.models import (
    ApprovalRecord,
    ClaimRecord,
    ConflictRecord,
    EvidenceState,
    PackageStatus,
    ReadinessStatus,
)
from continuity.packaging import (
    CandidateBuildRequest,
    _publish_release_no_replace,
    build_candidate,
    promote_candidate,
    validate_package,
)
from continuity.reconciliation import IntegrityFinding, ReconciliationReport


DOCUMENT_PATHS = (
    "HANDOFF_README.md",
    "CANONICAL_STATE.md",
    "AUTHORITY_LEDGER.md",
    "CONFLICT_RESOLUTIONS.md",
    "UNRESOLVED.md",
    "NEXT_THREAD_PROMPT.txt",
    "SUPERPOWERS_PREFLIGHT.md",
)
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _report(*, blocked: bool = False) -> ReconciliationReport:
    project = ClaimRecord(
        "project-alpha",
        "project id",
        "alpha",
        "source-tree",
        "source/project.json",
        EvidenceState.VERIFIED,
    )
    conflict = (
        ConflictRecord(
            "conflict-architecture",
            "architecture",
            True,
            ("claim-monolith", "claim-services"),
            None,
        ),
    ) if blocked else ()
    return ReconciliationReport(
        claims=(project,),
        approvals=(),
        findings=(
            IntegrityFinding(
                "integrity-source",
                "source-tree",
                EvidenceState.VERIFIED,
                structurally_valid=True,
                lineage_valid=True,
            ),
        ),
        conflicts=conflict,
        selected_claim_ids=(project.claim_id,),
        notes=(),
    )


def _request(
    tmp_path: Path,
    *,
    package_id: str = "candidate-alpha",
    report: ReconciliationReport | None = None,
    canonical_files: dict[str, Path] | None = None,
    secure_handling_approvals: tuple[ApprovalRecord, ...] = (),
    readiness: ReadinessStatus = ReadinessStatus.READY,
) -> CandidateBuildRequest:
    source_root = tmp_path / "source"
    source_root.mkdir(exist_ok=True)
    source_file = source_root / "app.py"
    if not source_file.exists():
        source_file.write_text("print('preserved')\n", encoding="utf-8")
    source_zip = tmp_path / "input.zip"
    if not source_zip.exists():
        with zipfile.ZipFile(source_zip, "w") as archive:
            archive.writestr("proof.txt", "immutable evidence\n")
    return CandidateBuildRequest(
        package_id=package_id,
        project_id="alpha",
        created_at="2026-08-09T12:00:00Z",
        selected_source_hashes={
            "source-tree": _tree_hash(source_root),
            "input-zip": sha256_file(source_zip),
        },
        approved_reconciliation_report=report or _report(),
        canonical_files=canonical_files or {"src/app.py": source_file},
        rendered_documents={path: f"# {path}\n\nApproved state.\n" for path in DOCUMENT_PATHS},
        lineage_data={
            "schema": "continuity.lineage/v1",
            "package_id": package_id,
            "project_id": "alpha",
            "created_at": "2026-08-09T12:00:00Z",
            "status": "Candidate",
            "readiness": readiness.value,
            "parent_ids": [],
            "source_hashes": {
                "source-tree": _tree_hash(source_root),
                "input-zip": sha256_file(source_zip),
            },
        },
        evidence_index={
            "schema": "continuity.evidence-index/v1",
            "items": [
                {
                    "source_id": "source-tree",
                    "state": "Verified",
                    "reference": "external-by-sha256",
                }
            ],
        },
        secure_handling_approvals=secure_handling_approvals,
        readiness=readiness,
        output=tmp_path / package_id,
    )


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _package_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _approval(package_id: str) -> ApprovalRecord:
    return ApprovalRecord(
        "approval-promote-alpha",
        "promote-candidate",
        (package_id,),
        "approved",
        "user",
        "conversation://approval/42",
        "2026-08-09T13:00:00Z",
    )


def test_candidate_contract_is_complete_and_sources_are_unchanged(tmp_path: Path) -> None:
    """Catches construction omitting a required handoff artifact or mutating evidence."""
    request = _request(tmp_path)
    source_root = tmp_path / "source"
    source_zip = tmp_path / "input.zip"
    before_tree = _tree_hash(source_root)
    before_zip = sha256_file(source_zip)

    result = build_candidate(request)

    assert result.release == request.output
    assert result.root == request.output / "package"
    assert result.zip_path == request.output / "candidate-alpha.zip"
    regular_paths = set(_package_snapshot(result.root))
    assert regular_paths == {
        *DOCUMENT_PATHS,
        "canonical/src/app.py",
        "evidence/INDEX.json",
        "lineage/LINEAGE.json",
        "receipts/RECONCILIATION.json",
        "MANIFEST.json",
        "SHA256SUMS.txt",
    }
    assert all((result.root / path).read_text(encoding="utf-8").strip() for path in DOCUMENT_PATHS)
    assert (result.root / "canonical").is_dir()
    assert (result.root / "receipts").is_dir()
    assert _tree_hash(source_root) == before_tree
    assert sha256_file(source_zip) == before_zip
    assert result.status is PackageStatus.CANDIDATE
    assert validate_package(result.root).valid


def test_manifest_and_checksums_cover_every_regular_file(tmp_path: Path) -> None:
    """Catches a packaged file escaping either integrity inventory."""
    result = build_candidate(_request(tmp_path))
    checksummed = set(_package_snapshot(result.root)) - {"SHA256SUMS.txt"}
    payload = checksummed - {"MANIFEST.json"}
    manifest = json.loads((result.root / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest_paths = {item["path"] for item in manifest["files"]}
    checksum_paths = {
        line.split("  ", 1)[1]
        for line in (result.root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    }

    assert manifest_paths == payload
    assert checksum_paths == checksummed
    manifest_line = next(
        line for line in (result.root / "SHA256SUMS.txt").read_text().splitlines()
        if line.endswith("  MANIFEST.json")
    )
    assert manifest_line == f"{sha256_file(result.root / 'MANIFEST.json')}  MANIFEST.json"


def test_validation_recalculates_digests_from_current_bytes(tmp_path: Path) -> None:
    """Catches validation trusting stored manifest and checksum claims."""
    result = build_candidate(_request(tmp_path))
    (result.root / "canonical/src/app.py").write_text("tampered = True\n", encoding="utf-8")

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("digest differs" in violation for violation in validation.violations)
    assert any("checksum inventory" in violation for violation in validation.violations)


@pytest.mark.parametrize(
    ("field", "expected_message"),
    (
        ("project_id", "project_id"),
        ("created_at", "created_at"),
        ("lineage_roots", "lineage_roots"),
        ("allow_conditional_promotion", "allow_conditional_promotion"),
        ("selected_source_hashes", "selected_source_hashes"),
    ),
)
def test_validation_rejects_incomplete_manifest_structure(
    tmp_path: Path, field: str, expected_message: str
) -> None:
    """Catches checksum-validity logic overlooking required manifest structure."""
    result = build_candidate(_request(tmp_path))
    manifest_path = result.root / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop(field)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    validation = validate_package(result.root)

    assert not validation.valid
    assert any(expected_message in violation for violation in validation.violations)


def test_validation_rejects_blocked_status_with_ready_readiness(tmp_path: Path) -> None:
    """Catches inconsistent lifecycle pairs being treated as safely blocked."""
    result = build_candidate(_request(tmp_path))
    manifest_path = result.root / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "Blocked"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("lifecycle/readiness" in violation for violation in validation.violations)


def test_candidate_zip_has_sorted_entries_and_fixed_metadata(tmp_path: Path) -> None:
    """Catches filesystem order or ambient timestamps leaking into the archive."""
    result = build_candidate(_request(tmp_path))

    with zipfile.ZipFile(result.zip_path) as archive:
        infos = archive.infolist()

    assert [info.filename for info in infos] == sorted(info.filename for info in infos)
    assert all(info.date_time == FIXED_ZIP_TIMESTAMP for info in infos)
    assert {info.filename for info in infos if info.is_dir()} >= {"canonical/", "receipts/"}


def test_identical_normalized_requests_make_identical_zips(tmp_path: Path) -> None:
    """Catches mapping insertion order or output location changing archive bytes."""
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = build_candidate(_request(first_root, package_id="same-package"))
    second_request = _request(second_root, package_id="same-package")
    second = build_candidate(second_request)

    assert first.zip_path.read_bytes() == second.zip_path.read_bytes()


def test_failed_construction_publishes_neither_directory_nor_zip(tmp_path: Path) -> None:
    """Catches validation failures leaking a partially built handoff."""
    request = _request(
        tmp_path,
        canonical_files={"src/missing.py": tmp_path / "does-not-exist.py"},
    )

    with pytest.raises((FileNotFoundError, ValueError)):
        build_candidate(request)

    assert not request.output.exists()


def test_build_never_overwrites_existing_output(tmp_path: Path) -> None:
    """Catches atomic publication replacing a prior package or archive."""
    request = _request(tmp_path)
    request.output.mkdir()
    sentinel = request.output / "owned.txt"
    sentinel.write_text("prior output\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        build_candidate(request)

    assert sentinel.read_text(encoding="utf-8") == "prior output\n"


def test_atomic_release_publication_never_replaces_a_racing_destination(tmp_path: Path) -> None:
    """Catches a destination created after validation being overwritten at publication."""
    temporary_release = tmp_path / ".temporary-release"
    temporary_release.mkdir()
    (temporary_release / "new.txt").write_text("new bytes\n", encoding="utf-8")
    destination = tmp_path / "release"
    destination.mkdir()
    sentinel = destination / "owned.txt"
    sentinel.write_text("racing owner\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _publish_release_no_replace(temporary_release, destination)

    assert sentinel.read_text(encoding="utf-8") == "racing owner\n"
    assert temporary_release.is_dir()


@pytest.mark.parametrize("destination", ("../escape.py", "/absolute.py", "C:\\escape.py"))
def test_unsafe_canonical_destination_is_rejected(tmp_path: Path, destination: str) -> None:
    """Catches canonical mappings escaping the package root."""
    source = tmp_path / "safe.py"
    source.write_text("safe = True\n", encoding="utf-8")
    request = _request(tmp_path, canonical_files={destination: source})

    with pytest.raises(ValueError):
        build_candidate(request)

    assert not request.output.exists()


@pytest.mark.parametrize("package_id", ("../escape", "nested/package", "nested\\package"))
def test_package_id_cannot_redirect_release_zip(tmp_path: Path, package_id: str) -> None:
    """Catches package identity being interpreted as a path outside the temporary release."""
    request = _request(tmp_path, package_id=package_id)
    request = CandidateBuildRequest(
        **{**request.__dict__, "output": tmp_path / "release"}
    )

    with pytest.raises(ValueError, match="package_id"):
        build_candidate(request)

    assert not request.output.exists()
    assert not (tmp_path / "escape.zip").exists()


def test_canonical_symlink_source_is_rejected_without_following(tmp_path: Path) -> None:
    """Catches copy construction following a link to bytes outside the selected source."""
    target = tmp_path / "target.txt"
    target.write_text("outside selection\n", encoding="utf-8")
    link = tmp_path / "source-link"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        build_candidate(_request(tmp_path, canonical_files={"linked.txt": link}))


def test_secret_bearing_file_requires_path_specific_secure_handling_approval(tmp_path: Path) -> None:
    """Catches broad or unrelated approvals including credential-bearing source bytes."""
    secret = tmp_path / "secrets.env"
    secret.write_text("API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    unrelated = ApprovalRecord(
        "approval-secret-other",
        "secure-handling",
        ("canonical/other.env",),
        "approved",
        "user",
        "conversation://approval/41",
        "2026-08-09T11:00:00Z",
    )

    with pytest.raises(ValueError, match="secure-handling approval"):
        build_candidate(
            _request(
                tmp_path,
                canonical_files={"secrets.env": secret},
                secure_handling_approvals=(unrelated,),
            )
        )

    exact = ApprovalRecord(
        "approval-secret-exact",
        "secure-handling",
        ("canonical/secrets.env",),
        "approved",
        "user",
        "conversation://approval/43",
        "2026-08-09T11:30:00Z",
    )
    result = build_candidate(
        _request(
            tmp_path,
            canonical_files={"secrets.env": secret},
            secure_handling_approvals=(exact,),
        )
    )
    assert (result.root / "canonical/secrets.env").read_bytes() == secret.read_bytes()


def test_secure_handling_approval_must_enumerate_each_secret_path(tmp_path: Path) -> None:
    """Catches a multi-file approval being mistaken for broad, unnamed authority."""
    first = tmp_path / "first.env"
    second = tmp_path / "second.env"
    first.write_text("API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    second.write_text("PASSWORD=highly-sensitive-password\n", encoding="utf-8")
    enumerated = ApprovalRecord(
        "approval-secret-enumerated",
        "secure-handling",
        ("canonical/first.env", "canonical/second.env"),
        "approved",
        "user",
        "conversation://approval/44",
        "2026-08-09T11:45:00Z",
    )

    result = build_candidate(
        _request(
            tmp_path,
            canonical_files={"first.env": first, "second.env": second},
            secure_handling_approvals=(enumerated,),
        )
    )

    assert (result.root / "canonical/first.env").read_bytes() == first.read_bytes()
    assert (result.root / "canonical/second.env").read_bytes() == second.read_bytes()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("approval_id", ""),
        ("source_id", " "),
        ("source_ref", ""),
        ("approved_at", "not-a-time"),
        ("action", "secure handling"),
        ("scope", ("canonical/*.env",)),
        ("scope", ("canonical/secrets.env", "canonical/*.env")),
    ),
)
def test_secret_approval_requires_complete_exact_provenance(
    tmp_path: Path, field: str, value: object
) -> None:
    """Catches unauditable or wildcard secret authority entering the package."""
    secret = tmp_path / "secrets.env"
    secret.write_text("API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    values = {
        "approval_id": "approval-secret-exact",
        "action": "secure-handling",
        "scope": ("canonical/secrets.env",),
        "decision": "approved",
        "source_id": "user",
        "source_ref": "conversation://approval/43",
        "approved_at": "2026-08-09T11:30:00Z",
    }
    values[field] = value
    approval = ApprovalRecord(**values)

    with pytest.raises(ValueError, match="secure-handling approval"):
        build_candidate(
            _request(
                tmp_path,
                canonical_files={"secrets.env": secret},
                secure_handling_approvals=(approval,),
            )
        )


def test_lineage_source_hashes_must_match_selected_sources(tmp_path: Path) -> None:
    """Catches lineage naming different evidence bytes than the package manifest."""
    request = _request(tmp_path)
    lineage = dict(request.lineage_data)
    lineage["source_hashes"] = {"source-tree": "f" * 64}
    request = CandidateBuildRequest(
        **{
            **request.__dict__,
            "lineage_data": lineage,
        }
    )

    with pytest.raises(ValueError, match="source hashes"):
        build_candidate(request)

    assert not request.output.exists()


@pytest.mark.parametrize(
    ("artifact", "field"),
    (
        ("lineage_data", "schema"),
        ("lineage_data", "project_id"),
        ("lineage_data", "created_at"),
        ("lineage_data", "status"),
        ("lineage_data", "readiness"),
        ("lineage_data", "parent_ids"),
        ("lineage_data", "source_hashes"),
        ("evidence_index", "schema"),
        ("evidence_index", "items"),
    ),
)
def test_incomplete_structured_request_is_rejected_before_publication(
    tmp_path: Path, artifact: str, field: str
) -> None:
    """Catches incomplete machine-readable contract artifacts reaching a release."""
    request = _request(tmp_path)
    incomplete = dict(getattr(request, artifact))
    incomplete.pop(field)
    request = CandidateBuildRequest(**{**request.__dict__, artifact: incomplete})

    with pytest.raises(ValueError):
        build_candidate(request)

    assert not request.output.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    (("status", "Canonical"), ("readiness", "Conditional")),
)
def test_request_lineage_lifecycle_must_match_candidate_inputs(
    tmp_path: Path, field: str, value: str
) -> None:
    """Catches contradictory request lineage being silently overwritten during build."""
    request = _request(tmp_path)
    request = CandidateBuildRequest(
        **{
            **request.__dict__,
            "lineage_data": {**request.lineage_data, field: value},
        }
    )

    with pytest.raises(ValueError, match=field):
        build_candidate(request)


def test_empty_evidence_index_is_rejected_before_publication(tmp_path: Path) -> None:
    """Catches an evidence index schema label substituting for actual evidence."""
    request = _request(tmp_path)
    request = CandidateBuildRequest(
        **{**request.__dict__, "evidence_index": {**request.evidence_index, "items": []}}
    )

    with pytest.raises(ValueError, match="evidence"):
        build_candidate(request)

    assert not request.output.exists()


@pytest.mark.parametrize(
    "created_at",
    ("", "2026-08-09", "2026-08-09 12:00:00Z", "2026-13-09T12:00:00Z"),
)
def test_build_rejects_non_rfc3339_creation_time(tmp_path: Path, created_at: str) -> None:
    """Catches ambiguous or invalid creation timestamps entering identity metadata."""
    request = _request(tmp_path)
    lineage = {**request.lineage_data, "created_at": created_at}
    request = CandidateBuildRequest(
        **{**request.__dict__, "created_at": created_at, "lineage_data": lineage}
    )

    with pytest.raises(ValueError, match="RFC3339"):
        build_candidate(request)


def test_blocking_reconciliation_builds_only_blocked_status(tmp_path: Path) -> None:
    """Catches unresolved material conflicts being mislabeled promotable."""
    result = build_candidate(_request(tmp_path, report=_report(blocked=True)))
    manifest = json.loads((result.root / "MANIFEST.json").read_text(encoding="utf-8"))

    assert result.status is PackageStatus.BLOCKED
    assert manifest["status"] == "Blocked"
    assert manifest["readiness"] == "Blocked"
    with pytest.raises(ValueError, match="Candidate"):
        promote_candidate(
            result.root,
            tmp_path / "canonical-alpha",
            _approval(result.package_id),
            "2026-08-09T14:00:00Z",
        )


@pytest.mark.parametrize(
    "approval",
    (
        None,
        ApprovalRecord("wrong-action", "promote", ("candidate-alpha",), "approved", "user", "ref", "2026-08-09T13:00:00Z"),
        ApprovalRecord("wrong-scope", "promote-candidate", ("other",), "approved", "user", "ref", "2026-08-09T13:00:00Z"),
    ),
)
def test_promotion_requires_exact_action_and_candidate_scope(
    tmp_path: Path, approval: ApprovalRecord | None
) -> None:
    """Catches inferred or differently scoped authority promoting a candidate."""
    candidate = build_candidate(_request(tmp_path))

    with pytest.raises(ValueError, match="approval"):
        promote_candidate(
            candidate.root,
            tmp_path / "canonical-alpha",
            approval,
            "2026-08-09T14:00:00Z",
        )

    assert not (tmp_path / "canonical-alpha").exists()
    assert not (tmp_path / "canonical-alpha.zip").exists()


def test_promotion_is_append_only_and_regenerates_integrity_artifacts(tmp_path: Path) -> None:
    """Catches in-place promotion or stale candidate inventories in the successor."""
    candidate = build_candidate(_request(tmp_path))
    candidate_before = _package_snapshot(candidate.root)
    candidate_zip_before = candidate.zip_path.read_bytes()

    canonical = promote_candidate(
        candidate.root,
        tmp_path / "canonical-alpha",
        _approval(candidate.package_id),
        "2026-08-09T14:00:00Z",
    )

    assert canonical.root != candidate.root
    assert canonical.status is PackageStatus.CANONICAL
    assert canonical.package_id == "canonical-alpha"
    assert canonical.release == tmp_path / "canonical-alpha"
    assert canonical.root == canonical.release / "package"
    assert canonical.zip_path == canonical.release / "canonical-alpha.zip"
    assert validate_package(canonical.root).valid
    assert (canonical.root / "receipts/PROMOTION.json").is_file()
    receipt = json.loads((canonical.root / "receipts/PROMOTION.json").read_text(encoding="utf-8"))
    assert receipt["candidate_package_id"] == candidate.package_id
    assert receipt["candidate_sha256"] == candidate.package_sha256
    assert receipt["approval"]["approval_id"] == "approval-promote-alpha"
    successor_manifest = json.loads((canonical.root / "MANIFEST.json").read_text())
    successor_lineage = json.loads((canonical.root / "lineage/LINEAGE.json").read_text())
    assert successor_manifest["created_at"] == "2026-08-09T14:00:00Z"
    assert successor_lineage["created_at"] == "2026-08-09T14:00:00Z"
    assert _package_snapshot(candidate.root) == candidate_before
    assert candidate.zip_path.read_bytes() == candidate_zip_before
    assert canonical.zip_path.read_bytes() != candidate.zip_path.read_bytes()


def test_conditional_candidate_requires_explicit_build_permission_to_promote(
    tmp_path: Path,
) -> None:
    """Catches a Conditional package being promoted without its recorded allowance."""
    candidate = build_candidate(
        _request(tmp_path, readiness=ReadinessStatus.CONDITIONAL)
    )

    with pytest.raises(ValueError, match="Conditional"):
        promote_candidate(
            candidate.root,
            tmp_path / "canonical-conditional",
            _approval(candidate.package_id),
            "2026-08-09T14:00:00Z",
        )


def test_recorded_conditional_allowance_permits_exactly_approved_promotion(
    tmp_path: Path,
) -> None:
    """Catches the allowed Conditional lifecycle branch being rejected as Blocked."""
    request = _request(tmp_path, readiness=ReadinessStatus.CONDITIONAL)
    request = CandidateBuildRequest(
        **{**request.__dict__, "allow_conditional_promotion": True}
    )
    candidate = build_candidate(request)

    canonical = promote_candidate(
        candidate.root,
        tmp_path / "canonical-conditional",
        _approval(candidate.package_id),
        "2026-08-09T14:00:00Z",
    )

    assert canonical.status is PackageStatus.CANONICAL
    assert validate_package(canonical.root).valid


@pytest.mark.parametrize("status", (PackageStatus.CANONICAL, PackageStatus.SUPERSEDED))
def test_only_candidate_status_can_be_promoted(tmp_path: Path, status: PackageStatus) -> None:
    """Catches replaying promotion against canonical or historical package state."""
    candidate = build_candidate(_request(tmp_path))
    manifest_path = candidate.root / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = status.value
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError):
        promote_candidate(
            candidate.root,
            tmp_path / f"successor-{status.value}",
            _approval(candidate.package_id),
            "2026-08-09T14:00:00Z",
        )


@pytest.mark.parametrize("created_at", ("", "2026-08-09", "tomorrow"))
def test_promotion_requires_explicit_rfc3339_successor_time(
    tmp_path: Path, created_at: str
) -> None:
    """Catches promotion reusing candidate time or accepting ambiguous successor time."""
    candidate = build_candidate(_request(tmp_path))

    with pytest.raises(ValueError, match="RFC3339"):
        promote_candidate(
            candidate.root,
            tmp_path / "canonical-alpha",
            _approval(candidate.package_id),
            created_at,
        )

    assert not (tmp_path / "canonical-alpha").exists()
