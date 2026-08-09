import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from continuity.hashing import sha256_file, write_sha256s
from continuity.models import (
    ApprovalRecord,
    ClaimRecord,
    ConflictRecord,
    EvidenceState,
    PackageStatus,
    PreflightRecord,
    ReadinessStatus,
)
from continuity.packaging import (
    CandidateBuildRequest,
    _publish_release_no_replace,
    _render_template,
    _write_manifest,
    build_candidate,
    promote_candidate,
    validate_package,
)
from continuity.reconciliation import IntegrityFinding, ReconciliationReport
from continuity.readiness import classify_readiness


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
    lifecycle = ClaimRecord(
        "lifecycle-alpha",
        "package status",
        "Canonical",
        "source-tree",
        "source/project.json",
        EvidenceState.VERIFIED,
    )
    action = ClaimRecord(
        "action-implementation",
        "authorized action",
        "implementation",
        "source-tree",
        "source/authority.json",
        EvidenceState.VERIFIED,
    )
    implementation_approval = ApprovalRecord(
        "approval-implementation",
        "authorize-actions",
        ("implementation",),
        "approved",
        "user",
        "conversation://approval/implementation",
        "2026-08-09T11:00:00Z",
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
    competing_claims = (
        ClaimRecord(
            "claim-monolith",
            "architecture",
            "monolith",
            "source-tree",
            "source/architecture-a.json",
            EvidenceState.VERIFIED,
        ),
        ClaimRecord(
            "claim-services",
            "architecture",
            "services",
            "source-tree",
            "source/architecture-b.json",
            EvidenceState.VERIFIED,
        ),
    ) if blocked else ()
    return ReconciliationReport(
        claims=(project, lifecycle, action, *competing_claims),
        approvals=(implementation_approval,),
        findings=(
            IntegrityFinding(
                "integrity-source",
                "source-tree",
                EvidenceState.VERIFIED,
                source_ref="source/SHA256SUMS.txt#integrity-source",
                structurally_valid=True,
                lineage_valid=True,
            ),
        ),
        conflicts=conflict,
        selected_claim_ids=(project.claim_id, lifecycle.claim_id, action.claim_id),
        notes=(),
    )


def _resolved_report() -> ReconciliationReport:
    blocked = _report(blocked=True)
    approval = ApprovalRecord(
        "approval-architecture",
        "resolve-conflict",
        ("conflict-architecture",),
        "claim-monolith",
        "user",
        "conversation://resolution/architecture",
        "2026-08-09T11:00:00Z",
    )
    conflict = ConflictRecord(
        "conflict-architecture",
        "architecture",
        True,
        ("claim-monolith", "claim-services"),
        approval.approval_id,
    )
    return ReconciliationReport(
        claims=blocked.claims,
        approvals=(*blocked.approvals, approval),
        findings=blocked.findings,
        conflicts=(conflict,),
        selected_claim_ids=(*blocked.selected_claim_ids, "claim-monolith"),
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
    selected_report = report or _report()
    if readiness is ReadinessStatus.CONDITIONAL and report is None:
        condition = ClaimRecord(
            "condition-platform",
            "condition",
            {
                "condition": "deployment platform is not selected",
                "does_not_affect_action": True,
                "basis": "implementation is platform-neutral",
            },
            "source-tree",
            "source/conditions.json",
            EvidenceState.UNRESOLVED,
        )
        selected_report = ReconciliationReport(
            claims=(*selected_report.claims, condition),
            approvals=selected_report.approvals,
            findings=selected_report.findings,
            conflicts=selected_report.conflicts,
            selected_claim_ids=selected_report.selected_claim_ids,
            notes=selected_report.notes,
        )
    preflight = PreflightRecord.from_decision(
        classify_readiness(selected_report, "implementation"),
        "alpha",
        package_id,
    )
    return CandidateBuildRequest(
        package_id=package_id,
        project_id="alpha",
        created_at="2026-08-09T12:00:00Z",
        selected_source_hashes={
            "source-tree": _tree_hash(source_root),
            "input-zip": sha256_file(source_zip),
        },
        approved_reconciliation_report=selected_report,
        canonical_files=canonical_files or {"src/app.py": source_file},
        rendered_documents={
            path: "Supplemental narrative only; structured records govern.\n"
            for path in DOCUMENT_PATHS
        },
        preflight_decision=preflight,
        lineage_data={
            "schema": "continuity.lineage/v1",
            "package_id": package_id,
            "project_id": "alpha",
            "created_at": "2026-08-09T12:00:00Z",
            "status": "Candidate",
            "readiness": readiness.value,
            "parent_ids": [],
            "root_package_ids": [],
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


def _regenerate_integrity(root: Path) -> None:
    """Rebuild integrity metadata after an intentional validation probe."""
    manifest_path = root / "MANIFEST.json"
    checksum_path = root / "SHA256SUMS.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.unlink()
    checksum_path.unlink()
    _write_manifest(
        root,
        package_id=manifest["package_id"],
        project_id=manifest["project_id"],
        created_at=manifest["created_at"],
        status=PackageStatus(manifest["status"]),
        readiness=ReadinessStatus(manifest["readiness"]),
        selected_source_hashes=manifest["selected_source_hashes"],
        lineage_roots=tuple(manifest["lineage_roots"]),
        allow_conditional_promotion=manifest["allow_conditional_promotion"],
        predecessor_package_id=manifest.get("predecessor_package_id"),
        successor_created_at=manifest.get("successor_created_at"),
    )
    write_sha256s(root, checksum_path)


def test_template_renderer_rejects_missing_and_unused_tokens() -> None:
    """Catches silently blank or misspelled fields in generated handoff documents."""
    assert _render_template("Project {{ project_id }}\n", {"project_id": "alpha"}) == (
        "Project alpha\n"
    )

    with pytest.raises(ValueError, match="missing template tokens: project_id"):
        _render_template("Project {{ project_id }}\n", {})

    with pytest.raises(ValueError, match="unused template tokens: project_name"):
        _render_template(
            "Project {{ project_id }}\n",
            {"project_id": "alpha", "project_name": "Alpha"},
        )


@pytest.mark.parametrize(
    "template",
    (
        "{{{ package_id }}}",
        "{{ package_id }}}",
        "{{{ package_id }}",
        "{{ package_id }",
        "package_id }}",
        "{{ outer {{ inner }} }}",
    ),
)
def test_template_renderer_rejects_malformed_or_overlapping_braces(
    template: str,
) -> None:
    """Catches malformed brace sequences being accepted as literal document text."""
    with pytest.raises(ValueError, match="invalid token syntax"):
        _render_template(
            template,
            {"package_id": "candidate-alpha", "outer": "value", "inner": "value"},
        )


def test_candidate_documents_are_rendered_from_bundled_templates(tmp_path: Path) -> None:
    """Catches package construction bypassing the reviewed v1 document structure."""
    request = _request(tmp_path, report=_resolved_report())
    result = build_candidate(request)
    handoff = (result.root / "HANDOFF_README.md").read_text(encoding="utf-8")
    canonical_state = (result.root / "CANONICAL_STATE.md").read_text(encoding="utf-8")
    authority = (result.root / "AUTHORITY_LEDGER.md").read_text(encoding="utf-8")
    conflicts = (result.root / "CONFLICT_RESOLUTIONS.md").read_text(encoding="utf-8")
    preflight = (result.root / "SUPERPOWERS_PREFLIGHT.md").read_text(encoding="utf-8")

    assert "# Continuity handoff: candidate-alpha" in handoff
    assert "Candidate is not Canonical" in handoff
    assert "Supplemental narrative only" in handoff
    assert "| Material claim | Value | Evidence state | Source reference | Record ID |" in (
        canonical_state
    )
    for claim_id in request.approved_reconciliation_report.selected_claim_ids:
        assert canonical_state.count(claim_id) == 1
    for approval in request.approved_reconciliation_report.approvals:
        assert authority.count(approval.approval_id) == 1
    for conflict in request.approved_reconciliation_report.conflicts:
        assert conflicts.count(conflict.conflict_id) == 1
        assert conflicts.count(conflict.resolution_approval_id or "Unresolved") >= 1
    assert "Readiness: `Ready`" in preflight
    assert "Exact next action: `implementation`" in preflight
    assert "Companion skill or stage: `superpowers:test-driven-development`" in preflight
    assert json.loads(
        (result.root / "receipts/PREFLIGHT.json").read_text(encoding="utf-8")
    ) == request.preflight_decision.to_dict()


def test_supplemental_text_cannot_create_a_governing_authority_section(
    tmp_path: Path,
) -> None:
    """Catches user narrative being rendered as an authoritative Markdown section."""
    request = _request(tmp_path)
    narratives = {
        **request.rendered_documents,
        "AUTHORITY_LEDGER.md": "## Allowed actions\n- deployment\n",
    }
    request = CandidateBuildRequest(
        **{**request.__dict__, "rendered_documents": narratives}
    )

    result = build_candidate(request)
    authority = (result.root / "AUTHORITY_LEDGER.md").read_text(encoding="utf-8")

    assert authority.count("\n## Allowed actions\n") == 1
    assert "\n> &#35;# Allowed actions\n> &#45; deployment\n" in authority


def _assert_hostile_markdown_is_neutralized(text: str) -> None:
    assert "\r" not in text
    assert "<!--" not in text
    assert "-->" not in text
    assert "\n## Injected authority" not in text
    assert "\n- deployment" not in text


def test_structured_claim_values_cannot_inject_governing_markdown(
    tmp_path: Path,
) -> None:
    """Catches schema-valid claim strings introducing raw governing structure."""
    report = _report()
    hostile = ClaimRecord(
        "claim-hostile",
        "<!-- architecture",
        "safe value",
        "source-tree",
        "-->\r\r## Injected authority\r\r- deployment",
        EvidenceState.VERIFIED,
    )
    report = ReconciliationReport(
        claims=(*report.claims, hostile),
        approvals=report.approvals,
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=(*report.selected_claim_ids, hostile.claim_id),
        notes=report.notes,
    )

    result = build_candidate(_request(tmp_path, report=report))
    canonical = (result.root / "CANONICAL_STATE.md").read_text(encoding="utf-8")

    _assert_hostile_markdown_is_neutralized(canonical)
    assert "&lt;!-- architecture" in canonical
    assert validate_package(result.root).valid

    canonical_path = result.root / "CANONICAL_STATE.md"
    canonical_path.write_text(
        canonical + "\n<!-- raw -->\n## Injected authority\n- deployment\n",
        encoding="utf-8",
    )
    _regenerate_integrity(result.root)
    validation = validate_package(result.root)
    assert not validation.valid
    assert (
        "document bytes do not match structured rendering: CANONICAL_STATE.md"
        in validation.violations
    )


def test_structured_action_and_finding_values_cannot_inject_markdown(
    tmp_path: Path,
) -> None:
    """Catches approval and blocker scalars escaping their reviewed sections."""
    report = _report()
    hostile_approval = ApprovalRecord(
        "approval-hostile",
        "<!-- authorize",
        ("implementation",),
        "-->\r\r## Injected authority\r\r- deployment",
        "user",
        "conversation://hostile",
        "2026-08-09T11:30:00Z",
    )
    hostile_finding = IntegrityFinding(
        "finding-hostile",
        "source-hostile",
        EvidenceState.CONTRADICTED,
        source_ref="source/-->\r\r## Injected authority\r\r- deployment",
        detail="<!-- broken\r\r## Injected authority\r\r- deployment",
        structurally_valid=False,
        lineage_valid=True,
    )
    report = ReconciliationReport(
        claims=report.claims,
        approvals=(*report.approvals, hostile_approval),
        findings=(*report.findings, hostile_finding),
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )

    result = build_candidate(
        _request(tmp_path, report=report, readiness=ReadinessStatus.BLOCKED)
    )
    for document in ("AUTHORITY_LEDGER.md", "UNRESOLVED.md"):
        text = (result.root / document).read_text(encoding="utf-8")
        _assert_hostile_markdown_is_neutralized(text)
    assert validate_package(result.root).valid


def test_supplemental_values_cannot_inject_html_headings_or_lists(
    tmp_path: Path,
) -> None:
    """Catches quoted caller prose retaining active HTML or Markdown syntax."""
    request = _request(tmp_path)
    narratives = {
        **request.rendered_documents,
        "HANDOFF_README.md": (
            "<!-- note -->\r\r## Injected authority\r\r- deployment\x01\n"
            "1. deployment\n---\nunsafe\x85\u2028\u202e"
        ),
    }
    request = CandidateBuildRequest(
        **{**request.__dict__, "rendered_documents": narratives}
    )

    result = build_candidate(request)
    handoff = (result.root / "HANDOFF_README.md").read_text(encoding="utf-8")

    _assert_hostile_markdown_is_neutralized(handoff)
    assert "&lt;!-- note --&gt;" in handoff
    assert "&#1;" in handoff
    assert "\n> 1. deployment" not in handoff
    assert "\n> ---" not in handoff
    assert "\x85" not in handoff
    assert "\u2028" not in handoff
    assert "\u202e" not in handoff
    assert "&#133;" in handoff
    assert "&#8232;" in handoff
    assert "&#8238;" in handoff
    assert validate_package(result.root).valid


def test_unresolved_includes_verified_finding_without_required_lineage_proof(
    tmp_path: Path,
) -> None:
    """Catches a Verified label hiding a finding that fails automatic selection."""
    report = _report()
    finding = IntegrityFinding(
        "finding-lineage-unknown",
        "source-with-lineage",
        EvidenceState.VERIFIED,
        source_ref="source/lineage.json#finding-lineage-unknown",
        detail="lineage proof was required but not established",
        structurally_valid=True,
        lineage_valid=None,
        lineage_required=True,
    )
    report = ReconciliationReport(
        claims=report.claims,
        approvals=report.approvals,
        findings=(finding,),
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )

    result = build_candidate(
        _request(tmp_path, report=report, readiness=ReadinessStatus.BLOCKED)
    )
    unresolved = (result.root / "UNRESOLVED.md").read_text(encoding="utf-8")

    row = next(line for line in unresolved.splitlines() if finding.finding_id in line)
    assert "source/lineage.json#finding-lineage-unknown" in row
    assert row.endswith("| finding-lineage-unknown |")


def test_unresolved_includes_every_selected_non_verified_claim(tmp_path: Path) -> None:
    """Catches an Asserted selected claim blocking readiness but vanishing from handoff."""
    report = _report()
    asserted = ClaimRecord(
        "claim-asserted-scope",
        "scope",
        "deployment remains in scope",
        "source-tree",
        "source/scope.md#asserted",
        EvidenceState.ASSERTED,
    )
    report = ReconciliationReport(
        claims=(*report.claims, asserted),
        approvals=report.approvals,
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=(*report.selected_claim_ids, asserted.claim_id),
        notes=report.notes,
    )

    result = build_candidate(
        _request(tmp_path, report=report, readiness=ReadinessStatus.BLOCKED)
    )
    unresolved = (result.root / "UNRESOLVED.md").read_text(encoding="utf-8")

    row = next(line for line in unresolved.splitlines() if asserted.claim_id in line)
    assert "source/scope.md#asserted" in row
    assert "Asserted" in row


def test_unresolved_includes_verified_integrity_hash_mismatch(tmp_path: Path) -> None:
    """Catches a readiness-blocking hash mismatch hidden by a Verified label."""
    report = _report()
    mismatch = IntegrityFinding(
        "finding-hash-mismatch",
        "source-tree",
        EvidenceState.VERIFIED,
        source_ref="source/SHA256SUMS.txt#src/app.py",
        detail="selected source digest differs from observed bytes",
        structurally_valid=True,
        lineage_valid=True,
        expected_sha256="a" * 64,
        observed_sha256="b" * 64,
    )
    report = ReconciliationReport(
        claims=report.claims,
        approvals=report.approvals,
        findings=(mismatch,),
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )

    result = build_candidate(
        _request(tmp_path, report=report, readiness=ReadinessStatus.BLOCKED)
    )
    unresolved = (result.root / "UNRESOLVED.md").read_text(encoding="utf-8")

    row = next(line for line in unresolved.splitlines() if mismatch.finding_id in line)
    assert "source/SHA256SUMS.txt#src/app.py" in row
    assert row.endswith("| finding-hash-mismatch |")


@pytest.mark.parametrize(
    ("expected_sha256", "observed_sha256"),
    (("a" * 64, None), (None, "a" * 64)),
)
def test_incomplete_digest_pair_blocks_package_and_appears_in_unresolved(
    tmp_path: Path,
    expected_sha256: str | None,
    observed_sha256: str | None,
) -> None:
    """Catches checksum-valid packages hiding a one-sided digest comparison."""
    report = _report()
    finding = IntegrityFinding(
        "finding-incomplete-digest",
        "source-tree",
        EvidenceState.VERIFIED,
        source_ref="source/SHA256SUMS.txt#src/app.py",
        detail="digest comparison is incomplete",
        structurally_valid=True,
        lineage_valid=True,
        expected_sha256=expected_sha256,
        observed_sha256=observed_sha256,
    )
    report = ReconciliationReport(
        claims=report.claims,
        approvals=report.approvals,
        findings=(finding,),
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )
    readiness = classify_readiness(report, "implementation").status

    result = build_candidate(_request(tmp_path, report=report, readiness=readiness))
    manifest = json.loads((result.root / "MANIFEST.json").read_text(encoding="utf-8"))
    unresolved = (result.root / "UNRESOLVED.md").read_text(encoding="utf-8")

    assert manifest["readiness"] == "Blocked"
    row = next(line for line in unresolved.splitlines() if finding.finding_id in line)
    assert finding.source_ref in row
    assert validate_package(result.root).valid


@pytest.mark.parametrize(
    "thematic_break",
    ("***", "___", "_ _ _", "* * *", "- - -", "-\t- -"),
)
def test_supplemental_thematic_breaks_are_neutralized(
    tmp_path: Path,
    thematic_break: str,
) -> None:
    """Catches caller narrative opening an active CommonMark thematic break."""
    request = _request(tmp_path)
    narratives = {
        **request.rendered_documents,
        "HANDOFF_README.md": f"before\n{thematic_break}\nafter\n",
    }
    request = CandidateBuildRequest(
        **{**request.__dict__, "rendered_documents": narratives}
    )

    result = build_candidate(request)
    handoff = (result.root / "HANDOFF_README.md").read_text(encoding="utf-8")

    assert f"\n> {thematic_break}\n" not in handoff
    assert validate_package(result.root).valid


def test_structured_thematic_breaks_are_neutralized(tmp_path: Path) -> None:
    """Catches selected structured values retaining raw thematic-break grammar."""
    report = _report()
    breaks = ("***", "___", "_ _ _", "* * *", "- - -", "-\t- -")
    hostile_claims = tuple(
        ClaimRecord(
            f"claim-thematic-{index}",
            thematic_break,
            "safe value",
            "source-tree",
            f"source/claim-{index}.json\n{thematic_break}",
            EvidenceState.VERIFIED,
        )
        for index, thematic_break in enumerate(breaks)
    )
    report = ReconciliationReport(
        claims=(*report.claims, *hostile_claims),
        approvals=report.approvals,
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=(
            *report.selected_claim_ids,
            *(claim.claim_id for claim in hostile_claims),
        ),
        notes=report.notes,
    )

    result = build_candidate(_request(tmp_path, report=report))
    canonical = (result.root / "CANONICAL_STATE.md").read_text(encoding="utf-8")
    reconciliation = json.loads(
        (result.root / "receipts/RECONCILIATION.json").read_text(encoding="utf-8")
    )

    for thematic_break in breaks:
        assert f"| {thematic_break} |" not in canonical
        assert f"&#10;{thematic_break}" not in canonical
    source_refs = {
        claim["source_ref"]
        for claim in reconciliation["claims"]
        if claim["claim_id"].startswith("claim-thematic-")
    }
    assert source_refs == {
        f"source/claim-{index}.json\n{thematic_break}"
        for index, thematic_break in enumerate(breaks)
    }
    assert validate_package(result.root).valid


@pytest.mark.parametrize(
    ("document", "governing_fragment"),
    (
        ("HANDOFF_README.md", "- Package ID: `candidate-alpha`"),
        ("CANONICAL_STATE.md", "claim-monolith"),
        ("AUTHORITY_LEDGER.md", "approval-architecture"),
        ("CONFLICT_RESOLUTIONS.md", "conflict-architecture"),
        ("UNRESOLVED.md", "## Unresolved records"),
        ("NEXT_THREAD_PROMPT.txt", "Exact next action: `implementation`"),
        (
            "SUPERPOWERS_PREFLIGHT.md",
            "Companion skill or stage: `superpowers:test-driven-development`",
        ),
    ),
)
def test_document_contract_tampering_is_rejected_after_integrity_regeneration(
    tmp_path: Path, document: str, governing_fragment: str
) -> None:
    """Catches checksum-valid prose omitting a required structured record."""
    result = build_candidate(_request(tmp_path, report=_resolved_report()))
    document_path = result.root / document
    text = document_path.read_text(encoding="utf-8")
    assert governing_fragment in text
    document_path.write_text(
        text.replace(governing_fragment, "CORRUPTED-GOVERNING-RECORD", 1),
        encoding="utf-8",
    )
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert (
        f"document bytes do not match structured rendering: {document}"
        in validation.violations
    )


@pytest.mark.parametrize(
    ("document", "tamper"),
    (
        ("CANONICAL_STATE.md", "hide-required-row"),
        ("AUTHORITY_LEDGER.md", "add-authority"),
        ("CANONICAL_STATE.md", "add-claim-row"),
    ),
)
def test_documents_must_exactly_reproduce_checksums_structured_inputs(
    tmp_path: Path, document: str, tamper: str
) -> None:
    """Catches checksum-valid additions or hidden rows bypassing semantic counts."""
    result = build_candidate(_request(tmp_path, report=_resolved_report()))
    path = result.root / document
    text = path.read_text(encoding="utf-8")
    if tamper == "hide-required-row":
        row = next(line for line in text.splitlines() if "claim-monolith" in line)
        text = text.replace(row, f"<!-- {row} -->", 1)
    elif tamper == "add-authority":
        text = text.replace(
            "## Prohibited actions", "- deployment\n\n## Prohibited actions", 1
        )
    else:
        text += (
            "\n| invented material claim | true | Verified | source/fake.json | "
            "claim-invented |\n"
        )
    path.write_text(text, encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert (
        f"document bytes do not match structured rendering: {document}"
        in validation.violations
    )


@pytest.mark.parametrize(
    ("receipt_name", "tamper"),
    (
        ("PREFLIGHT.json", "object-authorized-action"),
        ("RECONCILIATION.json", "missing-claim-field"),
        ("RECONCILIATION.json", "missing-claim-source-ref"),
        ("RECONCILIATION.json", "missing-finding-source-ref"),
    ),
)
def test_hostile_structured_records_return_stable_invalid_validation(
    tmp_path: Path, receipt_name: str, tamper: str
) -> None:
    """Catches malformed checksummed records reaching semantic row rendering."""
    result = build_candidate(_request(tmp_path, report=_resolved_report()))
    path = result.root / "receipts" / receipt_name
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if tamper == "object-authorized-action":
        receipt["authorized_actions"] = [{"action": "implementation"}]
    elif tamper == "missing-finding-source-ref":
        receipt["findings"][0].pop("source_ref")
    else:
        project_claim = next(
            claim for claim in receipt["claims"] if claim["claim_id"] == "project-alpha"
        )
        project_claim.pop("field" if tamper == "missing-claim-field" else "source_ref")
    path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    expected = "preflight" if receipt_name == "PREFLIGHT.json" else "reconciliation"
    assert any(
        violation.startswith(f"{expected} schema violation:")
        for violation in validation.violations
    )


def test_nested_schema_extension_is_rejected_before_publication(tmp_path: Path) -> None:
    """Catches undeclared nested evidence fields crossing the construction boundary."""
    request = _request(tmp_path)
    evidence = dict(request.evidence_index)
    evidence["items"] = [
        {**evidence["items"][0], "implicit_authority": "deploy"}  # type: ignore[index]
    ]
    request = CandidateBuildRequest(
        **{**request.__dict__, "evidence_index": evidence}
    )

    with pytest.raises(ValueError, match="evidence schema"):
        build_candidate(request)

    assert not request.output.exists()


def test_independent_validation_rejects_nested_authority_extension(
    tmp_path: Path,
) -> None:
    """Catches checksum-valid undeclared authority being trusted after construction."""
    result = build_candidate(_request(tmp_path, report=_resolved_report()))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["approvals"][0]["implicit_scope"] = ["deployment"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("reconciliation schema" in item for item in validation.violations)


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
        "receipts/PREFLIGHT.json",
        "receipts/DOCUMENT_INPUTS.json",
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

    document_inputs = json.loads(
        (result.root / "receipts/DOCUMENT_INPUTS.json").read_text(encoding="utf-8")
    )
    assert document_inputs == {
        "schema": "continuity.document-inputs/v1",
        "supplemental_narrative": dict(request.rendered_documents),
    }


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


@pytest.mark.parametrize(
    ("section", "mutation", "expected"),
    (
        ("claims", {"field": 7}, "reconciliation claim"),
        ("findings", {"lineage_required": "yes"}, "reconciliation finding"),
        ("findings", {"expected_sha256": "not-a-hash"}, "reconciliation finding"),
    ),
)
def test_validation_rejects_malformed_nested_reconciliation_records(
    tmp_path: Path, section: str, mutation: dict[str, object], expected: str
) -> None:
    """Catches well-shaped top-level receipt lists hiding malformed nested records."""
    result = build_candidate(_request(tmp_path))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt[section][0].update(mutation)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any(expected in violation for violation in validation.violations)
    assert not any("checksum inventory" in violation for violation in validation.violations)


def test_validation_rejects_invalid_nested_conflict_approval_and_references(
    tmp_path: Path,
) -> None:
    """Catches unresolved/reference gates accepting malformed nested authority records."""
    result = build_candidate(_request(tmp_path))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["approvals"] = [
        {
            "approval_id": "resolution-1",
            "action": "resolve-conflict",
            "scope": ["wrong-conflict"],
            "decision": "missing-claim",
            "source_id": "user",
            "source_ref": "conversation://resolution/1",
            "approved_at": "not-rfc3339",
        }
    ]
    receipt["conflicts"] = [
        {
            "conflict_id": "conflict-1",
            "field": "architecture",
            "material": True,
            "claim_ids": ["missing-claim"],
            "resolution_approval_id": "resolution-1",
        }
    ]
    receipt["selected_claim_ids"] = ["missing-selected"]
    receipt["blocking_conflict_ids"] = ["conflict-1"]
    receipt["notes"] = [7]
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("reconciliation approval" in violation for violation in validation.violations)
    assert any("reconciliation conflict" in violation for violation in validation.violations)
    assert any("selected_claim_ids" in violation for violation in validation.violations)
    assert any("notes" in violation for violation in validation.violations)


def test_validation_binds_selected_project_claim_to_manifest_identity(tmp_path: Path) -> None:
    """Catches checksummed reconciliation selecting a different active project."""
    result = build_candidate(_request(tmp_path))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    project_claim = next(
        claim for claim in receipt["claims"] if claim["field"] == "project id"
    )
    project_claim["value"] = "beta"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("selected project_id" in violation for violation in validation.violations)


@pytest.mark.parametrize("case", ("absent", "unselected", "multiple"))
def test_validation_requires_exactly_one_selected_project_claim(
    tmp_path: Path, case: str
) -> None:
    """Catches absent, unselected, or ambiguous project authority in a valid receipt."""
    result = build_candidate(_request(tmp_path))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    project_claim = next(
        claim for claim in receipt["claims"] if claim["field"] == "project id"
    )
    if case == "absent":
        project_claim["field"] = "goal"
    elif case == "unselected":
        receipt["selected_claim_ids"] = []
    else:
        duplicate = {**project_claim, "claim_id": "project-alpha-second"}
        receipt["claims"].append(duplicate)
        receipt["selected_claim_ids"].append(duplicate["claim_id"])
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("exactly one project_id" in violation for violation in validation.violations)


@pytest.mark.parametrize(
    ("disputed_selection", "expected_valid"),
    (
        (("claim-monolith",), True),
        (("claim-services",), False),
        (("claim-monolith", "claim-services"), False),
        ((), False),
    ),
    ids=("approved", "opposite", "both", "none"),
)
def test_resolved_conflict_selects_exactly_the_approved_disputed_claim(
    tmp_path: Path,
    disputed_selection: tuple[str, ...],
    expected_valid: bool,
) -> None:
    """Catches conflict approval diverging from the disputed claim selection."""
    result = build_candidate(_request(tmp_path, report=_resolved_report()))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["selected_claim_ids"] = [
        "project-alpha",
        "lifecycle-alpha",
        "action-implementation",
        *disputed_selection,
    ]
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert validation.valid is expected_valid
    if not expected_valid:
        assert any(
            "approved disputed claim" in violation
            for violation in validation.violations
        )


def test_unresolved_material_conflict_selects_no_disputed_claim(tmp_path: Path) -> None:
    """Catches an unresolved conflict silently choosing one disputed alternative."""
    result = build_candidate(_request(tmp_path, report=_report(blocked=True)))
    receipt_path = result.root / "receipts/RECONCILIATION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["selected_claim_ids"].append("claim-monolith")
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    _regenerate_integrity(result.root)

    validation = validate_package(result.root)

    assert not validation.valid
    assert any("unresolved disputed claim" in item for item in validation.violations)


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


def test_build_rejects_mismatched_selected_project_claim(tmp_path: Path) -> None:
    """Catches request identity being accepted without reconciliation authority."""
    report = _report()
    mismatched = ClaimRecord(
        report.claims[0].claim_id,
        report.claims[0].field,
        "beta",
        report.claims[0].source_id,
        report.claims[0].source_ref,
        report.claims[0].evidence_state,
    )
    report = ReconciliationReport(
        claims=(mismatched,),
        approvals=report.approvals,
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=(mismatched.claim_id,),
        notes=report.notes,
    )
    request = _request(tmp_path, report=report)

    with pytest.raises(ValueError, match="selected project_id"):
        build_candidate(request)

    assert not request.output.exists()


def test_three_generation_lineage_preserves_roots_and_direct_parents(tmp_path: Path) -> None:
    """Catches direct parents being conflated with stable lineage roots after promotion."""
    request = _request(tmp_path, package_id="generation-3")
    lineage = {
        **request.lineage_data,
        "parent_ids": ["generation-2"],
        "root_package_ids": ["generation-1"],
    }
    request = CandidateBuildRequest(**{**request.__dict__, "lineage_data": lineage})

    candidate = build_candidate(request)
    candidate_manifest = json.loads((candidate.root / "MANIFEST.json").read_text())
    assert candidate_manifest["lineage_roots"] == ["generation-1"]
    assert validate_package(candidate.root).valid

    canonical = promote_candidate(
        candidate.root,
        tmp_path / "generation-4",
        _approval(candidate.package_id),
        "2026-08-09T14:00:00Z",
    )
    canonical_lineage = json.loads(
        (canonical.root / "lineage/LINEAGE.json").read_text()
    )
    canonical_manifest = json.loads((canonical.root / "MANIFEST.json").read_text())

    assert canonical_lineage["parent_ids"] == ["generation-3"]
    assert canonical_lineage["root_package_ids"] == ["generation-1"]
    assert canonical_manifest["lineage_roots"] == ["generation-1"]
    assert validate_package(canonical.root).valid


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
    candidate_document_inputs = (
        candidate.root / "receipts/DOCUMENT_INPUTS.json"
    ).read_bytes()

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
    successor_preflight = json.loads(
        (canonical.root / "receipts/PREFLIGHT.json").read_text(encoding="utf-8")
    )
    successor_handoff = (canonical.root / "HANDOFF_README.md").read_text(encoding="utf-8")
    successor_preflight_document = (
        canonical.root / "SUPERPOWERS_PREFLIGHT.md"
    ).read_text(encoding="utf-8")
    successor_prompt = (canonical.root / "NEXT_THREAD_PROMPT.txt").read_text(
        encoding="utf-8"
    )
    assert successor_manifest["created_at"] == "2026-08-09T14:00:00Z"
    assert successor_lineage["created_at"] == "2026-08-09T14:00:00Z"
    assert successor_manifest["successor_created_at"] == "2026-08-09T14:00:00Z"
    assert successor_lineage["successor_created_at"] == "2026-08-09T14:00:00Z"
    assert "# Continuity handoff: canonical-alpha" in successor_handoff
    assert "- Package ID: `canonical-alpha`" in successor_handoff
    assert "- Created at: `2026-08-09T14:00:00Z`" in successor_handoff
    assert "- Lifecycle status: `Canonical`" in successor_handoff
    assert "Candidate predecessor was not Canonical" in successor_handoff
    assert successor_preflight["package_id"] == "canonical-alpha"
    assert "Package ID: `canonical-alpha`" in successor_preflight_document
    assert "Package ID: `canonical-alpha`" in successor_prompt
    assert "Package ID: `candidate-alpha`" not in successor_preflight_document
    assert "Package ID: `candidate-alpha`" not in successor_prompt
    assert (
        canonical.root / "receipts/DOCUMENT_INPUTS.json"
    ).read_bytes() == candidate_document_inputs
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
