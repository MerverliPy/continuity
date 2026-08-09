import hashlib

import pytest

from continuity.lineage import LineageState, SourcePackage, build_lineage
from continuity.models import ApprovalRecord, ClaimRecord, EvidenceState, PackageStatus
from continuity.reconciliation import (
    IntegrityFinding,
    conflict_id_for,
    reconcile_sources,
)


def _package(
    package_id: str,
    *,
    parents: tuple[str, ...] = (),
    status: PackageStatus = PackageStatus.CANDIDATE,
    current: bool = False,
    root_sha256: str | None = None,
    created_at: str | None = None,
) -> SourcePackage:
    return SourcePackage(
        package_id=package_id,
        root_sha256=root_sha256 or hashlib.sha256(package_id.encode("utf-8")).hexdigest(),
        status=status,
        parent_ids=parents,
        declared_current_root=current,
        created_at=created_at,
    )


def _claim(
    claim_id: str,
    field: str,
    value: object,
    source_id: str,
    *,
    state: EvidenceState = EvidenceState.VERIFIED,
    source_ref: str | None = None,
    recorded_at: str | None = None,
) -> ClaimRecord:
    return ClaimRecord(
        claim_id=claim_id,
        field=field,
        value=value,
        source_id=source_id,
        source_ref=source_ref or f"{source_id}.json",
        evidence_state=state,
        recorded_at=recorded_at,
    )


def _integrity(
    finding_id: str,
    source_id: str,
    state: EvidenceState = EvidenceState.VERIFIED,
    **kwargs: object,
) -> IntegrityFinding:
    kwargs.setdefault("lineage_required", False)
    kwargs.setdefault("source_ref", f"source://{source_id}/{finding_id}")
    return IntegrityFinding(finding_id, source_id, state, **kwargs)


def test_lineage_topological_order_is_deterministic() -> None:
    """Catches discovery order controlling parent-before-child output."""
    sources = (
        _package("leaf-z", parents=("middle",), created_at="2026-01-03T00:00:00Z"),
        _package("root", created_at="2026-01-01T00:00:00Z"),
        _package("leaf-a", parents=("middle",), created_at="2026-01-02T00:00:00Z"),
        _package("middle", parents=("root",)),
    )

    graph = build_lineage(sources)

    assert graph.state is LineageState.VALID
    assert graph.ordered_package_ids == ("root", "middle", "leaf-a", "leaf-z")
    assert graph.root_package_ids == ("root",)


def test_empty_lineage_is_invalid() -> None:
    """Catches absence of project identity being reported as a valid project."""
    graph = build_lineage(())

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "no-sources" for finding in graph.findings)


def test_lineage_with_missing_parent_is_invalid() -> None:
    """Catches an unverifiable successor being accepted as a lineage root."""
    graph = build_lineage((_package("child", parents=("absent",)),))

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "missing-parent" for finding in graph.findings)


def test_multiple_independent_roots_are_ambiguous() -> None:
    """Catches silent project selection when unrelated packages are mixed."""
    graph = build_lineage((_package("project-b"), _package("project-a")))

    assert graph.state is LineageState.AMBIGUOUS
    assert graph.root_package_ids == ("project-a", "project-b")
    assert graph.current_package_id is None


def test_lineage_cycle_is_invalid() -> None:
    """Catches cyclic parent declarations yielding a partial valid graph."""
    graph = build_lineage(
        (_package("one", parents=("two",)), _package("two", parents=("one",)))
    )

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "cycle" for finding in graph.findings)


def test_duplicate_package_id_with_different_hash_is_invalid() -> None:
    """Catches one package identity being reused for different content."""
    graph = build_lineage(
        (
            _package("same", root_sha256="a" * 64),
            _package("same", root_sha256="b" * 64),
        )
    )

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "identity-collision" for finding in graph.findings)


def test_same_identity_with_conflicting_parents_validates_every_declaration() -> None:
    """Catches duplicate collapsing that hides a missing parent declaration."""
    root_sha256 = hashlib.sha256(b"duplicate").hexdigest()
    graph = build_lineage(
        (
            _package("duplicate", root_sha256=root_sha256),
            _package("duplicate", root_sha256=root_sha256, parents=("absent",)),
        )
    )

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "metadata-conflict" for finding in graph.findings)
    assert any(finding.code == "missing-parent" for finding in graph.findings)


def test_same_identity_with_conflicting_current_status_metadata_is_invalid() -> None:
    """Catches duplicate collapsing that hides a superseded-current declaration."""
    root_sha256 = hashlib.sha256(b"duplicate-current").hexdigest()
    graph = build_lineage(
        (
            _package(
                "duplicate",
                root_sha256=root_sha256,
                status=PackageStatus.CANDIDATE,
            ),
            _package(
                "duplicate",
                root_sha256=root_sha256,
                status=PackageStatus.SUPERSEDED,
                current=True,
            ),
        )
    )

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "metadata-conflict" for finding in graph.findings)
    assert any(finding.code == "superseded-current" for finding in graph.findings)


def test_malformed_root_sha256_is_invalid() -> None:
    """Catches a non-hash package identity entering lineage comparisons."""
    graph = build_lineage((_package("source", root_sha256="not-a-sha256"),))

    assert graph.state is LineageState.INVALID
    assert any(finding.code == "invalid-root-sha256" for finding in graph.findings)


def test_canonical_successor_of_superseded_predecessor_is_current() -> None:
    """Catches valid append-only promotion lineage being rejected."""
    graph = build_lineage(
        (
            _package("old", status=PackageStatus.SUPERSEDED),
            _package(
                "new",
                parents=("old",),
                status=PackageStatus.CANONICAL,
                current=True,
            ),
        )
    )

    assert graph.state is LineageState.VALID
    assert graph.current_package_id == "new"
    assert graph.ordered_package_ids == ("old", "new")


def test_superseded_package_cannot_be_selected_as_current() -> None:
    """Catches historical evidence being presented as current authority."""
    graph = build_lineage(
        (_package("old", status=PackageStatus.SUPERSEDED, current=True),)
    )

    assert graph.state is LineageState.INVALID
    assert graph.current_package_id is None
    assert any(finding.code == "superseded-current" for finding in graph.findings)


older_verified_architecture = _claim(
    "claim-older",
    "architecture",
    "modular monolith",
    "older",
    recorded_at="2026-01-01T00:00:00Z",
)
newer_asserted_architecture = _claim(
    "claim-newer",
    "architecture",
    "microservices",
    "newer",
    state=EvidenceState.ASSERTED,
    recorded_at="2026-02-01T00:00:00Z",
)
older_scoped_approval = ApprovalRecord(
    "approval-older",
    "approve-claim",
    (older_verified_architecture.claim_id,),
    "approved",
    "user",
    "decision.md",
    "2026-01-01T01:00:00Z",
)
older_integrity_pass = _integrity("integrity-older", "older")
newer_missing_manifest = _integrity(
    "integrity-newer",
    "newer",
    EvidenceState.MISSING,
    detail="required manifest is missing",
)


def test_newer_incomplete_source_does_not_override_complete_approved_source() -> None:
    report = reconcile_sources(
        claims=(older_verified_architecture, newer_asserted_architecture),
        approvals=(older_scoped_approval,),
        integrity=(older_integrity_pass, newer_missing_manifest),
    )
    assert report.selected_claim_ids == (older_verified_architecture.claim_id,)
    assert report.blocking_conflicts == ()
    assert "newer timestamp is not controlling authority" in report.notes


approved_monolith = _claim("claim-monolith", "architecture", "monolith", "approved")
asserted_microservices = _claim(
    "claim-microservices",
    "architecture",
    "microservices",
    "proposal",
    state=EvidenceState.ASSERTED,
)
approve_monolith = ApprovalRecord(
    "approval-monolith",
    "approve-claim",
    (approved_monolith.claim_id,),
    "approved",
    "user",
    "approval.md",
    "2026-01-01T00:00:00Z",
)
both_integrity_pass = _integrity("integrity-all", "*")


def test_material_architecture_conflict_requires_scoped_user_resolution() -> None:
    report = reconcile_sources(
        claims=(approved_monolith, asserted_microservices),
        approvals=(approve_monolith,),
        integrity=(both_integrity_pass,),
    )
    assert report.blocking_conflicts[0].material is True
    assert report.blocking_conflicts[0].resolution_approval_id is None


def test_matching_content_under_different_filenames_preserves_both_provenances() -> None:
    """Catches filename spelling being treated as a content disagreement."""
    left = _claim("claim-a", "behavior", "retry three times", "a", source_ref="PLAN.md")
    right = _claim("claim-b", "behavior", "retry three times", "b", source_ref="notes.txt")

    report = reconcile_sources((right, left), (), (both_integrity_pass,))

    assert report.selected_claim_ids == ("claim-a", "claim-b")
    assert report.blocking_conflicts == ()
    assert {claim.source_ref for claim in report.claims} == {"PLAN.md", "notes.txt"}


def test_hash_mismatch_is_retained_but_cannot_control_selection() -> None:
    """Catches contradicted package content being discarded or selected."""
    claim = _claim("claim-bad", "behavior", "deploy immediately", "broken")
    mismatch = _integrity(
        "integrity-bad",
        "broken",
        EvidenceState.CONTRADICTED,
        detail="root hash mismatch",
        expected_sha256="a" * 64,
        observed_sha256="b" * 64,
    )

    report = reconcile_sources((claim,), (), (mismatch,))

    assert report.selected_claim_ids == ()
    assert report.findings[0].evidence_state is EvidenceState.CONTRADICTED
    assert report.findings[0].expected_sha256 == "a" * 64
    assert report.findings[0].observed_sha256 == "b" * 64


def test_verified_label_cannot_override_expected_observed_hash_mismatch() -> None:
    """Catches the shared blocker predicate trusting a contradictory digest pair."""
    claim = _claim("claim-bad-verified", "behavior", "deploy", "broken")
    mismatch = _integrity(
        "integrity-bad-verified",
        "broken",
        EvidenceState.VERIFIED,
        structurally_valid=True,
        lineage_valid=True,
        expected_sha256="a" * 64,
        observed_sha256="b" * 64,
    )

    report = reconcile_sources((claim,), (), (mismatch,))

    assert mismatch.permits_automatic_selection is False
    assert report.selected_claim_ids == ()


@pytest.mark.parametrize(
    ("expected_sha256", "observed_sha256"),
    (("a" * 64, None), (None, "a" * 64)),
)
def test_incomplete_digest_pair_cannot_control_selection(
    expected_sha256: str | None,
    observed_sha256: str | None,
) -> None:
    """Catches one-sided digest evidence passing the shared integrity gate."""
    claim = _claim("claim-incomplete-digest", "behavior", "deploy", "source")
    finding = _integrity(
        "integrity-incomplete-digest",
        "source",
        EvidenceState.VERIFIED,
        structurally_valid=True,
        lineage_valid=True,
        expected_sha256=expected_sha256,
        observed_sha256=observed_sha256,
    )

    report = reconcile_sources((claim,), (), (finding,))

    assert finding.permits_automatic_selection is False
    assert report.selected_claim_ids == ()


def test_global_invalid_integrity_is_combined_with_source_verified_finding() -> None:
    """Catches source-specific evidence replacing a controlling global failure."""
    claim = _claim("claim-source", "behavior", "retry", "source")
    global_failure = _integrity(
        "integrity-global",
        "*",
        EvidenceState.CONTRADICTED,
        detail="global package manifest hash mismatch",
    )
    source_pass = _integrity("integrity-source", "source")

    report = reconcile_sources((claim,), (), (source_pass, global_failure))

    assert report.selected_claim_ids == ()
    assert {finding.finding_id for finding in report.findings} == {
        "integrity-global",
        "integrity-source",
    }


def test_broad_urgency_cannot_override_narrow_safety_prohibition() -> None:
    """Catches broad permission silently deciding a material safety conflict."""
    prohibition = _claim("claim-safe", "safety", "do not delete production", "runbook")
    urgency = _claim(
        "claim-urgent",
        "safety",
        "delete production to recover now",
        "chat",
        state=EvidenceState.ASSERTED,
    )
    broad = ApprovalRecord(
        "approval-urgent",
        "proceed",
        ("project",),
        "urgent",
        "chat",
        "message-1",
        "2026-01-02T00:00:00Z",
    )

    report = reconcile_sources((urgency, prohibition), (broad,), (both_integrity_pass,))

    assert report.selected_claim_ids == ()
    assert len(report.blocking_conflicts) == 1
    assert report.blocking_conflicts[0].field == "safety"


def test_unresolved_integrity_remains_unresolved_and_non_controlling() -> None:
    """Catches a limited evidence search being upgraded to verified or missing."""
    claim = _claim("claim-unknown", "scope", "all services", "partial")
    unresolved = _integrity(
        "integrity-partial",
        "partial",
        EvidenceState.UNRESOLVED,
        detail="manifest was not in inspected scope",
    )

    report = reconcile_sources((claim,), (), (unresolved,))

    assert report.selected_claim_ids == ()
    assert report.findings[0].evidence_state is EvidenceState.UNRESOLVED


def test_unresolved_claim_remains_non_controlling_when_container_integrity_passes() -> None:
    """Catches verified container bytes upgrading an unresolved semantic claim."""
    claim = _claim(
        "claim-unresolved",
        "scope",
        "all services",
        "verified-container",
        state=EvidenceState.UNRESOLVED,
    )

    report = reconcile_sources((claim,), (), (both_integrity_pass,))

    assert report.selected_claim_ids == ()
    assert report.claims[0].evidence_state is EvidenceState.UNRESOLVED


def test_non_material_formatting_differences_do_not_block() -> None:
    """Catches whitespace and case-only presentation differences becoming conflicts."""
    left = _claim("claim-title-a", "title", "Release Checklist", "a")
    right = _claim("claim-title-b", "title", "  release   checklist ", "b")

    report = reconcile_sources((right, left), (), (both_integrity_pass,))

    assert report.selected_claim_ids == ("claim-title-a", "claim-title-b")
    assert report.blocking_conflicts == ()


@pytest.mark.parametrize(
    "field",
    [
        "system architecture",
        "runtime behavior",
        "approved scope",
        "canonical authority",
        "safety gate",
        "release readiness",
        "exact next action",
    ],
)
def test_all_qualified_controlling_fields_are_material(field: str) -> None:
    """Catches a controlling difference becoming non-material because its field is qualified."""
    left = _claim(f"claim-{field}-a", field, "one", "a")
    right = _claim(f"claim-{field}-b", field, "two", "b")

    report = reconcile_sources((left, right), (), (both_integrity_pass,))

    assert report.blocking_conflicts[0].material is True


def test_approval_without_exact_conflict_scope_does_not_resolve() -> None:
    """Catches an approval for a different disputed action leaking across scope."""
    conflict_id = conflict_id_for("architecture", (approved_monolith, asserted_microservices))
    wrong_scope = ApprovalRecord(
        "approval-wrong",
        "resolve-conflict",
        ("conflict-for-release",),
        approved_monolith.claim_id,
        "user",
        "decision.md",
        "2026-01-03T00:00:00Z",
    )

    report = reconcile_sources(
        (approved_monolith, asserted_microservices),
        (wrong_scope,),
        (both_integrity_pass,),
    )

    assert report.blocking_conflicts[0].conflict_id == conflict_id
    assert report.blocking_conflicts[0].resolution_approval_id is None


def test_exact_conflict_scoped_approval_resolves_to_named_claim() -> None:
    """Catches a correctly scoped user resolution being ignored."""
    conflict_id = conflict_id_for("architecture", (approved_monolith, asserted_microservices))
    resolution = ApprovalRecord(
        "approval-resolution",
        "resolve-conflict",
        (conflict_id,),
        approved_monolith.claim_id,
        "user",
        "decision.md",
        "2026-01-03T00:00:00Z",
    )

    report = reconcile_sources(
        (approved_monolith, asserted_microservices),
        (resolution,),
        (both_integrity_pass,),
    )

    assert report.selected_claim_ids == (approved_monolith.claim_id,)
    assert report.blocking_conflicts == ()
    assert report.conflicts[0].resolution_approval_id == resolution.approval_id


def test_resolution_from_invalid_evidence_cannot_control() -> None:
    """Catches a broken approval artifact resolving a material conflict."""
    conflict_id = conflict_id_for("architecture", (approved_monolith, asserted_microservices))
    resolution = ApprovalRecord(
        "approval-broken",
        "resolve-conflict",
        (conflict_id,),
        approved_monolith.claim_id,
        "broken-approval",
        "decision.md",
        "2026-01-03T00:00:00Z",
    )
    claim_integrity = _integrity("integrity-all-claims", "*")
    approval_integrity = _integrity(
        "integrity-broken-approval",
        "broken-approval",
        EvidenceState.CONTRADICTED,
        detail="approval hash mismatch",
    )

    report = reconcile_sources(
        (approved_monolith, asserted_microservices),
        (resolution,),
        (claim_integrity, approval_integrity),
    )

    assert report.blocking_conflicts[0].resolution_approval_id is None
    assert any(
        finding.finding_id == "integrity-broken-approval" for finding in report.findings
    )


def test_successor_claim_without_valid_lineage_is_retained_but_not_selected() -> None:
    """Catches an unlinked successor declaration becoming current automatically."""
    claim = _claim("claim-unlinked", "next action", "deploy", "successor")
    invalid_lineage = _integrity(
        "integrity-successor",
        "successor",
        EvidenceState.VERIFIED,
        lineage_valid=False,
        detail="declared predecessor is not present",
    )

    report = reconcile_sources((claim,), (), (invalid_lineage,))

    assert report.selected_claim_ids == ()
    assert report.findings[0].lineage_valid is False


def test_successor_claim_without_affirmative_lineage_proof_cannot_control() -> None:
    """Catches a successor claim passing because missing lineage proof defaults valid."""
    claim = _claim("claim-successor", "authority", "current", "successor")
    missing_lineage_proof = _integrity(
        "integrity-successor-missing-lineage",
        "successor",
        EvidenceState.VERIFIED,
        lineage_required=True,
    )

    report = reconcile_sources((claim,), (), (missing_lineage_proof,))

    assert report.selected_claim_ids == ()
    assert report.findings[0].lineage_required is True
    assert report.findings[0].lineage_valid is None


def test_unknown_lineage_is_noncontrolling_by_default() -> None:
    """Catches omitted lineage applicability silently exempting a source."""
    claim = _claim("claim-default-lineage", "authority", "current", "unknown")
    unknown_lineage = IntegrityFinding(
        "integrity-default-lineage",
        "unknown",
        EvidenceState.VERIFIED,
        source_ref="source://unknown/integrity-default-lineage",
    )

    report = reconcile_sources((claim,), (), (unknown_lineage,))

    assert report.selected_claim_ids == ()
    assert report.findings[0].lineage_required is True
    assert report.findings[0].lineage_valid is None


def test_trusted_non_successor_can_explicitly_exempt_lineage() -> None:
    """Catches the standalone/root exemption being lost under fail-closed defaults."""
    claim = _claim("claim-root-fact", "title", "Continuity", "trusted-root")
    trusted_root = IntegrityFinding(
        "integrity-root",
        "trusted-root",
        EvidenceState.VERIFIED,
        source_ref="source://trusted-root/integrity-root",
        lineage_required=False,
    )

    report = reconcile_sources((claim,), (), (trusted_root,))

    assert report.selected_claim_ids == (claim.claim_id,)


def test_successor_claim_with_affirmative_lineage_proof_can_control() -> None:
    """Catches affirmative validated successor lineage being treated as absent."""
    claim = _claim("claim-linked-successor", "authority", "current", "successor")
    valid_lineage = _integrity(
        "integrity-successor-valid-lineage",
        "successor",
        EvidenceState.VERIFIED,
        lineage_required=True,
        lineage_valid=True,
    )

    report = reconcile_sources((claim,), (), (valid_lineage,))

    assert report.selected_claim_ids == (claim.claim_id,)


def test_report_serialization_sorts_every_record_collection_by_stable_id() -> None:
    """Catches caller input order leaking into persisted reconciliation reports."""
    claim_a = _claim("claim-a", "architecture", "one", "a")
    claim_z = _claim("claim-z", "architecture", "two", "z")
    conflict_id = conflict_id_for("architecture", (claim_a, claim_z))
    approval_z = ApprovalRecord(
        "approval-z", "resolve-conflict", (conflict_id,), "claim-a", "user", "z", "2026"
    )
    approval_a = ApprovalRecord(
        "approval-a", "approve-claim", ("claim-a",), "approved", "user", "a", "2025"
    )
    finding_z = _integrity("integrity-z", "z")
    finding_a = _integrity("integrity-a", "a")

    report = reconcile_sources(
        (claim_z, claim_a),
        (approval_z, approval_a),
        (finding_z, finding_a),
    )
    serialized = report.to_dict()

    assert [item["claim_id"] for item in serialized["claims"]] == ["claim-a", "claim-z"]
    assert [item["conflict_id"] for item in serialized["conflicts"]] == [conflict_id]
    assert [item["finding_id"] for item in serialized["findings"]] == [
        "integrity-a",
        "integrity-z",
    ]
    assert [item["source_ref"] for item in serialized["findings"]] == [
        "source://a/integrity-a",
        "source://z/integrity-z",
    ]
    assert [item["approval_id"] for item in serialized["approvals"]] == [
        "approval-a",
        "approval-z",
    ]
