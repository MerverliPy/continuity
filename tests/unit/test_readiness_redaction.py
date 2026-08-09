import json

import pytest

from continuity.models import (
    ApprovalRecord,
    ClaimRecord,
    ConflictRecord,
    EvidenceState,
    ReadinessStatus,
)
from continuity.readiness import classify_readiness
from continuity.reconciliation import IntegrityFinding, ReconciliationReport
from continuity.redaction import exclude_secret_bearing_files, redact_text


def _claim(
    claim_id: str,
    field: str,
    value: object,
    *,
    state: EvidenceState = EvidenceState.VERIFIED,
) -> ClaimRecord:
    return ClaimRecord(
        claim_id=claim_id,
        field=field,
        value=value,
        source_id="canonical-package",
        source_ref=f"manifest.json#/{claim_id}",
        evidence_state=state,
    )


def _report(
    *,
    authorized_actions: tuple[str, ...] = ("implementation",),
    package_status: str = "Canonical",
    integrity: tuple[IntegrityFinding, ...] | None = None,
    conflicts: tuple[ConflictRecord, ...] = (),
    extra_claims: tuple[ClaimRecord, ...] = (),
    extra_selected: tuple[str, ...] = (),
) -> ReconciliationReport:
    project = _claim("project-alpha", "project id", "alpha")
    authority = _claim(
        "authority-alpha", "authorized actions", authorized_actions
    )
    lifecycle = _claim("lifecycle-alpha", "package status", package_status)
    claims = (project, authority, lifecycle, *extra_claims)
    selected = (
        project.claim_id,
        authority.claim_id,
        lifecycle.claim_id,
        *extra_selected,
    )
    if integrity is None:
        integrity = (
            IntegrityFinding(
                "integrity-canonical",
                "canonical-package",
                EvidenceState.VERIFIED,
                structurally_valid=True,
                lineage_valid=True,
            ),
        )
    return ReconciliationReport(
        claims=claims,
        approvals=(),
        findings=integrity,
        conflicts=conflicts,
        selected_claim_ids=selected,
        notes=(),
    )


_HASH_MISMATCH = IntegrityFinding(
    "integrity-hash-mismatch",
    "canonical-package",
    EvidenceState.CONTRADICTED,
    detail="checksum mismatch",
    structurally_valid=True,
    lineage_valid=True,
    expected_sha256="a" * 64,
    observed_sha256="b" * 64,
)
_MISSING_MANIFEST = IntegrityFinding(
    "integrity-required-manifest",
    "canonical-package",
    EvidenceState.MISSING,
    detail="required manifest is missing",
    structurally_valid=False,
    lineage_valid=True,
)
_MATERIAL_CONFLICT = ConflictRecord(
    "conflict-architecture",
    "architecture",
    True,
    ("claim-monolith", "claim-services"),
    None,
)
_NON_BLOCKING_UNKNOWN = _claim(
    "condition-platform-version",
    "condition",
    {
        "condition": "deployment platform version is not yet recorded",
        "does_not_affect_action": True,
        "basis": "implementation is confined to platform-neutral domain code",
    },
    state=EvidenceState.UNRESOLVED,
)
_SECOND_PROJECT = _claim("project-beta", "project id", "beta")


@pytest.mark.parametrize(
    ("report", "expected"),
    (
        (_report(), ReadinessStatus.READY),
        (
            _report(extra_claims=(_NON_BLOCKING_UNKNOWN,)),
            ReadinessStatus.CONDITIONAL,
        ),
        (_report(integrity=(_HASH_MISMATCH,)), ReadinessStatus.BLOCKED),
        (_report(integrity=(_MISSING_MANIFEST,)), ReadinessStatus.BLOCKED),
        (_report(conflicts=(_MATERIAL_CONFLICT,)), ReadinessStatus.BLOCKED),
        (
            _report(authorized_actions=("planning",)),
            ReadinessStatus.BLOCKED,
        ),
        (
            _report(
                extra_claims=(_SECOND_PROJECT,),
                extra_selected=(_SECOND_PROJECT.claim_id,),
            ),
            ReadinessStatus.BLOCKED,
        ),
        (_report(package_status="Candidate"), ReadinessStatus.BLOCKED),
    ),
    ids=(
        "all-gates-pass",
        "documented-harmless-unknown",
        "hash-mismatch",
        "missing-required-manifest",
        "material-authority-conflict",
        "action-exceeds-approval",
        "multiple-selected-projects",
        "implementation-not-promoted",
    ),
)
def test_readiness_uses_explicit_gates(
    report: ReconciliationReport, expected: ReadinessStatus
) -> None:
    """Catches a blocking gate being averaged into a permissive readiness score."""

    decision = classify_readiness(report, "implementation")

    assert decision.status is expected
    assert decision.reasons == tuple(sorted(decision.reasons))
    assert decision.authorized_actions
    assert decision.prohibited_actions
    if expected is ReadinessStatus.BLOCKED:
        assert "implementation" in decision.prohibited_actions
        assert decision.exact_next_action is None
        assert decision.recommended_superpowers_skill is None
    else:
        assert "implementation" in decision.authorized_actions
        assert decision.exact_next_action == "implementation"


def test_conditional_preserves_machine_readable_condition_and_citation() -> None:
    """Catches a prose-only unknown being treated as proven harmless."""

    decision = classify_readiness(
        _report(extra_claims=(_NON_BLOCKING_UNKNOWN,)), "implementation"
    )

    assert decision.status is ReadinessStatus.CONDITIONAL
    assert len(decision.conditions) == 1
    condition = json.loads(decision.conditions[0])
    assert condition == {
        "basis": "implementation is confined to platform-neutral domain code",
        "condition": "deployment platform version is not yet recorded",
        "does_not_affect_action": True,
        "source_ref": "manifest.json#/condition-platform-version",
    }


@pytest.mark.parametrize(
    "condition_value",
    (
        {
            "condition": "runtime is unknown",
            "does_not_affect_action": False,
            "basis": "runtime controls the implementation target",
        },
        {
            "condition": "runtime is unknown",
            "does_not_affect_action": True,
        },
        "runtime is unknown but probably harmless",
    ),
)
def test_unproven_condition_blocks_requested_action(condition_value: object) -> None:
    """Catches an unknown without affirmative machine-readable proof passing the gate."""
    unknown = _claim(
        "condition-runtime", "condition", condition_value, state=EvidenceState.UNRESOLVED
    )

    decision = classify_readiness(
        _report(extra_claims=(unknown,)), "implementation"
    )

    assert decision.status is ReadinessStatus.BLOCKED
    assert "implementation" in decision.prohibited_actions


def test_action_named_approval_with_unrelated_scope_does_not_authorize() -> None:
    """Catches an approval action label bypassing its exact recorded scope."""
    report = _report(authorized_actions=())
    unrelated = ApprovalRecord(
        "approval-unrelated",
        "implementation",
        ("different-project",),
        "approved",
        "user",
        "approval.md",
        "2026-08-09T12:00:00Z",
    )
    report = ReconciliationReport(
        claims=report.claims,
        approvals=(unrelated,),
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )

    decision = classify_readiness(report, "implementation")

    assert decision.status is ReadinessStatus.BLOCKED
    assert "implementation" in decision.prohibited_actions


def test_redacts_likely_secrets_without_destroying_source_context() -> None:
    """Catches report serialization leaking several high-confidence secret forms."""
    private_body = "c3VwZXItc2VjcmV0LWtleS1tYXRlcmlhbA=="
    source = "\n".join(
        (
            "config/app.env:3 API_KEY='sk-proj-abcdefghijklmnopqrstuv'",
            "logs/request.txt:8 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "config/db.env:2 password = 'correct-horse-battery-staple'",
            "config/db.env:4 DATABASE_URL=postgresql://alice:db-password@db.example/app",
            "keys/service.pem:1 -----BEGIN PRIVATE KEY-----",
            private_body,
            "-----END PRIVATE KEY-----",
        )
    )

    result = redact_text(source)

    for secret in (
        "sk-proj-abcdefghijklmnopqrstuv",
        "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "correct-horse-battery-staple",
        "db-password",
        private_body,
    ):
        assert secret not in result.text
    for context in (
        "config/app.env:3 API_KEY=",
        "logs/request.txt:8 Authorization: Bearer ",
        "config/db.env:2 password = ",
        "postgresql://alice:",
        "keys/service.pem:1 -----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
    ):
        assert context in result.text
    assert {finding.kind for finding in result.findings} == {
        "api-key",
        "bearer-token",
        "connection-string-password",
        "password",
        "private-key",
    }
    assert all(source[item.start : item.end] != item.replacement for item in result.findings)


def test_does_not_over_redact_identifiers_or_checksum_evidence() -> None:
    """Catches entropy-only matching that destroys ordinary integrity evidence."""
    source = "\n".join(
        (
            "sha256: 6f1ed002ab5595859014ebf0951522d9d5871d0f9c640b4cdb812e5da20fca9c",
            "checksums.txt: 75a90e9f284bd6685a343a1ed6ce748abc7f9f7290f600ad0a7358447e47efdf  package.zip",
            "project_uuid=123e4567-e89b-12d3-a456-426614174000",
            "package_id=continuity-v1-build_20260809",
        )
    )

    result = redact_text(source)

    assert result.text == source
    assert result.findings == ()


def test_secret_bearing_files_require_exact_secure_handling_approval() -> None:
    """Catches secret files entering a candidate through broad or unrelated approval."""
    sources = {
        "README.md": "No credentials here.",
        "config/app.env": "API_KEY=sk-proj-abcdefghijklmnopqrstuv",
        "config/other.env": "password=other-secret-value",
    }
    broad = ApprovalRecord(
        "approval-broad",
        "secure-handling",
        ("*",),
        "approved",
        "user",
        "approval.md",
        "2026-08-09T12:00:00Z",
    )
    exact = ApprovalRecord(
        "approval-exact",
        "secure-handling",
        ("config/app.env",),
        "approved",
        "user",
        "approval.md",
        "2026-08-09T12:01:00Z",
    )

    assert exclude_secret_bearing_files(sources, ()) == ("README.md",)
    assert exclude_secret_bearing_files(sources, (broad, exact)) == (
        "README.md",
        "config/app.env",
    )
