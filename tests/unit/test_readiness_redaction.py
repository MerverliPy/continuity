import json

import pytest
import continuity.models as continuity_models

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
                source_ref="canonical/SHA256SUMS.txt#integrity-canonical",
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
    source_ref="canonical/SHA256SUMS.txt#integrity-hash-mismatch",
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
    source_ref="canonical/MANIFEST.json#integrity-required-manifest",
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


def test_preflight_record_serializes_the_exact_v1_contract() -> None:
    """Catches typed readiness drifting from the schema and CLI field names."""
    record_type = getattr(continuity_models, "PreflightRecord", None)
    assert record_type is not None
    decision = classify_readiness(_report(), "implementation")

    record = record_type.from_decision(decision, "alpha", "canonical-alpha")

    assert record.to_dict() == {
        "schema": "continuity.preflight/v1",
        "project_id": "alpha",
        "package_id": "canonical-alpha",
        "status": "Ready",
        "reasons": ["all readiness gates passed"],
        "conditions": [],
        "authorized_actions": ["implementation"],
        "prohibited_actions": ["actions outside recorded authorization"],
        "unresolved_actions": [],
        "exact_next_action": "implementation",
        "companion_skill_or_stage": "superpowers:test-driven-development",
        "evidence_references": [
            "canonical/SHA256SUMS.txt#integrity-canonical#integrity-canonical",
            "manifest.json#/authority-alpha#authority-alpha",
            "manifest.json#/lifecycle-alpha#lifecycle-alpha",
            "manifest.json#/project-alpha#project-alpha",
        ],
    }


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
    assert decision.prohibited_actions
    if expected is ReadinessStatus.BLOCKED:
        assert decision.authorized_actions == ()
        assert decision.unresolved_actions
        assert "implementation" in decision.prohibited_actions
        assert decision.exact_next_action is None
        assert decision.companion_skill_or_stage is None
    else:
        assert "implementation" in decision.authorized_actions
        assert decision.unresolved_actions == ()
        assert decision.exact_next_action == "implementation"


@pytest.mark.parametrize(
    ("requested_action", "expected"),
    (
        ("fix bug", ReadinessStatus.BLOCKED),
        ("modify source", ReadinessStatus.BLOCKED),
        ("write feature", ReadinessStatus.BLOCKED),
        ("review", ReadinessStatus.READY),
    ),
)
def test_noncanonical_lifecycle_allows_only_explicit_safe_operations(
    requested_action: str, expected: ReadinessStatus
) -> None:
    """Catches unknown mutating verbs bypassing the canonical lifecycle gate."""
    report = _report(
        authorized_actions=(requested_action,), package_status="Candidate"
    )

    decision = classify_readiness(report, requested_action)

    assert decision.status is expected
    if expected is ReadinessStatus.BLOCKED:
        assert requested_action in decision.prohibited_actions
        assert decision.exact_next_action is None
    else:
        assert decision.exact_next_action == requested_action


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


def test_blank_requested_action_has_explicit_stable_prohibition() -> None:
    """Catches invalid requests producing a blocked decision with no prohibition."""

    decision = classify_readiness(_report(), "   ")

    assert decision.status is ReadinessStatus.BLOCKED
    assert "blank or invalid requested action" in decision.prohibited_actions
    assert decision.exact_next_action is None


def _report_with_material_resolution(
    approval: ApprovalRecord | None,
) -> ReconciliationReport:
    selected = _claim("claim-monolith", "architecture", "monolith")
    competing = _claim("claim-services", "architecture", "services")
    conflict = ConflictRecord(
        "conflict-resolved-architecture",
        "architecture",
        True,
        (selected.claim_id, competing.claim_id),
        "approval-resolution",
    )
    report = _report(
        conflicts=(conflict,),
        extra_claims=(selected, competing),
        extra_selected=(selected.claim_id,),
    )
    return ReconciliationReport(
        claims=report.claims,
        approvals=() if approval is None else (approval,),
        findings=report.findings,
        conflicts=report.conflicts,
        selected_claim_ids=report.selected_claim_ids,
        notes=report.notes,
    )


@pytest.mark.parametrize(
    "approval",
    (
        None,
        ApprovalRecord(
            "approval-resolution",
            "approve-claim",
            ("conflict-resolved-architecture",),
            "claim-monolith",
            "user",
            "approval.md",
            "2026-08-09T12:00:00Z",
        ),
        ApprovalRecord(
            "approval-resolution",
            "resolve-conflict",
            ("conflict-other",),
            "claim-monolith",
            "user",
            "approval.md",
            "2026-08-09T12:00:00Z",
        ),
        ApprovalRecord(
            "approval-resolution",
            "resolve-conflict",
            ("conflict-resolved-architecture",),
            "claim-unrelated",
            "user",
            "approval.md",
            "2026-08-09T12:00:00Z",
        ),
    ),
    ids=("stale-id", "wrong-action", "wrong-scope", "fabricated-decision"),
)
def test_material_resolution_requires_exact_referenced_approval(
    approval: ApprovalRecord | None,
) -> None:
    """Catches a non-null resolution ID bypassing exact approval validation."""

    decision = classify_readiness(
        _report_with_material_resolution(approval), "implementation"
    )

    assert decision.status is ReadinessStatus.BLOCKED
    assert "implementation" in decision.prohibited_actions


def test_exact_material_resolution_approval_is_accepted() -> None:
    """Catches exact conflict decisions being blocked with fabricated resolutions."""
    approval = ApprovalRecord(
        "approval-resolution",
        "resolve-conflict",
        ("conflict-resolved-architecture",),
        "claim-monolith",
        "user",
        "approval.md",
        "2026-08-09T12:00:00Z",
    )

    decision = classify_readiness(
        _report_with_material_resolution(approval), "implementation"
    )

    assert decision.status is ReadinessStatus.READY


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


def test_namespaced_and_quoted_secret_assignments_are_fully_redacted() -> None:
    """Catches credential prefixes and escaped quotes leaking secret suffix bytes."""
    sources = {
        "config/service.env": "SERVICE_API_KEY=service-secret-value",
        "config/stripe.env": "STRIPE_SECRET_KEY=sk_live_exampleSecret123",
        "config/settings.json": '{"api_key": "json-secret-value"}',
        "config/escaped.json": '{"password": "before\\\"escaped-trailing-secret"}',
    }

    redacted = {path: redact_text(text) for path, text in sources.items()}
    allowed_canonical_paths = exclude_secret_bearing_files(sources, ())

    assert allowed_canonical_paths == ()
    assert all(result.findings for result in redacted.values())
    assert redacted["config/service.env"].text == "SERVICE_API_KEY=[REDACTED]"
    assert redacted["config/stripe.env"].text == "STRIPE_SECRET_KEY=[REDACTED]"
    assert redacted["config/settings.json"].text == '{"api_key": "[REDACTED]"}'
    assert redacted["config/escaped.json"].text == '{"password": "[REDACTED]"}'
    assert all(
        secret_fragment not in result.text
        for result in redacted.values()
        for secret_fragment in (
            "service-secret-value",
            "sk_live_exampleSecret123",
            "json-secret-value",
            "escaped-trailing-secret",
        )
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "api key = spaced-api-secret-value",
            "api key = [REDACTED]",
        ),
        (
            "client secret: spaced-client-secret-value",
            "client secret: [REDACTED]",
        ),
        (
            "access token = spaced-access-token-value",
            "access token = [REDACTED]",
        ),
        (
            "refresh token: spaced-refresh-token-value",
            "refresh token: [REDACTED]",
        ),
    ),
)
def test_spaced_credential_labels_redact_and_exclude_source(
    source: str, expected: str
) -> None:
    """Catches normalized space separators bypassing redaction and package exclusion."""

    result = redact_text(source)
    allowed_canonical_paths = exclude_secret_bearing_files(
        {"config/spaced-credential.env": source}, ()
    )

    assert result.text == expected
    assert len(result.findings) == 1
    assert allowed_canonical_paths == ()


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
