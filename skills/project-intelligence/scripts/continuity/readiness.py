"""Deterministic, fail-closed readiness gates for requested project actions."""

from collections.abc import Iterable, Mapping
import json

from .models import EvidenceState, PreflightDecision, ReadinessStatus
from .reconciliation import ReconciliationReport


_PROJECT_FIELDS = frozenset(
    {
        "project",
        "project id",
        "project identity",
        "selected project",
        "selected project id",
    }
)
_AUTHORIZED_ACTION_FIELDS = frozenset(
    {
        "approved action",
        "approved actions",
        "approval scope",
        "authorized action",
        "authorized actions",
    }
)
_PROHIBITED_ACTION_FIELDS = frozenset(
    {
        "prohibited action",
        "prohibited actions",
    }
)
_LIFECYCLE_FIELDS = frozenset(
    {
        "lifecycle",
        "lifecycle status",
        "package status",
        "status",
    }
)
_PRECANONICAL_ALLOWED_ACTIONS = frozenset(
    {
        "candidate promotion preparation",
        "conflict resolution",
        "inspect",
        "inspection",
        "prepare candidate promotion",
        "reconcile",
        "reconciliation",
        "resolve conflict",
        "review",
        "validate",
        "validation",
    }
)
_APPROVED_DECISIONS = frozenset({"allow", "allowed", "approve", "approved"})
_AUTHORIZATION_ACTIONS = frozenset(
    {"approve action", "approve actions", "authorize action", "authorize actions"}
)
_RECOMMENDED_SKILLS = {
    "brainstorm": "superpowers:brainstorming",
    "brainstorming": "superpowers:brainstorming",
    "implementation": "superpowers:test-driven-development",
    "implement": "superpowers:test-driven-development",
    "plan": "superpowers:writing-plans",
    "planning": "superpowers:writing-plans",
}


def classify_readiness(
    report: ReconciliationReport, requested_action: str
) -> PreflightDecision:
    """Classify one requested action by explicit gates, never a numeric score."""

    requested_action = requested_action.strip()
    normalized_requested = _normalize(requested_action)
    reasons: set[str] = set()
    blocking_reasons: set[str] = set()

    def block(reason: str) -> None:
        reasons.add(reason)
        blocking_reasons.add(reason)

    # Integrity gate: readiness requires affirmative structural and lineage evidence.
    if not report.findings:
        block("integrity gate: no integrity findings were supplied")
    for finding in report.findings:
        if (
            finding.expected_sha256 is not None
            and finding.observed_sha256 is not None
            and finding.expected_sha256 != finding.observed_sha256
        ):
            block(f"integrity gate: hash mismatch in {finding.finding_id}")
        elif finding.evidence_state is EvidenceState.MISSING and "manifest" in _normalize(
            finding.detail
        ):
            block(f"integrity gate: required manifest missing in {finding.finding_id}")
        elif not finding.permits_automatic_selection:
            block(f"integrity gate: {finding.finding_id} is not verified")

    selected_ids = set(report.selected_claim_ids)
    selected_claims = tuple(
        claim for claim in report.claims if claim.claim_id in selected_ids
    )
    absent_selected = sorted(
        selected_ids.difference(claim.claim_id for claim in report.claims)
    )
    if absent_selected:
        block(
            "evidence gate: selected claims are absent: " + ", ".join(absent_selected)
        )
    for claim in selected_claims:
        if claim.evidence_state is not EvidenceState.VERIFIED:
            block(f"evidence gate: selected claim {claim.claim_id} is not verified")

    # Project identity gate: zero or multiple selected identities are both unsafe.
    project_ids = {
        _stable_value(claim.value)
        for claim in selected_claims
        if _normalize(claim.field) in _PROJECT_FIELDS
    }
    if not project_ids:
        block("project identity gate: no selected project is verified")
    elif len(project_ids) > 1:
        block("project identity gate: multiple projects are selected")

    # Material conflict gate: independently validate every referenced resolution.
    for conflict in report.conflicts:
        if not conflict.material:
            continue
        referenced = tuple(
            approval
            for approval in report.approvals
            if approval.approval_id == conflict.resolution_approval_id
        )
        exact_resolution = (
            len(referenced) == 1
            and _normalize(referenced[0].action) == "resolve conflict"
            and referenced[0].scope == (conflict.conflict_id,)
            and referenced[0].decision in conflict.claim_ids
            and referenced[0].decision in selected_ids
        )
        if not exact_resolution:
            block(
                f"conflict gate: material conflict {conflict.conflict_id} lacks an "
                "exact referenced resolution"
            )

    authorized = _actions_from_claims(selected_claims, _AUTHORIZED_ACTION_FIELDS)
    prohibited = _actions_from_claims(selected_claims, _PROHIBITED_ACTION_FIELDS)
    authorized.update(_actions_from_approvals(report))
    normalized_authorized = {_normalize(action) for action in authorized}
    normalized_prohibited = {_normalize(action) for action in prohibited}

    # Authority and requested-action gates are kept separate in the reasons.
    if not authorized:
        block("authority gate: no authorized actions are recorded")
    if (
        not normalized_requested
        or normalized_requested not in normalized_authorized
        or normalized_requested in normalized_prohibited
    ):
        block(f"requested-action gate: {requested_action or '<empty>'} is not authorized")

    # Lifecycle gate is fail-closed until a package is affirmatively canonical.
    lifecycle_values = {
        _normalize(str(claim.value))
        for claim in selected_claims
        if _normalize(claim.field) in _LIFECYCLE_FIELDS
    }
    if (
        lifecycle_values != {"canonical"}
        and normalized_requested not in _PRECANONICAL_ALLOWED_ACTIONS
    ):
        block(
            "lifecycle gate: non-canonical packages permit only explicit "
            "non-mutating Continuity operations"
        )

    # Evidence/condition gate: unknowns are legal only with affirmative, cited proof.
    conditions: list[str] = []
    for claim in report.claims:
        if claim.evidence_state is EvidenceState.UNRESOLVED:
            condition = _condition_json(claim.value, claim.source_ref)
            if condition is None:
                block(
                    f"evidence gate: unresolved claim {claim.claim_id} lacks cited non-impact proof"
                )
            else:
                conditions.append(condition)
        elif claim.evidence_state in {EvidenceState.CONTRADICTED, EvidenceState.MISSING}:
            block(
                f"evidence gate: claim {claim.claim_id} is {claim.evidence_state.value.casefold()}"
            )

    if blocking_reasons:
        blocked_actions = set(prohibited)
        if requested_action:
            blocked_actions.add(requested_action)
        else:
            blocked_actions.add("blank or invalid requested action")
        return PreflightDecision(
            status=ReadinessStatus.BLOCKED,
            reasons=tuple(sorted(reasons)),
            conditions=tuple(sorted(conditions)),
            authorized_actions=(),
            prohibited_actions=tuple(sorted(blocked_actions, key=_normalize)),
            unresolved_actions=("clarify readiness blockers",),
            exact_next_action=None,
            companion_skill_or_stage=None,
            evidence_references=_evidence_references(report),
        )

    if conditions:
        reasons.add("evidence gate: all remaining conditions have cited non-impact proof")
        status = ReadinessStatus.CONDITIONAL
    else:
        reasons.add("all readiness gates passed")
        status = ReadinessStatus.READY

    if not prohibited:
        prohibited.add("actions outside recorded authorization")
    return PreflightDecision(
        status=status,
        reasons=tuple(sorted(reasons)),
        conditions=tuple(sorted(conditions)),
        authorized_actions=tuple(sorted(authorized, key=_normalize)),
        prohibited_actions=tuple(sorted(prohibited, key=_normalize)),
        unresolved_actions=(),
        exact_next_action=requested_action,
        companion_skill_or_stage=_RECOMMENDED_SKILLS.get(normalized_requested),
        evidence_references=_evidence_references(report),
    )


def _evidence_references(report: ReconciliationReport) -> tuple[str, ...]:
    references = {
        f"{claim.source_ref}#{claim.claim_id}"
        for claim in report.claims
        if claim.source_ref.strip() and claim.claim_id.strip()
    }
    references.update(
        f"{approval.source_ref}#{approval.approval_id}"
        for approval in report.approvals
        if approval.source_ref.strip() and approval.approval_id.strip()
    )
    references.update(
        f"{finding.source_ref}#{finding.finding_id}"
        for finding in report.findings
        if finding.source_ref.strip() and finding.finding_id.strip()
    )
    return tuple(sorted(references))


def _actions_from_claims(claims: Iterable[object], fields: frozenset[str]) -> set[str]:
    actions: set[str] = set()
    for claim in claims:
        if _normalize(claim.field) in fields:
            actions.update(_as_actions(claim.value))
    return actions


def _actions_from_approvals(report: ReconciliationReport) -> set[str]:
    actions: set[str] = set()
    for approval in report.approvals:
        decision = _normalize(approval.decision)
        action = _normalize(approval.action)
        if decision not in _APPROVED_DECISIONS:
            continue
        if action in _AUTHORIZATION_ACTIONS:
            actions.update(item.strip() for item in approval.scope if item.strip())
    return actions


def _as_actions(value: object) -> set[str]:
    if isinstance(value, str):
        return {value.strip()} if value.strip() else set()
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def _condition_json(value: object, source_ref: str) -> str | None:
    if not isinstance(value, Mapping):
        return None
    condition = value.get("condition")
    basis = value.get("basis")
    if (
        value.get("does_not_affect_action") is not True
        or not isinstance(condition, str)
        or not condition.strip()
        or not isinstance(basis, str)
        or not basis.strip()
        or not source_ref.strip()
    ):
        return None
    payload = {
        "basis": basis.strip(),
        "condition": condition.strip(),
        "does_not_affect_action": True,
        "source_ref": source_ref,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").casefold().split())


def _stable_value(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return repr(value)
