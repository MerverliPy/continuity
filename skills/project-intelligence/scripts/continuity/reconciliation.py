"""Evidence-gated reconciliation of competing project-state claims."""

from dataclasses import dataclass
import hashlib
import json
from typing import Sequence

from .models import ApprovalRecord, ClaimRecord, ConflictRecord, EvidenceState


_MATERIAL_FIELDS = frozenset(
    {
        "architecture",
        "behavior",
        "scope",
        "authority",
        "safety",
        "release",
        "release readiness",
        "next action",
    }
)


@dataclass(frozen=True)
class IntegrityFinding:
    """Structural, checksum, and lineage evidence for one source."""

    finding_id: str
    source_id: str
    evidence_state: EvidenceState
    source_ref: str
    detail: str = ""
    structurally_valid: bool | None = None
    lineage_valid: bool | None = None
    lineage_required: bool = True
    expected_sha256: str | None = None
    observed_sha256: str | None = None

    @property
    def permits_automatic_selection(self) -> bool:
        return integrity_finding_permits_automatic_selection(
            evidence_state=self.evidence_state,
            structurally_valid=self.structurally_valid,
            lineage_valid=self.lineage_valid,
            lineage_required=self.lineage_required,
            expected_sha256=self.expected_sha256,
            observed_sha256=self.observed_sha256,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "source_id": self.source_id,
            "source_ref": self.source_ref,
            "evidence_state": self.evidence_state.value,
            "detail": self.detail,
            "structurally_valid": self.structurally_valid,
            "lineage_valid": self.lineage_valid,
            "lineage_required": self.lineage_required,
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
        }


def integrity_finding_permits_automatic_selection(
    *,
    evidence_state: EvidenceState,
    structurally_valid: bool | None,
    lineage_valid: bool | None,
    lineage_required: bool,
    expected_sha256: str | None,
    observed_sha256: str | None,
) -> bool:
    """Apply the one integrity blocker policy used by reconciliation and handoffs."""

    structural_gate = (
        evidence_state is EvidenceState.VERIFIED
        if structurally_valid is None
        else structurally_valid
    )
    lineage_gate = lineage_valid is not False and (
        not lineage_required or lineage_valid is True
    )
    digest_gate = not (
        expected_sha256 is not None
        and observed_sha256 is not None
        and expected_sha256 != observed_sha256
    )
    return (
        evidence_state is EvidenceState.VERIFIED
        and structural_gate
        and lineage_gate
        and digest_gate
    )


@dataclass(frozen=True)
class ReconciliationReport:
    """Stable reconciliation output preserving all evidence and provenance."""

    claims: tuple[ClaimRecord, ...]
    approvals: tuple[ApprovalRecord, ...]
    findings: tuple[IntegrityFinding, ...]
    conflicts: tuple[ConflictRecord, ...]
    selected_claim_ids: tuple[str, ...]
    notes: tuple[str, ...]

    @property
    def blocking_conflicts(self) -> tuple[ConflictRecord, ...]:
        return tuple(
            conflict
            for conflict in self.conflicts
            if conflict.material and conflict.resolution_approval_id is None
        )

    def to_dict(self) -> dict[str, object]:
        claims = sorted(self.claims, key=lambda claim: claim.claim_id)
        conflicts = sorted(self.conflicts, key=lambda conflict: conflict.conflict_id)
        findings = sorted(self.findings, key=lambda finding: finding.finding_id)
        approvals = sorted(self.approvals, key=lambda approval: approval.approval_id)
        return {
            "claims": [_claim_to_dict(claim) for claim in claims],
            "conflicts": [_conflict_to_dict(conflict) for conflict in conflicts],
            "findings": [finding.to_dict() for finding in findings],
            "approvals": [_approval_to_dict(approval) for approval in approvals],
            "selected_claim_ids": list(self.selected_claim_ids),
            "blocking_conflict_ids": [
                conflict.conflict_id
                for conflict in sorted(
                    self.blocking_conflicts, key=lambda conflict: conflict.conflict_id
                )
            ],
            "notes": list(self.notes),
        }


def conflict_id_for(field: str, claims: Sequence[ClaimRecord]) -> str:
    """Return the stable ID an exact conflict-resolution approval must cite."""

    claim_ids = sorted(claim.claim_id for claim in claims)
    identity = json.dumps(
        [_normalize_field(field), claim_ids], ensure_ascii=False, separators=(",", ":")
    )
    return f"conflict-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]}"


def reconcile_sources(
    claims: Sequence[ClaimRecord],
    approvals: Sequence[ApprovalRecord],
    integrity: Sequence[IntegrityFinding],
) -> ReconciliationReport:
    """Reconcile claims using ordered gates, never a numeric authority score."""

    ordered_claims = tuple(sorted(claims, key=lambda claim: claim.claim_id))
    ordered_approvals = tuple(sorted(approvals, key=lambda approval: approval.approval_id))
    findings = list(integrity)
    source_findings: dict[str, list[IntegrityFinding]] = {}
    wildcard_findings: list[IntegrityFinding] = []
    for finding in integrity:
        if finding.source_id == "*":
            wildcard_findings.append(finding)
        else:
            source_findings.setdefault(finding.source_id, []).append(finding)

    def relevant_findings(source_id: str) -> Sequence[IntegrityFinding]:
        if source_id == "*":
            return tuple(wildcard_findings)
        return (*wildcard_findings, *source_findings.get(source_id, ()))

    def source_permits_selection(source_id: str, *, allow_uninspected: bool = False) -> bool:
        relevant = relevant_findings(source_id)
        return (allow_uninspected and not relevant) or (
            bool(relevant)
            and all(finding.permits_automatic_selection for finding in relevant)
        )

    # Gate 1: invalid evidence is retained above but cannot enter selection.
    eligible: list[ClaimRecord] = []
    excluded: list[ClaimRecord] = []
    synthesized_sources: set[str] = set()
    for claim in ordered_claims:
        relevant = relevant_findings(claim.source_id)
        if not relevant:
            excluded.append(claim)
            if claim.source_id not in synthesized_sources:
                findings.append(
                    IntegrityFinding(
                        finding_id=_missing_integrity_id(claim.source_id),
                        source_id=claim.source_id,
                        evidence_state=EvidenceState.UNRESOLVED,
                        source_ref=f"reconciliation://missing-integrity/{claim.source_id}",
                        detail="no structural integrity evidence was supplied",
                    )
                )
                synthesized_sources.add(claim.source_id)
            continue

        # Gate 2 requires affirmative proof whenever a finding marks lineage required.
        if claim.evidence_state in {EvidenceState.VERIFIED, EvidenceState.ASSERTED} and all(
            finding.permits_automatic_selection for finding in relevant
        ):
            eligible.append(claim)
        else:
            excluded.append(claim)

    grouped: dict[str, list[ClaimRecord]] = {}
    for claim in eligible:
        grouped.setdefault(_normalize_field(claim.field), []).append(claim)

    selected: set[str] = set()
    conflicts: list[ConflictRecord] = []
    for normalized_field, field_claims in sorted(grouped.items()):
        variants: dict[str, list[ClaimRecord]] = {}
        for claim in field_claims:
            variants.setdefault(_normalized_value(claim.value), []).append(claim)

        # Gate 4: equivalent uncontested facts retain every source provenance.
        if len(variants) == 1:
            selected.update(claim.claim_id for claim in field_claims)
            continue

        material = _is_material_field(normalized_field)
        conflict_id = conflict_id_for(normalized_field, field_claims)
        resolution_id: str | None = None

        # Gates 3 and 6: only exact action/scope and a cited conflict can resolve.
        exact_resolutions = [
            approval
            for approval in ordered_approvals
            if approval.action == "resolve-conflict"
            and approval.scope == (conflict_id,)
            and approval.decision in {claim.claim_id for claim in field_claims}
            and source_permits_selection(approval.source_id, allow_uninspected=True)
        ]
        decisions = {approval.decision for approval in exact_resolutions}
        if material and len(decisions) == 1:
            selected.add(next(iter(decisions)))
            resolution_id = min(
                approval.approval_id
                for approval in exact_resolutions
                if approval.decision in decisions
            )
        elif not material:
            selected.update(claim.claim_id for claim in field_claims)

        conflicts.append(
            ConflictRecord(
                conflict_id=conflict_id,
                field=field_claims[0].field,
                material=material,
                claim_ids=tuple(sorted(claim.claim_id for claim in field_claims)),
                resolution_approval_id=resolution_id,
            )
        )

    notes: set[str] = set()
    if _newer_excluded_claim_exists(excluded, eligible):
        notes.add("newer timestamp is not controlling authority")

    return ReconciliationReport(
        claims=ordered_claims,
        approvals=ordered_approvals,
        findings=tuple(sorted(findings, key=lambda finding: finding.finding_id)),
        conflicts=tuple(sorted(conflicts, key=lambda conflict: conflict.conflict_id)),
        selected_claim_ids=tuple(sorted(selected)),
        notes=tuple(sorted(notes)),
    )


def _normalize_field(field: str) -> str:
    return " ".join(field.replace("_", " ").replace("-", " ").casefold().split())


def _is_material_field(field: str) -> bool:
    padded_field = f" {field} "
    return any(f" {material} " in padded_field for material in _MATERIAL_FIELDS)


def _normalized_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(" ".join(value.casefold().split()), ensure_ascii=False)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return repr(value)


def _newer_excluded_claim_exists(
    excluded: Sequence[ClaimRecord], eligible: Sequence[ClaimRecord]
) -> bool:
    eligible_by_field: dict[str, list[ClaimRecord]] = {}
    for claim in eligible:
        eligible_by_field.setdefault(_normalize_field(claim.field), []).append(claim)
    for claim in excluded:
        if claim.recorded_at is None:
            continue
        for selected in eligible_by_field.get(_normalize_field(claim.field), ()):
            if selected.recorded_at is not None and claim.recorded_at > selected.recorded_at:
                return True
    return False


def _missing_integrity_id(source_id: str) -> str:
    digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:16]
    return f"integrity-missing-{digest}"


def _claim_to_dict(claim: ClaimRecord) -> dict[str, object]:
    return {
        "claim_id": claim.claim_id,
        "field": claim.field,
        "value": claim.value,
        "source_id": claim.source_id,
        "source_ref": claim.source_ref,
        "evidence_state": claim.evidence_state.value,
        "recorded_at": claim.recorded_at,
    }


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


def _conflict_to_dict(conflict: ConflictRecord) -> dict[str, object]:
    return {
        "conflict_id": conflict.conflict_id,
        "field": conflict.field,
        "material": conflict.material,
        "claim_ids": list(sorted(conflict.claim_ids)),
        "resolution_approval_id": conflict.resolution_approval_id,
    }
