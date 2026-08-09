"""Immutable vocabulary and records for Continuity evidence operations."""

from dataclasses import dataclass
from enum import StrEnum


class EvidenceState(StrEnum):
    """How strongly an artifact or claim is supported by inspected evidence."""

    VERIFIED = "Verified"
    ASSERTED = "Asserted"
    UNRESOLVED = "Unresolved"
    CONTRADICTED = "Contradicted"
    MISSING = "Missing"


class PackageStatus(StrEnum):
    """The authority lifecycle state of a portable Continuity package."""

    CANDIDATE = "Candidate"
    BLOCKED = "Blocked"
    CANONICAL = "Canonical"
    SUPERSEDED = "Superseded"


class ReadinessStatus(StrEnum):
    """Whether the recorded project state permits the requested next action."""

    READY = "Ready"
    CONDITIONAL = "Conditional"
    BLOCKED = "Blocked"


@dataclass(frozen=True)
class ArtifactRecord:
    source_id: str
    observed_path: str
    normalized_path: str
    sha256: str
    size_bytes: int
    evidence_state: EvidenceState


@dataclass(frozen=True)
class ClaimRecord:
    claim_id: str
    field: str
    value: object
    source_id: str
    source_ref: str
    evidence_state: EvidenceState
    recorded_at: str | None = None


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    action: str
    scope: tuple[str, ...]
    decision: str
    source_id: str
    source_ref: str
    approved_at: str


@dataclass(frozen=True)
class ConflictRecord:
    conflict_id: str
    field: str
    material: bool
    claim_ids: tuple[str, ...]
    resolution_approval_id: str | None


@dataclass(frozen=True)
class PreflightDecision:
    status: ReadinessStatus
    reasons: tuple[str, ...]
    conditions: tuple[str, ...]
    authorized_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    unresolved_actions: tuple[str, ...]
    exact_next_action: str | None
    companion_skill_or_stage: str | None
    evidence_references: tuple[str, ...]


@dataclass(frozen=True)
class PreflightRecord:
    """Portable identity-bound representation of one readiness decision."""

    project_id: str
    package_id: str
    status: ReadinessStatus
    reasons: tuple[str, ...]
    conditions: tuple[str, ...]
    authorized_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    unresolved_actions: tuple[str, ...]
    exact_next_action: str | None
    companion_skill_or_stage: str | None
    evidence_references: tuple[str, ...]

    @classmethod
    def from_decision(
        cls,
        decision: PreflightDecision,
        project_id: str,
        package_id: str,
    ) -> "PreflightRecord":
        return cls(
            project_id=project_id,
            package_id=package_id,
            status=decision.status,
            reasons=decision.reasons,
            conditions=decision.conditions,
            authorized_actions=decision.authorized_actions,
            prohibited_actions=decision.prohibited_actions,
            unresolved_actions=decision.unresolved_actions,
            exact_next_action=decision.exact_next_action,
            companion_skill_or_stage=decision.companion_skill_or_stage,
            evidence_references=decision.evidence_references,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "continuity.preflight/v1",
            "project_id": self.project_id,
            "package_id": self.package_id,
            "status": self.status.value,
            "reasons": list(self.reasons),
            "conditions": list(self.conditions),
            "authorized_actions": list(self.authorized_actions),
            "prohibited_actions": list(self.prohibited_actions),
            "unresolved_actions": list(self.unresolved_actions),
            "exact_next_action": self.exact_next_action,
            "companion_skill_or_stage": self.companion_skill_or_stage,
            "evidence_references": list(self.evidence_references),
        }


@dataclass(frozen=True)
class VerificationFinding:
    """The comparison of one expected checksum with observed file evidence."""

    normalized_path: str
    expected_sha256: str | None
    observed_sha256: str | None
    evidence_state: EvidenceState


@dataclass(frozen=True)
class VerificationReport:
    """Stable, inspectable findings from a checksum sidecar verification."""

    findings: tuple[VerificationFinding, ...]
    checksum_present: bool = True

    @property
    def verified(self) -> bool:
        return self.checksum_present and all(
            finding.evidence_state is EvidenceState.VERIFIED for finding in self.findings
        )
