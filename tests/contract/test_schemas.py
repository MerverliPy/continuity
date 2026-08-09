from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


SCHEMA_NAMES = (
    "manifest",
    "lineage",
    "evidence-index",
    "reconciliation",
    "preflight",
    "document-inputs",
)


def _schema(repo_root: Path, name: str) -> dict[str, object]:
    path = (
        repo_root
        / "skills/project-intelligence/assets/schemas"
        / f"{name}.schema.json"
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _documents() -> dict[str, dict[str, object]]:
    digest = "a" * 64
    return {
        "manifest": {
            "schema": "continuity.package/v1",
            "package_id": "candidate-alpha",
            "project_id": "alpha",
            "created_at": "2026-08-09T12:00:00Z",
            "status": "Candidate",
            "readiness": "Ready",
            "allow_conditional_promotion": False,
            "lineage_roots": [],
            "selected_source_hashes": {"source-alpha": digest},
            "files": [
                {"path": "canonical/app.py", "sha256": digest, "size_bytes": 12}
            ],
        },
        "lineage": {
            "schema": "continuity.lineage/v1",
            "package_id": "candidate-alpha",
            "project_id": "alpha",
            "created_at": "2026-08-09T12:00:00Z",
            "status": "Candidate",
            "readiness": "Ready",
            "parent_ids": [],
            "root_package_ids": [],
            "source_hashes": {"source-alpha": digest},
        },
        "evidence-index": {
            "schema": "continuity.evidence-index/v1",
            "items": [
                {
                    "source_id": "source-alpha",
                    "state": "Verified",
                    "reference": "canonical/app.py#record-source-alpha",
                }
            ],
        },
        "reconciliation": {
            "claims": [
                {
                    "claim_id": "claim-project-alpha",
                    "field": "project id",
                    "value": "alpha",
                    "source_id": "source-alpha",
                    "source_ref": "canonical/project.json#project-alpha",
                    "evidence_state": "Verified",
                    "recorded_at": "2026-08-09T10:00:00Z",
                }
            ],
            "conflicts": [],
            "findings": [
                {
                    "finding_id": "finding-source-alpha",
                    "source_id": "source-alpha",
                    "source_ref": "canonical/SHA256SUMS.txt#finding-source-alpha",
                    "evidence_state": "Verified",
                    "detail": "checksum and lineage verified",
                    "structurally_valid": True,
                    "lineage_valid": True,
                    "lineage_required": True,
                    "expected_sha256": digest,
                    "observed_sha256": digest,
                }
            ],
            "approvals": [],
            "selected_claim_ids": ["claim-project-alpha"],
            "blocking_conflict_ids": [],
            "notes": [],
        },
        "preflight": {
            "schema": "continuity.preflight/v1",
            "project_id": "alpha",
            "package_id": "canonical-alpha",
            "status": "Ready",
            "reasons": ["all readiness gates passed"],
            "conditions": [],
            "authorized_actions": ["implementation"],
            "prohibited_actions": ["deployment"],
            "unresolved_actions": [],
            "exact_next_action": "implementation",
            "companion_skill_or_stage": "superpowers:test-driven-development",
            "evidence_references": ["receipts/RECONCILIATION.json#claim-project-alpha"],
        },
        "document-inputs": {
            "schema": "continuity.document-inputs/v1",
            "supplemental_narrative": {
                "HANDOFF_README.md": "Operator context.\n",
                "CANONICAL_STATE.md": "State context.\n",
                "AUTHORITY_LEDGER.md": "Authority context.\n",
                "CONFLICT_RESOLUTIONS.md": "Conflict context.\n",
                "UNRESOLVED.md": "Unknowns context.\n",
                "NEXT_THREAD_PROMPT.txt": "Continuation context.\n",
                "SUPERPOWERS_PREFLIGHT.md": "Preflight context.\n",
            },
        },
    }


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_is_valid_draft_2020_12(repo_root: Path, name: str) -> None:
    """Catches a bundled schema that cannot be consumed as Draft 2020-12."""
    schema = _schema(repo_root, name)

    Draft202012Validator.check_schema(schema)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"https://continuity.local/schemas/v1/{name}.schema.json"


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_accepts_representative_v1_document(repo_root: Path, name: str) -> None:
    """Catches a schema drifting away from the runtime's version-one artifacts."""
    validator = Draft202012Validator(_schema(repo_root, name))

    assert list(validator.iter_errors(_documents()[name])) == []


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_rejects_undeclared_top_level_fields(repo_root: Path, name: str) -> None:
    """Catches implicit authority entering a package through undeclared fields."""
    validator = Draft202012Validator(_schema(repo_root, name))
    document = {**_documents()[name], "implicit_authority": "deploy anything"}

    assert list(validator.iter_errors(document))


def test_manifest_requires_v1_identity_and_lifecycle(repo_root: Path) -> None:
    """Catches a package with the wrong schema identity or unknown lifecycle state."""
    validator = Draft202012Validator(_schema(repo_root, "manifest"))
    document = {**_documents()["manifest"], "schema": "continuity.package/v2"}

    assert list(validator.iter_errors(document))

    document = {**_documents()["manifest"], "status": "Approved"}
    assert list(validator.iter_errors(document))


def test_canonical_lineage_requires_explicit_successor_time(repo_root: Path) -> None:
    """Catches promotion authority being inferred from a reused candidate timestamp."""
    validator = Draft202012Validator(_schema(repo_root, "lineage"))
    document = {**_documents()["lineage"], "status": "Canonical"}

    assert list(validator.iter_errors(document))

    document["successor_created_at"] = "2026-08-09T13:00:00Z"
    assert list(validator.iter_errors(document)) == []


def test_evidence_schema_enumerates_claim_states(repo_root: Path) -> None:
    """Catches an evidence item silently inventing a sixth confidence state."""
    validator = Draft202012Validator(_schema(repo_root, "evidence-index"))
    document = _documents()["evidence-index"]
    document["items"][0]["state"] = "Probable"  # type: ignore[index]

    assert list(validator.iter_errors(document))


def test_reconciliation_authority_records_are_strict(repo_root: Path) -> None:
    """Catches an approval carrying undeclared authority beside its cited scope."""
    validator = Draft202012Validator(_schema(repo_root, "reconciliation"))
    document = _documents()["reconciliation"]
    document["approvals"] = [
        {
            "approval_id": "approval-alpha",
            "action": "authorize-actions",
            "scope": ["implementation"],
            "decision": "approved",
            "source_id": "user",
            "source_ref": "conversation://continuity/approval-alpha",
            "approved_at": "2026-08-09T11:00:00Z",
            "implicit_scope": ["deployment"],
        }
    ]

    assert list(validator.iter_errors(document))


def test_integrity_finding_requires_direct_source_reference(repo_root: Path) -> None:
    """Catches blocker provenance being replaced by a generic receipt citation."""
    validator = Draft202012Validator(_schema(repo_root, "reconciliation"))
    document = _documents()["reconciliation"]
    del document["findings"][0]["source_ref"]  # type: ignore[index]

    assert list(validator.iter_errors(document))


def test_blocked_preflight_cannot_name_an_execution_stage(repo_root: Path) -> None:
    """Catches Blocked readiness being routed to companion execution."""
    validator = Draft202012Validator(_schema(repo_root, "preflight"))
    document = {
        **_documents()["preflight"],
        "status": "Blocked",
        "authorized_actions": [],
        "unresolved_actions": ["resolve readiness blockers"],
        "exact_next_action": None,
    }

    assert list(validator.iter_errors(document))

    document["companion_skill_or_stage"] = None
    assert list(validator.iter_errors(document)) == []


def test_blocked_preflight_rejects_authorized_execution(repo_root: Path) -> None:
    """Catches an execution action remaining authorized behind a Blocked label."""
    validator = Draft202012Validator(_schema(repo_root, "preflight"))
    document = {
        **_documents()["preflight"],
        "status": "Blocked",
        "exact_next_action": None,
        "companion_skill_or_stage": None,
        "unresolved_actions": ["resolve readiness blockers"],
    }

    assert list(validator.iter_errors(document))


@pytest.mark.parametrize("status", ("Ready", "Conditional"))
def test_actionable_preflight_requires_authorized_and_exact_action(
    repo_root: Path, status: str
) -> None:
    """Catches actionable readiness without an explicit authorization boundary."""
    validator = Draft202012Validator(_schema(repo_root, "preflight"))
    document = {
        **_documents()["preflight"],
        "status": status,
        "authorized_actions": [],
    }

    assert list(validator.iter_errors(document))

    document["authorized_actions"] = ["implementation"]
    document["exact_next_action"] = None
    assert list(validator.iter_errors(document))


def test_identity_lifecycle_authority_and_readiness_objects_are_closed(
    repo_root: Path,
) -> None:
    """Catches strict v1 domains becoming open-ended through schema edits."""
    manifest = _schema(repo_root, "manifest")
    lineage = _schema(repo_root, "lineage")
    reconciliation = _schema(repo_root, "reconciliation")
    preflight = _schema(repo_root, "preflight")

    assert manifest["additionalProperties"] is False
    assert lineage["additionalProperties"] is False
    assert reconciliation["$defs"]["approval"]["additionalProperties"] is False  # type: ignore[index]
    assert reconciliation["$defs"]["conflict"]["additionalProperties"] is False  # type: ignore[index]
    assert preflight["additionalProperties"] is False
