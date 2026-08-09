"""End-to-end contracts for the deterministic Continuity command line."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest


DOCUMENT_PATHS = (
    "HANDOFF_README.md",
    "CANONICAL_STATE.md",
    "AUTHORITY_LEDGER.md",
    "CONFLICT_RESOLUTIONS.md",
    "UNRESOLVED.md",
    "NEXT_THREAD_PROMPT.txt",
    "SUPERPOWERS_PREFLIGHT.md",
)


def _json_file(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for relative, content in _snapshot(root).items():
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
    return digest.hexdigest()


def _complete_handoff(root: Path) -> None:
    root.mkdir()
    (root / "app.py").write_text("print('preserved source')\n", encoding="utf-8")
    (root / "MANIFEST.json").write_text("{}\n", encoding="utf-8")
    lines = []
    for path in sorted(item for item in root.iterdir() if item.is_file()):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run(
    wrapper: Path,
    *arguments: object,
    expected: int,
) -> tuple[dict[str, object], subprocess.CompletedProcess[str]]:
    completed = subprocess.run(
        [sys.executable, str(wrapper), *(str(argument) for argument in arguments)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == expected, completed.stderr or completed.stdout
    assert "Traceback" not in completed.stderr
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload, completed


def _assert_output(path: Path, payload: dict[str, object]) -> None:
    assert json.loads(path.read_text(encoding="utf-8")) == payload


def _claim(
    claim_id: str,
    field: str,
    value: object,
    source_id: str,
    *,
    recorded_at: str = "2026-08-09T10:00:00Z",
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "field": field,
        "value": value,
        "source_id": source_id,
        "source_ref": "HANDOFF.md",
        "evidence_state": "Verified",
        "recorded_at": recorded_at,
    }


def _approval(
    approval_id: str,
    action: str,
    scope: list[str],
    decision: str,
) -> dict[str, object]:
    return {
        "approval_id": approval_id,
        "action": action,
        "scope": scope,
        "decision": decision,
        "source_id": "user",
        "source_ref": "conversation://continuity/task-7",
        "approved_at": "2026-08-09T11:00:00Z",
    }


def _minimal_build_request(canonical_files: dict[str, str]) -> dict[str, object]:
    return {
        "package_id": "overlap",
        "project_id": "alpha",
        "created_at": "2026-08-09T12:30:00Z",
        "selected_source_hashes": {"source": "a" * 64},
        "reconciliation_report": {
            "claims": [],
            "conflicts": [],
            "findings": [],
            "approvals": [],
            "selected_claim_ids": [],
            "blocking_conflict_ids": [],
            "notes": [],
        },
        "canonical_files": canonical_files,
        "rendered_documents": {path: "state\n" for path in DOCUMENT_PATHS},
        "preflight_decision": {
            "schema": "continuity.preflight/v1",
            "project_id": "alpha",
            "package_id": "overlap",
            "status": "Ready",
            "reasons": ["all readiness gates passed"],
            "conditions": [],
            "authorized_actions": ["implementation"],
            "prohibited_actions": ["actions outside recorded authorization"],
            "unresolved_actions": [],
            "exact_next_action": "implementation",
            "companion_skill_or_stage": "superpowers:test-driven-development",
            "evidence_references": ["HANDOFF.md#claim-project"],
        },
        "lineage_data": {},
        "evidence_index": {},
        "secure_handling_approvals": [],
        "readiness": "Ready",
        "allow_conditional_promotion": False,
    }


def _standalone_preflight_report() -> dict[str, object]:
    claims = [
        _claim("claim-project", "project_id", "alpha", "source"),
        _claim("claim-lifecycle", "package status", "Canonical", "source"),
        _claim("claim-action", "authorized action", "implementation", "source"),
    ]
    return {
        "claims": claims,
        "conflicts": [],
        "findings": [
            {
                "finding_id": "finding-source",
                "source_id": "source",
                "source_ref": "source/SHA256SUMS.txt#finding-source",
                "evidence_state": "Verified",
                "detail": "checksum and lineage verified",
                "structurally_valid": True,
                "lineage_valid": True,
                "lineage_required": True,
                "expected_sha256": "a" * 64,
                "observed_sha256": "a" * 64,
            }
        ],
        "approvals": [
            _approval(
                "approval-implementation",
                "authorize-actions",
                ["implementation"],
                "approved",
            )
        ],
        "selected_claim_ids": [
            "claim-project",
            "claim-lifecycle",
            "claim-action",
        ],
        "blocking_conflict_ids": [],
        "notes": [],
    }


def _wrap_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(source, "r") as input_archive, zipfile.ZipFile(
        destination, "w"
    ) as output_archive:
        for info in input_archive.infolist():
            output_archive.writestr(f"package/{info.filename}", input_archive.read(info))


def test_ready_workflow_preserves_sources_and_candidate_bytes(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches any verb bypassing gates or mutating inspected/promoted inputs."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    older = tmp_path / "older"
    newer = tmp_path / "newer"
    _complete_handoff(older)
    _complete_handoff(newer)
    (newer / "app.py").write_text(
        "# Incomplete draft: no authoritative project-state claims.\n", encoding="utf-8"
    )
    lines = []
    for path in sorted(
        item for item in newer.iterdir() if item.is_file() and item.name != "SHA256SUMS.txt"
    ):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (newer / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sources_before = {"older": _snapshot(older), "newer": _snapshot(newer)}

    inspect_results: dict[str, dict[str, object]] = {}
    for source_id, source in (("older", older), ("newer", newer)):
        output = tmp_path / f"inspect-{source_id}.json"
        payload, _ = _run(
            wrapper,
            "inspect",
            source,
            "--output",
            output,
            expected=0,
        )
        assert payload["ok"] is True
        assert payload["operation"] == "inspect"
        assert payload["source"]["source_id"] == source_id
        assert payload["integrity"]["source_ref"] == f"directory://{source_id}"
        assert not any(str(tmp_path) in json.dumps(item) for item in payload.values())
        _assert_output(output, payload)
        inspect_results[source_id] = payload

    claims = [
        _claim("claim-project", "project id", "alpha", "older"),
        _claim("claim-architecture", "architecture", "modular monolith", "older"),
        _claim("claim-lifecycle", "package status", "Canonical", "older"),
    ]
    approvals = [
        _approval("approval-implementation", "authorize-actions", ["implementation"], "approved")
    ]
    claims_input = _json_file(tmp_path / "claims.json", claims)
    approvals_input = _json_file(tmp_path / "approvals.json", approvals)
    integrity_input = _json_file(
        tmp_path / "integrity.json",
        [
            inspect_results["older"]["integrity"],
            inspect_results["newer"]["integrity"],
        ],
    )
    reconcile_output = tmp_path / "reconciliation.json"
    reconciliation, _ = _run(
        wrapper,
        "reconcile",
        "--claims",
        claims_input,
        "--approvals",
        approvals_input,
        "--integrity",
        integrity_input,
        "--output",
        reconcile_output,
        expected=0,
    )
    assert reconciliation["ok"] is True
    assert reconciliation["report"]["blocking_conflict_ids"] == []
    assert "claim-architecture" in reconciliation["report"]["selected_claim_ids"]
    assert all(
        claim["source_id"] != "newer" for claim in reconciliation["report"]["claims"]
    )

    candidate_id = "candidate-alpha"
    preflight_input = _json_file(
        tmp_path / "preflight-input.json", reconciliation["report"]
    )
    candidate_preflight, _ = _run(
        wrapper,
        "preflight",
        "--reconciliation",
        preflight_input,
        "--project-id",
        "alpha",
        "--package-id",
        candidate_id,
        "--requested-action",
        "implementation",
        "--output",
        tmp_path / "candidate-preflight.json",
        expected=0,
    )
    selected_hashes = {
        source_id: str(result["source"]["sha256"])
        for source_id, result in inspect_results.items()
    }
    build_input = _json_file(
        tmp_path / "build-input.json",
        {
            "package_id": candidate_id,
            "project_id": "alpha",
            "created_at": "2026-08-09T12:30:00Z",
            "selected_source_hashes": selected_hashes,
            "reconciliation_report": reconciliation["report"],
            "canonical_files": {"src/app.py": str(older / "app.py")},
            "rendered_documents": {
                path: f"# {path}\n\nVerified Continuity state.\n" for path in DOCUMENT_PATHS
            },
            "preflight_decision": candidate_preflight,
            "lineage_data": {
                "schema": "continuity.lineage/v1",
                "package_id": candidate_id,
                "project_id": "alpha",
                "created_at": "2026-08-09T12:30:00Z",
                "status": "Candidate",
                "readiness": "Ready",
                "parent_ids": [],
                "root_package_ids": [],
                "source_hashes": selected_hashes,
            },
            "evidence_index": {
                "schema": "continuity.evidence-index/v1",
                "items": [
                    {
                        "source_id": "older",
                        "state": "Verified",
                        "reference": "external-by-sha256",
                    }
                ],
            },
            "secure_handling_approvals": [],
            "readiness": "Ready",
            "allow_conditional_promotion": False,
        },
    )
    candidate_release = tmp_path / candidate_id
    built, _ = _run(
        wrapper,
        "build",
        "--request",
        build_input,
        "--output-dir",
        candidate_release,
        expected=0,
    )
    assert built["package"] == {
        "package_id": candidate_id,
        "package_sha256": built["package"]["package_sha256"],
        "status": "Candidate",
    }
    candidate_before = _snapshot(candidate_release)

    candidate_validation, _ = _run(
        wrapper,
        "validate",
        candidate_release,
        "--output",
        tmp_path / "candidate-validation.json",
        expected=0,
    )
    assert candidate_validation["validation"]["status"] == "Candidate"

    rejected, _ = _run(
        wrapper,
        "promote",
        candidate_release / "package",
        "--output",
        tmp_path / "canonical-rejected",
        "--created-at",
        "2026-08-09T13:00:00Z",
        expected=1,
    )
    assert rejected == {
        "error": {
            "code": "invalid_input",
            "details": [],
            "message": "promotion requires an exact approval record",
        },
        "ok": False,
    }
    assert not (tmp_path / "canonical-rejected").exists()

    promotion_approval = _json_file(
        tmp_path / "promotion-approval.json",
        _approval("approval-promote", "promote-candidate", [candidate_id], "approved"),
    )
    canonical_id = "canonical-alpha"
    canonical_release = tmp_path / canonical_id
    promoted, _ = _run(
        wrapper,
        "promote",
        candidate_release / "package",
        "--approval",
        promotion_approval,
        "--created-at",
        "2026-08-09T13:00:00Z",
        "--output",
        canonical_release,
        expected=0,
    )
    assert promoted["package"]["package_id"] == canonical_id
    assert promoted["package"]["status"] == "Canonical"

    validation, _ = _run(
        wrapper,
        "validate",
        canonical_release / f"{canonical_id}.zip",
        "--output",
        tmp_path / "validation.json",
        expected=0,
    )
    assert validation["validation"] == {
        "package_id": canonical_id,
        "readiness": "Ready",
        "status": "Canonical",
        "valid": True,
        "violation_count": 0,
        "violations": [],
    }
    canonical_inspection, _ = _run(
        wrapper,
        "inspect",
        canonical_release / f"{canonical_id}.zip",
        "--output",
        tmp_path / "canonical-inspection.json",
        expected=0,
    )
    assert canonical_inspection["integrity"]["evidence_state"] == "Verified"
    assert canonical_inspection["archive"]["code"] == "package-verified"
    wrapped_canonical = tmp_path / "wrapped-canonical.zip"
    _wrap_zip(canonical_release / f"{canonical_id}.zip", wrapped_canonical)
    wrapped_inspection, _ = _run(
        wrapper,
        "inspect",
        wrapped_canonical,
        "--output",
        tmp_path / "wrapped-canonical.json",
        expected=0,
    )
    assert wrapped_inspection["integrity"]["evidence_state"] == "Verified"
    assert wrapped_inspection["archive"]["code"] == "package-verified"

    preflight, _ = _run(
        wrapper,
        "preflight",
        "--reconciliation",
        preflight_input,
        "--project-id",
        "alpha",
        "--package-id",
        canonical_id,
        "--requested-action",
        "implementation",
        "--output",
        tmp_path / "preflight.json",
        expected=0,
    )
    assert preflight["schema"] == "continuity.preflight/v1"
    assert preflight["project_id"] == "alpha"
    assert preflight["package_id"] == canonical_id
    assert preflight["status"] == "Ready"
    assert preflight["exact_next_action"] == "implementation"
    assert preflight["companion_skill_or_stage"] == (
        "superpowers:test-driven-development"
    )
    assert "recommended_superpowers_skill" not in preflight
    assert _snapshot(older) == sources_before["older"]
    assert _snapshot(newer) == sources_before["newer"]
    assert _snapshot(candidate_release) == candidate_before


@pytest.mark.parametrize(
    ("case", "project_id", "expected_message"),
    (
        (
            "absent",
            "alpha",
            "preflight requires exactly one selected project_id claim",
        ),
        (
            "unselected",
            "alpha",
            "preflight requires exactly one selected project_id claim",
        ),
        (
            "multiple",
            "alpha",
            "preflight requires exactly one selected project_id claim",
        ),
        (
            "mismatch",
            "beta",
            "preflight project_id does not match selected project identity",
        ),
    ),
)
def test_standalone_preflight_binds_selected_project_identity(
    tmp_path: Path,
    repo_root: Path,
    case: str,
    project_id: str,
    expected_message: str,
) -> None:
    """Catches caller project identity diverging from selected reconciliation truth."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    report = _standalone_preflight_report()
    claims = report["claims"]
    selected = report["selected_claim_ids"]
    assert isinstance(claims, list) and isinstance(selected, list)
    if case == "absent":
        report["claims"] = [
            claim for claim in claims if claim["claim_id"] != "claim-project"
        ]
        selected.remove("claim-project")
    elif case == "unselected":
        selected.remove("claim-project")
    elif case == "multiple":
        claims.append(_claim("claim-project-beta", "project id", "beta", "source"))
        selected.append("claim-project-beta")
    report_path = _json_file(tmp_path / f"preflight-{case}.json", report)

    payload, _ = _run(
        wrapper,
        "preflight",
        "--reconciliation",
        report_path,
        "--project-id",
        project_id,
        "--package-id",
        "candidate-alpha",
        "--requested-action",
        "implementation",
        "--output",
        tmp_path / f"preflight-{case}-output.json",
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert payload["error"]["message"] == expected_message


def test_architecture_conflict_blocks_candidate_and_implementation_recommendation(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches unresolved architecture authority being treated as implementation-ready."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    left = tmp_path / "left"
    right = tmp_path / "right"
    _complete_handoff(left)
    _complete_handoff(right)
    sources_before = {"left": _snapshot(left), "right": _snapshot(right)}

    findings = []
    for source_id, source in (("left", left), ("right", right)):
        inspected, _ = _run(
            wrapper,
            "inspect",
            source,
            "--output",
            tmp_path / f"{source_id}.json",
            expected=0,
        )
        findings.append(inspected["integrity"])

    claims = [
        _claim("project", "project id", "alpha", "left"),
        _claim("monolith", "architecture", "monolith", "left"),
        _claim("services", "architecture", "services", "right"),
        _claim("lifecycle", "package status", "Canonical", "left"),
        _claim("action", "authorized action", "implementation", "left"),
    ]
    claims_input = _json_file(tmp_path / "conflict-claims.json", claims)
    approvals_input = _json_file(tmp_path / "conflict-approvals.json", [])
    integrity_input = _json_file(tmp_path / "conflict-integrity.json", findings)
    reconciled, _ = _run(
        wrapper,
        "reconcile",
        "--claims",
        claims_input,
        "--approvals",
        approvals_input,
        "--integrity",
        integrity_input,
        "--output",
        tmp_path / "conflict-report.json",
        expected=2,
    )
    assert reconciled["report"]["blocking_conflict_ids"]

    blocked_id = "candidate-blocked"
    preflight_input = _json_file(tmp_path / "blocked-input.json", reconciled["report"])
    blocked_preflight, _ = _run(
        wrapper,
        "preflight",
        "--reconciliation",
        preflight_input,
        "--project-id",
        "alpha",
        "--package-id",
        blocked_id,
        "--requested-action",
        "implementation",
        "--output",
        tmp_path / "blocked-preflight.json",
        expected=2,
    )
    selected_hashes = {
        source_id: _tree_sha256(source)
        for source_id, source in (("left", left), ("right", right))
    }
    blocked_request = _json_file(
        tmp_path / "blocked-build.json",
        {
            "package_id": blocked_id,
            "project_id": "alpha",
            "created_at": "2026-08-09T12:30:00Z",
            "selected_source_hashes": selected_hashes,
            "reconciliation_report": reconciled["report"],
            "canonical_files": {"src/app.py": str(left / "app.py")},
            "rendered_documents": {
                path: f"# {path}\n\nBlocked Continuity state.\n" for path in DOCUMENT_PATHS
            },
            "preflight_decision": blocked_preflight,
            "lineage_data": {
                "schema": "continuity.lineage/v1",
                "package_id": blocked_id,
                "project_id": "alpha",
                "created_at": "2026-08-09T12:30:00Z",
                "status": "Candidate",
                "readiness": "Blocked",
                "parent_ids": [],
                "root_package_ids": [],
                "source_hashes": selected_hashes,
            },
            "evidence_index": {
                "schema": "continuity.evidence-index/v1",
                "items": [
                    {"source_id": "left", "state": "Verified", "reference": "sha256"}
                ],
            },
            "secure_handling_approvals": [],
            "readiness": "Blocked",
            "allow_conditional_promotion": False,
        },
    )
    blocked_release = tmp_path / blocked_id
    blocked_build, _ = _run(
        wrapper,
        "build",
        "--request",
        blocked_request,
        "--output-dir",
        blocked_release,
        expected=2,
    )
    assert blocked_build["package"]["status"] == "Blocked"
    assert not any(
        json.loads(path.read_text(encoding="utf-8"))["status"] == "Candidate"
        for path in blocked_release.rglob("MANIFEST.json")
    )
    blocked_before = _snapshot(blocked_release)

    promotion_approval = _json_file(
        tmp_path / "blocked-promotion-approval.json",
        _approval("blocked-promote", "promote-candidate", [blocked_id], "approved"),
    )
    canonical_release = tmp_path / "canonical-blocked"
    failed_promotion, _ = _run(
        wrapper,
        "promote",
        blocked_release,
        "--approval",
        promotion_approval,
        "--created-at",
        "2026-08-09T13:00:00Z",
        "--output",
        canonical_release,
        expected=1,
    )
    assert failed_promotion["ok"] is False
    assert not canonical_release.exists()
    assert _snapshot(blocked_release) == blocked_before
    assert _snapshot(left) == sources_before["left"]
    assert _snapshot(right) == sources_before["right"]

    blocked = blocked_preflight
    assert blocked["schema"] == "continuity.preflight/v1"
    assert blocked["status"] == "Blocked"
    assert blocked["authorized_actions"] == []
    assert blocked["exact_next_action"] is None
    assert blocked["companion_skill_or_stage"] is None
    assert blocked_release.exists()
    assert not canonical_release.exists()


def test_security_record_unknown_fields_are_rejected_without_path_or_secret_disclosure(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches permissive approval parsing or exception text leaking sensitive input."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    secret = "continuity-secret-value"
    claims_path = _json_file(tmp_path / "empty-claims.json", [])
    integrity_path = _json_file(tmp_path / "empty-integrity.json", [])
    approvals_path = _json_file(
        tmp_path / "bad-approvals.json",
        [
            {
                **_approval("bad", "authorize-actions", ["implementation"], "approved"),
                "unknown_secret": secret,
            }
        ],
    )

    payload, completed = _run(
        wrapper,
        "reconcile",
        "--claims",
        claims_path,
        "--approvals",
        approvals_path,
        "--integrity",
        integrity_path,
        "--output",
        tmp_path / "error.json",
        expected=1,
    )

    rendered = json.dumps(payload) + completed.stdout + completed.stderr
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_input"
    assert secret not in rendered
    assert str(tmp_path) not in rendered


def test_missing_output_parent_is_json_user_error_without_traceback(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches the fallback error writer re-raising its own path validation error."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source = tmp_path / "source"
    source.mkdir()

    completed = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "inspect",
            str(source),
            "--output",
            str(tmp_path / "absent" / "result.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    assert "Traceback" not in completed.stdout
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert payload["error"]["message"] == "output parent does not exist"


@pytest.mark.parametrize("verb", ("inspect", "validate"))
def test_json_output_cannot_replace_archive_input(
    tmp_path: Path, repo_root: Path, verb: str
) -> None:
    """Catches atomic report publication replacing a read-only ZIP input."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("evidence.txt", "preserve me")
    before = archive.read_bytes()

    payload, _ = _run(wrapper, verb, archive, "--output", archive, expected=1)

    assert payload["error"]["code"] == "invalid_input"
    assert archive.read_bytes() == before


@pytest.mark.parametrize("verb", ("inspect", "validate"))
def test_json_output_cannot_be_inside_source_directory(
    tmp_path: Path, repo_root: Path, verb: str
) -> None:
    """Catches report temp files mutating a directory being inspected or validated."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source = tmp_path / "package"
    _complete_handoff(source)
    before = _snapshot(source)

    payload, _ = _run(
        wrapper, verb, source, "--output", source / "report.json", expected=1
    )

    assert payload["error"]["code"] == "invalid_input"
    assert _snapshot(source) == before


def test_build_output_may_not_contain_a_canonical_source(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches release publication replacing or nesting around canonical evidence."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source_root = tmp_path / "release-overlap"
    source_root.mkdir()
    source = source_root / "app.py"
    source.write_text("preserve = True\n", encoding="utf-8")
    before = source.read_bytes()
    request = _json_file(
        tmp_path / "overlap-build.json",
        _minimal_build_request({"app.py": str(source)}),
    )

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        source_root,
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert source.read_bytes() == before


def test_build_rejects_legacy_or_unknown_preflight_fields(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches an alternate companion field bypassing the exact v1 adapter."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    value = _minimal_build_request({})
    preflight = dict(value["preflight_decision"])
    preflight["recommended_superpowers_skill"] = preflight.pop(
        "companion_skill_or_stage"
    )
    value["preflight_decision"] = preflight
    request = _json_file(tmp_path / "legacy-preflight.json", value)

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        tmp_path / "release",
        expected=1,
    )

    assert payload["error"]["message"] == (
        "preflight_decision has missing or unknown fields"
    )
    assert not (tmp_path / "release").exists()


def test_build_output_may_not_be_beneath_single_source_tree(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches a nonexistent release directory being created beside a source file."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "app.py"
    source.write_text("preserve = True\n", encoding="utf-8")
    before = _snapshot(source_root)
    request = _json_file(
        tmp_path / "single-source.json",
        _minimal_build_request({"app.py": str(source)}),
    )
    release = source_root / "release"

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        release,
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert payload["error"]["message"] == "release output overlaps canonical source tree"
    assert not release.exists()
    assert _snapshot(source_root) == before


def test_build_derives_common_root_for_multiple_nested_sources(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches per-file overlap checks missing their shared project boundary."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source_root = tmp_path / "project"
    first = source_root / "src/app.py"
    second = source_root / "config/settings.json"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("preserve = True\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")
    before = _snapshot(source_root)
    request = _json_file(
        tmp_path / "nested-sources.json",
        _minimal_build_request({"src/app.py": str(first), "config/settings.json": str(second)}),
    )
    release = source_root / "release"

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        release,
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert payload["error"]["message"] == "release output overlaps canonical source tree"
    assert not release.exists()
    assert _snapshot(source_root) == before


def test_build_rejects_canonical_source_through_symlink_parent(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches aliases obscuring the source-tree boundary used for release checks."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "app.py"
    source.write_text("preserve = True\n", encoding="utf-8")
    alias = tmp_path / "source-alias"
    alias.symlink_to(source_root, target_is_directory=True)
    request = _json_file(
        tmp_path / "aliased-source.json",
        _minimal_build_request({"app.py": str(alias / "app.py")}),
    )

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        tmp_path / "legitimate-sibling",
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert payload["error"]["message"] == "canonical source path may not traverse a symlink"
    assert not (tmp_path / "legitimate-sibling").exists()


def test_build_rejects_sources_with_only_filesystem_root_in_common(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches multiple-project evidence being treated as one writable project tree."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    local_source = tmp_path / "local.py"
    local_source.write_text("preserve = True\n", encoding="utf-8")
    remote_source = repo_root / "README.md"
    request = _json_file(
        tmp_path / "multiple-roots.json",
        _minimal_build_request(
            {"local.py": str(local_source), "documentation/README.md": str(remote_source)}
        ),
    )

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        tmp_path / "release",
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert payload["error"]["message"] == "canonical sources do not identify one project root"
    assert not (tmp_path / "release").exists()


def test_build_allows_sibling_release_outside_source_root(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches source-boundary validation rejecting a legitimate sibling destination."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "app.py"
    source.write_text("preserve = True\n", encoding="utf-8")
    request = _json_file(
        tmp_path / "sibling-output.json",
        _minimal_build_request({"app.py": str(source)}),
    )

    payload, _ = _run(
        wrapper,
        "build",
        "--request",
        request,
        "--output-dir",
        tmp_path / "release",
        expected=1,
    )

    assert payload["error"]["message"] != "release output overlaps canonical source evidence"


def test_promotion_output_may_not_be_inside_candidate_release(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches canonical publication mutating the candidate release tree."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "MANIFEST.json").write_text("{}\n", encoding="utf-8")
    before = _snapshot(candidate)
    approval = _json_file(
        tmp_path / "approval.json",
        _approval("approval", "promote-candidate", ["candidate"], "approved"),
    )

    payload, _ = _run(
        wrapper,
        "promote",
        candidate,
        "--approval",
        approval,
        "--created-at",
        "2026-08-09T13:00:00Z",
        "--output",
        candidate / "canonical",
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert _snapshot(candidate) == before


def test_zip_inspection_requires_verified_package_bytes(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches filenames alone being treated as verified package authority."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    archive = tmp_path / "fabricated.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("MANIFEST.json", "{}\n")
        output.writestr("SHA256SUMS.txt", "0" * 64 + "  MANIFEST.json\n")

    payload, _ = _run(
        wrapper, "inspect", archive, "--output", tmp_path / "inspect.json", expected=0
    )

    assert payload["integrity"]["evidence_state"] == "Contradicted"
    assert payload["integrity"]["source_ref"] == "zip://fabricated.zip"
    assert payload["archive"]["code"] == "package-validation-failed"
    assert "MANIFEST.json" not in json.dumps(payload)

    wrapped = tmp_path / "wrapped-fabricated.zip"
    _wrap_zip(archive, wrapped)
    wrapped_payload, _ = _run(
        wrapper,
        "inspect",
        wrapped,
        "--output",
        tmp_path / "wrapped-inspect.json",
        expected=0,
    )
    assert wrapped_payload["integrity"]["evidence_state"] == "Contradicted"
    assert wrapped_payload["archive"]["code"] == "package-validation-failed"


def test_safe_non_package_zip_remains_unresolved(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches structural ZIP safety being promoted to evidence authority."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    archive = tmp_path / "notes.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("notes.txt", "unstructured evidence")

    payload, _ = _run(
        wrapper, "inspect", archive, "--output", tmp_path / "notes.json", expected=0
    )

    assert payload["integrity"]["evidence_state"] == "Unresolved"
    assert payload["integrity"]["source_ref"] == "zip://notes.zip"
    assert payload["archive"]["code"] == "package-integrity-evidence-incomplete"


def test_malformed_checksum_and_secret_member_are_sanitized(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches archive/package failure details exposing submitted member names or secrets."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    secret = "submitted-secret-filename"
    archive = tmp_path / "malformed.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("package/MANIFEST.json", "{}\n")
        output.writestr("package/SHA256SUMS.txt", "malformed checksum\n")
        output.writestr(f"package/canonical/{secret}.txt", "secret-value")

    payload, completed = _run(
        wrapper, "inspect", archive, "--output", tmp_path / "result.json", expected=0
    )

    rendered = json.dumps(payload) + completed.stdout + completed.stderr
    assert payload["integrity"]["evidence_state"] == "Contradicted"
    assert secret not in rendered
    assert "secret-value" not in rendered
    assert str(tmp_path) not in rendered

    validation, validated = _run(
        wrapper,
        "validate",
        archive,
        "--output",
        tmp_path / "validation.json",
        expected=1,
    )
    rendered_validation = json.dumps(validation) + validated.stdout + validated.stderr
    assert validation["validation"]["violation_count"] > 0
    assert secret not in rendered_validation
    assert str(tmp_path) not in rendered_validation


def test_json_output_rejects_symlink_parent_redirection(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches a sibling temp report being redirected outside its explicit parent."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    source = tmp_path / "source"
    source.mkdir()
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(redirected, target_is_directory=True)

    payload, _ = _run(
        wrapper,
        "inspect",
        source,
        "--output",
        link / "report.json",
        expected=1,
    )

    assert payload["error"]["code"] == "invalid_input"
    assert not (redirected / "report.json").exists()


def test_runtime_publication_failure_is_stable_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches unavailable no-clobber publication escaping as a traceback."""
    from continuity import cli

    request = _json_file(
        tmp_path / "request.json",
        {
            "package_id": "candidate", "project_id": "alpha",
            "created_at": "2026-08-09T12:00:00Z", "selected_source_hashes": {},
            "reconciliation_report": {
                "claims": [], "conflicts": [], "findings": [], "approvals": [],
                "selected_claim_ids": [], "blocking_conflict_ids": [], "notes": [],
            },
            "canonical_files": {},
            "rendered_documents": {path: "state\n" for path in DOCUMENT_PATHS},
            "preflight_decision": {
                "schema": "continuity.preflight/v1",
                "project_id": "alpha",
                "package_id": "candidate",
                "status": "Ready",
                "reasons": ["all readiness gates passed"],
                "conditions": [],
                "authorized_actions": ["implementation"],
                "prohibited_actions": ["actions outside recorded authorization"],
                "unresolved_actions": [],
                "exact_next_action": "implementation",
                "companion_skill_or_stage": "superpowers:test-driven-development",
                "evidence_references": ["HANDOFF.md#claim-project"],
            },
            "lineage_data": {}, "evidence_index": {}, "secure_handling_approvals": [],
            "readiness": "Ready", "allow_conditional_promotion": False,
        },
    )
    monkeypatch.setattr(
        cli, "build_candidate", lambda request: (_ for _ in ()).throw(RuntimeError("no replace"))
    )

    code = cli.main(
        ["build", "--request", str(request), "--output-dir", str(tmp_path / "release")]
    )

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["error"]["message"] == "operation failed validation or could not be completed"
