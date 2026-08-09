"""End-to-end contracts for the deterministic Continuity command line."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


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


def test_ready_workflow_preserves_sources_and_candidate_bytes(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches any verb bypassing gates or mutating inspected/promoted inputs."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    older = tmp_path / "older-handoff"
    newer = tmp_path / "newer-handoff"
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
            "--source-id",
            source_id,
            "--output",
            output,
            expected=0,
        )
        assert payload["ok"] is True
        assert payload["operation"] == "inspect"
        assert payload["source"]["source_id"] == source_id
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
    reconcile_input = _json_file(
        tmp_path / "reconcile-input.json",
        {
            "claims": claims,
            "approvals": approvals,
            "integrity": [
                inspect_results["older"]["integrity"],
                inspect_results["newer"]["integrity"],
            ],
        },
    )
    reconcile_output = tmp_path / "reconciliation.json"
    reconciliation, _ = _run(
        wrapper,
        "reconcile",
        reconcile_input,
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
    build_output = tmp_path / "build-result.json"
    built, _ = _run(
        wrapper,
        "build",
        build_input,
        "--release",
        candidate_release,
        "--output",
        build_output,
        expected=0,
    )
    assert built["package"] == {
        "package_id": candidate_id,
        "package_sha256": built["package"]["package_sha256"],
        "status": "Candidate",
    }
    candidate_before = _snapshot(candidate_release)

    rejected, _ = _run(
        wrapper,
        "promote",
        candidate_release / "package",
        "--release",
        tmp_path / "canonical-rejected",
        "--created-at",
        "2026-08-09T13:00:00Z",
        "--output",
        tmp_path / "promotion-rejected.json",
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
        "--release",
        canonical_release,
        "--approval",
        promotion_approval,
        "--created-at",
        "2026-08-09T13:00:00Z",
        "--output",
        tmp_path / "promotion.json",
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
        "violations": [],
    }

    preflight_input = _json_file(
        tmp_path / "preflight-input.json", reconciliation["report"]
    )
    preflight, _ = _run(
        wrapper,
        "preflight",
        preflight_input,
        "--action",
        "implementation",
        "--output",
        tmp_path / "preflight.json",
        expected=0,
    )
    assert preflight["decision"]["status"] == "Ready"
    assert preflight["decision"]["exact_next_action"] == "implementation"
    assert preflight["decision"]["recommended_superpowers_skill"] == (
        "superpowers:test-driven-development"
    )
    assert _snapshot(older) == sources_before["older"]
    assert _snapshot(newer) == sources_before["newer"]
    assert _snapshot(candidate_release) == candidate_before


def test_architecture_conflict_blocks_candidate_and_implementation_recommendation(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches unresolved architecture authority being treated as implementation-ready."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    left = tmp_path / "left"
    right = tmp_path / "right"
    _complete_handoff(left)
    _complete_handoff(right)

    findings = []
    for source_id, source in (("left", left), ("right", right)):
        inspected, _ = _run(
            wrapper,
            "inspect",
            source,
            "--source-id",
            source_id,
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
    reconcile_input = _json_file(
        tmp_path / "conflict-input.json",
        {"claims": claims, "approvals": [], "integrity": findings},
    )
    reconciled, _ = _run(
        wrapper,
        "reconcile",
        reconcile_input,
        "--output",
        tmp_path / "conflict-report.json",
        expected=2,
    )
    assert reconciled["report"]["blocking_conflict_ids"]

    preflight_input = _json_file(tmp_path / "blocked-input.json", reconciled["report"])
    blocked, _ = _run(
        wrapper,
        "preflight",
        preflight_input,
        "--action",
        "implementation",
        "--output",
        tmp_path / "blocked-preflight.json",
        expected=2,
    )
    assert blocked["decision"]["status"] == "Blocked"
    assert blocked["decision"]["exact_next_action"] is None
    assert blocked["decision"]["recommended_superpowers_skill"] is None
    assert not (tmp_path / "candidate-blocked").exists()


def test_security_record_unknown_fields_are_rejected_without_path_or_secret_disclosure(
    tmp_path: Path, repo_root: Path
) -> None:
    """Catches permissive approval parsing or exception text leaking sensitive input."""
    wrapper = repo_root / "skills/project-intelligence/scripts/continuity_cli.py"
    secret = "continuity-secret-value"
    input_path = _json_file(
        tmp_path / "bad-input.json",
        {
            "claims": [],
            "approvals": [
                {
                    **_approval("bad", "authorize-actions", ["implementation"], "approved"),
                    "unknown_secret": secret,
                }
            ],
            "integrity": [],
        },
    )

    payload, completed = _run(
        wrapper,
        "reconcile",
        input_path,
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
            "--source-id",
            "source",
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
