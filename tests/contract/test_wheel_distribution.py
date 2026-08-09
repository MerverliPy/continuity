from __future__ import annotations

import json
import os
from pathlib import Path
from shutil import copytree, ignore_patterns
import subprocess
import sys
import venv
import zipfile


RESOURCE_FILES = {
    "schemas": {
        "document-inputs.schema.json",
        "evidence-index.schema.json",
        "lineage.schema.json",
        "manifest.schema.json",
        "preflight.schema.json",
        "reconciliation.schema.json",
    },
    "templates": {
        "AUTHORITY_LEDGER.md",
        "CANONICAL_STATE.md",
        "CONFLICT_RESOLUTIONS.md",
        "HANDOFF_README.md",
        "NEXT_THREAD_PROMPT.txt",
        "SUPERPOWERS_PREFLIGHT.md",
        "UNRESOLVED.md",
    },
}


def _plugin_assets(repo_root: Path) -> Path:
    return repo_root / "skills/project-intelligence/assets"


def _package_assets(repo_root: Path) -> Path:
    return repo_root / "skills/project-intelligence/scripts/continuity/assets"


def _relative_files(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}


def _build_python() -> str:
    return getattr(sys, "_base_executable", sys.executable)


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, env=env)


def _clean_python(venv_root: Path) -> Path:
    return venv_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _clean_console(venv_root: Path) -> Path:
    return venv_root / ("Scripts/continuity.exe" if os.name == "nt" else "bin/continuity")


def _preflight_report() -> dict[str, object]:
    digest = "a" * 64
    return {
        "claims": [
            {
                "claim_id": "project",
                "field": "project id",
                "value": "smoke",
                "source_id": "source",
                "source_ref": "source/project.json",
                "evidence_state": "Verified",
                "recorded_at": "2026-08-09T10:00:00Z",
            },
            {
                "claim_id": "lifecycle",
                "field": "package status",
                "value": "Canonical",
                "source_id": "source",
                "source_ref": "source/project.json",
                "evidence_state": "Verified",
                "recorded_at": "2026-08-09T10:00:00Z",
            },
            {
                "claim_id": "action",
                "field": "authorized action",
                "value": "implementation",
                "source_id": "source",
                "source_ref": "source/authority.json",
                "evidence_state": "Verified",
                "recorded_at": "2026-08-09T10:00:00Z",
            },
        ],
        "conflicts": [],
        "findings": [
            {
                "finding_id": "integrity-source",
                "source_id": "source",
                "source_ref": "source/SHA256SUMS.txt#integrity-source",
                "evidence_state": "Verified",
                "detail": "checksum and lineage verified",
                "structurally_valid": True,
                "lineage_valid": True,
                "lineage_required": True,
                "expected_sha256": digest,
                "observed_sha256": digest,
            }
        ],
        "approvals": [
            {
                "approval_id": "implementation",
                "action": "authorize-actions",
                "scope": ["implementation"],
                "decision": "approved",
                "source_id": "user",
                "source_ref": "conversation://smoke/approval",
                "approved_at": "2026-08-09T11:00:00Z",
            }
        ],
        "selected_claim_ids": ["project", "lifecycle", "action"],
        "blocking_conflict_ids": [],
        "notes": [],
    }


def test_plugin_assets_match_importable_runtime_assets(repo_root: Path) -> None:
    plugin_assets = _plugin_assets(repo_root)
    package_assets = _package_assets(repo_root)
    expected = {
        f"{directory}/{filename}"
        for directory, filenames in RESOURCE_FILES.items()
        for filename in filenames
    }
    assert _relative_files(plugin_assets) == expected
    assert _relative_files(package_assets) == expected
    for relative_path in expected:
        assert (package_assets / relative_path).read_bytes() == (
            plugin_assets / relative_path
        ).read_bytes()


def test_wheel_installs_resources_and_console_without_repository_paths(
    repo_root: Path, tmp_path: Path
) -> None:
    source_copy = tmp_path / "source"
    copytree(
        repo_root,
        source_copy,
        ignore=ignore_patterns(".git", ".pytest_cache", "__pycache__", "*.egg-info", "build", "dist"),
    )
    environment = {
        **os.environ,
        "PIP_CACHE_DIR": str(tmp_path / "pip-cache"),
        "PIP_NO_INDEX": "1",
        "PYTHONPATH": "",
    }
    wheel_directory = tmp_path / "wheel"
    wheel_build = _run(
        [
            _build_python(),
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "--no-index",
            "--wheel-dir",
            str(wheel_directory),
            ".",
        ],
        cwd=source_copy,
        env=environment,
    )
    assert wheel_build.returncode == 0, wheel_build.stderr
    wheel_path = next(wheel_directory.glob("continuity-*.whl"))
    expected_resources = {
        f"continuity/assets/{directory}/{filename}"
        for directory, filenames in RESOURCE_FILES.items()
        for filename in filenames
    }
    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_entries = set(wheel.namelist())
    assert {entry for entry in wheel_entries if entry.startswith("continuity/assets/")} == expected_resources
    assert "continuity/cli.py" in wheel_entries

    venv_root = tmp_path / "clean-venv"
    venv.EnvBuilder(with_pip=True).create(venv_root)
    clean_python = _clean_python(venv_root)
    wheel_install = _run(
        [
            str(clean_python),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-index",
            str(wheel_path),
        ],
        cwd=tmp_path,
        env=environment,
    )
    assert wheel_install.returncode == 0, wheel_install.stderr

    console = _clean_console(venv_root)
    help_result = _run([str(console), "--help"], cwd=tmp_path, env=environment)
    assert help_result.returncode == 0, help_result.stderr
    assert all(verb in help_result.stdout for verb in ("inspect", "reconcile", "build", "validate", "promote", "preflight"))

    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_preflight_report()), encoding="utf-8")
    preflight_path = tmp_path / "preflight.json"
    preflight = _run(
        [
            str(console),
            "preflight",
            "--reconciliation",
            str(report_path),
            "--project-id",
            "smoke",
            "--package-id",
            "smoke-candidate",
            "--requested-action",
            "implementation",
            "--output",
            str(preflight_path),
        ],
        cwd=tmp_path,
        env=environment,
    )
    assert preflight.returncode == 0, preflight.stderr
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "app.txt"
    source.write_text("preserved source\n", encoding="utf-8")
    build_request = {
        "package_id": "smoke-candidate",
        "project_id": "smoke",
        "created_at": "2026-08-09T12:00:00Z",
        "selected_source_hashes": {"source": "a" * 64},
        "reconciliation_report": _preflight_report(),
        "canonical_files": {"app.txt": str(source)},
        "rendered_documents": {
            name: "Supplemental narrative.\n"
            for name in (
                "HANDOFF_README.md",
                "CANONICAL_STATE.md",
                "AUTHORITY_LEDGER.md",
                "CONFLICT_RESOLUTIONS.md",
                "UNRESOLVED.md",
                "NEXT_THREAD_PROMPT.txt",
                "SUPERPOWERS_PREFLIGHT.md",
            )
        },
        "preflight_decision": json.loads(preflight_path.read_text(encoding="utf-8")),
        "lineage_data": {
            "schema": "continuity.lineage/v1",
            "package_id": "smoke-candidate",
            "project_id": "smoke",
            "created_at": "2026-08-09T12:00:00Z",
            "status": "Candidate",
            "readiness": "Ready",
            "parent_ids": [],
            "root_package_ids": [],
            "source_hashes": {"source": "a" * 64},
        },
        "evidence_index": {
            "schema": "continuity.evidence-index/v1",
            "items": [
                {
                    "source_id": "source",
                    "state": "Verified",
                    "reference": "external-by-sha256",
                }
            ],
        },
        "secure_handling_approvals": [],
        "readiness": "Ready",
        "allow_conditional_promotion": False,
    }
    request_path = tmp_path / "build.json"
    request_path.write_text(json.dumps(build_request), encoding="utf-8")
    release = tmp_path / "release"
    build = _run(
        [str(console), "build", "--request", str(request_path), "--output-dir", str(release)],
        cwd=tmp_path,
        env=environment,
    )
    assert build.returncode == 0, build.stderr
    validation_path = tmp_path / "validation.json"
    validation = _run(
        [
            str(console),
            "validate",
            str(release / "package"),
            "--output",
            str(validation_path),
        ],
        cwd=tmp_path,
        env=environment,
    )
    assert validation.returncode == 0, validation.stderr
    assert json.loads(validation_path.read_text(encoding="utf-8"))["validation"]["valid"] is True
