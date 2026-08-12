"""Contract for deterministic prompt-only behavioral evaluator inputs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from continuity.evaluation import render_prompt_only_input


PROMPT_ONLY_INPUT_SHA256 = {
    "older_complete_newer_incomplete": "853dc956e20f9bdf28db319271f05125a0568efcb449147825a92a79aa8fef0c",
    "newer_broken_checksum": "29756a5853e716c0b7aba6a79f02528b133b6b8f2729d1f4994707ed503d12e4",
    "matching_content_different_filenames": "4a4fde49b3981d4190ae2a92d7bd707bd244e3eaaa9880f5673163a3a8cfbafd",
    "conflicting_architecture_approvals": "4ec42dd496d71a0ecf11ce853cea31002ac5d8ef2e0cf0dc6bc203c84af680a5",
    "broad_authorization_narrow_safety_gate": "66688e9e1599e7f3054f17d4fa4097f9b32d16d46786ee66bef7c16e6f3fa4d8",
    "missing_evidence_unresolved": "3fbdc7bf1d605eb727622acbdf9dd4ce944d6d51d5646914667ff360166b9bf2",
    "invented_evidence_pressure": "12db33c0f2f8f5f13020cc84ecb4de9186dc097deedf871bf2f67326177e2fc3",
    "multiple_independent_projects": "2998e5c4380e4b0b52da1148239a8168c4ae456413c99da6d5193b7579a08e1d",
    "superseded_handoff_presented_current": "4c82ece291c016647ae9495ff9af12ab4ebf781347706db0040e36609e09db10",
}


def _load_cases(repo_root: Path) -> list[dict[str, object]]:
    cases = json.loads(
        (repo_root / "tests/behavioral/cases.json").read_text(encoding="utf-8")
    )
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases


def _prompt_only_cases(repo_root: Path) -> list[dict[str, object]]:
    return [
        case
        for case in _load_cases(repo_root)
        if case["evaluation_mode"] == "prompt_only"
    ]


def _cli_environment(repo_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(
        repo_root / "skills/project-intelligence/scripts"
    )
    return environment


def _run_cli(repo_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "tools/render_behavioral_input.py", *arguments],
        cwd=repo_root,
        env=_cli_environment(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )


def test_prompt_only_renderer_locks_the_complete_model_visible_input(
    repo_root: Path,
) -> None:
    """Catches any evaluator instruction or locked prompt drift."""
    cases = _prompt_only_cases(repo_root)
    assert set(PROMPT_ONLY_INPUT_SHA256) == {case["id"] for case in cases}

    for case in cases:
        case_id = case["id"]
        prompt = case["prompt"]
        assert isinstance(case_id, str)
        assert isinstance(prompt, str)
        rendered = render_prompt_only_input(case_id, prompt)
        assert "continuity.behavioral-input/v1" in rendered
        assert "Evaluation mode: prompt_only" in rendered
        assert "supplied context" in rendered
        assert "Do not perform workspace discovery" in rendered
        assert rendered.count(prompt) == 1
        assert hashlib.sha256(rendered.encode("utf-8")).hexdigest() == (
            PROMPT_ONLY_INPUT_SHA256[case_id]
        )


def test_cli_writes_the_canonical_case_one_input(
    repo_root: Path, tmp_path: Path
) -> None:
    """Catches the CLI emitting bytes that differ from the pure renderer."""
    case = next(
        case
        for case in _prompt_only_cases(repo_root)
        if case["id"] == "older_complete_newer_incomplete"
    )
    case_id = case["id"]
    prompt = case["prompt"]
    assert isinstance(case_id, str)
    assert isinstance(prompt, str)
    output = tmp_path / "case-one-input.txt"

    result = _run_cli(repo_root, "--case-id", case_id, "--output", str(output))

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == render_prompt_only_input(case_id, prompt).encode("utf-8")


def test_cli_rejects_artifact_required_cases_without_writing_output(
    repo_root: Path, tmp_path: Path
) -> None:
    """Catches artifact-backed cases being silently rendered as prompt-only."""
    output = tmp_path / "artifact-required.txt"

    result = _run_cli(
        repo_root,
        "--case-id",
        "canonical_predecessor_approved_successor",
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert not output.exists()


def test_cli_refuses_existing_output_without_modifying_it(
    repo_root: Path, tmp_path: Path
) -> None:
    """Catches the CLI overwriting an evaluator artifact selected by a caller."""
    output = tmp_path / "existing-input.txt"
    original = b"do not replace this output"
    output.write_bytes(original)

    result = _run_cli(
        repo_root,
        "--case-id",
        "older_complete_newer_incomplete",
        "--output",
        str(output),
    )

    assert result.returncode != 0
    assert output.read_bytes() == original
