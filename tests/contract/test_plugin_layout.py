import json
from pathlib import Path


def test_plugin_manifest_declares_skills_only(repo_root: Path) -> None:
    manifest = json.loads((repo_root / ".codex-plugin/plugin.json").read_text())
    assert manifest == {
        "name": "continuity",
        "version": "1.0.0",
        "description": "Preservation-first project intelligence and canonical handoffs for long-running work.",
        "skills": "./skills/",
    }
    assert "mcpServers" not in manifest


def test_five_skill_files_exist(repo_root: Path) -> None:
    expected = {
        "project-intelligence",
        "inspect-project-state",
        "reconcile-project-state",
        "create-canonical-handoff",
        "superpowers-preflight",
    }
    actual = {path.parent.name for path in (repo_root / "skills").glob("*/SKILL.md")}
    assert actual == expected


def test_each_skill_file_is_non_empty(repo_root: Path) -> None:
    expected = {
        "project-intelligence",
        "inspect-project-state",
        "reconcile-project-state",
        "create-canonical-handoff",
        "superpowers-preflight",
    }
    paths = list((repo_root / "skills").glob("*/SKILL.md"))
    assert {path.parent.name for path in paths} == expected
    for path in paths:
        assert path.read_text().strip()
