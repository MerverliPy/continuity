import json
import os
from pathlib import Path
from shutil import copytree, ignore_patterns
import subprocess
import sys
import tomllib


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


def test_packaging_configuration_installs_the_bundled_continuity_package(
    repo_root: Path, tmp_path: Path
) -> None:
    configuration = tomllib.loads((repo_root / "pyproject.toml").read_text())
    scripts_root = "skills/project-intelligence/scripts"
    assert configuration["tool"]["setuptools"]["packages"]["find"] == {
        "where": [scripts_root],
        "include": ["continuity*"],
    }
    package_init = repo_root / scripts_root / "continuity/__init__.py"
    assert package_init.read_text().strip()

    source_copy = tmp_path / "source"
    copytree(
        repo_root,
        source_copy,
        ignore=ignore_patterns(".git", ".pytest_cache", "__pycache__", "*.egg-info", "build"),
    )

    installation = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(tmp_path),
            ".",
        ],
        cwd=source_copy,
        capture_output=True,
        env={**os.environ, "PIP_CACHE_DIR": str(tmp_path / "pip-cache")},
        text=True,
        check=False,
    )

    assert installation.returncode == 0, installation.stderr
    assert (tmp_path / "continuity/__init__.py").is_file()
