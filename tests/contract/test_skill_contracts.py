import re
from pathlib import Path

import pytest


SKILLS = {
    "project-intelligence": "Select exactly one project before routing.",
    "inspect-project-state": "Read-only inspection",
    "reconcile-project-state": "User-approved material conflict resolution",
    "create-canonical-handoff": "Explicit promotion approval",
    "superpowers-preflight": "Blocked preflight",
}
REQUIRED_SECTIONS = (
    "## Trigger guidance",
    "## Ordered workflow",
    "## Output contract",
    "## Stop conditions",
    "## Delegation",
)


def parse_frontmatter(path: Path) -> dict[str, str]:
    document = path.read_text()
    assert document.startswith("---\n")
    _, frontmatter, _ = document.split("---\n", 2)
    fields = {}
    for line in frontmatter.splitlines():
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip('"')
    return fields


def test_skill_frontmatter_has_unique_kebab_case_names_and_third_person_descriptions(
    repo_root: Path,
) -> None:
    frontmatters = [
        parse_frontmatter(repo_root / "skills" / skill / "SKILL.md") for skill in SKILLS
    ]
    names = [frontmatter["name"] for frontmatter in frontmatters]
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"[a-z]+(?:-[a-z]+)*", name) for name in names)
    descriptions = [frontmatter["description"] for frontmatter in frontmatters]
    assert all(description and description.split(maxsplit=1)[0].endswith("s") for description in descriptions)


@pytest.mark.parametrize(("skill", "safety_phrase"), SKILLS.items())
def test_skill_states_its_required_safety_boundary(
    repo_root: Path, skill: str, safety_phrase: str
) -> None:
    document = (repo_root / "skills" / skill / "SKILL.md").read_text()
    assert safety_phrase in document


@pytest.mark.parametrize("skill", SKILLS)
def test_skill_documents_its_routing_contract(repo_root: Path, skill: str) -> None:
    document = (repo_root / "skills" / skill / "SKILL.md").read_text()
    for section in REQUIRED_SECTIONS:
        assert section in document
