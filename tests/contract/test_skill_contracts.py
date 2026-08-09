import re
from pathlib import Path

import pytest


SKILLS = {
    "project-intelligence": "Select exactly one project before routing.",
    "inspect-project-state": "directly inspected supporting evidence and passing relevant integrity checks",
    "reconcile-project-state": "User-approved resolution for every material conflict",
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
RESOURCE_PATH = re.compile(
    r"`((?:skills/project-intelligence/(?:assets|references)/)[^`]+)`"
)
REQUIRED_REFERENCES = {
    "skills/project-intelligence/references/evidence-states.md",
    "skills/project-intelligence/references/package-contract.md",
    "skills/project-intelligence/references/superpowers-handoff.md",
}


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


def test_every_skill_resource_reference_resolves_inside_plugin_root(
    repo_root: Path,
) -> None:
    """Catches a workflow sending an agent to a missing or external resource."""
    referenced: set[str] = set()
    plugin_root = repo_root.resolve()
    for skill in SKILLS:
        document = (repo_root / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
        referenced.update(RESOURCE_PATH.findall(document))

    assert REQUIRED_REFERENCES <= referenced
    for relative in referenced:
        resolved = (repo_root / relative).resolve()
        assert resolved.is_relative_to(plugin_root)
        assert resolved.is_file(), relative


@pytest.mark.parametrize("skill", SKILLS)
def test_skill_workflow_preserves_operating_boundaries(
    repo_root: Path, skill: str
) -> None:
    """Catches a skill bypassing deterministic or preservation-first operations."""
    document = (repo_root / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")

    assert "inspected file path" in document
    assert "record ID" in document
    assert "Continuity CLI" in document
    assert "read-only" in document
    assert "exactly scoped user authority" in document
    assert "Candidate" in document and "Canonical" in document
    assert "Blocked" in document and "execution" in document
    assert "directly relevant reference" in document
    assert "Superpowers is absent" in document


def test_bundled_templates_expose_evidence_authority_and_readiness_fields(
    repo_root: Path,
) -> None:
    """Catches a generated handoff that cannot preserve claim or gate provenance."""
    templates = repo_root / "skills/project-intelligence/assets/templates"
    handoff = (templates / "HANDOFF_README.md").read_text(encoding="utf-8")
    canonical = (templates / "CANONICAL_STATE.md").read_text(encoding="utf-8")
    authority = (templates / "AUTHORITY_LEDGER.md").read_text(encoding="utf-8")
    resolutions = (templates / "CONFLICT_RESOLUTIONS.md").read_text(encoding="utf-8")
    unresolved = (templates / "UNRESOLVED.md").read_text(encoding="utf-8")
    preflight = (templates / "SUPERPOWERS_PREFLIGHT.md").read_text(encoding="utf-8")

    assert "Candidate is not Canonical" in handoff
    assert handoff.index("Candidate is not Canonical") < handoff.index("Promotion")
    for material_template in (canonical, authority, resolutions, unresolved, preflight):
        assert "Evidence state" in material_template
    assert "Source reference" in authority
    assert "Source reference" in resolutions
    for heading in ("## Allowed actions", "## Prohibited actions", "## Unresolved actions"):
        assert heading in authority
    for field in ("Readiness", "Exact next action", "Companion skill or stage"):
        assert field in preflight

    for path in templates.iterdir():
        if path.is_file():
            assert re.search(r"{{\s*[a-z][a-z0-9_]*\s*}}", path.read_text(encoding="utf-8"))
