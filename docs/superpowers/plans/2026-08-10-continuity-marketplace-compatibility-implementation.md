# Continuity Marketplace Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Make the existing Continuity plugin discoverable from its repository root by the Codex local-marketplace command used on CALVINPC.

**Architecture:** Add one catalog at \`.agents/plugins/marketplace.json\`. Its only entry points at the repository root with \`./\`, reusing \`.codex-plugin/plugin.json\` and \`skills/\` rather than creating a second plugin copy. The marketplace title uses the current \`interface.displayName\` contract. A contract test prevents policy, identity, or source-path drift; documentation distinguishes marketplace registration from host installation and evaluation.

**Tech Stack:** JSON marketplace manifest; Python 3.11+ pytest contract suite; Markdown; Codex CLI local marketplace registration.

## Global Constraints

- The design at \`docs/superpowers/specs/2026-08-10-continuity-marketplace-compatibility-design.md\` is authoritative.
- The existing \`.codex-plugin/plugin.json\` remains the only plugin manifest and must not change.
- The catalog contains exactly one plugin entry named \`continuity\`; a copied plugin source tree is forbidden.
- The entry must use local \`./\`, \`AVAILABLE\`, \`ON_INSTALL\`, and \`Productivity\` exactly.
- Do not add MCP, OAuth, UI, public submission, runtime code, or dependencies.
- Preserve the earlier failed registration receipt. New host evaluation is not passed until Continuity is installed in an eligible host and all required-mode cases run.
- Before handoff, run focused tests, full pytest, compilation, hygiene, whitespace, and status checks.

---

## Target File Map

\`\`\`text
continuity/
├── .agents/plugins/marketplace.json             # One-plugin local catalog
├── README.md                                    # Registration and host-install instructions
├── docs/evaluation.md                           # Host-evaluation prerequisite
├── docs/superpowers/plans/2026-08-10-continuity-marketplace-compatibility-implementation.md
└── tests/contract/test_plugin_layout.py         # Catalog contract and documentation checks
\`\`\`

## Marketplace Interface Contract

\`.agents/plugins/marketplace.json\` must parse as:

\`\`\`json
{
  "name": "continuity-local",
  "interface": {"displayName": "Continuity Local"},
  "plugins": [
    {
      "name": "continuity",
      "source": {"source": "local", "path": "./"},
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL"
      },
      "category": "Productivity"
    }
  ]
}
\`\`\`

The contract test resolves \`repo_root / "./"\`, requires that it is the repository root, requires the existing plugin manifest there, and requires that manifest's name to be \`continuity\`.

---

### Task 1: Lock the repository-local marketplace contract

**Files:**

- Create: \`.agents/plugins/marketplace.json\`
- Modify: \`tests/contract/test_plugin_layout.py\`

**Interfaces:**

- Consumes: pytest \`repo_root: Path\` fixture and existing \`.codex-plugin/plugin.json\`.
- Produces: catalog accepted by \`codex plugin marketplace add <repository-root>\`.

- [ ] **Step 1: Write the failing test.**

Add this test after \`test_plugin_manifest_declares_skills_only\`:

\`\`\`python
def test_local_marketplace_reuses_the_existing_continuity_plugin(
    repo_root: Path,
) -> None:
    marketplace_path = repo_root / ".agents/plugins/marketplace.json"
    marketplace = json.loads(marketplace_path.read_text())
    assert marketplace == {
        "name": "continuity-local",
        "interface": {"displayName": "Continuity Local"},
        "plugins": [
            {
                "name": "continuity",
                "source": {"source": "local", "path": "./"},
                "policy": {
                    "installation": "AVAILABLE",
                    "authentication": "ON_INSTALL",
                },
                "category": "Productivity",
            }
        ],
    }
    source_path = marketplace["plugins"][0]["source"]["path"]
    assert source_path.startswith("./")
    resolved_source = (repo_root / source_path).resolve()
    assert resolved_source == repo_root.resolve()
    plugin_manifest = json.loads(
        (resolved_source / ".codex-plugin/plugin.json").read_text()
    )
    assert plugin_manifest["name"] == "continuity"
\`\`\`

- [ ] **Step 2: Run test to verify it fails.**

Run:

\`\`\`bash
.venv/bin/python -m pytest -q tests/contract/test_plugin_layout.py::test_local_marketplace_reuses_the_existing_continuity_plugin
\`\`\`

Expected: FAIL with \`FileNotFoundError\`, because the catalog is absent.

- [ ] **Step 3: Add the minimal catalog.**

Create \`.agents/plugins/marketplace.json\` with exactly the object in **Marketplace Interface Contract**. Do not create a second plugin manifest or plugin directory.

- [ ] **Step 4: Run focused verification.**

Run:

\`\`\`bash
.venv/bin/python -m pytest -q tests/contract/test_plugin_layout.py
\`\`\`

Expected: PASS.

- [ ] **Step 5: Commit Task 1.**

\`\`\`bash
git add .agents/plugins/marketplace.json tests/contract/test_plugin_layout.py
git commit -m "feat: add local Continuity marketplace"
\`\`\`

### Task 2: Document the supported local registration and host boundary

**Files:**

- Modify: \`README.md\`
- Modify: \`docs/evaluation.md\`
- Modify: \`tests/contract/test_plugin_layout.py\`

**Interfaces:**

- Consumes: Task 1 catalog and observed CALVINPC command: \`codex plugin marketplace add <SOURCE>\`.
- Produces: copy/paste instructions that name registration a prerequisite, not proof of routing or host evaluation.

- [ ] **Step 1: Write the failing documentation test.**

Add this test:

\`\`\`python
def test_documentation_separates_marketplace_registration_from_host_evaluation(
    repo_root: Path,
) -> None:
    readme = (repo_root / "README.md").read_text()
    evaluation = (repo_root / "docs/evaluation.md").read_text()
    assert "codex plugin marketplace add ." in readme
    assert "Plugins Directory" in readme
    assert "does not prove skill routing" in readme
    assert "marketplace registration" in evaluation
    assert "not run" in evaluation
\`\`\`

- [ ] **Step 2: Run test to verify it fails.**

Run:

\`\`\`bash
.venv/bin/python -m pytest -q tests/contract/test_plugin_layout.py::test_documentation_separates_marketplace_registration_from_host_evaluation
\`\`\`

Expected: FAIL because the required wording is absent.

- [ ] **Step 3: Update README.**

After the opening overview, add \`## Local marketplace registration\` with:

\`\`\`bash
cd /path/to/continuity-v1
codex plugin marketplace add .
\`\`\`

State that exit code \`0\` records the local marketplace source only. State that the evaluator must open an eligible ChatGPT desktop/work surface, locate **Continuity Local** in the **Plugins Directory**, install it, and record plugin version and Git commit before host cases. Include exactly: \`Codex marketplace registration does not prove skill routing or host-level evaluation.\`

- [ ] **Step 4: Update the evaluation prerequisite.**

At the beginning of \`## Host-level ChatGPT evaluator method\` in \`docs/evaluation.md\`, require recorded successful marketplace registration for the exact checkout and an installed **Continuity Local** plugin. State that a failed registration, unavailable Plugins Directory, or host without access to the marketplace makes the suite incomplete and the affected case \`not run\`, not passed.

- [ ] **Step 5: Run focused verification.**

Run:

\`\`\`bash
.venv/bin/python -m pytest -q tests/contract/test_plugin_layout.py
\`\`\`

Expected: PASS.

- [ ] **Step 6: Commit Task 2.**

\`\`\`bash
git add README.md docs/evaluation.md tests/contract/test_plugin_layout.py
git commit -m "docs: explain Continuity marketplace testing"
\`\`\`

### Task 3: Verify and package the release

**Files:**

- Create: transfer ZIP and SHA-256 sidecar under \`../deliverables/\`, outside the worktree.
- Modify: none in the repository.

**Interfaces:**

- Consumes: Tasks 1–2 and all deterministic tests.
- Produces: a verified transfer artifact and one CALVINPC acceptance command with observable exit code.

- [ ] **Step 1: Run final deterministic checks.**

Run:

\`\`\`bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q skills/project-intelligence/scripts
rg -n "TO""DO|FIX""ME|NotImplemented""Error|pass$|place""holder|lorem"" ipsum" . \
  -g '!docs/superpowers/plans/**' \
  -g '!docs/superpowers/specs/**' \
  -g '!.git/**'
git diff --check
git status --short
\`\`\`

Expected: pytest exits \`0\`; all remaining commands emit no output.

- [ ] **Step 2: Build the transfer handoff.**

From the parent directory, create a ZIP that excludes \`.git\`, \`.venv\`, \`__pycache__\`, \`.pytest_cache\`, build directories, and local wheel metadata. Name it \`CONTINUITY_V1_MARKETPLACE_READY_<short-commit>_<UTC timestamp>.zip\`, write its SHA-256 to a same-named \`.sha256\` file, and include a release note with commit, full-suite result, catalog path, and acceptance command.

- [ ] **Step 3: Run CALVINPC marketplace acceptance.**

After extracting the replacement handoff into a new directory:

\`\`\`bash
EVAL_ROOT="$HOME/continuity-host-evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVAL_ROOT"
cd "$HOME/continuity-evaluation/continuity-v1"
set -o pipefail
codex plugin marketplace add . 2>&1 | tee "$EVAL_ROOT/continuity-marketplace-add.txt"
printf 'ADD_EXIT_CODE=%s\n' "${PIPESTATUS[0]}" \
  | tee "$EVAL_ROOT/continuity-marketplace-add-exit-code.txt"
\`\`\`

Expected: \`ADD_EXIT_CODE=0\`. Preserve both the earlier failed receipt and new result. If nonzero, stop and do not claim host evaluation passed.

- [ ] **Step 4: Run host tests only on a capable host.**

Install **Continuity Local** from the **Plugins Directory** in an eligible ChatGPT desktop/work surface. Record version, commit, host surface, model, UTC time, and evaluator. Run the ten versioned cases in \`docs/evaluation.md\`; mark an artifact-required case \`not run\` when real staged artifacts and workspace tools are unavailable.

- [ ] **Step 5: Keep generated evidence out of Git.**

Do not commit host evidence, ZIPs, SHA files, virtual environments, or generated caches. Confirm status is clean after packaging.

## Plan Self-Review

### Spec coverage

- Exact catalog identity, source, policies, and category: Task 1.
- Root-plugin reuse without duplication: Task 1.
- Registration versus host installation/evaluation: Task 2.
- Evidence capture and fail-closed host acceptance: Task 3.
- No MCP, OAuth, UI, public submission, runtime changes, or dependencies: Global Constraints and Tasks 1–2.

### Placeholder scan

Every task gives exact files, test code, commands, expected results, and catalog content. No incomplete implementation instructions appear.

### Interface consistency

Tasks use the same catalog name (\`continuity-local\`), display name (\`Continuity Local\`), plugin name (\`continuity\`), source (\`./\`), and policies.

## Execution Handoff

Plan complete and saved to \`docs/superpowers/plans/2026-08-10-continuity-marketplace-compatibility-implementation.md\`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks.
2. **Inline Execution** — execute the tasks in this session using \`superpowers:executing-plans\`, with checkpoints for review.
