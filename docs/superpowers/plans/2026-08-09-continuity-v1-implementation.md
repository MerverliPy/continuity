# Continuity v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and package Continuity v1 as a skills-first ChatGPT/Codex plugin that preserves source evidence, deterministically inspects and reconciles project state, creates approval-gated canonical handoffs, and blocks unsafe Superpowers execution.

**Architecture:** Five skills form the user-facing workflow. A standard-library Python package bundled under the entry skill supplies deterministic archive, hash, manifest, lineage, readiness, redaction, lifecycle, and CLI operations. Skills make semantic judgments only through cited structured records; scripts establish structural facts and enforce package gates. Candidate promotion creates a new canonical successor rather than mutating source evidence or the candidate.

**Tech Stack:** OpenAI plugin manifest and `SKILL.md` files; Python 3.11+ standard library at runtime; JSON Schema Draft 2020-12 contracts; pytest and jsonschema for tests; ZIP and SHA-256 portable artifacts.

## Global Constraints

- The approved design at `docs/superpowers/specs/2026-08-09-continuity-plugin-design.md` is authoritative.
- Runtime code must use only the Python standard library. `pytest` and `jsonschema` are test-only dependencies.
- Original evidence is never overwritten. Source inputs are read-only; test their SHA-256 before and after every successful and failed end-to-end workflow.
- Never infer semantic authority from timestamps alone. Timestamps are supporting evidence only.
- Never convert `Asserted`, `Unresolved`, `Contradicted`, or `Missing` to `Verified` without inspected supporting evidence.
- Material conflicts are never silently resolved; each requires an explicit, scoped approval record.
- Candidate promotion must produce a new package with a promotion receipt; it must not rewrite the candidate or predecessor.
- Normalize paths and ordering deterministically. Preserve observed source paths separately from normalized paths.
- Isolate volatile creation times from normalized findings so identical inputs yield equivalent normalized reports.
- A `Blocked` preflight must return a non-zero CLI status and must never recommend an implementation-stage Superpowers skill.
- No MCP server, OAuth flow, external mutation, cloud database, or required UI belongs in v1.
- Use `apply_patch` for hand edits. Do not add placeholder text, `TODO`, `FIXME`, `pass`, empty handlers, or mocked success paths.
- After every task, run the focused tests, then `python -m pytest -q`, then commit only that task's files.

---

## Target File Map

```text
continuity/
├── .codex-plugin/plugin.json
├── README.md
├── pyproject.toml
├── docs/
│   ├── evaluation.md
│   └── superpowers/
│       ├── specs/2026-08-09-continuity-plugin-design.md
│       └── plans/2026-08-09-continuity-v1-implementation.md
├── skills/
│   ├── project-intelligence/
│   │   ├── SKILL.md
│   │   ├── assets/
│   │   │   ├── schemas/
│   │   │   │   ├── evidence-index.schema.json
│   │   │   │   ├── lineage.schema.json
│   │   │   │   ├── manifest.schema.json
│   │   │   │   ├── reconciliation.schema.json
│   │   │   │   └── preflight.schema.json
│   │   │   └── templates/
│   │   │       ├── AUTHORITY_LEDGER.md
│   │   │       ├── CANONICAL_STATE.md
│   │   │       ├── CONFLICT_RESOLUTIONS.md
│   │   │       ├── HANDOFF_README.md
│   │   │       ├── NEXT_THREAD_PROMPT.txt
│   │   │       ├── SUPERPOWERS_PREFLIGHT.md
│   │   │       └── UNRESOLVED.md
│   │   ├── references/
│   │   │   ├── evidence-states.md
│   │   │   ├── package-contract.md
│   │   │   └── superpowers-handoff.md
│   │   └── scripts/
│   │       ├── continuity_cli.py
│   │       └── continuity/
│   │           ├── __init__.py
│   │           ├── archives.py
│   │           ├── cli.py
│   │           ├── hashing.py
│   │           ├── lineage.py
│   │           ├── manifests.py
│   │           ├── models.py
│   │           ├── packaging.py
│   │           ├── paths.py
│   │           ├── readiness.py
│   │           ├── reconciliation.py
│   │           └── redaction.py
│   ├── inspect-project-state/SKILL.md
│   ├── reconcile-project-state/SKILL.md
│   ├── create-canonical-handoff/SKILL.md
│   └── superpowers-preflight/SKILL.md
└── tests/
    ├── conftest.py
    ├── behavioral/
    │   ├── cases.json
    │   └── test_case_contract.py
    ├── contract/
    │   ├── test_plugin_layout.py
    │   ├── test_schemas.py
    │   └── test_skill_contracts.py
    ├── integration/test_end_to_end.py
    └── unit/
        ├── test_archives.py
        ├── test_hashing_manifests.py
        ├── test_lineage_reconciliation.py
        ├── test_packaging.py
        └── test_readiness_redaction.py
```

## Stable Public Interfaces

Implementation may add private helpers, but these public names and CLI verbs must remain stable throughout v1:

```python
# skills/project-intelligence/scripts/continuity/models.py
class EvidenceState(StrEnum):
    VERIFIED = "Verified"
    ASSERTED = "Asserted"
    UNRESOLVED = "Unresolved"
    CONTRADICTED = "Contradicted"
    MISSING = "Missing"

class PackageStatus(StrEnum):
    CANDIDATE = "Candidate"
    BLOCKED = "Blocked"
    CANONICAL = "Canonical"
    SUPERSEDED = "Superseded"

class ReadinessStatus(StrEnum):
    READY = "Ready"
    CONDITIONAL = "Conditional"
    BLOCKED = "Blocked"

@dataclass(frozen=True)
class ArtifactRecord:
    source_id: str
    observed_path: str
    normalized_path: str
    sha256: str
    size_bytes: int
    evidence_state: EvidenceState

@dataclass(frozen=True)
class ClaimRecord:
    claim_id: str
    field: str
    value: object
    source_id: str
    source_ref: str
    evidence_state: EvidenceState
    recorded_at: str | None = None

@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    action: str
    scope: tuple[str, ...]
    decision: str
    source_id: str
    source_ref: str
    approved_at: str

@dataclass(frozen=True)
class ConflictRecord:
    conflict_id: str
    field: str
    material: bool
    claim_ids: tuple[str, ...]
    resolution_approval_id: str | None

@dataclass(frozen=True)
class PreflightDecision:
    status: ReadinessStatus
    reasons: tuple[str, ...]
    conditions: tuple[str, ...]
    authorized_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    unresolved_actions: tuple[str, ...]
    exact_next_action: str | None
    companion_skill_or_stage: str | None
    evidence_references: tuple[str, ...]

@dataclass(frozen=True)
class PreflightRecord:
    project_id: str
    package_id: str
    status: ReadinessStatus
    reasons: tuple[str, ...]
    conditions: tuple[str, ...]
    authorized_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    unresolved_actions: tuple[str, ...]
    exact_next_action: str | None
    companion_skill_or_stage: str | None
    evidence_references: tuple[str, ...]
```

```python
# deterministic service functions
sha256_file(path: Path) -> str
inventory_tree(root: Path, source_id: str) -> tuple[ArtifactRecord, ...]
write_sha256s(root: Path, destination: Path) -> None
verify_sha256s(root: Path, checksum_file: Path) -> VerificationReport
inspect_zip(path: Path, policy: ArchivePolicy = ArchivePolicy()) -> ArchiveInspection
safe_extract_zip(path: Path, destination: Path, policy: ArchivePolicy = ArchivePolicy()) -> ArchiveInspection
build_manifest(root: Path, package_id: str, status: PackageStatus, lineage_roots: tuple[str, ...]) -> dict[str, object]
compare_manifests(left: Mapping[str, object], right: Mapping[str, object]) -> ManifestDiff
build_lineage(sources: Sequence[SourcePackage]) -> LineageGraph
reconcile_sources(claims: Sequence[ClaimRecord], approvals: Sequence[ApprovalRecord], integrity: Sequence[IntegrityFinding]) -> ReconciliationReport
classify_readiness(report: ReconciliationReport, requested_action: str) -> PreflightDecision
redact_text(text: str) -> RedactionResult
build_candidate(request: CandidateBuildRequest) -> CandidateResult
validate_package(root: Path) -> PackageValidation
promote_candidate(candidate: Path, output: Path, approval: ApprovalRecord, successor_created_at: str) -> PromotionResult
```

CLI contract:

```text
continuity_cli.py inspect INPUT --output REPORT.json
continuity_cli.py reconcile --claims CLAIMS.json --approvals APPROVALS.json --integrity INTEGRITY.json --output REPORT.json
continuity_cli.py build --request BUILD_REQUEST.json --output-dir DIR
continuity_cli.py validate PACKAGE_OR_ZIP --output REPORT.json
continuity_cli.py promote CANDIDATE --approval APPROVAL.json --created-at RFC3339 --output DIR
continuity_cli.py preflight --reconciliation REPORT.json --requested-action ACTION --output PREFLIGHT.json
```

Commands emit stable JSON to the requested output. Exit code `0` means the operation completed and its gate passed; `2` means a valid but blocked result; `1` means invalid input or an operational failure.

---

## Task 1: Establish the Plugin Contract and Skill Routing

**Files:**

- Create: `.codex-plugin/plugin.json`
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `skills/project-intelligence/SKILL.md`
- Create: `skills/inspect-project-state/SKILL.md`
- Create: `skills/reconcile-project-state/SKILL.md`
- Create: `skills/create-canonical-handoff/SKILL.md`
- Create: `skills/superpowers-preflight/SKILL.md`
- Create: `tests/conftest.py`
- Create: `tests/contract/test_plugin_layout.py`
- Create: `tests/contract/test_skill_contracts.py`

- [ ] **Step 1: Write failing plugin-layout and skill-routing tests.**

`tests/contract/test_plugin_layout.py` must assert the manifest has exactly the required v1 metadata and that every declared skill directory contains a non-empty `SKILL.md`:

```python
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
```

`test_skill_contracts.py` must parse each YAML frontmatter block and assert unique kebab-case `name`, non-empty third-person `description`, and required safety phrases: entry routing, read-only inspection, user-approved material conflicts, explicit promotion approval, and Blocked preflight behavior.

- [ ] **Step 2: Run the contract tests and confirm they fail.**

Run: `python -m pytest -q tests/contract/test_plugin_layout.py tests/contract/test_skill_contracts.py`

Expected: failure because the manifest and skill files do not exist.

- [ ] **Step 3: Add the exact manifest, test configuration, and five routing skills.**

Use this manifest:

```json
{
  "name": "continuity",
  "version": "1.0.0",
  "description": "Preservation-first project intelligence and canonical handoffs for long-running work.",
  "skills": "./skills/"
}
```

Configure Python 3.11+, runtime dependency list `[]`, test extras `pytest>=8,<9` and `jsonschema>=4,<5`, setuptools package discovery under `skills/project-intelligence/scripts`, and pytest `testpaths = ["tests"]`.

Each skill must contain complete trigger guidance, ordered workflow, output contract, stop conditions, and precise delegation to the other Continuity skills. The entry skill must choose a single project before routing. No skill may claim that another plugin is installed; `superpowers-preflight` must describe the companion handoff conditionally.

- [ ] **Step 4: Run the focused tests and the full suite.**

Run: `python -m pytest -q tests/contract/test_plugin_layout.py tests/contract/test_skill_contracts.py`

Expected: `5 passed` or more, depending on parameterization.

Run: `python -m pytest -q`

Expected: all collected tests pass.

- [ ] **Step 5: Commit the plugin contract.**

```bash
git add .codex-plugin/plugin.json pyproject.toml README.md skills tests/conftest.py tests/contract
git commit -m "feat: define Continuity plugin and skill contracts"
```

---

## Task 2: Implement Evidence Models, Hashing, and Manifests

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/__init__.py`
- Create: `skills/project-intelligence/scripts/continuity/models.py`
- Create: `skills/project-intelligence/scripts/continuity/paths.py`
- Create: `skills/project-intelligence/scripts/continuity/hashing.py`
- Create: `skills/project-intelligence/scripts/continuity/manifests.py`
- Create: `tests/unit/test_hashing_manifests.py`

- [ ] **Step 1: Write failing tests for evidence vocabulary and deterministic inventory.**

Cover these cases:

```python
def test_inventory_is_sorted_and_preserves_observed_path(tmp_path: Path) -> None:
    (tmp_path / "z.txt").write_text("last", encoding="utf-8")
    (tmp_path / "A folder").mkdir()
    (tmp_path / "A folder/a.txt").write_text("first", encoding="utf-8")
    records = inventory_tree(tmp_path, source_id="source-1")
    assert [r.normalized_path for r in records] == ["A folder/a.txt", "z.txt"]
    assert records[0].observed_path == "A folder/a.txt"
    assert all(r.evidence_state is EvidenceState.VERIFIED for r in records)

def test_checksum_file_is_excluded_from_its_own_inventory(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    write_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")
    lines = (tmp_path / "SHA256SUMS.txt").read_text().splitlines()
    assert lines == [f"{sha256_file(tmp_path / 'a.txt')}  a.txt"]
```

Also test invalid enum values, Unicode/path normalization behavior, checksum mismatch preserving expected and observed hashes, missing checksum as `Unresolved`, stable manifest file ordering, duplicate normalized paths, missing files, and unexpected files.

- [ ] **Step 2: Run the focused tests and confirm import failures.**

Run: `python -m pytest -q tests/unit/test_hashing_manifests.py`

Expected: collection fails because `continuity` modules do not exist.

- [ ] **Step 3: Implement immutable models and safe normalized paths.**

Add the stable public enums and dataclasses. In `paths.py`, reject NUL bytes, absolute paths, drive-prefixed paths, `..`, and empty normalized destinations. Convert backslashes to `/` for destination collision checks while preserving `observed_path` unchanged.

- [ ] **Step 4: Implement streaming SHA-256 and deterministic tree inventory.**

Read files in fixed-size chunks. Sort by normalized relative path. Do not follow symlinks. Return a structured `VerificationReport` whose findings include expected hash, observed hash, normalized path, and evidence state.

- [ ] **Step 5: Implement manifest build and comparison.**

`build_manifest` must emit:

```json
{
  "schema": "continuity.package/v1",
  "package_id": "...",
  "status": "Candidate",
  "lineage_roots": [],
  "files": [
    {"path": "CANONICAL_STATE.md", "sha256": "...", "size_bytes": 123}
  ]
}
```

Exclude both `MANIFEST.json` and `SHA256SUMS.txt` from the manifest `files` array to avoid recursive self-hashing. Include every other regular payload file. `SHA256SUMS.txt` separately records the actual byte digest of `MANIFEST.json` and every other regular file except itself. `compare_manifests` returns sorted `missing`, `unexpected`, and `changed` paths and must not collapse hash mismatches into missing files.

- [ ] **Step 6: Run focused and full tests.**

Run: `python -m pytest -q tests/unit/test_hashing_manifests.py`

Expected: all tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 7: Commit deterministic evidence primitives.**

```bash
git add skills/project-intelligence/scripts/continuity tests/unit/test_hashing_manifests.py
git commit -m "feat: add deterministic evidence inventory"
```

---

## Task 3: Reject Unsafe Archives Without Touching Sources

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/archives.py`
- Create: `tests/unit/test_archives.py`

- [ ] **Step 1: Write failing archive security tests.**

Create ZIPs in test code, not as opaque binary fixtures. Test rejection of:

- `../escape.txt` traversal;
- `/absolute.txt` and `C:/drive.txt`;
- backslash traversal;
- duplicate normalized destinations;
- case-fold collisions when policy enables portable paths;
- ZIP entries whose Unix mode marks them as symlinks;
- encrypted, corrupt, and truncated archives;
- per-file and total uncompressed limits;
- compression ratio above the default policy;
- an extraction destination containing a pre-existing file.

Test a normal archive and assert source ZIP SHA-256 is identical before and after inspection and extraction.

- [ ] **Step 2: Run the archive tests and confirm failure.**

Run: `python -m pytest -q tests/unit/test_archives.py`

Expected: import failure for `continuity.archives`.

- [ ] **Step 3: Implement the policy and inspection result.**

Use immutable dataclasses:

```python
@dataclass(frozen=True)
class ArchivePolicy:
    max_entries: int = 10_000
    max_file_size: int = 256 * 1024 * 1024
    max_total_size: int = 1024 * 1024 * 1024
    max_compression_ratio: float = 100.0
    portable_paths: bool = True

@dataclass(frozen=True)
class ArchiveInspection:
    safe: bool
    entries: tuple[ArchiveEntry, ...]
    violations: tuple[str, ...]
```

Inspect the central directory before writing any byte. Treat a zero compressed size with non-zero uncompressed size as an infinite ratio. Reject all violations as a set so the report is useful, but never partially extract.

- [ ] **Step 4: Implement atomic safe extraction.**

Extract to a sibling temporary directory created by `tempfile.mkdtemp`. Open destination files with exclusive creation, re-check the resolved parent remains inside the temporary root, stream-copy with byte limits, then atomically rename the complete root to the requested destination. Clean only the tool-created temporary directory on failure.

- [ ] **Step 5: Run focused and full tests.**

Run: `python -m pytest -q tests/unit/test_archives.py`

Expected: all archive tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 6: Commit archive defenses.**

```bash
git add skills/project-intelligence/scripts/continuity/archives.py tests/unit/test_archives.py
git commit -m "feat: add safe archive inspection and extraction"
```

---

## Task 4: Build Lineage and Reconcile Competing Project States

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/lineage.py`
- Create: `skills/project-intelligence/scripts/continuity/reconciliation.py`
- Create: `tests/unit/test_lineage_reconciliation.py`

- [ ] **Step 1: Write failing lineage tests.**

Test deterministic topological ordering, missing parents, multiple roots, cycles, duplicate package IDs with different root hashes, a valid canonical predecessor/successor, and a superseded package incorrectly selected as current.

The graph result must distinguish `valid`, `ambiguous`, and `invalid`; it must not silently pick a root when multiple unrelated projects are present.

- [ ] **Step 2: Write failing reconciliation tests for the approved behavioral rules.**

Include these exact scenarios:

```python
def test_newer_incomplete_source_does_not_override_complete_approved_source() -> None:
    report = reconcile_sources(
        claims=(older_verified_architecture, newer_asserted_architecture),
        approvals=(older_scoped_approval,),
        integrity=(older_integrity_pass, newer_missing_manifest),
    )
    assert report.selected_claim_ids == (older_verified_architecture.claim_id,)
    assert report.blocking_conflicts == ()
    assert "newer timestamp is not controlling authority" in report.notes

def test_material_architecture_conflict_requires_scoped_user_resolution() -> None:
    report = reconcile_sources(
        claims=(approved_monolith, asserted_microservices),
        approvals=(approve_monolith,),
        integrity=(both_integrity_pass,),
    )
    assert report.blocking_conflicts[0].material is True
    assert report.blocking_conflicts[0].resolution_approval_id is None
```

Also test matching content under different filenames, hash mismatch, broad urgency conflicting with a narrow safety prohibition, unresolved evidence remaining `Unresolved`, non-material formatting differences, and an explicit approval whose scope does not cover the disputed action.

- [ ] **Step 3: Run focused tests and confirm failure.**

Run: `python -m pytest -q tests/unit/test_lineage_reconciliation.py`

Expected: import failures for lineage and reconciliation modules.

- [ ] **Step 4: Implement lineage validation.**

Represent every source package with package ID, root SHA-256, status, parent IDs, declared current-root flag, and optional created time. Reject cycles and ID/hash identity collisions. Allow multiple roots only when the result is explicitly `ambiguous`; the caller must select one project before candidate creation.

- [ ] **Step 5: Implement evidence-based reconciliation.**

Use a fixed precedence of gates, not a numeric authority score:

1. Exclude structurally invalid evidence from automatic selection but retain it in findings.
2. Require a valid lineage relationship for successor claims.
3. Apply explicit approvals only to their exact action and scope.
4. Preserve uncontested verified facts with provenance.
5. Classify differences affecting architecture, behavior, scope, authority, safety, release readiness, or next action as material.
6. Require an approval that cites the conflict ID to resolve a material conflict.
7. Use timestamps only to order display when all controlling evidence is otherwise equivalent.

`ReconciliationReport.to_dict()` must sort claims, conflicts, findings, and approvals by stable IDs.

- [ ] **Step 6: Run focused and full tests.**

Run: `python -m pytest -q tests/unit/test_lineage_reconciliation.py`

Expected: all tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 7: Commit lineage and reconciliation.**

```bash
git add skills/project-intelligence/scripts/continuity/lineage.py skills/project-intelligence/scripts/continuity/reconciliation.py tests/unit/test_lineage_reconciliation.py
git commit -m "feat: reconcile project lineage and authority"
```

---

## Task 5: Calculate Readiness and Redact Likely Secrets

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/readiness.py`
- Create: `skills/project-intelligence/scripts/continuity/redaction.py`
- Create: `tests/unit/test_readiness_redaction.py`

- [ ] **Step 1: Write failing readiness table tests.**

Use parameterized cases for:

| Condition | Expected |
| --- | --- |
| Integrity passes, authority clear, no material conflict, action allowed | `Ready` |
| Unknown is documented and cannot affect requested action | `Conditional` |
| Hash mismatch | `Blocked` |
| Missing required manifest | `Blocked` |
| Material authority conflict | `Blocked` |
| Requested action exceeds approval | `Blocked` |
| Multiple selected projects | `Blocked` |
| Candidate not explicitly promoted | `Blocked` for implementation |

Assert every decision has sorted reasons, explicit authorized/prohibited/unresolved actions, cited evidence references, and one exact next action or `None`. A blocked decision must have no authorized actions, no exact next action, and `companion_skill_or_stage is None`.

- [ ] **Step 2: Write failing redaction tests.**

Test representative API keys, bearer tokens, private-key blocks, password assignments, and high-confidence connection strings. Assert output preserves enough context to identify the source location but never retains the secret. Also test ordinary hashes, UUIDs, package IDs, and checksum lines to prevent destructive over-redaction.

- [ ] **Step 3: Run focused tests and confirm failure.**

Run: `python -m pytest -q tests/unit/test_readiness_redaction.py`

Expected: import failures for readiness and redaction modules.

- [ ] **Step 4: Implement readiness as explicit gates.**

Do not use a confidence score. Evaluate integrity, project identity, authority, conflict, evidence, lifecycle, and requested-action gates separately. `Conditional` is legal only when each condition includes a machine-readable `does_not_affect_action: true` assertion plus a cited basis.

- [ ] **Step 5: Implement conservative report redaction.**

Return:

```python
@dataclass(frozen=True)
class RedactionFinding:
    kind: str
    start: int
    end: int
    replacement: str

@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: tuple[RedactionFinding, ...]
```

Redact reporting output before serialization. Exclude source files with secret findings from candidate packaging unless the build request carries an explicit secure-handling approval that names each path.

- [ ] **Step 6: Run focused and full tests.**

Run: `python -m pytest -q tests/unit/test_readiness_redaction.py`

Expected: all tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 7: Commit readiness and redaction gates.**

```bash
git add skills/project-intelligence/scripts/continuity/readiness.py skills/project-intelligence/scripts/continuity/redaction.py tests/unit/test_readiness_redaction.py
git commit -m "feat: enforce readiness and redaction gates"
```

---

## Task 6: Build, Validate, and Promote Portable Handoffs

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/packaging.py`
- Create: `tests/unit/test_packaging.py`

- [ ] **Step 1: Write failing package-contract tests.**

Create a complete request fixture in Python and assert candidate output contains exactly the required paths from the approved design, including non-empty Markdown/text artifacts, `lineage/LINEAGE.json`, `evidence/INDEX.json`, `canonical/`, `receipts/`, `MANIFEST.json`, and `SHA256SUMS.txt`.

Assert:

- source directory and input ZIP hashes are unchanged;
- every regular payload file except `MANIFEST.json` and `SHA256SUMS.txt` is in the manifest, while every regular file except `SHA256SUMS.txt` (including `MANIFEST.json`) is in the checksum inventory;
- ZIP entry metadata uses a fixed timestamp and sorted order for reproducibility;
- identical normalized requests produce byte-identical ZIPs when `created_at` is supplied;
- failed construction leaves no output directory or partial ZIP;
- unsafe canonical source paths are rejected;
- blocked reconciliation produces `Blocked`, never `Candidate` or `Canonical`;
- a candidate cannot be promoted without an approval for action `promote-candidate` scoped to its package ID;
- promotion creates a separate output, adds a receipt, regenerates manifest/checksums, and leaves the candidate byte-identical;
- promotion of an already canonical or superseded package fails.

- [ ] **Step 2: Run the package tests and confirm failure.**

Run: `python -m pytest -q tests/unit/test_packaging.py`

Expected: import failure for `continuity.packaging`.

- [ ] **Step 3: Implement candidate construction.**

`CandidateBuildRequest` must contain package ID, project ID, explicit `created_at`, selected source hashes, approved reconciliation report, canonical file mappings, a required identity-bound `preflight_decision: PreflightRecord`, supplemental document narrative, lineage data, evidence index, and secure-handling approvals. Supplemental narrative cannot satisfy or override structured claims, approvals, conflicts, unresolved records, or readiness fields.

Build in a tool-owned temporary outer release directory. Copy files into `package/` by streaming bytes without following symlinks. Render supplied structured content through fixed templates in Task 8; until those files exist, tests may supply template text directly through the request. Validate, generate the manifest and checksums, and write `<package_id>.zip` beside `package/`. Atomically rename the single outer release directory to its final path using no-clobber publication semantics. The ZIP contains the contents of `package/` at its archive root; the outer release directory is transport structure and is not inventoried.

- [ ] **Step 4: Implement validation and append-only promotion.**

Validation must independently recalculate every digest and compare the package contract. Promotion must:

1. validate the candidate;
2. verify status `Candidate` and readiness `Ready` or allowed `Conditional`;
3. verify scoped explicit approval;
4. copy to a new temporary root;
5. add `receipts/PROMOTION.json` with candidate hash and approval provenance;
6. set new status `Canonical`, a new package ID or approved successor ID, and the explicit deterministic `successor_created_at` in both manifest and lineage;
7. regenerate manifest and checksums;
8. validate again;
9. place the canonical `package/` directory and `<package_id>.zip` inside one temporary outer release directory, then atomically publish that outer directory with no-clobber semantics.

- [ ] **Step 5: Run focused and full tests.**

Run: `python -m pytest -q tests/unit/test_packaging.py`

Expected: all tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 6: Commit package lifecycle enforcement.**

```bash
git add skills/project-intelligence/scripts/continuity/packaging.py tests/unit/test_packaging.py
git commit -m "feat: build approval-gated canonical handoffs"
```

---

## Task 7: Expose Deterministic Operations Through the CLI

**Files:**

- Create: `skills/project-intelligence/scripts/continuity/cli.py`
- Create: `skills/project-intelligence/scripts/continuity_cli.py`
- Create: `tests/integration/test_end_to_end.py`

- [ ] **Step 1: Write failing CLI integration tests.**

Invoke the wrapper with `subprocess.run([sys.executable, wrapper, ...], check=False)`. Cover all six verbs and assert stable JSON, no tracebacks for user errors, exit codes `0/1/2`, and no writes outside explicit output paths.

The principal end-to-end test must:

1. create two handoffs where the newer one is incomplete;
2. hash both source trees;
3. inspect both;
4. reconcile claims and a scoped approval;
5. build and validate a candidate;
6. reject promotion with no approval;
7. promote with an exact approval;
8. validate the canonical ZIP;
9. assert both sources and the candidate are byte-identical to their initial states;
10. produce a `Ready` preflight with an exact authorized next action.

Add a second flow where architecture conflicts; expect exit `2`, `Blocked`, no candidate promotion, and no implementation-stage Superpowers recommendation.

- [ ] **Step 2: Run the integration tests and confirm failure.**

Run: `python -m pytest -q tests/integration/test_end_to_end.py`

Expected: failure because the CLI wrapper does not exist.

- [ ] **Step 3: Implement JSON parsing and serialization adapters.**

Reject unknown fields in security-sensitive records. Produce error JSON shaped as:

```json
{
  "ok": false,
  "error": {"code": "invalid_input", "message": "...", "details": []}
}
```

Do not expose local absolute paths or secret values in error messages. The wrapper should import `continuity.cli.main` from its sibling package and exit with its integer return value.

- [ ] **Step 4: Implement all CLI verbs and gate exit codes.**

Use `argparse` subcommands. Write output via a temporary sibling file followed by `os.replace`. `inspect` accepts a directory or ZIP. `validate` accepts an unpacked package or ZIP but must use safe extraction for ZIPs. `preflight` returns the exact schema-validated `continuity.preflight/v1` object with `schema`, project/package identity, status, reasons, conditions, authorized/prohibited/unresolved actions, exact next action, `companion_skill_or_stage`, and evidence references. It returns exit `2` for `Blocked` and `0` for `Ready` or `Conditional`.

- [ ] **Step 5: Run integration and full tests.**

Run: `python -m pytest -q tests/integration/test_end_to_end.py`

Expected: both Ready and Blocked flows pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 6: Commit the CLI workflow.**

```bash
git add skills/project-intelligence/scripts/continuity/cli.py skills/project-intelligence/scripts/continuity_cli.py tests/integration/test_end_to_end.py
git commit -m "feat: expose Continuity project-state workflow"
```

---

## Task 8: Add Versioned Schemas, Templates, and Skill Operating Rules

**Files:**

- Create: `skills/project-intelligence/assets/schemas/manifest.schema.json`
- Create: `skills/project-intelligence/assets/schemas/lineage.schema.json`
- Create: `skills/project-intelligence/assets/schemas/evidence-index.schema.json`
- Create: `skills/project-intelligence/assets/schemas/reconciliation.schema.json`
- Create: `skills/project-intelligence/assets/schemas/preflight.schema.json`
- Create: `skills/project-intelligence/assets/templates/HANDOFF_README.md`
- Create: `skills/project-intelligence/assets/templates/CANONICAL_STATE.md`
- Create: `skills/project-intelligence/assets/templates/AUTHORITY_LEDGER.md`
- Create: `skills/project-intelligence/assets/templates/CONFLICT_RESOLUTIONS.md`
- Create: `skills/project-intelligence/assets/templates/UNRESOLVED.md`
- Create: `skills/project-intelligence/assets/templates/NEXT_THREAD_PROMPT.txt`
- Create: `skills/project-intelligence/assets/templates/SUPERPOWERS_PREFLIGHT.md`
- Create: `skills/project-intelligence/references/evidence-states.md`
- Create: `skills/project-intelligence/references/package-contract.md`
- Create: `skills/project-intelligence/references/superpowers-handoff.md`
- Modify: all five `skills/*/SKILL.md`
- Modify: `skills/project-intelligence/scripts/continuity/packaging.py`
- Create: `tests/contract/test_schemas.py`
- Expand: `tests/contract/test_skill_contracts.py`

- [ ] **Step 1: Write failing schema and resource-resolution tests.**

Use `jsonschema.Draft202012Validator.check_schema`. Validate representative good and bad documents. Assert `additionalProperties: false` on identity, lifecycle, authority, and readiness objects. Assert every file path referenced by every `SKILL.md` resolves inside the plugin root.

Assert template sections include:

- evidence state beside every material claim;
- source references for approvals and conflict resolutions;
- allowed, prohibited, and unresolved actions in the authority ledger;
- readiness, exact next action, and companion skill/stage in Superpowers preflight;
- explicit `Candidate` warning in the handoff README before promotion.

- [ ] **Step 2: Run contract tests and confirm failure.**

Run: `python -m pytest -q tests/contract/test_schemas.py tests/contract/test_skill_contracts.py`

Expected: failures for missing schemas, templates, and references.

- [ ] **Step 3: Implement strict Draft 2020-12 schemas.**

Use `$id` values under `https://continuity.local/schemas/v1/`. Require schema ID `continuity.package/v1`, stable IDs, lifecycle status, provenance, and enumerated evidence/readiness states. Allow extensibility only through a named `extensions` object; do not permit undeclared top-level authority fields.

- [ ] **Step 4: Write complete templates and references.**

Templates must use explicit token syntax such as `{{ package_id }}` and the renderer must fail on missing or unused tokens. References must define:

- `Verified`, `Asserted`, `Unresolved`, `Contradicted`, and `Missing` with examples;
- the complete portable package contract and lifecycle;
- the companion boundary: Continuity supplies truth/readiness, Superpowers performs design/plan/build/test/review only after gates pass.

- [ ] **Step 5: Tighten all five skill workflows.**

The skills must instruct the agent to:

- quote or cite the inspected file path and record ID for material claims;
- use the CLI for hashes, archives, manifests, validation, and packaging;
- pause for exactly scoped user authority when material conflicts exist;
- keep source evidence read-only;
- ensure a candidate is never labeled canonical;
- never route a Blocked package into execution;
- load only the directly relevant reference files;
- produce a useful Continuity result even if Superpowers is absent.

- [ ] **Step 6: Connect package rendering to the bundled templates and validate schemas.**

Package construction must load assets relative to `packaging.py`, reject malformed, unbalanced, nested, unknown, missing, or unused template tokens, and render governing sections from the approved reconciliation report and exact `PreflightRecord`. User document text is supplemental narrative only. Before checksums and publication, validate every completed document for its required headings and one entry per governing record; independent package validation repeats those semantic checks and rejects stale lifecycle identity or contradictory authority.

- [ ] **Step 7: Run contract, unit, integration, and full tests.**

Run: `python -m pytest -q tests/contract tests/unit/test_packaging.py tests/integration/test_end_to_end.py`

Expected: all focused tests pass.

Run: `python -m pytest -q`

Expected: all tests pass.

- [ ] **Step 8: Commit schemas and skill resources.**

```bash
git add skills tests/contract tests/unit/test_packaging.py tests/integration/test_end_to_end.py
git commit -m "feat: add Continuity package schemas and resources"
```

---

## Task 9: Lock Behavioral Evaluations and Release Verification

**Files:**

- Create: `tests/behavioral/cases.json`
- Create: `tests/behavioral/test_case_contract.py`
- Create: `docs/evaluation.md`
- Modify: `README.md`

- [ ] **Step 1: Write the failing behavioral-case contract test.**

Require one case for every approved fixture:

1. older complete versus newer incomplete;
2. newer broken checksum;
3. matching content with different filenames;
4. conflicting architecture approvals;
5. broad chat authorization versus narrow safety gate;
6. missing evidence remains `Unresolved`;
7. invented-evidence pressure;
8. multiple independent projects;
9. canonical predecessor plus approved successor;
10. superseded handoff presented as current.

Each case must include `id`, `prompt`, `fixture`, `expected_skill`, `expected_status`, `required_assertions`, `forbidden_assertions`, and `requires_user_decision`. Forbid invented facts, timestamp-only authority, silent material resolution, false `Ready`, source mutation, and candidate-as-canonical wording.

- [ ] **Step 2: Run the behavioral contract and confirm failure.**

Run: `python -m pytest -q tests/behavioral/test_case_contract.py`

Expected: failure because `cases.json` does not exist.

- [ ] **Step 3: Add the ten executable evaluation cases.**

Make prompts realistic and self-contained. Keep expected assertions semantic, not exact prose, so future copy edits do not invalidate safety behavior. Document how to run deterministic tests locally and how to record host-level ChatGPT skill-trigger evaluations for each release.

- [ ] **Step 4: Complete README operator instructions.**

Document installation/package layout, supported inputs, the five workflows, CLI examples, candidate approval flow, readiness meanings, Superpowers companion behavior, security limits, and v1 non-goals. Include the official plugin references:

- `https://developers.openai.com/plugins`
- `https://developers.openai.com/plugins/build/plugins`
- `https://developers.openai.com/plugins/build/skills`
- `https://developers.openai.com/plugins/deploy/connect-chatgpt`

- [ ] **Step 5: Run release-blocking verification.**

Run:

```bash
python -m pytest -q
python -m compileall -q skills/project-intelligence/scripts
python skills/project-intelligence/scripts/continuity_cli.py --help
rg -n "TODO|FIXME|NotImplementedError|pass$|placeholder|lorem ipsum" . \
  -g '!docs/superpowers/plans/**' \
  -g '!docs/superpowers/specs/**' \
  -g '!.git/**'
git diff --check
git status --short
```

Expected:

- pytest exits `0` with all tests passing;
- compileall exits `0` with no output;
- CLI help lists `inspect`, `reconcile`, `build`, `validate`, `promote`, and `preflight`;
- placeholder scan returns no matches;
- `git diff --check` returns no output;
- status lists only the intended Task 9 files before commit.

- [ ] **Step 6: Manually verify specification coverage.**

Create a checklist mapping design sections 6–17 to at least one implementation file and test. Confirm all seven release-blocking invariants have direct automated coverage. Confirm function names and JSON property names match across code, schemas, templates, tests, and README.

- [ ] **Step 7: Commit release evaluation assets.**

```bash
git add README.md docs/evaluation.md tests/behavioral
git commit -m "test: lock Continuity v1 behavioral safety"
```

- [ ] **Step 8: Perform final clean-tree verification.**

Run:

```bash
python -m pytest -q
git diff --check HEAD~9..HEAD
git status --short --branch
```

Expected: all tests pass, no whitespace errors, and only `## main` (or the active feature branch) appears with no uncommitted files.

---

## Definition of Done

- All five skills have tested trigger and stop behavior.
- Every deterministic interface and CLI verb above is implemented without placeholders.
- All required package files validate against `continuity.package/v1`.
- Every source remains byte-identical across success, blocking, and failure tests.
- Unsafe archives are rejected before extraction.
- Material authority conflicts cannot be silently resolved.
- Candidate promotion requires exact scoped approval and creates a separate canonical successor.
- `Blocked` preflight cannot recommend or enter Superpowers execution.
- The ten behavioral cases contain no false-evidence or false-authority acceptance.
- Full tests, compile checks, resource checks, placeholder scan, and Git checks pass.

## Implementation Handoff

Execute this plan in order. The recommended workflow is `superpowers:subagent-driven-development` with one implementation task at a time and review after each task. If implementation remains in this conversation, use `superpowers:executing-plans`, preserve the approved spec and this plan as immutable governing inputs, and stop immediately if a discovered requirement would change the architecture or authority model.
