# Continuity

Continuity is a skills-first ChatGPT and Codex plugin for preservation-first project intelligence and canonical handoffs. It inventories supplied evidence, reconciles competing project states, creates approval-gated portable handoffs, and produces a fail-closed readiness brief before companion work begins.

Version 1 operates on files available in the active workspace. Original evidence stays read-only, timestamps never establish authority by themselves, and no unsupported claim is upgraded to verified fact.

## Install and package layout

Keep the repository layout intact when installing or packaging the plugin. `.codex-plugin/plugin.json` declares the plugin and `skills/` contains the five skill entry points. The deterministic Python package, schemas, templates, and operator references are bundled under `skills/project-intelligence/` so they resolve after installation.

```text
.codex-plugin/plugin.json
skills/
  project-intelligence/
    SKILL.md
    assets/{schemas,templates}/
    references/
    scripts/continuity_cli.py
    scripts/continuity/
  inspect-project-state/SKILL.md
  reconcile-project-state/SKILL.md
  create-canonical-handoff/SKILL.md
  superpowers-preflight/SKILL.md
```

Use the official OpenAI plugin flow for the host where Continuity will run:

- [Plugins overview](https://developers.openai.com/plugins)
- [Build plugins](https://developers.openai.com/plugins/build/plugins)
- [Build skills](https://developers.openai.com/plugins/build/skills)
- [Connect from ChatGPT](https://developers.openai.com/plugins/deploy/connect-chatgpt)

The runtime package supports Python 3.11 or newer and uses only the standard library. From a checkout, invoke the bundled CLI directly:

```bash
python skills/project-intelligence/scripts/continuity_cli.py --help
```

For development tests, install the test-only dependencies in an isolated environment:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
```

## Supported inputs

Continuity accepts workspace project directories, repository snapshots, Continuity handoff directories or ZIP archives, manifests and checksum inventories, structured claim/integrity/approval JSON, reconciliation reports, build-request JSON, and explicit user decision records. Inspection and validation accept only non-symlink directories or ZIP files. Reconciliation, build, promotion, and preflight inputs are strict JSON contracts; unknown security-sensitive fields are rejected.

Select exactly one project before combining evidence. Independent projects remain separate unless a future, separately approved design introduces an explicit cross-project workflow.

## Five workflows

1. `project-intelligence` selects one project, records scope, and routes to exactly one next Continuity skill.
2. `inspect-project-state` inventories supplied sources, verifies structural evidence where possible, preserves observed paths, and classifies material claims without changing originals.
3. `reconcile-project-state` compares integrity, lineage, completeness, claims, approvals, and safety gates. It may merge only uncontested facts with provenance and must stop for every unresolved material conflict.
4. `create-canonical-handoff` builds and validates a separate `Candidate` or `Blocked` release. Exact promotion approval creates a new `Canonical` successor and receipt; it never rewrites the candidate or predecessor.
5. `superpowers-preflight` reports readiness, authorized and prohibited scope, unresolved actions, evidence references, and one exact next action. A `Blocked` result never enters or recommends execution.

Start with `project-intelligence` unless the selected project and required downstream workflow are already explicit.

## Deterministic CLI

All commands emit stable JSON to the requested output. Exit code `0` means the operation completed and its gate passed, `2` means a valid result is blocked, and `1` means invalid input or an operational failure. Output paths must be separate from inspected sources.

Set a short shell variable for readability:

```bash
continuity_cli=skills/project-intelligence/scripts/continuity_cli.py
```

Inspect a directory or ZIP:

```bash
python "$continuity_cli" inspect handoffs/atlas-7.zip \
  --output work/atlas-7-inspection.json
```

Reconcile arrays of strict claim, approval, and integrity records:

```bash
python "$continuity_cli" reconcile \
  --claims work/claims.json \
  --approvals work/approvals.json \
  --integrity work/integrity.json \
  --output work/reconciliation.json
```

Build a release from a strict build-request object. The output is one atomically published outer directory containing `package/` and `<package_id>.zip`:

```bash
python "$continuity_cli" build \
  --request work/build-request.json \
  --output-dir releases/atlas-8-candidate
```

Validate an unpacked package, outer release directory, or ZIP:

```bash
python "$continuity_cli" validate releases/atlas-8-candidate/package \
  --output work/candidate-validation.json
python "$continuity_cli" validate releases/atlas-8-candidate/atlas-8-candidate.zip \
  --output work/zip-validation.json
```

Promote with an inspected approval record and an explicit RFC3339 successor creation time:

```bash
python "$continuity_cli" promote releases/atlas-8-candidate/package \
  --approval work/promote-atlas-8.json \
  --created-at 2026-08-09T15:00:00Z \
  --output releases/atlas-8
```

Run preflight against a reconciliation report. The selected reconciliation must contain exactly one selected, verified `project_id` or `project id` claim matching `--project-id`:

```bash
python "$continuity_cli" preflight \
  --reconciliation work/reconciliation.json \
  --project-id atlas \
  --package-id atlas-8 \
  --requested-action implementation \
  --output work/preflight.json
```

Use each command's `--help` for the current syntax. The public verbs are exactly `inspect`, `reconcile`, `build`, `validate`, `promote`, and `preflight`.

## Candidate approval and promotion

A successful build is not authority. Before promotion:

1. inspect and reconcile one project;
2. resolve every material conflict with an approval scoped to its exact conflict ID;
3. build and independently validate the release;
4. review the candidate's manifest, checksum inventory, authority ledger, unresolved record, and preflight receipt; and
5. supply a promotion approval whose action is `promote-candidate`, scope is exactly the candidate package ID, decision is approved, and source reference is inspectable.

A promotion approval record has the strict shape:

```json
{
  "approval_id": "approval-promote-atlas-8",
  "action": "promote-candidate",
  "scope": ["atlas-8-candidate"],
  "decision": "approved",
  "source_id": "user",
  "source_ref": "conversation://atlas/promotion",
  "approved_at": "2026-08-09T14:55:00Z"
}
```

Promotion is append-only. It publishes a distinct successor release with a new package identity, `Canonical` status, updated lineage, regenerated documents, manifest and checksums, and `receipts/PROMOTION.json`. The source packages, predecessor, and candidate remain byte-identical.

## Readiness meanings

- `Ready`: integrity passes, canonical authority is clear, no material conflict remains, and the exact requested action is explicitly authorized.
- `Conditional`: remaining unknowns are cited and proven not to affect the authorized exact next action; every condition travels with the handoff.
- `Blocked`: integrity, project identity, required evidence, authority, conflict, lifecycle, or requested-action scope failed. The CLI returns `2`; no implementation-stage companion is named.

Readiness and package lifecycle are different contracts. A package may be `Candidate`, `Blocked`, `Canonical`, or `Superseded`; only exact promotion approval creates a `Canonical` successor. Never describe `Candidate` as canonical or a `Superseded` package as the current root.

## Continuity alongside Superpowers

Continuity supplies preserved truth, evidence state, authority boundary, lifecycle, readiness, and the exact next action. Superpowers supplies design, planning, implementation, testing, debugging, review, and verification practices after those gates pass. Continuity does not copy or alter Superpowers workflows, and a Superpowers recommendation never expands recorded authority.

Continuity remains fully useful when Superpowers is absent: it still returns inspection, reconciliation, portable package, validation, and preflight results. When preflight is `Blocked`, do not invoke planning, implementation, testing, review, deployment, or any mutation. When it is `Ready` or `Conditional`, hand off only the cited scope and exact next action.

## Security boundaries and limits

- Sources are read-only. Successful, blocked, and failed operations must not overwrite, delete, or extract into them.
- Archive inspection rejects traversal, absolute paths, duplicate normalized destinations, symlinks, encryption, corrupt data, and unsafe expansion before publication.
- Expected and observed hashes are both retained on mismatch; a missing checksum is not verification.
- Every material claim carries an evidence state and source reference. A limited search yields `Unresolved`, not proof that an artifact is `Missing`.
- Material architecture, behavior, scope, authority, safety, readiness, or next-action conflicts require exact user resolution.
- Broad urgency or administrative language cannot override a narrower recorded prohibition.
- Likely secrets are redacted from reports and excluded from packages unless exact path-scoped secure-handling approval is supplied.
- Candidate and canonical publication uses one atomic, no-clobber outer release boundary. Every canonical file is covered by the manifest and checksum inventory.
- User-supplied narrative is supplemental and cannot create governing claims, approvals, conflict resolutions, or readiness authority.

## Version 1 non-goals

Version 1 has no MCP server, OAuth flow, external account access, cloud database, cloud synchronization, persistent project registry, required custom UI, or external mutation. It does not choose among independent projects, replace user authority, infer approval from age or urgency, or make Superpowers a dependency. A visual lineage viewer and team/cloud capabilities require a separate approved design.

## Test and evaluation

Run deterministic verification from the repository root:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q skills/project-intelligence/scripts
.venv/bin/python skills/project-intelligence/scripts/continuity_cli.py --help
git diff --check
```

The behavioral matrix is contract-tested separately:

```bash
.venv/bin/python -m pytest -q tests/behavioral/test_case_contract.py
```

Deterministic tests prove code, schema, resource, and case-contract behavior. They do not prove ChatGPT skill routing. Every release must also run all ten cases in fresh host conversations and capture semantic evidence. See [the evaluation and release sign-off guide](docs/evaluation.md).
