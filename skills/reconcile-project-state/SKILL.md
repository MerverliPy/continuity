---
name: reconcile-project-state
description: Reconciles inspected project evidence while preserving authority boundaries.
---

# Reconcile project state

## Trigger guidance

Use this skill when inspection reports, integrity findings, lineage records, or claims for one selected project disagree or need comparison. Do not use it to choose among different projects; return that ambiguity to `project-intelligence`.

## Ordered workflow

1. Confirm that every input belongs to the single project selected by `project-intelligence`.
2. Compare source integrity, lineage, approval scope, completeness, and consistency with recorded safety gates; treat timestamps as supporting evidence only.
3. Preserve uncontested facts with provenance and classify each difference as non-material or material.
4. Keep every material conflict unresolved until a user decision identifies the exact conflict and scope.
5. Apply a User-approved resolution for every material conflict only when its record cites the deciding source, decision, and affected scope.
6. Produce a reconciliation report that identifies verified facts, assertions, unresolved facts, contradictions, missing evidence, conflict status, and authorized next actions.
7. Route approved, complete reconciliation results to `create-canonical-handoff`; route a readiness-only request with a clear authority basis to `superpowers-preflight`.

## Operating rules

Load only the directly relevant reference files: classify evidence with `skills/project-intelligence/references/evidence-states.md` and check portable authority/lifecycle constraints with `skills/project-intelligence/references/package-contract.md`. For every material claim, quote or cite the inspected file path and record ID. Keep source evidence read-only. Use the Continuity CLI for hashes, archive inspection, manifests, validation, and packaging so comparisons use deterministic records. Pause for exactly scoped user authority when material conflicts exist; do not infer a decision from age, urgency, or broad approval. Never label a `Candidate` as `Canonical`, and never route a `Blocked` package into execution. Return a useful Continuity reconciliation result even if Superpowers is absent.

## Prompt-only evaluation rule

When a locked behavioral evaluation explicitly identifies its mode as `prompt_only`, treat the stated integrity, lineage, approval, and requested-action facts as facts supplied in the prompt. Cite the stated source paths and record IDs as supplied context; do not claim textual paths were opened, hashed, or inspected by a tool. Do not downgrade readiness solely because those named paths are not available in the local workspace. This rule never supplies unstated facts, does not apply to ordinary workspace reconciliation, and does not apply to `artifact_required` cases, which require staged artifacts and actual tool evidence.

## Output contract

Return a reconciliation report with the selected project, compared sources, integrity and lineage findings, claim provenance, inspected file path and record ID for every material claim, materiality classification, required approval records, prohibited actions, and a `Ready`, `Conditional`, or `Blocked` readiness basis. It never upgrades unsupported claims to `Verified`.

## Stop conditions

Stop promotion and execution handoff when a material conflict, failed integrity check, missing required evidence, or out-of-scope approval remains. Do not silently resolve a conflict, select a newer source solely by time, or edit any inspected source. Ask the user for a scoped decision when an authority choice would change architecture, behavior, scope, safety, readiness, or the exact next action.

## Delegation

Delegate missing inventories or source fact extraction to `inspect-project-state`. Delegate candidate construction and promotion only to `create-canonical-handoff` when this report has no unresolved material conflict and supplies approved inputs. Delegate the execution-readiness brief only to `superpowers-preflight`; return project-selection ambiguity to `project-intelligence`.
