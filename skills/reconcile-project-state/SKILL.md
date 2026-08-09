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
4. Keep every material authority conflict unresolved until a user decision identifies the exact conflict and scope.
5. Apply only User-approved material conflict resolution records that cite the deciding source, decision, and affected scope.
6. Produce a reconciliation report that identifies verified facts, assertions, unresolved facts, contradictions, missing evidence, conflict status, and authorized next actions.
7. Route approved, complete reconciliation results to `create-canonical-handoff`; route a readiness-only request with a clear authority basis to `superpowers-preflight`.

## Output contract

Return a reconciliation report with the selected project, compared sources, integrity and lineage findings, claim provenance, materiality classification, required approval records, prohibited actions, and a `Ready`, `Conditional`, or `Blocked` readiness basis. It never upgrades unsupported claims to `Verified`.

## Stop conditions

Stop promotion and execution handoff when a material conflict, failed integrity check, missing required evidence, or out-of-scope approval remains. Do not silently resolve a conflict, select a newer source solely by time, or edit any inspected source. Ask the user for a scoped decision when an authority choice would change architecture, behavior, scope, safety, readiness, or the exact next action.

## Delegation

Delegate missing inventories or source fact extraction to `inspect-project-state`. Delegate candidate construction and promotion only to `create-canonical-handoff` when this report has no unresolved material conflict and supplies approved inputs. Delegate the execution-readiness brief only to `superpowers-preflight`; return project-selection ambiguity to `project-intelligence`.
