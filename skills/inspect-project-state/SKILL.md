---
name: inspect-project-state
description: Inspects selected project evidence without changing its sources.
---

# Inspect project state

## Trigger guidance

Use this skill after `project-intelligence` has selected one project and the request needs an evidence inventory, extracted project state, or a record of unknowns. It accepts project folders, handoff packages, repository snapshots, reports, receipts, and user-supplied decisions within that selected scope.

## Ordered workflow

1. Confirm the selected project, source list, and inspection boundary received from `project-intelligence`.
2. Perform Read-only inspection of every supplied source; preserve each observed path and do not overwrite, extract into, or normalize a source in place.
3. Inventory accessible artifacts and record identity, provenance, integrity evidence, and unreadable or unsupported artifacts.
4. Extract only directly supported goals, requirements, architecture, decisions, approvals, progress, safety gates, and unresolved facts.
5. Label each material claim as `Verified`, `Asserted`, `Unresolved`, `Contradicted`, or `Missing` according to the inspected evidence.
6. Return one inspection report with citations to source artifacts and clear limits on what was not inspected.
7. Route competing states or claims to `reconcile-project-state`; return to `project-intelligence` when the selected scope or intended route changes.

## Output contract

Return an inspection report containing the selected project, source inventory, source references for extracted claims, integrity observations, evidence states, unresolved facts, and safety gates. The report distinguishes an absent required artifact from an artifact that was merely outside the inspected scope.

## Stop conditions

Stop and ask for a narrower scope when sources cannot be assigned to the selected project. Stop any operation that would modify an original source. Record unreadable, missing, or unsafe material as evidence limitations rather than inventing its contents or a successful validation result.

## Delegation

Delegate cross-source comparison, lineage modeling, and authority conflicts to `reconcile-project-state`. Delegate a request to make a portable candidate only to `create-canonical-handoff` after reconciliation has approved the necessary inputs. Delegate readiness briefing only to `superpowers-preflight` after reconciliation or canonical status supplies a readiness basis.
