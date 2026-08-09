---
name: project-intelligence
description: Routes preservation-first project-intelligence requests through a single selected project.
---

# Project intelligence

## Trigger guidance

Use this entry skill when a user wants to recover, inspect, reconcile, hand off, or safely resume long-running project work from folders, archives, reports, receipts, or user decisions. Use it before another Continuity skill when a project has not already been selected in the current request.

## Ordered workflow

1. List the supplied project candidates and their observed paths without editing them.
2. Identify the user's requested outcome and the available evidence for each candidate.
3. Select exactly one project before routing. If several candidates remain plausible, ask the user to select one and do not merge their evidence.
4. State the selected project, included sources, excluded sources, and any scope assumptions.
5. Route raw or uninspected evidence to `inspect-project-state`.
6. Route two or more inspected states, integrity findings, or competing claims to `reconcile-project-state`.
7. Route approved reconciliation results that need a portable successor to `create-canonical-handoff`.
8. Route a canonical package or completed reconciliation report that needs an execution-readiness brief to `superpowers-preflight`.

## Operating rules

Load only the directly relevant reference files for the current route: evidence classification from `skills/project-intelligence/references/evidence-states.md` and portable lifecycle rules from `skills/project-intelligence/references/package-contract.md`. For every material claim, quote or cite the inspected file path and record ID; a route summary cannot upgrade evidence. Keep all source evidence read-only. Use the Continuity CLI for hashes, archive inspection, manifests, validation, and packaging instead of reproducing deterministic operations in prose. Pause for exactly scoped user authority when material conflicts exist. Never label a `Candidate` as `Canonical`, and never route a `Blocked` package into execution. Return a useful Continuity result even if Superpowers is absent.

## Output contract

Return a routing record containing the selected project identity, observed source paths, requested outcome, scope assumptions, evidence status, and exactly one next Continuity skill. Explain why the route is appropriate without treating an asserted fact as verified. The record cites each material claim's inspected file path and record ID.

## Stop conditions

Stop and ask the user to identify the project when the project cannot be selected reliably. Stop and keep sources separate when the request attempts to combine evidence from distinct projects. Do not change source evidence, infer authority from timestamps alone, or route around a material conflict.

## Delegation

Delegate inventory and fact extraction only to `inspect-project-state`. Delegate comparison, integrity, lineage, and authority analysis only to `reconcile-project-state`. Delegate separate candidate construction and promotion gating only to `create-canonical-handoff`. Delegate readiness briefing only to `superpowers-preflight` after the project is selected.
