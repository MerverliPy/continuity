---
name: superpowers-preflight
description: Produces approval-aware readiness briefs for companion execution workflows.
---

# Superpowers preflight

## Trigger guidance

Use this skill when a selected project has a reconciliation report or validated canonical handoff and the user needs a precise readiness decision before planning or implementation. It can produce a portable preflight brief independently; a companion Superpowers handoff is available only if that companion is present in the environment.

## Ordered workflow

1. Confirm the selected project and obtain its reconciliation report or validated canonical-handoff record.
2. Evaluate integrity, canonical authority, material conflicts, required evidence, requested-action scope, and recorded approvals.
3. Classify readiness as `Ready`, `Conditional`, or `Blocked` and preserve the evidence supporting that classification.
4. State the canonical scope, authorized actions, prohibited actions, unresolved facts, conditions, and one exact next action.
5. For a Blocked preflight, return a non-zero status and do not recommend or invoke an implementation-stage Superpowers skill.
6. For `Ready` or `Conditional`, describe the relevant companion handoff only if Superpowers is available; otherwise return the portable brief without claiming any companion is installed.
7. Return to `reconcile-project-state` when authority or material-conflict evidence is incomplete, and return to `project-intelligence` when the selected project is uncertain.

## Operating rules

Load only the directly relevant reference files: use `skills/project-intelligence/references/superpowers-handoff.md` for the companion boundary, `skills/project-intelligence/references/evidence-states.md` for cited readiness evidence, and `skills/project-intelligence/references/package-contract.md` when package lifecycle controls routing. For every material claim, quote or cite the inspected file path and record ID. Keep source evidence read-only. Use the Continuity CLI for hashes, archive inspection, manifests, validation, and packaging before relying on deterministic package facts. Pause for exactly scoped user authority when material conflicts exist. Never label a `Candidate` as `Canonical`, and never route a `Blocked` package into execution. Produce a useful Continuity preflight result even if Superpowers is absent.

## Output contract

Return `SUPERPOWERS_PREFLIGHT.md` or equivalent structured content containing readiness, selected project, canonical scope, authorized actions, prohibited actions, unresolved facts, conditions, exact next action, evidence citations with inspected file path and record ID, and an optional companion-stage recommendation. A `Blocked` result includes no implementation-stage recommendation.

## Stop conditions

Stop and produce `Blocked` when integrity fails, authority is unclear, a material conflict remains, required evidence is missing, the requested action exceeds approval, or project identity cannot be verified. Do not invoke planning, implementation, testing, review, deployment, or any external mutation while `Blocked`.

## Delegation

Delegate source inventory and evidence extraction to `inspect-project-state`. Delegate authority comparison and conflict handling to `reconcile-project-state`. Delegate candidate construction and promotion gating to `create-canonical-handoff`. Delegate project selection to `project-intelligence`; this skill only consumes a project already selected there.
