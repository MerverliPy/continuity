---
name: create-canonical-handoff
description: Creates separate canonical-handoff candidates from approved reconciliation results.
---

# Create canonical handoff

## Trigger guidance

Use this skill after `reconcile-project-state` has produced approved inputs for one selected project and the user needs a portable candidate handoff or a promotion decision. It does not replace inspection or reconciliation, and it never treats a candidate as authoritative by default.

## Ordered workflow

1. Confirm the selected project, approved reconciliation report, source references, and intended handoff scope.
2. Build a separate candidate package that preserves source provenance and includes only authorized canonical material; leave all original evidence unchanged.
3. Record candidate identity, lineage, validation evidence, unresolved facts, prohibited actions, and checksum or integrity evidence.
4. Validate the candidate before describing it as complete or usable.
5. Keep the package status `Candidate` or `Blocked` until the user supplies an approval record scoped to promotion.
6. Require Explicit promotion approval before creating a new `Canonical` successor and its promotion receipt.
7. Route the promoted canonical package to `superpowers-preflight` when an execution-readiness brief is requested.

## Output contract

Return a candidate or canonical handoff record containing package identity, status, source lineage, validation result, unresolved facts, approved scope, prohibited actions, and any promotion receipt. A promotion creates a new successor and does not rewrite a candidate, source, or predecessor.

## Stop conditions

Stop when reconciliation leaves a material conflict, integrity validation fails, required evidence is missing, candidate construction is incomplete, or promotion approval is absent or broader than its recorded scope. Do not delete, overwrite, or mutate source evidence. Do not promote a `Candidate` because a timestamp, request urgency, or another approval implies authority.

## Delegation

Delegate uninspected inputs to `inspect-project-state` and disputed or incomplete authority to `reconcile-project-state`. Delegate project selection back to `project-intelligence` when scope is unclear. Delegate only the readiness brief for a validated canonical package to `superpowers-preflight`.
