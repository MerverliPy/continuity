# Continuity

Continuity is a skills-only plugin for preservation-first project intelligence and canonical handoffs. It establishes a trustworthy project state from supplied workspace evidence before work proceeds in a later session or companion workflow.

Version 1 operates only on files available in the active workspace. It has no MCP server, OAuth flow, custom UI, cloud synchronization, or external mutation capability.

## Workflow

Start with `project-intelligence`. It selects one project and routes the request to inspection, reconciliation, canonical-handoff creation, or a Superpowers preflight. Original evidence remains read-only, material conflicts require scoped user approval, and a candidate becomes canonical only after explicit promotion approval.

## Skills

- `project-intelligence` selects the project and routes the request.
- `inspect-project-state` records evidence without changing a source.
- `reconcile-project-state` compares competing project states and preserves unresolved conflicts.
- `create-canonical-handoff` creates and validates a separate candidate handoff.
- `superpowers-preflight` produces an approval-aware readiness brief.
