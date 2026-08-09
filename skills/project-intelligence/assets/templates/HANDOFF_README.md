# Continuity handoff: {{ package_id }}

> Warning: Candidate is not Canonical. Do not treat this package as authoritative or route it to execution before explicit, scoped promotion approval.

## Package identity

- Schema: `continuity.package/v1`
- Project ID: `{{ project_id }}`
- Package ID: `{{ package_id }}`
- Created at: `{{ created_at }}`
- Lifecycle status: `{{ status }}`
- Readiness: `{{ readiness }}`

## Safe resume

Verify `SHA256SUMS.txt`, validate `MANIFEST.json`, and inspect the authority ledger before relying on any package claim. The outer release directory is transport structure; the portable package is the `package/` directory or its sibling ZIP.

{{ handoff_body }}

## Promotion

Promotion requires an explicit approval record scoped exactly to this Candidate and creates a separate Canonical successor. It never rewrites this package or its source evidence.
