# Continuity handoff: {{ package_id }}

> Safety rule: Candidate is not Canonical; only a separately promoted Canonical successor is authoritative.

{{ lifecycle_notice }}

## Package identity

- Schema: `continuity.package/v1`
- Project ID: `{{ project_id }}`
- Package ID: `{{ package_id }}`
- Created at: `{{ created_at }}`
- Lifecycle status: `{{ status }}`
- Readiness: `{{ readiness }}`

## Safe resume

Verify `SHA256SUMS.txt`, validate `MANIFEST.json`, and inspect the authority ledger before relying on any package claim. The outer release directory is transport structure; the portable package is the `package/` directory or its sibling ZIP.

## Supplemental narrative

{{ supplemental_narrative }}

## Promotion

Promotion requires an explicit approval record scoped exactly to this Candidate and creates a separate Canonical successor. It never rewrites this package or its source evidence.
