# Continuity v1 portable package contract

The schema identifier is `continuity.package/v1`. A published release is one outer directory containing `package/` and `<package_id>.zip`; both cross one atomic no-clobber publication boundary. The outer directory is transport structure and is not inventoried.

## Required portable package entries

- `HANDOFF_README.md`: entry point, identity, lifecycle, creation time, warning, and safe resume instructions.
- `CANONICAL_STATE.md`: material project claims with evidence state, source reference, and record ID.
- `AUTHORITY_LEDGER.md`: allowed, prohibited, and unresolved actions plus cited approval scope.
- `CONFLICT_RESOLUTIONS.md`: compared claims, decisions, rejected alternatives, and cited resolution approvals.
- `UNRESOLVED.md`: unknowns, missing evidence, contradictions, impact, and required authority.
- `NEXT_THREAD_PROMPT.txt`: exact preservation-first continuation prompt.
- `SUPERPOWERS_PREFLIGHT.md`: readiness, authorization boundary, exact next action, and optional companion stage.
- `lineage/LINEAGE.json`: package/project identity, parents, roots, source hashes, lifecycle, readiness, and promotion time.
- `evidence/INDEX.json`: evidence identity, provenance reference, and enumerated evidence state.
- `canonical/`: selected files required for safe continuation.
- `receipts/RECONCILIATION.json`: claims, findings, approvals, conflicts, selections, and blockers.
- `MANIFEST.json`: strict versioned identity, lifecycle, provenance, and payload inventory.
- `SHA256SUMS.txt`: byte-level SHA-256 inventory.

`MANIFEST.json.files` contains every regular package file except `MANIFEST.json` and `SHA256SUMS.txt`. `SHA256SUMS.txt` contains the actual byte digest for `MANIFEST.json` and every other regular package file except itself. Entries are normalized, unique, sorted, and verified against current bytes.

Historical sources may be referenced by stable package ID and immutable SHA-256 instead of duplicated, provided their bytes remain available. Evidence required for safe continuation belongs in `canonical/` or `receipts/`. Originals remain read-only.

## Lifecycle

- `Candidate`: generated and validated, but not authoritative. Candidate is never a synonym for Canonical.
- `Blocked`: failed gate or unresolved material conflict. It cannot be promoted or routed to execution.
- `Canonical`: a separate successor created after exact promotion approval.
- `Superseded`: preserved historical authority replaced by an approved successor.

Promotion is append-only. It requires an approval whose action and scope identify the exact Candidate, plus an explicit RFC3339 `successor_created_at` recorded in both `MANIFEST.json` and `lineage/LINEAGE.json`. It creates a new outer release, promotion receipt, package ID, manifest, checksums, and archive without changing the Candidate, predecessor, or source evidence.

Use the Continuity CLI for hashes, archive safety, manifest creation, package construction, validation, and promotion. Both construction-time validation and independent completed-package validation must run; schema validity does not replace cross-file identity, lifecycle, authority, or checksum checks.
