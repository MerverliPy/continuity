# Evidence states

Use exactly one evidence state beside every material claim. Cite the inspected file path and stable record ID that support the classification. A source statement and an integrity result are separate evidence: content is `Verified` only when the relevant bytes were inspected and applicable integrity checks passed.

## Verified

The claim is directly supported by inspected evidence and every relevant integrity gate passes.

Example: `architecture = modular monolith` is recorded in inspected path `canonical/architecture.json`, record ID `claim-architecture-7`, and the file digest matches both `MANIFEST.json` and `SHA256SUMS.txt`.

## Asserted

The user or a source states the claim, but Continuity cannot independently verify it.

Example: a user says deployment approval exists, but no approval receipt is available. Record the statement and its conversation record ID as `Asserted`; do not authorize deployment.

## Unresolved

The inspected scope does not contain enough evidence to decide. A limited or unsuccessful search normally supports `Unresolved`, not `Missing`.

Example: no architecture decision is found in the supplied snapshot, but other project stores were outside scope. Record the inspected paths and search record ID as `Unresolved`.

## Contradicted

Credible inspected sources disagree, or stored integrity claims disagree with observed bytes.

Example: two checksum-valid handoffs cite different approved architectures. Preserve both claim IDs as `Contradicted` and pause for exactly scoped user authority.

## Missing

A required artifact or field is confirmed absent from the complete inspected scope.

Example: the portable package contract requires `MANIFEST.json`, the complete package root was inventoried, and no such entry exists. Cite the inventory finding ID and classify the artifact `Missing`.

Never convert `Asserted`, `Unresolved`, `Contradicted`, or `Missing` into `Verified` through summary wording, timestamps, request urgency, or an unrelated approval.
