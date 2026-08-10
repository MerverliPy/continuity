# Continuity marketplace compatibility design

## Purpose

Allow the existing Continuity v1 plugin bundle to be discovered by the Codex
local-marketplace workflow used on CALVINPC. The existing plugin remains the
only source of skills, scripts, schemas, templates, and Python runtime.

## Scope and non-goals

This change adds one repository-scoped marketplace catalog at
`.agents/plugins/marketplace.json`. It does not add MCP, OAuth, a UI, a public
directory submission, a second copy of the plugin, or any new Continuity
workflow.

## Marketplace contract

The repository root is both the marketplace root and the Continuity plugin
root. The catalog contains exactly one entry:

- marketplace name: `continuity-local`
- marketplace interface display name: `Continuity Local` via
  `interface.displayName`
- plugin name: `continuity`
- source type: `local`
- source path: `./`
- installation policy: `AVAILABLE`
- authentication policy: `ON_INSTALL`
- category: `Productivity`

`./` is deliberate: it is a `./`-prefixed path inside the marketplace root
and resolves to the existing root that contains `.codex-plugin/plugin.json`.
No copied `plugins/continuity` directory is allowed, preventing source drift.

## Verification

Automated regression coverage will parse the marketplace catalog and verify
the exact single-entry contract, path containment, required policies, and
that the resolved source is the same root containing the existing plugin
manifest. Existing layout and full-suite tests remain required.

Host acceptance on CALVINPC will run
`codex plugin marketplace add "$HOME/continuity-evaluation/continuity-v1"`.
The command must exit zero. The evaluator must then use a plugin-enabled
ChatGPT desktop host that can access that marketplace, install Continuity from
the Plugins Directory, and run the versioned behavioral cases in fresh
conversations. Codex CLI registration alone does not prove skill routing.

## Failure handling

If marketplace registration rejects the catalog, capture the command output
and exit code in the host evidence directory. Do not claim host evaluation
passed, alter the source plugin, or invent a supported manifest schema.
