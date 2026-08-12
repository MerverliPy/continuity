# Continuity prompt-only renderer final fix report

Date: 2026-08-12

## Scope

This fix hardens only the Task 2 prompt-only behavioral input CLI and its
regression tests. The pure renderer and its model-visible envelope were not
changed. No GitHub remote, branch, pull request, marketplace/plugin, host
evaluation, raw behavioral case data, evidence archive, or Task 3 manifest was
touched.

## RED evidence

Before changing production code, I added regression coverage for both kinds of
pre-existing predictable temporary entry and for a destination-leaf symlink
inserted after the early output check.

Command:

```text
PYTHONPATH=/tmp/continuity-contract-base.8O9ocA/repo/.worktrees/continuity-prompt-only-contract-v1/skills/project-intelligence/scripts TMPDIR=/workspace/scratch/7f652685ef9a/pytest-tmp PYTHONDONTWRITEBYTECODE=1 /tmp/continuity-prompt-only-contract-v1-venv/bin/python -m pytest -q tests/behavioral/test_evaluator_input_contract.py
```

Result:

```text
.....FFF                                                                 [100%]
3 failed, 5 passed in 0.21s
```

The failures were the expected contract failures:

- `test_cli_does_not_alter_a_preexisting_predictable_temporary_entry[file]`:
  the predictable entry no longer existed after the run.
- `test_cli_does_not_alter_a_preexisting_predictable_temporary_entry[symlink]`:
  the predictable symlink no longer existed after the run (and the old writer
  had followed it while writing).
- `test_cli_never_follows_a_destination_symlink_inserted_after_validation`:
  the CLI did not reject the raced leaf; it published to and reported the
  symlink target.

## Implementation

`tools/render_behavioral_input.py` now:

- retains the caller's original final path component and resolves only its
  parent directory;
- repeats the destination existence/symlink refusal after parent resolution;
- creates a randomized temporary sibling with `tempfile.mkstemp`, whose
  standard-library implementation uses exclusive creation;
- encloses temporary creation, descriptor conversion/write, hard-link
  publication, descriptor cleanup, and pathname cleanup in one outer
  `try/finally`;
- keeps `os.link(temporary, output)` as the atomic no-clobber publication gate;
  a destination file or symlink created after either validation check causes
  `FileExistsError` rather than being followed or replaced; and
- computes the reported digest from the already-rendered bytes, avoiding a
  post-publication read through a destination leaf that another process could
  replace.

Race prevention does not rely on the validation checks alone. They provide
clear early refusal, while the hard-link operation is the atomic final decision:
the destination directory entry must still be absent at that exact operation.
Because the output leaf is never resolved, a symlink inserted after early
validation cannot redirect publication. The temporary name is unpredictable,
created exclusively in the resolved parent, and cleaned on every return or
exception after successful creation. A stale file or symlink at the former
PID-derived name is neither opened nor removed.

## GREEN evidence

Focused command (same controlled environment as RED):

```text
PYTHONPATH=/tmp/continuity-contract-base.8O9ocA/repo/.worktrees/continuity-prompt-only-contract-v1/skills/project-intelligence/scripts TMPDIR=/workspace/scratch/7f652685ef9a/pytest-tmp PYTHONDONTWRITEBYTECODE=1 /tmp/continuity-prompt-only-contract-v1-venv/bin/python -m pytest -q tests/behavioral/test_evaluator_input_contract.py
```

Final focused result:

```text
........                                                                 [100%]
8 passed in 0.20s
```

This focused run also rechecked prompt-only-only behavior, artifact-required
rejection before output, existing regular and dangling-symlink refusal, exact
rendered bytes, and all nine locked rendered digests.

## Full-suite verification

Command:

```text
env PYTHONPATH=/tmp/continuity-contract-base.8O9ocA/repo/.worktrees/continuity-prompt-only-contract-v1/skills/project-intelligence/scripts TMPDIR=/workspace/scratch/7f652685ef9a/pytest-tmp PYTHONDONTWRITEBYTECODE=1 /tmp/continuity-prompt-only-contract-v1-venv/bin/python -m pytest -q
```

Result:

```text
........................................................................ [ 19%]
........................................................................ [ 39%]
........................................................................ [ 59%]
........................................................................ [ 79%]
........................................................................ [ 99%]
.                                                                        [100%]
361 passed in 22.30s
```

An earlier attempt to start this command was cancelled by the execution
environment's network-approval preflight before pytest ran and produced no test
result. The result above is the completed full-suite run.

`git diff --check` exited 0 with no output. A filesystem check found no `.venv`,
`*.egg-info`, or `__pycache__` directory in the source worktree.

## Files changed

- `tools/render_behavioral_input.py`
- `tests/behavioral/test_evaluator_input_contract.py`
- `.superpowers/sdd/CONTINUITY_PROMPT_ONLY_CONTRACT_REPAIR_PLAN_2026-08-12/final-fix-report.md`

## Self-review

- The pure `continuity.evaluation` renderer remains filesystem/network-free and
  byte-for-byte unchanged.
- Artifact-required validation still precedes every output-path check and write.
- The output parent must exist, and only the parent is canonicalized.
- Existing regular outputs and both regular and dangling symlink outputs remain
  untouched.
- Publication remains an atomic, no-clobber hard link rather than a rename that
  could replace the destination.
- The temporary file uses only Python standard-library facilities and is not
  placed outside the destination filesystem.
- Regression assertions exercise real filesystem effects. The race test inserts
  a real symlink after early validation at the deterministic parent-resolution
  boundary and verifies that neither the link target nor the link itself is
  modified.
- Locked raw case prompts and rendered digest constants were not changed.

## Concerns

None within the requested scope.
