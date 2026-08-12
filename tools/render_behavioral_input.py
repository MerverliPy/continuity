"""Render one prompt-only behavioral case for a model evaluator."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from continuity.evaluation import render_prompt_only_input


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--cases", default="tests/behavioral/cases.json")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    cases_path = Path(args.cases)
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    matching_cases = [case for case in cases if case.get("id") == args.case_id]
    if len(matching_cases) != 1:
        parser.error(f"expected exactly one case with id: {args.case_id}")
    case = matching_cases[0]
    if case.get("evaluation_mode") != "prompt_only":
        parser.error(f"case is not prompt_only: {args.case_id}")

    requested_output = args.output
    if requested_output.exists() or requested_output.is_symlink():
        parser.error(f"refusing to overwrite {requested_output}")
    output_parent = requested_output.parent.resolve()
    if not output_parent.is_dir():
        parser.error(f"output parent does not exist: {output_parent}")
    output = output_parent / requested_output.name
    if output.exists() or output.is_symlink():
        parser.error(f"refusing to overwrite {output}")

    rendered = render_prompt_only_input(args.case_id, case["prompt"])
    rendered_bytes = rendered.encode("utf-8")
    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output_parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(rendered_bytes)
        try:
            os.link(temporary, output)
        except FileExistsError:
            parser.error(f"refusing to overwrite {output}")
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(rendered_bytes).hexdigest()
    print(f"SHA256={digest}")
    print(f"OUTPUT={output}")


if __name__ == "__main__":
    main()
