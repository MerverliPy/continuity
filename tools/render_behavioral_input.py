"""Render one prompt-only behavioral case for a model evaluator."""

import argparse
import hashlib
import json
import os
from pathlib import Path

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

    output = args.output.resolve()
    if output.exists():
        parser.error(f"refusing to overwrite {output}")
    if not output.parent.is_dir():
        parser.error(f"output parent does not exist: {output.parent}")

    rendered = render_prompt_only_input(args.case_id, case["prompt"])
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_bytes(rendered.encode("utf-8"))
    try:
        os.link(temporary, output)
    except FileExistsError:
        parser.error(f"refusing to overwrite {output}")
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"SHA256={digest}")
    print(f"OUTPUT={output}")


if __name__ == "__main__":
    main()
