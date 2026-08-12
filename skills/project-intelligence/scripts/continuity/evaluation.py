"""Deterministic inputs for prompt-only behavioral evaluation."""

PROMPT_ONLY_EVALUATOR_CONTRACT_VERSION = "continuity.behavioral-input/v1"


def render_prompt_only_input(case_id: str, prompt: str) -> str:
    """Render one immutable behavioral prompt with its evaluator instructions."""
    if not case_id.strip() or not prompt.strip():
        raise ValueError("case_id and prompt must be non-empty")
    return (
        "Continuity behavioral evaluator contract: "
        f"{PROMPT_ONLY_EVALUATOR_CONTRACT_VERSION}\n"
        "Evaluation mode: prompt_only\n"
        "This case supplies facts as text; no case artifacts are staged.\n"
        "Do not perform workspace discovery or call tools for the named paths.\n"
        "Do not claim a named path or record ID was opened, hashed, or independently verified.\n"
        "When citing a named path or record ID, identify it as supplied context.\n"
        f"--- BEGIN LOCKED CASE {case_id} ---\n"
        f"{prompt}\n"
        f"--- END LOCKED CASE {case_id} ---"
    )
