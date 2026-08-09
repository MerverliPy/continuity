"""Conservative report redaction and secret-bearing source exclusion."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re

from .models import ApprovalRecord


@dataclass(frozen=True)
class RedactionFinding:
    kind: str
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: tuple[RedactionFinding, ...]


_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?P<label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
    r"\r?\n(?P<body>.*?)\r?\n-----END (?P=label)-----",
    re.DOTALL,
)
_CONNECTION_PASSWORD_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://"
    r"[^\s:/@]+:(?P<secret>[^\s@/?#]+)(?=@)"
)
_BEARER_RE = re.compile(
    r"(?i)\bBearer[ \t]+(?P<secret>[A-Za-z0-9._~+/=-]{12,})"
)
_CREDENTIAL_NAME = (
    r"(?:[A-Za-z][A-Za-z0-9]*[_-])*"
    r"(?:api[ _-]?key|secret[ _-]?key|client[ _-]?secret|access[ _-]?token|"
    r"refresh[ _-]?token|password|passwd|pwd)"
)
_ASSIGNMENT_RE = re.compile(
    rf"(?im)(?P<label>(?<![\w-])"
    rf"(?:(?P<key_quote>['\"])(?P<quoted_key>{_CREDENTIAL_NAME})(?P=key_quote)|"
    rf"(?P<bare_key>{_CREDENTIAL_NAME}))\s*[:=]\s*)"
    r'(?:(?:"(?P<double_quoted>(?:\\.|[^"\\\r\n])*)")|'
    r"(?:'(?P<single_quoted>(?:\\.|[^'\\\r\n])*)')|"
    r"(?P<unquoted>[^\s,;#]+))"
)
_PREFIXED_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<secret>"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|"
    r"AKIA[0-9A-Z]{16}"
    r")(?![A-Za-z0-9_-])"
)
_SECURE_HANDLING_ACTION = "secure handling"
_APPROVED_DECISIONS = frozenset({"allow", "allowed", "approve", "approved"})


def redact_text(text: str) -> RedactionResult:
    """Redact high-confidence secrets while retaining surrounding source context."""

    findings: list[RedactionFinding] = []

    for match in _PRIVATE_KEY_RE.finditer(text):
        _append_nonoverlapping(
            findings,
            RedactionFinding(
                "private-key",
                match.start("body"),
                match.end("body"),
                "[REDACTED PRIVATE KEY]",
            ),
        )

    for match in _CONNECTION_PASSWORD_RE.finditer(text):
        _append_nonoverlapping(
            findings,
            RedactionFinding(
                "connection-string-password",
                match.start("secret"),
                match.end("secret"),
                "[REDACTED]",
            ),
        )

    for match in _BEARER_RE.finditer(text):
        _append_nonoverlapping(
            findings,
            RedactionFinding(
                "bearer-token",
                match.start("secret"),
                match.end("secret"),
                "[REDACTED]",
            ),
        )

    for match in _ASSIGNMENT_RE.finditer(text):
        group = next(
            name
            for name in ("double_quoted", "single_quoted", "unquoted")
            if match.group(name) is not None
        )
        key = match.group("quoted_key") or match.group("bare_key")
        normalized_key = _normalize(key)
        kind = "password" if normalized_key.endswith(
            ("password", "passwd", "pwd")
        ) else (
            "api-key"
            if normalized_key.endswith(("api key", "secret key"))
            else "token"
        )
        _append_nonoverlapping(
            findings,
            RedactionFinding(
                kind,
                match.start(group),
                match.end(group),
                "[REDACTED]",
            ),
        )

    for match in _PREFIXED_TOKEN_RE.finditer(text):
        _append_nonoverlapping(
            findings,
            RedactionFinding(
                "api-key",
                match.start("secret"),
                match.end("secret"),
                "[REDACTED]",
            ),
        )

    ordered = tuple(sorted(findings, key=lambda finding: (finding.start, finding.end)))
    redacted = text
    for finding in reversed(ordered):
        redacted = redacted[: finding.start] + finding.replacement + redacted[finding.end :]
    return RedactionResult(text=redacted, findings=ordered)


def exclude_secret_bearing_files(
    source_texts: Mapping[str, str],
    secure_handling_approvals: Sequence[ApprovalRecord],
) -> tuple[str, ...]:
    """Return packageable paths, requiring exact approval for every secret-bearing path."""

    approved_paths: set[str] = set()
    for approval in secure_handling_approvals:
        if (
            _normalize(approval.action) == _SECURE_HANDLING_ACTION
            and _normalize(approval.decision) in _APPROVED_DECISIONS
        ):
            approved_paths.update(approval.scope)

    included = [
        path
        for path, content in source_texts.items()
        if not redact_text(content).findings or path in approved_paths
    ]
    return tuple(sorted(included))


def _append_nonoverlapping(
    findings: list[RedactionFinding], finding: RedactionFinding
) -> None:
    if finding.start == finding.end:
        return
    if any(
        finding.start < existing.end and existing.start < finding.end
        for existing in findings
    ):
        return
    findings.append(finding)


def _normalize(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").casefold().split())
