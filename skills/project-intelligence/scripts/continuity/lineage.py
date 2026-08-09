"""Deterministic validation of portable Continuity package lineage."""

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
import heapq
import re
from typing import Sequence

from .models import PackageStatus


class LineageState(StrEnum):
    """Whether package identity and ancestry identify one usable project."""

    VALID = "valid"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


@dataclass(frozen=True)
class SourcePackage:
    """The identity and declared ancestry of one inspected source package."""

    package_id: str
    root_sha256: str
    status: PackageStatus
    parent_ids: tuple[str, ...] = ()
    declared_current_root: bool = False
    created_at: str | None = None


@dataclass(frozen=True)
class LineageFinding:
    """One stable explanation of a lineage validation result."""

    code: str
    package_ids: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "package_ids": list(self.package_ids),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class LineageGraph:
    """A validated, deterministically ordered package graph."""

    state: LineageState
    ordered_package_ids: tuple[str, ...]
    root_package_ids: tuple[str, ...]
    current_package_id: str | None
    findings: tuple[LineageFinding, ...]

    @property
    def status(self) -> LineageState:
        """Alias used by report consumers that call graph state a status."""

        return self.state

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "ordered_package_ids": list(self.ordered_package_ids),
            "root_package_ids": list(self.root_package_ids),
            "current_package_id": self.current_package_id,
            "findings": [
                finding.to_dict()
                for finding in sorted(
                    self.findings, key=lambda item: (item.code, item.package_ids, item.detail)
                )
            ],
        }


def build_lineage(sources: Sequence[SourcePackage]) -> LineageGraph:
    """Validate identities and ancestry without selecting among unrelated roots."""

    findings: list[LineageFinding] = []
    by_id: dict[str, SourcePackage] = {}
    hashes_by_id: dict[str, set[str]] = defaultdict(set)

    if not sources:
        findings.append(
            LineageFinding("no-sources", (), "lineage contains no source packages")
        )

    for source in sources:
        hashes_by_id[source.package_id].add(source.root_sha256.casefold())
        if re.fullmatch(r"[0-9a-fA-F]{64}", source.root_sha256) is None:
            findings.append(
                LineageFinding(
                    "invalid-root-sha256",
                    (source.package_id,),
                    "package root SHA-256 must contain exactly 64 hexadecimal characters",
                )
            )
        existing = by_id.get(source.package_id)
        if existing is None or _source_sort_key(source) < _source_sort_key(existing):
            by_id[source.package_id] = source

    for package_id, root_hashes in sorted(hashes_by_id.items()):
        if len(root_hashes) > 1:
            findings.append(
                LineageFinding(
                    "identity-collision",
                    (package_id,),
                    "package ID is associated with more than one root SHA-256",
                )
            )

    children: dict[str, set[str]] = defaultdict(set)
    indegree = {package_id: 0 for package_id in by_id}
    for package_id, source in sorted(by_id.items()):
        for parent_id in sorted(set(source.parent_ids)):
            if parent_id not in by_id:
                findings.append(
                    LineageFinding(
                        "missing-parent",
                        (package_id, parent_id),
                        f"package {package_id!r} names missing parent {parent_id!r}",
                    )
                )
                continue
            if package_id not in children[parent_id]:
                children[parent_id].add(package_id)
                indegree[package_id] += 1

    queue = [package_id for package_id, degree in indegree.items() if degree == 0]
    heapq.heapify(queue)
    ordered: list[str] = []
    while queue:
        package_id = heapq.heappop(queue)
        ordered.append(package_id)
        for child_id in sorted(children[package_id]):
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                heapq.heappush(queue, child_id)

    cyclic_ids = tuple(sorted(set(by_id).difference(ordered)))
    if cyclic_ids:
        findings.append(
            LineageFinding("cycle", cyclic_ids, "package parent relationships contain a cycle")
        )

    current_ids = tuple(
        sorted(source.package_id for source in by_id.values() if source.declared_current_root)
    )
    superseded_current_ids = tuple(
        package_id
        for package_id in current_ids
        if by_id[package_id].status is PackageStatus.SUPERSEDED
    )
    for package_id in superseded_current_ids:
        findings.append(
            LineageFinding(
                "superseded-current",
                (package_id,),
                "a superseded package cannot be the declared current root",
            )
        )

    roots = tuple(
        sorted(
            package_id
            for package_id, source in by_id.items()
            if not source.parent_ids
        )
    )
    invalid = any(
        finding.code
        in {
            "identity-collision",
            "invalid-root-sha256",
            "missing-parent",
            "no-sources",
            "cycle",
            "superseded-current",
        }
        for finding in findings
    )
    ambiguous = len(roots) > 1 or len(current_ids) > 1
    if len(roots) > 1:
        findings.append(
            LineageFinding(
                "multiple-roots",
                roots,
                "multiple independent roots require explicit project selection",
            )
        )
    if len(current_ids) > 1:
        findings.append(
            LineageFinding(
                "multiple-current-roots",
                current_ids,
                "multiple packages declare themselves current",
            )
        )

    state = (
        LineageState.INVALID
        if invalid
        else LineageState.AMBIGUOUS
        if ambiguous
        else LineageState.VALID
    )
    current_package_id = (
        current_ids[0]
        if state is LineageState.VALID and len(current_ids) == 1
        else None
    )
    return LineageGraph(
        state=state,
        ordered_package_ids=tuple(ordered),
        root_package_ids=roots,
        current_package_id=current_package_id,
        findings=tuple(
            sorted(findings, key=lambda item: (item.code, item.package_ids, item.detail))
        ),
    )


def _source_sort_key(source: SourcePackage) -> tuple[object, ...]:
    return (
        source.package_id,
        source.root_sha256,
        source.status.value,
        tuple(sorted(source.parent_ids)),
        source.declared_current_root,
        source.created_at or "",
    )
