from pathlib import Path

import pytest

from continuity.hashing import inventory_tree, sha256_file, verify_sha256s, write_sha256s
from continuity.manifests import build_manifest, compare_manifests
from continuity.models import EvidenceState, PackageStatus
from continuity.paths import normalize_relative_path


def test_inventory_is_sorted_and_preserves_observed_path(tmp_path: Path) -> None:
    """Catches inventory sorting by discovery order or replacing source spelling."""
    (tmp_path / "z.txt").write_text("last", encoding="utf-8")
    (tmp_path / "A folder").mkdir()
    (tmp_path / "A folder/a.txt").write_text("first", encoding="utf-8")

    records = inventory_tree(tmp_path, source_id="source-1")

    assert [record.normalized_path for record in records] == ["A folder/a.txt", "z.txt"]
    assert records[0].observed_path == "A folder/a.txt"
    assert all(record.evidence_state is EvidenceState.VERIFIED for record in records)


def test_checksum_file_is_excluded_from_its_own_inventory(tmp_path: Path) -> None:
    """Catches recursive checksum manifests that change after every write."""
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")

    write_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")

    assert (tmp_path / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines() == [
        f"{sha256_file(tmp_path / 'a.txt')}  a.txt"
    ]


def test_checksum_generation_does_not_overwrite_an_existing_destination(tmp_path: Path) -> None:
    """Catches source evidence being overwritten when a checksum sidecar already exists."""
    destination = tmp_path / "SHA256SUMS.txt"
    destination.write_bytes(b"original evidence\n")

    with pytest.raises(FileExistsError):
        write_sha256s(tmp_path, destination)

    assert destination.read_bytes() == b"original evidence\n"


def test_checksum_generation_rejects_destination_outside_root(tmp_path: Path) -> None:
    """Catches a checksum operation mutating a path outside its explicit package root."""
    outside = tmp_path.parent / "outside-SHA256SUMS.txt"

    with pytest.raises(ValueError, match="inside root"):
        write_sha256s(tmp_path, outside)

    assert outside.exists() is False


def test_checksum_generation_rejects_a_symlinked_parent(tmp_path: Path) -> None:
    """Catches a lexical in-root destination being redirected into external evidence."""
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected_destination = outside / "SHA256SUMS.txt"
    redirected_destination.write_bytes(b"external evidence\n")
    (tmp_path / "redirect").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        write_sha256s(tmp_path, tmp_path / "redirect" / "SHA256SUMS.txt")

    assert redirected_destination.read_bytes() == b"external evidence\n"


def test_invalid_evidence_state_is_rejected() -> None:
    """Catches accidental acceptance of unrecognized evidence vocabulary."""
    with pytest.raises(ValueError):
        EvidenceState("verified")


def test_path_normalization_keeps_unicode_and_converts_backslashes() -> None:
    """Catches a destination collision caused by treating backslashes as literal names."""
    observed = "資料\\résumé.txt"

    assert normalize_relative_path(observed) == "資料/résumé.txt"


@pytest.mark.parametrize("unsafe", ["", ".", "../escape.txt", "/absolute.txt", "C:\\drive.txt", "bad\x00name"])
def test_path_normalization_rejects_unsafe_destinations(unsafe: str) -> None:
    """Catches extraction destinations that can escape or collapse out of the root."""
    with pytest.raises(ValueError):
        normalize_relative_path(unsafe)


def test_checksum_mismatch_preserves_expected_and_observed_hashes(tmp_path: Path) -> None:
    """Catches verification reports that discard the evidence required to diagnose a mismatch."""
    target = tmp_path / "a.txt"
    target.write_text("before", encoding="utf-8")
    write_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")
    expected = sha256_file(target)
    target.write_text("after", encoding="utf-8")

    report = verify_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")

    assert report.verified is False
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.normalized_path == "a.txt"
    assert finding.expected_sha256 == expected
    assert finding.observed_sha256 == sha256_file(target)
    assert finding.evidence_state is EvidenceState.CONTRADICTED


def test_missing_checksum_leaves_regular_files_unresolved(tmp_path: Path) -> None:
    """Catches a missing checksum sidecar being promoted to verified evidence."""
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")

    report = verify_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")

    assert report.verified is False
    assert [(finding.normalized_path, finding.evidence_state) for finding in report.findings] == [
        ("a.txt", EvidenceState.UNRESOLVED)
    ]


def test_empty_tree_with_an_empty_checksum_sidecar_verifies(tmp_path: Path) -> None:
    """Catches a valid empty inventory being treated as an integrity failure."""
    (tmp_path / "SHA256SUMS.txt").write_text("", encoding="utf-8")

    report = verify_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")

    assert report.findings == ()
    assert report.verified is True


def test_checksum_verification_reports_missing_listed_file(tmp_path: Path) -> None:
    """Catches a listed artifact disappearing without a Missing evidence finding."""
    target = tmp_path / "a.txt"
    target.write_text("a", encoding="utf-8")
    write_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")
    target.unlink()

    report = verify_sha256s(tmp_path, tmp_path / "SHA256SUMS.txt")

    assert [(finding.normalized_path, finding.evidence_state) for finding in report.findings] == [
        ("a.txt", EvidenceState.MISSING)
    ]


def test_inventory_does_not_follow_symbolic_links(tmp_path: Path) -> None:
    """Catches linked external evidence being silently marked as inspected local content."""
    target = tmp_path / "target.txt"
    target.write_text("private", encoding="utf-8")
    (tmp_path / "linked.txt").symlink_to(target)

    records = inventory_tree(tmp_path, source_id="source-1")

    assert [record.normalized_path for record in records] == ["target.txt"]


def test_manifest_is_sorted_and_excludes_checksum_file(tmp_path: Path) -> None:
    """Catches non-deterministic manifests and recursive checksum inclusion."""
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "A").mkdir()
    (tmp_path / "A/a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "SHA256SUMS.txt").write_text("not inventory", encoding="utf-8")

    manifest = build_manifest(
        tmp_path,
        package_id="package-1",
        status=PackageStatus.CANDIDATE,
        lineage_roots=("root-z", "root-a"),
    )

    assert manifest == {
        "schema": "continuity.package/v1",
        "package_id": "package-1",
        "status": "Candidate",
        "lineage_roots": ["root-a", "root-z"],
        "files": [
            {"path": "A/a.txt", "sha256": sha256_file(tmp_path / "A/a.txt"), "size_bytes": 1},
            {"path": "z.txt", "sha256": sha256_file(tmp_path / "z.txt"), "size_bytes": 1},
        ],
    }


def test_manifest_comparison_rejects_duplicate_normalized_paths() -> None:
    """Catches silent loss of a file when two source spellings normalize to one destination."""
    left = {
        "files": [
            {"path": "dir/file.txt", "sha256": "a", "size_bytes": 1},
            {"path": "dir\\file.txt", "sha256": "b", "size_bytes": 1},
        ]
    }

    with pytest.raises(ValueError, match="duplicate normalized path"):
        compare_manifests(left, {"files": []})


def test_manifest_comparison_separates_missing_unexpected_and_changed() -> None:
    """Catches hash changes being misreported as both a missing and unexpected file."""
    left = {
        "files": [
            {"path": "missing.txt", "sha256": "a", "size_bytes": 1},
            {"path": "changed.txt", "sha256": "b", "size_bytes": 1},
        ]
    }
    right = {
        "files": [
            {"path": "changed.txt", "sha256": "c", "size_bytes": 2},
            {"path": "unexpected.txt", "sha256": "d", "size_bytes": 1},
        ]
    }

    assert compare_manifests(left, right).to_dict() == {
        "missing": ["missing.txt"],
        "unexpected": ["unexpected.txt"],
        "changed": ["changed.txt"],
    }
