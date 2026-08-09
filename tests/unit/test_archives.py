import hashlib
import stat
import struct
import zipfile
from pathlib import Path

import pytest

from continuity.archives import ArchivePolicy, inspect_zip, safe_extract_zip


def _write_zip(path: Path, entries: list[tuple[str, bytes]], *, compression: int = zipfile.ZIP_STORED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)


def _set_encryption_flags(path: Path) -> None:
    data = bytearray(path.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (header := data.find(signature, start)) != -1:
            flags = struct.unpack_from("<H", data, header + flag_offset)[0]
            struct.pack_into("<H", data, header + flag_offset, flags | 1)
            start = header + len(signature)
    path.write_bytes(data)


def _set_compressed_size_to_zero(path: Path) -> None:
    data = bytearray(path.read_bytes())
    local_header = data.index(b"PK\x03\x04")
    central_header = data.index(b"PK\x01\x02")
    struct.pack_into("<I", data, local_header + 18, 0)
    struct.pack_into("<I", data, central_header + 20, 0)
    path.write_bytes(data)


def _corrupt_first_payload(path: Path) -> None:
    data = bytearray(path.read_bytes())
    header = data.index(b"PK\x03\x04")
    name_length, extra_length = struct.unpack_from("<HH", data, header + 26)
    payload = header + 30 + name_length + extra_length
    data[payload] ^= 0xFF
    path.write_bytes(data)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "unsafe_name",
    ["../escape.txt", "/absolute.txt", "C:/drive.txt", "..\\escape.txt"],
)
def test_unsafe_paths_are_rejected_before_any_destination_is_created(
    tmp_path: Path, unsafe_name: str
) -> None:
    """Catches extraction of traversal, absolute, drive, or backslash escapes."""
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "output"
    _write_zip(archive_path, [("safe-first.txt", b"safe"), (unsafe_name, b"escape")])

    inspection = safe_extract_zip(archive_path, destination)

    assert inspection.safe is False
    assert any("unsafe path" in violation for violation in inspection.violations)
    assert destination.exists() is False
    assert (tmp_path / "escape.txt").exists() is False


def test_duplicate_normalized_destinations_are_rejected(tmp_path: Path) -> None:
    """Catches a later ZIP member overwriting an earlier normalized destination."""
    archive_path = tmp_path / "duplicate.zip"
    _write_zip(archive_path, [("folder/file.txt", b"one"), ("folder/./file.txt", b"two")])

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("duplicate normalized path" in violation for violation in inspection.violations)


def test_portable_casefold_collisions_follow_policy(tmp_path: Path) -> None:
    """Catches archives that would overwrite files on case-insensitive filesystems."""
    archive_path = tmp_path / "casefold.zip"
    _write_zip(archive_path, [("Readme.txt", b"one"), ("README.TXT", b"two")])

    portable = inspect_zip(archive_path)
    platform_specific = inspect_zip(archive_path, ArchivePolicy(portable_paths=False))

    assert portable.safe is False
    assert any("portable path collision" in violation for violation in portable.violations)
    assert platform_specific.safe is True


def test_symlink_entries_are_rejected(tmp_path: Path) -> None:
    """Catches Unix symlink metadata being extracted as a link escape."""
    archive_path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("link.txt")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(link, "../outside.txt")

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("symbolic link" in violation for violation in inspection.violations)


def test_encrypted_entries_are_rejected(tmp_path: Path) -> None:
    """Catches password-protected members that cannot be completely inspected."""
    archive_path = tmp_path / "encrypted.zip"
    _write_zip(archive_path, [("secret.txt", b"secret")])
    _set_encryption_flags(archive_path)

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("encrypted" in violation for violation in inspection.violations)


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_corrupt_member_payload_is_rejected(tmp_path: Path, compression: int) -> None:
    """Catches inspection that trusts the central directory without verifying member bytes."""
    archive_path = tmp_path / "corrupt.zip"
    _write_zip(archive_path, [("damaged.txt", b"contents")], compression=compression)
    _corrupt_first_payload(archive_path)

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("corrupt" in violation for violation in inspection.violations)


def test_truncated_archive_is_rejected(tmp_path: Path) -> None:
    """Catches incomplete ZIP data being mistaken for an empty or safe archive."""
    archive_path = tmp_path / "truncated.zip"
    _write_zip(archive_path, [("file.txt", b"contents")])
    archive_path.write_bytes(archive_path.read_bytes()[:-8])

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("corrupt" in violation for violation in inspection.violations)


def test_entry_limit_is_enforced(tmp_path: Path) -> None:
    """Catches excessive archive member counts before extraction starts."""
    archive_path = tmp_path / "entries.zip"
    _write_zip(archive_path, [("one.txt", b"1"), ("two.txt", b"2")])

    inspection = inspect_zip(archive_path, ArchivePolicy(max_entries=1))

    assert inspection.safe is False
    assert any("entry limit" in violation for violation in inspection.violations)


def test_per_file_uncompressed_limit_is_enforced(tmp_path: Path) -> None:
    """Catches one oversized member before it can consume destination storage."""
    archive_path = tmp_path / "large-file.zip"
    _write_zip(archive_path, [("large.txt", b"1234")])

    inspection = inspect_zip(archive_path, ArchivePolicy(max_file_size=3))

    assert inspection.safe is False
    assert any("per-file size limit" in violation for violation in inspection.violations)


def test_total_uncompressed_limit_is_enforced(tmp_path: Path) -> None:
    """Catches many individually valid members exceeding the aggregate size budget."""
    archive_path = tmp_path / "large-total.zip"
    _write_zip(archive_path, [("one.txt", b"123"), ("two.txt", b"456")])

    inspection = inspect_zip(archive_path, ArchivePolicy(max_file_size=3, max_total_size=5))

    assert inspection.safe is False
    assert any("total size limit" in violation for violation in inspection.violations)


def test_default_compression_ratio_limit_is_enforced(tmp_path: Path) -> None:
    """Catches highly compressible ZIP bomb members under the default policy."""
    archive_path = tmp_path / "ratio.zip"
    _write_zip(archive_path, [("zeros.bin", b"0" * 200_000)], compression=zipfile.ZIP_DEFLATED)

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("compression ratio limit" in violation for violation in inspection.violations)


def test_nonempty_member_with_zero_compressed_size_has_infinite_ratio(tmp_path: Path) -> None:
    """Catches division workarounds that treat an impossible zero denominator as safe."""
    archive_path = tmp_path / "zero-compressed-size.zip"
    _write_zip(archive_path, [("payload.bin", b"x")])
    _set_compressed_size_to_zero(archive_path)

    inspection = inspect_zip(archive_path)

    assert inspection.safe is False
    assert any("inf" in violation for violation in inspection.violations)


def test_existing_destination_is_never_modified(tmp_path: Path) -> None:
    """Catches atomic publication replacing an existing evidence destination."""
    archive_path = tmp_path / "normal.zip"
    destination = tmp_path / "output"
    destination.mkdir()
    existing = destination / "evidence.txt"
    existing.write_bytes(b"original")
    _write_zip(archive_path, [("evidence.txt", b"replacement")])

    with pytest.raises(FileExistsError):
        safe_extract_zip(archive_path, destination)

    assert existing.read_bytes() == b"original"


def test_normal_archive_is_inspected_and_extracted_without_mutating_source(tmp_path: Path) -> None:
    """Catches inspection or extraction rewriting source evidence or losing file contents."""
    archive_path = tmp_path / "normal.zip"
    destination = tmp_path / "output"
    unrelated_sibling = tmp_path / ".output.continuity-keep"
    unrelated_sibling.mkdir()
    (unrelated_sibling / "marker").write_bytes(b"untouched")
    _write_zip(
        archive_path,
        [("folder/first.txt", b"first"), ("second.bin", b"\x00\x01")],
        compression=zipfile.ZIP_DEFLATED,
    )
    original_hash = _sha256(archive_path)

    inspection = inspect_zip(archive_path)

    assert inspection.safe is True
    assert inspection.violations == ()
    assert [entry.normalized_path for entry in inspection.entries] == [
        "folder/first.txt",
        "second.bin",
    ]
    assert _sha256(archive_path) == original_hash

    extracted = safe_extract_zip(archive_path, destination)

    assert extracted == inspection
    assert (destination / "folder/first.txt").read_bytes() == b"first"
    assert (destination / "second.bin").read_bytes() == b"\x00\x01"
    assert _sha256(archive_path) == original_hash
    assert (unrelated_sibling / "marker").read_bytes() == b"untouched"
