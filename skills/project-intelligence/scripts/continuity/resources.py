"""Access packaged Continuity schemas and document templates."""

from importlib.resources import files
from importlib.resources.abc import Traversable


def asset_file(category: str, filename: str) -> Traversable:
    """Return one installed runtime asset after checking its package location."""

    asset = files("continuity").joinpath("assets", category, filename)
    if not asset.is_file():
        raise ValueError(f"bundled {category} asset is missing: {filename}")
    return asset


def read_asset_text(category: str, filename: str, label: str) -> str:
    """Read a UTF-8 runtime asset through importlib resource traversal."""

    try:
        return asset_file(category, filename).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"bundled {label} is unreadable: {filename}") from error
