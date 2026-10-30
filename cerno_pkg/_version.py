"""Version management for cerno package.

Provides a hybrid approach to reading version:
1. Try the adjacent pyproject.toml (source checkout / editable install)
2. Fall back to importlib.metadata (installed packages: pipx / wheel)
3. Fall back to "unknown" if both fail

pyproject.toml is resolved relative to this file, so it is only found when the
running code lives in the repo (``python cerno.py`` or ``pip install -e .``). In
that case it is the source of truth for the code actually executing, which keeps
``cerno --version`` in sync with the checkout. A pipx/wheel install has no
adjacent pyproject.toml, so it falls through to installed metadata as before.
"""

from pathlib import Path
from typing import Optional


def _get_version_from_metadata() -> Optional[str]:
    """Attempt to get version from installed package metadata.

    Returns:
        Version string if package is installed, None otherwise
    """
    try:
        from importlib.metadata import version

        return version("cerno")
    except Exception:
        # Package not installed or importlib.metadata not available
        return None


def _get_version_from_pyproject() -> Optional[str]:
    """Attempt to read version from pyproject.toml.

    Returns:
        Version string if pyproject.toml exists and is parseable, None otherwise
    """
    try:
        import tomllib

        # Find pyproject.toml relative to this file
        current_file = Path(__file__).resolve()
        pkg_dir = current_file.parent  # cerno_pkg
        repo_root = pkg_dir.parent  # cerno repo root
        pyproject_path = repo_root / "pyproject.toml"

        if not pyproject_path.exists():
            return None

        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
            version = data.get("project", {}).get("version")
            return str(version) if version is not None else None
    except Exception:
        # tomllib not available, file not found, or parsing error
        return None


def get_version() -> str:
    """Get cerno version from the best available source.

    Priority:
    1. pyproject.toml adjacent to this file (source checkout / editable install)
    2. Installed package metadata (importlib.metadata)
    3. "unknown" (fallback)

    Returns:
        Version string (e.g., "1.10.4" or "unknown")
    """
    # Prefer the repo's pyproject.toml when running from a source checkout, so
    # the reported version matches the code actually executing. Only resolvable
    # when pyproject.toml sits next to the package (not in a pipx/wheel install).
    version = _get_version_from_pyproject()
    if version:
        return version

    # Installed package metadata (pipx / wheel installs).
    version = _get_version_from_metadata()
    if version:
        return version

    # Ultimate fallback
    return "unknown"


# Cache the version for performance (read once per process)
__version__ = get_version()
