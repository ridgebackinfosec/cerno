"""Version management for cerno package.

Provides a hybrid approach to reading version:
1. Try importlib.metadata (for installed packages)
2. Fall back to parsing pyproject.toml (for development)
3. Fall back to "unknown" if both fail
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
            return data.get("project", {}).get("version")
    except Exception:
        # tomllib not available, file not found, or parsing error
        return None


def get_version() -> str:
    """Get cerno version from the best available source.

    Priority:
    1. Installed package metadata (importlib.metadata)
    2. pyproject.toml parsing (development mode)
    3. "unknown" (fallback)

    Returns:
        Version string (e.g., "1.10.4" or "unknown")
    """
    # Try installed package metadata first (fastest for production)
    version = _get_version_from_metadata()
    if version:
        return version

    # Fall back to parsing pyproject.toml (development mode)
    version = _get_version_from_pyproject()
    if version:
        return version

    # Ultimate fallback
    return "unknown"


# Cache the version for performance (read once per process)
__version__ = get_version()
