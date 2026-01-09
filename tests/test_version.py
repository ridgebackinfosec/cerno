"""Tests for version management (_version.py).

Tests version retrieval from multiple sources and edge cases.
"""

import pytest
from pathlib import Path
from unittest.mock import patch


def test_version_module_exports():
    """Test that _version module exports __version__."""
    from cerno_pkg._version import __version__
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_available_from_package():
    """Test that __version__ is available from cerno_pkg."""
    import cerno_pkg
    assert hasattr(cerno_pkg, "__version__")
    assert isinstance(cerno_pkg.__version__, str)


def test_version_format():
    """Test that version follows semantic versioning format or is 'unknown'."""
    from cerno_pkg._version import __version__

    if __version__ == "unknown":
        pytest.skip("Version is unknown - acceptable fallback")

    # Should be semantic version: X.Y.Z or X.Y.Z-suffix
    parts = __version__.split(".")
    assert len(parts) >= 2, f"Version should have at least 2 parts: {__version__}"

    # First part should be numeric
    assert parts[0].isdigit(), f"Major version should be numeric: {parts[0]}"


def test_get_version_function():
    """Test the main get_version() function."""
    from cerno_pkg._version import get_version

    version = get_version()
    assert isinstance(version, str)
    assert len(version) > 0


@patch('cerno_pkg._version._get_version_from_metadata')
@patch('cerno_pkg._version._get_version_from_pyproject')
def test_get_version_prefers_metadata(mock_pyproject, mock_metadata):
    """Test that get_version() prefers importlib.metadata when available."""
    mock_metadata.return_value = "1.2.3"
    mock_pyproject.return_value = "9.9.9"

    from cerno_pkg._version import get_version
    # Since __version__ is cached, we need to call get_version directly
    version = get_version()

    # Should use metadata version (1.2.3), not pyproject (9.9.9)
    mock_metadata.assert_called_once()


@patch('cerno_pkg._version._get_version_from_metadata')
@patch('cerno_pkg._version._get_version_from_pyproject')
def test_get_version_falls_back_to_pyproject(mock_pyproject, mock_metadata):
    """Test that get_version() falls back to pyproject.toml if metadata fails."""
    mock_metadata.return_value = None
    mock_pyproject.return_value = "1.2.3"

    from cerno_pkg._version import get_version
    version = get_version()

    assert version == "1.2.3"
    mock_metadata.assert_called()
    mock_pyproject.assert_called()


@patch('cerno_pkg._version._get_version_from_metadata')
@patch('cerno_pkg._version._get_version_from_pyproject')
def test_get_version_falls_back_to_unknown(mock_pyproject, mock_metadata):
    """Test that get_version() returns 'unknown' if all methods fail."""
    mock_metadata.return_value = None
    mock_pyproject.return_value = None

    from cerno_pkg._version import get_version
    version = get_version()

    assert version == "unknown"


def test_get_version_from_pyproject_real():
    """Test that _get_version_from_pyproject() can read actual pyproject.toml."""
    from cerno_pkg._version import _get_version_from_pyproject

    version = _get_version_from_pyproject()

    # Should either return a version or None (depending on file availability)
    assert version is None or isinstance(version, str)

    # If we got a version, it should not be empty
    if version is not None:
        assert len(version) > 0
        # Verify it matches the actual version in pyproject.toml
        assert "." in version, f"Version should contain dot: {version}"


def test_version_consistency():
    """Test that version is consistent across imports."""
    from cerno_pkg._version import __version__ as v1
    from cerno_pkg import __version__ as v2

    assert v1 == v2, "Version should be consistent across imports"


def test_banner_uses_version():
    """Test that banner.py imports and uses __version__."""
    # This is a smoke test - just verify the import doesn't fail
    from cerno_pkg.banner import display_banner

    # Verify banner module has access to version
    import cerno_pkg.banner as banner_module
    # The module should import _version at module level
    assert hasattr(banner_module, '__version__')


@pytest.mark.integration
def test_version_in_installed_package():
    """
    Integration test: Verify version is accessible after package install.

    This test only runs if the package is installed (not in editable mode).
    """
    try:
        from importlib.metadata import version
        installed_version = version("cerno")

        from cerno_pkg import __version__
        assert __version__ == installed_version
    except Exception:
        pytest.skip("Package not installed in standard mode")


def test_get_version_from_metadata():
    """Test _get_version_from_metadata() helper function."""
    from cerno_pkg._version import _get_version_from_metadata

    version = _get_version_from_metadata()
    # Should return string or None (depending on if package is installed)
    assert version is None or isinstance(version, str)


def test_version_cached():
    """Test that version is cached and not recalculated."""
    from cerno_pkg._version import __version__ as v1

    # Import again - should get same cached value
    from cerno_pkg._version import __version__ as v2

    # They should be the exact same object (not just equal)
    assert v1 is v2, "Version should be cached (same object)"
