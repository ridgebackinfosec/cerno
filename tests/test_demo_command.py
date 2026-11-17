"""Tests for bundled demo setup helpers."""

import hashlib
from pathlib import Path

import pytest

#: Every scan file `cerno demo` imports. Both demo trees must carry all of them.
DEMO_ASSETS = (
    "cerno-demo-initial.nessus",
    "cerno-demo-expanded.nessus",
    "cerno-demo-nuclei-initial.json",
    "cerno-demo-nuclei-expanded.json",
    "cerno-demo-burp-scan.xml",
)


def test_repo_root_detects_checkout_root():
    """The demo command should derive paths from the checkout, not CWD."""
    import cerno

    repo_root = cerno._repo_root()  # type: ignore[attr-defined]

    assert (repo_root / "pyproject.toml").is_file()
    assert (repo_root / "cerno.py").is_file()
    assert (repo_root / "cerno_pkg").is_dir()


def test_demo_assets_dir_is_independent_of_cwd(monkeypatch, tmp_path: Path):
    """Changing directories should not affect where demo assets are found."""
    import cerno

    monkeypatch.chdir(tmp_path)

    assets_dir = cerno._demo_assets_dir()  # type: ignore[attr-defined]

    assert assets_dir == cerno._repo_root() / "docs" / "demo"  # type: ignore[attr-defined]
    for asset in DEMO_ASSETS:
        assert (assets_dir / asset).is_file(), asset


def test_demo_assets_dir_falls_back_to_packaged_assets(monkeypatch, tmp_path: Path):
    """Installed commands should find demo assets even without repository docs."""
    import cerno

    monkeypatch.setattr(cerno, "_repo_root", lambda: tmp_path)

    assets_dir = cerno._demo_assets_dir()  # type: ignore[attr-defined]

    assert "cerno_pkg" in assets_dir.parts
    for asset in DEMO_ASSETS:
        assert (assets_dir / asset).is_file(), asset
    assert (assets_dir / "nxc-workspace" / "smb.db").is_file()


@pytest.mark.parametrize("asset", DEMO_ASSETS)
def test_demo_trees_are_byte_identical(asset: str):
    """`docs/demo/` and `cerno_pkg/demo/` are two copies of the same assets.

    `_demo_assets_dir()` prefers the repo copy and falls back to the packaged
    one, so a checkout and a pipx install must see identical demo data. Nothing
    but this test enforces that: regenerating a fixture and forgetting to copy
    it across would otherwise ship silently.
    """
    import cerno

    repo_root = cerno._repo_root()  # type: ignore[attr-defined]
    docs_copy = repo_root / "docs" / "demo" / asset
    package_copy = repo_root / "cerno_pkg" / "demo" / asset

    assert docs_copy.is_file(), docs_copy
    assert package_copy.is_file(), package_copy
    assert hashlib.sha256(docs_copy.read_bytes()).hexdigest() == (
        hashlib.sha256(package_copy.read_bytes()).hexdigest()
    ), f"{asset} differs between docs/demo and cerno_pkg/demo"


def test_demo_nuclei_assets_match_package_data_glob():
    """A new demo file type must also match a package-data glob.

    `demo/*.nessus` does not match `.json`, so without the extra glob the nuclei
    fixtures ship in the sdist but are missing from the wheel -- broken for
    pipx/pip users only, and invisible in a checkout.
    """
    import tomllib

    import cerno

    repo_root = cerno._repo_root()  # type: ignore[attr-defined]
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text())
    globs = pyproject["tool"]["setuptools"]["package-data"]["cerno_pkg"]

    assert "demo/*.json" in globs
    assert "demo/*.nessus" in globs
