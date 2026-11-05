"""Packaging guards: what the wheel will actually contain.

setuptools does not auto-discover subpackages, and a `package-data` glob that
matches nothing fails silently — both produce a wheel that imports or runs
differently from the repo. Neither shows up in an editable install, which is how
development and CI run, so nothing else in the suite would notice. These checks
read `pyproject.toml` and the tree directly, so they need no build tooling.
"""

import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)


@pytest.mark.unit
def test_every_package_data_glob_matches_something(pyproject):
    """A glob matching nothing ships a wheel missing those files.

    `demo/*.nessus` does not match `demo/*.json`, so adding the nuclei demo
    fixtures needed its own glob; without one, `cerno demo` would work from a
    git clone and fail for pipx users only.
    """
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    unmatched = []
    for package, globs in package_data.items():
        base = REPO_ROOT / package.replace(".", "/")
        for pattern in globs:
            if not list(base.glob(pattern)):
                unmatched.append(f"{package}:{pattern}")
    assert not unmatched, f"package-data globs matching no files: {unmatched}"


@pytest.mark.unit
def test_every_subpackage_is_declared(pyproject):
    """An undeclared subpackage is a ModuleNotFoundError under pip/pipx."""
    declared = set(pyproject["tool"]["setuptools"]["packages"])
    found = {
        f"cerno_pkg.{d.name}"
        for d in (REPO_ROOT / "cerno_pkg").iterdir()
        if d.is_dir() and (d / "__init__.py").exists()
    } | {"cerno_pkg"}
    missing = found - declared
    assert not missing, (
        f"subpackages present on disk but absent from [tool.setuptools] packages: "
        f"{sorted(missing)} — these would be missing from the wheel"
    )


@pytest.mark.unit
def test_demo_data_is_covered_by_a_glob(pyproject):
    """Every file `cerno demo` needs must match some package-data pattern."""
    globs = pyproject["tool"]["setuptools"]["package-data"]["cerno_pkg"]
    demo_dir = REPO_ROOT / "cerno_pkg" / "demo"
    uncovered = [
        str(f.relative_to(REPO_ROOT / "cerno_pkg"))
        for f in demo_dir.rglob("*")
        if f.is_file()
        and not any(
            f.match(f"cerno_pkg/{g}") or f.relative_to(REPO_ROOT / "cerno_pkg").match(g)
            for g in globs
        )
    ]
    assert not uncovered, f"demo files no package-data glob matches: {uncovered}"
