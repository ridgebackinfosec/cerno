"""Guard: the TUI examples in the docs must match what the code renders.

The README previously carried hand-captured screenshots. They went stale within
a release -- by v3 they still showed pre-3.0 labels ("Plugin ID") and bare
finding IDs -- because nothing forced an update. The examples are now generated
by ``scripts/generate_doc_examples.py`` from the bundled demo data, and this
test is what keeps them honest: change a renderer without regenerating and the
suite goes red, naming the command to fix it.

Deliberately a subprocess rather than an in-process import. The generator
redirects ``HOME`` *before* importing ``cerno_pkg``, because
``constants.SCANS_ROOT`` and ``database.DATABASE_PATH`` are resolved at import
time -- in-process it would either pick up the developer's real ``~/.cerno`` or
fight the autouse fixtures that isolate it.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
GENERATOR = REPO_ROOT / "scripts" / "generate_doc_examples.py"


@pytest.mark.slow
@pytest.mark.integration
def test_generated_doc_examples_are_current():
    if not GENERATOR.exists():  # pragma: no cover - generator always shipped
        pytest.skip("generator script not present")

    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode == 2:
        pytest.skip(f"demo fixture unavailable: {result.stderr.strip()[:200]}")

    assert result.returncode == 0, (
        "Documentation examples are out of date.\n\n"
        f"{result.stderr}\n"
        "Regenerate with:  python scripts/generate_doc_examples.py"
    )


@pytest.mark.unit
def test_every_generated_marker_has_a_matching_example():
    """A marker with no example is a silently empty block in the docs."""
    import re

    names_in_docs = set()
    for path in [REPO_ROOT / "README.md", *(REPO_ROOT / "docs").rglob("*.md")]:
        for match in re.finditer(
            r"<!-- BEGIN GENERATED: ([a-z0-9-]+) -->", path.read_text(encoding="utf-8")
        ):
            names_in_docs.add(match.group(1))

    source = GENERATOR.read_text(encoding="utf-8")
    defined = set(re.findall(r'Example\(\s*"([a-z0-9-]+)"', source))

    orphans = names_in_docs - defined
    assert not orphans, (
        f"markers in the docs with no example defined in the generator: "
        f"{sorted(orphans)}"
    )
