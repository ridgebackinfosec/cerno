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
@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Generated examples are POSIX-shaped: Windows renders the masked paths "
        "with backslash separators, so byte-identical output across all three "
        "OSes is not achievable. The check exists to catch a maintainer "
        "forgetting to regenerate, and `bcp` runs on Linux."
    ),
)
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


#: Characters a Rich table line can start with (borders and row bodies).
_BOX_START = "┏┡├└│┃┌┠┣┗"


@pytest.mark.unit
def test_generated_table_borders_line_up():
    """A generated table whose rows are not all the same width is corrupted.

    The drift check only compares against the committed file, so it happily
    enforced a *corrupted* capture: masking machine-specific paths after Rich had
    already laid the table out shortened individual lines, and v3.3.1 shipped
    ``docs/CONFIGURATION.md`` with ``results_root`` reading ``~/.cerno/ar`` +
    ``tifacts`` and borders that did not meet. Equal line width is the invariant
    that catches that, independent of whatever happens to be committed.
    """
    import re

    text = (REPO_ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    block = re.search(
        r"<!-- BEGIN GENERATED: config-show -->(.*?)<!-- END GENERATED: config-show -->",
        text,
        re.DOTALL,
    )
    assert block is not None, "config-show generated block is missing"

    widths: dict[int, list[str]] = {}
    for line in block.group(1).splitlines():
        if line and line[0] in _BOX_START:
            widths.setdefault(len(line), []).append(line)

    assert widths, "no table lines found in the config-show block"
    assert len(widths) == 1, (
        "generated table lines have differing widths "
        f"{sorted(widths)} -- the table is misaligned. Sample of each width:\n"
        + "\n".join(f"  {w}: {lines[0]}" for w, lines in sorted(widths.items()))
        + "\n\nRegenerate with:  python scripts/generate_doc_examples.py"
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
