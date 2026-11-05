#!/usr/bin/env python3
"""Generate the Cerno TUI examples embedded in the documentation.

The README used to carry hand-captured screenshots. They went stale within a
release and could only be refreshed by hand, so by v3 they still showed
pre-3.0 labels ("Plugin ID") and bare finding IDs. These examples are captured
from the real renderers against the bundled demo data instead, so they track
the code.

Two output shapes, one capture each:

* **SVG** (colour) for ``README.md`` -- Cerno's TUI is heavily colour-coded by
  severity and review state, and a Markdown code block renders monospace but
  monochrome, which loses the thing the screenshots were showing.
* **Plain text** for ``docs/`` -- copy-pasteable, diffable in review, and
  readable where the point is the content rather than the look.

Both are byte-deterministic, which is what lets ``--check`` guard against
drift. Determinism depends on three things, all handled here: a fixed console
width per example, a throwaway ``HOME`` so the demo database is identical every
run, and masking of machine-specific paths.

Usage::

    python scripts/generate_doc_examples.py            # write
    python scripts/generate_doc_examples.py --check    # fail on drift
    python scripts/generate_doc_examples.py --only finding-browser

Content is written between marker pairs, so prose and captions around an
example are hand-owned and never clobbered::

    <!-- BEGIN GENERATED: finding-browser -->
    ...generated...
    <!-- END GENERATED: finding-browser -->
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import io
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# HOME must be redirected BEFORE cerno_pkg is imported: constants.SCANS_ROOT and
# database.DATABASE_PATH are computed at import time from Path.home(), so a late
# override would leave them pointing at the developer's real ~/.cerno.
# ---------------------------------------------------------------------------
_TMP_HOME = Path(tempfile.mkdtemp(prefix="cerno-docgen-"))
os.environ["HOME"] = str(_TMP_HOME)
os.environ["USERPROFILE"] = str(_TMP_HOME)  # Windows equivalent
os.environ["COLUMNS"] = "120"

sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

# ---------------------------------------------------------------------------
# Marker protocol
# ---------------------------------------------------------------------------

BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED: {name} -->"

REGEN_HINT = "python scripts/generate_doc_examples.py"


@dataclass
class Example:
    """One captured renderer output and where it belongs."""

    name: str
    #: Console width. Chosen per example: wide enough that the renderer does not
    #: wrap in a way that obscures the point, narrow enough to read on GitHub.
    width: int
    #: Builds the renderable by calling the real renderer. Receives the demo
    #: context dict.
    capture: Callable[[dict], None]
    #: "svg"      writes docs/images/examples/<name>.svg and injects an <img>
    #: "text"     injects a fenced block of captured terminal output
    #: "markdown" injects the string the callable returns, verbatim
    kind: str = "svg"
    #: Markdown files to inject into.
    targets: list[str] = field(default_factory=list)
    #: SVG window title (the fake terminal titlebar).
    title: str = "cerno"


# ---------------------------------------------------------------------------
# Demo fixture
# ---------------------------------------------------------------------------


def build_demo_context() -> dict:
    """Import the bundled demo scans and return handles the captures need.

    Uses the same path `cerno demo` does, so the examples show exactly what an
    operator sees after running it.
    """
    from cerno_pkg.database import get_connection, initialize_database
    from cerno_pkg.models import Finding, Scan

    initialize_database()

    import cerno

    # The demo command narrates its progress; that is noise here, and it would
    # otherwise interleave with --check's diff output.
    with contextlib.redirect_stdout(io.StringIO()):
        cerno.demo_cmd(overwrite=True, no_nxc=False)

    conn = get_connection()
    scans = {s["scan_name"]: s["scan_id"] for s in Scan.get_all_with_stats(conn)}
    nessus_id = scans["Cerno_Demo_Expanded_Scan"]
    nuclei_id = scans["Cerno_Demo_Nuclei_Expanded_Scan"]

    return {
        "conn": conn,
        "scans": scans,
        "nessus_scan_id": nessus_id,
        "nuclei_scan_id": nuclei_id,
        "nessus_findings": Finding.get_by_scan_with_plugin(nessus_id, conn=conn),
        "nuclei_findings": Finding.get_by_scan_with_plugin(nuclei_id, conn=conn),
    }


# ---------------------------------------------------------------------------
# Masking: anything machine- or run-specific must not reach the docs
# ---------------------------------------------------------------------------

#: Timestamps would differ on every run and break --check.
#:
#: Deliberately unanchored: a \b before the year fails when Rich's style codes
#: sit immediately in front of it, because they end in "m" and a digit follows,
#: so there is no word boundary. That silently left table cells unmasked while
#: the surrounding prose was masked.
_DATE_RE = re.compile(r"20\d{2}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?")


def mask(text: str) -> str:
    """Replace machine-specific values with stable placeholders."""
    text = text.replace(str(_TMP_HOME), "~")
    text = text.replace(str(REPO_ROOT), "/path/to/cerno")
    return _DATE_RE.sub("2026-01-01", text)


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

#: Modules whose _console_global must be swapped. The renderers look it up at
#: call time, which is what makes capture possible at all.
_CONSOLE_MODULES = (
    "cerno",
    "cerno_pkg.render",
    "cerno_pkg.fs",
    "cerno_pkg.analysis",
    "cerno_pkg.tui",
    "cerno_pkg.tools",
    "cerno_pkg.session",
)


def capture(example: Example, ctx: dict) -> tuple[str, str]:
    """Run one example's renderer and return ``(plain_text, svg)``.

    Output arrives by two routes that have to end up interleaved correctly: Rich
    renderables go through each module's ``_console_global``, while
    ``ansi.info()``/``ok()``/``warn()`` use a plain ``print``. Pointing both at
    one buffer is what keeps, say, a table and the ``info()`` line beneath it in
    the order an operator sees them. The SVG is then re-rendered from that
    captured ANSI, so it shows exactly what the text does.

    A ``markdown`` example is the exception: it produces Markdown rather than
    terminal output, so its callable *returns* the string instead of printing,
    and there is no SVG to render.
    """
    import importlib

    if example.kind == "markdown":
        return mask(example.capture(ctx) or ""), ""

    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=example.width,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )

    modules = [importlib.import_module(m) for m in _CONSOLE_MODULES]
    saved = [getattr(m, "_console_global", None) for m in modules]

    # Some renderers offer an interactive continuation (render.py's [H] group
    # pager, for one). With no TTY those block forever, so answer every prompt
    # with its default -- which is the "just show me the summary" path, and the
    # one a reader of the docs wants to see anyway. Patched on the class, so it
    # applies however a module imported Prompt.
    from rich.prompt import Prompt
    from rich.text import Text

    original_ask = Prompt.ask

    def _auto_answer(*args, **kwargs):
        return kwargs.get("default", "")

    try:
        Prompt.ask = _auto_answer  # type: ignore[method-assign]
        for m in modules:
            if hasattr(m, "_console_global"):
                m._console_global = console
        with contextlib.redirect_stdout(buffer):
            example.capture(ctx)
    finally:
        Prompt.ask = original_ask  # type: ignore[method-assign]
        for m, old in zip(modules, saved):
            if old is not None:
                m._console_global = old

    raw = mask(buffer.getvalue())
    ansi = Text.from_ansi(raw)

    svg_console = Console(
        file=io.StringIO(),
        record=True,
        width=example.width,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    svg_console.print(ansi, end="")

    return ansi.plain, svg_console.export_svg(title=example.title)


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------


def render_block(example: Example, text: str) -> str:
    """The Markdown that goes between the markers."""
    if example.kind == "svg":
        return (
            f'<p align="center">\n'
            f'  <img src="docs/images/examples/{example.name}.svg" '
            f'alt="{example.title}" width="100%">\n'
            f"</p>"
        )
    if example.kind == "markdown":
        return text.rstrip("\n")
    return "```text\n" + text.rstrip("\n") + "\n```"


def inject(path: Path, name: str, block: str) -> Optional[str]:
    """Replace the marked region in ``path``; return the new text or None.

    None means the markers are absent -- a configuration error worth reporting
    rather than silently skipping, since it means an example is generated but
    never shown.
    """
    if not path.exists():
        return None
    source = path.read_text(encoding="utf-8")
    begin, end = BEGIN.format(name=name), END.format(name=name)
    if begin not in source or end not in source:
        return None
    pattern = re.compile(
        re.escape(begin) + r".*?" + re.escape(end),
        re.DOTALL,
    )
    return pattern.sub(f"{begin}\n{block}\n{end}", source, count=1)


# ---------------------------------------------------------------------------
# The examples
#
# Each calls a real renderer, so an example can only go stale if the renderer
# changes -- at which point --check fails and regeneration fixes it.
# ---------------------------------------------------------------------------


def _host_counter(ctx: dict):
    """Real host counts per finding, mirroring `cerno.py`'s `get_counts_for`.

    A stub returning a constant would put fabricated numbers in the README,
    which is worse than the stale screenshot it replaces.
    """
    from cerno_pkg.database import query_one

    def counts(finding) -> tuple[int, str]:
        if finding.finding_id is None:
            return (0, "")
        row = query_one(
            ctx["conn"],
            "SELECT COUNT(DISTINCT host_id) FROM finding_affected_hosts "
            "WHERE finding_id = ?",
            (finding.finding_id,),
        )
        return (row[0] if row else 0, "")

    return counts


def _severity_menu(ctx: dict) -> None:
    """The review entry point: findings by severity, with review progress."""
    from cerno_pkg.constants import SCANS_ROOT
    from cerno_pkg.models import Finding
    from cerno_pkg.render import render_severity_table

    scan_id = ctx["nessus_scan_id"]
    names = Finding.get_severity_dirs_for_scan(scan_id, conn=ctx["conn"])
    scan_dir = SCANS_ROOT / "Cerno_Demo_Expanded_Scan"
    render_severity_table([scan_dir / n for n in names], scan_id=scan_id)


def _finding_browser(ctx: dict) -> None:
    """The core screen, deliberately mixing both scanners.

    A single-source page would hide the thing that matters most in v3: ids are
    namespaced and two scanners' findings sit side by side.
    """
    from cerno_pkg.render import render_finding_list_table

    rows = ctx["nuclei_findings"][:4] + ctx["nessus_findings"][:4]
    render_finding_list_table(
        rows,
        "severity",
        _host_counter(ctx),
        show_severity=True,
    )


def _finding_detail(ctx: dict) -> None:
    """The finding panel, on a nuclei finding so the template link shows."""
    from pathlib import Path as _Path

    from cerno_pkg.render import display_finding_preview
    from cerno_pkg.workflow_mapper import WorkflowMapper

    finding, plugin = next(
        fp for fp in ctx["nuclei_findings"] if "CVE-2021-44228" in str(fp[1].plugin_id)
    )
    display_finding_preview(
        plugin, finding, None, _Path(str(plugin.plugin_id)), WorkflowMapper()
    )


def _scan_list(ctx: dict) -> None:
    """`cerno scan list` -- the Source column at a glance."""
    import cerno

    cerno.list_scans(wide=False, json_output=False)


def _host_comparison(ctx: dict) -> None:
    """`[H]` -- findings grouped by identical host:port coverage."""
    from cerno_pkg.analysis import compare_filtered

    compare_filtered(ctx["nessus_findings"][:8], conn=ctx["conn"])


def _superset_analysis(ctx: dict) -> None:
    """`[O]` -- which findings' host:port sets cover which others."""
    from cerno_pkg.analysis import analyze_inclusions

    analyze_inclusions(ctx["nessus_findings"][:8], conn=ctx["conn"])


def _tool_menu(ctx: dict) -> None:
    """The `[T]` tool menu, which now includes nuclei.

    The real table probes the local PATH and reads each binary's version, so
    captured unstubbed it documents whatever happens to be installed on the
    machine that ran the generator -- it would differ on CI, on another
    developer's box, and the day someone installs a tool. Stubbed to show the
    menu an operator with the tools installed sees, which is the useful
    illustration and is the same everywhere.
    """
    import shutil

    from cerno_pkg import ops
    from cerno_pkg.render import render_tool_availability_table

    real_which, real_version = shutil.which, ops.get_tool_version
    try:
        shutil.which = lambda cmd, *a, **k: f"/usr/bin/{cmd}"
        ops.get_tool_version = lambda name, requires=None: _DEMO_TOOL_VERSIONS.get(
            name, "1.0.0"
        )
        render_tool_availability_table(include_unavailable=True)
    finally:
        shutil.which, ops.get_tool_version = real_which, real_version


#: Fixed versions for the tool-availability example. Illustrative, not probed.
_DEMO_TOOL_VERSIONS = {
    "nmap": "7.95",
    "netexec": "1.5.1",
    "nuclei": "3.4.10",
    "metasploit": "6.4.0",
}


def _workflow_display(ctx: dict) -> None:
    """`[W]` on the cross-source workflow: one entry, two scanners."""
    from cerno_pkg.fs import display_workflow
    from cerno_pkg.workflow_mapper import WorkflowMapper

    workflow = WorkflowMapper().get_workflow("nuclei:http-missing-security-headers")
    assert workflow is not None, "the bundled cross-source workflow is missing"
    display_workflow(workflow)


def _config_table(ctx: dict) -> str:
    """The full settings reference, built from the dataclass itself.

    Returns Markdown rather than printing: ``config.build_config_rows()`` is
    already the single source ``cerno config show`` renders from, so deriving
    the table from it means the doc and the command cannot disagree about which
    settings exist. The hand-maintained version of this table was found six keys
    stale while still claiming to list every setting.

    Grouped by the same ``section`` metadata the command groups by, in field
    order, so the two read the same way.
    """
    from cerno_pkg.config import CernoConfig, build_config_rows

    def cell(text: object) -> str:
        """Escape what would otherwise break out of a Markdown table row."""
        return str(text).replace("|", "\\|").replace("\n", " ")

    lines = ["| Setting | Default | Purpose |", "| --- | --- | --- |"]
    current_section = None
    for section, key, value, _is_default, help_text in build_config_rows(CernoConfig()):
        if section != current_section:
            lines.append(f"| **{cell(section)}** | | |")
            current_section = section
        lines.append(f"| `{cell(key)}` | `{cell(value)}` | {cell(help_text)} |")
    return "\n".join(lines)


def _config_show(ctx: dict) -> None:
    """`cerno config show` -- backs README's claim that its table matches."""
    import cerno

    cerno.config_show()


def _scan_history(ctx: dict) -> None:
    """`cerno scan history` across two scanners.

    Shows the Source column and the Trend reading `n/a` where the sources
    differ -- the guard against claiming remediation that never happened.
    """
    from cerno_pkg.cross_scan import get_host_vulnerability_history
    from cerno_pkg.render import render_host_history

    history = get_host_vulnerability_history("198.51.100.10", ctx["conn"])
    assert history is not None, "demo host 198.51.100.10 is missing from the fixture"
    render_host_history(history)


EXAMPLES: list[Example] = [
    Example(
        "severity-selection",
        100,
        _severity_menu,
        targets=["README.md"],
        title="cerno review",
    ),
    Example(
        "finding-browser",
        110,
        _finding_browser,
        targets=["README.md"],
        title="cerno review - findings",
    ),
    Example(
        "finding-detail",
        100,
        _finding_detail,
        targets=["README.md"],
        title="cerno review - finding detail",
    ),
    Example(
        "scan-list", 100, _scan_list, targets=["README.md"], title="cerno scan list"
    ),
    Example(
        "host-comparison",
        110,
        _host_comparison,
        targets=["README.md"],
        title="cerno review - [H] compare",
    ),
    Example(
        "superset-analysis",
        110,
        _superset_analysis,
        targets=["README.md"],
        title="cerno review - [O] overlap",
    ),
    Example(
        "tool-orchestration",
        90,
        _tool_menu,
        targets=["README.md"],
        title="cerno review - [T] tools",
    ),
    Example(
        "workflow-display",
        100,
        _workflow_display,
        targets=["README.md"],
        title="cerno review - [W] workflow",
    ),
    # Plain text, where copy-paste and diffability matter more than colour.
    # Markdown, not terminal output: the reference table is generated from the
    # same rows `cerno config show` renders, so the two cannot disagree about
    # which settings exist.
    Example(
        "config-table",
        100,
        _config_table,
        kind="markdown",
        targets=["docs/CONFIGURATION.md"],
    ),
    Example(
        "config-show",
        100,
        _config_show,
        kind="text",
        targets=["docs/CONFIGURATION.md"],
    ),
    Example(
        "scan-history", 110, _scan_history, kind="text", targets=["docs/demo/README.md"]
    ),
]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any generated content is out of date",
    )
    parser.add_argument("--only", help="generate a single example by name")
    args = parser.parse_args(argv)

    examples = [e for e in EXAMPLES if not args.only or e.name == args.only]
    if args.only and not examples:
        print(f"No such example: {args.only}", file=sys.stderr)
        return 2

    try:
        ctx = build_demo_context()
    except Exception as exc:  # pragma: no cover - setup failure
        print(f"Could not build the demo fixture: {exc}", file=sys.stderr)
        return 2

    svg_dir = REPO_ROOT / "docs" / "images" / "examples"
    svg_dir.mkdir(parents=True, exist_ok=True)

    stale: list[str] = []
    missing_markers: list[str] = []

    for example in examples:
        text, svg = capture(example, ctx)

        if example.kind == "svg":
            svg_path = svg_dir / f"{example.name}.svg"
            current = (
                svg_path.read_text(encoding="utf-8") if svg_path.exists() else None
            )
            if current != svg:
                if args.check:
                    stale.append(f"{svg_path.relative_to(REPO_ROOT)} (rendered SVG)")
                else:
                    svg_path.write_text(svg, encoding="utf-8")

        block = render_block(example, text)
        for target in example.targets:
            path = REPO_ROOT / target
            updated = inject(path, example.name, block)
            if updated is None:
                missing_markers.append(f"{target}: no markers for '{example.name}'")
                continue
            if updated != path.read_text(encoding="utf-8"):
                if args.check:
                    stale.append(f"{target} ({example.name})")
                    diff = difflib.unified_diff(
                        path.read_text(encoding="utf-8").splitlines(),
                        updated.splitlines(),
                        fromfile=f"{target} (committed)",
                        tofile=f"{target} (current)",
                        lineterm="",
                        n=1,
                    )
                    print("\n".join(list(diff)[:40]), file=sys.stderr)
                else:
                    path.write_text(updated, encoding="utf-8")

    for problem in missing_markers:
        print(f"warning: {problem}", file=sys.stderr)

    if args.check and stale:
        print(
            "\nDocumentation examples are out of date:\n  "
            + "\n  ".join(stale)
            + f"\n\nRegenerate with:  {REGEN_HINT}",
            file=sys.stderr,
        )
        return 1

    if not args.check:
        print(f"Generated {len(examples)} example(s).")
    return 1 if missing_markers else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        shutil.rmtree(_TMP_HOME, ignore_errors=True)
