"""Tests for the CLI flag surface after the config-key migration.

Every flag that duplicated a config key, or encoded a standing preference with
no key behind it, was removed; ``config.yaml`` is now the only way to express
those. These tests pin that surface down from two sides:

* each removed flag spelling is rejected, so the surface cannot quietly grow
  back (or go quiet by being accepted and ignored, which is how
  ``--export-root`` survived for releases after it stopped doing anything);
* each replacement key actually changes behaviour.

The flags that remain take a per-invocation value -- a filename, an output
channel, a one-off action -- and are not preferences.
"""

from __future__ import annotations

import re

import pytest
import yaml
from typer.testing import CliRunner

from cerno_pkg import config as config_mod

#: Typer force-enables color when ``GITHUB_ACTIONS`` (or ``FORCE_COLOR`` /
#: ``PY_COLORS``) is set, so help output in CI is styled even though
#: ``CliRunner`` captures to a non-tty. Rich then emits an option name as two
#: styled spans -- ``\x1b[1;36m-\x1b[0m\x1b[1;36m-name\x1b[0m`` -- and the flag
#: stops being a literal substring. Assert against the de-styled text instead:
#: these tests pin the *surface*, not its colors. ``ansi.strip_unsafe_escapes()``
#: is deliberately not reused here -- it keeps SGR by design.
_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Drop SGR color codes so flag spellings match as written."""
    return _SGR_RE.sub("", text)


#: (argv, flag) for every flag spelling removed in the 3.4.0 surface cleanup.
REMOVED_FLAGS = [
    (["review"], "--export-root"),
    (["review"], "-r"),
    (["review"], "--no-tools"),
    (["review"], "--custom-workflows"),
    (["review"], "-w"),
    (["review"], "--custom-workflows-only"),
    (["review"], "--quiet"),
    (["review"], "-q"),
    (["review"], "--check"),
    (["review"], "--proxy"),
    (["review"], "--no-proxy"),
    (["workflow", "list"], "--custom-workflows"),
    (["workflow", "list"], "-w"),
    (["dataset", "list"], "--wide"),
    (["dataset", "list"], "--details"),
    (["import", "nuclei"], "--min-severity"),
]

#: Flags that are per-invocation data and must survive.
KEPT_FLAGS = [
    (["import", "nuclei"], "--name"),
    (["import", "burp"], "--name"),
    (["dataset", "list"], "--json"),
    (["dataset", "compare"], "--severity"),
    (["dataset", "compare"], "-s"),
    (["demo"], "--overwrite"),
    (["demo"], "--no-nxc"),
]


def _write_config(**values) -> None:
    """Write values into the test-isolated config file (see conftest)."""
    config_mod.get_config_path().write_text(yaml.safe_dump(values), encoding="utf-8")


@pytest.mark.integration
@pytest.mark.parametrize(
    "argv,flag", REMOVED_FLAGS, ids=[f"{' '.join(a)} {f}" for a, f in REMOVED_FLAGS]
)
def test_removed_flag_is_rejected(argv, flag):
    """A removed flag must error, not be silently accepted and ignored."""
    from cerno import app

    result = CliRunner().invoke(app, [*argv, flag])

    assert result.exit_code != 0, f"{' '.join(argv)} still accepts {flag}"
    assert "No such option" in _plain(result.output), result.output


@pytest.mark.integration
@pytest.mark.parametrize(
    "argv,flag", KEPT_FLAGS, ids=[f"{' '.join(a)} {f}" for a, f in KEPT_FLAGS]
)
def test_kept_flag_is_still_documented(argv, flag):
    """Per-invocation flags stay on the command's --help."""
    from cerno import app

    result = CliRunner().invoke(app, [*argv, "--help"])

    assert result.exit_code == 0, result.output
    # Rich wraps long help lines, so match the flag token itself.
    assert flag in _plain(result.output).replace("\n", " "), result.output


@pytest.mark.integration
def test_review_takes_no_options():
    """`cerno review` is entirely config-driven now."""
    from cerno import app

    result = CliRunner().invoke(app, ["review", "--help"])

    assert result.exit_code == 0, result.output
    options = _plain(result.output).split("Options")[-1]
    # --help is the only remaining entry.
    assert options.count("--") == 1, options


@pytest.mark.integration
def test_check_is_its_own_command():
    """`review --check` became `cerno check`, discoverable at the top level."""
    from cerno import app

    runner = CliRunner()
    assert "check" in runner.invoke(app, ["--help"]).output

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0, result.output
    assert "Tool Availability" in result.output


# ---------------------------------------------------------------------------
# The replacement keys change behaviour
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_new_preference_keys_have_expected_defaults():
    """Defaults must preserve the behaviour of running with no flags before."""
    cfg = config_mod.CernoConfig()

    assert cfg.show_banner is True  # banner shown unless -q was passed
    assert cfg.tools_enabled is True  # tools offered unless --no-tools
    assert cfg.dataset_list_wide is False  # compact unless --wide
    assert cfg.custom_workflows_exclusive is False  # supplement, not replace
    assert cfg.nuclei_min_severity == 0  # keep every severity


@pytest.mark.integration
@pytest.mark.parametrize("enabled", [True, False])
def test_show_banner_gates_the_banner(enabled, monkeypatch):
    """show_banner replaces `review -q`.

    Driven through the real CLI entry point rather than calling ``review()``
    directly: ``get_current_config()`` prefers the contextvar that
    ``main_callback`` populates, so a direct call would read whatever config a
    previous invocation happened to leave there.
    """
    import cerno

    _write_config(show_banner=enabled)
    calls: list[int] = []
    monkeypatch.setattr(cerno, "display_banner", lambda: calls.append(1))
    # Stop before the interactive review; the banner decision is already made.
    monkeypatch.setattr(cerno, "main", lambda: None)

    result = CliRunner().invoke(cerno.app, ["review"])

    assert result.exit_code == 0, result.output
    assert bool(calls) is enabled


@pytest.mark.integration
@pytest.mark.parametrize("enabled", [True, False])
def test_tools_enabled_controls_the_run_tool_action(enabled, capsys, monkeypatch):
    """tools_enabled replaces `review --no-tools` for the [T] action."""
    from cerno_pkg.render import render_finding_actions_footer

    monkeypatch.setenv("COLUMNS", "120")
    _write_config(tools_enabled=enabled)
    cfg = config_mod.load_config()
    assert cfg.tools_enabled is enabled

    # fs.handle_finding_view passes exactly this expression to the footer.
    render_finding_actions_footer(no_tools=not cfg.tools_enabled)
    footer = capsys.readouterr().out.replace("\n", " ")

    assert ("Run tool" in footer) is enabled, footer


@pytest.mark.integration
def test_tools_disabled_refuses_an_explicit_t(monkeypatch, capsys):
    """Typing 't' must be refused too, not merely hidden from the footer.

    The footer only hides the action; without the guard in
    ``fs.handle_finding_view`` an operator who knows the key could still start
    a tool run in review-only mode.
    """
    from cerno_pkg import fs

    _write_config(tools_enabled=False)

    answers = iter(["t", "b"])
    monkeypatch.setattr("cerno_pkg.fs.Prompt.ask", lambda *a, **k: next(answers))
    # handle_finding_view imports these inside the function, so patch the source
    # modules rather than attributes on fs.
    monkeypatch.setattr("cerno_pkg.nxc_db.get_nxc_manager", lambda: None)

    def _fail(*a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("run_tool_workflow was reached with tools disabled")

    monkeypatch.setattr("cerno_pkg.tools.run_tool_workflow", _fail)

    result = fs.handle_finding_view(
        chosen=config_mod.get_config_path().parent / "nessus_100.txt",
        hosts=["10.0.0.1"],
        ports_str="445",
    )

    assert result == "back"
    assert "tools_enabled" in capsys.readouterr().out.replace("\n", " ")


@pytest.mark.integration
def test_burp_min_severity_is_validated_before_import(tmp_path):
    """A hand-edited out-of-range value is refused, not silently ignored."""
    from cerno import app

    report = tmp_path / "report.xml"
    report.write_text("<issues></issues>", encoding="utf-8")
    _write_config(burp_min_severity=9)

    result = CliRunner().invoke(app, ["import", "burp", str(report)])

    assert result.exit_code == 1, result.output
    assert "burp_min_severity" in result.output


@pytest.mark.integration
def test_burp_import_rejects_a_non_xml_file(tmp_path):
    """.nessus and .json files go to their own importers."""
    from cerno import app

    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")

    result = CliRunner().invoke(app, ["import", "burp", str(report)])

    assert result.exit_code == 1, result.output
    assert ".xml" in result.output


@pytest.mark.integration
def test_nuclei_min_severity_is_validated_before_import(tmp_path):
    """A hand-edited out-of-range value is refused, not silently ignored."""
    from cerno import app

    results = tmp_path / "results.json"
    results.write_text("[]", encoding="utf-8")
    _write_config(nuclei_min_severity=9)

    result = CliRunner().invoke(app, ["import", "nuclei", str(results)])

    assert result.exit_code == 1, result.output
    assert "nuclei_min_severity" in result.output


# ---------------------------------------------------------------------------
# The 4.0.0 vocabulary reaches the terminal
# ---------------------------------------------------------------------------

#: Phrases that can only mean the *container* (a named body of findings) or a
#: command that no longer exists. Each is retired as of 4.0.0.
#:
#: Deliberately **not** listed, because they mean something else and must
#: survive: ``scan_target`` (the string a scanner was pointed at), "remote
#: scan" / "Remote Scan" (nmap really does scan from a pivot), "scanner" /
#: "Burp Scanner", "UDP Scan" (an nmap scan type), "a Nessus scan" (a real
#: scan you run), and ``scan.nessus`` (a scanner export's filename).
RETIRED_OUTPUT_PHRASES = [
    # NOTE: these are the *retired* spellings on purpose. A bulk vocabulary
    # sweep will happily rewrite them into the new ones and silently invert
    # this test -- it did exactly that once. They must stay as written.
    "scan name",
    "scan named",
    # The removed subcommands, bare as well as prefixed: the
    # `dataset_list_wide` help string said "`scan list` shows every severity
    # column" and reached docs/CONFIGURATION.md, where "cerno scan" alone
    # would not have matched it.
    "cerno scan",
    "scan list",
    "scan compare",
    "scan delete",
    "scan history",
    "delete scan",
    "import a scan",
    "scan prompt",
    "per scan",
    "multi-scan",
    "cross-scan",
    "plugin id",
    "plugin name",
    # The MCP ``report_brief`` adapter raised "dataset_ids must contain at
    # least one scan id" -- the parameter's own error contradicting its name.
    "scan id",
    # The scope checker returned "Target 'x' is not a known scan host" in
    # ``scope_warnings``, one line below a ``raise`` that said "imported
    # datasets" correctly.
    "scan host",
    # ``cerno mcp --help`` opened with "Serve Cerno's scan database and
    # tooling" -- the fifth home of this phrase, after two in the README,
    # docs/MCP.md and the docs prose. The database holds findings from five
    # sources, only three of which are scanners.
    "scan database",
]

#: The calls whose string arguments are printed to the user's terminal.
_OUTPUT_CALLS = {"err", "warn", "info", "ok", "header", "ask"}

#: Dict keys whose values are rendered to the user rather than printed
#: directly -- config field metadata reaches the screen through
#: ``cerno config show`` and, from there, the generated settings table in
#: ``docs/CONFIGURATION.md``. The ``dataset_list_wide`` help string said
#: "`scan list` shows every severity column" and regenerated straight into
#: the published docs, which is why these are checked alongside the calls.
_OUTPUT_KEYS = {"help", "placeholder"}


def _literal(node):
    """A string from a literal or the literal halves of an f-string.

    Shared by :func:`_console_strings` and :func:`_exception_strings`.
    """
    import ast

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value
            for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
    return None


def _console_strings(path):
    """Every string that reaches the user's screen from ``path``.

    Walks the AST rather than grepping, so a message split across adjacent
    implicit-concatenation lines is still seen as one string and an
    identically-worded docstring is not mistaken for output.
    """
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in _OUTPUT_CALLS:
                for arg in node.args:
                    text = _literal(arg)
                    if text is not None:
                        out.append((node.lineno, text))
        elif isinstance(node, ast.Dict):
            # Config field metadata: {"help": "...", "placeholder": "..."}.
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in _OUTPUT_KEYS:
                    text = _literal(value)
                    if text is not None:
                        out.append((getattr(value, "lineno", node.lineno), text))
    return out


@pytest.mark.unit
def test_terminal_output_uses_the_4_0_vocabulary():
    """No message printed to the user may use a retired noun or command.

    The 4.0.0 rename was driven by ``git grep -w`` on *identifiers*, so it
    never touched English. That left eleven strings printing "scan" where the
    container was meant -- and, worse, four telling the user to run
    ``cerno scan list``, a command the same release removed. An identifier
    sweep cannot catch either, so this checks the strings themselves.
    """
    from pathlib import Path

    root = Path(__file__).parent.parent
    sources = [root / "cerno.py", *sorted((root / "cerno_pkg").rglob("*.py"))]

    offenders = []
    for path in sources:
        for lineno, text in _console_strings(path):
            lowered = text.lower()
            for phrase in RETIRED_OUTPUT_PHRASES:
                if phrase in lowered:
                    rel = path.relative_to(root)
                    offenders.append(f"{rel}:{lineno}: {phrase!r} in {text[:70]!r}")

    assert not offenders, "retired vocabulary printed to the terminal:\n" + "\n".join(
        offenders
    )


#: Substrings in which ``scan``/``plugin`` mean something 4.0.0 kept, checked
#: before the bare-word rule below.
#:
#: Deliberately short: ``\b(scans?|plugins?)\b`` already cannot match
#: ``scanner``, ``scan_target`` or ``plugin_output`` -- there is no word
#: boundary after "scan"/"plugin" in any of them -- so exempting those would be
#: noise. Only these genuinely trip the rule.
_EXCEPTION_KEEPS = (
    "scan target",  # the string a scanner was pointed at
    "nessus scan",  # a real scan someone ran
    "remote scan",  # nmap scanning from a pivot
    "udp scan",  # an nmap scan type
    "scan.nessus",  # a scanner export's filename
    "tenable.com/plugins",  # Tenable's own URL path
)


def _exception_strings(path):
    """Every string literal raised as an exception message from ``path``.

    Separate from :func:`_console_strings` because the two surfaces get
    different rules -- see
    :func:`test_exception_messages_use_the_4_0_vocabulary`.

    Reads list arguments as well as plain ones: ``AuthoredFindingError`` takes
    a *list* of problems (so the TUI can re-prompt with every one at once), and
    an args-only walk misses "Could not create the {name} scan." entirely.
    """
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
            continue
        for arg in node.exc.args:
            candidates = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
            for candidate in candidates:
                text = _literal(candidate)
                if text is not None:
                    out.append((getattr(candidate, "lineno", node.lineno), text))
    return out


@pytest.mark.unit
def test_exception_messages_use_the_4_0_vocabulary():
    """No exception message may call a dataset a "scan" or a finding type a
    "plugin".

    Exception text is a user surface: ``cerno import --overwrite`` raised
    "Failed to replace existing scan", the ``[+]`` authoring flow raised "Could
    not create the Operator scan.", and the MCP server answered a client with
    "dataset_ids must contain at least one scan id". None reached
    :func:`test_terminal_output_uses_the_4_0_vocabulary`, which only reads
    ``err``/``warn``/``info``/``ok``/``header``/``ask`` calls and config
    metadata.

    The rule here is **stricter** than the one for console output: the bare
    word, not a phrase list. Printed text legitimately needs all three senses
    of "scan" (the container, ``scan_target``, the act), so it has to be
    phrase-matched; exception text is short and in practice never needs the
    other two, so a phrase list would just be a list of the specific wordings
    that happened to exist -- and indeed "scan id", "existing scan" and "No
    scan with id" were all absent from it.
    """
    import re
    from pathlib import Path

    retired = re.compile(r"\b(scans?|plugins?)\b", re.IGNORECASE)

    root = Path(__file__).parent.parent
    sources = [root / "cerno.py", *sorted((root / "cerno_pkg").rglob("*.py"))]

    offenders = []
    for path in sources:
        for lineno, text in _exception_strings(path):
            lowered = text.lower()
            for keep in _EXCEPTION_KEEPS:
                lowered = lowered.replace(keep, " ")
            match = retired.search(lowered)
            if match:
                rel = path.relative_to(root)
                offenders.append(f"{rel}:{lineno}: {match.group(0)!r} in {text[:70]!r}")

    assert not offenders, "retired vocabulary in an exception message:\n" + "\n".join(
        offenders
    )


@pytest.mark.unit
def test_mcp_server_strings_use_the_4_0_vocabulary():
    """No string in the MCP server may use a retired noun or command.

    Every string here is effectively a client-facing surface: tool docstrings
    become the tool *descriptions* an agent reads, and response text is handed
    straight back. Two leaked past the narrower checks above:

    * the scope checker *returned* "Target 'x' is not a known scan host" from a
      list comprehension into ``scope_warnings`` -- not a console call and not
      a ``raise``, so neither other rule saw it, one line below a ``raise``
      that said "imported datasets" correctly;
    * ``get_workflow``'s docstring told agents ``finding_type_id`` could be "a
      bare Nessus plugin id (\\"57608\\")". Every source has been prefixed since
      schema v5, so that form matches nothing and the tool would answer "no
      workflow" for a finding that has one.

    A whole-module string check is viable *here* precisely because this module
    is user-facing almost end to end; the same rule over ``cerno_pkg`` at large
    would fight every legitimate "scanner" and ``scan_target``.
    """
    from pathlib import Path

    import ast

    root = Path(__file__).parent.parent
    offenders = []
    for path in sorted((root / "cerno_pkg" / "mcp_server").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            text = _literal(node)
            if not text:
                continue
            lowered = text.lower()
            for phrase in RETIRED_OUTPUT_PHRASES:
                if phrase in lowered:
                    rel = path.relative_to(root)
                    lineno = getattr(node, "lineno", 0)
                    offenders.append(f"{rel}:{lineno}: {phrase!r} in {text[:70]!r}")

    assert not offenders, "retired vocabulary in an MCP server string:\n" + "\n".join(
        offenders
    )


#: A docstring line documenting a parameter whose name 4.0.0 renamed.
#: ``Args:`` blocks are plain text, so the name and its description are matched
#: off the same line: ``dataset_name: Name of scan``.
_PARAM_DOC = re.compile(r"^\s*((?:dataset|finding_type)[a-z_]*)\s*:\s*(.+)$")


def _docstring_lines(path):
    """Every line of every docstring in ``path``, with its real line number.

    Covers module, class, function and method docstrings. Lines come from the
    *raw* string rather than :func:`ast.get_docstring`, whose ``clean=True``
    dedent can drop leading blank lines and shift every line number after it.
    """
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    holders = [tree] + [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    out = []
    for holder in holders:
        body = getattr(holder, "body", None)
        if not body or not isinstance(body[0], ast.Expr):
            continue
        node = body[0].value
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        for offset, line in enumerate(node.value.splitlines()):
            out.append((node.lineno + offset, line))
    return out


@pytest.mark.unit
def test_param_docs_match_their_dataset_names():
    """A parameter named ``dataset*`` may not be described as a "scan".

    This is the general form of the whole class 4.0.0 created. The rename moved
    the *identifiers* (``scan_name`` -> ``dataset_name``, ``scan_ids`` ->
    ``dataset_ids``) and left their prose behind, so ~62 docstrings ended up
    documenting a parameter under a name it no longer had: ``dataset_name: Name
    of scan``. Each is self-contradictory on one line, which is why the check is
    worth having mechanically rather than by sweep -- the three guards above all
    match *phrases* ("scan name", "scan id", bare ``scans?`` in a ``raise``),
    and five of these matched none of them.

    Being scoped to a renamed parameter name is what lets this one use the bare
    word where :func:`test_terminal_output_uses_the_4_0_vocabulary` cannot: a
    line that already says ``dataset_name:`` is not talking about
    ``scan_target`` or about the act of scanning. A guard over docstrings at
    large would fight every legitimate use in the keep list instead.

    ``tests/`` is in scope here, unlike the guards above: a stale parameter
    description is just as wrong in a fixture's docstring, and nothing in the
    suite depends on the retired spelling the way
    :data:`RETIRED_OUTPUT_PHRASES` does.
    """
    from pathlib import Path

    retired = re.compile(r"\b(scans?|plugins?)\b", re.IGNORECASE)

    root = Path(__file__).parent.parent
    sources = [
        root / "cerno.py",
        *sorted((root / "cerno_pkg").rglob("*.py")),
        *sorted((root / "tests").rglob("*.py")),
    ]

    offenders = []
    for path in sources:
        for lineno, line in _docstring_lines(path):
            match = _PARAM_DOC.match(line)
            if not match:
                continue
            name, description = match.group(1), match.group(2)
            lowered = description.lower()
            for keep in _EXCEPTION_KEEPS:
                lowered = lowered.replace(keep, " ")
            found = retired.search(lowered)
            if found:
                rel = path.relative_to(root)
                offenders.append(f"{rel}:{lineno}: {name}: {description.strip()!r}")

    assert (
        not offenders
    ), "parameter documented under the name it was renamed from:\n" + "\n".join(
        offenders
    )


def _command_help(path):
    """Every Typer command's help text: ``(function name, first paragraph)``.

    A Typer command's docstring *is* its ``--help`` output, and Typer shows the
    first paragraph in the command list. Detection is by decorator rather than
    by name, so the ``import`` / ``dataset`` / ``config`` / ``workflow`` /
    ``creds`` sub-apps are covered alongside the top-level ones.
    """
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [ast.unparse(d) for d in node.decorator_list]
        if not any(".command(" in d or ".callback(" in d for d in decorators):
            continue
        doc = ast.get_docstring(node) or ""
        if doc:
            out.append((node.name, doc.split("\n\n")[0].replace("\n", " ")))
    return out


@pytest.mark.unit
def test_command_help_uses_the_4_0_vocabulary():
    """``--help`` text is user-facing output and must use the 4.0 vocabulary.

    This is the fourth category of text that reaches a user, and until now the
    only one no guard read: the three above cover console calls, config field
    metadata and exception messages, plus every string in the MCP server. A
    Typer command's docstring is rendered by ``--help``, so it is output that
    merely happens to be written as a docstring -- and
    :func:`test_param_docs_match_their_dataset_names` only inspects ``Args:``
    lines naming a renamed parameter, not the summary above them.

    What survived there: ``cerno mcp --help`` opened with "Serve Cerno's scan
    database and tooling", the fifth home of a phrase 4.0.0 corrected in the
    README twice, in ``docs/MCP.md`` and in the docs prose. It is also the first
    text a new user reads.
    """
    from pathlib import Path

    path = Path(__file__).parent.parent / "cerno.py"
    helps = _command_help(path)
    # A decorator-detection change must not quietly reduce this to checking
    # nothing -- the failure mode that once left `reset` unchecked.
    assert len(helps) >= 15, f"only {len(helps)} Typer commands found; detection broke"

    offenders = []
    for name, summary in helps:
        lowered = summary.lower()
        for phrase in RETIRED_OUTPUT_PHRASES:
            if phrase in lowered:
                offenders.append(f"{name}(): {phrase!r} in {summary.strip()!r}")

    assert not offenders, "--help text uses retired vocabulary:\n" + "\n".join(
        offenders
    )
