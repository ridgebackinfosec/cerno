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

import pytest
import yaml
from typer.testing import CliRunner

from cerno_pkg import config as config_mod

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
    (["scan", "list"], "--wide"),
    (["scan", "list"], "--details"),
    (["import", "nuclei"], "--min-severity"),
]

#: Flags that are per-invocation data and must survive.
KEPT_FLAGS = [
    (["import", "nuclei"], "--name"),
    (["scan", "list"], "--json"),
    (["scan", "compare"], "--severity"),
    (["scan", "compare"], "-s"),
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
    assert "No such option" in result.output, result.output


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
    assert flag in result.output.replace("\n", " "), result.output


@pytest.mark.integration
def test_review_takes_no_options():
    """`cerno review` is entirely config-driven now."""
    from cerno import app

    result = CliRunner().invoke(app, ["review", "--help"])

    assert result.exit_code == 0, result.output
    options = result.output.split("Options")[-1]
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
    assert cfg.scan_list_wide is False  # compact unless --wide
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
def test_nuclei_min_severity_is_validated_before_import(tmp_path):
    """A hand-edited out-of-range value is refused, not silently ignored."""
    from cerno import app

    results = tmp_path / "results.json"
    results.write_text("[]", encoding="utf-8")
    _write_config(nuclei_min_severity=9)

    result = CliRunner().invoke(app, ["import", "nuclei", str(results)])

    assert result.exit_code == 1, result.output
    assert "nuclei_min_severity" in result.output
