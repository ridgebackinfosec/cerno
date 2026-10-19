"""Tests for render.py rendering behaviour."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

pytest_mark = pytest.mark.unit


@pytest.mark.unit
def test_render_claude_panel_prints_with_soft_wrap(monkeypatch):
    """Panel must be printed with soft_wrap=True so the terminal handles wrapping.

    Ensures Ctrl+Shift+C copies clean unwrapped text from the terminal.
    """
    from cerno_pkg import render as render_module

    mock_turn = MagicMock()
    mock_turn.role = "assistant"
    mock_turn.content = "A long Claude response that must not be hard-wrapped."
    mock_turn.created_at = "2026-04-21T12:00:00"

    mock_console = MagicMock()
    monkeypatch.setattr(render_module, "_console_global", mock_console)

    render_module.render_claude_panel([mock_turn], is_resumed=False)

    soft_wrap_calls = [
        c for c in mock_console.print.call_args_list
        if c.kwargs.get("soft_wrap") is True
    ]
    assert len(soft_wrap_calls) > 0, (
        "Expected _console_global.print() with soft_wrap=True for the Panel"
    )


@pytest.mark.unit
def test_render_claude_panel_labels_use_plain_styles():
    """Labels use plain cyan/magenta — no bold or dim — for light+dark terminal compat.

    Verifies that no brightness-dependent styles are applied so the panel is
    readable on both light (dark-on-white) and dark (light-on-black) terminals.
    """
    from rich.text import Text
    from cerno_pkg.render import _build_claude_panel_renderables

    def make_turn(role, content):
        t = MagicMock()
        t.role = role
        t.content = content
        return t

    turns = [
        make_turn("user", "Is this exploitable?"),
        make_turn("assistant", "Yes, via EternalBlue."),
        make_turn("user", "What payload?"),
        make_turn("assistant", "Use meterpreter/reverse_tcp."),
    ]

    renderables = _build_claude_panel_renderables(turns)

    label_styles = []
    for item in renderables:
        if isinstance(item, Text) and item._spans:
            label_styles.append(str(item._spans[0].style))

    assert "cyan" in label_styles, f"Expected 'cyan' user label. Got: {label_styles}"
    assert "magenta" in label_styles, f"Expected 'magenta' Claude label. Got: {label_styles}"
    assert not any(s in label_styles for s in ("dim cyan", "dim magenta", "bold cyan", "bold magenta")), (
        f"Found bold/dim label styles — should be plain. Got: {label_styles}"
    )


def _record_console(monkeypatch, module):
    """Swap a module's _console_global for a wide recording Console; return it."""
    from rich.console import Console

    console = Console(record=True, width=200, force_terminal=False)
    monkeypatch.setattr(module, "_console_global", console)
    return console


@pytest.mark.unit
@pytest.mark.parametrize("active,label", [(False, "In Progress only"), (True, "All statuses")])
def test_actions_footer_shows_status_toggle(monkeypatch, active, label):
    """Findings-list footer offers [I] with a label that reflects the toggle state."""
    from cerno_pkg import ansi, render as render_module

    console = _record_console(monkeypatch, render_module)
    monkeypatch.setattr(ansi, "get_terminal_width", lambda: 200)
    render_module.render_actions_footer(
        group_applied=False,
        candidates_count=3,
        sort_mode="severity",
        can_next=False,
        can_prev=False,
        status_filter_active=active,
    )
    out = console.export_text()
    assert "[I]" in out
    assert label in out


@pytest.mark.unit
def test_actions_help_mentions_status_toggle(monkeypatch):
    from cerno_pkg import render as render_module

    console = _record_console(monkeypatch, render_module)
    render_module.show_actions_help(
        group_applied=False,
        candidates_count=0,
        sort_mode="severity",
        can_next=False,
        can_prev=False,
    )
    assert "[I]" in console.export_text()


@pytest.mark.unit
def test_empty_state_status_mismatch(monkeypatch):
    from cerno_pkg import render as render_module

    messages: list[str] = []
    monkeypatch.setattr(render_module, "info", lambda msg="": messages.append(msg))
    render_module.render_empty_state("status_mismatch", "In Progress")
    text = "\n".join(messages)
    assert "In Progress" in text
    assert "[I]" in text


def _preview_plugin(plugin_url):
    from cerno_pkg.models import Plugin

    return Plugin(
        plugin_id=41028,
        plugin_name="SNMP Agent Default Community Name (public)",
        severity_int=3,
        severity_label="High",
        plugin_url=plugin_url,
    )


def _preview_finding():
    finding = MagicMock()
    finding.get_hosts_and_ports.return_value = (["198.51.100.20"], [161])
    finding.get_port_distribution.return_value = {"161": 1}
    return finding


def _render_preview(monkeypatch, plugin_url):
    import cerno_pkg.render as render_module

    console = _record_console(monkeypatch, render_module)
    monkeypatch.setattr(render_module, "render_nxc_enrichment_summary", lambda hosts: None)
    render_module.display_finding_preview(
        _preview_plugin(plugin_url), _preview_finding(), None, Path("x.txt")
    )
    return console


@pytest.mark.unit
def test_finding_preview_shows_plugin_url(monkeypatch):
    console = _render_preview(monkeypatch, "https://www.tenable.com/plugins/nessus/41028")
    out = console.export_text(clear=False)
    assert "Plugin Details: https://tenable.com/plugins/nessus/41028" in out
    assert "www." not in out


@pytest.mark.unit
def test_finding_preview_plugin_url_fallback(monkeypatch):
    console = _render_preview(monkeypatch, None)
    assert "Plugin Details: https://tenable.com/plugins/nessus/41028" in console.export_text()


@pytest.mark.unit
def test_finding_preview_link_target_is_full_url(monkeypatch):
    import cerno_pkg.render as render_module
    from rich.text import Text

    printed = []
    monkeypatch.setattr(render_module, "_console_global", MagicMock(print=lambda *a, **k: printed.extend(a)))
    monkeypatch.setattr(render_module, "render_nxc_enrichment_summary", lambda hosts: None)
    render_module.display_finding_preview(
        _preview_plugin("https://www.tenable.com/plugins/nessus/41028"), _preview_finding(), None, Path("x.txt")
    )
    panel = printed[-1]
    assert isinstance(panel.renderable, Text)
    links = {str(span.style) for span in panel.renderable.spans if "link" in str(span.style)}
    assert any("link https://www.tenable.com/plugins/nessus/41028" in s for s in links), links
