"""Tests for render.py rendering behaviour."""
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
def test_render_claude_panel_latest_exchange_is_bright():
    """Latest exchange uses bright styles; prior exchanges use dim styles.

    Verifies the core brightness contract: bold cyan/magenta for latest,
    dim cyan/magenta for prior. Uses _spans which is stable Rich internals.
    """
    from rich.text import Text
    from cerno_pkg import render as render_module

    def make_turn(role, content):
        t = MagicMock()
        t.role = role
        t.content = content
        t.created_at = "2026-04-21T12:00:00"
        return t

    turns = [
        make_turn("user", "Is this exploitable?"),
        make_turn("assistant", "Yes, via EternalBlue."),
        make_turn("user", "What payload?"),
        make_turn("assistant", "Use meterpreter/reverse_tcp."),
    ]

    with patch("cerno_pkg.render._console_global") as mock_console:
        render_module.render_claude_panel(turns, is_resumed=True)

    # The Panel print is the only call with soft_wrap=True (proven by test 1)
    panel_call = next(
        (c for c in mock_console.print.call_args_list if c.kwargs.get("soft_wrap") is True),
        None,
    )
    assert panel_call is not None, "Expected print() with soft_wrap=True for Panel"
    panel = panel_call.args[0]

    # Collect all span styles from Text objects in the Group
    group = panel.renderable
    all_span_styles = []
    for item in group._renderables:
        if isinstance(item, Text):
            for span in item._spans:
                all_span_styles.append(str(span.style))

    dim_labels = [s for s in all_span_styles if s in ("dim cyan", "dim magenta")]
    bright_labels = [s for s in all_span_styles if s in ("bold cyan", "bold magenta")]

    assert len(dim_labels) >= 1, (
        f"Expected dim label span(s) for prior exchange, found none. "
        f"All span styles: {all_span_styles}"
    )
    assert len(bright_labels) >= 1, (
        f"Expected bright label span(s) for latest exchange, found none. "
        f"All span styles: {all_span_styles}"
    )
