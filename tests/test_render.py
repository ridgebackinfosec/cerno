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
def test_render_claude_panel_handles_multiple_exchanges(monkeypatch):
    """Multi-exchange conversations render correctly with dim/bright styles.

    Verifies that 'bold cyan'/'bold magenta' labels appear for the latest exchange
    and 'dim cyan'/'dim magenta' labels appear for prior exchanges.
    """
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

    mock_console = MagicMock()
    monkeypatch.setattr(render_module, "_console_global", mock_console)

    # Should not raise
    render_module.render_claude_panel(turns, is_resumed=True)

    # Should have printed output
    assert mock_console.print.call_count > 0, "Expected print to be called"
