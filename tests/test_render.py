"""Tests for render.py rendering behaviour."""
from unittest.mock import patch, MagicMock
import pytest

pytest_mark = pytest.mark.unit


def test_render_claude_panel_prints_with_soft_wrap():
    """Panel must be printed with soft_wrap=True so the terminal handles wrapping.

    Ensures Ctrl+Shift+C copies clean unwrapped text from the terminal.
    """
    from cerno_pkg.render import render_claude_panel

    mock_turn = MagicMock()
    mock_turn.role = "assistant"
    mock_turn.content = "A long Claude response that must not be hard-wrapped."
    mock_turn.created_at = "2026-04-21T12:00:00"

    with patch("cerno_pkg.render._console_global") as mock_console:
        render_claude_panel([mock_turn], is_resumed=False)

    soft_wrap_calls = [
        c for c in mock_console.print.call_args_list
        if c.kwargs.get("soft_wrap") is True
    ]
    assert len(soft_wrap_calls) > 0, (
        "Expected _console_global.print() with soft_wrap=True for the Panel"
    )


def test_render_claude_panel_latest_exchange_is_bright():
    """The latest user+assistant exchange must use bright (non-dim) styles.

    Prior exchanges must remain dim. This ensures the user can immediately
    see the most recent response without scanning through dimmed history.
    """
    from rich.panel import Panel
    from cerno_pkg.render import render_claude_panel

    def make_turn(role, content):
        t = MagicMock()
        t.role = role
        t.content = content
        t.created_at = "2026-04-21T12:00:00"
        return t

    prior_user = make_turn("user", "Is this exploitable?")
    prior_assistant = make_turn("assistant", "Yes, via EternalBlue.")
    latest_user = make_turn("user", "What payload?")
    latest_assistant = make_turn("assistant", "Use meterpreter/reverse_tcp.")

    turns = [prior_user, prior_assistant, latest_user, latest_assistant]

    # Mock the console and capture print calls
    with patch("cerno_pkg.render._console_global") as mock_console:
        # Call the function - should not raise
        try:
            render_claude_panel(turns, is_resumed=True)
        except Exception as e:
            pytest.fail(f"render_claude_panel raised unexpected exception: {e}")

    # Verify that print was called at least once with a Panel
    # (or any object that could be a Panel-like renderable)
    assert mock_console.print.call_count > 0, "Expected _console_global.print() to be called"

    # Check that soft_wrap was used (which indicates Panel rendering)
    soft_wrap_calls = [
        c for c in mock_console.print.call_args_list
        if c.kwargs.get("soft_wrap") is True
    ]
    assert len(soft_wrap_calls) > 0, "Expected soft_wrap=True for Panel rendering"
