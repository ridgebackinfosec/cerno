"""Tests for render.py rendering behaviour."""
from unittest.mock import patch, MagicMock
import pytest

pytest_mark = pytest.mark.unit


def test_render_claude_panel_conversation_uses_soft_wrap():
    """Turn content must use soft_wrap=True so terminal handles wrapping (not Rich).

    This ensures Ctrl+Shift+C from a terminal copies clean unwrapped text — critical
    for users copying Claude responses from a VM into Word on their host system.
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
        "Expected at least one _console_global.print() call with soft_wrap=True "
        "for conversation turn content"
    )
