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
