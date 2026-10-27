"""Tests for the light/dark terminal color scheme (``color_scheme`` config key)."""

import io

import pytest
from rich.table import Table

from cerno_pkg import ansi
from cerno_pkg.ansi import C, CernoConsole, initialize_colors, remap_style
from cerno_pkg.config import CernoConfig


def _render(scheme: str, *renderables) -> str:
    buf = io.StringIO()
    console = CernoConsole(
        scheme=scheme, file=buf, force_terminal=True, color_system="256", width=40
    )
    console.print(*renderables)
    return buf.getvalue()


@pytest.fixture
def restore_c():
    """initialize_colors mutates the C class; restore it after each test."""
    saved = {k: v for k, v in vars(C).items() if k.isupper()}
    yield
    for k, v in saved.items():
        setattr(C, k, v)


@pytest.mark.unit
class TestRemapStyle:
    def test_light_remaps_compound_style(self):
        assert remap_style("bold yellow", "light") == "bold dark_orange3"

    def test_dark_is_identity(self):
        assert remap_style("bold yellow", "dark") == "bold yellow"

    def test_white_becomes_default(self):
        assert remap_style("dim white", "light") == "dim default"

    def test_background_after_on_is_remapped(self):
        assert remap_style("black on yellow", "light") == "black on dark_orange3"

    def test_theme_names_and_links_untouched(self):
        assert remap_style("prompt.choices", "light") == "prompt.choices"
        assert remap_style("link https://yellow.example", "light") == (
            "link https://yellow.example"
        )

    def test_unknown_scheme_falls_back_to_light(self):
        assert remap_style("cyan", "bogus") == "turquoise4"


@pytest.mark.unit
class TestCernoConsole:
    def test_light_markup_uses_256_color(self):
        out = _render("light", "[bold yellow]x[/]")
        assert "38;5;166" in out
        assert "\x1b[1;33m" not in out

    def test_dark_markup_unchanged(self):
        assert "\x1b[1;33mx" in _render("dark", "[bold yellow]x[/]")

    def test_light_table_column_style(self):
        table = Table()
        table.add_column("c", style="cyan")
        table.add_row("v")
        assert "38;5;30" in _render("light", table)


@pytest.mark.unit
class TestInitializeColors:
    def test_light_codes(self, restore_c):
        initialize_colors(CernoConfig(color_scheme="light"))
        assert C.YELLOW == "\x1b[38;5;166m"
        assert C.RESET == "\x1b[0m"

    def test_dark_codes_match_classic_ansi(self, restore_c):
        initialize_colors(CernoConfig(color_scheme="dark"))
        assert C.YELLOW == "\x1b[33m"
        assert C.CYAN == "\x1b[36m"

    def test_no_color_leaves_codes_empty(self, restore_c):
        for k in ("RESET", "YELLOW"):
            setattr(C, k, "")
        initialize_colors(CernoConfig(no_color=True))
        assert C.YELLOW == ""


@pytest.mark.unit
def test_severity_label_uses_scheme(monkeypatch, restore_c):
    monkeypatch.setattr(ansi, "get_no_color", lambda config=None: False)
    initialize_colors(CernoConfig(color_scheme="light"))
    assert "\x1b[38;5;166m" in ansi.colorize_severity_label("High")
    initialize_colors(CernoConfig(color_scheme="dark"))
    assert "\x1b[33m" in ansi.colorize_severity_label("High")
