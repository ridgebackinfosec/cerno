"""Tests for the light/dark terminal color scheme (``color_scheme`` config key)."""

import io

import pytest
import rich
from rich.style import Style
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
class TestRichCouplingGuards:
    """Guards for the three points where ansi.py reaches into Rich's internals.

    Each of these fails *silently* on a Rich upgrade — the palette quietly
    reverts to Rich's defaults with no exception raised — so they are asserted
    directly rather than inferred from rendered output.
    """

    def test_get_style_override_intercepts_named_colors(self):
        """Rich routes every string style through ``Console.get_style()``.

        If the override stops being called (signature change, added caching),
        named colors stop being remapped for the active scheme.
        """
        assert CernoConsole(scheme="light").get_style("yellow") == Style.parse(
            "dark_orange3"
        )
        assert CernoConsole(scheme="dark").get_style("yellow") == Style.parse("yellow")

    def test_rich_default_styles_still_importable(self):
        """``CernoConsole.__init__`` rebuilds Rich's built-in theme from this
        semi-private mapping, so a rename or relocation breaks theming."""
        from rich.default_styles import DEFAULT_STYLES

        assert DEFAULT_STYLES, "rich.default_styles.DEFAULT_STYLES is empty"
        assert "prompt.choices" in DEFAULT_STYLES

    def test_traceback_suppress_entries_are_modules_not_strings(self):
        """Rich resolves a *string* suppress entry as a filesystem path, not a
        module name, so ``suppress=["typer"]`` silently expands to ``./typer``
        and suppresses nothing. Entries must be module objects.
        """
        import os

        from rich.traceback import Traceback

        from cerno import _TB_SUPPRESS  # type: ignore[reportPrivateUsage]

        assert (
            _TB_SUPPRESS
        ), "nothing suppressed; CLI tracebacks will show framework frames"
        for entry in _TB_SUPPRESS:
            assert not isinstance(
                entry, str
            ), f"{entry!r} is a str; Rich would treat it as a path, not a module"

        try:
            raise ValueError("probe")
        except ValueError:
            resolved = Traceback(suppress=_TB_SUPPRESS).suppress
        for path in resolved:
            assert os.path.isdir(path), f"suppress path does not exist: {path}"

    def test_installed_as_rich_global_console(self, monkeypatch):
        """Bare ``Prompt``/``Confirm``/``Progress`` calls fall back to Rich's
        global console, which ``get_console()`` sets via the private
        ``rich._console``. If that attribute is renamed or lazily initialized
        the assignment becomes a no-op and every prompt loses the scheme.
        """
        monkeypatch.setattr(rich, "_console", None, raising=False)
        monkeypatch.setattr(ansi, "_console_cache", None)

        console = ansi.get_console(CernoConfig(color_scheme="light"))

        assert rich.get_console() is console


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
