"""Rich markup and terminal-escape injection from untrusted scan data.

Plugin names, hostnames and scan names come from third-party ``.nessus`` files.
They were interpolated straight into Rich markup strings, which meant a name
containing square brackets could crash rendering, silently lose text, restyle
output, or inject a clickable hyperlink into the operator's terminal.

Raw ESC bytes cannot reach us through ``.nessus`` (a literal ``\\x1b`` is an
invalid XML character, so the parser rejects the file), but they can arrive via
CLI arguments, the NetExec workspace DB and tool output -- hence the message
helper tests below.
"""

import io

import pytest
from rich.console import Console

from cerno_pkg import ansi, render
from cerno_pkg.ansi import C, safe_text
from cerno_pkg.models import Finding, Plugin

# Hostile / awkward values, all of which survive a .nessus round-trip verbatim.
CRASH = "SMB [/] Signing"
STYLE = "SMB [red]Signing[/red]"
LINK = "SMB [link=file:///etc/passwd]click[/link]"
LOSSY = "TLS Version 1.0 [deprecated] Detection"
BENIGN = "Apache Log4j [CVE-2021-44228] RCE"
OSC = "SMB \x1b]0;pwned\x07 Signing"


def _render(renderable, *, color: bool = False) -> str:
    buf = io.StringIO()
    Console(
        file=buf,
        width=200,
        force_terminal=color,
        no_color=not color,
        legacy_windows=False,
    ).print(renderable)
    return buf.getvalue()


@pytest.mark.unit
class TestSafeText:
    def test_markup_is_escaped_so_it_renders_literally(self):
        assert "[/]" in _render(f"[bold cyan]{safe_text(CRASH)}[/]")

    def test_unbalanced_tag_no_longer_crashes(self):
        # Unescaped, this raises MarkupError.
        assert "SMB" in _render(f"[bold cyan]{safe_text(CRASH)}[/]")

    def test_bracketed_style_word_is_not_swallowed(self):
        """``[deprecated]`` parses as a Rich style, so it used to vanish."""
        out = _render(f"[bold cyan]{safe_text(LOSSY)}[/]")
        assert "[deprecated]" in out
        assert "TLS Version 1.0 [deprecated] Detection" in out

    def test_link_markup_does_not_become_a_hyperlink(self):
        out = _render(f"[bold cyan]{safe_text(LINK)}[/]", color=True)
        assert "\x1b]8;" not in out, "OSC-8 hyperlink was injected"

    def test_control_characters_are_stripped(self):
        cleaned = safe_text(OSC)
        assert "\x1b" not in cleaned
        assert "\x07" not in cleaned
        assert "SMB" in cleaned and "Signing" in cleaned

    def test_benign_text_is_unchanged_after_rendering(self):
        """A real-world bracketed name must survive byte-for-byte."""
        assert BENIGN in _render(f"[bold cyan]{safe_text(BENIGN)}[/]")

    def test_tabs_and_newlines_survive(self):
        assert safe_text("a\tb\nc") == "a\tb\nc"

    def test_double_application_is_visible_not_silent(self):
        """safe_text is deliberately NOT idempotent.

        rich.markup.escape is not idempotent either, so applying it twice shows
        a literal backslash rather than quietly collapsing. Pinning this makes
        the "apply exactly once" contract explicit instead of surprising.
        """
        once = safe_text(LOSSY)
        assert safe_text(once) != once
        assert "\\" in safe_text(once)

    def test_accepts_non_str(self):
        assert safe_text(42) == "42"
        assert safe_text(None) == "None"


@pytest.mark.unit
class TestRenderNxcHostPanelHostileHost:
    """render_nxc_host_panel interpolates host_ip, which comes from scan data."""

    def test_unbalanced_tag_in_host_does_not_crash(self):
        panel = render.render_nxc_host_panel(CRASH, None, has_data=False)
        assert "SMB" in _render(panel)

    def test_style_word_in_host_is_preserved(self):
        panel = render.render_nxc_host_panel(LOSSY, None, has_data=False)
        assert "[deprecated]" in _render(panel)

    def test_link_in_host_is_not_a_hyperlink(self):
        panel = render.render_nxc_host_panel(LINK, None, has_data=False)
        assert "\x1b]8;" not in _render(panel, color=True)


@pytest.mark.unit
class TestFindingPreviewHostilePluginName:
    """display_finding_preview titles its panel with plugin.plugin_name."""

    @staticmethod
    def _preview(name: str, capsys) -> str:
        plugin = Plugin(plugin_id=90001, plugin_name=name, severity_int=3)
        finding = Finding(finding_id=1, scan_id=1, plugin_id=90001)
        finding.get_hosts_and_ports = lambda *a, **k: ([], "")  # type: ignore[method-assign]
        render.display_finding_preview(plugin, finding, None, None)  # type: ignore[arg-type]
        return capsys.readouterr().out

    def test_unbalanced_tag_does_not_crash(self, capsys):
        assert "SMB" in self._preview(CRASH, capsys)

    def test_style_word_is_preserved(self, capsys):
        assert "[deprecated]" in self._preview(LOSSY, capsys)

    def test_benign_bracketed_name_survives(self, capsys):
        assert "[CVE-2021-44228]" in self._preview(BENIGN, capsys)


@pytest.mark.unit
class TestMessageHelperEscapes:
    """err/warn/ok/header/info print raw ANSI directly (not via Rich), so they
    must drop dangerous escapes while keeping intentional SGR color."""

    @pytest.mark.parametrize("fn_name", ["err", "warn", "ok", "header", "info"])
    def test_osc_and_bare_escapes_are_stripped(self, fn_name, capsys):
        getattr(ansi, fn_name)(OSC)
        out = capsys.readouterr().out
        assert "\x1b]0;" not in out, "OSC window-title sequence reached the terminal"
        assert "\x07" not in out

    def test_intentional_sgr_color_is_preserved(self, capsys, monkeypatch):
        """Regression guard for tools.py:1035, which passes C.BOLD into info()."""
        monkeypatch.setattr(C, "BOLD", "\x1b[1m")
        monkeypatch.setattr(C, "RESET", "\x1b[0m")

        ansi.info(f"{C.BOLD}NSE scripts to run:{C.RESET} smb-vuln-ms17-010")

        out = capsys.readouterr().out
        assert "\x1b[1m" in out, "SGR color was stripped; intentional styling lost"
        assert "NSE scripts to run:" in out
