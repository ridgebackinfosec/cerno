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
from pathlib import Path

import pytest
from rich.console import Console

from cerno_pkg import ansi, render
from cerno_pkg.ansi import C, safe_text
from cerno_pkg.cross_scan import HostVulnerabilityHistory, ScanSnapshot
from cerno_pkg.models import Finding, Plugin
from cerno_pkg.nxc_db import NxcHostData, NxcShare

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


#: Each hostile name paired with the literal substring that must survive to the
#: screen. Benign brackets are included so a fix cannot "pass" by mangling
#: everything with square brackets in it.
HOSTILE_CASES = [
    pytest.param(CRASH, "[/]", id="unbalanced-close"),
    pytest.param(LOSSY, "[deprecated]", id="style-word"),
    pytest.param(LINK, "[link=", id="link-injection"),
    pytest.param(BENIGN, "[CVE-2021-44228]", id="benign-brackets"),
]


def _capture(monkeypatch, module, call) -> str:
    """Run a renderer against a fixed-width recording console.

    The renderers print through their module-level ``_console_global``, looked up
    at call time, so swapping it captures output at a deterministic width (real
    terminal width would wrap and split the tokens being asserted on).
    """
    buf = io.StringIO()
    monkeypatch.setattr(
        module,
        "_console_global",
        Console(file=buf, width=240, no_color=True, legacy_windows=False),
    )
    call()
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


@pytest.mark.unit
class TestTableRenderersHostileNames:
    """Table cells are markup-parsed too.

    Any bare ``str`` handed to Rich is parsed as markup — including a
    ``table.add_row(...)`` cell, which looks nothing like markup in the source.
    The 2.12.0 sweep searched for f-strings *containing* tags and so fixed the
    panel titles while missing every table, which is how the findings list
    shipped able to crash on a plugin name from a ``.nessus`` file.

    Each case asserts BOTH that nothing raised AND that the bracketed text
    reached the screen intact. Asserting only "no crash" would let a silent
    text-swallowing regression through, which is the worse failure for a triage
    tool: a plugin name quietly loses characters with no error at all.
    """

    @pytest.mark.parametrize("name,token", HOSTILE_CASES)
    def test_finding_list_table(self, monkeypatch, name, token):
        """The main findings list — this is the one that crashed."""
        plugin = Plugin(plugin_id=99001, plugin_name=name, severity_int=4)
        finding = Finding(finding_id=1, scan_id=1, plugin_id=99001)

        out = _capture(
            monkeypatch,
            render,
            lambda: render.render_finding_list_table(
                [(finding, plugin)], "severity", lambda pf: (1, "445")
            ),
        )

        assert token in out, f"{token!r} was swallowed by markup parsing"

    @pytest.mark.parametrize(
        "name,token",
        [
            pytest.param("SMB [deprecated] Scan", "[deprecated]", id="style-word"),
            pytest.param("SMB [red] Scan", "[red]", id="colour-word"),
            pytest.param(
                "Log4j [CVE-2021-44228] Scan", "[CVE-2021-44228]", id="benign-brackets"
            ),
        ],
    )
    def test_scan_table(self, monkeypatch, name, token):
        """Scan-selection menu; the name comes from the .nessus / filename.

        This renderer takes ``Path`` objects and prints ``.name``, a single path
        component, which on POSIX cannot contain ``/``. So the closing-tag and
        ``[link=file:///...]`` payloads are unreachable here by construction --
        only opening-tag shapes are, and those swallow text rather than crash.
        """
        out = _capture(
            monkeypatch,
            render,
            lambda: render.render_scan_table([Path("/tmp") / name]),
        )

        assert token in out

    @pytest.mark.parametrize("name,token", HOSTILE_CASES)
    def test_compare_group_table(self, monkeypatch, name, token):
        """`[H]` compare groups join plugin names into one cell."""
        out = _capture(
            monkeypatch,
            render,
            lambda: render.render_compare_tables(
                [("f1", ["10.0.0.1"], {"445"}, {"10.0.0.1": {"445"}}, True)],
                {"10.0.0.1"},
                {"10.0.0.1"},
                {"445"},
                {"445"},
                True,
                True,
                True,
                # Two groups: the table is only rendered when len(groups) > 1.
                [[name], ["other finding"]],
            ),
        )

        assert token in out

    @pytest.mark.parametrize("name,token", HOSTILE_CASES)
    def test_nxc_share_names(self, monkeypatch, name, token):
        """Share names come from the NetExec workspace DB, not Cerno."""
        host_data = NxcHostData(
            host_address="10.0.0.1",
            shares=[NxcShare(name=name, read_access=True)],
        )

        panel = render.render_nxc_host_panel("10.0.0.1", host_data)

        assert token in _render(panel)

    @pytest.mark.parametrize("name,token", HOSTILE_CASES)
    def test_host_history_scan_names(self, monkeypatch, name, token):
        """`cerno scan history` timeline rows carry the scan name."""
        history = HostVulnerabilityHistory(
            host_id=1,
            ip_address="10.0.0.1",
            scan_target="10.0.0.1",
            scan_target_type="ipv4",
            first_seen="2026-10-01",
            last_seen="2026-10-02",
            scans=[
                ScanSnapshot(
                    scan_id=1,
                    scan_name=name,
                    scan_date="2026-10-01",
                    finding_count=1,
                    max_severity=4,
                    critical_count=1,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    info_count=0,
                )
            ],
        )

        out = _capture(monkeypatch, render, lambda: render.render_host_history(history))

        assert token in out


@pytest.mark.integration
class TestOverlapGroupTableHostileNames:
    """`[O]` overlap groups render plugin names as the root/covered cells."""

    @staticmethod
    def _seed_superset(conn, hostile_name: str) -> list:
        """Two findings where the hostile-named one covers the other's hosts."""
        conn.execute("INSERT INTO scans (scan_name, export_root) VALUES ('s','/tmp')")
        scan_id = conn.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
        conn.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (?,?,4)",
            (100, hostile_name),
        )
        conn.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) "
            "VALUES (101,'Covered Finding',3)"
        )
        for ip in ("10.0.0.1", "10.0.0.2"):
            # scan_target / scan_target_type are NOT NULL; OR IGNORE would
            # silently swallow the violation and leave no row behind.
            conn.execute(
                "INSERT INTO hosts (ip_address, scan_target, scan_target_type) "
                "VALUES (?, ?, 'ipv4')",
                (ip, ip),
            )
        conn.execute("INSERT OR IGNORE INTO ports (port_number) VALUES (445)")

        findings = []
        for plugin_id, ips in ((100, ("10.0.0.1", "10.0.0.2")), (101, ("10.0.0.1",))):
            conn.execute(
                "INSERT INTO findings (scan_id, plugin_id) VALUES (?,?)",
                (scan_id, plugin_id),
            )
            fid = conn.execute(
                "SELECT finding_id FROM findings WHERE plugin_id = ?", (plugin_id,)
            ).fetchone()["finding_id"]
            for ip in ips:
                host_id = conn.execute(
                    "SELECT host_id FROM hosts WHERE ip_address = ?", (ip,)
                ).fetchone()["host_id"]
                conn.execute(
                    "INSERT INTO finding_affected_hosts "
                    "(finding_id, host_id, port_number) VALUES (?,?,445)",
                    (fid, host_id),
                )
            findings.append(fid)
        conn.commit()
        return findings

    @pytest.mark.parametrize("name,token", HOSTILE_CASES)
    def test_overlap_groups_table(self, temp_db, monkeypatch, name, token):
        from cerno_pkg import analysis

        fids = self._seed_superset(temp_db, name)
        pairs = [
            (
                Finding(finding_id=fids[0], scan_id=1, plugin_id=100),
                Plugin(plugin_id=100, plugin_name=name, severity_int=4),
            ),
            (
                Finding(finding_id=fids[1], scan_id=1, plugin_id=101),
                Plugin(plugin_id=101, plugin_name="Covered Finding", severity_int=3),
            ),
        ]

        out = _capture(
            monkeypatch,
            analysis,
            lambda: analysis.analyze_inclusions(pairs, conn=temp_db),
        )

        assert token in out
