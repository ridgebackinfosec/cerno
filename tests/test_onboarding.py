"""Tests for onboarding guidance, focused on multi-scan ``scan_ids`` handling.

``show_workflow_guidance`` and ``_show_context_aware_tips`` both derive an
``effective_scan_ids`` list from an ``Optional[list[int]]``, which decides both
the scan set their COUNT queries span and the singular/plural wording. These
tests pin that behavior down for the None / single / multi cases.
"""

import io
import sqlite3

import pytest
from rich.console import Console

import cerno_pkg.database as db
from cerno_pkg import onboarding


def _seed_two_scans(conn: sqlite3.Connection) -> list[int]:
    """Two scans, each with one Critical (severity 4) finding."""
    scan_ids = []
    for name in ("alpha", "beta"):
        conn.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, '/tmp')", (name,)
        )
        scan_ids.append(
            conn.execute(
                "SELECT scan_id FROM scans WHERE scan_name = ?", (name,)
            ).fetchone()["scan_id"]
        )
    conn.execute(
        "INSERT INTO plugins (plugin_id, plugin_name, severity_int) "
        "VALUES (100, 'SMB Signing Disabled', 4)"
    )
    for sid in scan_ids:
        conn.execute(
            "INSERT INTO findings (scan_id, plugin_id, review_state) "
            "VALUES (?, 100, 'unreviewed')",
            (sid,),
        )
    conn.commit()
    return scan_ids


@pytest.fixture
def patched_db(temp_db: sqlite3.Connection, monkeypatch) -> sqlite3.Connection:
    """Point onboarding's lazily-imported get_connection at the temp DB."""
    monkeypatch.setattr(db, "get_connection", lambda *a, **k: temp_db)
    return temp_db


@pytest.fixture
def no_prompt(monkeypatch) -> None:
    """show_workflow_guidance ends on a Prompt.ask; keep it non-interactive."""
    monkeypatch.setattr(onboarding.Prompt, "ask", staticmethod(lambda *a, **k: ""))


def _render(renderable) -> str:
    buf = io.StringIO()
    Console(file=buf, width=200, force_terminal=False).print(renderable)
    return buf.getvalue()


@pytest.mark.integration
class TestContextAwareTipsScanIds:
    def test_single_scan_counts_only_that_scan(self, patched_db):
        """scan_ids=None must fall back to the primary scan alone."""
        first, _second = _seed_two_scans(patched_db)

        panel = onboarding._show_context_aware_tips(
            first, total=1, unreviewed=1, completed=0, scan_ids=None
        )

        assert panel is not None
        out = _render(panel)
        assert "This scan has 1 Critical finding(s)" in out

    def test_single_element_scan_ids_is_not_multi(self, patched_db):
        """A one-element scan_ids is a single-scan review, not a merged one."""
        first, _second = _seed_two_scans(patched_db)

        panel = onboarding._show_context_aware_tips(
            first, total=1, unreviewed=1, completed=0, scan_ids=[first]
        )

        assert panel is not None
        out = _render(panel)
        assert "This scan has 1 Critical finding(s)" in out

    def test_multi_scan_aggregates_across_all_scans(self, patched_db):
        """scan_ids with >1 entry must span every selected scan and pluralize."""
        first, second = _seed_two_scans(patched_db)

        panel = onboarding._show_context_aware_tips(
            first, total=2, unreviewed=2, completed=0, scan_ids=[first, second]
        )

        assert panel is not None
        out = _render(panel)
        assert "These scans have 2 Critical finding(s)" in out


@pytest.mark.integration
class TestWorkflowGuidanceScanIds:
    def test_multi_scan_label_uses_both_names(self, patched_db, no_prompt, capsys):
        first, second = _seed_two_scans(patched_db)

        onboarding.show_workflow_guidance(
            "alpha",
            first,
            scan_ids=[first, second],
            scan_names=["alpha", "beta"],
        )

        assert "alpha + beta" in capsys.readouterr().out

    def test_single_scan_does_not_crash_without_scan_ids(
        self, patched_db, no_prompt, capsys
    ):
        """The Optional[list[int]] path must not blow up when omitted."""
        first, _second = _seed_two_scans(patched_db)

        onboarding.show_workflow_guidance("alpha", first)

        assert "alpha" in capsys.readouterr().out

    def test_skipped_when_a_session_already_exists(self, patched_db, no_prompt, capsys):
        """Guidance is first-run only; an existing session suppresses it."""
        first, _second = _seed_two_scans(patched_db)
        patched_db.execute(
            "INSERT INTO sessions (scan_id, session_start) VALUES (?, ?)",
            (first, "2026-10-29T00:00:00"),
        )
        patched_db.commit()

        onboarding.show_workflow_guidance("alpha", first)

        assert capsys.readouterr().out == ""
