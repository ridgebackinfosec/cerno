"""Tests for tool availability (OR semantics), the picker, and soft cmd checks."""

from unittest.mock import patch

import pytest

from cerno_pkg.config import CernoConfig
from cerno_pkg.tool_registry import Tool, get_available_tools


def _noop_workflow(*_a, **_k):
    return None


@pytest.mark.unit
class TestToolAvailability:
    def _tool(self, requires):
        return Tool(
            id="t",
            name="t",
            description="t",
            workflow_builder=_noop_workflow,
            requires=requires,
        )

    def test_no_requirements_is_always_available(self):
        assert self._tool([]).is_available() is True

    def test_or_semantics_either_binary_suffices(self):
        tool = self._tool(["nxc", "netexec"])
        # Only netexec present → still available (OR, not AND).
        with patch("shutil.which", side_effect=lambda c: c == "netexec"):
            assert tool.is_available() is True
        # Neither present → unavailable.
        with patch("shutil.which", return_value=None):
            assert tool.is_available() is False

    def test_hint_lists_acceptable_binaries(self):
        assert self._tool(["nxc", "netexec"]).missing_requirement_hint() == (
            "not installed: nxc/netexec"
        )


@pytest.mark.unit
def test_get_available_tools_filters_by_or_semantics():
    # Simulate only nmap present on PATH.
    with patch("shutil.which", side_effect=lambda c: c == "nmap"):
        ids = {t.id for t in get_available_tools(check_requirements=True)}
    assert "nmap" in ids
    assert "netexec" not in ids  # needs nxc or netexec, neither present
    assert "custom" in ids  # no requirements → always available


@pytest.mark.unit
class TestSelectToolPicker:
    def _nmap_index(self):
        tools = get_available_tools(check_requirements=False)
        for i, t in enumerate(tools, start=1):
            if t.id == "nmap":
                return i
        raise AssertionError("nmap not in registry")

    def test_enter_default_is_never_a_missing_tool(self):
        from cerno_pkg import tools as tools_mod

        cfg = CernoConfig(default_tool="nmap")  # default points at a missing tool
        # nmap missing; nxc present so netexec is available.
        with (
            patch("shutil.which", side_effect=lambda c: c in ("nxc",)),
            patch.object(tools_mod.Prompt, "ask", return_value=""),
        ):
            chosen = tools_mod.choose_tool(cfg)
        assert chosen != "nmap"
        assert chosen is not None  # fell back to an available tool

    def test_numeric_pick_of_missing_tool_is_rejected(self):
        from cerno_pkg import tools as tools_mod

        nmap_idx = self._nmap_index()
        # nmap missing; pick its index, then Back.
        with (
            patch("shutil.which", side_effect=lambda c: False),
            patch.object(tools_mod.Prompt, "ask", side_effect=[str(nmap_idx), "b"]),
            patch.object(tools_mod, "warn") as warn,
        ):
            chosen = tools_mod.choose_tool(CernoConfig())
        assert chosen is None  # never returned the missing tool
        assert warn.called


@pytest.mark.unit
class TestEnsureCmd:
    def test_ensure_cmd_true_when_present(self):
        from cerno_pkg import ops

        with patch("cerno_pkg.ops.shutil.which", return_value="/usr/bin/nmap"):
            assert ops.ensure_cmd("nmap") is True

    def test_ensure_cmd_false_without_exit(self):
        from cerno_pkg import ops

        with patch("cerno_pkg.ops.shutil.which", return_value=None):
            # Must NOT raise SystemExit (unlike require_cmd).
            assert ops.ensure_cmd("nmap") is False
