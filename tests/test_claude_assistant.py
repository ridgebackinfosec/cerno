"""Tests for cerno_pkg.claude_assistant module."""

from unittest.mock import patch

import pytest

from cerno_pkg.claude_assistant import build_aggregate_context
from cerno_pkg.models import Finding, Plugin


@pytest.mark.unit
class TestBuildAggregateContext:
    """Tests for build_aggregate_context()."""

    def _make_plugin(self, plugin_id: int = 12345, name: str = "Test Plugin", severity: int = 2) -> Plugin:
        return Plugin(plugin_id=plugin_id, plugin_name=name, severity_int=severity)

    def _make_finding(self, finding_id: int = 1, scan_id: int = 1, plugin_id: int = 12345) -> Finding:
        f = Finding(scan_id=scan_id, plugin_id=plugin_id)
        f.finding_id = finding_id
        return f

    def test_no_attribute_error_on_host_count(self):
        """Regression: Finding has no host_count attribute — must use get_hosts_and_ports()."""
        finding = self._make_finding()
        plugin = self._make_plugin()

        with patch.object(Finding, "get_hosts_and_ports", return_value=(["192.168.1.1"], "80")):
            result = build_aggregate_context(
                scan_names=["test_scan"],
                scope_description="All findings",
                findings_with_plugins=[(finding, plugin)],
            )

        assert "1 hosts" in result

    def test_host_count_zero_when_no_hosts(self):
        """Finding with no affected hosts shows 0 hosts in context."""
        finding = self._make_finding()
        plugin = self._make_plugin()

        with patch.object(Finding, "get_hosts_and_ports", return_value=([], "")):
            result = build_aggregate_context(
                scan_names=["test_scan"],
                scope_description="All findings",
                findings_with_plugins=[(finding, plugin)],
            )

        assert "0 hosts" in result

    def test_context_includes_plugin_name(self):
        """Context output includes plugin name and severity."""
        finding = self._make_finding()
        plugin = self._make_plugin(name="MS17-010 EternalBlue", severity=4)

        with patch.object(Finding, "get_hosts_and_ports", return_value=(["10.0.0.1", "10.0.0.2"], "445")):
            result = build_aggregate_context(
                scan_names=["corp_scan"],
                scope_description="Critical findings",
                findings_with_plugins=[(finding, plugin)],
            )

        assert "MS17-010 EternalBlue" in result
        assert "Critical" in result
        assert "2 hosts" in result
