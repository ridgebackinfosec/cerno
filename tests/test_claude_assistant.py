"""Tests for cerno_pkg.claude_assistant module."""

from unittest.mock import patch

import pytest

from cerno_pkg.claude_assistant import build_aggregate_context, build_finding_context
from cerno_pkg.models import Finding, Plugin
from cerno_pkg.workflow_mapper import Workflow, WorkflowStep


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


@pytest.mark.unit
class TestBuildFindingContextWorkflow:
    """Tests for workflow section in build_finding_context()."""

    def _make_plugin(self, plugin_id: int = 11011, plugin_name: str = "MS17-010", severity_int: int = 4) -> Plugin:
        return Plugin(plugin_id=plugin_id, plugin_name=plugin_name, severity_int=severity_int)

    def _make_finding(self, finding_id: int = 1, scan_id: int = 1, plugin_id: int = 11011) -> Finding:
        f = Finding(scan_id=scan_id, plugin_id=plugin_id)
        f.finding_id = finding_id
        return f

    def _make_workflow(self) -> Workflow:
        return Workflow(
            plugin_id="11011",
            workflow_name="EternalBlue Check",
            description="Verify MS17-010 exploitability on affected hosts.",
            steps=[
                WorkflowStep(
                    title="Scan with Nmap NSE",
                    commands=["nmap -p 445 --script smb-vuln-ms17-010 {hosts}"],
                    notes="Look for 'VULNERABLE' in output.",
                ),
                WorkflowStep(
                    title="Attempt exploitation",
                    commands=["use exploit/windows/smb/ms17_010_eternalblue", "set RHOSTS {hosts}", "run"],
                    notes="",
                ),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        )

    def test_workflow_section_included_when_present(self):
        """When a Workflow is passed, context includes the full workflow section."""
        plugin = self._make_plugin()
        finding = self._make_finding()
        workflow = self._make_workflow()

        result = build_finding_context(plugin, finding, hosts=[], workflow=workflow)

        assert "=== Verification Workflow ===" in result
        assert "EternalBlue Check" in result
        assert "Verify MS17-010 exploitability" in result
        assert "Scan with Nmap NSE" in result
        assert "nmap -p 445 --script smb-vuln-ms17-010 {hosts}" in result
        assert "Look for 'VULNERABLE'" in result
        assert "Attempt exploitation" in result
        assert "use exploit/windows/smb/ms17_010_eternalblue" in result
        assert "set RHOSTS {hosts}" in result
        assert "References:" in result
        assert "https://nvd.nist.gov/vuln/detail/CVE-2017-0144" in result
        assert "=== End Workflow ===" in result
        assert result.count("Notes:") == 1

    def test_no_workflow_section_when_none(self):
        """When workflow=None, no workflow section appears in context."""
        plugin = self._make_plugin()
        finding = self._make_finding()

        result = build_finding_context(plugin, finding, hosts=[], workflow=None)

        assert "=== Verification Workflow ===" not in result
        assert "=== End Workflow ===" not in result

    def test_no_workflow_section_when_omitted(self):
        """Omitting workflow= defaults to no workflow section (backward compat)."""
        plugin = self._make_plugin()
        finding = self._make_finding()

        result = build_finding_context(plugin, finding, hosts=[])

        assert "=== Verification Workflow ===" not in result
