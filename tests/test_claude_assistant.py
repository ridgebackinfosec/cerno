"""Tests for cerno_pkg.claude_assistant module."""

from unittest.mock import patch

import pytest

from cerno_pkg.claude_assistant import build_aggregate_context, build_finding_context
from cerno_pkg.models import Finding, FindingType
from cerno_pkg.workflow_mapper import Workflow, WorkflowStep


@pytest.mark.unit
class TestBuildAggregateContext:
    """Tests for build_aggregate_context()."""

    def _make_finding_type(
        self,
        finding_type_id: int = 12345,
        name: str = "Test FindingType",
        severity: int = 2,
    ) -> FindingType:
        return FindingType(
            finding_type_id=finding_type_id,
            finding_type_name=name,
            severity_int=severity,
        )

    def _make_finding(
        self, finding_id: int = 1, dataset_id: int = 1, finding_type_id: int = 12345
    ) -> Finding:
        f = Finding(dataset_id=dataset_id, finding_type_id=finding_type_id)
        f.finding_id = finding_id
        return f

    def test_no_attribute_error_on_host_count(self):
        """Regression: Finding has no host_count attribute — must use get_hosts_and_ports()."""
        finding = self._make_finding()
        finding_type = self._make_finding_type()

        with patch.object(
            Finding, "get_hosts_and_ports", return_value=(["192.168.1.1"], "80")
        ):
            result = build_aggregate_context(
                dataset_names=["test_dataset"],
                scope_description="All findings",
                findings_with_finding_types=[(finding, finding_type)],
            )

        assert "1 hosts" in result

    def test_host_count_zero_when_no_hosts(self):
        """Finding with no affected hosts shows 0 hosts in context."""
        finding = self._make_finding()
        finding_type = self._make_finding_type()

        with patch.object(Finding, "get_hosts_and_ports", return_value=([], "")):
            result = build_aggregate_context(
                dataset_names=["test_dataset"],
                scope_description="All findings",
                findings_with_finding_types=[(finding, finding_type)],
            )

        assert "0 hosts" in result

    def test_context_includes_finding_type_name(self):
        """Context output includes finding_type name and severity."""
        finding = self._make_finding()
        finding_type = self._make_finding_type(name="MS17-010 EternalBlue", severity=4)

        with patch.object(
            Finding,
            "get_hosts_and_ports",
            return_value=(["10.0.0.1", "10.0.0.2"], "445"),
        ):
            result = build_aggregate_context(
                dataset_names=["corp_dataset"],
                scope_description="Critical findings",
                findings_with_finding_types=[(finding, finding_type)],
            )

        assert "MS17-010 EternalBlue" in result
        assert "Critical" in result
        assert "2 hosts" in result


@pytest.mark.unit
class TestBuildFindingContextWorkflow:
    """Tests for workflow section in build_finding_context()."""

    def _make_finding_type(
        self,
        finding_type_id: int = 11011,
        finding_type_name: str = "MS17-010",
        severity_int: int = 4,
    ) -> FindingType:
        return FindingType(
            finding_type_id=finding_type_id,
            finding_type_name=finding_type_name,
            severity_int=severity_int,
        )

    def _make_finding(
        self, finding_id: int = 1, dataset_id: int = 1, finding_type_id: int = 11011
    ) -> Finding:
        f = Finding(dataset_id=dataset_id, finding_type_id=finding_type_id)
        f.finding_id = finding_id
        return f

    def _make_workflow(self) -> Workflow:
        return Workflow(
            finding_type_id="nessus:11011",
            workflow_name="EternalBlue Check",
            description="Verify MS17-010 exploitability on affected hosts.",
            steps=[
                WorkflowStep(
                    title="Dataset with Nmap NSE",
                    commands=["nmap -p 445 --script smb-vuln-ms17-010 {hosts}"],
                    notes="Look for 'VULNERABLE' in output.",
                ),
                WorkflowStep(
                    title="Attempt exploitation",
                    commands=[
                        "use exploit/windows/smb/ms17_010_eternalblue",
                        "set RHOSTS {hosts}",
                        "run",
                    ],
                    notes="",
                ),
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        )

    def test_workflow_section_included_when_present(self):
        """When a Workflow is passed, context includes the full workflow section."""
        finding_type = self._make_finding_type()
        finding = self._make_finding()
        workflow = self._make_workflow()

        result = build_finding_context(
            finding_type, finding, hosts=[], workflow=workflow
        )

        assert "=== Verification Workflow ===" in result
        assert "EternalBlue Check" in result
        assert "Verify MS17-010 exploitability" in result
        assert "Dataset with Nmap NSE" in result
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
        finding_type = self._make_finding_type()
        finding = self._make_finding()

        result = build_finding_context(finding_type, finding, hosts=[], workflow=None)

        assert "=== Verification Workflow ===" not in result
        assert "=== End Workflow ===" not in result

    def test_no_workflow_section_when_omitted(self):
        """Omitting workflow= defaults to no workflow section (backward compat)."""
        finding_type = self._make_finding_type()
        finding = self._make_finding()

        result = build_finding_context(finding_type, finding, hosts=[])

        assert "=== Verification Workflow ===" not in result


@pytest.mark.unit
class TestClaudeConsent:
    """Tests for the opt-in gate and first-use consent flow."""

    def _cfg(self, enabled: bool):
        from cerno_pkg.config import CernoConfig

        return CernoConfig(claude_assistant_enabled=enabled)

    def test_claude_enabled_requires_install_and_flag(self):
        from cerno_pkg import claude_assistant as ca

        with patch.object(ca, "check_claude_available", return_value=True):
            assert ca.claude_enabled(self._cfg(True)) is True
            assert ca.claude_enabled(self._cfg(False)) is False
        with patch.object(ca, "check_claude_available", return_value=False):
            assert ca.claude_enabled(self._cfg(True)) is False

    def test_ensure_enabled_noop_when_already_on(self):
        from cerno_pkg import claude_assistant as ca

        cfg = self._cfg(True)
        with patch("cerno_pkg.config.save_config") as save:
            assert ca.ensure_enabled(cfg) is True
            save.assert_not_called()

    def test_ensure_enabled_persists_on_consent(self):
        from cerno_pkg import claude_assistant as ca

        cfg = self._cfg(False)
        with (
            patch("rich.prompt.Confirm.ask", return_value=True),
            patch("cerno_pkg.config.save_config", return_value=True) as save,
        ):
            assert ca.ensure_enabled(cfg) is True
            assert cfg.claude_assistant_enabled is True
            save.assert_called_once()

    def test_ensure_enabled_declined_leaves_disabled(self):
        from cerno_pkg import claude_assistant as ca

        cfg = self._cfg(False)
        with (
            patch("rich.prompt.Confirm.ask", return_value=False),
            patch("cerno_pkg.config.save_config") as save,
        ):
            assert ca.ensure_enabled(cfg) is False
            assert cfg.claude_assistant_enabled is False
            save.assert_not_called()
