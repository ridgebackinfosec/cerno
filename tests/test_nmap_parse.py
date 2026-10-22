"""Tests for the pure nmap XML parser (cerno_pkg.nmap_parse)."""

from pathlib import Path

import pytest

from cerno_pkg.nmap_parse import (
    VERDICT_NOT_VULNERABLE,
    VERDICT_UNKNOWN,
    VERDICT_VULNERABLE,
    classify_nse_verdict,
    parse_nmap_xml,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


@pytest.mark.unit
class TestClassifyNseVerdict:
    def test_vulnerable(self) -> None:
        assert classify_nse_verdict("  State: VULNERABLE") == VERDICT_VULNERABLE

    def test_not_vulnerable_wins_over_vulnerable_substring(self) -> None:
        # "NOT VULNERABLE" contains "VULNERABLE"; must classify as NOT.
        assert classify_nse_verdict("State: NOT VULNERABLE") == VERDICT_NOT_VULNERABLE

    def test_unknown_for_plain_output(self) -> None:
        assert classify_nse_verdict("message_signing: disabled") == VERDICT_UNKNOWN

    def test_none_and_empty(self) -> None:
        assert classify_nse_verdict(None) == VERDICT_UNKNOWN
        assert classify_nse_verdict("") == VERDICT_UNKNOWN


@pytest.mark.integration
class TestParseNmapXml:
    def test_parses_hosts_ports_scripts(self) -> None:
        result = parse_nmap_xml(FIXTURES / "ms17_vulnerable.xml")
        assert not result.is_empty
        # one up host, one down host
        states = {h.address: h.state for h in result.hosts}
        assert states == {"10.0.0.1": "up", "10.0.0.99": "down"}
        # open ports only come from the up host
        ports = {(p.port, p.state) for p in result.ports}
        assert (445, "open") in ports and (139, "open") in ports
        # the MS17-010 port script classifies VULNERABLE
        ms17 = next(s for s in result.scripts if s.script_id == "smb-vuln-ms17-010")
        assert ms17.verdict == VERDICT_VULNERABLE
        assert ms17.port == 445
        # the host script has port None
        hostscript = next(
            s for s in result.scripts if s.script_id == "smb-security-mode"
        )
        assert hostscript.port is None

    def test_empty_run_down_host_only(self) -> None:
        result = parse_nmap_xml(FIXTURES / "no_hosts_up.xml")
        assert result.ports == []
        assert result.scripts == []

    def test_missing_file_is_empty(self) -> None:
        assert parse_nmap_xml(FIXTURES / "does_not_exist.xml").is_empty

    def test_malformed_xml_is_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("<nmaprun><host><not-closed>")
        assert parse_nmap_xml(bad).is_empty
