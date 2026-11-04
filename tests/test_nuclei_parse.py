"""Tests for the pure nuclei result parser (cerno_pkg.nuclei_parse).

Fixtures under tests/fixtures/nuclei/ are derived from a real
``nuclei -je`` export (anonymized, with request/response stripped), so the
record shapes and the duplicate-match pattern are the genuine article rather
than something invented for the test.
"""

from pathlib import Path

import pytest

from cerno_pkg.nuclei_parse import (
    NUCLEI_TEMPLATE_REPO_BASE,
    NUCLEI_TEMPLATE_URL_BASE,
    classify_cvss,
    extract_cves,
    format_plugin_output,
    normalize_port,
    parse_nuclei_file,
    resolve_template_url,
    safe_template_repo_url,
    severity_to_int,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nuclei"


@pytest.mark.unit
class TestSeverityToInt:
    def test_the_five_real_levels(self) -> None:
        assert severity_to_int("info") == 0
        assert severity_to_int("low") == 1
        assert severity_to_int("medium") == 2
        assert severity_to_int("high") == 3
        assert severity_to_int("critical") == 4

    def test_case_and_whitespace_insensitive(self) -> None:
        assert severity_to_int("  CRITICAL ") == 4

    def test_nuclei_unknown_and_undefined_floor_to_info(self) -> None:
        # Neither has a severity_levels row; Info is the conservative floor.
        assert severity_to_int("unknown") == 0
        assert severity_to_int("") == 0
        assert severity_to_int(None) == 0

    def test_unrecognized_label_floors_to_info(self) -> None:
        assert severity_to_int("catastrophic") == 0


@pytest.mark.unit
class TestExtractCves:
    def test_json_null_yields_empty(self) -> None:
        # The real sample had cve-id: null in 14/14 classification blocks.
        assert extract_cves(None) == []

    def test_bare_string(self) -> None:
        assert extract_cves("CVE-2021-44228") == ["CVE-2021-44228"]

    def test_list(self) -> None:
        assert extract_cves(["CVE-2021-44228", "CVE-2023-12345"]) == [
            "CVE-2021-44228",
            "CVE-2023-12345",
        ]

    def test_uppercases_and_sorts_and_dedupes(self) -> None:
        assert extract_cves(["cve-2024-0001", "CVE-2024-0001", "CVE-2023-9999"]) == [
            "CVE-2023-9999",
            "CVE-2024-0001",
        ]

    def test_filters_malformed_ids(self) -> None:
        assert extract_cves(["CVE-2023-12345", "CVE-21-1", "not-a-cve", ""]) == [
            "CVE-2023-12345"
        ]

    def test_comma_separated_string(self) -> None:
        assert extract_cves("CVE-2021-44228,CVE-2023-12345") == [
            "CVE-2021-44228",
            "CVE-2023-12345",
        ]


@pytest.mark.unit
class TestClassifyCvss:
    def test_v3_metrics_go_to_cvss3(self) -> None:
        assert classify_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H", 9.8) == (
            9.8,
            None,
        )

    def test_v2_prefixed_metrics_go_to_cvss2(self) -> None:
        assert classify_cvss("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5) == (None, 7.5)

    def test_legacy_unprefixed_v2_vector_goes_to_cvss2(self) -> None:
        assert classify_cvss("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5) == (None, 7.5)

    def test_v4_metrics_recorded_in_cvss3_column(self) -> None:
        # Cerno has no cvss4 column; v3 is the closest slot. Documented.
        assert classify_cvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N", 8.7) == (8.7, None)

    def test_no_metrics_defaults_to_cvss3(self) -> None:
        assert classify_cvss(None, 5.0) == (5.0, None)

    def test_no_score_yields_neither(self) -> None:
        assert classify_cvss("CVSS:3.1/AV:N", None) == (None, None)
        assert classify_cvss(None, None) == (None, None)

    def test_zero_score_is_not_treated_as_missing(self) -> None:
        assert classify_cvss("CVSS:3.1/AV:N", 0.0) == (0.0, None)


@pytest.mark.unit
class TestNormalizePort:
    def test_plain_port(self) -> None:
        assert normalize_port("443", None) == 443

    def test_integer_input(self) -> None:
        assert normalize_port(8080, None) == 8080

    def test_zero_empty_and_missing_are_none(self) -> None:
        # ports.port_number has CHECK(port_number BETWEEN 1 AND 65535).
        assert normalize_port("0", None) is None
        assert normalize_port("", None) is None
        assert normalize_port(None, None) is None

    def test_out_of_range_is_none(self) -> None:
        assert normalize_port("99999", None) is None
        assert normalize_port("-1", None) is None

    def test_non_numeric_is_none(self) -> None:
        assert normalize_port("abc", None) is None

    def test_derives_from_scheme_when_port_absent(self) -> None:
        assert normalize_port(None, "https") == 443
        assert normalize_port(None, "http") == 80

    def test_explicit_port_wins_over_scheme(self) -> None:
        assert normalize_port("8443", "https") == 8443

    def test_unknown_scheme_yields_none(self) -> None:
        assert normalize_port(None, "ftp") is None


@pytest.mark.integration
class TestParseRealExport:
    """The -je array fixture: 28 real records over 20 distinct templates."""

    def test_array_shape_parses(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        assert not result.is_empty
        assert result.total_matches == 28
        assert len(result.templates) == 20

    def test_jsonl_shape_parses_identically(self) -> None:
        as_array = parse_nuclei_file(FIXTURES / "web_scan.json")
        as_jsonl = parse_nuclei_file(FIXTURES / "web_scan.jsonl")
        assert as_jsonl.total_matches == as_array.total_matches
        assert [t.template_id for t in as_jsonl.templates] == [
            t.template_id for t in as_array.templates
        ]

    def test_collisions_are_preserved_not_collapsed(self) -> None:
        """The parser keeps every match; the importer merges them."""
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        assert len(by_id["http-missing-security-headers"].matches) == 6
        assert len(by_id["tech-detect"].matches) == 3
        assert len(by_id["tls-version"].matches) == 2

    def test_matcher_name_discriminates_security_header_matches(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        names = {m.matcher_name for m in by_id["http-missing-security-headers"].matches}
        assert "content-security-policy" in names
        assert "strict-transport-security" in names
        assert len(names) == 6

    def test_extracted_results_discriminate_when_matcher_name_absent(self) -> None:
        """tls-version carries no matcher-name; only extracted-results differ."""
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        matches = by_id["tls-version"].matches
        assert all(m.matcher_name is None for m in matches)
        assert sorted(tuple(m.extracted_results) for m in matches) == [
            ("tls12",),
            ("tls13",),
        ]

    def test_dns_records_have_no_port_and_fall_back_to_host_for_ip(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        dns = [m for t in result.templates for m in t.matches if m.result_type == "dns"]
        assert len(dns) == 8
        assert all(m.port is None for m in dns)
        assert all(m.ip is None for m in dns)
        # hosts.ip_address is NOT NULL, so the importer needs this fallback.
        assert all(m.effective_ip == m.host for m in dns)

    def test_http_and_ssl_records_carry_port_and_ip(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        web = [
            m
            for t in result.templates
            for m in t.matches
            if m.result_type in ("http", "ssl")
        ]
        assert len(web) == 20
        assert all(m.port == 443 for m in web)
        assert all(m.effective_ip == "192.0.2.10" for m in web)

    def test_template_url_prefers_the_template_source(self) -> None:
        """`template` (the repo path) beats `template-url` (the viewer)."""
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["ssl-dns-names"].template_url == (
            NUCLEI_TEMPLATE_REPO_BASE + "ssl/ssl-dns-names.yaml"
        )

    def test_all_sample_records_are_info_severity(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        assert {t.severity_int for t in result.templates} == {0}

    def test_local_template_path_is_never_surfaced(self) -> None:
        """template-path leaks the operator's home dir; it must not be retained."""
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        for template in result.templates:
            for match in template.matches:
                assert "nuclei-templates" not in repr(match)


@pytest.mark.integration
class TestParseAdversarial:
    def test_non_matches_are_filtered(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        ids = {t.template_id for t in result.templates}
        assert "non-match-must-be-filtered" not in ids
        assert result.skipped_non_matches == 1

    def test_record_without_template_id_is_skipped(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        assert result.skipped_malformed == 1
        assert result.total_matches == 16

    def test_expected_template_count(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        # 18 lines - 1 non-match - 1 missing id = 16 matches over 15 templates
        assert len(result.templates) == 15

    def test_null_cve_id(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["cve-null-classification"].cves == []
        assert by_id["cve-null-classification"].cvss3_score == 9.8
        assert by_id["cve-null-classification"].cvss2_score is None

    def test_scalar_stringslices(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        tmpl = by_id["scalar-stringslices"]
        assert tmpl.cves == ["CVE-2021-44228"]
        assert tmpl.cvss2_score == 7.5
        assert tmpl.cvss3_score is None

    def test_malformed_cves_filtered_from_list(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["cve-list-with-invalid"].cves == [
            "CVE-2023-12345",
            "CVE-2024-0001",
        ]

    def test_unmapped_severities_floor_to_info(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["severity-unknown"].severity_int == 0
        assert by_id["severity-empty-string"].severity_int == 0
        assert by_id["severity-absent"].severity_int == 0

    def test_port_edge_cases_become_none(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        for tid in ("port-zero", "port-empty-string", "port-out-of-range"):
            assert by_id[tid].matches[0].port is None, tid

    def test_name_falls_back_to_template_id(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["empty-info-block"].template_name == "empty-info-block"
        assert by_id["no-info-block-at-all"].template_name == "no-info-block-at-all"

    def test_template_url_falls_back_to_public_base(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["severity-unknown"].template_url == (
            NUCLEI_TEMPLATE_URL_BASE + "severity-unknown"
        )

    def test_ipv6_host(self) -> None:
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        match = by_id["ipv6-host"].matches[0]
        assert match.port == 8443
        assert match.effective_ip == "2001:db8::1"

    def test_escapes_survive_parsing_untouched(self) -> None:
        """The parser must not sanitize - the DB holds what the scanner said."""
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert "\x1b" in by_id["esc-in-untrusted-text"].template_name
        assert any(
            "\x1b" in value
            for value in by_id["esc-in-untrusted-text"].matches[0].extracted_results
        )


@pytest.mark.unit
class TestParseFailuresAreForgiving:
    """Mirrors parse_nmap_xml: never raise, return an empty result."""

    def test_missing_file(self) -> None:
        result = parse_nuclei_file(FIXTURES / "does_not_exist.json")
        assert result.is_empty

    def test_empty_file(self) -> None:
        result = parse_nuclei_file(FIXTURES / "empty.jsonl")
        assert result.is_empty

    def test_malformed_file(self) -> None:
        result = parse_nuclei_file(FIXTURES / "malformed.json")
        assert result.is_empty

    def test_directory_instead_of_file(self) -> None:
        assert parse_nuclei_file(FIXTURES).is_empty

    def test_partial_jsonl_keeps_good_lines(self, tmp_path: Path) -> None:
        """A truncated final line (interrupted scan) must not lose the rest."""
        good = (
            '{"template-id":"ok","info":{"name":"Fine","severity":"low"},'
            '"type":"http","host":"h.example.com","port":"80",'
            '"matched-at":"http://h.example.com/","matcher-status":true}'
        )
        path = tmp_path / "partial.jsonl"
        path.write_text(good + "\n" + '{"template-id":"trunc","info":{')
        result = parse_nuclei_file(path)
        assert [t.template_id for t in result.templates] == ["ok"]
        assert result.skipped_malformed == 1


@pytest.mark.unit
class TestFormatPluginOutput:
    def test_single_match(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        text = format_plugin_output(by_id["ssl-dns-names"].matches)
        assert "matched-at: example.com:443" in text
        assert "extracted: example.com" in text

    def test_merged_matches_retain_every_matcher_name(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        text = format_plugin_output(by_id["http-missing-security-headers"].matches)
        for name in (
            "content-security-policy",
            "strict-transport-security",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "x-permitted-cross-domain-policies",
        ):
            assert name in text

    def test_merged_matches_retain_distinct_extracted_results(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        text = format_plugin_output(by_id["tls-version"].matches)
        assert "tls12" in text and "tls13" in text

    def test_empty_matches(self) -> None:
        assert format_plugin_output([]) == ""

    def test_identical_curl_commands_are_not_repeated(self) -> None:
        """6 matches on one URL share one curl; printing it 6x buries the matchers."""
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        matches = by_id["http-missing-security-headers"].matches
        assert len(matches) == 6
        text = format_plugin_output(matches)
        assert text.count("curl: ") == 1

    def test_curl_commands_come_after_the_match_evidence(self) -> None:
        result = parse_nuclei_file(FIXTURES / "web_scan.json")
        by_id = {t.template_id: t for t in result.templates}
        text = format_plugin_output(by_id["http-missing-security-headers"].matches)
        assert text.index("matcher: ") < text.index("curl: ")


@pytest.mark.unit
class TestSafeTemplateRepoUrl:
    """`template` is attacker-influenced and is appended to a base URL, then
    interpolated into a Rich *style* string for the panel's OSC-8 link."""

    def test_plain_relative_yaml_path(self) -> None:
        assert safe_template_repo_url("http/cves/2021/CVE-2021-44228.yaml") == (
            NUCLEI_TEMPLATE_REPO_BASE + "http/cves/2021/CVE-2021-44228.yaml"
        )

    def test_yml_suffix_is_accepted(self) -> None:
        assert safe_template_repo_url("ssl/tls-version.yml") is not None

    def test_path_traversal_is_rejected(self) -> None:
        assert safe_template_repo_url("../../etc/passwd.yaml") is None
        assert safe_template_repo_url("http/../../../etc/passwd.yaml") is None

    def test_absolute_path_is_rejected(self) -> None:
        assert safe_template_repo_url("/etc/passwd.yaml") is None

    def test_whitespace_is_rejected(self) -> None:
        """Whitespace would become extra tokens in the Rich style string."""
        assert safe_template_repo_url("http/a b.yaml") is None
        assert safe_template_repo_url("http/a.yaml bold") is None

    def test_a_smuggled_url_is_rejected(self) -> None:
        assert safe_template_repo_url("https://evil.example/x.yaml") is None

    def test_non_yaml_suffix_is_rejected(self) -> None:
        assert safe_template_repo_url("http/x.txt") is None
        assert safe_template_repo_url("http/x") is None

    def test_empty_and_none(self) -> None:
        assert safe_template_repo_url("") is None
        assert safe_template_repo_url(None) is None


@pytest.mark.unit
class TestResolveTemplateUrl:
    """Most useful URL first: template source, then viewer, then derived."""

    def test_template_path_wins_over_template_url(self) -> None:
        url = resolve_template_url(
            {
                "template": "ssl/tls-version.yaml",
                "template-url": NUCLEI_TEMPLATE_URL_BASE + "tls-version",
            },
            "tls-version",
        )
        assert url == NUCLEI_TEMPLATE_REPO_BASE + "ssl/tls-version.yaml"

    def test_falls_back_to_template_url_when_path_is_absent(self) -> None:
        url = resolve_template_url(
            {"template-url": NUCLEI_TEMPLATE_URL_BASE + "tls-version"}, "tls-version"
        )
        assert url == NUCLEI_TEMPLATE_URL_BASE + "tls-version"

    def test_falls_back_when_the_path_is_hostile(self) -> None:
        url = resolve_template_url(
            {
                "template": "../../etc/passwd.yaml",
                "template-url": NUCLEI_TEMPLATE_URL_BASE + "tls-version",
            },
            "tls-version",
        )
        assert url == NUCLEI_TEMPLATE_URL_BASE + "tls-version"

    def test_derives_from_the_id_when_nothing_usable_is_present(self) -> None:
        """`template` is omitempty in nuclei's output, so this must always work."""
        assert resolve_template_url({}, "tls-version") == (
            NUCLEI_TEMPLATE_URL_BASE + "tls-version"
        )

    def test_adversarial_fixture_has_no_template_paths(self) -> None:
        """Guards the fallback coverage above against fixture drift."""
        result = parse_nuclei_file(FIXTURES / "adversarial.jsonl")
        by_id = {t.template_id: t for t in result.templates}
        assert by_id["severity-unknown"].template_url.startswith(
            NUCLEI_TEMPLATE_URL_BASE
        )
