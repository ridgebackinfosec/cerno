"""Tests for the pure Burp Suite report parser (cerno_pkg.burp_parse).

The fixture under tests/fixtures/burp/ reproduces the element shapes Burp's
"Report issues" XML export writes, including the three request/response forms
(base64, plain, absent), a dismissed issue, the shared extension type index and
an unusable one.
"""

from pathlib import Path

import pytest

from cerno_pkg.constants import (
    BURP_KB_BASE,
    BURP_MAX_INSTANCES_RENDERED,
    BURP_RESPONSE_MAX_BYTES,
)
from cerno_pkg.burp_parse import (
    ParsedBurpInstance,
    extract_cwes,
    find_cves,
    format_plugin_output,
    html_to_text,
    kb_url,
    parse_burp_file,
    severity_to_int,
    split_target,
    type_to_ref,
)

FIXTURES = Path(__file__).parent / "fixtures" / "burp"
WEB_SCAN = FIXTURES / "web_scan.xml"


@pytest.mark.unit
class TestSeverityToInt:
    def test_burps_four_levels(self) -> None:
        assert severity_to_int("Information") == 0
        assert severity_to_int("Low") == 1
        assert severity_to_int("Medium") == 2
        assert severity_to_int("High") == 3

    def test_high_is_not_critical(self) -> None:
        # Burp has no Critical; nothing it reports may land in severity 4.
        assert severity_to_int("High") != 4

    def test_case_and_whitespace_insensitive(self) -> None:
        assert severity_to_int("  hIgH  ") == 3

    def test_info_spelling_variant(self) -> None:
        assert severity_to_int("Info") == 0

    def test_unrecognized_floors_to_info(self) -> None:
        # severity_levels is an FK and v_plugins_with_severity an INNER JOIN,
        # so an unmapped value would make the finding vanish, not fail loudly.
        assert severity_to_int("Catastrophic") == 0
        assert severity_to_int(None) == 0


@pytest.mark.unit
class TestTypeToRef:
    def test_decimal_type_becomes_eight_digit_hex(self) -> None:
        assert type_to_ref("2097920", "Cross-site scripting (reflected)") == "00200300"

    def test_hex_ref_matches_the_published_kb_page(self) -> None:
        ref = type_to_ref("2097920", "Cross-site scripting (reflected)")
        assert kb_url(ref) == BURP_KB_BASE + "00200300"

    def test_extension_type_is_slugged_by_name(self) -> None:
        assert type_to_ref("134217728", "JWT none algorithm accepted") == (
            "08000000-jwt-none-algorithm-accepted"
        )

    def test_two_extension_issues_do_not_collide(self) -> None:
        first = type_to_ref("134217728", "JWT none algorithm accepted")
        second = type_to_ref("134217728", "Hardcoded API key in JavaScript")
        assert first != second

    def test_slugged_ref_has_no_knowledge_base_page(self) -> None:
        assert kb_url("08000000-jwt-none-algorithm-accepted") is None

    def test_zero_type_is_also_generic(self) -> None:
        assert type_to_ref("0", "Something custom") == "00000000-something-custom"

    def test_non_integer_type_is_unusable(self) -> None:
        assert type_to_ref("not-a-number", "Broken issue") is None

    def test_missing_type_is_unusable(self) -> None:
        assert type_to_ref(None, "Broken issue") is None

    def test_unnamed_generic_issue_still_gets_a_ref(self) -> None:
        assert type_to_ref("134217728", "") == "08000000"


@pytest.mark.unit
class TestHtmlToText:
    def test_tags_are_stripped(self) -> None:
        assert html_to_text("<p>Hello <b>world</b></p>") == "Hello world"

    def test_entities_are_unescaped(self) -> None:
        assert html_to_text("&lt;script&gt;alert(1)&lt;/script&gt;") == (
            "<script>alert(1)</script>"
        )

    def test_block_tags_become_newlines(self) -> None:
        assert html_to_text("<p>one</p><p>two</p>") == "one\ntwo"
        assert html_to_text("first<br>second") == "first\nsecond"

    def test_list_items_become_lines(self) -> None:
        assert html_to_text("<ul><li>a</li><li>b</li></ul>") == "a\nb"

    def test_blank_runs_collapse(self) -> None:
        assert html_to_text("<p>a</p><p></p><p></p><p>b</p>") == "a\nb"

    def test_empty_and_none(self) -> None:
        assert html_to_text("") == ""
        assert html_to_text(None) == ""


@pytest.mark.unit
class TestClassificationExtraction:
    def test_cwes_from_classification_block(self) -> None:
        raw = (
            '<ul><li><a href="https://cwe.mitre.org/data/definitions/79.html">'
            "CWE-79: Improper Neutralization</a></li>"
            '<li><a href="...">CWE-80: Script-Related HTML Tags</a></li></ul>'
        )
        assert extract_cwes(raw) == ["CWE-79", "CWE-80"]

    def test_cwes_are_deduplicated_and_sorted_numerically(self) -> None:
        assert extract_cwes("CWE-200 CWE-79 CWE-200") == ["CWE-79", "CWE-200"]

    def test_no_cwes(self) -> None:
        assert extract_cwes("no classification here") == []
        assert extract_cwes(None) == []

    def test_cves_are_found_in_prose(self) -> None:
        assert find_cves("see CVE-2021-44228 for details") == ["CVE-2021-44228"]

    def test_malformed_cves_are_dropped(self) -> None:
        # Same validation the Nessus and nuclei importers apply.
        assert find_cves("CVE-21-4 and CVE-2021-1") == []

    def test_cves_are_deduplicated_and_sorted(self) -> None:
        assert find_cves("CVE-2022-0001 cve-2021-44228 CVE-2022-0001") == [
            "CVE-2021-44228",
            "CVE-2022-0001",
        ]


@pytest.mark.unit
class TestSplitTarget:
    def test_https_defaults_to_443(self) -> None:
        assert split_target("https://web01.corp.local") == (
            "https",
            "web01.corp.local",
            443,
        )

    def test_http_defaults_to_80(self) -> None:
        assert split_target("http://web02.corp.local") == (
            "http",
            "web02.corp.local",
            80,
        )

    def test_explicit_port_wins(self) -> None:
        assert split_target("http://web01.corp.local:8080") == (
            "http",
            "web01.corp.local",
            8080,
        )

    def test_ipv6_brackets_are_removed_from_the_host(self) -> None:
        # hosts.ip_address stores bare addresses; a bracketed form would key a
        # second, duplicate host row.
        assert split_target("https://[2001:db8::21]:8443") == (
            "https",
            "2001:db8::21",
            8443,
        )

    def test_out_of_range_port_becomes_none(self) -> None:
        # ports.port_number CHECKs BETWEEN 1 AND 65535.
        assert split_target("http://web01.corp.local:0")[2] is None

    def test_unparseable_target_is_tolerated(self) -> None:
        assert split_target("") == ("", "", None)


@pytest.mark.unit
class TestFormatPluginOutput:
    @staticmethod
    def _instance(**kw) -> ParsedBurpInstance:
        base = dict(
            host="web01.corp.local",
            ip="10.0.0.21",
            port=443,
            scheme="https",
            path="/search",
            location="/search [q parameter]",
            confidence="Certain",
            detail="A detail line.",
            request=None,
            response=None,
        )
        base.update(kw)
        return ParsedBurpInstance(**base)  # type: ignore[arg-type]

    def test_location_confidence_and_detail_are_rendered(self) -> None:
        out = format_plugin_output([self._instance()])
        assert "/search [q parameter]" in out
        assert "Certain" in out
        assert "A detail line." in out

    def test_request_and_response_come_last(self) -> None:
        out = format_plugin_output(
            [self._instance(request="GET / HTTP/1.1", response="HTTP/1.1 200 OK")]
        )
        assert out.index("A detail line.") < out.index("GET / HTTP/1.1")
        assert out.index("GET / HTTP/1.1") < out.index("HTTP/1.1 200 OK")

    def test_every_instance_is_kept_up_to_the_cap(self) -> None:
        instances = [
            self._instance(location=f"/search [p{i} parameter]")
            for i in range(BURP_MAX_INSTANCES_RENDERED)
        ]
        out = format_plugin_output(instances)
        for i in range(BURP_MAX_INSTANCES_RENDERED):
            assert f"/search [p{i} parameter]" in out
        assert "more instance" not in out

    def test_instances_beyond_the_cap_are_summarised(self) -> None:
        instances = [
            self._instance(location=f"/search [p{i} parameter]")
            for i in range(BURP_MAX_INSTANCES_RENDERED + 3)
        ]
        out = format_plugin_output(instances)
        assert f"/search [p{BURP_MAX_INSTANCES_RENDERED} parameter]" not in out
        assert "3 more instances" in out

    def test_empty_instance_list(self) -> None:
        assert format_plugin_output([]) == ""


@pytest.fixture(scope="module")
def parsed():
    return parse_burp_file(WEB_SCAN)


@pytest.mark.unit
class TestParseBurpFile:
    def test_issue_types_are_grouped(self, parsed) -> None:
        refs = {issue.type_ref for issue in parsed.issues}
        assert refs == {
            "00200300",  # reflected XSS, three instances over two ports
            "00200100",  # the markup-injection issue
            "00600600",  # robots.txt
            "01000100",  # TLS certificate
            "08000000-jwt-none-algorithm-accepted",
            "08000000-hardcoded-api-key-in-javascript",
        }

    def test_dismissed_issue_is_skipped_not_imported_as_info(self, parsed) -> None:
        names = {issue.name for issue in parsed.issues}
        assert "Frameable response (potential Clickjacking)" not in names
        assert parsed.skipped_false_positives == 1

    def test_unusable_type_is_counted_as_malformed(self, parsed) -> None:
        assert parsed.skipped_malformed == 1
        assert "Broken issue" not in {issue.name for issue in parsed.issues}

    def test_instances_of_one_type_are_collected_together(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert len(xss.instances) == 3

    def test_severity_is_the_worst_seen_across_instances(self, parsed) -> None:
        # The third XSS instance is Medium; the issue must stay High.
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert xss.severity_int == 3

    def test_details_url_is_the_knowledge_base_page(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert xss.url == BURP_KB_BASE + "00200300"

    def test_extension_issue_has_no_details_url(self, parsed) -> None:
        jwt = next(
            i
            for i in parsed.issues
            if i.type_ref.endswith("jwt-none-algorithm-accepted")
        )
        assert jwt.url is None

    def test_cwes_are_captured(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert xss.cwes == ["CWE-79", "CWE-80"]

    def test_cves_found_in_prose_are_captured(self, parsed) -> None:
        tls = next(i for i in parsed.issues if i.type_ref == "01000100")
        assert tls.cves == ["CVE-2021-44228"]

    def test_prose_reaches_the_issue_as_plain_text(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert "<p>" not in xss.background
        assert xss.background.startswith("Reflected cross-site scripting")

    def test_detail_html_is_stripped_per_instance(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        first = xss.instances[0]
        assert "<b>" not in first.detail
        assert "<script>alert(1)</script>" in first.detail

    def test_base64_request_and_response_are_decoded(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        first = xss.instances[0]
        assert first.request is not None
        assert first.request.startswith("GET /search?q=")
        assert first.response is not None
        assert "alert(1)" in first.response

    def test_plain_text_request_response_is_taken_as_is(self, parsed) -> None:
        robots = next(i for i in parsed.issues if i.type_ref == "00600600")
        instance = robots.instances[0]
        assert instance.request is not None
        assert instance.request.startswith("GET /robots.txt")
        assert instance.response is not None
        assert "Disallow: /admin" in instance.response

    def test_issue_without_requestresponse_has_none(self, parsed) -> None:
        tls = next(i for i in parsed.issues if i.type_ref == "01000100")
        assert tls.instances[0].request is None
        assert tls.instances[0].response is None

    def test_ports_come_from_the_target_url(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert sorted({i.port for i in xss.instances}) == [443, 8080]

    def test_missing_ip_attribute_falls_back_to_the_host(self, parsed) -> None:
        robots = next(i for i in parsed.issues if i.type_ref == "00600600")
        instance = robots.instances[0]
        assert instance.ip is None
        assert instance.effective_ip == "web02.corp.local"

    def test_ipv6_target_is_unbracketed(self, parsed) -> None:
        tls = next(i for i in parsed.issues if i.type_ref == "01000100")
        assert tls.instances[0].host == "2001:db8::21"

    def test_service_name_comes_from_the_scheme(self, parsed) -> None:
        xss = next(i for i in parsed.issues if i.type_ref == "00200300")
        assert {i.service_name for i in xss.instances} == {"https", "http"}

    def test_markup_is_preserved_verbatim_for_the_renderer_to_neutralize(
        self, parsed
    ) -> None:
        # The database holds exactly what the scanner reported; only terminal
        # rendering is unsafe. See tests/test_markup_injection.py.
        injected = next(i for i in parsed.issues if i.type_ref == "00200100")
        assert "[/]" in injected.name

    def test_totals(self, parsed) -> None:
        assert parsed.total_instances == 8
        assert not parsed.is_empty


@pytest.mark.unit
class TestParseBurpFileIsForgiving:
    def test_missing_file(self, tmp_path) -> None:
        result = parse_burp_file(tmp_path / "nope.xml")
        assert result.is_empty
        assert result.issues == []

    def test_directory(self, tmp_path) -> None:
        assert parse_burp_file(tmp_path).is_empty

    def test_empty_file(self, tmp_path) -> None:
        path = tmp_path / "empty.xml"
        path.write_text("")
        assert parse_burp_file(path).is_empty

    def test_truncated_xml(self, tmp_path) -> None:
        # An export interrupted mid-write: keep what was flushed, do not raise.
        path = tmp_path / "truncated.xml"
        path.write_text(
            '<?xml version="1.0"?>\n<issues>\n'
            "<issue><type>2097920</type><name>XSS</name>"
            '<host ip="10.0.0.1">https://a.example</host>'
            "<severity>High</severity></issue>\n"
            "<issue><type>6291712</type><name>Rob"
        )
        result = parse_burp_file(path)
        assert [i.type_ref for i in result.issues] == ["00200300"]

    def test_not_a_burp_report(self, tmp_path) -> None:
        # .xml is also nmap's and Nessus's extension, so the root element is
        # what distinguishes a Burp report.
        path = tmp_path / "scan.xml"
        path.write_text('<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>')
        result = parse_burp_file(path)
        assert result.is_empty
        assert result.wrong_format is True

    def test_a_real_burp_report_is_not_flagged_wrong_format(self) -> None:
        assert parse_burp_file(WEB_SCAN).wrong_format is False

    def test_empty_issues_element(self, tmp_path) -> None:
        path = tmp_path / "none.xml"
        path.write_text('<?xml version="1.0"?><issues burpVersion="2024.9.2"></issues>')
        result = parse_burp_file(path)
        assert result.is_empty
        assert result.wrong_format is False


@pytest.mark.unit
class TestPayloadTruncation:
    def test_oversized_response_is_truncated(self, tmp_path) -> None:
        body = "A" * (BURP_RESPONSE_MAX_BYTES * 2)
        path = tmp_path / "big.xml"
        path.write_text(
            '<?xml version="1.0"?><issues><issue><type>2097920</type>'
            '<name>XSS</name><host ip="10.0.0.1">https://a.example</host>'
            "<severity>High</severity><confidence>Certain</confidence>"
            "<requestresponse>"
            f'<response base64="false"><![CDATA[{body}]]></response>'
            "</requestresponse></issue></issues>"
        )
        instance = parse_burp_file(path).issues[0].instances[0]
        assert instance.response is not None
        assert len(instance.response) < len(body)
        assert "truncated" in instance.response
