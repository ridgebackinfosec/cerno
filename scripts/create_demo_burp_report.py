#!/usr/bin/env python3
"""Create a synthetic Burp Suite XML report for Cerno demos.

Emits the demo report that ``cerno demo`` imports, shaped exactly like Burp's
"Report issues" XML export (``<issues>`` root, one ``<issue>`` per occurrence,
base64 request/response pairs).

**Targets are derived, not hard-coded.** Like
``scripts/create_demo_nuclei_results.py``, this parses the expanded demo
``.nessus`` file and reproduces the ``v_http_services`` selection logic -- in
fact it imports that script's :func:`http_targets` so the logic lives in one
place. An issue spec naming a target that is not in that set is a hard error
rather than a silently wrong fixture.

**Host identity matters.** ``Host.get_or_create`` keys on the
``(ip_address, scan_target)`` composite, so each issue's ``<host>`` URL is built
from the Nessus ``ReportHost@name`` and its ``ip`` attribute is that host's
``host-ip`` tag. Get this wrong and the Burp issues create duplicate host rows
instead of reusing the Nessus and nuclei ones, which is what makes cross-source
review useful in the first place.

**Issue metadata is real.** Every type index, name and default severity below
is PortSwigger's own -- each ``type`` resolves to its knowledge-base page at
``https://portswigger.net/kb/issues/<hex>``. Inventing plausible-looking issue
types would make the demo actively misleading, and would produce dead links in
the finding panel.

Output is deterministic (fixed base timestamp, stable ordering, serial numbers
derived from content) so regenerating produces a byte-identical file and review
diffs stay empty unless the data actually changed.

Usage:
    python3 scripts/create_demo_burp_report.py
    python3 scripts/create_demo_burp_report.py --output docs/demo
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path
from typing import Any, Optional
from xml.sax.saxutils import quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parent))

from create_demo_nuclei_results import http_targets  # noqa: E402

#: Where the issue metadata below came from.
ISSUE_SOURCE = "portswigger.net/kb/issues @ 2026-11-12"

#: Burp version string written into the report header.
BURP_VERSION = "2024.9.2"

#: Fixed clock, so regeneration is byte-stable.
EXPORT_TIME = "Thu Nov 12 09:15:00 EST 2026"

#: Issue type metadata: hex type index -> (name, default severity).
#:
#: The hex index is what PortSwigger publishes and what keys its knowledge
#: base; the report itself carries the decimal form, exactly as Burp writes it.
ISSUE_TYPES: dict[str, tuple[str, str]] = {
    "00100200": ("SQL injection", "High"),
    "00200300": ("Cross-site scripting (reflected)", "High"),
    "00300100": ("Cleartext submission of password", "High"),
    "00500200": ("TLS cookie without secure flag set", "Medium"),
    "00500600": ("Cookie without HttpOnly flag set", "Low"),
    "01000300": ("Strict transport security not enforced", "Low"),
    "00600600": ("Robots.txt file", "Information"),
    "00700100": ("Cacheable HTTPS response", "Information"),
    "00800200": ("HTML does not specify charset", "Information"),
}

#: Shared prose per issue type, as HTML (Burp's own fields are HTML fragments).
BACKGROUND: dict[str, str] = {
    "00100200": (
        "<p>SQL injection vulnerabilities arise when user-controllable data is "
        "incorporated into database SQL queries in an unsafe manner.</p>"
    ),
    "00200300": (
        "<p>Reflected cross-site scripting vulnerabilities arise when data is "
        "copied from a request and echoed into the application's immediate "
        "response in an unsafe way.</p>"
    ),
    "00300100": (
        "<p>Passwords submitted over an unencrypted connection are vulnerable "
        "to capture by an attacker who is suitably positioned on the network.</p>"
    ),
    "00500200": (
        "<p>If the secure flag is not set, then the cookie will be transmitted "
        "in cleartext if the user visits any HTTP URLs within the cookie's "
        "scope.</p>"
    ),
    "00500600": (
        "<p>If the HttpOnly attribute is set on a cookie, then the cookie's "
        "value cannot be read or set by client-side JavaScript.</p>"
    ),
    "01000300": (
        "<p>HTTP Strict Transport Security (HSTS) instructs web browsers to "
        "only access the web server over HTTPS.</p>"
    ),
    "00600600": (
        "<p>The file robots.txt is used to give instructions to web robots, "
        "such as search engine crawlers, about locations within the web site "
        "that robots are allowed, or not allowed, to crawl and index.</p>"
    ),
    "00700100": (
        "<p>Web responses that are cacheable may be stored by intermediate "
        "proxies and by the browser, where they may be accessible to other "
        "users.</p>"
    ),
    "00800200": (
        "<p>If a web response does not specify a character set, then the "
        "browser may process it using an unexpected character set.</p>"
    ),
}

REMEDIATION: dict[str, str] = {
    "00100200": (
        "<p>The most effective way to prevent SQL injection attacks is to use "
        "parameterized queries (also known as prepared statements).</p>"
    ),
    "00200300": (
        "<p>In most situations where user-controllable data is copied into "
        "application responses, the vulnerability can be prevented by "
        "HTML-encoding the data.</p>"
    ),
    "00300100": (
        "<p>Applications should use transport-level encryption (SSL/TLS) to "
        "protect all sensitive communications.</p>"
    ),
    "00500200": "<p>Set the secure flag on every cookie that is issued.</p>",
    "00500600": "<p>Set the HttpOnly attribute on every cookie that is issued.</p>",
    "01000300": (
        "<p>Return a Strict-Transport-Security header on every HTTPS " "response.</p>"
    ),
    "00600600": (
        "<p>The robots.txt file is not itself a security risk; review its "
        "contents for references to sensitive locations.</p>"
    ),
    "00700100": (
        "<p>Applications should return caching directives instructing browsers "
        "not to store local copies of any sensitive data.</p>"
    ),
    "00800200": (
        "<p>Specify the character set in the Content-Type header of every "
        "response.</p>"
    ),
}

CLASSIFICATIONS: dict[str, str] = {
    "00100200": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/89.html">'
        "CWE-89: Improper Neutralization of Special Elements used in an SQL "
        "Command</a></li></ul>"
    ),
    "00200300": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/79.html">'
        "CWE-79: Improper Neutralization of Input During Web Page Generation"
        '</a></li><li><a href="https://cwe.mitre.org/data/definitions/80.html">'
        "CWE-80: Improper Neutralization of Script-Related HTML Tags</a></li></ul>"
    ),
    "00300100": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/319.html">'
        "CWE-319: Cleartext Transmission of Sensitive Information</a></li></ul>"
    ),
    "00500200": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/614.html">'
        "CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute"
        "</a></li></ul>"
    ),
    "00500600": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/1004.html">'
        "CWE-1004: Sensitive Cookie Without HttpOnly Flag</a></li></ul>"
    ),
    "01000300": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/523.html">'
        "CWE-523: Unprotected Transport of Credentials</a></li></ul>"
    ),
    "00700100": (
        '<ul><li><a href="https://cwe.mitre.org/data/definitions/524.html">'
        "CWE-524: Use of Cache Containing Sensitive Information</a></li></ul>"
    ),
}


# ---------------------------------------------------------------------------
# Issue instances
#
# (type_hex, "host:port", {path, location, confidence, detail, request, response})
#
# "corroborates" comments name the Nessus or nuclei demo finding on the same
# host:port -- the whole point of importing three sources into one review.
# ---------------------------------------------------------------------------
ISSUES: list[tuple[str, str, dict[str, Any]]] = [
    # --- 198.51.100.10:80 (web01, plain HTTP) ---
    # corroborates nuclei http-missing-security-headers on the same host:port
    (
        "00300100",
        "198.51.100.10:80",
        {
            "path": "/login",
            "location": "/login",
            "confidence": "Certain",
            "detail": (
                "The page contains a form with the following action URL, which "
                "is submitted over clear-text HTTP:<ul><li>"
                "http://198.51.100.10/login</li></ul>"
            ),
            "request": "POST /login HTTP/1.1\r\nHost: 198.51.100.10\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 29\r\n\r\nusername=admin&password=hunter2",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><body><form action=/login method=post>"
            "<input name=password type=password></form></body></html>",
        },
    ),
    # corroborates nuclei robots-txt on the same host:port
    (
        "00600600",
        "198.51.100.10:80",
        {
            "path": "/robots.txt",
            "location": "/robots.txt",
            "confidence": "Certain",
            "detail": "The web server contains a robots.txt file.",
            "request": "GET /robots.txt HTTP/1.1\r\nHost: 198.51.100.10\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
            "User-agent: *\r\nDisallow: /admin\r\nDisallow: /backup\r\n",
        },
    ),
    (
        "00800200",
        "198.51.100.10:80",
        {
            "path": "/",
            "location": "/",
            "confidence": "Certain",
            "detail": (
                "The response does not specify a character set in its "
                "Content-Type header."
            ),
        },
    ),
    # --- 198.51.100.12:8080 (app server behind the edge) ---
    (
        "00100200",
        "198.51.100.12:8080",
        {
            "path": "/reports/list",
            "location": "/reports/list [category parameter]",
            "confidence": "Firm",
            "detail": (
                "The <b>category</b> parameter appears to be vulnerable to SQL "
                "injection attacks. The payload <b>'||(select '')||'</b> was "
                "submitted and the application returned the base response."
            ),
            "request": "GET /reports/list?category=sales%27%7c%7c(select+%27%27)"
            "%7c%7c%27 HTTP/1.1\r\nHost: 198.51.100.12:8080\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><body><table><tr><td>Q3 revenue</td></tr></table></body></html>",
        },
    ),
    (
        "00200300",
        "198.51.100.12:8080",
        {
            "path": "/reports/search",
            "location": "/reports/search [q parameter]",
            "confidence": "Certain",
            "detail": (
                "The value of the <b>q</b> request parameter is copied into the "
                "HTML document as plain text between tags. The payload "
                "<b>&lt;script&gt;alert(1)&lt;/script&gt;</b> was submitted in "
                "the q parameter."
            ),
            "request": "GET /reports/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            " HTTP/1.1\r\nHost: 198.51.100.12:8080\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><body><h1>Results for <script>alert(1)</script></h1>"
            "</body></html>",
        },
    ),
    # Second instance of the same type on the same host:port: merged into one
    # finding_affected_hosts row, which is the Burp importer's defining case.
    (
        "00200300",
        "198.51.100.12:8080",
        {
            "path": "/reports/search",
            "location": "/reports/search [sort parameter]",
            "confidence": "Firm",
            "detail": (
                "The value of the <b>sort</b> request parameter is copied into "
                "an HTML attribute value."
            ),
        },
    ),
    # --- portal.demo.example:443 (FQDN target, HTTPS) ---
    # corroborates nuclei deprecated-tls on the same host
    (
        "00500200",
        "portal.demo.example:443",
        {
            "path": "/",
            "location": "/",
            "confidence": "Firm",
            "detail": (
                "The following cookie was issued by the application and does "
                "not have the secure flag set:<ul><li>PORTALSESSID</li></ul>"
            ),
            "request": "GET / HTTP/1.1\r\nHost: portal.demo.example\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: PORTALSESSID=8d3f1a2b; Path=/\r\n\r\n",
        },
    ),
    (
        "00500600",
        "portal.demo.example:443",
        {
            "path": "/",
            "location": "/",
            "confidence": "Firm",
            "detail": (
                "The following cookie was issued by the application and does "
                "not have the HttpOnly flag set:<ul><li>PORTALSESSID</li></ul>"
            ),
        },
    ),
    (
        "01000300",
        "portal.demo.example:443",
        {
            "path": "/",
            "location": "/",
            "confidence": "Certain",
            "detail": (
                "The application does not return a Strict-Transport-Security "
                "header with any HTTPS response."
            ),
        },
    ),
    (
        "00700100",
        "portal.demo.example:443",
        {
            "path": "/account/profile",
            "location": "/account/profile",
            "confidence": "Certain",
            "detail": (
                "The response contains personal information and may be stored "
                "by the browser's cache."
            ),
        },
    ),
    # --- 198.51.100.13:8443 (second HTTPS listener) ---
    (
        "00200300",
        "198.51.100.13:8443",
        {
            "path": "/app/view",
            "location": "/app/view [id parameter]",
            "confidence": "Firm",
            "detail": (
                "The value of the <b>id</b> request parameter is copied into "
                "the HTML document as plain text between tags."
            ),
        },
    ),
    # --- ipv6-web.demo.example:443 (IPv6-resolved FQDN) ---
    (
        "01000300",
        "ipv6-web.demo.example:443",
        {
            "path": "/",
            "location": "/",
            "confidence": "Certain",
            "detail": (
                "The application does not return a Strict-Transport-Security "
                "header with any HTTPS response."
            ),
        },
    ),
]


def _target_url(target: dict[str, Any]) -> str:
    """The URL Burp records in ``<host>``, omitting an implied default port."""
    scheme, host, port = target["scheme"], target["host"], target["port"]
    if ":" in host and not host.startswith("["):  # literal IPv6
        host = f"[{host}]"
    implied = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = host if implied else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _cdata(text: str) -> str:
    """Wrap text in CDATA, splitting any literal ``]]>`` as XML requires."""
    return "<![CDATA[" + str(text).replace("]]>", "]]]]><![CDATA[>") + "]]>"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _serial(type_hex: str, target_key: str, location: str) -> int:
    """A stable 19-digit serial, as Burp writes, derived from the content."""
    seed = f"{type_hex}|{target_key}|{location}"
    value = 0
    for char in seed:
        value = (value * 131 + ord(char)) % 1_000_000_000_000_000_000
    return 7_000_000_000_000_000_000 + value


def build_issue(
    type_hex: str, target_key: str, spec: dict[str, Any], targets: dict
) -> str:
    """Render one ``<issue>`` element."""
    target = targets.get(target_key)
    if target is None:
        raise SystemExit(
            f"Target {target_key!r} is not an HTTP service in the demo scan. "
            "Fix the spec rather than the scan."
        )
    if type_hex not in ISSUE_TYPES:
        raise SystemExit(f"Unknown Burp issue type {type_hex!r}")

    name, severity = ISSUE_TYPES[type_hex]
    location = spec.get("location", spec.get("path", "/"))
    lines = [
        "  <issue>",
        f"    <serialNumber>{_serial(type_hex, target_key, location)}</serialNumber>",
        f"    <type>{int(type_hex, 16)}</type>",
        f"    <name>{_cdata(name)}</name>",
        f"    <host ip={quoteattr(target['ip'])}>{_target_url(target)}</host>",
        f"    <path>{_cdata(spec.get('path', '/'))}</path>",
        f"    <location>{_cdata(location)}</location>",
        f"    <severity>{severity}</severity>",
        f"    <confidence>{spec.get('confidence', 'Firm')}</confidence>",
    ]
    if type_hex in BACKGROUND:
        lines.append(
            f"    <issueBackground>{_cdata(BACKGROUND[type_hex])}</issueBackground>"
        )
    if type_hex in REMEDIATION:
        lines.append(
            f"    <remediationBackground>{_cdata(REMEDIATION[type_hex])}"
            "</remediationBackground>"
        )
    if type_hex in CLASSIFICATIONS:
        lines.append(
            f"    <vulnerabilityClassifications>{_cdata(CLASSIFICATIONS[type_hex])}"
            "</vulnerabilityClassifications>"
        )
    if spec.get("detail"):
        lines.append(f"    <issueDetail>{_cdata(spec['detail'])}</issueDetail>")

    request: Optional[str] = spec.get("request")
    response: Optional[str] = spec.get("response")
    if request or response:
        lines.append("    <requestresponse>")
        if request:
            lines.append(
                f'      <request method="GET" base64="true">{_cdata(_b64(request))}'
                "</request>"
            )
        if response:
            lines.append(
                f'      <response base64="true">{_cdata(_b64(response))}</response>'
            )
        lines.append("      <responseRedirected>false</responseRedirected>")
        lines.append("    </requestresponse>")

    lines.append("  </issue>")
    return "\n".join(lines)


def build_report(targets: dict) -> str:
    body = "\n".join(
        build_issue(type_hex, target_key, spec, targets)
        for type_hex, target_key, spec in ISSUES
    )
    return (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE issues [\n"
        "<!ELEMENT issues (issue*)>\n"
        '<!ATTLIST issues burpVersion CDATA "">\n'
        '<!ATTLIST issues exportTime CDATA "">\n'
        "]>\n"
        f'<issues burpVersion="{BURP_VERSION}" exportTime="{EXPORT_TIME}">\n'
        f"{body}\n"
        "</issues>\n"
    )


def _summarize(report: str) -> None:
    types = {t for t, _, _ in ISSUES}
    counts: dict[str, int] = {}
    for type_hex, _, _ in ISSUES:
        severity = ISSUE_TYPES[type_hex][1]
        counts[severity] = counts.get(severity, 0) + 1
    order = ["High", "Medium", "Low", "Information"]
    spread = ", ".join(f"{s}={counts[s]}" for s in order if s in counts)
    print(
        f"  {len(ISSUES)} issue instances, {len(types)} issue types "
        f"({spread}), {len(report)} bytes"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    repo_root = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "docs" / "demo",
        help="Directory to write the XML report to. Defaults to docs/demo.",
    )
    parser.add_argument(
        "--nessus-dir",
        type=Path,
        default=repo_root / "docs" / "demo",
        help="Directory holding the demo .nessus files. Defaults to docs/demo.",
    )
    parser.add_argument(
        "--also-package",
        action="store_true",
        default=True,
        help="Also write the identical copy into cerno_pkg/demo (default: on).",
    )
    parser.add_argument(
        "--no-also-package",
        dest="also_package",
        action="store_false",
        help="Write only to --output.",
    )
    args = parser.parse_args()

    targets = http_targets(args.nessus_dir / "cerno-demo-expanded.nessus")
    report = build_report(targets)

    outputs = [args.output]
    if args.also_package:
        outputs.append(repo_root / "cerno_pkg" / "demo")

    for directory in outputs:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "cerno-demo-burp-scan.xml").write_text(report, encoding="utf-8")
        print(f"Wrote demo Burp report to {directory}")

    print(f"Issue metadata source: {ISSUE_SOURCE}")
    _summarize(report)


if __name__ == "__main__":
    main()
