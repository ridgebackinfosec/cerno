#!/usr/bin/env python3
"""Create synthetic nuclei result files for Cerno demos.

Emits the two demo nuclei exports that ``cerno demo`` imports, shaped exactly
like a real ``nuclei -je`` run (a single JSON array of result objects).

**Targets are derived, not hard-coded.** The script parses the two demo
``.nessus`` files and reproduces the ``v_http_services`` selection logic, so the
generated findings can only ever land on host:port pairs that actually exist in
the demo scans. A finding spec naming a target that is not in that set is a hard
error rather than a silently wrong fixture -- that is the whole reason this is a
generator instead of two hand-written JSON files.

**Host identity matters.** ``Host.get_or_create`` keys on the
``(ip_address, scan_target)`` composite, so each record's ``host`` is the Nessus
``ReportHost@name`` and its ``ip`` is that host's ``host-ip`` tag. Get this wrong
and the nuclei records create duplicate host rows instead of reusing the Nessus
ones, which is what makes cross-source review useful in the first place.

**Template metadata is real.** Every ``template-id``, name, severity, tag,
author, description and classification below is copied verbatim from the
upstream template in nuclei-templates (see ``TEMPLATE_SOURCE``). Inventing
plausible-looking template metadata would make the demo actively misleading.

Two deliberate differences from a raw ``-je`` file, both documented in
``docs/demo/README.md``:

* ``request``/``response`` are omitted, as if the run used ``-or``. Cerno
  discards them at import and they would bloat these files roughly twenty-fold.
* ``template-path`` uses a neutral ``/opt/nuclei-templates`` prefix instead of a
  real home directory.

Output is deterministic (fixed base timestamp, stable ordering) so regenerating
produces a byte-identical file and review diffs stay empty unless the data
actually changed.

Usage:
    python3 scripts/create_demo_nuclei_results.py
    python3 scripts/create_demo_nuclei_results.py --output docs/demo
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

#: Upstream templates these records were copied from.
TEMPLATE_SOURCE = "projectdiscovery/nuclei-templates @ 2026-11-03"

#: Public template viewer; matches cerno_pkg.constants.NUCLEI_TEMPLATE_URL_BASE.
TEMPLATE_URL_BASE = "https://cloud.projectdiscovery.io/public/"

#: Neutral stand-in for the operator's local templates directory.
TEMPLATE_ROOT = "/opt/nuclei-templates"

#: Fixed clock, so regeneration is byte-stable.
BASE_TIME = datetime(2026, 11, 3, 9, 15, 0, tzinfo=timezone(timedelta(hours=-5)))

#: User-Agent matching config.nuclei_user_agent, for the curl reproduction lines.
DEMO_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
    "Gecko/20100101 Firefox/132.0"
)

#: Ports whose scheme is implied, so matched-at omits them (as nuclei does).
DEFAULT_PORTS = {("http", 80), ("https", 443)}


# Verbatim upstream template metadata -- see TEMPLATE_SOURCE.
TEMPLATES = {
    "CVE-2021-41773": {
        "info": {
            "author": ["daffainfo", "666asd"],
            "classification": {
                "cve-id": ["CVE-2021-41773"],
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvss-score": 7.5,
                "cwe-id": ["CWE-22"],
            },
            "description": 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally, this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.',
            "metadata": {"max-request": 3},
            "name": "Apache 2.4.49 - Path Traversal and Remote Code Execution",
            "reference": [
                "https://github.com/apache/httpd/commit/e150697086e70c552b2588f369f2d17815cb1782",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773",
                "https://twitter.com/ptswarm/status/1445376079548624899",
                "https://twitter.com/h4x0r_dz/status/1445401960371429381",
                "https://github.com/blasty/CVE-2021-41773",
            ],
            "severity": "high",
            "tags": [
                "cve2021",
                "cve",
                "lfi",
                "rce",
                "apache",
                "misconfig",
                "traversal",
                "kev",
                "vkev",
                "vuln",
            ],
        },
        "path": "http/cves/2021/CVE-2021-41773.yaml",
        "type": "http",
    },
    "CVE-2021-44228": {
        "info": {
            "author": [
                "melbadry9",
                "dhiyaneshDK",
                "daffainfo",
                "anon-artist",
                "0xceba",
                "Tea",
                "j4vaovo",
            ],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "cvss-score": 10,
                "cwe-id": ["CWE-20", "CWE-917"],
            },
            "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
            "metadata": {"max-request": 2},
            "name": "Apache Log4j2 Remote Code Injection",
            "reference": [
                "https://logging.apache.org/log4j/2.x/security.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
                "https://www.lunasec.io/docs/blog/log4j-zero-day/",
                "https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a",
            ],
            "severity": "critical",
            "tags": [
                "cve2021",
                "cve",
                "rce",
                "oast",
                "log4j",
                "injection",
                "kev",
                "apache",
                "vkev",
                "vuln",
            ],
        },
        "path": "http/cves/2021/CVE-2021-44228.yaml",
        "type": "http",
    },
    "apache-detect": {
        "info": {
            "author": ["philippedelteil"],
            "description": "Some Apache servers have the version on the response header. The OpenSSL version can be also obtained",
            "metadata": {"max-request": 1},
            "name": "Apache Detection",
            "severity": "info",
            "tags": ["tech", "apache", "discovery"],
        },
        "path": "http/technologies/apache/apache-detect.yaml",
        "type": "http",
    },
    "deprecated-tls": {
        "info": {
            "author": ["righettod", "forgedhallpass", "goosvorbook"],
            "classification": {"cwe-id": ["CWE-327"]},
            "description": "The service accepts one or more deprecated SSL/TLS protocol versions: SSL 2.0, SSL 3.0, TLS 1.0 or TLS 1.1. These versions are prohibited or deprecated (RFC 6176, RFC 7568, RFC 8996) and are affected by known weaknesses such as DROWN and POODLE.",
            "metadata": {"max-request": 4},
            "name": "Deprecated SSL/TLS Protocols - Detect",
            "reference": [
                "https://ssl-config.mozilla.org/#config=intermediate",
                "https://datatracker.ietf.org/doc/html/rfc6176",
                "https://datatracker.ietf.org/doc/html/rfc7568",
                "https://datatracker.ietf.org/doc/html/rfc8996",
                "https://drownattack.com/",
            ],
            "severity": "info",
            "tags": ["ssl", "tls", "vuln"],
        },
        "path": "ssl/deprecated-tls.yaml",
        "type": "ssl",
    },
    "expired-ssl": {
        "info": {
            "author": ["pdteam"],
            "description": "After an SSL certificate expires, you will no longer be able to communicate over a secure, encrypted HTTPS connection.",
            "metadata": {"max-request": 1},
            "name": "Expired SSL Certificate",
            "reference": [
                "https://www.acunetix.com/vulnerabilities/web/tls-ssl-certificate-about-to-expire/"
            ],
            "severity": "low",
            "tags": ["ssl", "tls", "vuln"],
        },
        "path": "ssl/expired-ssl.yaml",
        "type": "ssl",
    },
    "http-missing-security-headers": {
        "info": {
            "author": [
                "socketz",
                "geeknik",
                "G4L1T0",
                "convisoappsec",
                "kurohost",
                "dawid-czarnecki",
                "forgedhallpass",
                "jub0bs",
                "userdehghani",
                "celbahraoui",
                "safejulian",
            ],
            "classification": {"cwe-id": ["CWE-693"]},
            "description": "This template searches for missing HTTP security headers. The impact of these missing headers can vary.",
            "metadata": {"max-request": 1},
            "name": "HTTP Missing Security Headers",
            "severity": "info",
            "tags": ["misconfig", "headers", "generic", "vuln"],
        },
        "path": "http/misconfiguration/http-missing-security-headers.yaml",
        "type": "http",
    },
    "mismatched-ssl-certificate": {
        "info": {
            "author": ["pdteam"],
            "description": "Mismatched certificates occur when there is inconsistency between the common name to which the certificate was issued and the domain name in the URL. This issue impacts the trust value of the affected website.",
            "metadata": {"max-request": 1},
            "name": "Mismatched SSL Certificate",
            "reference": [
                "https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/ssl-certificate-name-hostname-mismatch/"
            ],
            "severity": "info",
            "tags": ["ssl", "tls", "mismatched", "vuln"],
        },
        "path": "ssl/mismatched-ssl-certificate.yaml",
        "type": "ssl",
    },
    "nginx-version": {
        "info": {
            "author": ["philippedelteil", "daffainfo"],
            "description": "Some nginx servers have the version on the response header. Useful when you need to find specific CVEs on your targets.",
            "metadata": {"max-request": 1},
            "name": "Nginx version detect",
            "severity": "info",
            "tags": ["tech", "nginx", "discovery"],
        },
        "path": "http/technologies/nginx/nginx-version.yaml",
        "type": "http",
    },
    "phpmyadmin-panel": {
        "info": {
            "author": ["pdteam", "righettod"],
            "classification": {
                "cvss-metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cwe-id": ["CWE-200"],
            },
            "description": "phpMyAdmin panel was detected.",
            "metadata": {"max-request": 14},
            "name": "phpMyAdmin Panel - Detect",
            "severity": "info",
            "tags": ["panel", "phpmyadmin", "detect", "discovery"],
        },
        "path": "http/exposed-panels/phpmyadmin-panel.yaml",
        "type": "http",
    },
    "robots-txt": {
        "info": {
            "author": ["CasperGN", "TheZakMan"],
            "metadata": {"max-request": 2},
            "name": "robots.txt file",
            "severity": "info",
            "tags": ["miscellaneous", "misc", "generic", "vuln"],
        },
        "path": "http/miscellaneous/robots-txt.yaml",
        "type": "http",
    },
    "self-signed-ssl": {
        "info": {
            "author": ["righettod", "pdteam"],
            "description": "self-signed certificates are public key certificates that are not issued by a certificate authority. These self-signed\ncertificates are easy to make and do not cost money. However, they do not provide any trust value.",
            "metadata": {"max-request": 1},
            "name": "Self Signed SSL Certificate",
            "reference": [
                "https://www.rapid7.com/db/vulnerabilities/ssl-self-signed-certificate/"
            ],
            "severity": "low",
            "tags": ["ssl", "tls", "self-signed", "vuln"],
        },
        "path": "ssl/self-signed-ssl.yaml",
        "type": "ssl",
    },
    "ssl-dns-names": {
        "info": {
            "author": ["pdteam"],
            "description": "Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.",
            "metadata": {"max-request": 1},
            "name": "SSL DNS Names",
            "severity": "info",
            "tags": ["ssl", "tls", "vuln"],
        },
        "path": "ssl/ssl-dns-names.yaml",
        "type": "ssl",
    },
    "tech-detect": {
        "info": {
            "author": ["hakluke", "righettod", "matejsmycka"],
            "metadata": {"max-request": 1},
            "name": "Wappalyzer Technology Detection",
            "severity": "info",
            "tags": ["tech", "discovery"],
        },
        "path": "http/technologies/tech-detect.yaml",
        "type": "http",
    },
    "tls-version": {
        "info": {
            "author": ["pdteam", "pussycat0x"],
            "description": "TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.\nIt is important to detect the TLS version in order to ensure secure communication between two computers or servers.",
            "metadata": {"max-request": 4},
            "name": "TLS Version - Detect",
            "severity": "info",
            "tags": ["ssl", "tls", "discovery"],
        },
        "path": "ssl/tls-version.yaml",
        "type": "ssl",
    },
    "tomcat-default-login": {
        "info": {
            "author": ["pdteam", "sinKettu", "nybble04"],
            "description": "Apache Tomcat Manager default login credentials were discovered.",
            "metadata": {"max-request": 25},
            "name": "Apache Tomcat Manager Default Login",
            "reference": [
                "https://www.rapid7.com/db/vulnerabilities/apache-tomcat-default-ovwebusr-password/",
                "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt",
            ],
            "severity": "high",
            "tags": ["tomcat", "apache", "default-login", "vuln"],
        },
        "path": "http/default-logins/apache/tomcat-default-login.yaml",
        "type": "http",
    },
    "tomcat-detect": {
        "info": {
            "author": ["philippedelteil", "dhiyaneshDk", "AdamCrosser"],
            "description": "If an Tomcat instance is deployed on the target URL, when we send a request for a non existent resource we receive a Tomcat error page with version.",
            "metadata": {"max-request": 3},
            "name": "Tomcat Detection",
            "severity": "info",
            "tags": ["tech", "tomcat", "apache", "intrusive", "discovery"],
        },
        "path": "http/technologies/apache/tomcat-detect.yaml",
        "type": "http",
    },
    "weak-cipher-suites": {
        "info": {
            "author": ["pussycat0x"],
            "description": "A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.",
            "metadata": {"max-request": 4},
            "name": "Weak Cipher Suites Detection",
            "reference": [
                "https://www.acunetix.com/vulnerabilities/web/tls-ssl-weak-cipher-suites/",
                "http://ciphersuite.info",
            ],
            "severity": "low",
            "tags": ["ssl", "tls", "misconfig", "vuln"],
        },
        "path": "ssl/weak-cipher-suites.yaml",
        "type": "ssl",
    },
}


# ---------------------------------------------------------------------------
# Finding specs
# ---------------------------------------------------------------------------
# Each entry: (template_id, target, options)
#   target  -- "host:port", which MUST exist in the scan's HTTP service set
#   options -- optional dict:
#       matchers  : list of matcher-name values; one record per matcher, all of
#                   which Cerno merges into a single plugin_output
#       extracted : extracted-results for a single record
#       per       : {matcher: extracted} for matcher-specific extractions
#       path      : URL path the template matched at (http only)
#
# "corroborates" comments name the Nessus demo plugin on the same host:port.

SHOP_HOSTS = [f"203.0.113.{n}:443" for n in range(80, 86)]
EDGE_HOSTS = [f"203.0.113.{n}:443" for n in range(70, 76)]

# Findings present in BOTH demo scans (the initial scan's four targets).
BASELINE_FINDINGS: list[tuple[str, str, dict]] = [
    # --- 198.51.100.10:80 (web01) ---
    ("tech-detect", "198.51.100.10:80", {"matchers": ["apache", "ubuntu"]}),
    # corroborates 10107 HTTP Server Type and Version
    ("apache-detect", "198.51.100.10:80", {"extracted": ["Apache/2.4.29 (Ubuntu)"]}),
    # corroborates 40984 Web Server Directory Enumeration
    ("robots-txt", "198.51.100.10:80", {"path": "/robots.txt"}),
    (
        "http-missing-security-headers",
        "198.51.100.10:80",
        {
            "matchers": [
                "strict-transport-security",
                "x-frame-options",
                "content-security-policy",
            ]
        },
    ),
    # --- 198.51.100.10:443 / 198.51.100.11:443 (web01, web02) ---
    # corroborates 20007 SSL Version 2 and 3 Protocol Detection
    ("deprecated-tls", "198.51.100.10:443", {"extracted": ["ssl3"]}),
    ("deprecated-tls", "198.51.100.11:443", {"extracted": ["tls10"]}),
    # corroborates 42873 SSL Medium Strength Cipher Suites Supported
    (
        "weak-cipher-suites",
        "198.51.100.10:443",
        {"extracted": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]},
    ),
    (
        "weak-cipher-suites",
        "198.51.100.11:443",
        {"extracted": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]},
    ),
    ("tls-version", "198.51.100.10:443", {"matchers": ["tls11", "tls12"]}),
    ("tls-version", "198.51.100.11:443", {"extracted": ["tls12"]}),
    # --- portal.demo.example:443 ---
    ("tech-detect", "portal.demo.example:443", {"matchers": ["nginx"]}),
    # corroborates 10107 HTTP Server Type and Version
    ("nginx-version", "portal.demo.example:443", {"extracted": ["nginx/1.14.0"]}),
    (
        "ssl-dns-names",
        "portal.demo.example:443",
        {"extracted": ["portal.demo.example"]},
    ),
]

# Findings unique to the expanded scan.
EXPANDED_ONLY_FINDINGS: list[tuple[str, str, dict]] = [
    # --- 198.51.100.12 (api01): Nessus sees an unsupported Apache; nuclei also
    #     finds the traversal CVE for that exact version, plus an exposed panel.
    # corroborates 56468 Apache HTTP Server Unsupported Version Detection
    ("apache-detect", "198.51.100.12:8080", {"extracted": ["Apache/2.4.49 (Unix)"]}),
    (
        "CVE-2021-41773",
        "198.51.100.12:8080",  # nuclei-only, high
        {
            "path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
            "extracted": ["root:x:0:0:root:/root:/bin/bash"],
        },
    ),
    ("phpmyadmin-panel", "198.51.100.12:8080", {"path": "/phpmyadmin/"}),
    # corroborates 11219 SSL Self-Signed Certificate + 104743 TLS Version 1.0
    ("self-signed-ssl", "198.51.100.12:443", {"extracted": ["api01.demo.example"]}),
    ("deprecated-tls", "198.51.100.12:443", {"extracted": ["tls10"]}),
    # --- 198.51.100.13 (api02) ---
    # corroborates 157288 TLS Version 1.1 Protocol Deprecated
    ("deprecated-tls", "198.51.100.13:443", {"extracted": ["tls11"]}),
    # corroborates 45411 SSL Certificate with Wrong Hostname (svc_name https-alt,
    # so this target qualifies for v_http_services by PORT only)
    (
        "mismatched-ssl-certificate",
        "198.51.100.13:8443",
        {"extracted": ["api02.demo.example"]},
    ),
    # --- 198.51.100.31 (app01): no Nessus web finding at all here ---
    ("CVE-2021-44228", "198.51.100.31:8080", {}),  # nuclei-only, critical
    # --- 198.51.100.90 (ci01): Nessus finds default FILES, nuclei default CREDS
    # corroborates 34970 Apache Tomcat Default Files
    ("tomcat-detect", "198.51.100.90:8080", {"extracted": ["Apache Tomcat/9.0.30"]}),
    (
        "tomcat-default-login",
        "198.51.100.90:8080",  # nuclei-only, high
        {"path": "/manager/html", "extracted": ["tomcat:tomcat"]},
    ),
    # --- 198.51.100.91 (git01) ---
    # corroborates 40984 Web Server Directory Enumeration
    ("robots-txt", "198.51.100.91:80", {"path": "/robots.txt"}),
    ("tech-detect", "198.51.100.91:80", {"matchers": ["nginx"]}),
    # --- vpn.demo.example:443 (FQDN-named host) ---
    # corroborates 57582 SSL Certificate Expiry
    ("expired-ssl", "vpn.demo.example:443", {"extracted": ["2025-04-12T00:00:00Z"]}),
    # corroborates 78479 POODLE
    ("deprecated-tls", "vpn.demo.example:443", {"extracted": ["ssl3"]}),
    (
        "weak-cipher-suites",
        "vpn.demo.example:443",
        {"extracted": ["TLS_RSA_EXPORT_WITH_RC4_40_MD5"]},
    ),
    # --- ipv6-web.demo.example:443 -> 2001:db8:10::25 ---
    (
        "ssl-dns-names",
        "ipv6-web.demo.example:443",
        {"extracted": ["ipv6-web.demo.example"]},
    ),
    ("tls-version", "ipv6-web.demo.example:443", {"extracted": ["tls12"]}),
]

# The centrepiece: Nessus splits missing security headers into three separate
# plugins (84502 HSTS, 85601 X-Frame-Options, 98033 CSP) on each shop host;
# nuclei reports all three as matchers on ONE finding, which Cerno merges into a
# single plugin_output. Same evidence, two scanner models, side by side.
for _host in SHOP_HOSTS:
    EXPANDED_ONLY_FINDINGS.append(
        (
            "http-missing-security-headers",
            _host,
            {
                "matchers": [
                    "strict-transport-security",
                    "x-frame-options",
                    "content-security-policy",
                ]
            },
        )
    )
EXPANDED_ONLY_FINDINGS.append(("tech-detect", SHOP_HOSTS[0], {"matchers": ["php"]}))

# corroborates 20007 SSLv2/3 and 42873 Medium Ciphers on the edge hosts
for _host in EDGE_HOSTS:
    EXPANDED_ONLY_FINDINGS.append(("deprecated-tls", _host, {"extracted": ["ssl3"]}))
    EXPANDED_ONLY_FINDINGS.append(
        ("weak-cipher-suites", _host, {"extracted": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]})
    )


# ---------------------------------------------------------------------------
# Target discovery (mirrors the v_http_services view)
# ---------------------------------------------------------------------------

_HTTP_SVC = {"www", "http?", "https?", "http", "https"}
_HTTP_PORTS = {80, 443, 8080, 8443}


def _scheme_for(svc_name: str, port: int) -> Optional[str]:
    """Reproduce the CASE expression in the v_http_services view."""
    if svc_name in ("https?", "https"):
        return "https"
    if port in (443, 8443):
        return "https"
    if svc_name in ("www", "http?", "http"):
        return "http"
    if port in (80, 8080):
        return "http"
    return None


def http_targets(nessus_file: Path) -> dict[str, dict[str, Any]]:
    """Return ``{"host:port": {host, ip, port, scheme}}`` for one demo scan.

    Keyed exactly as ``v_http_services`` would surface it: ``host`` is the
    ``ReportHost@name`` (an IP for most demo hosts, an FQDN for six of them) and
    ``ip`` is the ``host-ip`` tag, so importing these records reuses the Nessus
    host rows rather than creating duplicates.
    """
    targets: dict[str, dict[str, Any]] = {}
    root = ET.parse(nessus_file).getroot()
    for report_host in root.iter("ReportHost"):
        host = report_host.get("name") or ""
        ip = host
        for tag in report_host.iter("tag"):
            if tag.get("name") == "host-ip" and tag.text:
                ip = tag.text.strip()
                break
        for item in report_host.iter("ReportItem"):
            svc_name = item.get("svc_name", "")
            try:
                port = int(item.get("port", "0"))
            except ValueError:
                continue
            if not (svc_name in _HTTP_SVC or port in _HTTP_PORTS):
                continue
            scheme = _scheme_for(svc_name, port)
            if scheme is None:
                continue
            targets[f"{host}:{port}"] = {
                "host": host,
                "ip": ip,
                "port": port,
                "scheme": scheme,
            }
    return targets


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _matched_at(target: dict[str, Any], path: str = "") -> str:
    """Base URL as nuclei reports it, omitting an implied default port."""
    scheme, host, port = target["scheme"], target["host"], target["port"]
    if ":" in host and not host.startswith("["):  # literal IPv6
        host = f"[{host}]"
    authority = host if (scheme, port) in DEFAULT_PORTS else f"{host}:{port}"
    return f"{scheme}://{authority}{path}"


def _curl_command(url: str) -> str:
    return (
        "curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' "
        f"-H 'User-Agent: {DEMO_USER_AGENT}' '{url}'"
    )


def _record(
    template_id: str,
    target: dict[str, Any],
    index: int,
    *,
    matcher: Optional[str] = None,
    extracted: Optional[list[str]] = None,
    path: str = "",
) -> dict[str, Any]:
    """Build one nuclei result object, shaped per its template's protocol."""
    spec = TEMPLATES[template_id]
    rel_path = spec["path"]
    timestamp = (BASE_TIME + timedelta(seconds=index * 3)).isoformat()

    record: dict[str, Any] = {
        "template": rel_path,
        "template-url": TEMPLATE_URL_BASE + template_id,
        "template-id": template_id,
        "template-path": f"{TEMPLATE_ROOT}/{rel_path}",
        "info": json.loads(json.dumps(spec["info"])),  # deep copy per record
        "type": spec["type"],
        "host": target["host"],
    }

    if spec["type"] == "http":
        url = _matched_at(target)
        record["port"] = str(target["port"])
        record["scheme"] = target["scheme"]
        record["url"] = url
        record["matched-at"] = url + path
        if matcher:
            record["matcher-name"] = matcher
        if extracted:
            record["extracted-results"] = extracted
        record["ip"] = target["ip"]
        record["timestamp"] = timestamp
        record["curl-command"] = _curl_command(url + path)
    else:  # ssl
        record["port"] = str(target["port"])
        record["matched-at"] = f"{target['host']}:{target['port']}"
        if matcher:
            record["matcher-name"] = matcher
        if extracted:
            record["extracted-results"] = extracted
        record["ip"] = target["ip"]
        record["timestamp"] = timestamp

    record["matcher-status"] = True
    return record


def build_records(
    findings: Iterable[tuple[str, str, dict]],
    targets: dict[str, dict[str, Any]],
    scan_label: str,
) -> list[dict[str, Any]]:
    """Expand finding specs into nuclei result objects.

    Raises:
        SystemExit: If a spec targets a host:port that is not an HTTP service in
            this demo scan. That means the fixture has drifted from the .nessus
            files, which is exactly what this generator exists to prevent.
    """
    records: list[dict[str, Any]] = []
    index = 0
    for template_id, target_key, options in findings:
        if template_id not in TEMPLATES:
            raise SystemExit(f"{scan_label}: unknown template id {template_id!r}")
        target = targets.get(target_key)
        if target is None:
            raise SystemExit(
                f"{scan_label}: {template_id} targets {target_key!r}, which is not "
                f"an HTTP service in that scan. Known targets: "
                f"{', '.join(sorted(targets))}"
            )

        path = options.get("path", "")
        matchers = options.get("matchers")
        per = options.get("per") or {}
        if matchers:
            for matcher in matchers:
                records.append(
                    _record(
                        template_id,
                        target,
                        index,
                        matcher=matcher,
                        extracted=per.get(matcher),
                        path=path,
                    )
                )
                index += 1
        else:
            records.append(
                _record(
                    template_id,
                    target,
                    index,
                    extracted=options.get("extracted"),
                    path=path,
                )
            )
            index += 1
    return records


def write_results(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


def _summarize(label: str, records: list[dict[str, Any]]) -> None:
    by_severity: dict[str, int] = {}
    templates = {r["template-id"] for r in records}
    for record in records:
        sev = record["info"]["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    spread = ", ".join(f"{s}={by_severity[s]}" for s in order if s in by_severity)
    print(f"  {label}: {len(records)} records, {len(templates)} templates ({spread})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    repo_root = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "docs" / "demo",
        help="Directory to write the JSON files to. Defaults to docs/demo.",
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

    initial_targets = http_targets(args.nessus_dir / "cerno-demo-initial.nessus")
    expanded_targets = http_targets(args.nessus_dir / "cerno-demo-expanded.nessus")

    initial = build_records(BASELINE_FINDINGS, initial_targets, "initial")
    expanded = build_records(
        BASELINE_FINDINGS + EXPANDED_ONLY_FINDINGS, expanded_targets, "expanded"
    )

    outputs = [args.output]
    if args.also_package:
        outputs.append(repo_root / "cerno_pkg" / "demo")

    for directory in outputs:
        write_results(directory / "cerno-demo-nuclei-initial.json", initial)
        write_results(directory / "cerno-demo-nuclei-expanded.json", expanded)
        print(f"Wrote demo nuclei results to {directory}")

    print(f"Template metadata source: {TEMPLATE_SOURCE}")
    _summarize("initial ", initial)
    _summarize("expanded", expanded)


if __name__ == "__main__":
    main()
