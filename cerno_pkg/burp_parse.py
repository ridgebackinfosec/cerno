"""Pure PortSwigger Burp Suite report parser (no database dependency).

Parses Burp's "Report issues" XML export into structured dataclasses: one
:class:`ParsedBurpIssue` per *issue type*, each holding every individual
:class:`ParsedBurpInstance` that type produced. This is the Burp counterpart to
:mod:`cerno_pkg.nuclei_parse` and :mod:`cerno_pkg.nmap_parse`, and follows the
same contract.

**The identity is the hex type index.** Burp's XML stores its issue type in
decimal (``<type>2097920</type>``), but PortSwigger publishes it -- and keys its
knowledge base on it -- in 8-digit hex (``00200300``). Using the hex form as the
``plugin_ref`` makes the details URL derivable from the id alone, exactly like
the Nessus plugin number and the nuclei template id. Two type indexes identify
nothing specific and are handled separately; see
:data:`cerno_pkg.constants.BURP_GENERIC_TYPES`.

**Instances are preserved, never collapsed.** One issue type routinely fires on
many parameters of the same host:port -- reflected XSS on ``q`` and on ``lang``
of the same ``/search`` -- while ``finding_affected_hosts`` has a
``UNIQUE (finding_id, host_id, port_number)`` constraint. Merging that evidence
is the importer's job; this module's job is to lose none of it (bar the explicit
caps below).

**Prose is HTML, evidence is bytes.** ``issueBackground``, ``issueDetail`` and
friends are HTML fragments, converted to plain text here because they are
rendered into a terminal panel and into the Claude assistant's context, never
into a browser. ``request``/``response`` are full HTTP exchanges, optionally
base64-encoded, and are truncated to
:data:`~cerno_pkg.constants.BURP_REQUEST_MAX_BYTES` /
:data:`~cerno_pkg.constants.BURP_RESPONSE_MAX_BYTES`, with at most
:data:`~cerno_pkg.constants.BURP_MAX_INSTANCES_RENDERED` instances rendered per
host:port.

**Nothing is sanitized here.** The database should hold exactly what the scanner
reported. A Burp response body is lifted verbatim from a live target, so it may
carry ESC bytes and Rich markup -- every consumer must neutralize these values
at render time via :func:`cerno_pkg.ansi.safe_text` or ``rich.text.Text``.

Parsing is deliberately forgiving: a missing file, a directory, an empty file,
malformed XML or a truncated export yields an empty or partial
:class:`ParsedBurp` rather than raising. ``.xml`` is also nmap's and (renamed)
Nessus's extension, so a file whose root element is not ``<issues>`` is reported
through :attr:`ParsedBurp.wrong_format` -- the caller can then say "this is not
a Burp report" instead of "0 findings imported".
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlsplit

from .constants import (
    BURP_GENERIC_TYPES,
    BURP_KB_BASE,
    BURP_MAX_INSTANCES_RENDERED,
    BURP_REQUEST_MAX_BYTES,
    BURP_RESPONSE_MAX_BYTES,
)
from .logging_setup import log_debug, log_error
from .parsing import SCHEME_PORTS, unbracket

__all__ = [
    "ParsedBurp",
    "ParsedBurpInstance",
    "ParsedBurpIssue",
    "extract_cwes",
    "find_cves",
    "format_plugin_output",
    "html_to_text",
    "kb_url",
    "parse_burp_file",
    "severity_to_int",
    "split_target",
    "type_to_ref",
]

#: Burp severity label -> Cerno ``severity_int``.
#:
#: Burp's scale tops out at High: it has no Critical, so nothing imported from
#: a Burp report lands in severity 4, and a Burp High sorts alongside a Nessus
#: High rather than above it.
#:
#: Anything unrecognised floors to Info for the same reason the nuclei parser
#: does it: ``plugins.severity_int`` CHECKs ``BETWEEN 0 AND 4`` *and* foreign-keys
#: ``severity_levels``, while ``v_plugins_with_severity`` is an INNER JOIN -- so
#: an unmapped value would make the finding silently vanish from every query
#: rather than fail loudly.
SEVERITY_BY_LABEL: dict[str, int] = {
    "information": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}

#: The severity Burp writes for an issue the tester dismissed in the UI.
#:
#: Skipped rather than imported at Info: the operator has already ruled on it,
#: and re-surfacing it in the review list would undo that work.
FALSE_POSITIVE_LABEL = "false positive"

#: Same CVE validation the Nessus and nuclei importers apply.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

#: HTML block boundaries that should survive as line breaks.
_BLOCK_TAG_RE = re.compile(
    r"</?\s*(?:br|p|div|li|tr|h[1-6]|ul|ol|table)\s*/?>", re.IGNORECASE
)
_TAG_RE = re.compile(r"<[^>]+>")
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")


@dataclass
class ParsedBurpInstance:
    """One ``<issue>`` element: one occurrence of one issue type on one target."""

    host: str
    """The target host as Burp addressed it, brackets stripped."""

    ip: Optional[str]
    """``<host ip="...">``, when Burp resolved one. Often absent."""

    port: Optional[int]
    """From the target URL, defaulted by scheme. None if unusable."""

    scheme: str
    path: str
    location: str
    """The more specific of the two: ``/search [q parameter]``."""

    confidence: str
    """Burp's ``Certain`` / ``Firm`` / ``Tentative``.

    Kept as evidence rather than used as a filter: a Tentative finding is still
    the operator's to triage, and Cerno already records that judgement in
    ``finding_verdicts``.
    """

    detail: str
    """``issueDetail``, converted to plain text."""

    request: Optional[str] = None
    response: Optional[str] = None

    @property
    def effective_ip(self) -> str:
        """The value to store in ``hosts.ip_address``, which is NOT NULL.

        Burp leaves ``ip`` empty whenever it did not resolve the target, so the
        host falls back to itself -- the same precedent the Nessus and nuclei
        importers set.
        """
        return self.ip or self.host

    @property
    def target_key(self) -> tuple[str, str, Optional[int]]:
        """Identity of the affected host:port, for merging colliding instances."""
        return (self.effective_ip, self.host, self.port)

    @property
    def service_name(self) -> Optional[str]:
        """Service for ``host_services.svc_name``, or None if unknowable.

        Burp only ever reports a URL, so the scheme *is* the service.
        ``v_http_services`` accepts the literal ``http`` and ``https`` tokens,
        so these rows need no view change.
        """
        return self.scheme.strip().lower() or None


@dataclass
class ParsedBurpIssue:
    """Every instance of one Burp issue type, with its shared metadata."""

    type_ref: str
    """8-digit hex type index, name-slugged for a generic type."""

    name: str
    severity_int: int
    url: Optional[str] = None
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    background: str = ""
    remediation: str = ""
    references: str = ""
    instances: list[ParsedBurpInstance] = field(default_factory=list)


@dataclass
class ParsedBurp:
    """Full parsed result of a Burp Suite XML report."""

    issues: list[ParsedBurpIssue] = field(default_factory=list)

    skipped_false_positives: int = 0
    """Issues the tester dismissed in Burp (``severity="False positive"``)."""

    skipped_malformed: int = 0
    """Issues with no usable ``type``."""

    wrong_format: bool = False
    """True when the file parsed but is not a Burp report at all."""

    @property
    def total_instances(self) -> int:
        return sum(len(issue.instances) for issue in self.issues)

    @property
    def is_empty(self) -> bool:
        return not self.issues


def severity_to_int(label: Optional[str]) -> int:
    """Map a Burp severity label to Cerno's 0-4 ``severity_int``.

    ``"False positive"`` is *not* mapped here -- :func:`parse_burp_file` skips
    those issues outright. See :data:`SEVERITY_BY_LABEL` for why an unrecognised
    label floors to 0 rather than raising.
    """
    if label is None:
        return 0
    return SEVERITY_BY_LABEL.get(str(label).strip().lower(), 0)


def _slug(name: str) -> str:
    """A compact, stable, URL-safe form of an issue name."""
    return _SLUG_STRIP_RE.sub("-", str(name or "").strip().lower()).strip("-")


def type_to_ref(raw: Any, name: str) -> Optional[str]:
    """Return the ``plugin_ref`` for a Burp issue, or None if unusable.

    The decimal ``type`` becomes the 8-digit hex index PortSwigger publishes.
    A :data:`~cerno_pkg.constants.BURP_GENERIC_TYPES` index identifies nothing
    on its own -- every extension-generated issue reports ``0x08000000`` -- so a
    slug of the issue name is appended to keep two unrelated findings from
    merging onto one ``plugins`` row.

    Returns:
        ``"00200300"``, ``"08000000-jwt-none-algorithm-accepted"``, or None for
        a missing or non-integer type.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None

    hex_ref = f"{value:08x}"
    if hex_ref in BURP_GENERIC_TYPES:
        slug = _slug(name)
        return f"{hex_ref}-{slug}" if slug else hex_ref
    return hex_ref


def kb_url(type_ref: Optional[str]) -> Optional[str]:
    """The PortSwigger issue-definition page for a ref, or None if it has none.

    The bare hex index resolves without the slug PortSwigger's own links carry,
    so the id alone is enough. A generic (slugged) ref has no published page --
    returning None matters, because a fabricated URL would be a dead link in the
    finding panel.
    """
    if not type_ref:
        return None
    if type_ref.split("-", 1)[0] in BURP_GENERIC_TYPES:
        return None
    return BURP_KB_BASE + type_ref


def html_to_text(raw: Optional[str]) -> str:
    """Flatten a Burp HTML prose fragment into plain text.

    Block-level tags become line breaks, every other tag is dropped, entities
    are unescaped and blank lines are removed. The result is read in a terminal
    panel, so paragraph spacing buys nothing and costs vertical room in a cell
    that already merges many instances.
    """
    if not raw:
        return ""
    text = _BLOCK_TAG_RE.sub("\n", str(raw))
    text = _TAG_RE.sub("", text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def extract_cwes(raw: Optional[str]) -> list[str]:
    """Pull CWE ids out of Burp's ``vulnerabilityClassifications`` block.

    Sorted numerically, not lexically: ``CWE-79`` precedes ``CWE-200``.
    """
    numbers = {int(match) for match in _CWE_RE.findall(str(raw or ""))}
    return [f"CWE-{number}" for number in sorted(numbers)]


def find_cves(raw: Optional[str]) -> list[str]:
    """Pull valid CVE ids out of free text.

    Burp classifies by CWE, but its references and prose do sometimes name a
    CVE. Capturing those into the existing ``plugins.cves`` column is what lets
    a Burp finding cross-reference a Nessus one for the same vulnerability.
    """
    found = {match.upper() for match in _CVE_RE.findall(str(raw or ""))}
    return sorted(found)


def split_target(host_url: str) -> tuple[str, str, Optional[int]]:
    """Split Burp's target URL into ``(scheme, host, port)``.

    The port is defaulted from the scheme when the URL omits it, and is None
    when it is unusable -- ``ports.port_number`` CHECKs ``BETWEEN 1 AND 65535``,
    so 0 and out-of-range values must not reach it. IPv6 brackets are stripped,
    because a bracketed form would key a second, duplicate ``hosts`` row.
    """
    try:
        parts = urlsplit(str(host_url or "").strip())
    except ValueError:
        return ("", "", None)

    scheme = parts.scheme.lower()
    try:
        host = parts.hostname or ""
    except ValueError:
        host = ""

    # An explicit-but-invalid port does *not* fall back to the scheme default:
    # that would invent a port Burp never reported. Same rule as
    # ``nuclei_parse.normalize_port``.
    port: Optional[int]
    explicit = True
    try:
        port = parts.port
        explicit = port is not None
    except ValueError:
        port = None
    if port is not None and not 1 <= port <= 65535:
        port = None
    if port is None and not explicit:
        port = SCHEME_PORTS.get(scheme)

    if not host:
        # A target Burp wrote without a scheme ("web01.corp.local:8443") is not
        # a URL to urlsplit, which reads it as scheme + path.
        raw = unbracket(str(host_url or "").strip())
        if raw and "://" not in raw and not scheme:
            host = raw

    return (scheme, unbracket(host), port)


def _truncate(text: str, max_bytes: int) -> str:
    """Cap ``text`` at ``max_bytes`` UTF-8 bytes, marking it when cut."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    kept = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{kept}\n... [truncated, {len(encoded)} bytes total]"


def _decode_payload(elem: Optional[ET.Element], max_bytes: int) -> Optional[str]:
    """Decode a ``<request>``/``<response>`` element, or None if absent/empty.

    Burp writes these base64-encoded by default (``base64="true"``) but will
    write them as-is when the operator unticks that export option, so both
    shapes have to be handled. Truncation happens after decoding, so the cap is
    on real HTTP bytes rather than on base64 expansion.
    """
    if elem is None:
        return None
    raw = elem.text or ""
    if not raw.strip():
        return None

    if (elem.get("base64") or "").strip().lower() == "true":
        try:
            decoded = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            log_debug("Burp payload is marked base64 but did not decode; kept raw")
            return _truncate(raw, max_bytes)
        return _truncate(decoded.decode("utf-8", errors="replace"), max_bytes)

    return _truncate(raw, max_bytes)


def format_plugin_output(instances: list[ParsedBurpInstance]) -> str:
    """Render one issue type's instances for one host:port into one block.

    Every instance keeps its location, confidence and detail, followed by its
    HTTP exchange -- the longest content last, so the operator reads the
    triage-relevant lines first. Instances beyond
    :data:`~cerno_pkg.constants.BURP_MAX_INSTANCES_RENDERED` are summarised by a
    count: they all share one ``plugin_output`` cell, and a dozen full HTTP
    exchanges in a terminal panel is not evidence anyone reads.
    """
    blocks: list[str] = []
    for instance in instances[:BURP_MAX_INSTANCES_RENDERED]:
        lines = [f"location: {instance.location or instance.path or '/'}"]
        if instance.confidence:
            lines.append(f"confidence: {instance.confidence}")
        if instance.detail:
            lines.append(f"detail: {instance.detail}")
        if instance.request:
            lines.append(f"request:\n{instance.request}")
        if instance.response:
            lines.append(f"response:\n{instance.response}")
        blocks.append("\n".join(lines))

    remaining = len(instances) - BURP_MAX_INSTANCES_RENDERED
    if remaining > 0:
        blocks.append(
            f"... and {remaining} more instance{'s' if remaining != 1 else ''} "
            "of this issue on this host:port"
        )

    return "\n\n".join(blocks)


def _text(elem: Optional[ET.Element]) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def _add_issue(elem: ET.Element, result: ParsedBurp, index: dict) -> None:
    """Fold one ``<issue>`` element into ``result``, grouping by type."""
    severity_label = _text(elem.find("severity"))
    if severity_label.strip().lower() == FALSE_POSITIVE_LABEL:
        result.skipped_false_positives += 1
        return

    name = _text(elem.find("name"))
    type_ref = type_to_ref(_text(elem.find("type")) or None, name)
    if not type_ref:
        result.skipped_malformed += 1
        return

    severity = severity_to_int(severity_label)
    classifications = _text(elem.find("vulnerabilityClassifications"))
    references = _text(elem.find("references"))
    detail_html = _text(elem.find("issueDetail"))
    cves = find_cves(f"{references}\n{classifications}\n{detail_html}")
    cwes = extract_cwes(classifications)

    issue = index.get(type_ref)
    if issue is None:
        issue = ParsedBurpIssue(
            type_ref=type_ref,
            name=name or type_ref,
            severity_int=severity,
            url=kb_url(type_ref),
            cves=cves,
            cwes=cwes,
            background=html_to_text(_text(elem.find("issueBackground"))),
            remediation=html_to_text(_text(elem.find("remediationBackground"))),
            references=html_to_text(references),
        )
        index[type_ref] = issue
        result.issues.append(issue)
    else:
        # Several issues of one type: take the worst severity and the union of
        # classifications, mirroring how the nuclei importer merges templates.
        issue.severity_int = max(issue.severity_int, severity)
        if cves:
            issue.cves = sorted(set(issue.cves) | set(cves))
        if cwes:
            issue.cwes = extract_cwes(" ".join(issue.cwes + cwes))

    host_elem = elem.find("host")
    scheme, host, port = split_target(_text(host_elem))
    ip = (host_elem.get("ip") or "").strip() if host_elem is not None else ""

    issue.instances.append(
        ParsedBurpInstance(
            host=host,
            ip=unbracket(ip) or None,
            port=port,
            scheme=scheme,
            path=_text(elem.find("path")),
            location=_text(elem.find("location")),
            confidence=_text(elem.find("confidence")),
            detail=html_to_text(detail_html),
            request=_decode_payload(
                elem.find("requestresponse/request"), BURP_REQUEST_MAX_BYTES
            ),
            response=_decode_payload(
                elem.find("requestresponse/response"), BURP_RESPONSE_MAX_BYTES
            ),
        )
    )


def parse_burp_file(xml_path: Union[str, Path]) -> ParsedBurp:
    """Parse a Burp Suite "Report issues" XML export.

    Memory-efficient single-pass parsing via ``ET.iterparse`` with element
    clearing, as in :mod:`cerno_pkg.nmap_parse`: a Burp report of any size is
    dominated by base64 HTTP exchanges, and holding the whole tree would mean
    holding every one of them at once.

    Never raises on a missing/unreadable/malformed/empty file. Malformed XML
    keeps whatever issues were read before the break, so an export interrupted
    mid-write still imports everything it managed to flush.
    """
    result = ParsedBurp()
    path = Path(xml_path)

    if not path.is_file():
        log_debug(f"Burp report not found, nothing to parse: {path}")
        return result

    index: dict[str, ParsedBurpIssue] = {}
    root_checked = False

    try:
        for event, elem in ET.iterparse(str(path), events=("start", "end")):
            if event == "start":
                if not root_checked:
                    root_checked = True
                    if elem.tag != "issues":
                        log_error(
                            f"{path} is not a Burp report "
                            f"(root element is <{elem.tag}>, expected <issues>)"
                        )
                        return ParsedBurp(wrong_format=True)
                continue

            if elem.tag != "issue":
                continue
            _add_issue(elem, result, index)
            elem.clear()
    except ET.ParseError as exc:
        # A truncated trailing element is normal for an interrupted export.
        log_error(f"Burp report {path} is malformed (keeping partial results): {exc}")
    except OSError as exc:
        log_error(f"Error reading Burp report {path}: {exc}")
        return ParsedBurp()

    log_debug(
        f"Parsed {result.total_instances} Burp issue instances over "
        f"{len(result.issues)} issue types from {path} "
        f"(skipped {result.skipped_false_positives} false positives, "
        f"{result.skipped_malformed} malformed)"
    )
    return result
