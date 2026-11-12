"""Pure nuclei result parser (no database dependency).

Parses nuclei's JSON output into structured dataclasses: one
:class:`ParsedNucleiTemplate` per template that matched, each holding every
individual :class:`ParsedNucleiMatch` that template produced. This is the
nuclei counterpart to :mod:`cerno_pkg.nmap_parse` and follows the same contract.

**Three input shapes, all accepted.** nuclei writes its results three
different ways and operators use all of them, so the shape is sniffed from the
first non-whitespace byte rather than the file extension:

* ``-je/-json-export`` writes a **single JSON array** (``json.Marshal`` over a
  ``[]ResultEvent``). This is what Cerno's own post-import suggestion produces.
* ``-jle/-jsonl-export`` and ``-j/-jsonl`` write **newline-delimited JSON**,
  one record per line.

**Matches are preserved, never collapsed.** One template routinely matches the
same host:port several times -- six missing security headers, three detected
technologies, two TLS versions -- distinguished by ``matcher-name`` or, when
that is absent, only by ``extracted-results``. ``finding_affected_hosts`` has a
``UNIQUE (finding_id, host_id, port_number)`` constraint, so merging that
evidence is the importer's job; this module's job is to lose none of it.

**Nothing is sanitized here.** The database should hold exactly what the
scanner reported. Unlike ``.nessus`` XML, nuclei JSON *can* legally carry an
ESC byte (``\\u001b``) in attacker-influenced fields such as
``extracted-results``, which are lifted verbatim from response bodies -- so
every consumer must neutralize these values at render time via
:func:`cerno_pkg.ansi.safe_text` or ``rich.text.Text``.

Parsing is deliberately forgiving: a missing file, a directory, malformed JSON,
an empty file or a truncated final line (an interrupted scan) yields an empty
or partial :class:`ParsedNuclei` rather than raising, so the import path never
errors on a partial run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from .config import coerce_str_list
from .constants import NUCLEI_TEMPLATE_REPO_BASE, NUCLEI_TEMPLATE_URL_BASE
from .logging_setup import log_debug, log_error
from .parsing import SCHEME_PORTS

__all__ = [
    "NUCLEI_TEMPLATE_REPO_BASE",
    "NUCLEI_TEMPLATE_URL_BASE",
    "ParsedNuclei",
    "ParsedNucleiMatch",
    "ParsedNucleiTemplate",
    "classify_cvss",
    "extract_cves",
    "format_plugin_output",
    "normalize_port",
    "parse_nuclei_file",
    "resolve_template_url",
    "safe_template_repo_url",
    "safe_template_url",
    "severity_to_int",
]

#: nuclei severity label -> Cerno ``severity_int``.
#:
#: nuclei also emits ``unknown`` and ``""`` (its ``Undefined`` constant, whose
#: ``String()`` renders empty). Neither has a ``severity_levels`` row, and
#: ``plugins.severity_int`` both CHECKs ``BETWEEN 0 AND 4`` and foreign-keys to
#: that table -- while ``v_plugins_with_severity`` is an INNER JOIN, so an
#: unmapped value would make the finding silently vanish from every query
#: rather than fail loudly. Info is the conservative floor.
SEVERITY_BY_LABEL: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 0,
    "": 0,
}

#: Default port per URL scheme, for records that omit ``port``.
#:
#: Shared with the Burp parser via :data:`cerno_pkg.parsing.SCHEME_PORTS`, so
#: both scanners' scheme-derived ports and services stay in step.
_SCHEME_PORTS = SCHEME_PORTS

#: Same validation the Nessus importer applies to ``<cve>`` elements.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

#: A ``template-url`` we are willing to store: http(s) and no whitespace.
#:
#: This is attacker-influenced (it comes from the scanned file), and it is
#: later interpolated into a Rich *style* string to build the OSC-8 hyperlink
#: in the finding panel -- where embedded whitespace would be parsed as extra
#: style tokens and could abort rendering. Anything else falls back to the
#: deterministic public-viewer URL, so the stored value is always safe.
_TEMPLATE_URL_RE = re.compile(r"^https?://\S+$")

#: A ``template`` path we are willing to turn into a repository URL.
#:
#: Same hazard as :data:`_TEMPLATE_URL_RE` -- the resulting URL is interpolated
#: into a Rich *style* string -- plus a traversal concern, since this value is
#: appended to a base URL. Only a plain relative YAML path is accepted: the
#: character class excludes whitespace, backslashes and ``:`` (so no scheme or
#: authority can be smuggled in), a leading dot or slash cannot match, and
#: ``..`` is rejected separately.
_TEMPLATE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\.ya?ml$")


@dataclass
class ParsedNucleiMatch:
    """One nuclei result record: one match of one template against one target."""

    host: str
    """The target as nuclei addressed it (a bare hostname or IP, never a URL)."""

    ip: Optional[str]
    """The resolved IP, when nuclei reported one. Absent for dns templates."""

    port: Optional[int]
    """None where nuclei reported no usable port (dns templates, bad values)."""

    matched_at: str
    matcher_name: Optional[str]
    extracted_results: list[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    result_type: str = ""
    """nuclei's ``type``: ``http``, ``dns``, ``ssl``, ``network``, ..."""

    @property
    def effective_ip(self) -> str:
        """The value to store in ``hosts.ip_address``, which is NOT NULL.

        nuclei omits ``ip`` entirely for dns templates, so the host falls back
        to itself -- the same precedent the Nessus importer sets when a
        ``host-ip`` tag is missing.
        """
        return self.ip or self.host

    @property
    def target_key(self) -> tuple[str, str, Optional[int]]:
        """Identity of the affected host:port, for merging colliding matches."""
        return (self.effective_ip, self.host, self.port)

    @property
    def service_name(self) -> Optional[str]:
        """Service for ``host_services.svc_name``, or None if unknowable.

        nuclei reports a URL, not a service name, so the scheme in
        ``matched-at`` is the service: ``http://x/robots.txt`` is an ``http``
        service. ``v_http_services`` already accepts the literal ``http`` and
        ``https`` tokens, so these rows need no view change.

        Where there is no scheme -- an ``ssl`` template's ``matched-at`` is a
        bare ``host:port`` -- the record's ``type`` is used instead. That is
        deliberately *not* mapped to http/https: an ssl template firing on
        3389 is not a web service, and claiming otherwise would put RDP in the
        web-target list. The view's port-based arm still catches 443.
        """
        scheme, sep, _ = self.matched_at.partition("://")
        if sep and scheme.strip().lower() in _SCHEME_PORTS:
            return scheme.strip().lower()
        return self.result_type.strip().lower() or None


@dataclass
class ParsedNucleiTemplate:
    """Every match produced by one nuclei template, with its metadata."""

    template_id: str
    template_name: str
    severity_int: int
    template_url: Optional[str] = None
    cves: list[str] = field(default_factory=list)
    cvss3_score: Optional[float] = None
    cvss2_score: Optional[float] = None
    matches: list[ParsedNucleiMatch] = field(default_factory=list)


@dataclass
class ParsedNuclei:
    """Full parsed result of a nuclei JSON/JSONL file."""

    templates: list[ParsedNucleiTemplate] = field(default_factory=list)
    skipped_non_matches: int = 0
    """Records with ``matcher-status: false`` (emitted under ``-ms``)."""

    skipped_malformed: int = 0
    """Unparsable lines, or records with no ``template-id``."""

    @property
    def total_matches(self) -> int:
        return sum(len(t.matches) for t in self.templates)

    @property
    def is_empty(self) -> bool:
        return not self.templates


def severity_to_int(label: Optional[str]) -> int:
    """Map a nuclei severity label to Cerno's 0-4 ``severity_int``.

    Anything unrecognised -- including nuclei's own ``unknown`` and ``""`` --
    floors to 0 (Info). See :data:`SEVERITY_BY_LABEL` for why that matters.
    """
    if label is None:
        return 0
    return SEVERITY_BY_LABEL.get(str(label).strip().lower(), 0)


def extract_cves(value: Any) -> list[str]:
    """Normalize a nuclei ``classification.cve-id`` into sorted, valid CVE ids.

    The field is a ``stringslice.StringSlice``, whose ``MarshalJSON`` emits its
    underlying value verbatim -- so it arrives as JSON ``null`` (the common
    case), a bare string, or an array, depending on how the template author
    wrote the YAML. Malformed ids are dropped, matching the Nessus importer.
    """
    candidates = coerce_str_list(value, [])
    valid = {c.upper() for c in candidates if _CVE_RE.match(c.upper())}
    return sorted(valid)


def classify_cvss(
    metrics: Optional[str], score: Optional[float]
) -> tuple[Optional[float], Optional[float]]:
    """Route a single nuclei CVSS score into Cerno's v3 / v2 columns.

    nuclei reports one ``cvss-score`` plus a ``cvss-metrics`` vector string;
    Cerno has separate ``cvss3_score`` and ``cvss2_score`` columns. The vector's
    prefix decides which. CVSS v4 vectors are recorded in the v3 column because
    Cerno has no v4 slot.

    Returns:
        ``(cvss3_score, cvss2_score)``, with at most one set.
    """
    if score is None:
        return (None, None)
    vector = (metrics or "").strip().upper()
    is_v2 = vector.startswith("CVSS:2") or (
        bool(vector) and not vector.startswith("CVSS:") and "AU:" in vector
    )
    return (None, score) if is_v2 else (score, None)


def normalize_port(raw: Any, scheme: Optional[str]) -> Optional[int]:
    """Turn nuclei's string ``port`` into a value ``ports`` will accept.

    ``port`` is a string and is omitted entirely by whole template classes
    (every dns record in a real export). ``ports.port_number`` CHECKs
    ``BETWEEN 1 AND 65535``, so ``""``, ``"0"`` and out-of-range values must
    become NULL rather than 0. An explicit-but-invalid port does *not* fall
    back to the scheme default -- that would invent a port nuclei never probed.
    """
    if raw is not None and str(raw).strip() != "":
        try:
            port = int(str(raw).strip())
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65535 else None
    return _SCHEME_PORTS.get((scheme or "").strip().lower())


def format_plugin_output(matches: list[ParsedNucleiMatch]) -> str:
    """Render a template's matches for one host:port into one evidence block.

    Every sub-match keeps both its ``matcher-name`` *and* its
    ``extracted-results``: templates like ``http-missing-security-headers``
    differ only by the former, while ``tls-version`` carries no matcher name at
    all and differs only by the latter. Keying on either alone loses evidence.
    """
    blocks: list[str] = []
    for match in matches:
        lines = [f"matched-at: {match.matched_at}"]
        if match.matcher_name:
            lines.append(f"matcher: {match.matcher_name}")
        if match.extracted_results:
            lines.append("extracted: " + ", ".join(match.extracted_results))
        blocks.append("\n".join(lines))

    # Reproduction commands last, de-duplicated: a template matching one URL six
    # times (one per missing header) emits the same curl six times, which would
    # otherwise bury the matcher names the operator actually came to read.
    seen: list[str] = []
    for match in matches:
        if match.curl_command and match.curl_command not in seen:
            seen.append(match.curl_command)
    blocks.extend(f"curl: {cmd}" for cmd in seen)

    return "\n\n".join(blocks)


def safe_template_repo_url(raw: Any) -> Optional[str]:
    """Return the template's source URL in the nuclei-templates repo, or None.

    ``raw`` is the result's ``template`` field -- a path relative to the
    templates root, such as ``http/cves/2021/CVE-2021-44228.yaml``. It is
    attacker-influenced, so only a plain relative YAML path is accepted; see
    :data:`_TEMPLATE_PATH_RE`. Returning None lets the caller fall back rather
    than build a URL out of something unexpected.
    """
    candidate = str(raw or "").strip()
    if not _TEMPLATE_PATH_RE.match(candidate):
        return None
    if ".." in candidate.split("/"):
        return None
    return NUCLEI_TEMPLATE_REPO_BASE + candidate


def resolve_template_url(record: dict, template_id: str) -> str:
    """Pick the best details URL for a template, most useful first.

    1. The template's source in the nuclei-templates repo, built from the
       result's ``template`` path. This shows the matcher logic that fired.
    2. The result's own ``template-url`` (the public template viewer).
    3. The viewer URL derived from the template id, which always works because
       it needs no path -- ``template`` is ``omitempty`` in nuclei's output.
    """
    repo_url = safe_template_repo_url(record.get("template"))
    if repo_url:
        return repo_url
    return safe_template_url(record.get("template-url"), template_id)


def safe_template_url(raw: Any, template_id: str) -> str:
    """Return a storable ``template-url``, or the public-viewer fallback.

    See :data:`_TEMPLATE_URL_RE` for why an arbitrary string is not acceptable.
    """
    candidate = str(raw or "").strip()
    if _TEMPLATE_URL_RE.match(candidate):
        return candidate
    return NUCLEI_TEMPLATE_URL_BASE + template_id


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _add_record(record: dict, result: ParsedNuclei, index: dict) -> None:
    """Fold one nuclei record into ``result``, grouping by ``template-id``."""
    if record.get("matcher-status") is False:
        result.skipped_non_matches += 1
        return

    template_id = str(record.get("template-id") or "").strip()
    if not template_id:
        result.skipped_malformed += 1
        return

    info = record.get("info")
    if not isinstance(info, dict):
        info = {}
    classification = info.get("classification")
    if not isinstance(classification, dict):
        classification = {}

    severity = severity_to_int(info.get("severity"))
    cvss3, cvss2 = classify_cvss(
        classification.get("cvss-metrics"), _as_float(classification.get("cvss-score"))
    )

    template = index.get(template_id)
    if template is None:
        template = ParsedNucleiTemplate(
            template_id=template_id,
            template_name=str(info.get("name") or "").strip() or template_id,
            severity_int=severity,
            template_url=resolve_template_url(record, template_id),
            cves=extract_cves(classification.get("cve-id")),
            cvss3_score=cvss3,
            cvss2_score=cvss2,
        )
        index[template_id] = template
        result.templates.append(template)
    else:
        # Several records for one template: take the worst severity and the
        # union of CVEs, mirroring how the Nessus importer merges ReportItems.
        template.severity_int = max(template.severity_int, severity)
        if template.cves or classification.get("cve-id"):
            template.cves = sorted(
                set(template.cves) | set(extract_cves(classification.get("cve-id")))
            )
        if template.cvss3_score is None:
            template.cvss3_score = cvss3
        if template.cvss2_score is None:
            template.cvss2_score = cvss2

    # ``template-path`` is deliberately ignored: it is the operator's local
    # filesystem path and leaks their home directory.
    template.matches.append(
        ParsedNucleiMatch(
            host=str(record.get("host") or "").strip(),
            ip=str(record.get("ip") or "").strip() or None,
            port=normalize_port(record.get("port"), record.get("scheme")),
            matched_at=str(record.get("matched-at") or "").strip(),
            matcher_name=str(record.get("matcher-name") or "").strip() or None,
            extracted_results=[str(x) for x in (record.get("extracted-results") or [])],
            curl_command=str(record.get("curl-command") or "").strip() or None,
            result_type=str(record.get("type") or "").strip(),
        )
    )


def parse_nuclei_file(json_path: Union[str, Path]) -> ParsedNuclei:
    """Parse a nuclei ``-je`` / ``-jle`` / ``-jsonl`` file.

    The shape is detected from the first non-whitespace byte (``[`` for the
    ``-je`` array, ``{`` for newline-delimited records), so the caller needs no
    knowledge of which flag produced the file.

    Never raises on a missing/unreadable/malformed/empty file; returns an empty
    result and logs the reason instead. A malformed line in an otherwise valid
    JSONL file is counted and skipped, so a scan interrupted mid-write still
    imports everything it managed to flush.
    """
    result = ParsedNuclei()
    path = Path(json_path)

    if not path.is_file():
        log_debug(f"nuclei output not found, nothing to parse: {path}")
        return result

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log_error(f"Error reading nuclei output {path}: {exc}")
        return result

    stripped = text.lstrip()
    if not stripped:
        log_debug(f"nuclei output is empty: {path}")
        return result

    index: dict[str, ParsedNucleiTemplate] = {}

    if stripped[0] == "[":
        # -je / -json-export: one JSON array of every result.
        try:
            records = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as exc:
            log_error(f"Failed to parse nuclei JSON array {path}: {exc}")
            return ParsedNuclei()
        if not isinstance(records, list):
            log_error(f"nuclei JSON in {path} is not an array of results")
            return ParsedNuclei()
        for record in records:
            if isinstance(record, dict):
                _add_record(record, result, index)
            else:
                result.skipped_malformed += 1
    elif stripped[0] == "{":
        # -jle / -jsonl: newline-delimited records.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # A truncated trailing line is normal for an interrupted scan.
                result.skipped_malformed += 1
                continue
            if isinstance(record, dict):
                _add_record(record, result, index)
            else:
                result.skipped_malformed += 1
    else:
        log_error(f"{path} does not look like nuclei JSON or JSONL output")
        return ParsedNuclei()

    log_debug(
        f"Parsed {result.total_matches} nuclei matches over "
        f"{len(result.templates)} templates from {path} "
        f"(skipped {result.skipped_non_matches} non-matches, "
        f"{result.skipped_malformed} malformed)"
    )
    return result
