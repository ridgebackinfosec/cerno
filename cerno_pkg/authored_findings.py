"""Hand-authored findings: the sources Cerno creates rather than imports.

A tester who finds something by hand -- or an MCP client that discovers
something while running tools -- needs it recorded as a *finding*, not as a note
on somebody else's. This module is the single place that writes those, so the
review TUI and the MCP server cannot drift apart; it is to ``operator:`` and
``agent:`` what :mod:`cerno_pkg.nessus_import` is to ``nessus:``.

It writes the same normalized tables the three importers fill, so an authored
finding is indistinguishable downstream: same review states, same ``[W]``
workflow matching, same ``[R]`` verdicts, same ``query_findings``.

**Two sources, one writer.** Every entry point takes an explicit ``source`` --
:data:`~cerno_pkg.constants.SOURCE_OPERATOR` for the TUI,
:data:`~cerno_pkg.constants.SOURCE_AGENT` for an MCP client -- and
:func:`create_authored_finding` has no default for it. That is deliberate: the
whole point of the split is that a stored finding says which channel asserted
it, and a default would let a new caller silently inherit the operator's name
for something an agent wrote. The namespace records the *creator* only; editing
an ``agent:`` finding in the TUI leaves it ``agent:``.

Three things are specific to a source with no scanner behind it:

* **One shared scan per source.** ``findings`` needs a ``scan_id`` and a
  hand-authored finding belongs to no scanner run, so each source's findings
  live in one scan named by
  :data:`~cerno_pkg.constants.AUTHORED_SCAN_NAMES`, created on first use.
  Keeping them out of the scanner scans is what preserves the invariant
  :mod:`cerno_pkg.cross_scan` depends on -- that one scan has one source -- so
  ``cerno scan compare`` keeps working on the scans around them.
* **A sequential identity, per source.** There is no plugin number or template
  id to borrow, so the ref is ``MAX(ref) + 1`` over that source's ids alone,
  allocated inside the write transaction -- ``operator:1`` and ``agent:1``
  coexist. It is deliberately *not* derived from the title:
  ``Plugin.save()`` is ``INSERT OR REPLACE`` against a table global to every
  scan, so a title-derived id would let a second finding silently overwrite an
  earlier one's name and severity, and renaming a finding would move its
  identity.
* **No service discovery.** ``host_services`` rows are not written. The author
  is describing a finding, not reporting what is listening, and an invented
  ``svc_name`` would put guesses into ``v_http_services`` and the web-target
  lists.

Nothing here renders. Callers prompt, this validates and writes, and the
terminal neutralizes the text at display time via
:func:`cerno_pkg.ansi.safe_text` -- which matters as much as it does for scan
data, because an MCP client may write a title out of attacker-influenced tool
output.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from .constants import (
    AUTHORED_DESCRIPTION_MAX_CHARS,
    AUTHORED_SCAN_NAMES,
    AUTHORED_SOURCES,
    AUTHORED_TITLE_MAX_CHARS,
    PLUGIN_ID_PREFIXES,
    SCANS_ROOT,
    SOURCE_IDS,
)
from .database import db_transaction
from .logging_setup import log_info
from .models import Finding, Host, Plugin, Port, Scan, now_iso
from .parsing import plugin_source, scan_target_type, split_host_port, unbracket

__all__ = [
    "AuthoredFindingError",
    "AuthoredFindingInput",
    "UNCHANGED",
    "authored_scan_path",
    "create_authored_finding",
    "get_or_create_authored_scan",
    "load_authored_finding",
    "next_authored_ref",
    "parse_target_tokens",
    "update_authored_finding",
    "validate_authored_input",
]

#: Same CVE validation every other source applies.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

#: A reference URL we are willing to store.
#:
#: ``plugins.plugin_url`` is later interpolated into a Rich *style* string to
#: build the OSC-8 hyperlink in the finding panel, where embedded whitespace is
#: parsed as extra style tokens and can abort rendering -- the same hazard
#: ``nuclei_parse._TEMPLATE_URL_RE`` guards against, for the same reason.
_URL_RE = re.compile(r"^https?://\S+$")

#: Separators accepted between targets in one typed string.
_TARGET_SPLIT_RE = re.compile(r"[,\s]+")


class _Unchanged:
    """Sentinel distinguishing "leave this field alone" from "set it to None".

    :func:`update_authored_finding` must be able to *clear* a reference URL,
    which an ``Optional[str] = None`` default cannot express -- omitting the
    argument and clearing the field would be the same call.
    """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNCHANGED"


UNCHANGED = _Unchanged()
"""Default for :func:`update_authored_finding`'s ``reference_url``.

Callers that cannot pass a sentinel (the MCP tool, whose arguments cross a JSON
boundary) map an empty string to ``None`` and omission to this.
"""


class AuthoredFindingError(ValueError):
    """A hand-authored finding could not be created or updated.

    Carries every problem at once rather than the first, so a caller can show
    the author all of them and re-prompt instead of trickling them out one
    round-trip at a time.
    """

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass
class AuthoredFindingInput:
    """Everything needed to write one hand-authored finding.

    Carries no source: which channel is writing is the *caller's* fact, passed
    separately to :func:`create_authored_finding`, so the same collected input
    cannot be replayed under a different attribution by mistake.
    """

    title: str
    """Becomes ``plugins.plugin_name``."""

    severity_int: int
    """0-4. Unlike Burp, an author may call something Critical."""

    targets: list[tuple[str, Optional[int]]] = field(default_factory=list)
    """``(host, port)`` pairs. May be empty, and a port may be None."""

    description: str = ""
    """Stored as ``plugin_output`` on every affected-host row.

    ``plugins`` has no description column, and per-host evidence is where all
    three importers put theirs, so the finding's narrative goes there too --
    the same text against each host rather than one per host.
    """

    cves: list[str] = field(default_factory=list)
    reference_url: Optional[str] = None


def parse_target_tokens(tokens: Sequence[str]) -> list[tuple[str, Optional[int]]]:
    """Turn typed target strings into ``(host, port)`` pairs.

    Accepts one target per element or several in one string separated by commas
    or whitespace, so a typed line and an MCP list behave identically. Each
    token is split by :func:`cerno_pkg.parsing.split_host_port`, the canonical
    parser, so bracketed IPv6, bare IPv6 and hostnames are handled the one way
    Cerno handles them everywhere.

    Pairs are kept, not flattened into a host list and a port list:
    ``finding_affected_hosts`` stores ``(host_id, port_number)`` rows, and
    ``parse_hosts_ports()`` would turn two targets into their cross product.

    Duplicates collapse (that table is UNIQUE per finding/host/port) and the
    original order is preserved, so the evidence reads in the order it was
    entered.
    """
    pairs: list[tuple[str, Optional[int]]] = []
    seen: set[tuple[str, Optional[int]]] = set()

    for token in tokens:
        for part in _TARGET_SPLIT_RE.split(str(token or "").strip()):
            if not part:
                continue
            host, port_str = split_host_port(part)
            if not host:
                # Keep it rather than drop it, so validation can name it.
                host = part
            port: Optional[int] = None
            if port_str is not None:
                try:
                    port = int(port_str)
                except (TypeError, ValueError):
                    port = None
            pair = (unbracket(host), port)
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)

    return pairs


def validate_authored_input(data: AuthoredFindingInput) -> list[str]:
    """Return every problem with ``data``, or an empty list if it is writable.

    One validator for both callers, so the TUI's re-prompt and the MCP's error
    response refuse exactly the same things.
    """
    problems: list[str] = []

    title = (data.title or "").strip()
    if not title:
        problems.append("Title is required.")
    elif len(title) > AUTHORED_TITLE_MAX_CHARS:
        problems.append(
            f"Title is {len(title)} characters; the limit is "
            f"{AUTHORED_TITLE_MAX_CHARS}."
        )

    if not isinstance(data.severity_int, int) or isinstance(data.severity_int, bool):
        problems.append("Severity must be a whole number from 0 to 4.")
    elif not 0 <= data.severity_int <= 4:
        problems.append(
            f"Severity {data.severity_int} is out of range. Use 0=Info, 1=Low, "
            "2=Medium, 3=High, 4=Critical."
        )

    if len(data.description or "") > AUTHORED_DESCRIPTION_MAX_CHARS:
        problems.append(
            f"Description is {len(data.description)} characters; the limit is "
            f"{AUTHORED_DESCRIPTION_MAX_CHARS}."
        )

    for host, port in data.targets:
        if not str(host or "").strip():
            problems.append("A target was given with no host.")
            continue
        if port is not None and not 1 <= port <= 65535:
            problems.append(f"Port {port} on {host} is outside 1-65535.")

    for cve in data.cves:
        if not _CVE_RE.match(str(cve).strip().upper()):
            problems.append(f"{cve!r} is not a CVE id (expected CVE-YYYY-NNNN).")

    url = (data.reference_url or "").strip()
    if url and not _URL_RE.match(url):
        problems.append(f"Reference {url!r} must be an http(s) URL with no spaces.")

    return problems


def _require_authored_source(source: str) -> str:
    """Return ``source`` if it is a hand-authored one, else raise.

    The guard on every entry point, so a scanner source cannot be smuggled in
    and have findings written under it that no importer produced.
    """
    if source not in AUTHORED_SOURCES:
        raise AuthoredFindingError(
            [
                f"{source!r} is not a hand-authored source. Expected one of: "
                f"{', '.join(sorted(AUTHORED_SOURCES))}."
            ]
        )
    return source


def get_or_create_authored_scan(
    source: str, conn: Optional[sqlite3.Connection] = None
) -> Scan:
    """Return ``source``'s shared scan, creating it on first use.

    ``source_file_path`` and ``source_file_hash`` stay NULL: no file produced
    this scan, and claiming one would make ``cerno demo``-style hash
    idempotency checks compare against nothing. ``export_root`` is NOT NULL, so
    it points at the directory a tool run against these findings would write to.
    """
    scan_name = AUTHORED_SCAN_NAMES[_require_authored_source(source)]
    with db_transaction(conn) as c:
        existing = Scan.get_by_name(scan_name, c)
        if existing is not None:
            return existing

        scan = Scan(
            scan_name=scan_name,
            source_file_path=None,
            source_file_hash=None,
            export_root=str(SCANS_ROOT / scan_name),
            created_at=now_iso(),
        )
        scan.scan_id = scan.save(c)
        log_info(f"Created the {scan_name} scan for {source}-authored findings")
        return scan


def next_authored_ref(source: str, conn: Optional[sqlite3.Connection] = None) -> int:
    """Return the next free finding number for ``source``.

    ``MAX(ref) + 1`` over *that source's* ids, cast to INTEGER so ``operator:10``
    follows ``operator:9`` instead of sorting between 1 and 2. Filtered on
    ``source_id`` rather than a ``LIKE 'operator:%'`` scan, which is the reason
    that column is stored alongside the prefix -- and what keeps the two
    counters independent, so ``operator:1`` and ``agent:1`` coexist.

    Call it inside the write transaction: a TUI and an MCP client sharing the
    database must not be handed the same number.
    """
    _require_authored_source(source)
    prefix_len = len(PLUGIN_ID_PREFIXES[source])
    with db_transaction(conn) as c:
        row = c.execute(
            "SELECT MAX(CAST(substr(plugin_id, ?) AS INTEGER)) FROM plugins "
            "WHERE source_id = ?",
            (prefix_len + 1, SOURCE_IDS[source]),
        ).fetchone()
    highest = row[0] if row and row[0] is not None else 0
    return int(highest) + 1


def _normalized_cves(cves: Sequence[str]) -> Optional[list[str]]:
    """Upper-cased, de-duplicated, sorted -- or None for an empty list."""
    valid = {str(c).strip().upper() for c in cves if str(c).strip()}
    return sorted(valid) or None


def _write_targets(
    finding_id: int,
    targets: Sequence[tuple[str, Optional[int]]],
    description: str,
    conn: sqlite3.Connection,
) -> int:
    """Replace a finding's affected-host rows. Returns how many were written.

    Deletes first, so an edit that drops a target drops its row rather than
    leaving it behind -- an append would make a corrected finding claim hosts
    it no longer affects.
    """
    conn.execute(
        "DELETE FROM finding_affected_hosts WHERE finding_id = ?", (finding_id,)
    )

    written = 0
    for host, port in targets:
        host = unbracket(str(host).strip())
        if not host:
            continue
        host_id = Host.get_or_create(
            ip_address=host,
            scan_target=host,
            scan_target_type=scan_target_type(host),
            conn=conn,
        )
        if port is not None:
            Port.get_or_create(port, conn=conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO finding_affected_hosts (
                finding_id, host_id, port_number, plugin_output
            ) VALUES (?, ?, ?, ?)
            """,
            (finding_id, host_id, port, description),
        )
        written += 1

    return written


def create_authored_finding(
    data: AuthoredFindingInput,
    source: str,
    conn: Optional[sqlite3.Connection] = None,
) -> tuple[str, int]:
    """Write a new hand-authored finding. Returns ``(plugin_id, finding_id)``.

    Args:
        data: The collected fields, already validated here rather than by the
            caller.
        source: Which channel is writing --
            :data:`~cerno_pkg.constants.SOURCE_OPERATOR` for the review TUI,
            :data:`~cerno_pkg.constants.SOURCE_AGENT` for an MCP client. There
            is **no default**: attribution is the one fact a caller must state,
            because it is what the stored namespace then claims forever.
        conn: Optional existing connection to write through.

    Raises:
        AuthoredFindingError: If ``source`` is not a hand-authored source, or
            ``data`` fails validation. Nothing is written in that case -- not
            even the scan, so a rejected first attempt leaves no trace in
            ``cerno scan list``.
    """
    _require_authored_source(source)
    problems = validate_authored_input(data)
    if problems:
        raise AuthoredFindingError(problems)

    scan_name = AUTHORED_SCAN_NAMES[source]
    with db_transaction(conn) as c:
        scan = get_or_create_authored_scan(source, c)
        if scan.scan_id is None:
            raise AuthoredFindingError([f"Could not create the {scan_name} scan."])

        plugin_id = PLUGIN_ID_PREFIXES[source] + str(next_authored_ref(source, c))

        Plugin(
            plugin_id=plugin_id,
            plugin_name=data.title.strip(),
            severity_int=data.severity_int,
            has_metasploit=False,  # the author can note one in the description
            cvss3_score=None,
            cvss2_score=None,
            metasploit_names=None,
            cves=_normalized_cves(data.cves),
            plugin_url=(data.reference_url or "").strip() or None,
        ).save(c)

        finding_id = Finding(scan_id=scan.scan_id, plugin_id=plugin_id).save(c)
        if finding_id is None:
            raise AuthoredFindingError([f"Could not create a finding for {plugin_id}."])

        written = _write_targets(finding_id, data.targets, data.description, c)

    log_info(
        f"Created {source} finding {plugin_id} ({data.title.strip()!r}, "
        f"severity {data.severity_int}, {written} host entries)"
    )
    return plugin_id, finding_id


def load_authored_finding(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> AuthoredFindingInput:
    """Read a hand-authored finding back as the input that would recreate it.

    This is what lets an edit pre-fill every prompt with what is already
    stored, so the author corrects one field instead of retyping all six.
    Accepts either authored source: both channels may read either, and the
    returned input carries no attribution of its own.

    Raises:
        AuthoredFindingError: If the finding does not exist or was not
            hand-authored.
    """
    with db_transaction(conn) as c:
        row = c.execute(
            "SELECT plugin_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise AuthoredFindingError([f"No finding with id {finding_id}."])

        plugin_id = str(row["plugin_id"])
        if plugin_source(plugin_id) not in AUTHORED_SOURCES:
            raise AuthoredFindingError([f"{plugin_id} was not entered by hand."])

        plugin = Plugin.get_by_id(plugin_id, c)
        if plugin is None:
            raise AuthoredFindingError([f"No plugin row for {plugin_id}."])

        targets, description = _load_targets(finding_id, c)

    return AuthoredFindingInput(
        title=plugin.plugin_name,
        severity_int=plugin.severity_int,
        targets=targets,
        description=description,
        cves=list(plugin.cves or []),
        reference_url=plugin.plugin_url,
    )


def update_authored_finding(
    finding_id: int,
    *,
    title: Optional[str] = None,
    severity_int: Optional[int] = None,
    targets: Optional[Sequence[tuple[str, Optional[int]]]] = None,
    description: Optional[str] = None,
    cves: Optional[Sequence[str]] = None,
    reference_url: object = UNCHANGED,
    conn: Optional[sqlite3.Connection] = None,
) -> str:
    """Edit a hand-authored finding in place. Returns its ``plugin_id``.

    Only the fields given are touched; omitted ones keep their stored values.
    Pass ``reference_url=None`` to clear a reference (omitting it leaves the
    stored one alone).

    **Either channel may edit either namespace**, by design: the operator owns
    the engagement and must be able to correct an agent's finding, and an agent
    refining a finding the operator dictated is ordinary collaboration. The
    consequence is that the namespace records the finding's *creator*, not its
    last editor -- an edited ``agent:`` finding stays ``agent:``.

    The ``plugin_id`` never changes, including when the title does. That is the
    point of a sequential ref: a workflow mapping or a note that names
    ``operator:3`` still names the same finding after it is reworded.

    Raises:
        AuthoredFindingError: If the finding does not exist, was not
            hand-authored, or the resulting finding would fail validation.
            Scanner findings are refused deliberately -- they are a record of
            what the scanner reported, and editing one would make the database
            disagree with the scan file it came from.
    """
    with db_transaction(conn) as c:
        row = c.execute(
            "SELECT plugin_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise AuthoredFindingError([f"No finding with id {finding_id}."])

        plugin_id = str(row["plugin_id"])
        if plugin_source(plugin_id) not in AUTHORED_SOURCES:
            raise AuthoredFindingError(
                [
                    f"{plugin_id} was not entered by hand, so it cannot be "
                    "edited. Record a verdict on it instead."
                ]
            )

        plugin = Plugin.get_by_id(plugin_id, c)
        if plugin is None:
            raise AuthoredFindingError([f"No plugin row for {plugin_id}."])

        current_targets, current_description = _load_targets(finding_id, c)

        merged = AuthoredFindingInput(
            title=plugin.plugin_name if title is None else title,
            severity_int=(
                plugin.severity_int if severity_int is None else severity_int
            ),
            targets=(
                list(current_targets) if targets is None else [tuple(t) for t in targets]  # type: ignore[misc]
            ),
            description=(current_description if description is None else description),
            cves=list(plugin.cves or []) if cves is None else list(cves),
            reference_url=(
                plugin.plugin_url
                if reference_url is UNCHANGED
                else (reference_url if reference_url is None else str(reference_url))
            ),
        )

        problems = validate_authored_input(merged)
        if problems:
            raise AuthoredFindingError(problems)

        Plugin(
            plugin_id=plugin_id,
            plugin_name=merged.title.strip(),
            severity_int=merged.severity_int,
            has_metasploit=plugin.has_metasploit,
            cvss3_score=plugin.cvss3_score,
            cvss2_score=plugin.cvss2_score,
            metasploit_names=plugin.metasploit_names,
            cves=_normalized_cves(merged.cves),
            plugin_url=(merged.reference_url or "").strip() or None,
        ).save(c)

        # Rewritten even when only the description changed: it is stored once
        # per host, so every row has to be brought along.
        _write_targets(finding_id, merged.targets, merged.description, c)

    log_info(f"Updated authored finding {plugin_id}")
    return plugin_id


def _load_targets(
    finding_id: int, conn: sqlite3.Connection
) -> tuple[list[tuple[str, Optional[int]]], str]:
    """Read a finding's current targets and description back out.

    The description is shared across the rows, so the first non-empty one is
    the finding's; an edit that changes only the title must not lose it.
    """
    rows = conn.execute(
        """
        SELECT h.scan_target, fah.port_number, fah.plugin_output
        FROM finding_affected_hosts fah
        JOIN hosts h ON h.host_id = fah.host_id
        WHERE fah.finding_id = ?
        ORDER BY fah.rowid
        """,
        (finding_id,),
    ).fetchall()

    targets = [(str(r["scan_target"]), r["port_number"]) for r in rows]
    description = next(
        (str(r["plugin_output"]) for r in rows if r["plugin_output"]), ""
    )
    return targets, description


def authored_scan_path(source: str) -> Path:
    """Directory a tool run against ``source``'s findings writes its output to."""
    return SCANS_ROOT / AUTHORED_SCAN_NAMES[_require_authored_source(source)]
