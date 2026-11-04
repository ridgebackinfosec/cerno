"""Import nuclei results into the database (no files written).

Reads a nuclei ``-je`` / ``-jle`` / ``-jsonl`` export via the pure
:mod:`cerno_pkg.nuclei_parse` parser and writes it into the same normalized
tables the Nessus importer fills, so nuclei findings are reviewable, workflow-
matchable and visible to the TUI and the MCP server with no special cases
downstream.

Two things differ from :mod:`cerno_pkg.nessus_import` and are the reason this
module exists rather than a flag on that one:

* **Plugin identity.** ``plugins`` is global across scans and keyed by
  ``plugin_id``, so a nuclei template id is namespaced (``nuclei:apache-detect``)
  to keep it from colliding with a Nessus plugin number. See
  :data:`cerno_pkg.constants.PLUGIN_ID_PREFIXES`.
* **Evidence merging.** One template routinely matches the same host:port
  several times -- six missing security headers, three detected technologies,
  two TLS versions -- but ``finding_affected_hosts`` has a
  ``UNIQUE (finding_id, host_id, port_number)`` constraint. Those matches are
  merged into a single row's ``plugin_output`` (keeping each sub-match's
  ``matcher-name`` *and* ``extracted-results``), because inserting them
  separately would make ``INSERT OR REPLACE`` keep only the last and silently
  discard the operator's evidence.

Nothing is sanitized on the way in: the database holds exactly what the scanner
reported, and terminal rendering neutralizes it (see
:func:`cerno_pkg.ansi.safe_text`). Unlike ``.nessus`` XML, nuclei JSON can carry
an ESC byte in ``extracted-results``, which is lifted verbatim from response
bodies.
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional

from .ansi import info
from .constants import PLUGIN_ID_PREFIXES, SOURCE_NUCLEI
from .database import compute_file_hash, db_transaction
from .logging_setup import log_error, log_info, log_timing
from .models import Finding, Host, Plugin, Port, Scan, now_iso

# ExportResult is reused verbatim rather than redefined: the CLI and the MCP
# tool handle both importers' results identically, and a second near-identical
# dataclass would be a shape to keep in sync for no benefit.
from .nessus_import import ExportResult, sanitize_filename
from .nuclei_parse import (
    ParsedNucleiMatch,
    ParsedNucleiTemplate,
    format_plugin_output,
    parse_nuclei_file,
)
from .parsing import detect_host_type


def _namespaced_plugin_id(template_id: str) -> str:
    """Return the global ``plugins.plugin_id`` for a nuclei template id."""
    return PLUGIN_ID_PREFIXES[SOURCE_NUCLEI] + template_id


def _unbracket(host: str) -> str:
    """Strip the brackets nuclei puts around a literal IPv6 target."""
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _scan_target_type(host: str) -> str:
    """Map a host to the ``hosts.scan_target_type`` CHECK vocabulary."""
    detected = detect_host_type(_unbracket(host))
    # detect_host_type says 'hostname'; the column's CHECK says 'fqdn'.
    return "fqdn" if detected == "hostname" else detected


def _group_by_target(
    matches: list[ParsedNucleiMatch],
) -> "OrderedDict[tuple[str, str, Optional[int]], list[ParsedNucleiMatch]]":
    """Group a template's matches by the host:port they will be stored against.

    Insertion-ordered so the merged ``plugin_output`` reads in scan order.
    """
    grouped: "OrderedDict[tuple[str, str, Optional[int]], list[ParsedNucleiMatch]]" = (
        OrderedDict()
    )
    for match in matches:
        grouped.setdefault(match.target_key, []).append(match)
    return grouped


@log_timing
def import_nuclei_file(
    nuclei_file: Path,
    output_dir: Path,
    *,
    scan_name: Optional[str] = None,
    min_severity: int = 0,
) -> ExportResult:
    """Import a nuclei JSON/JSONL export into the database.

    Args:
        nuclei_file: Path to a nuclei ``-je`` (JSON array) or ``-jle``/``-jsonl``
            (newline-delimited) results file.
        output_dir: Directory recorded as the scan's ``export_root``. No files
            are written there by this importer.
        scan_name: Scan name to use. Defaults to the file's stem, since nuclei
            output carries no scan name of its own (unlike a ``.nessus``
            ``Report@name``).
        min_severity: Drop templates below this ``severity_int`` (0-4). A real
            ``pentest.yml`` run is dominated by Info findings, so this keeps a
            large scan from flooding the review list.

    Returns:
        An :class:`~cerno_pkg.nessus_import.ExportResult`. ``plugins_exported``
        counts templates (one finding each), ``total_hosts`` counts host:port
        rows written. A missing, empty or malformed file yields a zeroed result
        and writes nothing at all -- not even a scan row.
    """
    resolved_name = scan_name or sanitize_filename(nuclei_file.stem)
    log_info(f"Importing nuclei results from {nuclei_file}")

    parsed = parse_nuclei_file(nuclei_file)
    if parsed.is_empty:
        info("No nuclei results found.")
        return ExportResult(0, 0, resolved_name, {})

    templates = [t for t in parsed.templates if t.severity_int >= min_severity]
    if not templates:
        info(f"No nuclei results at or above severity {min_severity}.")
        return ExportResult(0, 0, resolved_name, {})

    if parsed.skipped_non_matches:
        log_info(
            f"Skipped {parsed.skipped_non_matches} nuclei record(s) with "
            "matcher-status=false (not findings)"
        )
    if parsed.skipped_malformed:
        log_info(f"Skipped {parsed.skipped_malformed} unparsable nuclei record(s)")

    total_hosts = _write_to_database(nuclei_file, resolved_name, output_dir, templates)

    severities: Dict[int, int] = {}
    for template in templates:
        severities[template.severity_int] = severities.get(template.severity_int, 0) + 1

    # Mirror the Nessus importer: invalidate the cached NetExec manager so a
    # scan imported into a live MCP server is visible to nxc enrichment.
    from .nxc_db import reset_nxc_manager

    reset_nxc_manager()

    log_info(
        f"nuclei import complete: {len(templates)} templates, "
        f"{total_hosts} host entries"
    )
    return ExportResult(
        plugins_exported=len(templates),
        total_hosts=total_hosts,
        scan_name=resolved_name,
        severities=severities,
    )


def _write_to_database(
    nuclei_file: Path,
    scan_name: str,
    output_dir: Path,
    templates: list[ParsedNucleiTemplate],
) -> int:
    """Write parsed templates to the database. Returns host:port rows written."""
    try:
        with db_transaction() as conn:
            scan = Scan(
                scan_name=scan_name,
                source_file_path=str(nuclei_file.resolve()),
                source_file_hash=(
                    compute_file_hash(nuclei_file) if nuclei_file.exists() else None
                ),
                export_root=str(output_dir),
                created_at=now_iso(),
            )
            existing = Scan.get_by_name(scan_name, conn)
            if existing:
                scan.scan_id = existing.scan_id
                scan.created_at = existing.created_at
                log_info(f"Updating existing scan: {scan_name}")
            else:
                log_info(f"Creating new scan: {scan_name}")

            scan_id = scan.save(conn)
            if scan_id is None:
                log_error("Failed to save scan - scan_id is None")
                return 0

            if existing:
                # Re-import replaces this scan's findings (cascading to
                # finding_affected_hosts); hosts/ports/plugins are global and
                # accretive, exactly as in the Nessus importer.
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))

            rows_written = 0
            for template in templates:
                plugin_id = _namespaced_plugin_id(template.template_id)
                Plugin(
                    plugin_id=plugin_id,
                    plugin_name=template.template_name,
                    severity_int=template.severity_int,
                    has_metasploit=False,  # nuclei carries no Metasploit data
                    cvss3_score=template.cvss3_score,
                    cvss2_score=template.cvss2_score,
                    metasploit_names=None,
                    cves=template.cves or None,
                    plugin_url=template.template_url,
                ).save(conn)

                finding_id = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
                if finding_id is None:
                    log_error(f"Failed to save finding for {plugin_id}")
                    continue

                for (ip_address, host, port), matches in _group_by_target(
                    template.matches
                ).items():
                    if not host:
                        continue
                    host_id = Host.get_or_create(
                        ip_address=_unbracket(ip_address),
                        scan_target=_unbracket(host),
                        scan_target_type=_scan_target_type(host),
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
                        (finding_id, host_id, port, format_plugin_output(matches)),
                    )
                    rows_written += 1

            log_info(
                f"Database updated: {len(templates)} nuclei templates, "
                f"scan_id={scan_id}"
            )
            return rows_written
    except Exception as exc:
        log_error(f"Failed to write nuclei results to database: {exc}")
        raise
