"""Import Burp Suite XML reports into the database (no files written).

Reads a PortSwigger Burp Suite "Report issues" XML export via the pure
:mod:`cerno_pkg.burp_parse` parser and writes it into the same normalized tables
the Nessus and nuclei importers fill, so Burp findings are reviewable,
workflow-matchable, verdict-recordable and visible to the TUI and the MCP server
with no special cases downstream.

Two things make this a module rather than a flag on another importer, and they
are the same two that justify :mod:`cerno_pkg.nuclei_import`:

* **Plugin identity.** ``plugins`` is global across scans and keyed by
  ``plugin_id``, so a Burp issue type is namespaced (``burp:00200300``) to keep
  it from colliding with a Nessus plugin number or a nuclei template id. See
  :data:`cerno_pkg.constants.PLUGIN_ID_PREFIXES`, and
  :func:`cerno_pkg.burp_parse.type_to_ref` for why the ref is hex.
* **Evidence merging.** One issue type routinely fires on many parameters of
  the same host:port, but ``finding_affected_hosts`` has a
  ``UNIQUE (finding_id, host_id, port_number)`` constraint. Those instances are
  merged into a single row's ``plugin_output``, because inserting them
  separately would make ``INSERT OR REPLACE`` keep only the last and silently
  discard the operator's evidence.

Nothing is sanitized on the way in: the database holds exactly what the scanner
reported, and terminal rendering neutralizes it (see
:func:`cerno_pkg.ansi.safe_text`). A Burp response body is lifted verbatim from
a live target, so it will contain Rich markup and may contain ESC bytes.
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional

from .ansi import info
from .burp_parse import (
    ParsedBurpInstance,
    ParsedBurpIssue,
    format_plugin_output,
    parse_burp_file,
)
from .constants import PLUGIN_ID_PREFIXES, SOURCE_BURP
from .database import compute_file_hash, db_transaction
from .logging_setup import log_error, log_info, log_timing
from .models import Finding, Host, Plugin, Port, Scan, now_iso

# ExportResult is reused verbatim rather than redefined: the CLI and the MCP
# tool handle every importer's result identically, and a third near-identical
# dataclass would be a shape to keep in sync for no benefit.
from .nessus_import import ExportResult, sanitize_filename
from .parsing import prefer_service, scan_target_type, unbracket


def _namespaced_plugin_id(type_ref: str) -> str:
    """Return the global ``plugins.plugin_id`` for a Burp issue type ref."""
    return PLUGIN_ID_PREFIXES[SOURCE_BURP] + type_ref


def _group_by_target(
    instances: list[ParsedBurpInstance],
) -> "OrderedDict[tuple[str, str, Optional[int]], list[ParsedBurpInstance]]":
    """Group an issue's instances by the host:port they will be stored against.

    Insertion-ordered so the merged ``plugin_output`` reads in report order.
    """
    grouped: "OrderedDict[tuple[str, str, Optional[int]], list[ParsedBurpInstance]]" = (
        OrderedDict()
    )
    for instance in instances:
        grouped.setdefault(instance.target_key, []).append(instance)
    return grouped


@log_timing
def import_burp_file(
    burp_file: Path,
    output_dir: Path,
    *,
    scan_name: Optional[str] = None,
    min_severity: int = 0,
) -> ExportResult:
    """Import a Burp Suite XML report into the database.

    Args:
        burp_file: Path to a Burp "Report issues" XML export.
        output_dir: Directory recorded as the scan's ``export_root``. No files
            are written there by this importer.
        scan_name: Scan name to use. Defaults to the file's stem, since a Burp
            report carries no scan name of its own (unlike a ``.nessus``
            ``Report@name``).
        min_severity: Drop issue types below this ``severity_int`` (0-4). Burp
            tops out at High (3), so a floor of 4 drops everything.

    Returns:
        An :class:`~cerno_pkg.nessus_import.ExportResult`. ``plugins_exported``
        counts issue types (one finding each), ``total_hosts`` counts host:port
        rows written. A missing, empty, malformed or non-Burp file yields a
        zeroed result and writes nothing at all -- not even a scan row.
    """
    resolved_name = scan_name or sanitize_filename(burp_file.stem)
    log_info(f"Importing Burp report from {burp_file}")

    parsed = parse_burp_file(burp_file)
    if parsed.wrong_format:
        info(f"{burp_file.name} is not a Burp Suite XML report.")
        return ExportResult(0, 0, resolved_name, {})
    if parsed.is_empty:
        info("No Burp issues found.")
        return ExportResult(0, 0, resolved_name, {})

    issues = [i for i in parsed.issues if i.severity_int >= min_severity]
    if not issues:
        info(f"No Burp issues at or above severity {min_severity}.")
        return ExportResult(0, 0, resolved_name, {})

    if parsed.skipped_false_positives:
        log_info(
            f"Skipped {parsed.skipped_false_positives} Burp issue(s) the tester "
            "marked as false positives"
        )
    if parsed.skipped_malformed:
        log_info(
            f"Skipped {parsed.skipped_malformed} Burp issue(s) with no usable type"
        )

    total_hosts = _write_to_database(burp_file, resolved_name, output_dir, issues)

    severities: Dict[int, int] = {}
    for issue in issues:
        severities[issue.severity_int] = severities.get(issue.severity_int, 0) + 1

    # Mirror the other importers: invalidate the cached NetExec manager so a
    # scan imported into a live MCP server is visible to nxc enrichment.
    from .nxc_db import reset_nxc_manager

    reset_nxc_manager()

    log_info(
        f"Burp import complete: {len(issues)} issue types, {total_hosts} host entries"
    )
    return ExportResult(
        plugins_exported=len(issues),
        total_hosts=total_hosts,
        scan_name=resolved_name,
        severities=severities,
    )


def _write_to_database(
    burp_file: Path,
    scan_name: str,
    output_dir: Path,
    issues: list[ParsedBurpIssue],
) -> int:
    """Write parsed issues to the database. Returns host:port rows written."""
    try:
        with db_transaction() as conn:
            scan = Scan(
                scan_name=scan_name,
                source_file_path=str(burp_file.resolve()),
                source_file_hash=(
                    compute_file_hash(burp_file) if burp_file.exists() else None
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
                # accretive, exactly as in the other importers.
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                # host_services has no FK to findings, so it does not cascade;
                # clear it explicitly or a re-import leaves stale services behind.
                conn.execute("DELETE FROM host_services WHERE scan_id = ?", (scan_id,))

            # host_services is UNIQUE(scan_id, host_id, port_number, protocol),
            # so one service wins per host:port. Collected while walking the
            # instances and inserted once at the end.
            service_records: Dict[tuple[int, int, str], str] = {}
            rows_written = 0
            for issue in issues:
                plugin_id = _namespaced_plugin_id(issue.type_ref)
                Plugin(
                    plugin_id=plugin_id,
                    plugin_name=issue.name,
                    severity_int=issue.severity_int,
                    has_metasploit=False,  # Burp carries no Metasploit data
                    cvss3_score=None,  # nor a CVSS score
                    cvss2_score=None,
                    metasploit_names=None,
                    cves=issue.cves or None,
                    plugin_url=issue.url,
                ).save(conn)

                finding_id = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
                if finding_id is None:
                    log_error(f"Failed to save finding for {plugin_id}")
                    continue

                for (ip_address, host, port), instances in _group_by_target(
                    issue.instances
                ).items():
                    if not host:
                        continue
                    host_id = Host.get_or_create(
                        ip_address=unbracket(ip_address),
                        scan_target=unbracket(host),
                        scan_target_type=scan_target_type(host),
                        conn=conn,
                    )
                    if port is not None:
                        Port.get_or_create(port, conn=conn)
                        # Record the service behind this host:port. Without
                        # this a Burp-only scan reports no web services at all,
                        # so get_web_targets, list_services,
                        # FindingQuery.service and the scan/{id}/hosts resource
                        # all come back empty -- and a web-app engagement may
                        # import nothing but a Burp report.
                        for instance in instances:
                            svc_name = instance.service_name
                            if svc_name:
                                key = (host_id, port, "tcp")
                                service_records[key] = prefer_service(
                                    service_records.get(key), svc_name
                                )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO finding_affected_hosts (
                            finding_id, host_id, port_number, plugin_output
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (finding_id, host_id, port, format_plugin_output(instances)),
                    )
                    rows_written += 1

            if service_records:
                conn.executemany(
                    """INSERT OR IGNORE INTO host_services
                       (scan_id, host_id, port_number, protocol, svc_name)
                       VALUES (?, ?, ?, ?, ?)""",
                    [
                        (scan_id, host_id, port, protocol, svc_name)
                        for (host_id, port, protocol), svc_name in sorted(
                            service_records.items()
                        )
                    ],
                )
                log_info(f"Inserting {len(service_records)} service mappings...")

            log_info(
                f"Database updated: {len(issues)} Burp issue types, scan_id={scan_id}"
            )
            return rows_written
    except Exception as exc:
        log_error(f"Failed to write Burp results to database: {exc}")
        raise
