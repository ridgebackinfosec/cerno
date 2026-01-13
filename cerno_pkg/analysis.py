"""Data analysis functions for comparing and grouping plugin findings.

This module provides functions to compare host/port combinations across
multiple plugin findings from the database, identify superset relationships,
and generate scan statistics.
"""

import re
from collections import defaultdict
from pathlib import Path
from typing import Union, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .models import Plugin, Finding

from rich import box
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .ansi import header, info, warn, style_if_enabled
from .logging_setup import log_timing
from .parsing import (
    build_item_set,
    normalize_combos,
)
from .render import render_compare_tables
from .ansi import get_console


_console_global = get_console()

@log_timing
def compare_filtered(files: Union[list['Finding'], list[tuple['Finding', 'Plugin']]]) -> list[list[str]]:
    """Compare host/port combinations across multiple findings (database-only).

    Queries database for host/port combinations, computes intersections and unions,
    groups findings with identical host:port combinations, and renders
    comparison tables.

    Args:
        files: List of Finding objects or (Finding, Plugin) tuples to compare

    Returns:
        List of groups where each group is a list of plugin identifiers with
        identical host:port combinations, sorted by group size descending
    """
    if not files:
        warn("No files selected for comparison.")
        return []

    header("Filtered Files: Host/Port Comparison")
    info(f"Files compared: {len(files)}")

    # Detect what type of input we have (database-only)
    from .models import Finding, Plugin
    if files and isinstance(files[0], tuple) and len(files[0]) == 2:
        # (Finding, Plugin) tuples - extract Findings with explicit cast for type narrowing
        tuple_files = cast(list[tuple[Finding, Plugin]], files)
        findings: list[Finding] = [pf for pf, _ in tuple_files]
        plugins_map = {pf.plugin_id: plugin for pf, plugin in tuple_files}
    else:
        # Just Finding objects (need to query plugins separately for display)
        finding_files = cast(list[Finding], files)
        findings = finding_files
        plugins_map = {}  # Will be populated if needed

    parsed = []
    with Progress(
        SpinnerColumn(style=style_if_enabled("cyan")),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Querying findings for comparison...", total=len(files)
        )

        # Database query: fetch all hosts/ports in a single batch
        from .database import db_transaction, query_all

        finding_ids = [pf.finding_id for pf in findings]
        with db_transaction() as conn:
            rows = query_all(
                conn,
                """
                SELECT
                        fah.finding_id,
                        h.host_address,
                        fah.port_number,
                        h.host_type
                    FROM finding_affected_hosts fah
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE fah.finding_id IN ({})
                    ORDER BY
                        fah.finding_id,
                        CASE WHEN h.host_type = 'ipv4' THEN 0
                             WHEN h.host_type = 'ipv6' THEN 1
                             ELSE 2 END,
                        h.host_address ASC
                """.format(','.join('?' * len(finding_ids))),
                tuple(finding_ids)
            )

        # Group results by finding_id
        hosts_by_file = defaultdict(list)
        for row in rows:
            hosts_by_file[row['finding_id']].append(row)

        # Process each Finding
        for pf in findings:
            file_rows = hosts_by_file.get(pf.finding_id, [])

            # Extract hosts and ports from database rows
            hosts = []
            ports_set = set()
            combos = defaultdict(set)
            had_explicit = False

            for row in file_rows:
                host = row['host_address']
                port = row['port_number']

                if host not in hosts:
                    hosts.append(host)
                if port:
                    ports_set.add(port)
                    combos[host].add(port)
                    had_explicit = True

            # Create display identifier from plugin info (not filename)
            if pf.plugin_id in plugins_map:
                plugin = plugins_map[pf.plugin_id]
                display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
            else:
                # Fallback if plugin info not available
                display_name = f"Plugin {pf.plugin_id}"

            parsed.append((display_name, hosts, ports_set, combos, had_explicit))
            progress.advance(task)

    all_host_sets = [set(h) for _, h, _, _, _ in parsed]
    all_port_sets = [set(p) for _, _, p, _, _ in parsed]
    host_intersection = (
        set.intersection(*all_host_sets) if all_host_sets else set()
    )
    host_union = set.union(*all_host_sets) if all_host_sets else set()
    port_intersection = (
        set.intersection(*all_port_sets) if all_port_sets else set()
    )
    port_union = set.union(*all_port_sets) if all_port_sets else set()

    host_signatures = [tuple(sorted(h)) for _, h, _, _, _ in parsed]
    port_signatures = [
        tuple(sorted(p, key=lambda x: int(x))) for _, _, p, _, _ in parsed
    ]
    combo_signatures = [
        normalize_combos(h, p, c, e) for _, h, p, c, e in parsed
    ]

    same_hosts = (
        all(sig == host_signatures[0] for sig in host_signatures)
        if host_signatures
        else True
    )
    same_ports = (
        all(sig == port_signatures[0] for sig in port_signatures)
        if port_signatures
        else True
    )
    same_combos = (
        all(sig == combo_signatures[0] for sig in combo_signatures)
        if combo_signatures
        else True
    )

    groups_dict = defaultdict(list)
    with Progress(
        SpinnerColumn(style=style_if_enabled("cyan")),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Grouping identical host:port combos...", total=len(parsed)
        )
        for (display_name, _h, _p, _c, _e), sig in zip(parsed, combo_signatures):
            groups_dict[sig].append(display_name)
            progress.advance(task)

    with Progress(
        SpinnerColumn(style=style_if_enabled("cyan")),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        progress.add_task("Sorting groups...", start=True)
        groups_sorted = sorted(
            groups_dict.values(), key=lambda names: len(names), reverse=True
        )

    render_compare_tables(
        parsed,
        host_intersection,
        host_union,
        port_intersection,
        port_union,
        same_hosts,
        same_ports,
        same_combos,
        groups_sorted,
    )
    return groups_sorted


@log_timing
def analyze_inclusions(files: Union[list['Finding'], list[tuple['Finding', 'Plugin']]]) -> list[list[str]]:
    """Analyze superset relationships across findings (database-only).

    Identifies which findings are supersets of others (contain all their
    host:port combinations) and groups them accordingly.

    Args:
        files: List of Finding objects or (Finding, Plugin) tuples to analyze

    Returns:
        List of groups where each group is [superset_name, *covered_names],
        representing plugins that are fully covered by the superset
    """
    if not files:
        warn("No files selected for superset analysis.")
        return []

    header("Filtered Files: Overlapping Findings Analysis")
    info(f"Files analyzed: {len(files)}")

    # Detect what type of input we have (database-only)
    from .models import Finding, Plugin
    if files and isinstance(files[0], tuple) and len(files[0]) == 2:
        # (Finding, Plugin) tuples - extract Findings with explicit cast for type narrowing
        tuple_files = cast(list[tuple[Finding, Plugin]], files)
        findings: list[Finding] = [pf for pf, _ in tuple_files]
        plugins_map = {pf.plugin_id: plugin for pf, plugin in tuple_files}
    else:
        # Just Finding objects with explicit cast for type narrowing
        finding_files = cast(list[Finding], files)
        findings = finding_files
        plugins_map = {}

    parsed = []
    item_sets = {}
    with Progress(
        SpinnerColumn(style=style_if_enabled("cyan")),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying findings...", total=len(files))

        # Database query: fetch all hosts/ports in a single batch
        from .database import db_transaction, query_all

        finding_ids = [pf.finding_id for pf in findings]
        with db_transaction() as conn:
            rows = query_all(
                conn,
                """
                SELECT
                        fah.finding_id,
                        h.host_address,
                        fah.port_number,
                        h.host_type
                    FROM finding_affected_hosts fah
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE fah.finding_id IN ({})
                    ORDER BY
                        fah.finding_id,
                        CASE WHEN h.host_type = 'ipv4' THEN 0
                             WHEN h.host_type = 'ipv6' THEN 1
                             ELSE 2 END,
                        h.host_address ASC
                    """.format(','.join('?' * len(finding_ids))),
                tuple(finding_ids)
            )

        # Group results by finding_id
        hosts_by_file = defaultdict(list)
        for row in rows:
            hosts_by_file[row['finding_id']].append(row)

        # Process each Finding
        for pf in findings:
            file_rows = hosts_by_file.get(pf.finding_id, [])

            # Extract hosts and ports from database rows
            hosts = []
            ports_set = set()
            combos = defaultdict(set)
            had_explicit = False

            for row in file_rows:
                host = row['host_address']
                port = row['port_number']

                if host not in hosts:
                    hosts.append(host)
                if port:
                    ports_set.add(port)
                    combos[host].add(port)
                    had_explicit = True

            # Create display identifier from plugin info (not filename)
            if pf.plugin_id in plugins_map:
                plugin = plugins_map[pf.plugin_id]
                display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
            else:
                # Fallback if plugin info not available
                display_name = f"Plugin {pf.plugin_id}"

            parsed.append((display_name, hosts, ports_set, combos, had_explicit))
            item_sets[display_name] = build_item_set(
                hosts, ports_set, combos, had_explicit
            )
            progress.advance(task)

    # Extract display names from parsed results
    display_names = [display_name for display_name, _, _, _, _ in parsed]

    # Build coverage map: for each plugin, which others does it fully include?
    cover_map = {display_name: set() for display_name in display_names}
    for i, name_a in enumerate(display_names):
        items_a = item_sets[name_a]
        for j, name_b in enumerate(display_names):
            if i == j:
                continue
            items_b = item_sets[name_b]
            if items_b.issubset(items_a):
                cover_map[name_a].add(name_b)

    # Maximals = plugins not strictly contained by any other
    maximals = []
    for name_a in display_names:
        items_a = item_sets[name_a]
        if not any(
            (items_a < item_sets[name_b])
            for name_b in display_names
            if name_b is not name_a
        ):
            maximals.append(name_a)

    # Build groups with explicit root (superset) and covered list
    groups = []
    for maximal_file in sorted(
        maximals,
        key=lambda p: (-len(cover_map[p]), natural_key(p)),
    ):
        covered = sorted(
            list(cover_map[maximal_file]), key=lambda p: natural_key(p)
        )
        groups.append((maximal_file, covered))

    if groups:
        groups_table = Table(
            title="Overlapping Findings Groups",
            box=box.SIMPLE,
            show_lines=False,
            pad_edge=False,
        )
        groups_table.add_column("#", justify="right", no_wrap=True)
        groups_table.add_column("Root Finding")
        groups_table.add_column("Covers", justify="right", no_wrap=True)
        groups_table.add_column("Covered findings (sample)")
        for i, (root, covered_list) in enumerate(groups, 1):
            sample_names = covered_list[:8]
            sample = "\n".join(sample_names) + (
                f"\n... (+{len(covered_list)-8} more)"
                if len(covered_list) > 8
                else ""
            )
            groups_table.add_row(
                str(i), root, str(len(covered_list)), sample or "—"
            )
        _console_global.print(groups_table)
    else:
        info(
            "\nNo coverage relationships detected "
            "(all sets are disjoint or mutually incomparable)."
        )

    # Convert back to name groups (root + covered) for filtering behavior
    name_groups = []
    for root, covered_list in groups:
        names = [root] + covered_list
        name_groups.append(names)
    return name_groups


def natural_key(s: str) -> list[int | str]:
    """Generate a natural sort key for alphanumeric strings.

    Splits strings into numeric and non-numeric parts for proper sorting
    (e.g., 'file2' comes before 'file10').

    Args:
        s: String to generate sort key for

    Returns:
        List of integers and lowercase strings for natural sorting
    """
    return [
        int(token) if token.isdigit() else token.lower()
        for token in re.split(r"(\d+)", s)
    ]


def count_reviewed_in_scan(
    scan_dir: Path,
    scan_id: int
) -> tuple[int, int]:
    """Count total and reviewed files in a scan directory (database-only).

    Args:
        scan_dir: Path to the scan directory (unused, kept for API compatibility)
        scan_id: Scan ID for database queries (required)

    Returns:
        Tuple of (total_files, reviewed_files)
    """
    from .models import Finding
    return Finding.count_by_scan(scan_id)
