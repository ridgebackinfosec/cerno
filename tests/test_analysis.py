"""Tests for cerno_pkg.analysis host comparison and overlap analysis.

Focuses on multi-scan correctness: merged (representative) findings must
include hosts from every selected scan, not just the lowest scan_id.
"""

from unittest.mock import patch

import pytest

from cerno_pkg.analysis import analyze_inclusions, compare_filtered
from cerno_pkg.models import Finding, Host, Plugin, Scan
from cerno_pkg.render import _collect_aggregate_host_ports

HOST_X = "10.0.0.1"
HOST_Y = "10.0.0.2"


def _link(conn, scan_id: int, plugin_id: int, hosts: list[str]) -> None:
    """Create finding for plugin in scan and link the given hosts to it."""
    Plugin(plugin_id=plugin_id, plugin_name=f"P{plugin_id}", severity_int=2).save(conn)
    finding_id = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
    for ip in hosts:
        host_id = Host.get_or_create(
            ip_address=ip, scan_target=ip, scan_target_type="ipv4", conn=conn
        )
        conn.execute(
            "INSERT OR IGNORE INTO finding_affected_hosts "
            "(finding_id, host_id, port_number, plugin_output) VALUES (?, ?, NULL, 'x')",
            (finding_id, host_id),
        )


@pytest.fixture
def merged_candidates(temp_db):
    """Two scans merged.

    - Plugin 100: host X in scan A, host Y in scan B  -> union {X, Y}
    - Plugin 200: hosts X and Y in scan A             -> {X, Y}
    - Plugin 300: host X in scan A                    -> {X}
    """
    a = Scan(scan_name="scan_a", export_root="/tmp").save(temp_db)
    b = Scan(scan_name="scan_b", export_root="/tmp").save(temp_db)
    _link(temp_db, a, 100, [HOST_X])
    _link(temp_db, b, 100, [HOST_Y])
    _link(temp_db, a, 200, [HOST_X, HOST_Y])
    _link(temp_db, a, 300, [HOST_X])
    temp_db.commit()
    display_list, _ = Finding.get_by_scan_ids_merged(scan_ids=[a, b], conn=temp_db)
    return display_list


@pytest.mark.integration
class TestCompareFilteredMultiScan:
    """compare_filtered() must use the cross-scan union of hosts."""

    def test_groups_use_union_of_scans(self, temp_db, merged_candidates):
        with patch("cerno_pkg.analysis.render_compare_tables"):
            groups = compare_filtered(merged_candidates, conn=temp_db)
        group_sets = [set(g) for g in groups]
        assert {"Plugin 100: P100", "Plugin 200: P200"} in group_sets
        assert {"Plugin 300: P300"} in group_sets


@pytest.mark.integration
class TestAnalyzeInclusionsMultiScan:
    """analyze_inclusions() must use the cross-scan union of hosts."""

    def test_superset_uses_union_of_scans(self, temp_db, merged_candidates):
        groups = analyze_inclusions(merged_candidates, conn=temp_db)
        # 100 and 200 are both {X, Y}: each covers the other and 300
        roots = {g[0]: set(g[1:]) for g in groups}
        assert "Plugin 100: P100" in roots
        assert roots["Plugin 100: P100"] == {"Plugin 200: P200", "Plugin 300: P300"}


@pytest.mark.integration
class TestAggregateHostPortsMultiScan:
    """[V] aggregate host view must include hosts from all selected scans."""

    def test_includes_secondary_scan_hosts(self, temp_db, merged_candidates):
        rep_100 = [(f, p) for f, p in merged_candidates if p.plugin_id == 100]
        host_ports, _ = _collect_aggregate_host_ports(rep_100, temp_db)
        assert set(host_ports) == {HOST_X, HOST_Y}
