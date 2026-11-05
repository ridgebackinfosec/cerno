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


def _link(conn, scan_id: int, ref: int, hosts: list[str]) -> None:
    """Create finding for plugin in scan and link the given hosts to it.

    Takes the bare Nessus reference and namespaces it the way the importer
    does, so the stored id is ``nessus:<ref>`` while the plugin name stays
    derived from the source-native number.
    """
    plugin_id = f"nessus:{ref}"
    Plugin(plugin_id=plugin_id, plugin_name=f"P{ref}", severity_int=2).save(conn)
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
        assert {"Finding nessus:100: P100", "Finding nessus:200: P200"} in group_sets
        assert {"Finding nessus:300: P300"} in group_sets


@pytest.mark.integration
class TestAnalyzeInclusionsMultiScan:
    """analyze_inclusions() must use the cross-scan union of hosts."""

    def test_superset_uses_union_of_scans(self, temp_db, merged_candidates):
        groups = analyze_inclusions(merged_candidates, conn=temp_db)
        # 100 and 200 are both {X, Y}: each covers the other and 300
        roots = {g[0]: set(g[1:]) for g in groups}
        assert "Finding nessus:100: P100" in roots
        assert roots["Finding nessus:100: P100"] == {
            "Finding nessus:200: P200",
            "Finding nessus:300: P300",
        }


@pytest.mark.integration
class TestAggregateHostPortsMultiScan:
    """[V] aggregate host view must include hosts from all selected scans."""

    def test_includes_secondary_scan_hosts(self, temp_db, merged_candidates):
        rep_100 = [(f, p) for f, p in merged_candidates if p.plugin_id == "nessus:100"]
        host_ports, _ = _collect_aggregate_host_ports(rep_100, temp_db)
        assert set(host_ports) == {HOST_X, HOST_Y}


@pytest.mark.integration
class TestGroupFilterRoundTrip:
    """The group filter is a string-identity contract between two producers.

    `compare_filtered` / `analyze_inclusions` return groups as *lists of label
    strings*, and `tui.filter_finding_candidates` re-derives the label from the
    Plugin row and tests set membership. If the two formats ever diverge the
    filter matches nothing, with the "[ACTIVE FILTER] Group #N" footer still
    showing and no error raised anywhere -- so only an end-to-end test catches
    it. Both sides now call `fs.finding_label`; this proves they agree.
    """

    def test_compare_group_actually_filters(self, temp_db, merged_candidates):
        from cerno_pkg.tui import filter_finding_candidates

        with patch("cerno_pkg.analysis.render_compare_tables"):
            groups = compare_filtered(merged_candidates, conn=temp_db)
        assert groups, "need at least one group to exercise the contract"

        for index, group in enumerate(groups, 1):
            group_filter = (index, set(group), "desc")
            matched = filter_finding_candidates(
                merged_candidates, "", group_filter, None
            )
            assert matched, (
                f"group #{index} matched zero findings: the label built by "
                f"analysis.py and the one rebuilt by tui.py have diverged "
                f"({sorted(group)!r})"
            )
            assert len(matched) == len(group)

    def test_overlap_group_actually_filters(self, temp_db, merged_candidates):
        from cerno_pkg.tui import filter_finding_candidates

        groups = analyze_inclusions(merged_candidates, conn=temp_db)
        assert groups
        for index, group in enumerate(groups, 1):
            matched = filter_finding_candidates(
                merged_candidates, "", (index, set(group), "desc"), None
            )
            assert matched, f"overlap group #{index} matched zero findings"

    def test_label_format_is_defined_in_one_place(self, temp_db, merged_candidates):
        """A direct check that the helper is what both sides use."""
        from cerno_pkg.fs import finding_label

        with patch("cerno_pkg.analysis.render_compare_tables"):
            groups = compare_filtered(merged_candidates, conn=temp_db)
        produced = {label for group in groups for label in group}
        expected = {finding_label(f, p) for f, p in merged_candidates}
        assert produced == expected
