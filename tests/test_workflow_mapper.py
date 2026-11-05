"""Tests for workflow_mapper module."""

import pytest
from pathlib import Path

from cerno_pkg.workflow_mapper import WorkflowMapper


@pytest.fixture
def sample_workflow_yaml(tmp_path: Path) -> Path:
    """Create a sample workflow YAML with comma-separated plugin IDs."""
    yaml_content = """version: "1.0"

workflows:
  - finding_id: "nessus:12345"
    workflow_name: "Test Workflow 1"
    description: "First test workflow"
    steps:
      - title: "Step 1"
        commands:
          - "command1"
        notes: "Note 1"
    references:
      - "https://example.com/1"

  - finding_id: "nessus:67890,nessus:11111,nessus:22222"
    workflow_name: "Test Workflow 2"
    description: "Second test workflow with comma-separated IDs"
    steps:
      - title: "Step 2"
        commands:
          - "command2"
        notes: "Note 2"
    references:
      - "https://example.com/2"

  - finding_id: "nessus:33333"
    workflow_name: "Test Workflow 3"
    description: "Third test workflow"
    steps:
      - title: "Step 3"
        commands:
          - "command3"
        notes: "Note 3"
    references:
      - "https://example.com/3"
"""
    yaml_file = tmp_path / "test_workflows.yaml"
    yaml_file.write_text(yaml_content)
    return yaml_file


class TestWorkflowMapper:
    """Tests for WorkflowMapper class."""

    def test_count_with_comma_separated_plugin_ids(self, sample_workflow_yaml: Path):
        """Test that count() returns distinct workflows, not plugin ID entries."""
        mapper = WorkflowMapper(sample_workflow_yaml)

        # Should count 3 distinct workflows, not 6 plugin ID entries
        # Workflow 1: plugin_id "12345" (1 entry)
        # Workflow 2: plugin_id "67890,11111,22222" (3 entries)
        # Workflow 3: plugin_id "33333" (1 entry)
        # Total distinct workflows: 3
        # Total dictionary entries: 5
        assert mapper.count() == 3, "count() should return 3 distinct workflows"

    def test_plugin_id_lookup_with_comma_separated(self, sample_workflow_yaml: Path):
        """Test that each plugin ID in comma-separated list can be looked up."""
        mapper = WorkflowMapper(sample_workflow_yaml)

        # All three IDs from comma-separated list should map to same workflow
        workflow_67890 = mapper.get_workflow("nessus:67890")
        workflow_11111 = mapper.get_workflow("nessus:11111")
        workflow_22222 = mapper.get_workflow("nessus:22222")

        assert workflow_67890 is not None
        assert workflow_11111 is not None
        assert workflow_22222 is not None

        # All should be the same workflow object
        assert workflow_67890.workflow_name == "Test Workflow 2"
        assert workflow_11111.workflow_name == "Test Workflow 2"
        assert workflow_22222.workflow_name == "Test Workflow 2"

    def test_get_all_workflows_deduplication(self, sample_workflow_yaml: Path):
        """Test that get_all_workflows() returns deduplicated list."""
        mapper = WorkflowMapper(sample_workflow_yaml)

        all_workflows = mapper.get_all_workflows()

        # Should return 3 distinct workflows
        assert len(all_workflows) == 3

        # Verify workflow names (get_all_workflows returns list of dicts)
        workflow_names = {w["workflow_name"] for w in all_workflows}
        assert workflow_names == {
            "Test Workflow 1",
            "Test Workflow 2",
            "Test Workflow 3",
        }

    def test_count_matches_get_all_workflows_length(self, sample_workflow_yaml: Path):
        """Test that count() matches len(get_all_workflows())."""
        mapper = WorkflowMapper(sample_workflow_yaml)

        assert mapper.count() == len(mapper.get_all_workflows())


def _write_wf(tmp_path: Path, entry_yaml: str) -> Path:
    """Write a one-entry workflow file from a raw YAML entry body."""
    path = tmp_path / "wf.yaml"
    path.write_text('version: "1.0"\n\nworkflows:\n' + entry_yaml, encoding="utf-8")
    return path


@pytest.mark.unit
class TestFindingIdKeyIsStrict:
    """The YAML key is `finding_id`, and every value must name its source."""

    def test_finding_id_key_loads(self, tmp_path: Path):
        path = _write_wf(
            tmp_path,
            '  - finding_id: "nessus:57608"\n'
            "    workflow_name: W\n"
            "    description: d\n"
            "    steps: []\n"
            "    references: []\n",
        )
        mapper = WorkflowMapper(yaml_path=path)
        assert mapper.get_workflow("nessus:57608") is not None

    def test_legacy_plugin_id_key_does_not_load(self, tmp_path: Path, capsys):
        """A renamed key is a hard break, but it must say so.

        Nothing raises when a workflow fails to load -- it simply never shows
        up in the TUI -- so the warning is the only thing that makes the break
        diagnosable.
        """
        path = _write_wf(
            tmp_path,
            '  - plugin_id: "nessus:57608"\n'
            "    workflow_name: Legacy\n"
            "    description: d\n"
            "    steps: []\n"
            "    references: []\n",
        )
        mapper = WorkflowMapper(yaml_path=path)
        assert mapper.count() == 0
        assert mapper.get_workflow("nessus:57608") is None
        out = capsys.readouterr().out
        assert "plugin_id" in out and "finding_id" in out and "Legacy" in out

    def test_unprefixed_value_does_not_load(self, tmp_path: Path, capsys):
        """A bare number can never match a finding, so it is rejected."""
        path = _write_wf(
            tmp_path,
            '  - finding_id: "57608"\n'
            "    workflow_name: Bare\n"
            "    description: d\n"
            "    steps: []\n"
            "    references: []\n",
        )
        mapper = WorkflowMapper(yaml_path=path)
        assert mapper.count() == 0
        assert mapper.get_workflow("57608") is None
        assert "57608" in capsys.readouterr().out

    def test_one_bad_id_rejects_the_whole_entry(self, tmp_path: Path):
        """Fail closed: a partly-registered entry would be a silent half-match."""
        path = _write_wf(
            tmp_path,
            '  - finding_id: "nessus:57608,90317"\n'
            "    workflow_name: Mixed validity\n"
            "    description: d\n"
            "    steps: []\n"
            "    references: []\n",
        )
        mapper = WorkflowMapper(yaml_path=path)
        assert mapper.get_workflow("nessus:57608") is None
        assert mapper.count() == 0


@pytest.mark.unit
class TestCrossSourceWorkflowEntry:
    """One entry can cover equivalent findings from different scanners."""

    @pytest.fixture
    def mapper(self, tmp_path: Path) -> WorkflowMapper:
        path = _write_wf(
            tmp_path,
            '  - finding_id: "nessus:84502,nuclei:http-missing-security-headers"\n'
            "    workflow_name: Missing Security Headers\n"
            "    description: d\n"
            "    steps:\n"
            "      - title: Check\n"
            '        commands: ["curl -skI https://<TARGET>:<PORT>/"]\n'
            "        notes: ''\n"
            "    references: []\n",
        )
        return WorkflowMapper(yaml_path=path)

    def test_retrievable_by_either_source(self, mapper: WorkflowMapper):
        nessus = mapper.get_workflow("nessus:84502")
        nuclei = mapper.get_workflow("nuclei:http-missing-security-headers")
        assert nessus is not None and nuclei is not None
        assert nessus is nuclei, "both ids must resolve to the same workflow"

    def test_counts_as_one_workflow(self, mapper: WorkflowMapper):
        assert mapper.count() == 1
        assert set(mapper.get_all_finding_ids()) == {
            "nessus:84502",
            "nuclei:http-missing-security-headers",
        }

    def test_multi_id_value_is_kept_intact(self, mapper: WorkflowMapper):
        """The value round-trips, so `workflow list` shows every covered id."""
        wf = mapper.get_workflow("nessus:84502")
        assert wf is not None
        assert wf.finding_id == "nessus:84502,nuclei:http-missing-security-headers"


@pytest.mark.unit
def test_bundled_yaml_ships_a_cross_source_entry():
    """The shipped mappings must prove the cross-source key actually works."""
    mapper = WorkflowMapper()
    nessus = mapper.get_workflow("nessus:84502")
    nuclei = mapper.get_workflow("nuclei:http-missing-security-headers")
    assert nessus is not None and nuclei is not None and nessus is nuclei


@pytest.mark.unit
def test_documented_yaml_examples_still_load(tmp_path: Path):
    """Every complete example in docs/CUSTOM_WORKFLOWS.md must load.

    The loader is strict about the `finding_id` key and its source prefixes, so
    a doc example written against the old format would teach a format that
    silently produces no workflows. Nothing else catches that drift.
    """
    import re

    import yaml

    doc = (Path(__file__).parent.parent / "docs" / "CUSTOM_WORKFLOWS.md").read_text()
    checked = 0
    for block in re.findall(r"```yaml\n(.*?)```", doc, re.S):
        # Skip fragments and the deliberate "don't do this" examples.
        if "finding_id" not in block or "❌" in block:
            continue
        data = yaml.safe_load(block)
        if not isinstance(data, dict) or "workflows" not in data:
            continue
        path = tmp_path / f"doc-{checked}.yaml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        mapper = WorkflowMapper(yaml_path=path)
        assert mapper.count() == len(data["workflows"]), (
            f"a documented example did not load: "
            f"{[w.get('finding_id') for w in data['workflows']]}"
        )
        checked += 1
    assert checked >= 5, f"expected several complete examples, found {checked}"


@pytest.mark.integration
def test_workflow_list_keeps_every_column_readable(capsys, monkeypatch):
    """A long multi-finding id must not squeeze out the name and description.

    Namespacing every id pushed the longest bundled value to ~160 characters.
    With the id column set to no_wrap that consumed the whole terminal width
    and left the Workflow Name and Description columns rendering at zero width
    — a table with nothing readable in it.
    """
    monkeypatch.setenv("COLUMNS", "120")

    from cerno import workflow_list

    workflow_list(custom_workflows=None)
    out = capsys.readouterr().out

    assert "Finding ID(s)" in out and "Workflow Name" in out
    # The cross-source entry is present and its name is actually rendered.
    assert "nuclei:" in out
    assert (
        "HSTS Missing From HTTPS Server" in out.replace("\n", " ").replace("  ", " ")
        or "HSTS Missing From HTTPS" in out
    )
    # Several distinct workflow names must be visible, not just borders.
    assert "ICMP Timestamp" in out
