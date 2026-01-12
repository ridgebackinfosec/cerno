"""Tests for workflow_mapper module."""

import pytest
from pathlib import Path

from cerno_pkg.workflow_mapper import WorkflowMapper


@pytest.fixture
def sample_workflow_yaml(tmp_path: Path) -> Path:
    """Create a sample workflow YAML with comma-separated plugin IDs."""
    yaml_content = """version: "1.0"

workflows:
  - plugin_id: "12345"
    workflow_name: "Test Workflow 1"
    description: "First test workflow"
    steps:
      - title: "Step 1"
        commands:
          - "command1"
        notes: "Note 1"
    references:
      - "https://example.com/1"

  - plugin_id: "67890,11111,22222"
    workflow_name: "Test Workflow 2"
    description: "Second test workflow with comma-separated IDs"
    steps:
      - title: "Step 2"
        commands:
          - "command2"
        notes: "Note 2"
    references:
      - "https://example.com/2"

  - plugin_id: "33333"
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
        workflow_67890 = mapper.get_workflow("67890")
        workflow_11111 = mapper.get_workflow("11111")
        workflow_22222 = mapper.get_workflow("22222")

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
            "Test Workflow 3"
        }

    def test_count_matches_get_all_workflows_length(self, sample_workflow_yaml: Path):
        """Test that count() matches len(get_all_workflows())."""
        mapper = WorkflowMapper(sample_workflow_yaml)

        assert mapper.count() == len(mapper.get_all_workflows())
