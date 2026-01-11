"""Workflow mapping system for plugin-specific verification workflows."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import yaml

from .ansi import warn
from .logging_setup import log_error


@dataclass
class WorkflowStep:
    """
    Represents a single step in a verification workflow.

    Attributes:
        title: Step title/description
        commands: List of commands to execute
        notes: Additional notes or guidance
    """

    title: str
    commands: list[str]
    notes: str


@dataclass
class Workflow:
    """
    Represents a complete verification workflow for plugin(s).

    Attributes:
        plugin_id: Original plugin_id string from YAML (may be comma-separated)
        workflow_name: Human-readable workflow name
        description: Brief description
        steps: List of workflow steps
        references: List of reference URLs
    """

    plugin_id: str
    workflow_name: str
    description: str
    steps: list[WorkflowStep]
    references: list[str]


class WorkflowMapper:
    """
    Manages workflow mappings from YAML configuration.
    """

    def __init__(self, yaml_path: Optional[Path] = None) -> None:
        """
        Initialize workflow mapper.

        Args:
            yaml_path: Path to workflow mappings YAML file.
                       If None, uses default workflow_mappings.yaml from package or repo root.
        """
        if yaml_path is None:
            yaml_path = self._find_default_yaml()

        self.yaml_path = yaml_path
        self.workflows: dict[str, Workflow] = {}
        self._last_mtime: Optional[float] = None
        self._load_workflows()

    def _find_default_yaml(self) -> Path:
        """
        Find default workflow_mappings.yaml file.

        Checks in order:
        1. Package directory (for pipx/pip install)
        2. Repository root (for git clone + direct execution)

        Returns:
            Path to workflow_mappings.yaml (may not exist)
        """
        # Try package directory first (pipx install case)
        package_yaml = Path(__file__).parent / "workflow_mappings.yaml"
        if package_yaml.exists():
            return package_yaml

        # Fallback to repo root (git clone case)
        repo_root_yaml = Path(__file__).parent.parent / "workflow_mappings.yaml"
        return repo_root_yaml

    def _load_workflows(self) -> None:
        """Load workflows from YAML file."""
        if not self.yaml_path.exists():
            # No workflow file - mapper will be empty
            self._last_mtime = None
            return

        try:
            # Update modification time
            self._last_mtime = self.yaml_path.stat().st_mtime

            with open(self.yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "workflows" not in data:
                return

            # Clear existing workflows before loading
            self.workflows.clear()

            for workflow_data in data["workflows"]:
                plugin_id = str(workflow_data.get("plugin_id", ""))
                if not plugin_id:
                    continue

                steps = []
                for step_data in workflow_data.get("steps", []):
                    step = WorkflowStep(
                        title=step_data.get("title", ""),
                        commands=step_data.get("commands", []),
                        notes=step_data.get("notes", ""),
                    )
                    steps.append(step)

                workflow = Workflow(
                    plugin_id=plugin_id,
                    workflow_name=workflow_data.get("workflow_name", ""),
                    description=workflow_data.get("description", ""),
                    steps=steps,
                    references=workflow_data.get("references", []),
                )

                # Split by comma and register workflow for each ID
                plugin_ids = [id.strip() for id in plugin_id.split(",")]
                for pid in plugin_ids:
                    if pid:  # Skip empty strings
                        self.workflows[pid] = workflow

        except yaml.YAMLError as e:
            # YAML syntax error - specific handling
            log_error(f"YAML syntax error in {self.yaml_path}: {e}")
            warn(f"Failed to parse workflow YAML: {self.yaml_path.name}")
            warn(f"Syntax error: {str(e).splitlines()[0] if str(e) else 'Invalid YAML format'}")
            warn("Please check YAML syntax and try again.")
        except FileNotFoundError:
            # File not found - this is OK, just means no workflows
            log_error(f"Workflow file not found: {self.yaml_path}")
        except Exception as e:
            # Unexpected error
            log_error(f"Unexpected error loading workflows from {self.yaml_path}: {e}")
            warn(f"Failed to load workflows from {self.yaml_path.name}")

    def _check_and_reload(self) -> None:
        """Check if YAML file has been modified and reload if necessary."""
        if not self.yaml_path.exists():
            # File was deleted - clear workflows
            if self.workflows:
                self.workflows.clear()
                self._last_mtime = None
            return

        try:
            current_mtime = self.yaml_path.stat().st_mtime

            # Reload if file modified or never loaded
            if self._last_mtime is None or current_mtime > self._last_mtime:
                self._load_workflows()

        except Exception as e:
            # Failed to check mtime - log but don't crash
            log_error(f"Failed to check modification time for {self.yaml_path}: {e}")

    def get_workflow(self, plugin_id: str) -> Optional[Workflow]:
        """
        Get workflow for a plugin ID.

        Args:
            plugin_id: Nessus plugin ID

        Returns:
            Workflow object if found, None otherwise
        """
        self._check_and_reload()
        return self.workflows.get(plugin_id)

    def has_workflow(self, plugin_id: str) -> bool:
        """
        Check if workflow exists for plugin ID.

        Args:
            plugin_id: Nessus plugin ID

        Returns:
            True if workflow exists, False otherwise
        """
        self._check_and_reload()
        return plugin_id in self.workflows

    def get_all_plugin_ids(self) -> list[str]:
        """
        Get list of all plugin IDs with workflows.

        Returns:
            List of plugin ID strings
        """
        return list(self.workflows.keys())

    def count(self) -> int:
        """
        Get count of loaded workflows.

        Returns:
            Number of workflows
        """
        return len(self.workflows)

    def load_additional_workflows(self, yaml_path: Path) -> int:
        """
        Load workflows from an additional YAML file and merge with existing.

        If a plugin_id already exists, the new workflow overrides it.

        Args:
            yaml_path: Path to additional workflow YAML file

        Returns:
            Number of workflow definitions loaded from the additional file
        """
        if not yaml_path.exists():
            return 0

        workflows_loaded = 0

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "workflows" not in data:
                return 0

            for workflow_data in data["workflows"]:
                plugin_id = str(workflow_data.get("plugin_id", ""))
                if not plugin_id:
                    continue

                steps = []
                for step_data in workflow_data.get("steps", []):
                    step = WorkflowStep(
                        title=step_data.get("title", ""),
                        commands=step_data.get("commands", []),
                        notes=step_data.get("notes", ""),
                    )
                    steps.append(step)

                workflow = Workflow(
                    plugin_id=plugin_id,
                    workflow_name=workflow_data.get("workflow_name", ""),
                    description=workflow_data.get("description", ""),
                    steps=steps,
                    references=workflow_data.get("references", []),
                )

                # Split by comma and register workflow for each ID (overrides existing)
                plugin_ids = [id.strip() for id in plugin_id.split(",")]
                for pid in plugin_ids:
                    if pid:
                        self.workflows[pid] = workflow

                # Count this workflow definition as loaded
                workflows_loaded += 1

        except yaml.YAMLError as e:
            # YAML syntax error - specific handling
            log_error(f"YAML syntax error in {yaml_path}: {e}")
            warn(f"Failed to parse additional workflow YAML: {yaml_path.name}")
            warn(f"Syntax error: {str(e).splitlines()[0] if str(e) else 'Invalid YAML format'}")
        except FileNotFoundError:
            # File not found
            log_error(f"Additional workflow file not found: {yaml_path}")
        except Exception as e:
            # Unexpected error
            log_error(f"Unexpected error loading additional workflows from {yaml_path}: {e}")
            warn(f"Failed to load additional workflows from {yaml_path.name}")

        return workflows_loaded

    def get_all_workflows(self) -> list[dict[str, str]]:
        """
        Get all workflows as a list of dictionaries.

        Returns:
            List of workflow dictionaries with keys: plugin_id, workflow_name, description
        """
        workflows_list = []
        seen_workflows = set()

        for workflow in self.workflows.values():
            # Use workflow_name as unique key to avoid duplicate workflows
            # (same workflow may be registered under multiple plugin IDs)
            workflow_key = workflow.workflow_name

            if workflow_key not in seen_workflows:
                workflows_list.append({
                    "plugin_id": workflow.plugin_id,
                    "workflow_name": workflow.workflow_name,
                    "description": workflow.description,
                })
                seen_workflows.add(workflow_key)

        # Sort by workflow name
        workflows_list.sort(key=lambda w: w["workflow_name"])

        return workflows_list
