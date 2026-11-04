"""Workflow mapping system for finding-specific verification workflows."""

from __future__ import annotations

import contextlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional
import yaml

from .ansi import warn
from .constants import SOURCE_UNKNOWN
from .logging_setup import log_debug, log_error
from .parsing import plugin_source

if TYPE_CHECKING:
    from .config import CernoConfig


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
    Represents a complete verification workflow for one or more findings.

    Attributes:
        finding_id: Original finding_id string from YAML (may be comma-separated)
        workflow_name: Human-readable workflow name
        description: Brief description
        steps: List of workflow steps
        references: List of reference URLs
    """

    finding_id: str
    workflow_name: str
    description: str
    steps: list[WorkflowStep]
    references: list[str]


def _parse_workflow_entry(entry: dict, origin: str) -> Optional[Workflow]:
    """Build a :class:`Workflow` from one YAML entry, or None if unusable.

    Enforces both halves of the finding-id contract, warning and skipping
    rather than raising, so one bad entry cannot stop a file from loading:

    * the key must be ``finding_id``; a legacy ``plugin_id`` key is named in
      the warning so the break is self-diagnosing, but it does **not** load;
    * every id in the (optionally comma-separated) value must carry a source
      prefix, because that is what ``plugins.plugin_id`` holds. A bare number
      like ``57608`` can never match a finding, so the entry is rejected whole
      rather than registered under a key nothing will look up.

    Args:
        entry: One mapping from the YAML ``workflows`` list.
        origin: File name, for the warning text.
    """
    finding_id = str(entry.get("finding_id", "") or "").strip()
    name = str(entry.get("workflow_name", "") or "") or "(unnamed)"

    if not finding_id:
        if entry.get("plugin_id"):
            warn(
                f"{origin}: workflow {name!r} uses the removed 'plugin_id' key. "
                f"Rename it to 'finding_id' and prefix each id with its source "
                f"(e.g. 'nessus:57608'). Skipping."
            )
        return None

    refs = [ref.strip() for ref in finding_id.split(",") if ref.strip()]
    unprefixed = [ref for ref in refs if plugin_source(ref) == SOURCE_UNKNOWN]
    if unprefixed:
        warn(
            f"{origin}: workflow {name!r} has finding id(s) with no source "
            f"prefix: {', '.join(unprefixed)}. Use 'nessus:57608' or "
            f"'nuclei:<template-id>'. Skipping."
        )
        return None

    steps = [
        WorkflowStep(
            title=step_data.get("title", ""),
            commands=step_data.get("commands", []),
            notes=step_data.get("notes", ""),
        )
        for step_data in entry.get("steps", [])
    ]

    return Workflow(
        finding_id=finding_id,
        workflow_name=entry.get("workflow_name", ""),
        description=entry.get("description", ""),
        steps=steps,
        references=entry.get("references", []),
    )


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
                workflow = _parse_workflow_entry(workflow_data, self.yaml_path.name)
                if workflow is None:
                    continue

                # Register the workflow under each id it covers, so one entry
                # can serve equivalent findings from different scanners.
                for fid in workflow.finding_id.split(","):
                    fid = fid.strip()
                    if fid:
                        self.workflows[fid] = workflow

        except yaml.YAMLError as e:
            # YAML syntax error - specific handling
            log_error(f"YAML syntax error in {self.yaml_path}: {e}")
            warn(f"Failed to parse workflow YAML: {self.yaml_path.name}")
            warn(
                f"Syntax error: {str(e).splitlines()[0] if str(e) else 'Invalid YAML format'}"
            )
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

    def get_workflow(self, finding_id: str) -> Optional[Workflow]:
        """
        Get workflow for a finding ID.

        Args:
            finding_id: Source-namespaced finding id ('nessus:57608')

        Returns:
            Workflow object if found, None otherwise
        """
        self._check_and_reload()
        return self.workflows.get(finding_id)

    def has_workflow(self, finding_id: str) -> bool:
        """
        Check if workflow exists for finding ID.

        Args:
            finding_id: Source-namespaced finding id ('nessus:57608')

        Returns:
            True if workflow exists, False otherwise
        """
        self._check_and_reload()
        return finding_id in self.workflows

    def get_all_finding_ids(self) -> list[str]:
        """
        Get list of all finding IDs with workflows.

        Returns:
            List of namespaced finding id strings
        """
        return list(self.workflows.keys())

    def count(self) -> int:
        """
        Get count of distinct workflows (not individual plugin ID entries).

        Returns:
            Number of distinct workflows
        """
        return len(self.get_all_workflows())

    def load_additional_workflows(self, yaml_path: Path) -> int:
        """
        Load workflows from an additional YAML file and merge with existing.

        If a finding_id already exists, the new workflow overrides it.

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
                workflow = _parse_workflow_entry(workflow_data, yaml_path.name)
                if workflow is None:
                    continue

                # Register under each id it covers (overrides existing).
                for fid in workflow.finding_id.split(","):
                    fid = fid.strip()
                    if fid:
                        self.workflows[fid] = workflow

                # Count this workflow definition as loaded
                workflows_loaded += 1

        except yaml.YAMLError as e:
            # YAML syntax error - specific handling
            log_error(f"YAML syntax error in {yaml_path}: {e}")
            warn(f"Failed to parse additional workflow YAML: {yaml_path.name}")
            warn(
                f"Syntax error: {str(e).splitlines()[0] if str(e) else 'Invalid YAML format'}"
            )
        except FileNotFoundError:
            # File not found
            log_error(f"Additional workflow file not found: {yaml_path}")
        except Exception as e:
            # Unexpected error
            log_error(
                f"Unexpected error loading additional workflows from {yaml_path}: {e}"
            )
            warn(f"Failed to load additional workflows from {yaml_path.name}")

        return workflows_loaded

    def get_all_workflows(self) -> list[dict[str, str]]:
        """
        Get all workflows as a list of dictionaries.

        Returns:
            List of workflow dictionaries with keys: finding_id, workflow_name, description
        """
        workflows_list = []
        seen_workflows = set()

        for workflow in self.workflows.values():
            # Use workflow_name as unique key to avoid duplicate workflows
            # (same workflow may be registered under multiple finding IDs)
            workflow_key = workflow.workflow_name

            if workflow_key not in seen_workflows:
                workflows_list.append(
                    {
                        "finding_id": workflow.finding_id,
                        "workflow_name": workflow.workflow_name,
                        "description": workflow.description,
                    }
                )
                seen_workflows.add(workflow_key)

        # Sort by workflow name
        workflows_list.sort(key=lambda w: w["workflow_name"])

        return workflows_list


def build_workflow_mapper(config: Optional[CernoConfig] = None) -> WorkflowMapper:
    """Build a mapper of bundled workflows supplemented by ``custom_workflows_path``.

    Mirrors the CLI's supplement mode (``cerno review`` with the config key set):
    bundled ``workflow_mappings.yaml`` first, then the custom file merged on top
    (custom overrides on finding_id conflict). A missing or empty custom file
    leaves the bundled set. Built fresh per call so edits to either YAML are seen.

    Mapper warnings are routed to stderr: this runs inside the MCP server, where
    stdout is the JSON-RPC channel.

    Args:
        config: Config source for ``custom_workflows_path``; loaded when None.

    Returns:
        A populated :class:`WorkflowMapper`.
    """
    if config is None:
        from .config import load_config

        config = load_config()

    with contextlib.redirect_stdout(sys.stderr):
        mapper = WorkflowMapper()
        if config.custom_workflows_path:
            custom = Path(config.custom_workflows_path).expanduser()
            added = mapper.load_additional_workflows(custom)
            log_debug(
                f"workflows: {mapper.count()} total ({added} custom from {custom})"
            )
    return mapper
