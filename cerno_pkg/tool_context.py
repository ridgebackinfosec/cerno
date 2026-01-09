"""
Tool Context and Result Types
==============================

Unified data structures for tool workflows and review sessions:
- ToolContext: Standardized parameters passed to all workflow builders
- CommandResult: Standardized return type from all workflow builders
- ReviewContext: Consolidated context for review session operations

This enables clean, generic dispatch without tool-specific parameter passing.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List, TYPE_CHECKING
import types

if TYPE_CHECKING:
    from .models import Plugin, Finding
    from .workflow_mapper import WorkflowMapper


@dataclass
class ToolContext:
    """
    Unified context passed to all tool workflow builders.

    This standardizes the workflow function signature, eliminating tool-specific
    parameter lists in dispatch logic.

    Attributes:
        tcp_ips: Path to TCP IP list file
        udp_ips: Path to UDP IP list file
        tcp_sockets: Path to TCP host:port list file
        ports_str: Comma-separated port list (e.g., "80,443,8080")
        use_sudo: Whether sudo is available for privileged commands
        workdir: Working directory for temporary files
        results_dir: Directory for final results/output
        oabase: Output file base path (for -oA style outputs)
        scan_dir: Scan-level directory
        sev_dir: Severity-level directory
        plugin_url: URL to Nessus plugin details (for metasploit search)
        chosen_file: The selected plugin file being processed
    """

    # Input files
    tcp_ips: Path
    udp_ips: Path
    tcp_sockets: Path

    # Configuration
    ports_str: str
    use_sudo: bool

    # Output paths
    workdir: Path
    results_dir: Path
    oabase: Path
    scan_dir: Path
    sev_dir: Path

    # Optional metadata
    plugin_url: Optional[str] = None
    chosen_file: Optional[Path] = None


@dataclass
class CommandResult:
    """
    Unified return type from tool workflow builders.

    This standardizes what workflows return, eliminating tool-specific
    unpacking logic in dispatch.

    Attributes:
        command: The actual command to execute (list for subprocess, str for shell)
        display_command: Command to show user (may differ from command)
        artifact_note: Human-readable note about where output will be saved
        relay_path: Optional path to relay targets file (netexec-specific)
    """

    command: Union[str, List[str]]
    display_command: Union[str, List[str]]
    artifact_note: str
    relay_path: Optional[Path] = None


@dataclass
class ReviewContext:
    """
    Consolidated context for review session operations.

    Replaces 8-11 parameter function signatures with single context object.
    Passed throughout the review workflow to eliminate parameter duplication.

    Attributes:
        scan_dir: Scan directory path
        scan_id: Database scan ID
        sev_dir: Severity directory (None for MSF/workflow modes)
        finding: Current Finding object (None until file selected)
        plugin: Current Plugin metadata (None until file selected)
        chosen_file: Current file path (None until file selected)
        hosts: List of target hosts for current finding
        ports_str: Comma-separated ports string
        args: CLI arguments namespace
        use_sudo: Whether sudo is available
        workflow_mapper: Workflow mapper for plugin workflows
        skipped_total: Tracking list for skipped findings
        reviewed_total: Tracking list for reviewed findings
        completed_total: Tracking list for completed findings
    """

    # Scan context (required)
    scan_dir: Path
    scan_id: int

    # Severity context (optional - None for MSF/workflow modes)
    sev_dir: Optional[Path] = None

    # Current file/finding (set when file selected)
    finding: Optional["Finding"] = None
    plugin: Optional["Plugin"] = None
    chosen_file: Optional[Path] = None

    # Hosts/ports for current finding
    hosts: List[str] = field(default_factory=list)
    ports_str: str = ""

    # System state
    args: Optional[types.SimpleNamespace] = None
    use_sudo: bool = False
    workflow_mapper: Optional["WorkflowMapper"] = None

    # Statistics tracking
    skipped_total: List[str] = field(default_factory=list)
    reviewed_total: List[str] = field(default_factory=list)
    completed_total: List[str] = field(default_factory=list)
