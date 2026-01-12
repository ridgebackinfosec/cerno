
"""Internal package for the cerno CLI (split from monolithic script)."""

# Explicit public API declaration
__all__ = [
    # Version
    "__version__",
    # ANSI module
    "C", "header", "ok", "warn", "err", "info", "fmt_action", "fmt_reviewed",
    "cyan_label", "colorize_severity_label", "breadcrumb", "initialize_colors",
    "get_no_color", "style_if_enabled",
    # Banner module
    "display_banner",
    # Constants module
    "get_results_root", "reset_results_root_cache", "SCANS_ROOT", "REVIEW_PREFIX",
    "PLUGIN_DETAILS_BASE", "NETEXEC_PROTOCOLS", "NSE_PROFILES", "HNAME_RE",
    "MAX_FILE_BYTES", "DEFAULT_TOP_PORTS", "SAMPLE_THRESHOLD", "VISIBLE_GROUPS",
    "PROCESS_TERMINATE_TIMEOUT", "SEARCH_WINDOW_SIZE", "MIN_TERM_LENGTH",
    "validate_results_root",
    # Logging module
    "setup_logging", "log_info", "log_error",
    # Ops module
    "require_cmd", "resolve_cmd", "root_or_sudo_available", "get_tool_version",
    "run_command_with_progress", "ExecutionMetadata", "log_tool_execution",
    "log_artifact", "log_artifacts_for_nmap",
    # Parsing module
    "is_ipv6", "is_ipv4", "is_valid_token", "build_item_set", "normalize_combos",
    "split_host_port", "parse_hosts_ports", "is_hostname",
    "extract_plugin_id_from_filename", "group_findings_by_workflow",
    # Render module
    "render_scan_table", "render_severity_table", "render_finding_list_table",
    "render_compare_tables", "render_actions_footer", "show_actions_help",
    "render_tool_availability_table",
    "show_reviewed_help", "menu_pager", "severity_cell", "severity_style",
    "print_action_menu", "file_raw_payload_text", "file_raw_paged_text",
    "grouped_payload_text", "grouped_paged_text", "hosts_only_payload_text",
    "hosts_only_paged_text", "build_plugin_output_details", "display_finding_preview",
    "page_text", "bulk_extract_cves_for_plugins", "bulk_extract_cves_for_findings",
    "display_bulk_cve_results", "color_unreviewed",
    # FS module
    "build_results_paths", "mark_review_complete", "undo_review_complete",
    "default_page_size", "pretty_severity_label", "write_work_files",
    "display_workflow", "handle_finding_view", "process_single_finding",
    # Tools module
    "build_nmap_cmd", "build_netexec_cmd", "choose_tool", "choose_netexec_protocol",
    "custom_command_help", "render_placeholders", "command_review_menu",
    "copy_to_clipboard", "choose_nse_profile", "run_tool_workflow",
    # TUI module
    "parse_severity_selection", "choose_from_list", "handle_finding_list_actions",
    # Analysis module
    "compare_filtered", "analyze_inclusions", "natural_key", "count_reviewed_in_scan",
    # Tool registry module
    "Tool", "TOOL_REGISTRY", "get_tool", "get_available_tools",
    "get_tool_by_menu_index", "get_tool_count", "register_tool",
    # Tool context module
    "ToolContext", "CommandResult", "ReviewContext",
    # Session module
    "SessionState", "save_session", "load_session", "delete_session", "show_scan_summary",
    # Workflow mapper module
    "Workflow", "WorkflowStep", "WorkflowMapper",
    # Config module
    "CernoConfig", "load_config", "save_config", "get_config_path", "create_example_config",
    # Nessus import module
    "import_nessus_file", "ExportResult",
    # Enums module
    "DisplayFormat", "ViewFormat", "SortMode",
    # Database module
    "get_database_path", "get_connection", "db_transaction", "initialize_database",
    "DATABASE_PATH",
    # Models module
    "Scan", "Plugin", "Finding", "ToolExecution", "Artifact",
]

from ._version import __version__
from .ansi import C, header, ok, warn, err, info, fmt_action, fmt_reviewed, cyan_label, colorize_severity_label, breadcrumb, initialize_colors, get_no_color, style_if_enabled
from .banner import display_banner
from .constants import (
    get_results_root, reset_results_root_cache, SCANS_ROOT, REVIEW_PREFIX,
    PLUGIN_DETAILS_BASE, NETEXEC_PROTOCOLS,
    NSE_PROFILES, HNAME_RE,
    MAX_FILE_BYTES, DEFAULT_TOP_PORTS,
    SAMPLE_THRESHOLD, VISIBLE_GROUPS,
    PROCESS_TERMINATE_TIMEOUT,
    SEARCH_WINDOW_SIZE, MIN_TERM_LENGTH,
    validate_results_root,
)
from .logging_setup import setup_logging, log_info, log_error
from .ops import (
    require_cmd, resolve_cmd, root_or_sudo_available, get_tool_version,
    run_command_with_progress, ExecutionMetadata,
    log_tool_execution, log_artifact, log_artifacts_for_nmap
)
from .parsing import (
    is_ipv6, is_ipv4,
    is_valid_token, build_item_set,
    normalize_combos,
    split_host_port, parse_hosts_ports,
    is_hostname,
    extract_plugin_id_from_filename, group_findings_by_workflow,
)
from .render import (
    render_scan_table, render_severity_table, render_finding_list_table,
    render_compare_tables, render_actions_footer, show_actions_help,
    render_tool_availability_table,
    show_reviewed_help, menu_pager, severity_cell, severity_style,
    print_action_menu,
    file_raw_payload_text, file_raw_paged_text,
    grouped_payload_text, grouped_paged_text,
    hosts_only_payload_text, hosts_only_paged_text,
    build_plugin_output_details, display_finding_preview,
    page_text,
    bulk_extract_cves_for_plugins, bulk_extract_cves_for_findings,
    display_bulk_cve_results, color_unreviewed,
)
from .fs import (
    build_results_paths, mark_review_complete, undo_review_complete,
    default_page_size, pretty_severity_label, write_work_files,
    display_workflow, handle_finding_view, process_single_finding
)
from .tools import (
    build_nmap_cmd, build_netexec_cmd,
    choose_tool, choose_netexec_protocol,
    custom_command_help, render_placeholders,
    command_review_menu, copy_to_clipboard,
    choose_nse_profile,
    run_tool_workflow,
)
from .tui import (
    parse_severity_selection,
    choose_from_list,
    handle_finding_list_actions,
)
from .analysis import (
    compare_filtered, analyze_inclusions,
    natural_key, count_reviewed_in_scan
)
from .tool_registry import (
    Tool, TOOL_REGISTRY,
    get_tool, get_available_tools,
    get_tool_by_menu_index, get_tool_count,
    register_tool,
)
from .tool_context import (
    ToolContext,
    CommandResult,
    ReviewContext,
)
from .session import (
    SessionState,
    save_session,
    load_session,
    delete_session,
    show_scan_summary,
)
from .workflow_mapper import (
    Workflow,
    WorkflowStep,
    WorkflowMapper,
)
from .config import (
    CernoConfig,
    load_config,
    save_config,
    get_config_path,
    create_example_config,
)
from .nessus_import import (
    import_nessus_file,
    ExportResult,
)
from .enums import (
    DisplayFormat,
    ViewFormat,
    SortMode,
)
from .database import (
    get_database_path,
    get_connection,
    db_transaction,
    initialize_database,
    DATABASE_PATH,
)
from .models import (
    Scan,
    Plugin,
    Finding,
    ToolExecution,
    Artifact,
)
# Note: tool_definitions is NOT imported here to avoid circular imports
# Tools are registered lazily on first access via _ensure_registered()