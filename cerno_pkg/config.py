"""User configuration management for cerno.

This module handles loading and managing user preferences from ~/.cerno/config.yaml.
Configuration is optional - the application works with defaults if no config file exists.
"""

from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

import yaml

from .constants import COLOR_SCHEMES

#: Default binaries the MCP ``execute_command`` tool may run (single source of truth).
#: Wrappers (sudo, proxychains4) need no entry: the wrapped target is what's checked.
DEFAULT_MCP_EXEC_ALLOWLIST: tuple[str, ...] = ("nmap", "nxc", "netexec", "msfconsole")

#: Default binaries the MCP ``execute_command`` tool may never run (destructive commands).
DEFAULT_MCP_EXEC_DENYLIST: tuple[str, ...] = (
    "rm",
    "rmdir",
    "dd",
    "shred",
    "wipefs",
    "mkfs*",
    "fdisk",
    "sfdisk",
    "parted",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
)


def coerce_str_list(value: Any, default: Sequence[str]) -> list[str]:
    """Normalize a config value into a list of non-empty, stripped strings.

    Accepts a list/tuple, or a comma-separated string (as typed into
    ``cerno config set`` or hand-edited into YAML as a scalar). ``None`` (key
    missing) and any other type fall back to a copy of ``default``. Coercing
    strings matters: a bare string would otherwise turn ``x in value`` into a
    substring test.
    """
    if value is None:
        return list(default)
    if isinstance(value, str):
        items: Sequence[Any] = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return list(default)
    return [str(x).strip() for x in items if str(x).strip()]


@dataclass
class CernoConfig:
    """User configuration for cerno application.

    All settings are optional and will fall back to application defaults if not specified.
    """

    # Field order within a section is the display order in `cerno config show`.
    # Per-field ``metadata`` is the single source of truth for load/save/show/set
    # (section, help, kind, optional placeholder/list_default) — see
    # ``iter_config_fields``. Add metadata when adding a field or the drift-guard
    # test (tests/test_config.py) fails.

    # Paths
    results_root: Optional[str] = field(
        default=None,
        metadata={
            "section": "Paths",
            "kind": "path",
            "help": "Directory for tool output",
        },
    )
    """Custom path for tool output and artifacts (default: ~/.cerno/artifacts)."""

    log_path: Optional[str] = field(
        default=None,
        metadata={"section": "Paths", "kind": "path", "help": "Log file location"},
    )
    """Path to log file (default: ~/.cerno/cerno.log)."""

    # Review & Display
    default_page_size: Optional[int] = field(
        default=None,
        metadata={
            "section": "Review & Display",
            "kind": "int",
            "help": "Items per page in lists",
            "placeholder": "auto",
        },
    )
    """Default items per page. Use None for auto-detection from terminal height.
    The MCP default limit and fs.default_page_size() enforce a minimum of 8."""

    top_ports_count: Optional[int] = field(
        default=None,
        metadata={
            "section": "Review & Display",
            "kind": "int",
            "help": "Top ports to show",
        },
    )
    """Default number of top ports to display in summaries."""

    no_color: bool = field(
        default=False,
        metadata={
            "section": "Review & Display",
            "kind": "bool",
            "help": "Disable ANSI colors",
        },
    )
    """Disable ANSI color output (default: False)."""

    color_scheme: str = field(
        default="light",
        metadata={
            "section": "Review & Display",
            "kind": "str",
            "choices": COLOR_SCHEMES,
            "help": "Terminal background: light or dark",
        },
    )
    """Terminal background the colors are tuned for: 'light' (default) or 'dark'."""

    term_override: Optional[str] = field(
        default=None,
        metadata={
            "section": "Review & Display",
            "kind": "str",
            "help": "Force terminal type",
            "placeholder": "(not set)",
        },
    )
    """Override TERM detection (e.g., 'dumb' to disable colors)."""

    # Tools & Workflows
    default_tool: Optional[str] = field(
        default=None,
        metadata={
            "section": "Tools & Workflows",
            "kind": "str",
            "help": "Pre-select: nmap/netexec/metasploit/custom",
            "placeholder": "(not set)",
        },
    )
    """Default tool to pre-select (a tool id: 'nmap', 'netexec', 'metasploit', 'custom')."""

    default_netexec_protocol: Optional[str] = field(
        default=None,
        metadata={
            "section": "Tools & Workflows",
            "kind": "str",
            "help": "Default: smb/ssh/ftp/etc",
            "placeholder": "smb",
        },
    )
    """Default protocol for netexec (e.g., 'smb', 'ssh')."""

    nmap_default_profile: Optional[str] = field(
        default=None,
        metadata={
            "section": "Tools & Workflows",
            "kind": "str",
            "help": "NSE profile name",
            "placeholder": "(not set)",
        },
    )
    """Default NSE profile name to pre-select."""

    custom_workflows_path: Optional[str] = field(
        default=None,
        metadata={
            "section": "Tools & Workflows",
            "kind": "path",
            "help": "Path to custom workflows YAML",
            "placeholder": "(not set)",
        },
    )
    """Path to custom workflows YAML."""

    # Logging
    debug_logging: bool = field(
        default=False,
        metadata={"section": "Logging", "kind": "bool", "help": "Enable DEBUG logs"},
    )
    """Enable DEBUG level logging (default: False)."""

    # NetExec Integration
    nxc_workspace_path: Optional[str] = field(
        default=None,
        metadata={
            "section": "NetExec Integration",
            "kind": "str",
            "help": "NetExec workspace directory",
            "placeholder": "~/.nxc/workspaces/default/",
        },
    )
    """Path to NetExec workspace directory (default: ~/.nxc/workspaces/default/).
    Can be set to a different workspace (e.g., ~/.nxc/workspaces/client_a/).
    Set to empty string to disable NetExec integration."""

    nxc_enrichment_enabled: bool = field(
        default=True,
        metadata={
            "section": "NetExec Integration",
            "kind": "bool",
            "help": "NetExec enrichment, cred refs and nxc ingest",
        },
    )
    """Enable NetExec integration (default: True).

    When False, get_nxc_manager() returns None, which also disables
    `cerno creds`, MCP credential tools/injection/reveal and nxc ingest."""

    # Claude Assistant
    claude_assistant_enabled: bool = field(
        default=False,
        metadata={
            "section": "Claude Assistant",
            "kind": "bool",
            "help": "Enable Claude Assistant",
        },
    )
    """Enable Claude Assistant interactive chat panel in review TUI (default: False).

    Opt-in because the assistant sends finding/host/plugin-output context to the
    local `claude` CLI; the TUI shows a data-path disclosure and persists consent
    on first use."""

    # MCP Server (BETA)
    mcp_allow_execution: bool = field(
        default=False,
        metadata={
            "section": "MCP Server",
            "kind": "bool",
            "help": "Allow MCP server to execute commands",
        },
    )
    """Allow the `cerno mcp` server to EXECUTE tool commands (nmap/netexec/etc.) (default: False).
    When False, the execute_command tool is not registered and only read + command-generation
    tools are exposed."""

    mcp_allow_mutations: bool = field(
        default=False,
        metadata={
            "section": "MCP Server",
            "kind": "bool",
            "help": "Allow MCP server to mutate state",
        },
    )
    """Allow the `cerno mcp` server to MUTATE state — update review state, import scans,
    ingest results, set verdicts (default: False).
    When False, those tools are not registered and the server is effectively read-only."""

    mcp_allow_cred_injection: bool = field(
        default=False,
        metadata={
            "section": "MCP Server",
            "kind": "bool",
            "help": "Allow execute_command to resolve @cred placeholders to real secrets",
        },
    )
    """Allow execute_command to resolve @cred:<ref>@ placeholders to real NetExec
    secrets server-side at run time (default: False). When False, a command still
    carrying a credential placeholder is refused. Independent of mcp_allow_execution
    so an operator can permit tool execution while forbidding secret substitution.
    The resolved secret is never logged, returned, or written to an artifact."""

    mcp_allow_cred_reveal: bool = field(
        default=False,
        metadata={
            "section": "MCP Server",
            "kind": "bool",
            "help": "Allow the MCP reveal_credential tool to return cleartext secrets",
        },
    )
    """Allow the `cerno mcp` server's reveal_credential tool to return a credential's
    CLEARTEXT secret to the caller (default: False). Strictly more sensitive than
    injection (injection keeps the secret server-side; reveal hands it back), so it
    is gated independently — enabling injection does NOT enable reveal. The local
    `cerno creds reveal` CLI works regardless of this flag (operator's own terminal)."""

    mcp_exec_allowlist: list[str] = field(
        default_factory=lambda: list(DEFAULT_MCP_EXEC_ALLOWLIST),
        metadata={
            "section": "MCP Server",
            "kind": "list",
            "help": "Binaries execute_command may run",
            "list_default": DEFAULT_MCP_EXEC_ALLOWLIST,
            "placeholder": "(empty: deny all)",
        },
    )
    """Binaries the `cerno mcp` server's execute_command tool may run, matched as
    glob patterns against the basename of the target binary (after unwrapping
    sudo/proxychains4). ``*`` permits any binary not in mcp_exec_denylist. An empty
    list denies everything. Only consulted when mcp_allow_execution is True."""

    mcp_exec_denylist: list[str] = field(
        default_factory=lambda: list(DEFAULT_MCP_EXEC_DENYLIST),
        metadata={
            "section": "MCP Server",
            "kind": "list",
            "help": "Binaries execute_command may never run",
            "list_default": DEFAULT_MCP_EXEC_DENYLIST,
            "placeholder": "(none)",
        },
    )
    """Binaries the `cerno mcp` server's execute_command tool may NEVER run, matched as
    glob patterns against the basename of every binary in the command chain
    (including wrappers, so adding ``sudo`` blocks privilege escalation). Always wins
    over mcp_exec_allowlist. A guardrail, not a security boundary: under ``*``,
    shells/interpreters can still run denied programs unless they are denied too."""

    mcp_allow_batch: bool = field(
        default=False,
        metadata={
            "section": "MCP Server",
            "kind": "bool",
            "help": "Allow execute_batch to run a whole query's commands",
        },
    )
    """Allow the `cerno mcp` server's execute_batch tool to RUN the generated command
    for every finding matched by a query (default: False). plan_batch (the reviewable
    dry run) is always available; execution additionally requires mcp_allow_execution,
    and every command still passes the allow/deny policy, cred gate, and timeout — this
    flag only authorizes the fan-out across a query. Strictly opt-in beyond single
    execute_command because a batch amplifies blast radius."""

    mcp_batch_concurrency: int = field(
        default=1,
        metadata={
            "section": "MCP Server",
            "kind": "int",
            "help": "Max commands execute_batch runs at once",
        },
    )
    """Maximum number of batch commands execute_batch runs concurrently (default: 1 =
    sequential). nmap/nxc are already internally parallel, so keep this small (2-3) to
    avoid overwhelming the host/network."""

    mcp_batch_timeout: int = field(
        default=300,
        metadata={
            "section": "MCP Server",
            "kind": "int",
            "help": "Per-command timeout (s) for execute_batch",
        },
    )
    """Per-command timeout in seconds for each command in an execute_batch run
    (default: 300), clamped to the same [1, 3600] ceiling as execute_command."""

    contribution_export_dir: Optional[str] = field(
        default=None,
        metadata={
            "section": "MCP Server",
            "kind": "str",
            "help": "Directory for exported workflow contributions",
            "placeholder": "<results_root>/contributions",
        },
    )
    """Directory where the MCP export_workflow_contribution tool writes sanitized,
    PR-ready workflow YAML files (default: None = ``<results_root>/contributions``).
    Export is local-only: nothing is sent anywhere."""

    # Proxychains4
    proxychains_enabled: bool = field(
        default=False,
        metadata={
            "section": "Proxychains4",
            "kind": "bool",
            "help": "Route tools through proxychains4 (SOCKS5)",
        },
    )
    """Route all tool executions through proxychains4 SOCKS5 proxy (default: False)."""

    proxychains_host: str = field(
        default="127.0.0.1",
        metadata={
            "section": "Proxychains4",
            "kind": "str",
            "help": "proxychains4 SOCKS5 proxy host",
        },
    )
    """SOCKS5 proxy host for proxychains4 (default: 127.0.0.1)."""

    proxychains_port: int = field(
        default=9000,
        metadata={
            "section": "Proxychains4",
            "kind": "int",
            "help": "proxychains4 SOCKS5 proxy port",
        },
    )
    """SOCKS5 proxy port for proxychains4 (default: 9000, matching ssh -D 9000)."""

    # Remote Scan Mode
    pivot_interface: Optional[str] = field(
        default=None,
        metadata={
            "section": "Remote Scan Mode",
            "kind": "str",
            "help": "Interface for remote scan HTTPS server",
            "placeholder": "(not set)",
        },
    )
    """Network interface whose IP is advertised in the remote scan HTTPS server URL (e.g. 'tun0').
    Set on first remote mode activation via the nmap options menu."""

    pivot_http_port: int = field(
        default=8877,
        metadata={
            "section": "Remote Scan Mode",
            "kind": "int",
            "help": "Port for remote scan HTTPS server",
        },
    )
    """Port for the temporary HTTPS server used in remote scan mode (default: 8877)."""


#: Config keys the ``cerno mcp`` server intentionally does NOT apply. They are
#: terminal/TUI concepts with no MCP meaning: colour/terminal handling, the TUI's
#: pre-selected tool menu, the in-TUI Claude chat, remote-scan pivot serving, and
#: the scan-summary "top ports" table. Every other key is honored by the MCP
#: server, with precedence explicit tool argument > config value > hardcoded
#: default. ``tests/test_mcp_config.py`` guards that every field is classified.
MCP_NOT_APPLICABLE_KEYS: frozenset[str] = frozenset(
    {
        "no_color",
        "color_scheme",
        "term_override",
        "default_tool",
        "claude_assistant_enabled",
        "pivot_interface",
        "pivot_http_port",
        "top_ports_count",
    }
)


def iter_config_fields() -> Iterable[Any]:
    """Yield CernoConfig dataclass fields in declaration order.

    The single place load/save and the ``cerno config`` CLI iterate, so a new
    field (with its ``metadata``) is picked up everywhere automatically.
    """
    return fields(CernoConfig)


def _field_default(f: Any) -> Any:
    """The scalar default for a field, or None when it uses a default_factory."""
    if f.default is not MISSING:
        return f.default
    return None


def config_key_names() -> list[str]:
    """All settable config key names, in declaration order (for CLI help)."""
    return [f.name for f in iter_config_fields()]


def config_field_kind(name: str) -> Optional[str]:
    """The ``kind`` metadata of a config field (drives ``config set`` coercion)."""
    for f in iter_config_fields():
        if f.name == name:
            kind = f.metadata.get("kind")
            return str(kind) if kind is not None else None
    return None


def reset_config_key(config: CernoConfig, key: str) -> Any:
    """Restore a single config key to its default value, in place.

    The default is read from a fresh ``CernoConfig()`` so ``default_factory``
    list fields get their real default (not None). Nullable defaults become None
    and are then omitted from the YAML by ``save_config``.

    Args:
        config: Configuration object to modify
        key: Config key name to reset

    Returns:
        The restored default value

    Raises:
        KeyError: If ``key`` is not a config field
    """
    if key not in config_key_names():
        raise KeyError(key)
    value = getattr(CernoConfig(), key)
    setattr(config, key, value)
    return value


def config_field_choices(name: str) -> Optional[tuple[str, ...]]:
    """The allowed values of a config field, or None when it is free-form."""
    for f in iter_config_fields():
        if f.name == name:
            choices = f.metadata.get("choices")
            return tuple(choices) if choices else None
    return None


def config_from_dict(data: dict[str, Any]) -> CernoConfig:
    """Build a CernoConfig from a parsed-YAML dict, honoring per-field ``kind``.

    List fields go through ``coerce_str_list`` (with their ``list_default``);
    everything else falls back to the field's declared default when the key is
    absent. Mirrors the previous hand-written extraction exactly.
    """
    kwargs: dict[str, Any] = {}
    for f in iter_config_fields():
        meta = f.metadata
        if meta.get("kind") == "list":
            kwargs[f.name] = coerce_str_list(
                data.get(f.name), meta.get("list_default", ())
            )
        else:
            kwargs[f.name] = data.get(f.name, _field_default(f))
    return CernoConfig(**kwargs)


def build_config_rows(config: CernoConfig) -> list[tuple[str, str, str, bool, str]]:
    """Rows for ``cerno config show``, derived entirely from the dataclass fields.

    Returns ``(section, key, value_str, is_default, help)`` in field (display)
    order. Pure and importable so the CLI has no per-field logic to drift and the
    guard test can assert every field renders. A few fields whose effective
    default is computed at runtime (results_root/log_path/top_ports_count) resolve
    their display here; others use the metadata ``placeholder``.
    """
    from .constants import DEFAULT_TOP_PORTS, get_results_root

    dynamic = {
        "results_root": lambda v: v or str(get_results_root()),
        "log_path": lambda v: v or str(Path.home() / ".cerno" / "cerno.log"),
        "top_ports_count": lambda v: v or DEFAULT_TOP_PORTS,
    }
    defaults = CernoConfig()
    rows: list[tuple[str, str, str, bool, str]] = []
    for f in iter_config_fields():
        meta = f.metadata
        value = getattr(config, f.name)
        is_default = value == getattr(defaults, f.name)
        if f.name in dynamic:
            shown: Any = dynamic[f.name](value)
        elif meta.get("kind") == "list":
            shown = ", ".join(value) or meta.get("placeholder", "")
        elif value is None or value == "":
            shown = meta.get("placeholder", "None")
        else:
            shown = value
        rows.append((meta["section"], f.name, str(shown), is_default, meta["help"]))
    return rows


def get_config_path() -> Path:
    """Get the path to the user's config file.

    Returns:
        Path to ~/.cerno/config.yaml
    """
    config_dir = Path.home() / ".cerno"
    return config_dir / "config.yaml"


def load_config() -> CernoConfig:
    """Load user configuration from ~/.cerno/config.yaml.

    Auto-creates config file with defaults if it doesn't exist.

    Returns:
        CernoConfig object with user preferences, or default config if file doesn't exist.
    """
    config_path = get_config_path()

    # Auto-create if doesn't exist
    if not config_path.exists():
        # Note: Don't log here since logger isn't initialized yet
        create_example_config()
        # Continue to load the newly created file

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            # Note: Don't log here since logger isn't initialized yet
            return CernoConfig()

        # Extract config values from the dataclass fields (single source of truth)
        return config_from_dict(data)

    except Exception:
        # Note: Don't log here since logger isn't initialized yet
        # Silently fall back to defaults if config load fails
        return CernoConfig()


def save_config(config: CernoConfig) -> bool:
    """Save user configuration to ~/.cerno/config.yaml.

    Args:
        config: Configuration object to save

    Returns:
        True if successful, False otherwise
    """
    config_path = get_config_path()

    # Create config directory if it doesn't exist
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Convert to dict from the dataclass fields (single source of truth),
        # excluding None values for cleaner YAML and preserving field order.
        data = {
            f.name: getattr(config, f.name)
            for f in iter_config_fields()
            if getattr(config, f.name) is not None
        }

        with open(config_path, "w", encoding="utf-8") as fh:
            yaml.dump(data, fh, default_flow_style=False, sort_keys=False)

        # Config saved successfully
        return True

    except Exception:
        # Failed to save config
        return False


def create_example_config() -> bool:
    """Create config file with all defaults uncommented.

    Returns:
        True if successful, False otherwise
    """
    # All defaults come from the dataclass itself; optional (None) fields are
    # omitted by save_config and show as "default" in `cerno config show`.
    return save_config(CernoConfig())
