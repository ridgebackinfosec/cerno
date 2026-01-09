"""
Tool Definitions and Registration
==================================

This module registers all available tools in the cerno tool registry.
Import this module to populate the TOOL_REGISTRY with all available tools.

To add a new tool:
1. Write the command builder function in tools.py
2. Write the workflow function in cerno.py
3. Add a Tool registration below with appropriate metadata
4. The tool will automatically appear in menus
"""

from typing import TYPE_CHECKING

from .tool_registry import Tool, register_tool

# Avoid circular imports by using TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Any


def register_all_tools() -> None:
    """
    Register all available tools in the tool registry.

    This function should be called once at module initialization time
    to populate the TOOL_REGISTRY with all available tools.

    Tools are registered with metadata that controls their behavior:
    - id: Unique identifier used in dispatch logic
    - name: Display name in menus
    - description: Short description for users
    - workflow_builder: Reference to workflow function (imported at runtime)
    - command_builder: Reference to command builder function (optional)
    - requires: List of required system binaries
    - menu_order: Display order (lower numbers appear first)
    """
    # Import workflow and builder functions at runtime to avoid circular imports
    # These imports happen inside the function so they're only loaded when needed
    from . import tools

    # ========================================================================
    # TOOL 1: nmap
    # ========================================================================
    register_tool(
        Tool(
            id="nmap",
            name="nmap",
            description="Network mapper",
            workflow_builder=tools._build_nmap_workflow,
            command_builder=tools.build_nmap_cmd,
            requires=["nmap"],
            menu_order=1,
            options={
                "supports_udp": True,
                "supports_nse": True,
            },
        )
    )

    # ========================================================================
    # TOOL 2: netexec
    # ========================================================================
    register_tool(
        Tool(
            id="netexec",
            name="netexec",
            description="Multi-protocol network executor",  # Improved description
            workflow_builder=tools._build_netexec_workflow,
            command_builder=tools.build_netexec_cmd,
            requires=["nxc", "netexec"],  # Either binary is acceptable
            menu_order=2,
            options={
                "protocols": [
                    "mssql", "smb", "ftp", "ldap", "nfs",
                    "rdp", "ssh", "vnc", "winrm", "wmi"
                ],
            },
        )
    )

    # ========================================================================
    # TOOL 3: metasploit
    # ========================================================================
    register_tool(
        Tool(
            id="metasploit",
            name="metasploit",
            description="Search for modules",
            workflow_builder=lambda *args, **kwargs: None,  # Metasploit has special handling
            command_builder=None,  # Metasploit doesn't build commands
            requires=[],  # No system requirements (web-based search)
            menu_order=3,
            options={
                "is_search_tool": True,
                "requires_plugin_url": True,
            },
        )
    )

    # ========================================================================
    # TOOL 4: custom
    # ========================================================================
    register_tool(
        Tool(
            id="custom",
            name="Custom command",
            description="Advanced - use placeholders",
            workflow_builder=tools._build_custom_workflow,
            command_builder=None,  # Custom commands are built in workflow
            requires=[],  # No requirements (user provides command)
            menu_order=4,
            options={
                "supports_placeholders": True,
                "placeholders": [
                    "{TCP_IPS}",
                    "{UDP_IPS}",
                    "{TCP_HOST_PORTS}",
                    "{PORTS}",
                    "{WORKDIR}",
                    "{RESULTS_DIR}",
                    "{OABASE}",
                ],
            },
        )
    )


# ============================================================================
# Auto-register tools on module import
# ============================================================================
# Note: Registration is deferred to avoid circular imports.
# Call register_all_tools() explicitly after cerno module is fully loaded,
# or use lazy registration on first access.
# ============================================================================

# DO NOT auto-register here - causes circular import with cerno.py
# Instead, registration happens lazily on first tool access
