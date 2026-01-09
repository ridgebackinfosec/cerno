"""
Tool Registry for Cerno
==========================

This module provides a centralized registry for all available tools in cerno.
The registry pattern makes adding and removing tools trivial - just add/remove
a Tool entry to the TOOL_REGISTRY.

Architecture:
- Tool: Dataclass defining tool metadata and behavior
- TOOL_REGISTRY: Single source of truth for all tools
- get_available_tools(): Filters tools based on system availability

Adding a New Tool:
1. Write command builder in tools.py (e.g., build_mytool_cmd)
2. Write workflow function in cerno.py (e.g., _build_mytool_workflow)
3. Add Tool entry to TOOL_REGISTRY with references to above functions
"""

from dataclasses import dataclass, field
from typing import Callable, Optional, Any
from pathlib import Path


@dataclass
class Tool:
    """
    Represents a tool available in cerno.

    Attributes:
        id: Unique identifier (used in dispatch logic)
        name: Display name shown in menus
        description: Short description for menu display
        workflow_builder: Function that gathers params and builds command
        command_builder: Function that constructs the command from params
        requires: List of required binaries (checked with shutil.which)
        menu_order: Display order in menus (lower = earlier)
        options: Tool-specific options/configuration (e.g., NSE profiles)
    """

    id: str
    name: str
    description: str
    workflow_builder: Callable[..., Any]
    command_builder: Optional[Callable[..., Any]] = None
    requires: list[str] = field(default_factory=list)
    menu_order: int = 999
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate required fields."""
        if not self.id or not self.name:
            raise ValueError("Tool must have id and name")
        if not self.workflow_builder:
            raise ValueError(f"Tool '{self.id}' must have workflow_builder")


# ============================================================================
# TOOL REGISTRY - Single Source of Truth
# ============================================================================
# To add a new tool:
# 1. Import the builder and workflow functions
# 2. Add a Tool entry in tool_definitions.py
# 3. Set menu_order to control display position
#
# Lazy Loading:
# The registry is populated on first access to avoid circular import issues
# with cerno.py. Call _ensure_registered() before accessing the registry.
# ============================================================================

TOOL_REGISTRY: dict[str, Tool] = {}
_registry_initialized = False


def _ensure_registered() -> None:
    """
    Ensure tools are registered. Called automatically on first registry access.

    This lazy initialization avoids circular import issues where:
    cerno.py → cerno_pkg → tool_definitions → cerno.py (circular!)

    Instead, tools are registered on first access after all modules are loaded.
    """
    global _registry_initialized
    if not _registry_initialized:
        from . import tool_definitions
        tool_definitions.register_all_tools()
        _registry_initialized = True


def register_tool(tool: Tool) -> None:
    """
    Register a tool in the global registry.

    Args:
        tool: Tool instance to register

    Raises:
        ValueError: If tool with same id already registered
    """
    if tool.id in TOOL_REGISTRY:
        raise ValueError(f"Tool with id '{tool.id}' already registered")
    TOOL_REGISTRY[tool.id] = tool


def get_tool(tool_id: str) -> Optional[Tool]:
    """
    Retrieve a tool by its id.

    Args:
        tool_id: Unique tool identifier

    Returns:
        Tool instance or None if not found
    """
    _ensure_registered()
    return TOOL_REGISTRY.get(tool_id)


def get_available_tools(check_requirements: bool = False) -> list[Tool]:
    """
    Get all available tools, optionally filtered by system availability.

    Args:
        check_requirements: If True, only return tools whose required
                          binaries are available on the system

    Returns:
        List of Tool instances sorted by menu_order
    """
    import shutil

    _ensure_registered()
    tools = list(TOOL_REGISTRY.values())

    if check_requirements:
        available = []
        for tool in tools:
            # Check if all required binaries are available
            if all(shutil.which(cmd) for cmd in tool.requires):
                available.append(tool)
        tools = available

    # Sort by menu_order, then by name
    return sorted(tools, key=lambda t: (t.menu_order, t.name))


def get_tool_by_menu_index(index: int, available_only: bool = False) -> Optional[Tool]:
    """
    Get a tool by its menu display index (1-based).

    Args:
        index: Menu index (1-based)
        available_only: If True, only consider tools with satisfied requirements

    Returns:
        Tool instance or None if index out of range
    """
    tools = get_available_tools(check_requirements=available_only)
    if 1 <= index <= len(tools):
        return tools[index - 1]
    return None


def get_tool_count(available_only: bool = False) -> int:
    """
    Get the number of registered tools.

    Args:
        available_only: If True, only count tools with satisfied requirements

    Returns:
        Number of tools
    """
    _ensure_registered()
    return len(get_available_tools(check_requirements=available_only))


# ============================================================================
# Tool Registration
# ============================================================================
# Tools will be registered here after imports to avoid circular dependencies
# This happens in __init__.py or at module load time
# ============================================================================
