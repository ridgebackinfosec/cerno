# Cerno Tool System Guide

Complete reference for the tool registry and unified workflow pattern.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Tool Registry System](#tool-registry-system)
4. [Unified Workflow Pattern](#unified-workflow-pattern)
5. [Adding a New Tool](#adding-a-new-tool)
6. [Custom Tool Development Guide](#migration-guide)
7. [Troubleshooting](#troubleshooting)

---

## Overview

Cerno uses two key patterns that make adding tools simple and maintainable:

1. **Tool Registry** - Centralized database of all available tools
2. **Unified Workflow** - Standardized parameters and return types

Together, these eliminate hardcoded tool definitions and per-tool dispatch logic.

### Key Benefits

✅ **Add tools in 3 steps** - No dispatch code changes needed
✅ **Type-safe** - ToolContext and CommandResult dataclasses
✅ **Clean dispatch** - Generic code handles all tools
✅ **Self-documenting** - Context shows all available fields
✅ **Easy to maintain** - Single source of truth for tools

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    TOOL REGISTRY                            │
│  Metadata: Tool dataclass (id, name, description, ...)     │
│  Storage: TOOL_REGISTRY dict                                │
│  Functions: get_tool(), get_available_tools()               │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ Registers
                            │
┌─────────────────────────────────────────────────────────────┐
│                  TOOL DEFINITIONS                           │
│  File: tool_definitions.py                                  │
│  Function: register_all_tools()                             │
│  Contains: Tool(...) registration entries                   │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ References
                            │
┌──────────────────────┬────────────────────────────────────────┐
│   COMMAND BUILDERS   │     WORKFLOW BUILDERS                  │
│  File: tools.py      │     File: cerno.py                   │
│  Pure functions      │     Interactive prompts               │
│  Return: list[str]   │     Use: ToolContext                  │
│                      │     Return: CommandResult             │
└──────────────────────┴────────────────────────────────────────┘
```

### Execution Flow

```
User selects tool from menu
         ↓
choose_tool() reads TOOL_REGISTRY (data-driven menu)
         ↓
Returns tool id (e.g., "nmap")
         ↓
Dispatch looks up Tool in registry
         ↓
Builds ToolContext with all parameters
         ↓
Calls Tool.workflow_builder(ctx) - unified signature!
         ↓
Workflow prompts user, calls command builder
         ↓
Returns CommandResult(command, display_command, artifact_note)
         ↓
Dispatch extracts command from result - generic code!
         ↓
Command displayed for review/execution
```

### Files

| File | Purpose | Contains |
|------|---------|----------|
| `tool_registry.py` | Registry infrastructure | Tool dataclass, TOOL_REGISTRY, helper functions |
| `tool_definitions.py` | Tool registration | register_all_tools(), Tool() entries |
| `tool_context.py` | Unified types | ToolContext, CommandResult dataclasses |
| `tools.py` | Command builders | build_*_cmd() functions |
| `cerno.py` | Workflows & dispatch | _build_*_workflow() functions, dispatch logic |

---

## Tool Registry System

### Tool Dataclass

Defines tool metadata and behavior.

**File:** `cerno_pkg/tool_registry.py`

```python
@dataclass
class Tool:
    """Represents a tool available in cerno."""

    id: str                             # Unique identifier
    name: str                           # Display name in menus
    description: str                    # Short description
    workflow_builder: Callable[..., Any]  # Workflow function reference
    command_builder: Optional[Callable]  # Command builder reference
    requires: list[str]                 # Required system binaries
    menu_order: int                     # Display position (lower = earlier)
    options: dict[str, Any]             # Tool-specific metadata
```

**Field Guide:**

- **id**: Lowercase, no spaces (e.g., "nmap", "netexec")
- **name**: Human-readable (can match id)
- **description**: Shown after "—" in menu (e.g., "Network mapper")
- **workflow_builder**: Function reference (e.g., `cerno._build_nmap_workflow`)
- **command_builder**: Function reference (e.g., `tools.build_nmap_cmd`) or None
- **requires**: Binary names to check (e.g., `["nmap"]`)
- **menu_order**: Integer (1, 2, 3...) - controls display order
- **options**: Custom dict (e.g., `{"supports_udp": True}`)

### Registry Functions

**Get a tool:**
```python
from cerno_pkg import get_tool

tool = get_tool("nmap")  # Returns Tool or None
```

**Get all tools:**
```python
from cerno_pkg import get_available_tools

tools = get_available_tools()  # Returns list sorted by menu_order
```

**Register a tool:**
```python
from cerno_pkg import register_tool

register_tool(Tool(id="mytool", ...))
```

---

## Unified Workflow Pattern

### ToolContext - Standardized Parameters

All workflows receive a single `ToolContext` object instead of individual parameters.

**File:** `cerno_pkg/tool_context.py`

```python
@dataclass
class ToolContext:
    """Unified context passed to all workflow builders."""

    # Input files
    tcp_ips: Path          # TCP IP list file
    udp_ips: Path          # UDP IP list file
    tcp_sockets: Path      # host:port list file

    # Configuration
    ports_str: str         # Comma-separated ports
    use_sudo: bool         # Sudo availability

    # Output paths
    workdir: Path          # Working directory
    results_dir: Path      # Results directory
    oabase: Path           # Output base path
    scan_dir: Path         # Scan directory
    sev_dir: Path          # Severity directory

    # Optional metadata
    plugin_url: Optional[str]    # Nessus plugin URL
    chosen_file: Optional[Path]  # Selected file
```

**Usage:**
```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    # Access fields as needed
    ips = ctx.tcp_ips
    ports = ctx.ports_str
    output = ctx.oabase
```

### CommandResult - Standardized Return

All workflows return a `CommandResult` object instead of tuples.

```python
@dataclass
class CommandResult:
    """Unified return type from workflow builders."""

    command: Union[str, List[str]]          # Actual command
    display_command: Union[str, List[str]]  # Shown to user
    artifact_note: str                      # Output location note
    relay_path: Optional[Path] = None       # Optional relay file
```

**Usage:**
```python
return CommandResult(
    command=cmd,
    display_command=cmd,
    artifact_note=f"Output: {output_file}",
)
```

### Dispatch Logic (Automatic)

The dispatch code in `cerno.py` is completely generic:

```python
# Build context once (same for ALL tools)
ctx = ToolContext(
    tcp_ips=tcp_ips,
    udp_ips=udp_ips,
    tcp_sockets=tcp_sockets,
    ports_str=ports_str,
    use_sudo=use_sudo,
    workdir=workdir,
    results_dir=results_dir,
    oabase=oabase,
    scan_dir=scan_dir,
    sev_dir=sev_dir,
    plugin_url=plugin_url,
    chosen_file=chosen,
)

# Call workflow (same signature for ALL tools!)
result = selected_tool.workflow_builder(ctx)

# Extract results (same for ALL tools!)
cmd = result.command
display_cmd = result.display_command
artifact_note = result.artifact_note
```

**No tool-specific dispatch code needed!**

---

## Adding a New Tool

### 3-Step Process

#### Step 1: Write Command Builder (`cerno_pkg/tools.py`)

```python
def build_mytool_cmd(
    param1: str,
    param2: Path,
    output: Path,
) -> list[str]:
    """
    Build mytool command.

    Args:
        param1: Description
        param2: Description
        output: Output file path

    Returns:
        Command as list of strings
    """
    return ["mytool", "--flag", param1, "-i", str(param2), "-o", str(output)]
```

#### Step 2: Write Workflow (`cerno.py`)

**Use ToolContext parameter and return CommandResult:**

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    """
    Build mytool command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if cancelled
    """
    from cerno_pkg.tool_context import CommandResult
    from cerno_pkg.tools import build_mytool_cmd

    # Gather user input
    try:
        param1 = input("Enter param1: ").strip()
        param2 = Path(input("File path: ").strip())
    except KeyboardInterrupt:
        return None  # User cancelled

    # Validation
    if not param1:
        warn("No param1 provided.")
        return None

    # Use context fields
    output = ctx.oabase.parent / f"{ctx.oabase.name}.mytool.txt"

    # Build command
    cmd = build_mytool_cmd(param1, param2, output)

    # Return unified result
    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"MyTool output: {output}",
    )
```

#### Step 3: Register Tool (`cerno_pkg/tool_definitions.py`)

Add to `register_all_tools()` function:

```python
def register_all_tools() -> None:
    import cerno as cerno_module
    from . import tools

    # ... existing registrations ...

    # ========================================================================
    # TOOL 5: mytool
    # ========================================================================
    register_tool(
        Tool(
            id="mytool",
            name="mytool",
            description="Brief description",
            workflow_builder=cerno_module._build_mytool_workflow,
            command_builder=tools.build_mytool_cmd,
            requires=["mytool"],
            menu_order=5,
        )
    )
```

**That's it!** The tool appears in menus automatically. No dispatch changes needed.

---

## Custom Tool Development Guide

### Legacy Pattern (For Reference)

If you're updating existing custom tools, here's the pattern comparison:

#### Old Pattern

```python
def _build_mytool_workflow(
    tcp_ips: Path,
    udp_ips: Path,
    ports_str: str,
    output: Path,
) -> Optional[Tuple[List[str], List[str], str]]:
    # ... logic ...
    return cmd, cmd, f"Output: {output}"
```

#### Current Pattern (Recommended)

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    from cerno_pkg.tool_context import CommandResult

    # Access params via ctx
    tcp_ips = ctx.tcp_ips
    udp_ips = ctx.udp_ips
    ports_str = ctx.ports_str
    output = ctx.oabase

    # ... same logic ...

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
    )
```

### Changes Required

1. **Signature:** `ctx: ToolContext` instead of individual params
2. **Return type:** `Optional[CommandResult]` instead of tuple
3. **Import:** Add `from cerno_pkg.tool_context import CommandResult`
4. **Return statement:** `return CommandResult(...)` instead of tuple
5. **Parameter access:** `ctx.field_name` instead of `field_name`
6. **Dispatch:** Remove tool-specific dispatch code (now automatic)

---

## Troubleshooting

### "Tool not found in registry"

**Problem:** `get_tool("mytool")` returns None

**Solutions:**
1. Check tool is registered in `tool_definitions.py`
2. Verify `register_all_tools()` is called
3. Check for typos in tool id

### "TypeError: missing required positional argument"

**Problem:** Old workflow signature used, but dispatch passes ToolContext

**Solution:** Update workflow signature to accept `ctx: ToolContext`

### "AttributeError: 'ToolContext' object has no attribute 'X'"

**Problem:** Trying to access field that doesn't exist

**Solution:** Check `tool_context.py` for available fields

### "Return value unpacking error"

**Problem:** Workflow returns tuple instead of CommandResult

**Solution:** Return `CommandResult(...)` instead of tuple

### Tool appears in wrong menu position

**Problem:** `menu_order` is incorrect or conflicting

**Solution:** Adjust `menu_order` values (lower appears earlier)

---

## Best Practices

### 1. Keep Command Builders Pure

```python
# Good - pure function
def build_tool_cmd(param: str) -> list[str]:
    return ["tool", param]

# Bad - has side effects
def build_tool_cmd(param: str) -> list[str]:
    print("Building command...")  # Avoid this
    return ["tool", param]
```

### 2. Handle Cancellation

```python
try:
    user_input = input("Enter value: ")
except KeyboardInterrupt:
    return None  # User cancelled
```

### 3. Validate Input

```python
if not user_input:
    warn("No input provided.")
    return None
```

### 4. Use Type Hints

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    # Type hints enable IDE autocomplete
```

### 5. Access Only Needed Context Fields

```python
# Don't need to use all fields!
def _build_simple_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    output = ctx.oabase  # Only use what you need
    # ...
```

---

## See Also

- [ADDING_TOOLS_QUICKSTART.md](ADDING_TOOLS_QUICKSTART.md) - Quick reference
- [tool_context.py](../cerno_pkg/tool_context.py) - ToolContext and CommandResult source
- [tool_registry.py](../cerno_pkg/tool_registry.py) - Tool registry source
- [tool_definitions.py](../cerno_pkg/tool_definitions.py) - Tool registration source
