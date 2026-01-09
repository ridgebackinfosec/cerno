# Quick Start: Adding a Tool

Add a new tool to cerno in **3 simple steps**.

**See [TOOL_SYSTEM_GUIDE.md](TOOL_SYSTEM_GUIDE.md) for complete documentation.**

---

## Prerequisites

- **ToolContext**: Unified parameter object (all workflows use this)
- **CommandResult**: Standard return type (all workflows return this)

---

## 3-Step Process

### Step 1: Command Builder (`cerno_pkg/tools.py`)

```python
def build_mytool_cmd(param1: str, output: Path) -> list[str]:
    """Build mytool command."""
    return ["mytool", "--flag", param1, "-o", str(output)]
```

### Step 2: Workflow (`cerno.py`)

```python
def _build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
    """Build mytool command through prompts."""
    from cerno_pkg.tool_context import CommandResult
    from cerno_pkg.tools import build_mytool_cmd

    try:
        param1 = input("Enter param1: ").strip()
    except KeyboardInterrupt:
        return None

    if not param1:
        warn("No input provided.")
        return None

    output = ctx.oabase.parent / f"{ctx.oabase.name}.mytool.txt"
    cmd = build_mytool_cmd(param1, output)

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Output: {output}",
    )
```

### Step 3: Register (`cerno_pkg/tool_definitions.py`)

```python
def register_all_tools() -> None:
    import cerno as cerno_module
    from . import tools

    # ... existing tools ...

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

**Done!** Tool appears in menus automatically. No dispatch changes needed.

---

## ToolContext Fields (Use What You Need)

```python
ctx.tcp_ips       # TCP IP list file
ctx.udp_ips       # UDP IP list file
ctx.tcp_sockets   # host:port list
ctx.ports_str     # Comma-separated ports
ctx.use_sudo      # Sudo availability
ctx.workdir       # Working directory
ctx.results_dir   # Results directory
ctx.oabase        # Output base path
```

---

## Tips

- Return `None` to cancel (KeyboardInterrupt)
- Validate user input before building command
- Use `ctx.field_name` to access context
- Return `CommandResult(...)` not tuple

---

**Full documentation:** [TOOL_SYSTEM_GUIDE.md](TOOL_SYSTEM_GUIDE.md)
