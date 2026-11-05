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

### Step 2: Workflow (`cerno_pkg/tools.py`)

```python
def build_mytool_workflow(ctx: ToolContext) -> Optional[CommandResult]:
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
    from . import tools

    # ... existing tools ...

    register_tool(
        Tool(
            id="mytool",
            name="mytool",
            description="Brief description",
            workflow_builder=tools.build_mytool_workflow,
            command_builder=tools.build_mytool_cmd,
            requires=["mytool"],
            menu_order=6,  # 1-5 are nmap, netexec, nuclei, metasploit, custom
        )
    )
```

**Almost done.** The tool appears in menus automatically -- no dispatch changes needed.

**If your tool writes a file Cerno should ingest** (an nmap `-oA` set, a nuclei
`-jle` export), teach `ops.log_artifacts_for_run()` about it as well. The TUI run
loop calls that helper for every run, and without an entry your tool logs a
`tool_executions` row with **no artifact**, so `ingest_results` reports
"no artifact registered for this execution". That is exactly the bug nuclei hit
in 3.1.0.

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
