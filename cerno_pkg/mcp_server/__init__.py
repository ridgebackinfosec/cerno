"""Cerno MCP (Model Context Protocol) server package.

Exposes Cerno's scan database and tooling over the Model Context Protocol via
local stdio transport, so any MCP client can query findings, build target
lists, generate/execute security-tool commands, and mutate review state.

The server surface is gated by two config flags (both default ``False``):

- ``mcp_allow_execution``  - enables the ``execute_command`` tool.
- ``mcp_allow_mutations``  - enables ``set_review_state`` and ``import_nessus``.

Read and command-generation tools are always available.
"""

from __future__ import annotations

from .server import build_server, main

__all__ = ["build_server", "main"]
