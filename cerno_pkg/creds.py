"""Credential reveal — the sanctioned, audited path to a NetExec secret's cleartext.

Masking the logs (see the MCP exec path) removes accidental leaks, not the
operator's ability to obtain a credential deliberately. This module is the single
place that returns a cleartext secret, shared by the local ``cerno creds reveal``
CLI and the gated MCP ``reveal_credential`` tool, and it records an audit event
for every reveal (the ref + timestamp, never the secret value).
"""

from __future__ import annotations

import sqlite3
from typing import List, Optional

from . import nxc_db
from .nxc_db import NxcCredentialRef, ResolvedSecret


def list_credential_refs() -> List[NxcCredentialRef]:
    """Non-secret references to every stored NetExec credential (no values)."""
    return nxc_db.list_credential_refs()


def _audit_reveal(ref: str, conn: Optional[sqlite3.Connection]) -> None:
    """Record a reveal in tool_executions (ref + timestamp only; never the secret)."""
    from .ops import ExecutionMetadata, log_tool_execution

    log_tool_execution(
        "cred_reveal",
        f"reveal_credential {ref}",
        ExecutionMetadata(exit_code=0, duration_seconds=0.0, used_sudo=False),
        conn=conn,
    )


def reveal_credential(
    ref: str, *, conn: Optional[sqlite3.Connection] = None
) -> Optional[ResolvedSecret]:
    """Resolve a credential ``ref`` to its cleartext secret, writing an audit event.

    Returns the :class:`ResolvedSecret` (caller must not persist it), or None when
    the ref has no usable secret. A real DB/access error propagates (it is not
    swallowed into a misleading None). Only a successful reveal is audited.
    """
    secret = nxc_db.resolve_credential_secret(ref)
    if secret is None:
        return None
    _audit_reveal(ref, conn)
    return secret
