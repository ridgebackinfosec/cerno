"""Shared command → target-binary resolution for the MCP execution path.

A single source of truth for "what binary does this argv actually run, after
stripping sudo/proxychains4/env/timeout/... wrappers". Three consumers rely on
it and must never drift:

- the execute_command allow/deny policy (``mcp_server/server.py``),
- result-ingestion dispatch (``ingest.py``) — which ingester to run,
- auth-flag masking scope (``ops.py``) — only mask secrets for nxc/netexec.

``command_chain`` fails closed (raises) for the policy path; the softer
``resolve_target_binary`` / ``effective_tool`` return ``None`` for callers that
must not raise.
"""

from __future__ import annotations

import dataclasses
import fnmatch
from pathlib import Path
from typing import Any, Optional, Sequence


@dataclasses.dataclass(frozen=True)
class _WrapperSpec:
    """How to step past a wrapper binary's own arguments to its wrapped command.

    ``short_val`` are short option letters that consume a value; ``long_val`` are
    ``--long`` options whose value is a separate argument. ``skip_positionals``
    is the count of positional arguments before the command (e.g. ``timeout``'s
    DURATION), and ``assignments`` skips leading ``NAME=VALUE`` tokens (``env``).
    """

    short_val: frozenset[str] = frozenset()
    long_val: frozenset[str] = frozenset()
    skip_positionals: int = 0
    assignments: bool = False


#: Wrapper binaries that run another command. The wrapped target is unwrapped so
#: policy applies to what actually runs — e.g. ``env rm`` or ``timeout 5 rm``
#: must expose ``rm`` to the denylist, not hide it behind the wrapper. The
#: positional-mask wrappers ``taskset`` / ``chrt`` are deliberately omitted (their
#: grammar is ambiguous to parse without running them).
EXEC_WRAPPERS: dict[str, _WrapperSpec] = {
    "sudo": _WrapperSpec(
        short_val=frozenset("ugCDhprtUT"),
        long_val=frozenset(
            {
                "--user",
                "--group",
                "--close-from",
                "--chdir",
                "--host",
                "--prompt",
                "--role",
                "--type",
                "--other-user",
                "--command-timeout",
            }
        ),
    ),
    # doas takes a subset of sudo's value options; overmatching is harmless here.
    "doas": _WrapperSpec(short_val=frozenset("uCa")),
    "proxychains4": _WrapperSpec(short_val=frozenset("f")),
    # Cerno only runs proxychains4; the legacy name is still unwrapped so it
    # can't hide a denied target (e.g. `proxychains rm ...`).
    "proxychains": _WrapperSpec(short_val=frozenset("f")),
    "env": _WrapperSpec(
        short_val=frozenset("uCS"),
        long_val=frozenset({"--unset", "--chdir", "--split-string"}),
        assignments=True,
    ),
    "nice": _WrapperSpec(short_val=frozenset("n")),
    "timeout": _WrapperSpec(
        short_val=frozenset("sk"),
        long_val=frozenset({"--signal", "--kill-after"}),
        skip_positionals=1,  # DURATION
    ),
    "stdbuf": _WrapperSpec(short_val=frozenset("ioe")),
    "ionice": _WrapperSpec(short_val=frozenset("cnp")),
    "setsid": _WrapperSpec(),
    "nohup": _WrapperSpec(),
    # /usr/bin/time (the shell builtin never reaches an argv list).
    "time": _WrapperSpec(
        short_val=frozenset("of"),
        long_val=frozenset({"--output", "--format"}),
    ),
}

#: Target-binary basenames mapped to the ingester / masking "tool" they imply.
_TOOL_BY_BINARY: dict[str, str] = {
    "nmap": "nmap",
    "nxc": "nxc",
    "netexec": "nxc",
}


def _skip_wrapper_options(command: Sequence[Any], i: int, spec: _WrapperSpec) -> int:
    """Return the index of the wrapper's command, stepping past its arguments.

    Handles getopt-style options (short flags may be clustered as ``-Eu root`` or
    carry an attached value as ``-uroot``; ``--`` ends option parsing), then any
    ``NAME=VALUE`` assignments (``env``), then ``skip_positionals`` positionals
    (``timeout`` DURATION).
    """
    short_vals, long_vals = spec.short_val, spec.long_val
    while i < len(command):
        arg = str(command[i])
        if arg == "--":
            i += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        if arg.startswith("--"):
            i += 2 if arg in long_vals else 1
            continue
        i += 1
        for pos, letter in enumerate(arg[1:], start=1):
            if letter in short_vals:
                if pos == len(arg) - 1:  # value is the next argument
                    i += 1
                break  # anything after the letter is its attached value

    if spec.assignments:
        while i < len(command):
            arg = str(command[i])
            if "=" in arg and not arg.startswith("-"):
                i += 1
            else:
                break

    i += spec.skip_positionals
    return i


def command_chain(command: Sequence[Any]) -> list[str]:
    """Basenames of every binary in ``command``, unwrapping known wrappers.

    ``["sudo", "-u", "root", "proxychains4", "-q", "nmap", ...]`` yields
    ``["sudo", "proxychains4", "nmap"]``; the last entry is the real target. Known
    wrappers (``EXEC_WRAPPERS``) such as sudo, env, timeout and nice are stepped
    past so the wrapped command is exposed. Raises ValueError if a wrapper is left
    with no command to run (fail closed).
    """
    chain: list[str] = []
    i = 0
    while i < len(command):
        name = Path(str(command[i])).name
        chain.append(name)
        spec = EXEC_WRAPPERS.get(name)
        if spec is None:
            return chain
        i = _skip_wrapper_options(command, i + 1, spec)
    raise ValueError(
        f"{chain[-1]!r} does not wrap a command to run"
        if chain
        else "command must be a non-empty list of arguments"
    )


def split_wrappers(command: Sequence[Any]) -> tuple[list[str], list[str]]:
    """Split ``command`` into ``(wrapper_basenames, wrapped_argv)``.

    Non-raising: known wrappers (and their own options) are peeled off the front
    and the remaining argv — starting at the real target binary — is returned. A
    dangling wrapper yields an empty ``wrapped_argv``. Used by the workflow
    contribution sanitizer to drop environment wrappers such as ``proxychains4 -q``.
    """
    wrappers: list[str] = []
    i = 0
    while i < len(command):
        name = Path(str(command[i])).name
        spec = EXEC_WRAPPERS.get(name)
        if spec is None:
            break
        wrappers.append(name)
        i = _skip_wrapper_options(command, i + 1, spec)
    return wrappers, [str(arg) for arg in command[i:]]


def resolve_target_binary(command: Sequence[Any]) -> Optional[str]:
    """Basename of the real target binary, or None if it can't be resolved.

    Soft counterpart to :func:`command_chain`: a dangling wrapper or empty command
    yields ``None`` instead of raising, for callers (ingestion, masking) that must
    never fail over a malformed command.
    """
    try:
        chain = command_chain(command)
    except ValueError:
        return None
    return chain[-1] if chain else None


def matches_any(name: str, patterns: Sequence[str]) -> bool:
    """True if ``name`` matches any glob pattern (``*`` matches everything).

    The single source of truth for allow/deny glob matching, shared by the
    execute_command policy (``mcp_server/server.py``), workflow-command
    eligibility (``workflow_prep.py``) and batch generation (``batch.py``).
    """
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def is_runnable(
    command: Sequence[Any],
    allowlist: Sequence[str],
    denylist: Sequence[str],
) -> tuple[bool, Optional[str]]:
    """Non-raising allow/deny check: ``(ok, reason_if_not_runnable)``.

    Mirrors ``_check_exec_policy`` semantics (every binary in the unwrapped chain
    is checked against the denylist, which always wins; the target must then match
    the allowlist; an empty allowlist denies everything) but returns a reason
    instead of raising, for callers (workflow prep, batch planning) that classify
    commands as executable-vs-manual rather than aborting.
    """
    try:
        chain = command_chain(command)
    except ValueError:
        return False, "command does not resolve to a runnable binary"
    for name in chain:
        if matches_any(name, denylist):
            return False, f"{name!r} is in the exec denylist"
    target = chain[-1]
    if not allowlist:
        return False, "exec allowlist is empty (all commands denied)"
    if not matches_any(target, allowlist):
        return False, f"{target!r} is not in the exec allowlist"
    return True, None


def effective_tool(command: Sequence[Any]) -> Optional[str]:
    """Map a command to the tool that drives ingestion/masking: nmap | nxc | None.

    ``netexec`` resolves to ``nxc`` (same ingester/masking). Unknown binaries
    return ``None``.
    """
    target = resolve_target_binary(command)
    if target is None:
        return None
    return _TOOL_BY_BINARY.get(target)
