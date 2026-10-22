"""Tests for the shared command->binary resolver (cerno_pkg.exec_chain)."""

import pytest

from cerno_pkg.exec_chain import (
    command_chain,
    effective_tool,
    resolve_target_binary,
)


@pytest.mark.unit
class TestCommandChain:
    def test_plain_command(self) -> None:
        assert command_chain(["nmap", "-A", "10.0.0.1"]) == ["nmap"]

    def test_unwraps_wrappers(self) -> None:
        assert command_chain(
            ["sudo", "-u", "root", "proxychains4", "-q", "nmap", "-A"]
        ) == ["sudo", "proxychains4", "nmap"]

    def test_absolute_path_basename(self) -> None:
        assert command_chain(["/usr/bin/nmap", "-A"]) == ["nmap"]

    def test_dangling_wrapper_raises(self) -> None:
        with pytest.raises(ValueError):
            command_chain(["sudo"])


@pytest.mark.unit
class TestResolveTargetBinary:
    def test_resolves_target(self) -> None:
        assert resolve_target_binary(["sudo", "nmap", "-A"]) == "nmap"

    def test_dangling_wrapper_is_none(self) -> None:
        assert resolve_target_binary(["sudo"]) is None

    def test_empty_is_none(self) -> None:
        assert resolve_target_binary([]) is None


@pytest.mark.unit
class TestEffectiveTool:
    @pytest.mark.parametrize(
        "command,expected",
        [
            (["nmap", "-A"], "nmap"),
            (["sudo", "proxychains4", "-q", "nmap", "-A"], "nmap"),
            (["nxc", "smb", "t"], "nxc"),
            (["netexec", "smb", "t"], "nxc"),  # netexec aliases to nxc
            (["timeout", "5", "nxc", "smb"], "nxc"),
            (["curl", "http://x"], None),
            (["sudo"], None),
        ],
    )
    def test_effective_tool(self, command, expected) -> None:
        assert effective_tool(command) == expected
