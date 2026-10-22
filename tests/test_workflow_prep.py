"""Tests for prepare_workflow: fill a mapped workflow's placeholders with a
finding's real hosts/ports/creds and mark which filled commands are actually
runnable via execute_command.

The fill logic is pure and injectable (temp WorkflowMapper, explicit allow/deny
lists, a non-secret credential spec), so these tests do not touch nxc or PATH
beyond binaries that reliably exist on Linux (``sh``).
"""

import pytest

from cerno_pkg.models import Finding, Host, Plugin, Port, Scan
from cerno_pkg.workflow_mapper import WorkflowMapper
from cerno_pkg.workflow_prep import prepare_workflow


def _mapper_with(tmp_path, workflows):
    import yaml

    data = {"version": "1.0", "workflows": workflows}
    path = tmp_path / "wf.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return WorkflowMapper(yaml_path=path)


@pytest.fixture
def finding(temp_db):
    c = temp_db
    scan = Scan(scan_name="engagement", export_root="/tmp").save(c)
    Plugin(
        plugin_id=57608, plugin_name="SMB Signing Not Required", severity_int=3
    ).save(c)
    fid = Finding(scan_id=scan, plugin_id=57608).save(c)
    h = Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=c)
    Port.get_or_create(445, conn=c)
    c.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, 445, 'x')",
        (fid, h),
    )
    c.commit()
    return {"conn": c, "finding_id": fid}


# A workflow exercising every placeholder + each executability outcome.
_STEPS = [
    {
        "title": "verify",
        "commands": [
            "sh -c 'echo <TARGET> <PORT>'",  # allowlisted + installed -> executable
            "nmap -p <PORT> --script smb-security-mode <TARGET>",  # filled but not allowlisted
            "responder -I <INTERFACE> -A",  # unresolved INTERFACE + not allowlisted
            "netexec smb <TARGET> -u <USERNAME> -p <PASSWORD>",  # needs credential
            "Manually build a request in Burp",  # prose -> manual
            "nmap IP_address -p $PORT",  # old-variant tokens must still fill
        ],
        "notes": "",
    }
]


def _prep(finding, tmp_path, **kwargs):
    mapper = _mapper_with(
        tmp_path,
        [
            {
                "plugin_id": "57608",
                "workflow_name": "SMB",
                "description": "d",
                "steps": _STEPS,
            }
        ],
    )
    return prepare_workflow(
        finding["finding_id"],
        workflow_mapper=mapper,
        allowlist=["sh"],
        denylist=[],
        conn=finding["conn"],
        **kwargs,
    )


def _cmds(prepared):
    return prepared.steps[0].commands


def test_returns_none_when_no_workflow_mapped(finding, tmp_path):
    mapper = _mapper_with(tmp_path, [])  # no workflow for plugin 57608
    assert (
        prepare_workflow(
            finding["finding_id"], workflow_mapper=mapper, conn=finding["conn"]
        )
        is None
    )


def test_fills_target_and_port(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[0]
    assert "10.0.0.1" in cmd.filled and "445" in cmd.filled
    assert "<TARGET>" not in cmd.filled and "<PORT>" not in cmd.filled


def test_old_variant_tokens_are_filled(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[5]
    assert "IP_address" not in cmd.filled and "$PORT" not in cmd.filled
    assert "10.0.0.1" in cmd.filled and "445" in cmd.filled


def test_allowlisted_installed_command_is_executable(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[0]
    assert cmd.executable is True
    assert cmd.manual_reason is None
    assert cmd.target_binary == "sh"


def test_not_allowlisted_command_is_manual(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[1]  # nmap, fully filled but not in allowlist
    assert cmd.executable is False
    assert "allowlist" in (cmd.manual_reason or "")


def test_unresolved_interface_marks_manual_and_is_listed(finding, tmp_path):
    prepared = _prep(finding, tmp_path)
    cmd = _cmds(prepared)[2]  # responder -I <INTERFACE>
    assert cmd.executable is False
    assert "<INTERFACE>" in (cmd.manual_reason or "")
    assert "<INTERFACE>" in prepared.unresolved_placeholders


def test_prose_command_is_manual(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[4]
    assert cmd.executable is False


def test_credential_command_flags_needs_credential(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[3]
    assert cmd.needs_credential is True


def test_credential_injection_uses_placeholder_not_secret(finding, tmp_path):
    cred = {"username": "admin", "secret_kind": "password", "ref": "nxc:1"}
    cmd = _cmds(_prep(finding, tmp_path, credential=cred))[3]
    assert "-u admin" in cmd.filled
    assert "@cred:nxc:1@" in cmd.filled
    assert "<USERNAME>" not in cmd.filled and "<PASSWORD>" not in cmd.filled


def test_credential_placeholder_unresolved_without_credential(finding, tmp_path):
    cmd = _cmds(_prep(finding, tmp_path))[3]  # no credential passed
    assert cmd.executable is False
    assert "<USERNAME>" in cmd.filled or "<PASSWORD>" in cmd.filled


def test_grouped_plugin_key_resolves(finding, tmp_path):
    mapper = _mapper_with(
        tmp_path,
        [
            {
                "plugin_id": "90317,57608,70658",
                "workflow_name": "G",
                "description": "d",
                "steps": _STEPS,
            }
        ],
    )
    prepared = prepare_workflow(
        finding["finding_id"],
        workflow_mapper=mapper,
        allowlist=["sh"],
        denylist=[],
        conn=finding["conn"],
    )
    assert prepared is not None and prepared.workflow_name == "G"


# --- Guard: the bundled YAML uses only the canonical placeholder vocabulary. ---

_FORBIDDEN_TOKENS = [
    "IP_address",
    "$IP",
    "$PORT",
    "<target>",
    "<port>",
    "<username>",
    "<user>",
    "<password>",
    "<interface>",
]


def test_bundled_workflow_yaml_uses_canonical_placeholders():
    mapper = WorkflowMapper()  # loads the packaged workflow_mappings.yaml
    offenders = []
    for wf in {w.workflow_name: w for w in mapper.workflows.values()}.values():
        for step in wf.steps:
            for cmd in step.commands:
                for tok in _FORBIDDEN_TOKENS:
                    if tok in cmd:
                        offenders.append((wf.workflow_name, tok, cmd))
    assert not offenders, f"non-canonical placeholder tokens remain: {offenders}"
