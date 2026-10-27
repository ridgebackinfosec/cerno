"""Tests for the workflow contribution feedback loop (cerno_pkg.workflow_contrib).

Covers the pure sanitizer (``genericize_command``), the fail-closed leak gate
(``scan_for_leaks`` / ``scan_candidate``), candidate classification
(new / enhanced / skip) from a seeded execution trail, and YAML round-trip through
``WorkflowMapper.load_additional_workflows``.
"""

from pathlib import Path

import pytest
import yaml

from cerno_pkg import workflow_contrib as wc
from cerno_pkg.models import Finding, Host, Plugin, Port, Scan, ToolExecution
from cerno_pkg.workflow_mapper import WorkflowMapper

HOSTS = ["10.20.0.11", "10.20.0.15", "dc01.acme.local", "DC01"]
PORTS = ["445"]


# ---------------------------------------------------------------------------
# genericize_command
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGenericizeCommand:
    def test_literal_hosts_and_port_collapse(self):
        out = wc.genericize_command(
            "nmap -p 445 --script smb-protocols 10.20.0.11 10.20.0.15", HOSTS, PORTS
        )
        assert out == "nmap -p <PORT> --script smb-protocols <TARGET>"

    def test_ip_boundary_not_prefix_matched(self):
        # 10.20.0.1 must not eat the prefix of 10.20.0.15
        out = wc.genericize_command("nmap 10.20.0.15", ["10.20.0.1"], PORTS)
        assert out == "nmap 10.20.0.15"

    def test_input_list_and_output_paths(self):
        cmd = (
            "sudo nmap -A --script=smb2-security-mode "
            "-iL /home/op/.cerno/artifacts/acme-q4/High/x/run-1/tcp_ips.list "
            "-p 445 -oA /home/op/.cerno/artifacts/acme-q4/High/x/run-1"
        )
        out = wc.genericize_command(cmd, HOSTS, PORTS)
        assert out == "sudo nmap -A --script=smb2-security-mode <TARGET> -p <PORT>"

    def test_attached_port_and_output_forms(self):
        out = wc.genericize_command("nmap -p445 -oX/tmp/a.xml 10.20.0.11", HOSTS, PORTS)
        assert out == "nmap -p <PORT> <TARGET>"

    def test_non_finding_port_kept(self):
        out = wc.genericize_command("nmap -p 1-1000 10.20.0.11", HOSTS, PORTS)
        assert out == "nmap -p 1-1000 <TARGET>"

    def test_numeric_flags_untouched(self):
        out = wc.genericize_command(
            "nmap -T4 --min-rate 445 -p 445 10.20.0.11", HOSTS, PORTS
        )
        assert out == "nmap -T4 --min-rate 445 -p <PORT> <TARGET>"

    def test_nxc_target_file_creds_and_logs(self):
        cmd = (
            "nxc smb /home/op/.cerno/artifacts/_mcp/418/run-p2x1/targets.txt "
            "-u svc_scan -d ACME -p ******** --gen-relay-list /home/op/x/relay.txt "
            "--shares --log /home/op/x/nxc.smb.log"
        )
        out = wc.genericize_command(cmd, HOSTS, PORTS)
        assert out == (
            "nxc smb <TARGET> -u <USERNAME> -d <DOMAIN> -p <PASSWORD> "
            "--gen-relay-list relay_targets.txt --shares"
        )

    def test_cred_placeholder_and_hash(self):
        out = wc.genericize_command(
            "netexec smb 10.20.0.11 -u admin -H @cred:smb:4@", HOSTS, PORTS
        )
        assert out == "netexec smb <TARGET> -u <USERNAME> -H <PASSWORD>"

    def test_nxc_dash_p_is_never_a_port(self):
        out = wc.genericize_command("nxc smb 10.20.0.11 -u a -p 445", HOSTS, PORTS)
        assert out == "nxc smb <TARGET> -u <USERNAME> -p <PASSWORD>"

    def test_proxychains_stripped_sudo_kept(self):
        out = wc.genericize_command(
            "sudo proxychains4 -q nmap -sV 10.20.0.11", HOSTS, PORTS
        )
        assert out == "sudo nmap -sV <TARGET>"

    def test_absolute_binary_path_basenamed(self):
        out = wc.genericize_command("/usr/bin/nmap -sV 10.20.0.11", HOSTS, PORTS)
        assert out == "nmap -sV <TARGET>"

    def test_hostnames_and_host_port_forms(self):
        out = wc.genericize_command(
            "curl -k https://dc01.acme.local:445/x && smbclient -L //DC01", HOSTS, PORTS
        )
        assert out == "curl -k https://<TARGET>:<PORT>/x && smbclient -L //<TARGET>"

    def test_quoted_script_arg_requoted(self):
        out = wc.genericize_command(
            "nmap --script 'snmp* and not snmp-brute' 10.20.0.11", HOSTS, PORTS
        )
        assert out == 'nmap --script "snmp* and not snmp-brute" <TARGET>'


# ---------------------------------------------------------------------------
# scan_for_leaks / baseline / normalization
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx():
    return wc.LeakContext(
        host_identifiers=["10.20.0.99", "web02.acme.local", "WEB02"],
        scan_names=["acme-internal-2026q4"],
        extra=["ACME"],
        usernames=["svc_scan", "anonymous"],
        secrets=["S3cr3t!pw", "anonymous"],
    )


@pytest.mark.unit
class TestScanForLeaks:
    def test_clean(self, ctx):
        assert (
            wc.scan_for_leaks("nmap -p <PORT> --script smb-protocols <TARGET>", ctx)
            == []
        )

    def test_residual_ipv4_and_cidr(self, ctx):
        assert wc.scan_for_leaks("nmap 192.168.4.7", ctx)
        assert wc.scan_for_leaks("nmap 172.16.0.0/16", ctx)

    def test_residual_ipv6(self, ctx):
        assert wc.scan_for_leaks("nmap -6 fe80::1ff:fe23:4567:890a", ctx)

    def test_allowed_loopback_and_any(self, ctx):
        assert wc.scan_for_leaks("tcpdump src 0.0.0.0 and dst 127.0.0.1", ctx) == []

    def test_identifiers(self, ctx):
        assert wc.scan_for_leaks("worst on WEB02", ctx)
        assert wc.scan_for_leaks("see web02.acme.local", ctx)
        assert wc.scan_for_leaks("from acme-internal-2026q4", ctx)
        assert wc.scan_for_leaks("-u svc_scan", ctx)

    def test_identifier_case_insensitive(self, ctx):
        assert wc.scan_for_leaks("worst on web02", ctx)

    def test_paths_only_when_checked(self, ctx):
        assert wc.scan_for_leaks("cat /home/op/loot.txt", ctx)
        assert wc.scan_for_leaks("cat ~/loot.txt", ctx)
        assert wc.scan_for_leaks("cat /home/op/loot.txt", ctx, check_paths=False) == []
        # SMB UNC-style target paths are not filesystem paths
        assert wc.scan_for_leaks("smbclient -L //<TARGET>", ctx) == []

    def test_generic_username_never_flags(self, ctx):
        # "anonymous" is both a nxc username and the anon-FTP password here.
        assert wc.scan_for_leaks("ftp -n <TARGET>  # login anonymous", ctx) == []
        assert wc.scan_for_leaks("FTP Anonymous Login", ctx) == []
        assert wc.scan_for_leaks("weak/anonymous/export ciphers", ctx) == []

    def test_usernames_skipped_only_when_asked(self, ctx):
        assert wc.scan_for_leaks("owned by svc_scan", ctx)
        assert wc.scan_for_leaks("owned by svc_scan", ctx, check_usernames=False) == []
        # host/scan/domain identifiers are still checked without usernames
        assert wc.scan_for_leaks("on WEB02", ctx, check_usernames=False)
        assert wc.scan_for_leaks("ACME domain", ctx, check_usernames=False)

    def test_secret_value_flagged_and_redacted(self, ctx):
        hits = wc.scan_for_leaks("smbclient -U x%S3cr3t!pw //<TARGET>/c$", ctx)
        assert hits == ["credential secret value (redacted)"]
        assert all("S3cr3t" not in h for h in hits)
        # case-sensitive, boundary-anchored
        assert wc.scan_for_leaks("s3cr3t!pw", ctx, check_paths=False) == []

    @pytest.mark.parametrize(
        "text",
        [
            "nxc smb <TARGET> -H 31d6cfe0d16ae931b73c59d7e0c089c0",
            "secretsdump.py -hashes "
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 <TARGET>",
        ],
    )
    def test_hash_literal_flagged_and_redacted(self, ctx, text):
        hits = wc.scan_for_leaks(text, ctx)
        assert hits == ["password hash literal (redacted)"]

    def test_longer_hex_is_not_a_hash(self, ctx):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert wc.scan_for_leaks(f"git checkout {sha1}", ctx) == []

    def test_local_paths_only(self, ctx):
        flag = dict(check_paths=False, local_paths_only=True)
        assert wc.scan_for_leaks("output in /home/op/loot", ctx, **flag)
        assert wc.scan_for_leaks("see ~/.cerno/x", ctx, **flag)
        assert (
            wc.scan_for_leaks("HTTP TRACE / TRACK Methods Allowed", ctx, **flag) == []
        )
        assert wc.scan_for_leaks("Web Server /cgi-bin/ Listing", ctx, **flag) == []


@pytest.mark.unit
class TestBaseline:
    @pytest.mark.parametrize(
        "cmd",
        [
            "nmap -A <TARGET> -p <PORT>",
            "sudo nmap -A -Pn <TARGET> -p <PORT>",
            "nxc smb <TARGET>",
            "nxc smb <TARGET> -u <USERNAME> -d <DOMAIN> -p <PASSWORD> "
            "--gen-relay-list relay_targets.txt --shares",
        ],
    )
    def test_baseline(self, cmd):
        assert wc.is_baseline_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        [
            "nmap -p <PORT> --script smb-protocols <TARGET>",
            "nmap --script=ssl-enum-ciphers <TARGET>",
            "nxc smb <TARGET> -M spooler",
            "smbclient -L //<TARGET>",
        ],
    )
    def test_not_baseline(self, cmd):
        assert not wc.is_baseline_command(cmd)


# ---------------------------------------------------------------------------
# build_candidate (integration: temp_db + custom mapper)
# ---------------------------------------------------------------------------


def _seed(
    conn,
    plugin_id=96982,
    hosts=("10.20.0.11", "10.20.0.15"),
    ports=(445,),
    plugin_name="SMB Protocol Version 1 Enabled",
):
    scan_id = Scan(scan_name="acme-internal-2026q4", export_root="/tmp").save(conn)
    Plugin(
        plugin_id=plugin_id,
        plugin_name=plugin_name,
        severity_int=2,
        cves=["CVE-2017-0144"],
        plugin_url=f"https://www.tenable.com/plugins/nessus/{plugin_id}",
    ).save(conn)
    fid = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
    for ip in hosts:
        hid = Host.get_or_create(ip, ip, "ipv4", netbios_name="DC01", conn=conn)
        for p in ports:
            Port.get_or_create(p, conn=conn)
            conn.execute(
                "INSERT OR IGNORE INTO finding_affected_hosts "
                "(finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, 'o')",
                (fid, hid, p),
            )
    conn.commit()
    return fid


def _exec(conn, fid, command_text, exit_code=0, tool_name="mcp"):
    eid = ToolExecution(
        finding_id=fid,
        tool_name=tool_name,
        command_text=command_text,
        exit_code=exit_code,
    ).save(conn)
    conn.commit()
    return eid


def _mapper(tmp_path, workflows):
    path = tmp_path / "wf.yaml"
    path.write_text(yaml.safe_dump({"version": "1.0", "workflows": workflows}))
    return WorkflowMapper(yaml_path=path)


EMPTY = []
SMB_WORKFLOW = {
    "plugin_id": "96982,57608",
    "workflow_name": "SMB checks",
    "description": "existing",
    "steps": [
        {
            "title": "Check",
            "commands": [
                "nmap -p445 --script smb-security-mode <TARGET>",
                "netexec smb <TARGET> -u <USERNAME> -p <PASSWORD>",
            ],
            "notes": "",
        }
    ],
    "references": ["https://example.org/smb"],
}


@pytest.mark.integration
class TestBuildCandidate:
    def test_new_when_unmapped(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(
            temp_db,
            fid,
            "nmap -p 445 --script smb-protocols 10.20.0.11 10.20.0.15 -oA /home/op/x",
        )
        _exec(temp_db, fid, "nxc smb 10.20.0.11 10.20.0.15")
        finding = Finding.get_by_id(fid, temp_db)
        cand = wc.build_candidate(finding, temp_db, _mapper(tmp_path, EMPTY))
        assert cand is not None and cand.reason == "new"
        assert cand.yaml_plugin_id == "96982"
        assert cand.description == "Verify: SMB Protocol Version 1 Enabled"
        titles = [s.title for s in cand.steps]
        assert titles == ["Run NSE scripts: smb-protocols", "Check with NetExec (smb)"]
        assert cand.steps[0].commands == [
            "nmap -p <PORT> --script smb-protocols <TARGET>"
        ]
        assert "https://www.tenable.com/plugins/nessus/96982" in cand.references
        assert "https://nvd.nist.gov/vuln/detail/CVE-2017-0144" in cand.references
        assert cand.review_hints

    def test_failed_and_cred_reveal_runs_ignored(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(temp_db, fid, "nmap --script smb-protocols 10.20.0.11", exit_code=1)
        _exec(temp_db, fid, "reveal_credential smb:1", tool_name="cred_reveal")
        finding = Finding.get_by_id(fid, temp_db)
        assert wc.build_candidate(finding, temp_db, _mapper(tmp_path, EMPTY)) is None

    def test_leaking_command_excluded(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(temp_db, fid, "nmap --script smb-protocols 10.20.0.11")
        leak = _exec(temp_db, fid, "nmap --script smb-vuln-ms17-010 192.168.9.9")
        finding = Finding.get_by_id(fid, temp_db)
        assess = wc.assess_candidate(finding, temp_db, _mapper(tmp_path, EMPTY))
        assert assess.candidate is not None
        assert [e["execution_id"] for e in assess.excluded] == [leak]
        all_cmds = [c for s in assess.candidate.steps for c in s.commands]
        assert all("192.168" not in c for c in all_cmds)

    def test_skip_when_existing_workflow_used_unchanged(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        # -p 445 vs -p445 / netexec vs nxc / order differences still count as "same"
        _exec(temp_db, fid, "nmap --script smb-security-mode -p 445 10.20.0.11")
        _exec(temp_db, fid, "nxc smb 10.20.0.11 -u bob -p ********")
        finding = Finding.get_by_id(fid, temp_db)
        assert (
            wc.build_candidate(finding, temp_db, _mapper(tmp_path, [SMB_WORKFLOW]))
            is None
        )

    def test_baseline_only_on_mapped_plugin_skips(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(temp_db, fid, "sudo nmap -A -iL /home/op/t.list -p 445 -oA /home/op/r")
        finding = Finding.get_by_id(fid, temp_db)
        assert (
            wc.build_candidate(finding, temp_db, _mapper(tmp_path, [SMB_WORKFLOW]))
            is None
        )

    def test_enhanced_appends_and_flags_superseded(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(temp_db, fid, "nmap -p 445 --script smb2-security-mode 10.20.0.11")
        finding = Finding.get_by_id(fid, temp_db)
        cand = wc.build_candidate(finding, temp_db, _mapper(tmp_path, [SMB_WORKFLOW]))
        assert cand is not None and cand.reason == "enhanced"
        assert cand.yaml_plugin_id == "96982,57608"  # multi-ID entry kept intact
        assert cand.workflow_name == "SMB checks"
        assert cand.steps[0].commands == SMB_WORKFLOW["steps"][0]["commands"]
        assert cand.steps[-1].title == "Additional verification (contributed)"
        assert cand.steps[-1].commands == [
            "nmap -p <PORT> --script smb2-security-mode <TARGET>"
        ]
        assert cand.new_commands == cand.steps[-1].commands
        assert cand.possibly_superseded == [
            "nmap -p445 --script smb-security-mode <TARGET>"
        ]


# ---------------------------------------------------------------------------
# Override, whole-candidate scan, YAML round-trip
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverrideAndYaml:
    def _draft(self, temp_db, tmp_path):
        fid = _seed(temp_db)
        _exec(temp_db, fid, "nmap -p 445 --script smb-protocols 10.20.0.11")
        finding = Finding.get_by_id(fid, temp_db)
        mapper = _mapper(tmp_path, EMPTY)
        return finding, mapper, wc.build_candidate(finding, temp_db, mapper)

    def test_yaml_round_trips(self, temp_db, tmp_path):
        finding, _, cand = self._draft(temp_db, tmp_path)
        text = wc.to_yaml_fragment(cand)
        assert text.startswith("#")
        assert "develop" in text and "ridgebackinfosec/cerno" in text
        path = tmp_path / "frag.yaml"
        path.write_text(text)
        m = WorkflowMapper(yaml_path=tmp_path / "missing.yaml")
        assert m.load_additional_workflows(path) == 1
        # get_workflow() would re-check the (missing) primary file and clear; read
        # the merged entry directly.
        wf = m.workflows.get("96982")
        assert wf is not None
        assert wf.steps[0].commands == [
            "nmap -p <PORT> --script smb-protocols <TARGET>"
        ]

    def test_override_is_genericized_and_validated(self, temp_db, tmp_path):
        finding, mapper, cand = self._draft(temp_db, tmp_path)
        override = {
            "workflow_name": "Confirm SMBv1 is enabled",
            "description": "Verify SMBv1",
            "steps": [
                {
                    "title": "Enumerate dialects",
                    "commands": ["nmap -p 445 --script smb-protocols 10.20.0.11"],
                    "notes": "NT LM 0.12 means SMBv1.",
                }
            ],
            "references": ["https://www.tenable.com/plugins/nessus/96982"],
        }
        edited = wc.candidate_from_override(finding, override, cand, temp_db, mapper)
        assert edited.yaml_plugin_id == "96982"
        assert edited.steps[0].commands == [
            "nmap -p <PORT> --script smb-protocols <TARGET>"
        ]
        ctx = wc.build_leak_context(finding, temp_db)
        assert wc.scan_candidate(edited, ctx) == []

    def test_override_bad_shape_rejected(self, temp_db, tmp_path):
        finding, mapper, cand = self._draft(temp_db, tmp_path)
        with pytest.raises(ValueError):
            wc.candidate_from_override(
                finding, {"steps": "nope"}, cand, temp_db, mapper
            )

    def test_scan_candidate_flags_notes_and_superseded(self, temp_db, tmp_path):
        finding, mapper, cand = self._draft(temp_db, tmp_path)
        override = {
            "workflow_name": "x",
            "description": "x",
            "steps": [
                {
                    "title": "t",
                    "commands": ["nmap <TARGET>"],
                    "notes": "worst on DC01 (10.20.0.11)",
                }
            ],
            "references": [],
        }
        edited = wc.candidate_from_override(finding, override, cand, temp_db, mapper)
        hits = wc.scan_candidate(edited, wc.build_leak_context(finding, temp_db))
        assert any("steps[0].notes" in h for h in hits)
        assert any("DC01" in h for h in hits)

    def test_anonymous_plugin_name_exports_clean(self, temp_db, tmp_path):
        """Regression: plugin 10092 'FTP Anonymous Login' with an nxc cred
        username (and anon password) 'anonymous' must not block the export."""
        fid = _seed(
            temp_db, plugin_id=10092, ports=(21,), plugin_name="FTP Anonymous Login"
        )
        _exec(temp_db, fid, "nmap -p 21 --script ftp-anon 10.20.0.11")
        finding = Finding.get_by_id(fid, temp_db)
        ctx = wc.build_leak_context(
            finding,
            temp_db,
            usernames=["anonymous"],
            secrets=["anonymous"],
        )
        cand = wc.assess_candidate(
            finding, temp_db, _mapper(tmp_path, EMPTY), ctx
        ).candidate
        assert cand is not None and cand.workflow_name == "FTP Anonymous Login"
        assert wc.scan_candidate(cand, ctx) == []

    def test_real_username_in_name_ok_but_flagged_in_notes(self, temp_db, tmp_path):
        finding, mapper, cand = self._draft(temp_db, tmp_path)
        override = {
            "workflow_name": "svc_scan check",
            "description": "svc_scan check",
            "steps": [
                {"title": "t", "commands": ["nmap <TARGET>"], "notes": "svc_scan"}
            ],
            "references": [],
        }
        edited = wc.candidate_from_override(finding, override, cand, temp_db, mapper)
        ctx = wc.build_leak_context(finding, temp_db, usernames=["svc_scan"])
        hits = wc.scan_candidate(edited, ctx)
        assert hits and all(h.startswith("steps[0].notes") for h in hits)

    @pytest.mark.parametrize(
        "field, value, needle",
        [
            ("command", "nmap --script ftp-anon 10.99.1.2", "IPv4"),
            ("command", "nmap --script ftp-anon dc01.acme.local", "identifier"),
            ("command", "ftp acme-internal-2026q4.lst", "acme-internal-2026q4"),
            ("command", "cat /home/op/loot.txt", "local path"),
            ("command", "smbclient -U x%Winter2026! //<TARGET>/c$", "secret"),
            (
                "command",
                "secretsdump.py -hashes "
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 <TARGET>",
                "hash",
            ),
            ("notes", "pw was Winter2026!", "secret"),
            ("description", "results in /home/op/acme", "local path"),
            ("description", "seen on DC01", "DC01"),
        ],
    )
    def test_override_still_fails_closed(self, temp_db, tmp_path, field, value, needle):
        finding, mapper, cand = self._draft(temp_db, tmp_path)
        step = {"title": "t", "commands": ["nmap <TARGET>"], "notes": ""}
        override = {
            "workflow_name": "x",
            "description": "x",
            "steps": [step],
            "references": [],
        }
        if field == "command":
            step["commands"] = [value]
        elif field == "notes":
            step["notes"] = value
        else:
            override[field] = value
        edited = wc.candidate_from_override(finding, override, cand, temp_db, mapper)
        ctx = wc.build_leak_context(
            finding, temp_db, usernames=["anonymous"], secrets=["Winter2026!"]
        )
        hits = wc.scan_candidate(edited, ctx)
        assert any(needle in h for h in hits), hits
        assert all("Winter2026" not in h for h in hits)
        assert all("31d6cfe0" not in h for h in hits)

    def test_copied_existing_paths_not_path_checked(self, temp_db, tmp_path):
        fid = _seed(temp_db, plugin_id=40984)
        _exec(temp_db, fid, "nmap -p 445 --script http-enum 10.20.0.11")
        finding = Finding.get_by_id(fid, temp_db)
        wf = {
            "plugin_id": "40984",
            "workflow_name": "Browse",
            "description": "d",
            "steps": [
                {
                    "title": "t",
                    "commands": ["gobuster dir -w /usr/share/wordlists/x.txt"],
                    "notes": "",
                }
            ],
            "references": [],
        }
        mapper = _mapper(tmp_path, [wf])
        cand = wc.build_candidate(finding, temp_db, mapper)
        assert cand is not None and cand.reason == "enhanced"
        assert wc.scan_candidate(cand, wc.build_leak_context(finding, temp_db)) == []


@pytest.mark.integration
def test_get_host_identifiers_and_by_finding(temp_db):
    fid = _seed(temp_db)
    finding = Finding.get_by_id(fid, temp_db)
    ids = finding.get_host_identifiers(temp_db)
    assert {"10.20.0.11", "10.20.0.15", "DC01"} <= set(ids)
    _exec(temp_db, fid, "nmap a")
    _exec(temp_db, fid, "nmap b")
    rows = ToolExecution.get_by_finding(fid, temp_db)
    assert [r.command_text for r in rows] == ["nmap a", "nmap b"]


@pytest.mark.integration
def test_prepare_workflow_fills_domain(temp_db, tmp_path):
    from cerno_pkg.workflow_prep import prepare_workflow

    fid = _seed(temp_db, plugin_id=555)
    wf = {
        "plugin_id": "555",
        "workflow_name": "w",
        "description": "d",
        "steps": [
            {
                "title": "t",
                "commands": [
                    "nxc smb <TARGET> -u <USERNAME> -d <DOMAIN> -p <PASSWORD>"
                ],
                "notes": "",
            }
        ],
        "references": [],
    }
    mapper = _mapper(tmp_path, [wf])
    cred = {
        "username": "bob",
        "domain": "CORP",
        "secret_kind": "password",
        "ref": "smb:1",
    }
    prepared = prepare_workflow(
        fid,
        credential=cred,
        workflow_mapper=mapper,
        allowlist=["*"],
        denylist=[],
        is_installed=lambda _: True,
        conn=temp_db,
    )
    assert prepared is not None
    filled = prepared.steps[0].commands[0]
    assert "-d CORP" in filled.filled and filled.executable

    no_domain = prepare_workflow(
        fid,
        credential={**cred, "domain": None},
        workflow_mapper=mapper,
        allowlist=["*"],
        denylist=[],
        is_installed=lambda _: True,
        conn=temp_db,
    )
    assert no_domain is not None
    cmd = no_domain.steps[0].commands[0]
    assert not cmd.executable and "<DOMAIN>" in no_domain.unresolved_placeholders
