# Cerno Demo Scans

This directory contains two synthetic Nessus exports for demos, screenshots, and
first-time exploration:

- `cerno-demo-initial.nessus` - smaller baseline scan for first import and
  comparison demos.
- `cerno-demo-expanded.nessus` - larger follow-up scan for screenshots,
  richer review demos, `[H] Compare`, `[O] Overlapping`, workflows, and
  Metasploit examples.
- `nxc-workspace/` - synthetic NetExec workspace with SMB, SSH, FTP, VNC,
  LDAP, and RDP databases for enrichment demos.

Both fixtures use documentation-only IP ranges from RFC 5737 and `.example`
hostnames. They are not scanner output from a real environment.

## Import And Review

From the repository root:

```bash
cerno demo
cerno review
```

For a throwaway local demo that does not touch your normal `~/.cerno` state:

```bash
export HOME=/tmp/cerno-demo
cerno demo
cerno review
```

To demonstrate cross-scan comparison:

```bash
cerno scan compare Cerno_Demo_Initial_Scan Cerno_Demo_Expanded_Scan
```

To demonstrate NetExec enrichment with the expanded scan:

```bash
export HOME=/tmp/cerno-demo
cerno demo
cerno review
```

Open an SMB, SSH, FTP, VNC, LDAP, or RDP finding and press `[N]` for the per-host NetExec
breakdown.

`cerno demo` imports both demo Nessus scans and sets `nxc_workspace_path` to the
bundled synthetic NetExec workspace. Use `cerno demo --no-nxc` to skip NetExec
configuration or `cerno demo --overwrite` to replace previously imported demo
scans if the fixture content changed.

For screenshot capture, see [SCREENSHOT_GUIDE.md](SCREENSHOT_GUIDE.md).

## Demo Coverage

The initial scan imports as 5 synthetic hosts and 11 Cerno findings. The
expanded scan imports as 42 synthetic hosts and 45 Cerno findings. Together they
make `cerno scan compare` useful while keeping the first review approachable.

- Critical, high, medium, low, and info severity buckets.
- Findings with bundled workflow mappings, including SMB signing, weak SSL/TLS,
  SSH service checks, SNMP default community strings, browsable web directories,
  ICMP timestamp disclosure, Telnet, and internal IP disclosure.
- Repeated host:port sets for comparison and overlap views.
- Deliberate identical host:port groups for `[H] Compare`, including TLS, SSH,
  and web-header findings.
- Deliberate superset/subset relationships for `[O] Overlapping`, including SMB
  signing covering SMB share and MS17-010 findings, and web-header findings
  covering cookie flag findings.
- CVE tags for bulk CVE extraction.
- Plugin output on affected hosts for finding detail views.
- Synthetic Metasploit module mappings for Telnet, VNC, MS17-010, Shellshock,
  and Tomcat search demos.
- Synthetic NetExec data for SMB signing, share access, domain credentials,
  SSH keys, FTP anonymous login, VNC service presence, LDAP signing, and RDP
  NLA context.
- Mixed host types: web, API, SMB/file, domain controller, database, legacy,
  VPN, mail, monitoring, backup, Linux, Windows workstation, shopping app, CI,
  Git, and IPv6 web targets.
- Documentation IPv4 ranges and one documentation IPv6 address.

Use this fixture for training and conference demos, not for validating scanner
fidelity. It is shaped for Cerno workflow coverage rather than for exact Nessus
plugin semantics.
