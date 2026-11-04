# Cerno Demo Scans

This directory contains synthetic scanner exports for demos, screenshots, and
first-time exploration — two Nessus scans and two matching nuclei scans, so
`cerno demo` exercises both import paths:

- `cerno-demo-initial.nessus` - smaller baseline scan for first import and
  comparison demos.
- `cerno-demo-expanded.nessus` - larger follow-up scan for screenshots,
  richer review demos, `[H] Compare`, `[O] Overlapping`, workflows, and
  Metasploit examples.
- `cerno-demo-nuclei-initial.json` - nuclei baseline covering the web services
  the initial Nessus scan discovered.
- `cerno-demo-nuclei-expanded.json` - nuclei follow-up covering the expanded
  scan's web services, including the critical and high findings.
- `nxc-workspace/` - synthetic NetExec workspace with SMB, SSH, FTP, VNC,
  LDAP, and RDP databases for enrichment demos.

All fixtures use documentation-only IP ranges from RFC 5737, one RFC 3849 IPv6
address, and `.example` hostnames. They are not scanner output from a real
environment — which is also why running the suggested nuclei command against
them produces an empty file: none of the targets resolve. The bundled nuclei
exports exist precisely so no live scan is needed.

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

To demonstrate cross-scan comparison, within each source:

```bash
cerno scan compare Cerno_Demo_Initial_Scan Cerno_Demo_Expanded_Scan
cerno scan compare Cerno_Demo_Nuclei_Initial_Scan Cerno_Demo_Nuclei_Expanded_Scan
```

Comparing *across* sources is refused by design: plugin IDs are namespaced per
source, so a Nessus scan and a nuclei scan share none and every finding would be
reported as both new and resolved.

To review both scanners together, run `cerno review` and select a Nessus and a
nuclei scan at the prompt (e.g. `2,4`).

To demonstrate NetExec enrichment with the expanded scan:

```bash
export HOME=/tmp/cerno-demo
cerno demo
cerno review
```

Open an SMB, SSH, FTP, VNC, LDAP, or RDP finding and press `[N]` for the per-host NetExec
breakdown.

`cerno demo` imports all four demo scans (two Nessus, two nuclei) and sets
`nxc_workspace_path` to the bundled synthetic NetExec workspace. Use `cerno demo --no-nxc` to skip NetExec
configuration or `cerno demo --overwrite` to replace previously imported demo
scans if the fixture content changed.

`cerno demo` reads these files from `docs/demo/` in a source checkout and falls
back to the identical packaged copy in `cerno_pkg/demo/` (used by pipx/pip
installs). If you regenerate the NetExec workspace with
`scripts/create_demo_nxc_workspace.py` (which writes to `docs/demo/nxc-workspace`
by default), copy the result into `cerno_pkg/demo/nxc-workspace` too.
`tests/test_demo_command.py` fails if the two trees drift apart.

## Regenerating The nuclei Fixtures

```bash
python3 scripts/create_demo_nuclei_results.py      # writes both trees
```

The generator **parses the two `.nessus` files to derive its target list**,
reproducing the `v_http_services` selection logic, so a finding can only ever
land on a host:port that actually exists in the corresponding Nessus scan. A
spec naming an unknown target is a hard error rather than a silently wrong
fixture. Output is deterministic, so regenerating an unchanged fixture produces
a byte-identical file.

Every `template-id`, name, severity, tag, author and classification is copied
verbatim from the upstream template in projectdiscovery/nuclei-templates;
inventing plausible-looking template metadata would make the demo misleading.

Two deliberate differences from a raw `nuclei -je` file:

- `request`/`response` are omitted, as if the run used `-or`. Cerno discards
  them at import and they would bloat the files roughly twenty-fold.
- `template-path` uses a neutral `/opt/nuclei-templates` prefix instead of a
  real home directory, which the real field would leak.

## Demo Coverage

The initial Nessus scan imports as 5 synthetic hosts and 11 Cerno findings; the
expanded one as 42 hosts and 45 findings. The nuclei scans add 9 and 17 findings
respectively, **without adding a single host row** — they target the same
host:port pairs, so both scanners' findings hang off the same hosts. Together
they make `cerno scan compare` useful while keeping the first review
approachable.

### What The Two Scanners Show Together

The nuclei fixtures are shaped to demonstrate why a second scanner is worth
running at all:

**Corroboration** — nuclei confirms Nessus findings on the same host:port:

| Nessus plugin | nuclei template |
|---|---|
| 20007 SSL Version 2 and 3, 42873 Medium Strength Ciphers | `deprecated-tls`, `weak-cipher-suites` |
| 11219 SSL Self-Signed Certificate, 104743 TLS 1.0 | `self-signed-ssl`, `deprecated-tls` |
| 57582 SSL Certificate Expiry, 78479 POODLE | `expired-ssl`, `deprecated-tls` |
| 45411 SSL Certificate with Wrong Hostname | `mismatched-ssl-certificate` |
| 10107 HTTP Server Type and Version | `nginx-version`, `tech-detect` |
| 56468 Apache Unsupported Version | `apache-detect` |
| 34970 Apache Tomcat Default Files | `tomcat-detect` |
| 40984 Web Server Directory Enumeration | `robots-txt` |

**The same evidence, two scanner models.** On each of the six `203.0.113.8x`
shop hosts, Nessus reports three separate plugins — 84502 HSTS Not Enforced,
85601 X-Frame-Options Not Set, 98033 CSP Not Set. nuclei reports all three as
*matcher names on one* `http-missing-security-headers` finding, which Cerno
merges into a single host:port row's plugin output. Open that finding on
`203.0.113.80` to see both shapes side by side.

**What only nuclei found** — the reason to run both:

| nuclei template | Severity | Host | Why Nessus missed it |
|---|---|---|---|
| `CVE-2021-44228` (Log4Shell) | Critical | `198.51.100.31:8080` | No Nessus web finding on this host at all |
| `CVE-2021-41773` (Apache path traversal) | High | `198.51.100.12:8080` | Nessus only flags the unsupported version |
| `tomcat-default-login` | High | `198.51.100.90:8080` | Nessus finds default *files*, not default *credentials* |
| `phpmyadmin-panel` | Info | `198.51.100.12:8080` | Exposed panel Nessus did not enumerate |

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
