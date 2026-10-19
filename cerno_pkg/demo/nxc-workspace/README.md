# Demo NetExec Workspace

This directory is a synthetic NetExec workspace for Cerno demos. It contains
SQLite databases built from the real NetExec 1.5.1 schemas (copied from
`tests/fixtures/nxc/`), so the demo exercises exactly what NetExec writes.

It is not output from a real assessment.

## Contents

- `smb.db` - SMB hosts, credentials, admin/logged-in relations, shares, and
  security flags.
- `ssh.db` - SSH hosts and working credentials.
- `ftp.db` - FTP anonymous access for the legacy demo host.
- `vnc.db` - VNC service presence and banner for the legacy demo host.
- `ldap.db` - Domain controller with LDAP signing not required.
- `rdp.db` - RDP hosts, some with NLA disabled.

## Use With Cerno

Option 1: point Cerno directly at this workspace:

```bash
cerno config set nxc_workspace_path docs/demo/nxc-workspace
cerno config set nxc_enrichment_enabled true
```

Option 2: copy it into a throwaway demo HOME as the default workspace:

```bash
export HOME=/tmp/cerno-demo
mkdir -p "$HOME/.nxc/workspaces"
cp -R docs/demo/nxc-workspace "$HOME/.nxc/workspaces/default"
```

Then import the demo Nessus scan and review:

```bash
cerno import nessus docs/demo/cerno-demo-expanded.nessus
cerno review
```

Findings that touch SMB, SSH, FTP, VNC, LDAP, or RDP hosts should display NetExec context
in the finding detail view. Press `[N]` for the per-host breakdown.

## Regenerate

From the repository root:

```bash
scripts/create_demo_nxc_workspace.py
```

The generator overwrites the demo databases in `docs/demo/nxc-workspace`.
