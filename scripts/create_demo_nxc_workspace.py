#!/usr/bin/env python3
"""Create synthetic NetExec databases for Cerno demos.

The generated workspace is intentionally small and read-only-demo oriented.
Each database starts as a copy of the real (empty) NetExec 1.5.1 schema in
``tests/fixtures/nxc/`` so the demo exercises exactly what NetExec writes.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
from pathlib import Path


SMB_HOSTS = [
    (1, "198.51.100.20", "FILE01", "DEMO", "Windows Server 2019", 0, 0, 0, 0),
    (2, "198.51.100.21", "FILE02", "DEMO", "Windows Server 2016", 1, 0, 0, 1),
    (3, "198.51.100.30", "DC01", "DEMO", "Windows Server 2019 Domain Controller", 0, 0, 1, 1),
    (4, "198.51.100.32", "DB01", "DEMO", "Windows Server 2012 R2", 1, 0, 0, 0),
    (5, "203.0.113.63", "BACKUP", "DEMO", "Windows Server 2019", 0, 0, 0, 0),
    (6, "198.51.100.60", "WIN01", "DEMO", "Windows 10 Enterprise", 0, 0, 0, 0),
    (7, "198.51.100.61", "WIN02", "DEMO", "Windows 10 Enterprise", 0, 0, 0, 0),
    (8, "198.51.100.62", "WIN03", "DEMO", "Windows 10 Enterprise", 0, 0, 0, 0),
    (9, "198.51.100.63", "WIN04", "DEMO", "Windows 10 Enterprise", 0, 0, 0, 0),
    (10, "198.51.100.64", "WIN05", "DEMO", "Windows 11 Enterprise", 0, 0, 0, 0),
    (11, "198.51.100.65", "WIN06", "DEMO", "Windows 11 Enterprise", 0, 1, 0, 0),
]

SMB_USERS = [
    (1, "DEMO", "da.backup", "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", "hash"),
    (2, "DEMO", "svc_deploy", "SyntheticPassword!23", "plaintext"),
    (3, "DEMO", "auditor", "SyntheticAudit!23", "plaintext"),
    (4, "DEMO", "helpdesk", "SyntheticHelpdesk!23", "plaintext"),
    (5, "DEMO", "sql_svc", "SyntheticSql!23", "plaintext"),
]

SMB_ADMIN_RELATIONS = [
    (1, 1, 3),
    (2, 1, 5),
    (3, 2, 8),
    (4, 2, 9),
    (5, 4, 6),
]

SMB_LOGGEDIN_RELATIONS = [
    (1, 2, 6),
    (2, 2, 7),
    (3, 2, 8),
    (4, 2, 9),
    (5, 2, 10),
    (6, 3, 1),
    (7, 3, 2),
    (8, 3, 5),
    (9, 4, 6),
    (10, 4, 7),
    (11, 5, 4),
]

SMB_SHARES = [
    (1, 1, "ADMIN$", 1, 0),
    (2, 1, "C$", 1, 1),
    (3, 1, "Projects", 1, 0),
    (4, 2, "ADMIN$", 1, 0),
    (5, 2, "C$", 1, 1),
    (6, 2, "Public", 1, 1),
    (7, 3, "SYSVOL", 1, 0),
    (8, 3, "NETLOGON", 1, 0),
    (9, 4, "backups", 1, 0),
    (10, 4, "db_exports", 1, 1),
    (11, 5, "restore", 1, 0),
    (12, 5, "backups", 1, 1),
    (13, 6, "public", 1, 0),
    (14, 7, "public", 1, 0),
    (15, 8, "public", 1, 0),
    (16, 9, "public", 1, 0),
]

SSH_HOSTS = [
    (1, "198.51.100.11", 22, "SSH-2.0-OpenSSH_8.4", "Linux"),
    (2, "198.51.100.31", 22, "SSH-2.0-OpenSSH_8.2", "Linux"),
    (3, "198.51.100.50", 22, "SSH-2.0-OpenSSH_8.9", "Linux"),
    (4, "198.51.100.51", 22, "SSH-2.0-OpenSSH_8.9", "Linux"),
    (5, "198.51.100.52", 22, "SSH-2.0-OpenSSH_8.9", "Linux"),
    (6, "198.51.100.53", 22, "SSH-2.0-OpenSSH_8.4", "Linux"),
    (7, "198.51.100.54", 22, "SSH-2.0-OpenSSH_8.4", "Linux"),
    (8, "198.51.100.55", 22, "SSH-2.0-OpenSSH_8.4", "Linux"),
    (9, "203.0.113.62", 22, "SSH-2.0-OpenSSH_9.0", "Linux"),
    (10, "203.0.113.63", 22, "SSH-2.0-OpenSSH_8.9", "Linux"),
]

SSH_CREDS = [
    (1, "ops", "SyntheticOpsKey", "key"),
    (2, "deploy", "SyntheticDeploy!23", "plaintext"),
    (3, "root", "SyntheticRootKey", "key"),
]

SSH_ADMIN_RELATIONS = [
    (1, 1, 3),
    (2, 1, 4),
    (3, 1, 5),
    (4, 3, 10),
]

SSH_LOGGEDIN_RELATIONS = [
    (1, 2, 1, 1),
    (2, 2, 2, 1),
    (3, 2, 6, 1),
    (4, 2, 7, 1),
    (5, 2, 8, 1),
    (6, 1, 9, 1),
]


LDAP_HOSTS = [
    # id, ip, hostname, domain, os, signing_required, channel_binding
    (1, "198.51.100.30", "DC01", "DEMO", "Windows Server 2019 Domain Controller", 0, "Never"),
]

RDP_HOSTS = [
    # id, ip, port, hostname, domain, os, nla
    (1, "198.51.100.30", 3389, "DC01", "DEMO", "Windows Server 2019 Domain Controller", 1),
    (2, "198.51.100.60", 3389, "WIN01", "DEMO", "Windows 10 Enterprise", 0),
    (3, "198.51.100.61", 3389, "WIN02", "DEMO", "Windows 10 Enterprise", 0),
    (4, "198.51.100.62", 3389, "WIN03", "DEMO", "Windows 10 Enterprise", 1),
]


def _from_template(schema_dir: Path, protocol: str, output: Path) -> sqlite3.Connection:
    """Copy the empty real-schema DB for ``protocol`` and open it for seeding."""
    path = output / f"{protocol}.db"
    shutil.copyfile(schema_dir / f"{protocol}.db", path)
    return sqlite3.connect(path)


def create_smb_db(conn: sqlite3.Connection) -> None:
    conn.executemany(
        "INSERT INTO hosts (id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        SMB_HOSTS,
    )
    conn.executemany(
        "INSERT INTO users (id, domain, username, password, credtype) VALUES (?, ?, ?, ?, ?)",
        SMB_USERS,
    )
    conn.executemany(
        "INSERT INTO admin_relations (id, userid, hostid) VALUES (?, ?, ?)", SMB_ADMIN_RELATIONS
    )
    conn.executemany(
        "INSERT INTO loggedin_relations (id, userid, hostid) VALUES (?, ?, ?)",
        SMB_LOGGEDIN_RELATIONS,
    )
    conn.executemany(
        "INSERT INTO shares (id, hostid, name, read, write) VALUES (?, ?, ?, ?, ?)",
        SMB_SHARES,
    )


def create_ssh_db(conn: sqlite3.Connection) -> None:
    conn.executemany("INSERT INTO hosts (id, host, port, banner, os) VALUES (?, ?, ?, ?, ?)", SSH_HOSTS)
    conn.executemany(
        "INSERT INTO credentials (id, username, password, credtype) VALUES (?, ?, ?, ?)", SSH_CREDS
    )
    conn.executemany(
        "INSERT INTO admin_relations (id, credid, hostid) VALUES (?, ?, ?)", SSH_ADMIN_RELATIONS
    )
    conn.executemany(
        "INSERT INTO loggedin_relations (id, credid, hostid, shell) VALUES (?, ?, ?, ?)",
        SSH_LOGGEDIN_RELATIONS,
    )


def create_ftp_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO hosts (id, host, port, banner) VALUES (1, '198.51.100.33', 21, 'vsFTPd 2.3.4')"
    )
    conn.execute("INSERT INTO credentials (id, username, password) VALUES (1, 'anonymous', '')")
    conn.execute("INSERT INTO loggedin_relations (id, credid, hostid) VALUES (1, 1, 1)")


def create_vnc_db(conn: sqlite3.Connection) -> None:
    # Real vnc schema has no relations table: host presence + banner only.
    conn.execute(
        "INSERT INTO hosts (id, ip, hostname, port, server_banner) "
        "VALUES (1, '198.51.100.33', 'legacy01.demo.example', 5900, 'RFB 003.003')"
    )


def create_ldap_db(conn: sqlite3.Connection) -> None:
    conn.executemany(
        "INSERT INTO hosts (id, ip, hostname, domain, os, signing_required, channel_binding) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        LDAP_HOSTS,
    )


def create_rdp_db(conn: sqlite3.Connection) -> None:
    conn.executemany(
        "INSERT INTO hosts (id, ip, port, hostname, domain, os, nla) VALUES (?, ?, ?, ?, ?, ?, ?)",
        RDP_HOSTS,
    )


DEMO_DBS = {
    "smb": create_smb_db,
    "ssh": create_ssh_db,
    "ftp": create_ftp_db,
    "vnc": create_vnc_db,
    "ldap": create_ldap_db,
    "rdp": create_rdp_db,
}


def create_workspace(output: Path, schema_dir: Path) -> None:
    if output.exists():
        for child in output.iterdir():
            if child.is_file() and child.suffix == ".db":
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)
    output.mkdir(parents=True, exist_ok=True)

    for protocol, populate in DEMO_DBS.items():
        conn = _from_template(schema_dir, protocol, output)
        populate(conn)
        conn.commit()
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/demo/nxc-workspace"),
        help="Workspace directory to create. Defaults to docs/demo/nxc-workspace.",
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "nxc",
        help="Directory of empty real-schema NetExec DBs to copy. Defaults to tests/fixtures/nxc.",
    )
    args = parser.parse_args()

    create_workspace(args.output, args.schema_dir)
    print(f"Created demo NetExec workspace: {args.output}")
    print("Databases: " + ", ".join(f"{p}.db" for p in DEMO_DBS))


if __name__ == "__main__":
    main()
