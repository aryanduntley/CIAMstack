"""The record's database roles and TLS against a real server: a throwaway PostgreSQL cluster run as the current user
(initdb in a temporary folder, its own CA, a server certificate and a client certificate), set up with the script
`opsdir db-roles` writes. The migration login builds the schema as the owner; the runtime login writes governed
entries but can't create, alter or drop anything, change the secret patterns or touch the history; nobody can change
the history; upgrade keeps the runtime's grants; and the runtime signs in over verify-full TLS with its client
certificate. Skipped without the PostgreSQL server binaries or openssl."""
import os
import pathlib
import shutil
import socket
import subprocess
from types import SimpleNamespace

import psycopg
import pytest

from opsdir import operations as ops
from opsdir.core.directory import get, values
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db
from opsdir.store.roles import Roles, db_roles_sql

pytestmark = pytest.mark.integration

ROLES = Roles("opsdir_owner", "opsdir_app")
BASE = """dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-1
ciamTitle: Roles
ciamChangeStatus: approved

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners
"""
NETOPS = "https://idp.example.com/ 7f3c9a10-netops"       # an identity provider group (issuer, immutable id)
TEAM = ("dn: cn=team-a,ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\n"
        "cn: team-a\nciamOwnerKind: team\n")


def _bindir():
    """The PostgreSQL server binaries' folder (pg_config's, else the newest Debian/Ubuntu one), or None."""
    found = shutil.which("pg_config")
    if found:
        bindir = pathlib.Path(subprocess.run([found, "--bindir"], capture_output=True, encoding="utf-8").stdout.strip())
        if (bindir / "initdb").exists():
            return bindir
    candidates = sorted(pathlib.Path("/usr/lib/postgresql").glob("*/bin/initdb"))
    return candidates[-1].parent if candidates else None


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _openssl(cwd, *args):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _certificates(d):
    """A CA, a server certificate for 127.0.0.1 / localhost and a client certificate for the runtime login."""
    _openssl(d, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2",
             "-subj", "/CN=opsdir test CA")
    for name, subject, ext in (("server", "/CN=localhost", "subjectAltName=IP:127.0.0.1,DNS:localhost"),
                               ("client", f"/CN={ROLES.runtime}", "basicConstraints=CA:FALSE")):
        _openssl(d, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                 "-subj", subject)
        (d / f"{name}.ext").write_text(ext + "\n", encoding="utf-8", newline="\n")
        _openssl(d, "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                 "-out", f"{name}.crt", "-days", "2", "-extfile", f"{name}.ext")
        os.chmod(d / f"{name}.key", 0o600)


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    bindir = _bindir()
    if bindir is None or shutil.which("openssl") is None:
        pytest.skip("no PostgreSQL server binaries (initdb, pg_ctl) or openssl here")
    root = tmp_path_factory.mktemp("pgcluster")
    data, port = root / "data", _free_port()
    subprocess.run([bindir / "initdb", "-D", data, "-U", "admin", "--auth=trust", "-E", "UTF8", "--locale=C"],
                   check=True, capture_output=True)
    _certificates(root)
    with open(data / "postgresql.conf", "a", encoding="utf-8", newline="\n") as conf:
        conf.write(f"port = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{root}'\n"
                   f"ssl = on\nssl_cert_file = '{root}/server.crt'\nssl_key_file = '{root}/server.key'\n"
                   f"ssl_ca_file = '{root}/ca.crt'\n")
    (data / "pg_hba.conf").write_text("local all all trust\n"
                                      f"hostssl all {ROLES.runtime} 127.0.0.1/32 cert\n"
                                      "host all all 127.0.0.1/32 reject\n", encoding="utf-8", newline="\n")
    subprocess.run([bindir / "pg_ctl", "-D", data, "-l", root / "server.log", "-w", "start"], check=True,
                   capture_output=True)
    try:
        with psycopg.connect(f"host={root} port={port} user=admin dbname=postgres", autocommit=True) as admin:
            admin.execute("create database opsdir")
        with psycopg.connect(f"host={root} port={port} user=admin dbname=opsdir", autocommit=True) as admin:
            admin.execute(db_roles_sql(ROLES.owner, "opsdir_migrate", ROLES.runtime, "opsdir", "certificate"))
        socket_dsn = f"host={root} port={port} dbname=opsdir user="
        with db.connect(socket_dsn + "opsdir_migrate") as migrator:
            ops.init(migrator, ROLES)
            db.load_records(migrator, parse(BASE))           # the initial load: the owner's (BOOTSTRAP)
        yield SimpleNamespace(root=root, port=port, socket_dsn=socket_dsn)
    finally:
        subprocess.run([bindir / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"], capture_output=True)


def test_the_owner_owns_everything_the_migration_login_built(cluster):
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as c:
        owners = {r[0] for r in c.execute("select tableowner from pg_tables where schemaname = 'opsdir' union "
                                          "select viewowner from pg_views where schemaname = 'opsdir'")}
    assert owners == {ROLES.owner}


def test_the_runtime_writes_governed_entries(cluster):
    with db.connect(cluster.socket_dsn + ROLES.runtime) as c:
        db.apply_records(c, tuple(parse(TEAM)), "CHG-1")
        assert c.execute("select count(*) from opsdir.entry_history where dn = 'cn=team-a,ou=owners,dc=ciam-ops'"
                         ).fetchone()[0] == 1
        c.execute("select * from opsdir.v_stale_runbooks").fetchall()                # views are readable


@pytest.mark.parametrize("statement", [
    "create table opsdir.x (i int)",
    "alter table opsdir.entry add column y int",
    "drop view opsdir.v_stale_runbooks",
    "create function opsdir.f() returns int language sql as 'select 1'",
    "delete from opsdir.secret_pattern",
    "update opsdir.schema_migration set name = name",
    "update opsdir.entry_history set dn = dn",
    "delete from opsdir.entry_history",
    "truncate opsdir.entry_history"])
def test_the_runtime_cant_change_the_schema_the_patterns_or_the_history(cluster, statement):
    with db.connect(cluster.socket_dsn + ROLES.runtime) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(statement)


def test_nobody_can_change_the_history(cluster):
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as c:
        c.execute(f"set role {ROLES.owner}")
        with pytest.raises(psycopg.errors.RaiseException, match="the history is append-only"):
            c.execute("update opsdir.entry_history set dn = dn")
        with pytest.raises(psycopg.errors.RaiseException, match="the history is append-only"):
            c.execute("delete from opsdir.entry_history")


def test_upgrade_keeps_the_runtimes_grants(cluster):
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as c:
        ops.upgrade(c, ROLES)                                     # drops and re-creates every view
    with db.connect(cluster.socket_dsn + ROLES.runtime) as c:
        c.execute("select * from opsdir.v_stale_runbooks").fetchall()


def test_the_runtime_signs_in_over_verified_tls_with_its_certificate(cluster):
    r = cluster.root
    tls = (f"host=127.0.0.1 port={cluster.port} dbname=opsdir user={ROLES.runtime} sslmode=verify-full "
           f"sslrootcert={r}/ca.crt")
    with db.connect(f"{tls} sslcert={r}/client.crt sslkey={r}/client.key") as c:
        assert c.pgconn.ssl_in_use and db.effective_options(c)["sslmode"] == "verify-full"
        assert c.execute("select current_user, ssl from pg_stat_ssl join pg_stat_activity using (pid) "
                         "where pid = pg_backend_pid()").fetchone() == (ROLES.runtime, True)
    with pytest.raises(psycopg.OperationalError):                 # no client certificate: refused by the server
        db.connect(f"{tls} sslcert={r}/none.crt sslkey={r}/none.key")


def test_the_posture_of_the_runtime_and_the_migration_logins(cluster):
    r = cluster.root
    tls = (f"host=127.0.0.1 port={cluster.port} dbname=opsdir user={ROLES.runtime} sslmode=verify-full "
           f"sslrootcert={r}/ca.crt sslcert={r}/client.crt sslkey={r}/client.key")
    with db.connect(tls) as c:
        rows = {check: (status, detail) for check, status, detail in ops.posture(c)[0].rows}
    assert rows["sign-in"] == ("ok", "client certificate")
    assert rows["login privileges"] == ("ok", f"{ROLES.runtime}: rows only, no schema rights")
    assert rows["schema"][0] == "ok" and rows["server version"][0] == "ok"
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as c:
        c.execute(f"set role {ROLES.owner}")
        rows = {check: (status, detail) for check, status, detail in ops.posture(c)[0].rows}
    assert rows["login privileges"][0] == "info" and "owns the schema" in rows["login privileges"][1]


def test_the_documented_backup_restores_into_a_new_database(cluster):
    """The logical backup and restore of documentation/RECORD-DATABASE.md, as the migration login acting as the owner:
    every entry and history row comes back, the runtime keeps its rights and the store's rules hold."""
    bindir, r, port = _bindir(), cluster.root, str(cluster.port)
    login = ("-h", str(r), "-p", port, "-U", "opsdir_migrate", "--role", ROLES.owner)
    subprocess.run([bindir / "pg_dump", *login, "-Fc", "-n", "opsdir", "-f", r / "record.dump", "opsdir"], check=True,
                   capture_output=True)
    with psycopg.connect(f"host={r} port={port} user=admin dbname=postgres", autocommit=True) as admin:
        admin.execute("create database opsdir_restored")
        admin.execute(f"grant connect on database opsdir_restored to opsdir_migrate, {ROLES.runtime}")
        admin.execute(f"grant create on database opsdir_restored to {ROLES.owner}")
    subprocess.run([bindir / "pg_restore", *login, "--exit-on-error", "-d", "opsdir_restored", r / "record.dump"],
                   check=True, capture_output=True)
    counts = "select (select count(*) from opsdir.entry), (select count(*) from opsdir.entry_history)"
    with db.connect(cluster.socket_dsn + ROLES.runtime) as live:
        before = live.execute(counts).fetchone()
    restored_dsn = f"host={r} port={port} dbname=opsdir_restored user="
    with db.connect(restored_dsn + ROLES.runtime) as c:
        assert c.execute(counts).fetchone() == before and before[1] > 0
        db.apply_records(c, tuple(parse("dn: ou=owners,dc=ciam-ops\nchangetype: modify\nreplace: description\n"
                                        "description: Teams\n-\n")), "CHG-1")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("delete from opsdir.entry_history")
    with db.connect(restored_dsn + "opsdir_migrate") as c:
        c.execute(f"set role {ROLES.owner}")
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            c.execute("delete from opsdir.entry_history")
        assert ops.upgrade(c, ROLES).applied == ()                        # the migration state came along


def test_people_with_their_own_logins_propose_and_approve_each_others_changes(cluster):
    r, port = cluster.root, cluster.port
    with psycopg.connect(f"host={r} port={port} user=admin dbname=opsdir", autocommit=True) as admin:
        for person in ("alice", "bob", "carol"):
            admin.execute(f"create role {person} login in role {ROLES.runtime}")
    with db.connect(cluster.socket_dsn + ROLES.runtime) as c:
        with pytest.raises(psycopg.errors.RaiseException, match="only the schema owner writes under BOOTSTRAP"):
            db.load_records(c, parse(TEAM.replace("team-a", "team-b").replace("changetype: add\n", "")))
        ops.apply_preview(c, ops.preview_person(c, "alice", "Alice"), "CHG-1")
        ops.apply_preview(c, ops.preview_person(c, "bob", "Bob"), "CHG-1")
    with db.connect(cluster.socket_dsn + "alice") as alice:
        ops.new_change(alice, "CHG-7", "Rotate the LDAPS certificate")
        with pytest.raises(psycopg.errors.RaiseException, match="alice wrote change CHG-7 and can't approve it"):
            ops.change_status(alice, "CHG-7", "approved")
    with db.connect(cluster.socket_dsn + "carol") as carol:              # a login, but not a recorded person
        with pytest.raises(psycopg.errors.RaiseException, match="carol approves change CHG-7 but isn't a recorded"):
            ops.change_status(carol, "CHG-7", "approved")
    with db.connect(cluster.socket_dsn + "bob") as bob:
        ops.change_status(bob, "CHG-7", "approved")
        assert ops.change_lines(bob, "CHG-7") == ("change     CHG-7", "status     approved",
                                                  "title      Rotate the LDAPS certificate", "author     alice",
                                                  "approved   bob")
        assert [row[3] for row in ops.history(bob).rows if row[-1].startswith("cn=CHG-7,")] == ["alice", "bob"]


def test_once_grants_exist_the_store_checks_the_writers_and_approvers_areas(cluster):
    """Runs after the people test above (alice, bob and carol exist; alice and bob are recorded people)."""
    svc = ("dn: cn=svc-a,ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\n"
           "cn: svc-a\nciamOwnerKind: team\nciamOwner: cn=network,ou=owners,dc=ciam-ops\n")
    network = ("dn: cn=network,ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamParty\n"
               "cn: network\nciamOwnerKind: team\n")
    touch = lambda dn: (f"dn: {dn}\nchangetype: modify\nreplace: description\ndescription: touched\n-\n")  # noqa: E731
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:     # the database's break-glass sets it up
        owner.execute(f"set role {ROLES.owner}")
        db.apply_records(owner, tuple(parse(network + "\n" + svc)), "CHG-1")
        ops.apply_preview(owner, ops.preview_grant(owner, "net-apply", ("apply",), ("bob",), (), ("network",)),
                          "CHG-1")
        ops.apply_preview(owner, ops.preview_grant(owner, "net-approve", ("approve",), ("alice",), (), ("network",)),
                          "CHG-1")
    with db.connect(cluster.socket_dsn + "alice") as alice:
        ops.new_change(alice, "CHG-8", "Self-reviewed by bob")
    with db.connect(cluster.socket_dsn + "bob") as bob:
        ops.change_status(bob, "CHG-8", "approved")
        with pytest.raises(psycopg.errors.RaiseException, match="CHG-8 was approved by bob, who may not approve"):
            db.apply_records(bob, tuple(parse(touch("cn=svc-a,ou=owners,dc=ciam-ops"))), "CHG-8")
        ops.new_change(bob, "CHG-9", "The network team's service")
    with db.connect(cluster.socket_dsn + "alice") as alice:
        ops.change_status(alice, "CHG-9", "approved")
        with pytest.raises(psycopg.errors.RaiseException, match="alice may not apply cn=svc-a"):
            db.apply_records(alice, tuple(parse(touch("cn=svc-a,ou=owners,dc=ciam-ops"))), "CHG-9")
    with db.connect(cluster.socket_dsn + "bob") as bob:
        db.apply_records(bob, tuple(parse(touch("cn=svc-a,ou=owners,dc=ciam-ops"))), "CHG-9")   # both in the area
        with pytest.raises(psycopg.errors.RaiseException, match="bob may not apply cn=platform"):   # no team's
            db.apply_records(bob, tuple(parse(network.replace("network", "platform"))), "CHG-9")
        with pytest.raises(psycopg.errors.RaiseException, match="bob may not settings cn=net-apply"):
            db.apply_records(bob, tuple(parse(touch("cn=net-apply,ou=grants,dc=ciam-ops"))), "CHG-9")
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:
        owner.execute(f"set role {ROLES.owner}")
        db.apply_records(owner, tuple(parse(touch("cn=network,ou=owners,dc=ciam-ops"))), "CHG-8")  # break-glass


def test_the_grant_check_evaluates_the_person_behind_the_api_login(cluster):
    """Runs after the grants test above (bob holds apply and alice approve over the network team's areas). The API
    login (opsdir db-roles --api-login), once the api-login setting names it, writes as the person it names; any other
    login naming a person still writes as itself."""
    r, port = cluster.root, cluster.port
    touch = "dn: cn=svc-a,ou=owners,dc=ciam-ops\nchangetype: modify\nreplace: description\ndescription: api\n-\n"
    script = db_roles_sql(ROLES.owner, "opsdir_migrate", ROLES.runtime, "opsdir", "certificate", api="opsdir_api")
    with psycopg.connect(f"host={r} port={port} user=admin dbname=opsdir", autocommit=True) as admin:
        for statement in [s for s in script.splitlines() if "opsdir_api" in s and not s.startswith("--")]:
            admin.execute(statement)
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:
        owner.execute(f"set role {ROLES.owner}")
        ops.apply_preview(owner, ops.preview_setting(owner, "api-login", "opsdir_api"), "CHG-1")
    with db.connect(cluster.socket_dsn + "opsdir_api") as api:
        with db.requesting("bob"):
            ops.new_change(api, "CHG-10", "Through the API")
        with db.requesting("alice"):
            ops.change_status(api, "CHG-10", "approved")
            with pytest.raises(psycopg.errors.RaiseException, match="alice may not apply cn=svc-a"):
                db.apply_records(api, tuple(parse(touch)), "CHG-10")
        with pytest.raises(psycopg.errors.RaiseException, match="opsdir_api may not apply cn=svc-a"):
            db.apply_records(api, tuple(parse(touch)), "CHG-10")       # no person named: the login, no grants
        with db.requesting("bob"):
            db.apply_records(api, tuple(parse(touch)), "CHG-10")
        assert [row[3] for row in ops.history(api).rows if row[-1].startswith("cn=svc-a,")][-1] == "bob"
    with db.connect(cluster.socket_dsn + "carol") as carol, db.requesting("bob"):
        with pytest.raises(psycopg.errors.RaiseException, match="carol may not apply cn=svc-a"):
            db.apply_records(carol, tuple(parse(touch)), "CHG-10")


def test_identity_provider_groups_decide_the_members_of_mapped_teams(cluster):
    """Runs after the API test above (opsdir_api is the API login; bob holds apply over the network team's areas,
    alice approve). The netops team stands for an identity provider group and holds apply and approve there: dave,
    recorded in netops, holds neither without the group in his request and both with it. An approval keeps the mapped
    teams its approver held, so the approver's grants are checked with them when someone else applies the change.
    History records the API client and the mapped teams. Mapping a team to a group needs the settings action."""
    touch = "dn: cn=svc-a,ou=owners,dc=ciam-ops\nchangetype: modify\nreplace: description\ndescription: {}\n-\n"
    refused = psycopg.errors.RaiseException
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:
        owner.execute(f"set role {ROLES.owner}")
        ops.apply_preview(owner, ops.preview_team(owner, "netops", groups=(NETOPS,)), "CHG-1")
        ops.apply_preview(owner, ops.preview_person(owner, "dave", "Dave", teams=("netops",)), "CHG-1")
        ops.apply_preview(owner, ops.preview_grant(owner, "netops-work", ("apply", "approve"), ("netops",), (),
                                                   ("network",)), "CHG-1")
    with db.connect(cluster.socket_dsn + "opsdir_api") as api:
        changed = lambda change_id: get(db.load_directory(api), f"cn={change_id},ou=changes,dc=ciam-ops")  # noqa: E731
        with db.requesting("bob"):
            for change_id in ("CHG-11", "CHG-12", "CHG-13"):
                ops.new_change(api, change_id, "Network work")
        with db.requesting("alice"):
            ops.change_status(api, "CHG-11", "approved")
        with db.requesting("dave"), pytest.raises(refused, match="dave may not apply cn=svc-a"):
            db.apply_records(api, tuple(parse(touch.format("no group"))), "CHG-11")   # recorded in netops: ignored
        with db.requesting("dave", ("https://idp.example.com/ another",)), pytest.raises(refused, match="dave may"):
            db.apply_records(api, tuple(parse(touch.format("another group"))), "CHG-11")
        with db.requesting("dave", (NETOPS,), "opsdir-console"):
            db.apply_records(api, tuple(parse(touch.format("netops"))), "CHG-11")
        written = [row for row in ops.history(api).rows if row[-1].startswith("cn=svc-a,")][-1]
        assert written[3:6] == ("dave", "opsdir-console", "netops")
        with db.requesting("dave", (NETOPS,)):
            ops.change_status(api, "CHG-12", "approved")
        with db.requesting("dave"):
            ops.change_status(api, "CHG-13", "approved")
        assert (values(changed("CHG-12"), "ciamApprovedAs"), values(changed("CHG-13"), "ciamApprovedAs"),
                values(changed("CHG-11"), "ciamApprovedAs")) == (("dave netops",), (), ())
        with db.requesting("bob"):
            db.apply_records(api, tuple(parse(touch.format("approved through netops"))), "CHG-12")
            with pytest.raises(refused, match="CHG-13 was approved by dave, who may not approve"):
                db.apply_records(api, tuple(parse(touch.format("approved without it"))), "CHG-13")
            with pytest.raises(refused, match="bob may not settings cn=network"):
                db.apply_records(api, tuple(parse(f"dn: cn=network,ou=owners,dc=ciam-ops\nchangetype: modify\n"
                                                  f"add: ciamIdpGroup\nciamIdpGroup: {NETOPS}\n-\n")), "CHG-12")
    with db.connect(cluster.socket_dsn + "carol") as carol, db.requesting("dave", (NETOPS,)):
        with pytest.raises(refused, match="carol may not apply cn=svc-a"):           # only the API login is trusted
            db.apply_records(carol, tuple(parse(touch.format("carol"))), "CHG-12")


def test_writes_need_the_approvals_their_environment_needs(cluster):
    """Runs after the groups test above (CHG-12 was approved by dave alone; bob holds apply over the network team's
    areas, alice approve, netops apply and approve through its group). With approvals-required *=2, a write under a
    change one person approved is refused; two approvers who may approve there let it through, and an approver
    without approve there doesn't count."""
    touch = "dn: cn=svc-a,ou=owners,dc=ciam-ops\nchangetype: modify\nreplace: description\ndescription: {}\n-\n"
    refused = psycopg.errors.RaiseException
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:
        owner.execute(f"set role {ROLES.owner}")
        ops.apply_preview(owner, ops.preview_setting(owner, "approvals-required", "*=2"), "CHG-1")
    with db.connect(cluster.socket_dsn + "opsdir_api") as api:
        with db.requesting("bob"), pytest.raises(refused, match="CHG-12 has 1 of the 2 approvals the record needs"):
            db.apply_records(api, tuple(parse(touch.format("one approval"))), "CHG-12")
        with db.requesting("bob"):
            for change_id in ("CHG-14", "CHG-15"):
                ops.new_change(api, change_id, "Two approvals")
        with db.requesting("alice"):
            ops.change_status(api, "CHG-14", "approved")
            ops.change_status(api, "CHG-15", "approved")
        assert ops.change_state(api, "CHG-14") == ("proposed", ("alice",), 2)
        with db.requesting("dave", (NETOPS,)):
            ops.change_status(api, "CHG-14", "approved")                    # dave may approve there through netops
        with db.requesting("dave"):
            ops.change_status(api, "CHG-15", "approved")                    # without the group: no grant there
        with db.requesting("bob"):
            db.apply_records(api, tuple(parse(touch.format("two approvals"))), "CHG-14")
            with pytest.raises(refused, match="CHG-15 has 1 approver.s. who may approve .* and 2 need to"):
                db.apply_records(api, tuple(parse(touch.format("one who may"))), "CHG-15")
    with db.connect(cluster.socket_dsn + "opsdir_migrate") as owner:
        owner.execute(f"set role {ROLES.owner}")
        db.apply_records(owner, tuple(parse(touch.format("break-glass"))), "CHG-12")   # the owner isn't held to it
        ops.apply_preview(owner, ops.preview_setting(owner, "approvals-required", "*=1"), "CHG-1")
