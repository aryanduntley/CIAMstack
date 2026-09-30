"""A PingDS server's own files imported into the store, against Postgres: `opsdir import pingds/config` reads a copy
of the server's config/ directory (its archived configurations compressed, as the server keeps them), the store
accepts every snapshot entry, the latest snapshot is compared with the declared configuration, and importing the same
configuration again changes nothing; `pingds/access-log` records the directory's consumers from its access log."""
import datetime as dt
import gzip
import json
import os
import shutil
from pathlib import Path

import pytest

import support
from opsdir import operations as ops
from opsdir.cli import read_texts
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

EXPORT = Path(__file__).resolve().parent / "ds-export"
AT = dt.datetime(2026, 9, 30, 14, 15, tzinfo=dt.timezone.utc)
ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
BASE = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: cloud=main,ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: main
ciamCloudProvider: aws
ciamRegion: us-east-1

dn: {ENV}
objectClass: top
objectClass: ciamEnvironment
env: prod

dn: ou=bindings,{ENV}
objectClass: top
objectClass: organizationalUnit
ou: bindings

dn: cn=subnet-ds,ou=bindings,{ENV}
objectClass: top
objectClass: ciamSubnetBinding
cn: subnet-ds
ciamBindingRole: subnet-ds
ciamCidr: 10.0.1.0/24

dn: cn=ds-1,{ENV}
objectClass: top
objectClass: ciamServer
cn: ds-1
ciamServerRole: ds
ciamHostname: ds-1.example.test
ciamSubnet: cn=subnet-ds,ou=bindings,{ENV}
ciamProductVersion: PingDS 7.5.1

dn: ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: user-schema

dn: cn=mail,ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: ciamUserAttribute
cn: mail
ciamLdapName: mail
ciamPiiClass: moderate

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-DS-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-DS-1
ciamTitle: Record the directory servers' observed configuration
ciamChangeStatus: approved
"""


@pytest.fixture
def conn():
    c = db.connect(support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB))
    ops.init(c)
    db.load_records(c, parse(BASE))
    yield c
    c.close()


@pytest.fixture
def export(tmp_path):
    """The export as an operator copies it: each server's config/ directory, archived configurations compressed."""
    root = tmp_path / "ds-export"
    shutil.copytree(EXPORT, root)
    config = root / "ds-1.example.test" / "config"
    archived = config / "archived-configs"
    archived.mkdir()
    earlier = (config / "config.ldif").read_text().replace("ds-cfg-lockout-failure-count: 5",
                                                           "ds-cfg-lockout-failure-count: 3")
    (archived / "config-20260920030000Z.gz").write_bytes(gzip.compress(earlier.encode()))
    return root


def _snapshots(conn):
    return sorted(r[0] for r in conn.execute(
        "select dn from opsdir.entry where 'ciamSnapshot' = any (object_classes)").fetchall())


def test_a_servers_configuration_is_imported_under_a_change_and_again_changes_nothing(conn, export):
    files, skipped = read_texts(export)
    assert skipped == ()
    preview = ops.preview_import(conn, "pingds/config", files, AT)
    applied = ops.apply_preview(conn, preview, "CHG-DS-1")
    assert applied.lines and _snapshots(conn) == [
        "snap=main-prod-ds-1-20260920030000Z,ou=observed,ou=config,dc=ciam-ops",
        "snap=main-prod-ds-1-20260930141500Z,ou=observed,ou=config,dc=ciam-ops"]
    assert "main/prod ds-1: backend userData: indexes on attributes with no user-schema record, not recorded: " \
           "objectClass" in preview.notices
    later = ops.preview_import(conn, "pingds/config", files, AT + dt.timedelta(days=1))
    assert later.changes == () and "main/prod ds-1: configuration unchanged since snapshot " \
                                   "main-prod-ds-1-20260930141500Z; no new snapshot" in later.notices


def test_the_latest_snapshot_is_compared_with_the_declared_configuration(conn, export):
    files, _ = read_texts(export)
    ops.apply_preview(conn, ops.preview_import(conn, "pingds/declared", {
        "ds-1/config.ldif": files["ds-1.example.test/config/config.ldif"]}, AT), "CHG-DS-1")
    ops.apply_preview(conn, ops.preview_import(conn, "pingds/config", files, AT), "CHG-DS-1")
    assert ops.report(conn, "drift").rows == ()          # declared from the same server: nothing drifted


def _log_line(conn, op, at, user=None, **request):
    return json.dumps({"eventName": "DJ-LDAP", "client": {"ip": "10.0.5.7", "port": 40000},
                       "request": {"protocol": "LDAPS", "operation": op, "connId": conn, **request},
                       "response": {"status": "SUCCESSFUL", "statusCode": "0"}, "timestamp": at,
                       **({"userId": user} if user else {})})


def test_consumers_are_mined_from_access_logs_and_again_change_nothing(conn, tmp_path):
    app = "uid=app-svc,ou=service-accounts,dc=example,dc=test"
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "ldap-access.audit.json").write_text("\n".join((
        _log_line(1, "BIND", "2026-09-20T03:00:00Z", dn=app),
        _log_line(1, "SEARCH", "2026-09-20T03:00:01Z", user=app, dn="ou=people,dc=example,dc=test", scope="sub",
                  attrs=["mail"]),
        _log_line(2, "BIND", "2026-09-20T03:00:02Z", dn="uid=alice,ou=people,dc=example,dc=test"))) + "\n")
    files, _ = read_texts(tmp_path)
    preview = ops.preview_import(conn, "pingds/access-log", files, AT)
    assert ops.apply_preview(conn, preview, "CHG-DS-1").lines
    row = conn.execute("select attrs from opsdir.entry where dn = 'cn=app-svc,ou=consumers,dc=ciam-ops'").fetchone()[0]
    assert (row["ciamAttrRead"], row["ciamObservedSource"], row["ciamMigrationStatus"]) == \
        (["cn=mail,ou=user-schema,dc=ciam-ops"], ["10.0.5.7/32"], ["unknown"])
    assert "alice" not in str(conn.execute("select jsonb_agg(attrs) from opsdir.entry").fetchone()[0])
    assert ops.preview_import(conn, "pingds/access-log", files, AT).changes == ()
