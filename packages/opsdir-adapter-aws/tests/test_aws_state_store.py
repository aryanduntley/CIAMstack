"""AWS Terraform state imported into the store, against Postgres: a new tagged instance is added under an approved
change with its subnet linked, nothing secret reaches the store, and importing the same state again changes nothing."""
import json
import os

import pytest

import support
from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse
from opsdir.store import postgres as db

pytestmark = pytest.mark.integration

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

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-TF-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-TF-1
ciamTitle: Record the environment from its Terraform state
ciamChangeStatus: approved
"""


def _res(mode, type_, name, attrs, sensitive=()):
    return {"mode": mode, "type": type_, "name": name, "instances": [
        {"attributes": attrs, "sensitive_attributes": [[{"type": "get_attr", "value": s}] for s in sensitive]}]}


STATE = json.dumps({"version": 4, "resources": [
    _res("data", "aws_vpc", "main", {"id": "vpc-1", "cidr_block": "10.20.0.0/16"}),
    _res("managed", "aws_subnet", "ds_a", {"id": "subnet-1", "cidr_block": "10.20.1.0/24",
                                           "availability_zone": "us-east-1a", "tags": {"Role": "subnet-ds"}}),
    _res("managed", "aws_instance", "ds_1", {"id": "i-1", "ami": "ami-0abc", "instance_type": "m6i.xlarge",
                                             "private_ip": "10.20.1.11", "availability_zone": "us-east-1a",
                                             "subnet_id": "subnet-1",
                                             "tags": {"Name": "ds-1", "Role": "ds", "Hostname": "ds-1.internal.test"}}),
    _res("managed", "random_password", "root", {"id": "none", "result": "p4ss-w0rd-not-real"}, sensitive=("result",))]})


@pytest.fixture
def conn():
    c = db.connect(support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB))
    ops.init(c)
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def test_a_state_is_imported_under_a_change_and_again_changes_nothing(conn):
    files = {"main/prod/terraform.tfstate": STATE}
    preview = ops.preview_import(conn, "aws/terraform-state", files)
    assert ops.apply_preview(conn, preview, "CHG-TF-1").lines
    row = conn.execute(f"select attrs from opsdir.entry where dn = 'cn=ds-1,{ENV}'").fetchone()[0]
    assert (row["ciamSubnet"], row["ciamServerRole"]) == ([f"cn=subnet-1,ou=bindings,{ENV}"], ["ds"])
    assert "p4ss" not in str(conn.execute("select jsonb_agg(attrs) from opsdir.entry").fetchone()[0])
    assert ops.preview_import(conn, "aws/terraform-state", files).changes == ()
