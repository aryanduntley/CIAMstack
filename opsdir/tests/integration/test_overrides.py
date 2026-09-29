"""The store governs environment overrides, against Postgres: only attributes whose definition is X-OVERRIDABLE may be
overridden, with values valid for the attribute, on an entry whose classes allow it; the environment then renders
with its value."""
import pytest

from opsdir.connectors.registry import store_parts
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.overlays import apply_overrides
from opsdir.core.directory import get, one
from opsdir.store import migrations, postgres as db

pytestmark = pytest.mark.integration

ENV = "env=stage,cloud=home,ou=environments,dc=ciam-ops"
TOPOLOGY = "cn=topology,ou=config,dc=ciam-ops"
BASE = f"""dn: dc=ciam-ops
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
ciamTitle: Smaller stage
ciamChangeStatus: approved

dn: ou=config,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: config

dn: {TOPOLOGY}
objectClass: top
objectClass: ciamReplicationTopology
cn: topology
ciamReplicaCount: 3

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: cloud=home,ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: home
ciamCloudProvider: aws
ciamRegion: region-1

dn: {ENV}
objectClass: top
objectClass: ciamEnvironment
env: stage

dn: ou=overrides,{ENV}
objectClass: top
objectClass: organizationalUnit
ou: overrides
"""


def override(attr, *vals, target=TOPOLOGY, cn="replicas"):
    return (f"dn: cn={cn},ou=overrides,{ENV}\nchangetype: add\nobjectClass: top\nobjectClass: ciamOverride\n"
            f"cn: {cn}\nciamOverrides: {target}\nciamOverrideAttribute: {attr}\n"
            + "".join(f"ciamOverrideValue: {v}\n" for v in vals) + "description: stage runs one replica\n")


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def change(conn, text):
    return db.apply_records(conn, tuple(parse(text)), "CHG-1")


def test_an_overridable_attribute_is_overridden_and_the_environment_sees_its_value(conn):
    change(conn, override("ciamReplicaCount", "1"))
    d = db.load_directory(conn)
    m = env_model(d, "home/stage")
    assert one(get(apply_overrides(d, m.overrides), TOPOLOGY), "ciamReplicaCount") == "1"
    assert one(get(d, TOPOLOGY), "ciamReplicaCount") == "3"          # the shared value is untouched


@pytest.mark.parametrize("attr, vals, refusal", [
    ("cn", ("other",), '"cn" may not be overridden per environment (its definition is not X-OVERRIDABLE)'),
    ("ciamReplicaCount", ("one",), 'value "one" is not a valid int for "ciamReplicaCount"'),
    ("ciamReplicaCount", ("1", "2"), '"ciamReplicaCount" is SINGLE-VALUE'),
    ("ciamNoSuchThing", ("1",), 'names unknown attribute "ciamNoSuchThing"'),
    ("ciamLockoutFailureCount", ("5",), 'does not allow "ciamLockoutFailureCount"'),
])
def test_an_override_the_definitions_dont_allow_is_refused(conn, attr, vals, refusal):
    with pytest.raises(Exception) as refused:
        change(conn, override(attr, *vals))
    assert refusal in str(refused.value)
