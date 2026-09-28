"""The same directory record rendered by two products of the DS lineage: the showcase estate as PingDS (its declared
stack) and as OpenDJ (servers and stack switched in memory). The standard LDAP files and the ACIs are the same; each
product's dsconfig names its own handlers, and each joins the source's replication its own way."""
import datetime as dt
from types import MappingProxyType

import pytest

from opsdir.connectors.plan import plan
from opsdir.connectors.render import render_env
from opsdir.core.directory import make_entry, one
from opsdir.core.environment import env_model

SRC, DST = "source/prod", "target/prod"


def _as_opendj(e):
    """A server running OpenDJ instead of PingDS, a stack naming the opendj adapter instead of pingds."""
    if one(e, "ciamProductVersion", "").startswith("PingDS"):
        return make_entry(e.dn, e.classes, {**e.attrs, "ciamProductVersion": ("OpenDJ 4.6.4",)})
    if one(e, "ciamAdapter") == "pingds":
        return make_entry(e.dn, e.classes, {**e.attrs, "ciamAdapter": ("opendj",)})
    return e


@pytest.fixture(scope="module")
def pingds(estate):
    return estate["before"]


@pytest.fixture(scope="module")
def opendj(estate):
    d = estate["before"]
    return d._replace(entries=MappingProxyType({n: _as_opendj(e) for n, e in d.entries.items()}))


@pytest.fixture(scope="module")
def renders(pingds, opendj):
    return {"pingds": render_env(pingds, DST)[1], "opendj": render_env(opendj, DST)[1]}


def _hosts(d, spec):
    return [one(s, "ciamHostname") for s in env_model(d, spec).servers if one(s, "ciamServerRole") == "ds"]


def test_both_products_render_the_standard_ldap_files_and_the_acis_identically(renders):
    for path in ("ldap/schema.ldif", "ldap/dit.ldif", "ds/acis.ldif"):
        assert renders["pingds"][path] == renders["opendj"][path]


def test_each_dsconfig_names_the_products_handlers(renders):
    assert "--handler-name LDAPS --set" in renders["pingds"]["ds/dsconfig.batch"]
    assert '--handler-name "LDAPS Connection Handler" --set' in renders["opendj"]["ds/dsconfig.batch"]
    strip = [line for line in renders["opendj"]["ds/dsconfig.batch"].splitlines() if "handler" not in line
             and not line.startswith("#")]
    assert strip == [line for line in renders["pingds"]["ds/dsconfig.batch"].splitlines() if "handler" not in line
                     and not line.startswith("#")]


def test_opendj_replicas_join_the_source_topology_through_a_source_replica(opendj, renders):
    first_source = _hosts(opendj, SRC)[0]
    scripts = [text for path, text in renders["opendj"].items() if path.startswith("ds/setup-")]
    assert scripts and all(f"--host1 {first_source} " in s and "./bin/dsreplication initialize" in s for s in scripts)
    assert all("--deploymentId" not in s and 'cn=Directory Manager' in s for s in scripts)


def test_without_a_joined_environment_the_first_opendj_replica_starts_the_topology(opendj):
    _, files = render_env(opendj, SRC)
    first, *rest = _hosts(opendj, SRC)
    scripts = [files[p] for p in sorted(files) if p.startswith("ds/setup-")]
    assert "First replica of a new topology" in scripts[0]
    assert all(f"--host1 {first} " in s for s in scripts[1:]) and len(scripts) == 1 + len(rest)


def test_opendj_requires_its_replication_administrator(opendj):
    assert "ds-replication-admin-password" in render_env(opendj, DST)[0].unbound


def test_each_product_words_its_own_join_check(pingds, opendj):
    as_of = dt.date(2026, 9, 23)
    assert any("joins the DS replication deployment of source/prod" in ok for ok in plan(pingds, SRC, DST, as_of).ok)
    assert any("joins the DS replication topology of source/prod" in ok for ok in plan(opendj, SRC, DST, as_of).ok)
