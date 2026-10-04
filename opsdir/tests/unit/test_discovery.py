"""Discovering domains and adapters from entry points: validation and ordering (pure)."""
import pytest

from opsdir.connectors.registry import (ADAPTER_GROUP, DOMAIN_GROUP, DOMAINS, ordered_adapters, ordered_domains,
                                        registered)
from opsdir.core.contract import Adapter, Domain
from opsdir.core.standard import fragment


def domain(name, order):
    return Domain(name, fragment((), ()), (), (), {}, (), order, {})


def adapter(name, kind):
    return Adapter(name, kind, lambda m: True, (), None, None, (), (), {}, None, None, {}, None, (), (), (), (), None,
                   None)


def test_registered_returns_the_records():
    d = domain("a", 1)
    assert registered(DOMAIN_GROUP, Domain, (("a", d, "1.0"),)) == (d,)


def test_registered_refuses_objects_that_are_not_records():
    with pytest.raises(SystemExit, match="not a Adapter record: bad"):
        registered(ADAPTER_GROUP, Adapter, (("bad", object(), None),))


def test_registered_refuses_two_records_with_one_name():
    with pytest.raises(SystemExit, match="registered more than once: a"):
        registered(DOMAIN_GROUP, Domain, (("x", domain("a", 1), None), ("y", domain("a", 2), None)))


def test_domains_run_in_declared_order_then_by_name():
    assert [d.name for d in ordered_domains((domain("c", 20), domain("b", 10), domain("a", 20)))] == ["b", "a", "c"]


def test_adapters_run_providers_first_then_products_then_secret_stores():
    found = (adapter("secrets", "secret-store"), adapter("prod-b", "product"), adapter("cloud-z", "provider"),
             adapter("prod-a", "product"), adapter("cloud-a", "provider"))
    assert [a.name for a in ordered_adapters(found)] == ["cloud-a", "cloud-z", "prod-a", "prod-b", "secrets"]


def test_adapter_of_unknown_kind_is_refused():
    with pytest.raises(SystemExit, match="unknown kind: x"):
        ordered_adapters((adapter("x", "gadget"),))


def test_installed_core_registers_its_domains():
    assert [d.name for d in DOMAINS] == ["infrastructure", "directory", "federation", "pki", "governance",
                                         "configuration", "automation", "compute", "messaging", "custom",
                                         "observability", "access", "edge"]
