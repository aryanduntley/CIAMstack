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
                                         "observability", "access", "edge", "network", "data", "recovery", "estate"]


# ------------------------------------------------------------------ product roles and kits' logs (U.14 task 515)
def test_product_roles_by_product_name_and_kind():
    from opsdir.core.environment import EnvModel, product_roles, roles_for, with_product_roles
    am = adapter("am", "product")._replace(products=(("PingAM", ">=7"), ("ForgeRock AM", ">=7")),
                                           roles=(("server", ("am",)), ("keystore", ("am-keystore",))))
    found = product_roles((adapter("cloud", "provider"), am))
    assert found == (("PingAM", "server", "am"), ("PingAM", "keystore", "am-keystore"),
                     ("ForgeRock AM", "server", "am"), ("ForgeRock AM", "keystore", "am-keystore"))
    m = with_product_roles(EnvModel(*(None,) * 14), found)
    assert roles_for(m, "ForgeRock AM", "keystore") == ("am-keystore",)
    assert roles_for(m, "PingIDM", "server") == () and EnvModel(*(None,) * 14).product_roles == ()


def test_what_the_kits_rendering_an_environment_answer_for_a_products_cluster_discovery():
    from opsdir.core.contract import DiscoveryAnswer
    from opsdir.core.environment import EnvModel, discovery_answers, with_cluster_discovery
    answer = DiscoveryAnswer("Prod", "ns", "prod.ns.svc.cluster.local", "kit", "QUERY_SETTING")
    kit = adapter("kit", "platform")._replace(cluster_discovery=lambda m: (answer,))
    m = with_cluster_discovery(EnvModel(*(None,) * 14), (adapter("prod", "product"), kit))
    assert discovery_answers(m, "Prod") == (answer,) and discovery_answers(m, "Other") == ()
    assert EnvModel(*(None,) * 14).cluster_discovery == () and adapter("prod", "product").cluster_discovery is None


def test_the_installed_products_declare_their_roles_by_known_kinds():
    from opsdir.connectors.registry import ADAPTERS
    from opsdir.core.contract import ROLE_KINDS
    from opsdir.core.environment import product_roles
    declared = product_roles(ADAPTERS)
    assert {k for _, k, _ in declared} <= set(ROLE_KINDS)
    assert {(p, k) for p, k, _ in declared} >= {("PingAM", "server"), ("PingAM", "keystore"), ("PingIDM", "keystore"),
                                                ("PingDS", "service"), ("PingFederate", "cluster-discovery")}


def test_a_kits_callable_logs_resolve_once_over_the_others_static_ones():
    from opsdir.connectors.registry import ADAPTERS, resolved_logs
    from opsdir.core.contract import LogSource
    product = adapter("prod", "product")._replace(products=(("Prod", ">=1"),), roles=(("server", ("web",)),),
                                                  logs=(LogSource("web", "servers", "log/a.log", "text", "access"),))
    kit = adapter("kit", "platform")._replace(logs=lambda sources, roles: tuple(
        s._replace(on="kubernetes", path=None) for s in sources if (s.server_role and ("Prod", "server", s.server_role)
                                                                     in roles)))
    resolved = {a.name: a.logs for a in resolved_logs((product, kit))}
    assert resolved == {"prod": product.logs, "kit": (LogSource("web", "kubernetes", None, "text", "access"),)}
    assert all(not callable(a.logs) for a in ADAPTERS)


def test_the_stack_check_gives_a_plain_model_the_adapters_product_roles():
    from opsdir.connectors.stack import declared_adapters
    from opsdir.core.environment import EnvModel, roles_for
    seen = []
    kit = adapter("kit", "platform")._replace(applies=lambda m: seen.append(roles_for(m, "Prod", "server")) or True)
    product = adapter("prod", "product")._replace(products=(("Prod", ">=1"),), roles=(("server", ("web",)),))
    plain = EnvModel(*(None,) * 6, (), (), (), (), (), (), (), None)
    assert declared_adapters(plain, (product, kit)) == (product, kit) and seen == [("web",)]


# ------------------------------------------------------------------ collect options (U.14 task 519)
def test_collect_options_once_each_by_order_a_shared_declaration_counting_once():
    from opsdir.connectors.registry import COLLECT_OPTIONS, collect_options, option_key
    from opsdir.core.contract import CollectOption, Collector
    shared, own = CollectOption("--shared", "DIR", "a library's option", 20), CollectOption("--own", "P", "mine", 10)
    a = adapter("a", "provider")._replace(collectors=(Collector("x", "environment", None, options=(shared,)),))
    b = adapter("b", "product")._replace(collectors=(Collector("y", "environment", None, options=(own, shared)),))
    assert collect_options((a, b)) == (own, shared) and option_key(shared) == "shared"
    assert [option_key(o) for o in COLLECT_OPTIONS] == ["terraform_dir", "amster_key", "ldapsearch",
                                                        "ldap_truststore", "ldap_ca", "inventory_container"]


def test_two_different_declarations_of_one_collect_flag_are_refused_naming_both_adapters():
    from opsdir.connectors.registry import collect_options
    from opsdir.core.contract import CollectOption, Collector
    a = adapter("a", "provider")._replace(collectors=(
        Collector("x", "environment", None, options=(CollectOption("--dir", "DIR", "one", 10),)),))
    b = adapter("b", "product")._replace(collectors=(
        Collector("y", "environment", None, options=(CollectOption("--dir", "PATH", "another", 10),)),))
    with pytest.raises(SystemExit, match=r"--dir \(a and b\)"):
        collect_options((a, b))
