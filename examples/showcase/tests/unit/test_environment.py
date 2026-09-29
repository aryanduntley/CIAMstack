import pytest

from opsdir.connectors.registry import environment, required_roles
from opsdir.core.environment import (by_role, env_dn, env_model, joins, of_class, one_role, secret, servers_with_role,
                                     subnet_of, with_required_roles)


def test_env_dn_expands_specs_and_passes_full_dns_through():
    assert env_dn("source/prod") == "env=prod,cloud=source,ou=environments,dc=ciam-ops"
    assert env_dn("env=a,cloud=b,ou=environments,dc=ciam-ops") == "env=a,cloud=b,ou=environments,dc=ciam-ops"


def test_unknown_environment_exits(estate):
    with pytest.raises(SystemExit):
        env_model(estate["before"], "nowhere/prod")


def test_env_model_resolves_cloud_servers_and_bindings(estate):
    m = env_model(estate["before"], "source/prod")
    assert (m.provider, m.label, m.unbound) == ("aws", "source/prod", ())
    assert len(m.servers) == 10 and all("ciamServer" in s.classes for s in m.servers)
    assert one_role(m, "network").dn.startswith("cn=vpc,")
    assert one_role(m, "no-such-role") is None
    assert len(by_role(m, "subnet-ds")) == 3
    assert {b.dn.split(",")[0] for b in of_class(m, "ciamServiceName")} == {"cn=svc-ldaps", "cn=svc-sso", "cn=svc-login", "cn=svc-apps"}


def test_role_lookups_on_servers(estate):
    m = env_model(estate["before"], "source/prod")
    ds = servers_with_role(m, "ds")
    assert len(ds) == 3
    assert all(subnet_of(m, s) in by_role(m, "subnet-ds") for s in ds)
    assert secret(m, "ds-root-password") is not None
    assert secret(m, "no-such-role") is None


def test_required_roles_decide_what_is_unbound(estate):
    m = env_model(estate["before"], "target/prod", ("network", "backup-target"))
    assert m.unbound == ("backup-target",)
    assert with_required_roles(m, ("network",)).unbound == ()


def test_adapters_are_chosen_from_directory_data(estate):
    for spec, provider in (("source/prod", "aws"), ("target/prod", "azure")):
        m, adapters = environment(estate["before"], spec)
        assert [a.name for a in adapters] == [provider, "pingam", "pingds", "pingfederate", "pinggateway", "pingidm"]
        assert m.unbound == (("backup-target",) if provider == "azure" else ())
        assert "backup-target" in required_roles(adapters)


def test_joins_names_the_deployment_a_migration_target_joins(estate):
    assert joins(env_model(estate["before"], "source/prod")) is None
    assert joins(env_model(estate["before"], "target/prod")).dn == env_dn("source/prod")
