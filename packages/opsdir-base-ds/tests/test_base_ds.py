"""The DS-lineage base: products as data, the neutral files every product of the lineage renders, setup inputs."""
from types import SimpleNamespace

from opsdir.core.directory import make_directory, make_entry
from opsdir.domains.directory.naming import DECLARED
from opsdir.connectors.registry import format_named
from opsdir.core.formats import format_of
from opsdir_base_ds.config import DSCONFIG_BATCH, FORMATS, dsconfig_batch, neutral_files
from opsdir_base_ds.product import DsProduct, handler_name, runs
from opsdir_base_ds.setup import handler_ports, port

PRODUCT = DsProduct(name="SomeDS", root_dn="cn=admin", dsconfig_apply=("# Apply: somehow",),
                    handler_names={"LDAPS": "Secure Handler"}, builtin_policies=("Default Password Policy",))


def _directory():
    return make_directory((), {}, (
        (f"cn=LDAPS,ou=connection-handlers,{DECLARED}", ("top", "ciamConnectionHandler"),
         {"cn": ["LDAPS"], "ciamEnabled": ["TRUE"], "ciamListenPort": ["1636"]}),
        (f"cn=LDAP,ou=connection-handlers,{DECLARED}", ("top", "ciamConnectionHandler"),
         {"cn": ["LDAP"], "ciamEnabled": ["FALSE"]})))


def test_a_product_is_recognized_from_the_servers_it_runs_on():
    m = SimpleNamespace(servers=(make_entry("cn=a,dc=x", ["ciamServer"], {"ciamProductVersion": ["SomeDS 2.0"]}),))
    assert runs(PRODUCT, m) and not runs(PRODUCT._replace(name="Other"), m)


def test_handlers_recorded_under_neutral_names_get_the_products_names():
    assert (handler_name(PRODUCT, "LDAPS"), handler_name(PRODUCT, "LDAP")) == ("Secure Handler", "LDAP")
    batch = dsconfig_batch(PRODUCT, _directory())
    assert '--handler-name "Secure Handler" --set enabled:true --set listen-port:1636' in batch
    assert "--handler-name LDAP --set enabled:false\n" in batch and "# Apply: somehow" in batch


def test_every_product_renders_the_standard_ldap_files_and_its_lineage_files():
    assert sorted(neutral_files(PRODUCT, make_directory((), {}, ()))) == [
        "ds/acis.ldif", "ds/dsconfig.batch", "ldap/dit.ldif", "ldap/schema.ldif"]


def test_ports_come_from_the_declared_handlers_else_the_lineage_defaults():
    ports = handler_ports(_directory())
    assert (port(ports, "LDAPS"), port(ports, "LDAP"), port(ports, "HTTPS")) == ("1636", 1389, 8443)


def test_the_lineages_batch_syntax_is_a_registered_format():
    assert format_named("dsconfig-batch") == DSCONFIG_BATCH
    assert format_of("ds/dsconfig.batch", FORMATS) == "dsconfig-batch" and format_of("ldap/dit.ldif", FORMATS) == "ldif"


def _replicas(*servers):
    from opsdir_base_ds.replication import check_replication_path
    env = make_entry("env=prod,cloud=x,ou=environments,dc=ciam-ops", ["ciamEnvironment"], {"env": ["prod"]})
    m = lambda label, srv: SimpleNamespace(label=label, env=env, servers=srv, bindings=())  # noqa: E731
    return check_replication_path(SimpleNamespace(d=make_directory((), {}, ()), src=m("x/prod", ()),
                                                  dst=m("y/prod", servers)))


def test_a_replica_without_a_private_ip_is_named_not_skipped():
    ds = make_entry("cn=ds-1,env=prod,cloud=y", ["ciamServer"], {"cn": ["ds-1"], "ciamServerRole": ["ds"]})
    assert "y/prod replica ds-1 records no private IP, so whether x/prod admits it on port 8989 can't be checked." in \
        [text for _, text, _ in _replicas(ds).blockers]


def test_no_replicas_is_said_not_passed_as_all_admitted():
    assert "y/prod records no directory replicas: no replication traffic to admit." in _replicas().ok


def test_a_policy_every_server_already_has_is_set_not_created():
    d = make_directory((), {}, tuple(
        (f"cn={name},ou=password-policies,{DECLARED}", ("top", "ciamPasswordPolicy"),
         {"cn": [name], "ciamStorageScheme": ["PBKDF2-HMAC-SHA256"], "ciamLockoutFailureCount": ["5"]})
        for name in ("Default Password Policy", "customers")))
    batch = dsconfig_batch(PRODUCT, d)
    assert ('set-password-policy-prop --policy-name "Default Password Policy" --set default-password-storage-scheme:'
            'PBKDF2-HMAC-SHA256 --set password-attribute:userPassword --set lockout-failure-count:5') in batch
    assert 'create-password-policy --policy-name "customers" --type password-policy' in batch


def test_a_target_that_doesn_t_join_gets_the_fix_declaring_it():
    from opsdir.core.directory import make_entry
    from opsdir_base_ds.replication import check_joins
    src = SimpleNamespace(dn="env=prod,cloud=a,ou=environments,dc=ciam-ops", label="a/prod")
    d = make_directory((), {}, ())
    dst = SimpleNamespace(dn="env=prod,cloud=b,ou=environments,dc=ciam-ops", label="b/prod", d=d,
                          env=make_entry("env=prod,cloud=b,ou=environments,dc=ciam-ops", ("ciamEnvironment",), {}))
    found = check_joins(d, src, dst, "joins", "doesn't join")
    (fix,) = found.fixes
    assert (fix.key, fix.records[0].dn, fix.records[0].mods) == (
        "replication:joins", dst.dn, (("replace", "ciamJoinsDeploymentOf", (src.dn,)),))
    assert fix.risks[0].startswith("If b/prod is meant as a fresh topology")
