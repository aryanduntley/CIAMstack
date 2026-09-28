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
                    handler_names={"LDAPS": "Secure Handler"})


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
