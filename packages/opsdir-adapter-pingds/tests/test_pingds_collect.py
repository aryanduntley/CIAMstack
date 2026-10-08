"""PingDS configuration collectors: cn=config searched on each directory server's administration port with PingDS's
own ldapsearch (its option names), the password only on standard input, written as <host>/config/config.ldif (declared:
the first server's config.ldif); credentials (password values, store PINs, secrets) dropped before anything sees them,
the password policies' settings kept, so the importer reads the same configuration; a source without its bind DN or
credential says so."""
import pathlib

from opsdir.connectors.collecting import collect
from opsdir_adapter_pingds.adapter import ADAPTER
from opsdir_adapter_pingds.render import PINGDS
from opsdir_base_ds.collect import holds_credential, without_credentials
from opsdir_base_ds.observe import config_entries
from network_fixtures import ALPHA, entry, model

CONFIG = (pathlib.Path(__file__).parent / "ds-export" / "ds-1.example.test" / "config" / "config.ldif").read_text()
SOURCE = dict(ciamBindingRole="collect-ds", ciamImporter="pingds/config", ciamTargetRole="ds", ciamPort="4444",
              ciamLoginName="uid=config-reader,ou=admins,ou=identities", ciamCredentialRole="ds-reader")
READER = entry(ALPHA, "ds-reader", "ciamSecretRef", ciamBindingRole="ds-reader", ciamRefUri="fake://kv/ds-reader")


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, "ds-config", "ciamCollectionSource", **{**SOURCE, **over}), READER))
    return alpha


def test_cn_config_of_each_directory_server_with_the_password_on_standard_input():
    assert [c.importer for c in ADAPTER.collectors] == ["config", "declared"]
    m = _alpha()
    steps = ADAPTER.collectors[0].steps(m.d, m, {}, {"ldapsearch": "/opt/ds/bin/ldapsearch",
                                                      "ldap_truststore": "/secure/ds-truststore.p12"})
    assert [p for p, _ in steps] == ["ds-1.example.test/config/config.ldif", "ds-2.example.test/config/config.ldif"]
    call = steps[0][1]
    assert call.argv == ("/opt/ds/bin/ldapsearch", "--hostname", "ds-1.example.test", "--port", "4444", "--useSsl",
                         "--trustStorePath", "/secure/ds-truststore.p12",
                         "--bindDn", "uid=config-reader,ou=admins,ou=identities", "--bindPassword:file", "/dev/stdin",
                         "--baseDn", "cn=config", "--searchScope", "sub", "--wrapColumn", "0", "(objectClass=*)", "*",
                         "+")
    assert call.secrets == ("fake://kv/ds-reader",) and call.stdin({"fake://kv/ds-reader": "pw"}) == "pw"
    c = collect("pingds/config", ADAPTER.collectors[0], m.d, m, lambda call: (CONFIG, None))
    assert c.problems == () and set(c.files) == {"ds-1.example.test/config/config.ldif",
                                                 "ds-2.example.test/config/config.ldif"}


def test_declared_reads_the_first_server_only():
    m = _alpha(ciamImporter="pingds/declared")
    ((path, call),) = ADAPTER.collectors[1].steps(m.d, m, {}, {})
    assert path == "config.ldif" and call.argv[0] == "ldapsearch" and "--trustStorePath" not in call.argv


def test_credentials_are_dropped_and_the_configuration_reads_the_same():
    secret = ("dn: cn=Default Key Manager,cn=Key Manager Providers,cn=config\nds-cfg-key-store-pin: changeit\n"
              "ds-cfg-key-store-file: /opt/ds/config/keystore\n\ndn: uid=admin\nuserPassword: {PBKDF2-HMAC-SHA256}10\n"
              " 000:abcdef\ncn: admin\n")
    kept = without_credentials(secret)
    assert "changeit" not in kept and "PBKDF2" not in kept and " 000:abcdef" not in kept
    assert "ds-cfg-key-store-file: /opt/ds/config/keystore" in kept and "cn: admin" in kept
    assert [holds_credential(a) for a in ("ds-cfg-password-history-count", "ds-cfg-default-password-storage-scheme",
                                          "ds-cfg-password-change-requires-current-password", "ds-cfg-trust-store-pin",
                                          "ds-cfg-smtp-password", "authPassword;binary")] == \
        [False, False, False, True, True, True]
    d, _, _ = model()
    assert config_entries(PINGDS, d, without_credentials(CONFIG), "ou=declared,dc=ciam-ops", "x") == \
        config_entries(PINGDS, d, CONFIG, "ou=declared,dc=ciam-ops", "x")


def test_a_source_without_its_bind_dn_or_credential_says_so():
    _, alpha, _ = model(alpha=(entry(ALPHA, "ds-config", "ciamCollectionSource", ciamBindingRole="collect-ds",
                                     ciamImporter="pingds/config", ciamTargetRole="ds", ciamPort="4444"),))
    c = collect("pingds/config", ADAPTER.collectors[0], alpha.d, alpha, lambda call: ("", None))
    assert c.files is None and c.problems == ("collection source `ds-config`: no bind DN (ciamLoginName)",
                                              "collection source `ds-config`: no credential (ciamCredentialRole)")
