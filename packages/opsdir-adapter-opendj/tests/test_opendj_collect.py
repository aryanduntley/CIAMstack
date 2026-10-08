"""OpenDJ configuration collectors: the same search as PingDS's with OpenDJ's own ldapsearch option names."""
from opsdir_adapter_opendj.adapter import ADAPTER
from network_fixtures import ALPHA, entry, model


def test_opendj_option_names():
    _, m, _ = model(alpha=(entry(ALPHA, "ds-config", "ciamCollectionSource", ciamBindingRole="collect-ds",
                                 ciamImporter="opendj/config", ciamSourceRef="ldaps://dj-1.example.test:4444",
                                 ciamLoginName="cn=Directory Manager", ciamCredentialRole="dj-reader"),
                           entry(ALPHA, "dj-reader", "ciamSecretRef", ciamBindingRole="dj-reader",
                                 ciamRefUri="fake://kv/dj")))
    ((path, call),) = ADAPTER.collectors[0].steps(m.d, m, {}, {})
    assert path == "dj-1.example.test/config/config.ldif"
    assert ("--useSSL", "--bindDN", "--bindPasswordFile", "--baseDN") == tuple(
        a for a in call.argv if a in ("--useSSL", "--bindDN", "--bindPasswordFile", "--baseDN"))
