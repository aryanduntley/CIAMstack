"""The data profile's collector: OpenLDAP's ldapsearch over LDAPS of the source's base DN (paged, unwrapped, all
attributes), the password on standard input, its output streamed through the profiler the front end gives: the export
is the profile only; without the base DN in the source's URL it says so."""
from opsdir.connectors.collecting import collect
from opsdir_adapter_ldap.adapter import ADAPTER
from opsdir_adapter_ldap.collect import COLLECTORS, problems, profile_steps
from network_fixtures import ALPHA, entry, model

SOURCE = dict(ciamBindingRole="collect-profile", ciamImporter="ldap/data-profile",
              ciamSourceRef="ldaps://ds-replica.example.test:1636/ou=people,dc=example,dc=test",
              ciamLoginName="uid=profiler,ou=admins", ciamCredentialRole="profiler")


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, "profile", "ciamCollectionSource", **{**SOURCE, **over}),
                               entry(ALPHA, "profiler", "ciamSecretRef", ciamBindingRole="profiler",
                                     ciamRefUri="fake://kv/profiler")))
    return alpha


def test_the_search_streams_through_the_profiler():
    assert [c.importer for c in ADAPTER.collectors] == ["data-profile"]
    m = _alpha()
    count = lambda lines: f'{{"entries": {sum(1 for x in lines if x.startswith("dn:"))}}}'
    ((path, call),) = profile_steps(m.d, m, {}, {"profile": count, "ldap_ca": "/secure/ca.pem"})
    assert path == "data-profile-prod.json"
    assert call.argv == ("ldapsearch", "-H", "ldaps://ds-replica.example.test:1636", "-x", "-D",
                         "uid=profiler,ou=admins", "-y", "/dev/stdin", "-b", "ou=people,dc=example,dc=test",
                         "-E", "pr=1000/noprompt", "-o", "ldif-wrap=no", "(objectClass=*)", "*", "+")
    assert call.env == (("LDAPTLS_CACERT", "/secure/ca.pem"),) and call.digest is count
    assert profile_steps(m.d, m, {}, {}) == ()                         # no profiler given: nothing to run


def test_a_source_without_a_base_dn_says_so():
    m = _alpha(ciamSourceRef="ldaps://ds-replica.example.test:1636")
    assert problems(m.d, m, {}) == (
        "collection source `profile`: ciamSourceRef must be ldaps://<host>:<port>/<base DN>",)
    c = collect("ldap/data-profile", COLLECTORS[0], m.d, m, lambda call: ("", None), {"profile": len})
    assert c.files is None and c.calls == ()
