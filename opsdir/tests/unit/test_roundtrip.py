"""Round trip (files >> db >> files): an environment's render read back by the adapters' own importers, as each adapter
declares (Adapter.reads_back); a faithful render changes nothing, an unfaithful one is caught."""
import pytest

from opsdir.connectors.roundtrip import fixed_point, read_back, round_trip
from opsdir.core.contract import Imported, Importer, ReadBack
from opsdir.core.directory import get, make_entry, one
from mini_estate import FAKE, directory

SSO = "cn=sso,ou=identity-services,dc=ciam-ops"
READS = (ReadBack("services", "fake/services/*", "fake/"),)


def _rendering(url_of):
    """The fake adapter rendering the identity service's URL as its export writes it (services/<name>.url)."""
    return FAKE._replace(render_env=lambda m, services: {"fake/services/sso.url": url_of(m) + "\n"}, reads_back=READS,
                         formats=(*FAKE.formats, ("fake/services/*.url", "text")))


def test_a_faithful_render_reads_back_unchanged():
    adapter = _rendering(lambda m: one(get(m.d, SSO), "ciamBaseUrl"))
    (rt,) = round_trip(directory(), "alpha/prod", (adapter,))
    assert (rt.importer, rt.files, rt.changes) == ("fake-cloud/services", ("services/sso.url",), ())


def test_a_render_that_drifts_from_the_record_is_caught():
    adapter = _rendering(lambda m: "https://elsewhere.example.test")
    (rt,) = round_trip(directory(), "beta/prod", (adapter,))
    assert [(c.dn, c.changetype) for c in rt.changes] == [(SSO, "modify")]


def test_a_declaration_nothing_rendered_matches_reads_nothing_and_says_so():
    adapter = FAKE._replace(reads_back=(ReadBack("services", "fake/missing/*", "fake/"),))
    (rt,) = round_trip(directory(), "alpha/prod", (adapter,))
    assert (rt.files, rt.changes, rt.notices) == ((), (), ("nothing rendered matches fake/missing/*",))


def test_an_optional_declaration_nothing_rendered_matches_is_no_round_trip():
    rendering = _rendering(lambda m: one(get(m.d, SSO), "ciamBaseUrl"))
    adapter = rendering._replace(reads_back=(ReadBack("services", "fake/missing/*", "fake/", "", True), *READS))
    assert [(rt.importer, rt.files) for rt in round_trip(directory(), "alpha/prod", (adapter,))] == \
        [("fake-cloud/services", ("services/sso.url",))]


def test_paths_are_read_as_rendered_unless_a_prefix_is_stripped():
    rendered = {"fake/services/sso.url": "https://sso.example.test\n", "fake/env.txt": "x\n"}
    kept = FAKE._replace(reads_back=(ReadBack("services", "fake/services/*"),))
    stripped = FAKE._replace(reads_back=READS)
    assert read_back(directory(), kept, rendered, (kept,))[0].files == ("fake/services/sso.url",)
    assert read_back(directory(), stripped, rendered, (stripped,))[0].files == ("services/sso.url",)


def test_a_read_back_can_prepare_what_its_importer_reads_from_the_rendered_files():
    def prepare(files, d, environment):          # e.g. a cloud's Terraform roots into states
        return {f"{environment}/{p.rsplit('/', 1)[-1]}": text.upper() for p, text in files.items()}
    rendered = {"fake/services/sso.url": "https://sso.example.test\n"}
    prepared = FAKE._replace(reads_back=(ReadBack("services", "fake/services/*", "fake/", "", False, prepare),))
    (rt,) = read_back(directory(), prepared, rendered, (prepared,), environment="alpha/prod")
    assert rt.files == ("alpha/prod/sso.url",)


def test_files_can_be_placed_in_the_rendered_environments_folder():
    rendered = {"fake/services/sso.url": "https://sso.example.test\n"}
    placed = FAKE._replace(reads_back=(ReadBack("services", "fake/services/*", "fake/", "{environment}/"),))
    assert read_back(directory(), placed, rendered, (placed,), environment="alpha/prod")[0].files == \
        ("alpha/prod/services/sso.url",)
    with pytest.raises(ValueError, match="name the environment"):
        read_back(directory(), placed, rendered, (placed,))


def test_a_render_that_is_intent_drifts_only_by_copies_and_must_be_a_fixed_point():
    """A cloud's render is the record's intent: reading it back records what applying it would change (here the
    service's URL), which is no drift; a render depending on what the read-back changes isn't a fixed point, unless
    the change is a known gap."""
    intent = _rendering(lambda m: "https://intent.example.test")._replace(
        reads_back=(ReadBack("services", "fake/services/*", "fake/", "", False, None, True),))
    (rt,) = round_trip(directory(), "alpha/prod", (intent,))
    assert ([(c.changetype, c.dn) for c in rt.changes], rt.drift) == ([("modify", SSO)], ())
    assert fixed_point(directory(), "alpha/prod", (intent,)) == ()
    moving = intent._replace(render_env=lambda m, services: {
        "fake/services/sso.url": one(get(m.d, SSO), "ciamBaseUrl") + "/next\n"})
    assert fixed_point(directory(), "alpha/prod", (moving,)) == ("MANIFEST.json", "fake/services/sso.url")
    assert fixed_point(directory(), "alpha/prod", (moving,), known=((SSO, "ciamBaseUrl"),)) == ()


def test_an_entry_read_back_for_a_role_the_environment_already_binds_is_a_copy():
    env = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    copy = make_entry(f"cn=net-2,ou=bindings,{env}", ("top", "ciamNetwork"),
                      {"cn": ("net-2",), "ciamBindingRole": ("network",), "ciamCidr": ("10.9.0.0/16",)})
    fresh = make_entry(f"cn=edge,ou=bindings,{env}", ("top", "ciamNetwork"),
                       {"cn": ("edge",), "ciamBindingRole": ("edge-network",), "ciamCidr": ("10.8.0.0/16",)})
    read = Importer("bindings", "", lambda files, d, patterns, at=None:
                    Imported((), tuple((e.dn, (e,)) for e in (copy, fresh)), ()))
    adapter = _rendering(lambda m: "x")._replace(importers=(read,), reads_back=(
        ReadBack("bindings", "fake/services/*", "", "", False, None, True),))
    (rt,) = round_trip(directory(), "alpha/prod", (adapter,))
    assert {c.dn for c in rt.changes} == {copy.dn, fresh.dn} and [c.dn for c in rt.drift] == [copy.dn]
