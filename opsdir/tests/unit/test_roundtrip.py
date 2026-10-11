"""Round trip (files >> db >> files): an environment's render read back by the adapters' own importers, as each adapter
declares (Adapter.reads_back); a faithful render changes nothing, an unfaithful one is caught."""
import pytest

from opsdir.connectors.roundtrip import read_back, round_trip
from opsdir.core.contract import ReadBack
from opsdir.core.directory import get, one
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


def test_paths_are_read_as_rendered_unless_a_prefix_is_stripped():
    rendered = {"fake/services/sso.url": "https://sso.example.test\n", "fake/env.txt": "x\n"}
    kept = FAKE._replace(reads_back=(ReadBack("services", "fake/services/*"),))
    stripped = FAKE._replace(reads_back=READS)
    assert read_back(directory(), kept, rendered, (kept,))[0].files == ("fake/services/sso.url",)
    assert read_back(directory(), stripped, rendered, (stripped,))[0].files == ("services/sso.url",)


def test_files_can_be_placed_in_the_rendered_environments_folder():
    rendered = {"fake/services/sso.url": "https://sso.example.test\n"}
    placed = FAKE._replace(reads_back=(ReadBack("services", "fake/services/*", "fake/", "{environment}/"),))
    assert read_back(directory(), placed, rendered, (placed,), environment="alpha/prod")[0].files == \
        ("alpha/prod/services/sso.url",)
    with pytest.raises(ValueError, match="name the environment"):
        read_back(directory(), placed, rendered, (placed,))
