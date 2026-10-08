"""PingAM collector: Amster's export-config run in a private work directory with the operator's key (given when
collecting, never stored) against the collection source's AM; without the key it says so and runs nothing."""
from opsdir.connectors.collecting import collect
from opsdir_adapter_pingam.adapter import ADAPTER
from opsdir_adapter_pingam.collect import COLLECTORS, amster_steps, problems
from network_fixtures import ALPHA, entry, model

SOURCE = dict(ciamBindingRole="collect-am", ciamImporter="pingam/amster", ciamSourceRef="https://am.example.test/am/")


def _alpha():
    _, alpha, _ = model(alpha=(entry(ALPHA, "am", "ciamCollectionSource", **SOURCE),))
    return alpha


def test_amster_exports_in_a_private_directory_with_the_operators_key():
    assert [c.importer for c in ADAPTER.collectors] == ["amster"]
    m = _alpha()
    ((path, call),) = amster_steps(m.d, m, {}, {"amster_key": "/secure/amster_rsa"})
    assert (path, call.argv, call.workdir) == ("", ("amster", "{dir}/collect.amster"), True)
    assert call.inputs == (("collect.amster", "connect https://am.example.test/am -k /secure/amster_rsa\n"
                                              "export-config --path {dir}/export --failOnError\n:exit\n"),)
    entity = '{"metadata": {"realm": "/", "entityType": "Realms", "entityId": "alpha"}, "data": {}}'
    c = collect("pingam/amster", COLLECTORS[0], m.d, m, lambda call: ({"realms/root/Realms/alpha.json": entity}, None),
                options={"amster_key": "/secure/amster_rsa"})
    assert c.problems == () and c.files == {"realms/root/Realms/alpha.json": entity}


def test_without_the_key_it_says_so_and_runs_nothing():
    m = _alpha()
    assert amster_steps(m.d, m, {}, {}) == ()
    assert problems(m.d, m, {}) == ("give --amster-key PATH: the private key AM trusts for Amster",)
    c = collect("pingam/amster", COLLECTORS[0], m.d, m, lambda call: ({}, None))
    assert c.files is None and c.calls == ()
