"""Round trip (files >> db >> files): every environment of the synthetic estate, rendered as `opsdir render` writes it,
reads back through the adapters' own importers (Adapter.reads_back) without changing the record, before and after the
approved changes. What an importer withholds (secrets) is in its notices, never a change."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment, environment_specs
from opsdir.connectors.roundtrip import round_trip


@pytest.mark.parametrize("state", ["before", "after"])
def test_every_environment_reads_back_unchanged(estate, state):
    d = estate[state]
    trips = {spec: round_trip(d, spec) for spec in environment_specs(d)}
    changed = [(spec, rt.importer, [(c.changetype, c.dn) for c in rt.changes])
               for spec, rts in trips.items() for rt in rts if rt.changes]
    unread = [(spec, rt.importer, rt.notices) for spec, rts in trips.items() for rt in rts if not rt.files]
    assert (changed, unread) == ([], [])


def test_every_declared_read_back_runs_somewhere(estate):
    """Each installed adapter that declares a read-back and applies to an environment of the estate is exercised, so a
    passing round trip is never vacuous."""
    d = estate["after"]
    applying = {a.name for spec in environment_specs(d) for a in environment(d, spec)[1] if a.reads_back}
    exercised = {rt.importer.split("/")[0] for spec in environment_specs(d) for rt in round_trip(d, spec)}
    declared = {a.name for a in ADAPTERS if a.reads_back}
    assert applying and exercised == applying <= declared
