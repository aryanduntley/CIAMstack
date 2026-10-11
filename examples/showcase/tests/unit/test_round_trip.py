"""Round trip (files >> db >> files): every environment of the synthetic estate, rendered as `opsdir render` writes it,
reads back through the adapters' own importers (Adapter.reads_back), before and after the approved changes. A
product's render is a projection of the record: it reads back without changing it. A cloud's is the record's intent
(ReadBack.intent): it reads back as the bindings it came from (no copies), what applying it would record where the
record still holds what was observed, and rendering again gives the same files (decision on milestone 89). What an
importer withholds (secrets) is in its notices, never a change."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment, environment_specs
from opsdir.connectors.roundtrip import fixed_point, round_trip

INTENT = {f"{a.name}/{rb.importer}" for a in ADAPTERS for rb in a.reads_back if rb.intent}
# What a render can't express yet, so reading it back drops it: (DN, attribute) -> why
KNOWN = {("cn=cloudtrail,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops", "ciamAuditEvents"):
         "CloudTrail data events aren't rendered yet (milestone 5.7, note 1950): the trail renders control-plane only"}


@pytest.mark.parametrize("state", ["before", "after"])
def test_every_environment_reads_back_unchanged(estate, state):
    d = estate[state]
    trips = {spec: round_trip(d, spec) for spec in environment_specs(d)}
    changed = [(spec, rt.importer, [(c.changetype, c.dn) for c in (rt.drift if rt.importer in INTENT else rt.changes)])
               for spec, rts in trips.items() for rt in rts if (rt.drift if rt.importer in INTENT else rt.changes)]
    unread = [(spec, rt.importer, rt.notices) for spec, rts in trips.items() for rt in rts if not rt.files]
    assert (changed, unread) == ([], [])


@pytest.mark.parametrize("state", ["before", "after"])
def test_every_environment_render_is_a_fixed_point(estate, state):
    """What the read-backs record leaves every environment's render as it was."""
    d = estate[state]
    assert {spec: fixed_point(d, spec, known=KNOWN) for spec in environment_specs(d)} == \
        {spec: () for spec in environment_specs(d)}


def test_every_declared_read_back_runs_somewhere(estate):
    """Each read-back declared by an installed adapter that applies to an environment of the estate is exercised
    (optional ones included: the estate renders what they read somewhere), so a passing round trip is never vacuous."""
    d = estate["after"]
    applying = {f"{a.name}/{rb.importer}" for spec in environment_specs(d) for a in environment(d, spec)[1]
                for rb in a.reads_back}
    exercised = {rt.importer for spec in environment_specs(d) for rt in round_trip(d, spec)}
    declared = {f"{a.name}/{rb.importer}" for a in ADAPTERS for rb in a.reads_back}
    assert applying and exercised == applying <= declared
