"""PingAM planner checks: every journey of a realm the target serves can run (it starts at a node it has, and every
outcome leads to one of its nodes or ends the journey)."""
from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.findings import findings, merge_findings, responsible
from .naming import JOURNEYS, realm_container
from .realms import STATIC_NODES, realm_path, realms


def journey_problems(d, j):
    """Why a journey can't run: an entry node it doesn't have, outcomes leading to nodes it doesn't have."""
    nodes = {rdn_value(n): n for n in children(d, j.dn, "pingamNode")}
    known = {*nodes, *STATIC_NODES}
    entry = one(j, "pingamEntryNode")
    return (*((f"it starts at node {entry}, which it doesn't have",) if entry not in known else ()),
            *(f"outcome {o.split('=', 1)[0]!r} of {one(n, 'pingamDisplayName') or nid} leads to node "
              f"{o.split('=', 1)[1]}, which it doesn't have"
              for nid, n in nodes.items() for o in values(n, "pingamOutcome") if o.split("=", 1)[1] not in known))


def _journey(ctx, service, j):
    why = journey_problems(ctx.d, j)
    if why:
        return findings(blockers=[("Journey", f"Journey `{rdn_value(j)}` of realm {realm_path(service)} can't run in "
                                   f"{ctx.dst.label}: {'; '.join(why)}.", responsible(ctx.d, j, service))])
    return findings()


def check_journeys(ctx):
    """Journeys of the realms AM serves that can't run are blockers; the rest are counted in one line."""
    js = tuple((s, j) for s in realms(ctx.d) for j in children(ctx.d, realm_container(JOURNEYS, rdn_value(s)),
                                                                "pingamJourney"))
    found = merge_findings([_journey(ctx, s, j) for s, j in js])
    counted = "The AM journey is" if len(js) == 1 else f"All {len(js)} AM journeys are"
    return found if found.blockers or not js else findings(ok=[f"{counted} complete (every node leads to one of "
                                                                "its own, or ends the journey)."])
