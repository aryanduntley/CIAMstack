"""Directory planner checks: consumers not yet proven against the target, and source hygiene."""
from ...core.directory import children, one, rdn_value
from ...core.findings import findings, owner_label, responsible
from .drift import drift
from .naming import ACIS, CONSUMERS

TERMINAL = frozenset({"tested", "cutover"})


def _consumer_blocker(d, dst, c):
    status = one(c, "ciamMigrationStatus", "unknown")
    tls = " It also binds without TLS." if one(c, "ciamTlsOnly") == "FALSE" else ""
    unindexed = one(c, "ciamUnindexedSearchesPerDay", "0")
    scans = f" {unindexed} unindexed searches/day." if int(unindexed) > 0 else ""
    return ("Consumer", f"Consumer `{rdn_value(c)}` ({one(c, 'ciamBindDn')}) is `{status}`, not tested against "
            f"{dst.label}.{tls}{scans}", owner_label(d, c))


def check_consumers(ctx):
    """Consumers whose migration status is not tested/cutover block the move."""
    return findings(blockers=[_consumer_blocker(ctx.d, ctx.dst, c) for c in children(ctx.d, CONSUMERS, "ciamConsumer")
                              if one(c, "ciamMigrationStatus", "unknown") not in TERMINAL])


def check_hygiene(ctx):
    """Migrate the declared state, not accidents: drift on the source's servers and ACIs without owner/justification."""
    drifted = [("Drift", f"{ctx.src.label} {server}: {kind}: `{rel}` {detail}".rstrip(),
                responsible(ctx.d, ctx.src.env), None)
               for server, kind, rel, detail in drift(ctx.d, [s.dn for s in ctx.src.servers])]
    acis = [("Access", f"ACI `{rdn_value(aci)}` has no owner/justification. Review before recreating it "
             f"in {ctx.dst.label}.", responsible(ctx.d, ctx.dst.env), None)
            for aci in children(ctx.d, ACIS, "ciamAci")
            if not one(aci, "ciamOwner") or not one(aci, "ciamJustification")]
    return findings(actions=drifted + acis)
