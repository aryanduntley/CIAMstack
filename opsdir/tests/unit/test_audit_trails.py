"""Control-plane audit trails (core observability): a target without a trail while the source keeps one, and a target
trail whose records go to a role it doesn't bind, are blockers; a target trail recording less than the source's
(activity, regions, integrity, how long its records are kept) gives actions; the audit-trails report."""
from opsdir.core.findings import findings
from opsdir.domains.observability.audit import audit_rows, audit_trails, check_audit, coverage
from network_fixtures import ALPHA, BETA, context, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")


def trail(env, cn="cloudtrail", events=("control-plane", "data-write"), everywhere="TRUE", integrity="TRUE",
          destination="audit-logs", **more):
    return entry(env, cn, "ciamAuditTrail", ciamBindingRole="audit-trail", ciamAuditScope="account",
                 ciamAuditEvents=tuple(events), ciamAllRegions=everywhere, ciamIntegrityValidation=integrity,
                 **({"ciamLogDestinationRole": destination} if destination else {}), **more)


def logs(env, days):
    return entry(env, "audit-logs", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="bucket",
                 ciamRetentionDays=str(days))


def _ctx(alpha=(), beta=()):
    d, a, b = model(alpha=alpha, beta=beta, tree=OWNERS)
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_neither_environment_records_a_trail():
    ctx, _ = _ctx()
    assert check_audit(ctx) == findings()


def test_a_target_without_a_trail_is_a_blocker():
    ctx, _ = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)))
    assert [b[1] for b in check_audit(ctx).blockers] == [
        "alpha/prod keeps a control-plane audit trail (cloudtrail) and beta/prod records none: who changes the "
        "target's cloud would go unrecorded. Record the target's trail (its own, or the organization trail the landing "
        "zone keeps)."]


def test_a_target_trail_kept_nowhere_is_a_blocker():
    ctx, _ = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)), beta=(trail(BETA),))
    assert [b[1] for b in check_audit(ctx).blockers] == [
        "Audit trail `cloudtrail` in beta/prod sends its records to role `audit-logs`, which beta/prod doesn't bind: "
        "they are kept nowhere. Record where they go."]


def test_a_weaker_target_trail_gives_actions():
    ctx, _ = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 0)),
                  beta=(trail(BETA, events=("control-plane",), everywhere="FALSE", integrity="FALSE"), logs(BETA, 90)))
    f = check_audit(ctx)
    assert f.blockers == () and [(a[1], a[3]) for a in f.actions] == [
        ("alpha/prod's audit trails record data-write activity and beta/prod's don't: record it in the target's "
         "trail, or decide it isn't needed there.", "2026-12-01"),
        ("alpha/prod's audit trail records every region and beta/prod's records one: activity in the target's other "
         "regions would go unrecorded.", "2026-12-01"),
        ("alpha/prod's audit records can be proven unaltered (integrity validation) and beta/prod's can't: turn it "
         "on for the target's trail.", "2026-12-01"),
        ("alpha/prod keeps its audit records forever and beta/prod 90 days: keep the target's at least as long.",
         "2026-12-01")]


def test_a_target_trail_as_strong_as_the_source_s_is_ok():
    ctx, _ = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)), beta=(trail(BETA), logs(BETA, 400)))
    f = check_audit(ctx)
    assert (f.blockers, f.actions, f.ok) == ((), (), ("Control-plane audit trail recorded in beta/prod (1).",))
    assert coverage(ctx.src, audit_trails(ctx.src)) == (("control-plane", "data-write"), True, True, 365)


def test_the_report_names_who_keeps_each_trail():
    _, d = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 0)),
                beta=(trail(BETA, "org-trail", destination=None, ciamManagedBy=PARTY),))
    assert audit_rows(d) == [
        ("alpha/prod", "cloudtrail", "account", "control-plane, data-write", "yes", "yes", "audit-logs", "forever",
         "platform"),
        ("beta/prod", "org-trail", "account", "control-plane, data-write", "yes", "yes", "", "", "landing-zone")]
