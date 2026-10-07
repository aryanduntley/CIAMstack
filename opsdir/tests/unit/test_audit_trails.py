"""Control-plane audit trails (core observability): a target without a trail while the source keeps one, and a target
trail whose records go to a role it doesn't bind, are blockers; a target trail recording less than the source's
(activity, regions, integrity, how long its records are kept) gives actions (records kept in an immutable object store
count as proven unaltered); the audit-trails report."""
from opsdir.core.findings import findings
from opsdir.domains.observability.audit import (PROTECTED, UNLOCKED, audit_rows, audit_trails, check_audit,
                                               coverage, integrity)
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
        ("alpha/prod's audit records are protected from alteration (cryptographic validation or a locked immutable "
         "store) and beta/prod's aren't: turn on the cloud's cryptographic validation where it has one (CloudTrail "
         "log file validation), or keep the target's exported records in a locked immutable (WORM) object store.",
         "2026-12-01"),
        ("alpha/prod keeps its audit records forever and beta/prod 90 days: keep the target's at least as long.",
         "2026-12-01")]


def test_a_target_trail_as_strong_as_the_source_s_is_ok():
    ctx, _ = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)), beta=(trail(BETA), logs(BETA, 400)))
    f = check_audit(ctx)
    assert (f.blockers, f.actions, f.ok) == ((), (), ("Control-plane audit trail recorded in beta/prod (1).",))
    assert coverage(ctx.src, audit_trails(ctx.src)) == (("control-plane", "data-write"), True, PROTECTED, 365)


def test_the_report_names_who_keeps_each_trail():
    _, d = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 0)),
                beta=(trail(BETA, "org-trail", destination=None, ciamManagedBy=PARTY),))
    assert audit_rows(d) == [
        ("alpha/prod", "cloudtrail", "account", "control-plane, data-write", "yes", "validated", "audit-logs", "forever",
         "platform"),
        ("beta/prod", "org-trail", "account", "control-plane, data-write", "yes", "validated", "", "",
         "landing-zone")]


def _store(env, mode):
    return entry(env, "activity-logs", "ciamObjectStore", ciamBindingRole="activity-logs",
                 ciamStorageRef="azblob://ciamaudit/insights-activity-logs", ciamStorageImmutability=mode,
                 ciamStorageLockDays="365")


def _azure_like(env, mode):
    return (trail(env, "activity-log", integrity="FALSE", destination="activity-logs"), _store(env, mode))


def test_records_in_a_locked_immutable_store_are_as_protected_as_validated_ones():
    ctx, d = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)), beta=_azure_like(BETA, "compliance"))
    assert integrity(ctx.dst, audit_trails(ctx.dst)[0]) == PROTECTED
    assert not [a for a in check_audit(ctx).actions if "alteration" in a[1]]
    assert [r[5] for r in audit_rows(d)] == ["validated", "locked immutable store"]


def test_an_unlocked_immutable_store_is_weaker_than_validation():
    ctx, d = _ctx(alpha=(trail(ALPHA), logs(ALPHA, 365)), beta=_azure_like(BETA, "governance"))
    assert integrity(ctx.dst, audit_trails(ctx.dst)[0]) == UNLOCKED
    assert [a[1] for a in check_audit(ctx).actions if "alteration" in a[1]] == [
        "alpha/prod's audit records are protected from alteration (cryptographic validation or a locked immutable "
        "store) and beta/prod's only by an immutable store whose policy a privileged user can lift: lock the target's "
        "immutability policy (compliance), or turn on the cloud's cryptographic validation where it has one."]
    assert [r[5] for r in audit_rows(d)] == ["validated", "unlocked immutable store"]


def test_a_log_destination_never_counts_and_each_side_is_graded_by_its_own_evidence():
    ctx, _ = _ctx(alpha=_azure_like(ALPHA, "governance"),
                  beta=(trail(BETA, "activity-log", integrity="FALSE"), logs(BETA, 365)))
    assert coverage(ctx.dst, audit_trails(ctx.dst)).integrity == 0
    assert [a[1] for a in check_audit(ctx).actions if "alteration" in a[1]] == [
        "alpha/prod's audit records are protected from alteration (an immutable store whose policy a privileged "
        "user can lift) and beta/prod's aren't: turn on the cloud's cryptographic validation where it has one "
        "(CloudTrail log file validation), or keep the target's exported records in a locked immutable (WORM) object "
        "store."]
