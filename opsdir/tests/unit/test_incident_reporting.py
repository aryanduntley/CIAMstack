"""Incident reporting (core estate): a target not held to the source's reporting obligations, or held to one no one
can meet, blocks the move; incident routing the target lost blocks where it is held to an obligation, a role it doesn't
bind always; a higher threshold gives an action, a blocker where its data is restricted; records kept shorter than the
obligation preserves evidence block unless a hold runbook is named; the incident-reporting and reportable-incidents
reports."""
import datetime as dt

from opsdir.core.directory import get
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.incidents import (check_incident_reporting, incident_obligations, incident_reporting_rows,
                                             incident_routes, obligations_of, report_due, reportable_incident_rows,
                                             severity_rank)
from network_fixtures import ALPHA, BETA, context, entry, model

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
OBLIGATIONS = "ou=reporting-obligations,dc=ciam-ops"
DFARS = f"cn=dfars-7012,{OBLIGATIONS}"
CERT = "cn=dibnet-eca,ou=certificates,dc=ciam-ops"
FINGERPRINT = ":".join(["AB"] * 32)


def party(cn, kind="team", **more):
    lines = "".join(f"{k}: {v}\n" for k, v in more.items())
    return (f"dn: cn={cn},ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: {cn}\n"
            f"ciamOwnerKind: {kind}\n{lines}")


def obligation(cn="dfars-7012", hours=72, preserve=90, filer="isso", authority="dod-dc3", cert=CERT, **more):
    attrs = {"ciamReportingHours": hours, "ciamPreservationDays": preserve,
             **({"ciamReportingParty": f"cn={filer},ou=owners,dc=ciam-ops"} if filer else {}),
             **({"ciamReportingAuthority": f"cn={authority},ou=owners,dc=ciam-ops"} if authority else {}),
             **({"ciamReportingCertificateRef": cert} if cert else {}), **more}
    lines = "".join(f"{k}: {v}\n" for k, v in attrs.items())
    return f"dn: cn={cn},{OBLIGATIONS}\nobjectClass: top\nobjectClass: ciamReportingObligation\ncn: {cn}\n{lines}"


TREE = (OU.format("owners"), OU.format("certificates"), OU.format("reporting-obligations"), OU.format("incidents"),
        party("isso", mail="isso@example.test"), party("dod-dc3", kind="partner", ciamContactUrl="https://dibnet.dod.mil"),
        party("silent"), party("phone-only", telephoneNumber="+1 202 555 0100"),
        f"dn: {CERT}\nobjectClass: top\nobjectClass: ciamCertificate\ncn: dibnet-eca\nciamFingerprint: {FINGERPRINT}\n"
        "ciamNotAfter: 20270601000000Z\nciamCertPurpose: client-auth\n")


def held(env, *refs, restricted=False):
    return LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                          *((("replace", "ciamReportingObligationRef", refs),) if refs else ()),
                                          *((("replace", "ciamDataClassification", ("restricted",)),)
                                            if restricted else ())))


def detector(env, severity=None, role="incidents", findings_role="security-alerts", **more):
    return entry(env, "detector", "ciamSecurityService", ciamBindingRole="threat-detection",
                 ciamSecurityKind="threat-detection", ciamFindingsRole=findings_role,
                 **({"ciamIncidentRole": role} if role else {}),
                 **({"ciamIncidentSeverity": severity} if severity else {}), **more)


def channel(env, cn="incidents"):
    return entry(env, cn, "ciamAlertChannel", ciamBindingRole=cn, ciamChannelKind="topic")


def _ctx(alpha=(), beta=(), tree=(), changes=()):
    d, a, b = model(alpha=alpha, beta=beta, tree=(*TREE, *tree), changes=changes)
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_no_obligation_routing_or_restricted_data():
    ctx, _ = _ctx(tree=(obligation(),))
    assert check_incident_reporting(ctx) == findings()


def test_obligations_and_routes_of_an_environment():
    ctx, d = _ctx(alpha=(detector(ALPHA), channel(ALPHA)), tree=(obligation(),), changes=(held(ALPHA, DFARS),))
    assert [o.dn for o in obligations_of(ctx.src)] == [DFARS]
    assert [(r.kind, r.severity, r.role, r.binding is not None) for r in incident_routes(ctx.src)] == [
        ("threat-detection", "high", "incidents", True)]
    assert [severity_rank(s) for s in ("low", "critical", None, "bogus")] == [0, 3, 2, 2]


def test_a_target_not_held_to_the_sources_obligation_is_a_blocker():
    ctx, _ = _ctx(tree=(obligation(),), changes=(held(ALPHA, DFARS),))
    assert [b[1] for b in check_incident_reporting(ctx).blockers] == [
        "alpha/prod is held to reporting obligation `dfars-7012` and beta/prod isn't: its incidents would go "
        "unreported. Hold the target to it (ciamReportingObligationRef), or record why it no longer applies."]


def test_an_obligation_no_one_can_meet_is_a_blocker_and_an_unreachable_filer_an_action():
    ctx, _ = _ctx(tree=(obligation(filer=None, authority=None, cert=None),), changes=(held(BETA, DFARS),))
    assert [b[1] for b in check_incident_reporting(ctx).blockers] == [
        "Reporting obligation `dfars-7012` (beta/prod is held to it) can't be met: no one files its reports "
        "(ciamReportingParty); it names no authority to report to (ciamReportingAuthority); it names no certificate "
        "to file with (ciamReportingCertificateRef). Record it."]
    ctx, _ = _ctx(tree=(obligation(filer="silent"),), changes=(held(BETA, DFARS),))
    f = check_incident_reporting(ctx)
    assert f.blockers == () and [(a[1], a[3]) for a in f.actions] == [
        ("`silent` files beta/prod's incident reports and the record gives no way to reach them (mail, "
         "telephoneNumber, ciamContactUrl): record one.", "2026-12-01")]
    ctx, _ = _ctx(tree=(obligation(filer="phone-only"),), changes=(held(BETA, DFARS),))
    assert check_incident_reporting(ctx).actions == ()      # a telephone is a way to reach them


def test_a_ref_that_isnt_an_obligation_is_a_blocker():
    ctx, _ = _ctx(changes=(held(BETA, CERT),))
    assert [b[1] for b in check_incident_reporting(ctx).blockers] == [
        f"beta/prod names `{CERT}` as a reporting obligation, which isn't one (a ciamReportingObligation under "
        "ou=reporting-obligations)."]


def test_restricted_data_held_to_no_obligation_is_an_action():
    ctx, _ = _ctx(changes=(held(BETA, restricted=True),))
    f = check_incident_reporting(ctx)
    assert f.blockers == () and [a[1].split(":")[0] for a in f.actions] == [
        "beta/prod's data is classified restricted and it is held to no reporting obligation"]


def test_lost_routing_blocks_under_an_obligation_else_an_action():
    alpha = (detector(ALPHA), channel(ALPHA))
    ctx, _ = _ctx(alpha=alpha, beta=(detector(BETA, role=None),), tree=(obligation(),),
                  changes=(held(ALPHA, DFARS), held(BETA, DFARS)))
    assert [b[1] for b in check_incident_reporting(ctx).blockers if "preserves evidence" not in b[1]] == [
        "alpha/prod's threat-detection sends high and worse findings to the incident process and beta/prod's sends "
        "none: they would wait for someone to notice them. Route them (ciamIncidentRole). beta/prod is held to "
        "dfars-7012: this blocks the move."]
    ctx, _ = _ctx(alpha=alpha, beta=(detector(BETA, role=None),))
    f = check_incident_reporting(ctx)
    assert f.blockers == () and [a[1].split(":")[0] for a in f.actions] == [
        "alpha/prod's threat-detection sends high and worse findings to the incident process and beta/prod's sends "
        "none"]


def test_an_unbound_incident_role_is_a_blocker():
    ctx, _ = _ctx(beta=(detector(BETA),))
    assert [b[1] for b in check_incident_reporting(ctx).blockers] == [
        "Security service `detector` in beta/prod sends high and worse findings to the incident process through role "
        "`incidents`, which beta/prod doesn't bind: they reach no one. Record where they go."]


def test_a_higher_threshold_is_an_action_and_a_blocker_where_restricted():
    alpha, beta = (detector(ALPHA, "medium"), channel(ALPHA)), (detector(BETA, "critical"), channel(BETA))
    text = ("alpha/prod's threat-detection sends medium and worse findings to the incident process and beta/prod's "
            "only critical and worse: lower the target's ciamIncidentSeverity to medium.")
    f = check_incident_reporting(_ctx(alpha=alpha, beta=beta)[0])
    assert f.blockers == () and [a[1] for a in f.actions] == [text]
    f = check_incident_reporting(_ctx(alpha=alpha, beta=beta, tree=(obligation(),),
                                      changes=(held(BETA, DFARS, restricted=True),))[0])
    assert [b[1] for b in f.blockers if "preserves evidence" not in b[1]] == [
        text + " beta/prod's data is classified restricted: this blocks the move."]


def _kept(days):
    return (detector(BETA, ciamRetentionDays=str(days)), channel(BETA),
            entry(BETA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                  ciamChannelKind="topic"),
            entry(BETA, "cloudtrail", "ciamAuditTrail", ciamBindingRole="audit-trail", ciamAuditScope="account"))


def test_records_kept_shorter_than_preservation_block_unless_a_hold_runbook_is_named():
    ctx, _ = _ctx(beta=_kept(30), tree=(obligation(),), changes=(held(BETA, DFARS),))
    assert [b[1] for b in check_incident_reporting(ctx).blockers] == [
        "Reporting obligation `dfars-7012` preserves evidence 90 days after a report and beta/prod keeps less: audit "
        "trail `cloudtrail` (not recorded), threat-detection `detector` 30 days. Keep them at least 90 days, or "
        "record the runbook placing a preservation hold at discovery (ciamRunbookRef)."]
    runbook = (OU.format("runbooks"), "dn: cn=evidence-hold,ou=runbooks,dc=ciam-ops\nobjectClass: top\n"
               "objectClass: ciamRunbook\ncn: evidence-hold\nciamTitle: Evidence hold\n"
               "ciamLastValidated: 20260901000000Z\n")
    ctx, _ = _ctx(beta=_kept(30),
                  tree=(*runbook, obligation(ciamRunbookRef="cn=evidence-hold,ou=runbooks,dc=ciam-ops")),
                  changes=(held(BETA, DFARS),))
    f = check_incident_reporting(ctx)
    assert f.blockers == () and [a[1].split(", or ")[1] for a in f.actions] == [
        "confirm the hold runbook copies them within beta/prod's retention."]


def test_a_target_meeting_its_obligation_is_ok():
    beta = (detector(BETA, ciamRetentionDays="0"), channel(BETA),
            entry(BETA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                  ciamChannelKind="topic"))
    f = check_incident_reporting(_ctx(beta=beta, tree=(obligation(),), changes=(held(BETA, DFARS),))[0])
    assert (f.blockers, f.actions) == ((), ()) and f.ok == (
        "beta/prod is held to dfars-7012, with its incident routing and evidence kept as long as the source's.",)


def test_incident_reporting_report():
    ctx, d = _ctx(alpha=(detector(ALPHA, "medium"), channel(ALPHA)),
                  tree=(obligation(ciamInternalReportingHours=1),), changes=(held(BETA, DFARS),))
    assert incident_reporting_rows(d) == [
        ("alpha/prod", "", "", "", "", "", "", "", "", "detector: medium+ to incidents"),
        ("beta/prod", "dfars-7012", "72", "1", "dod-dc3 (https://dibnet.dod.mil)", "isso (isso@example.test)",
         "dibnet-eca", "20270601",
         "90", "")]


def _incident(cn, discovered=None, reported=None, refs=(), envs=()):
    attrs = {**({"ciamDiscoveredAt": discovered} if discovered else {}),
             **({"ciamReportedAt": reported} if reported else {})}
    lines = "".join(f"{k}: {v}\n" for k, v in attrs.items()) + "".join(
        f"ciamReportingObligationRef: {r}\n" for r in refs) + "".join(f"ciamAffectedEnvironment: {e}\n" for e in envs)
    return (f"dn: cn={cn},ou=incidents,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamIncident\n"
            f"objectClass: ciamReportableIncident\ncn: {cn}\nciamTitle: {cn}\nciamOpenedAt: 20260920000000Z\n{lines}")


def test_reportable_incidents_report_and_due_times():
    tree = (obligation(), obligation("internal-4h", hours=4, filer=None, authority=None, cert=None),
            _incident("INC-1", "20260920080000Z", "20260922080000Z", envs=(BETA,)),
            _incident("INC-2", "20260920080000Z", "20260924080000Z", refs=(DFARS,)),
            _incident("INC-3", "20260928080000Z", envs=(BETA,)),
            _incident("INC-4", "20260930120000Z", refs=(DFARS, f"cn=internal-4h,{OBLIGATIONS}")),
            _incident("INC-5", refs=(DFARS,)), _incident("INC-6", "20260928080000Z"))
    _, d = _ctx(tree=tree, changes=(held(BETA, DFARS),))
    assert [o.dn for o in incident_obligations(d, _get(d, "INC-1"))] == [DFARS]
    assert report_due(d, _get(d, "INC-4")) == dt.datetime(2026, 9, 30, 16, tzinfo=dt.timezone.utc)
    assert report_due(d, _get(d, "INC-5")) is None
    assert [(r[0], r[1], r[2], r[4], r[7]) for r in reportable_incident_rows(d, as_of=dt.date(2026, 10, 1))] == [
        ("INC-1", "dfars-7012", "beta/prod", "2026-09-23 08:00Z", "on time"),
        ("INC-2", "dfars-7012", "", "2026-09-23 08:00Z", "late"),
        ("INC-3", "dfars-7012", "beta/prod", "2026-10-01 08:00Z", "open"),
        ("INC-4", "dfars-7012, internal-4h", "", "2026-09-30 16:00Z", "overdue"),
        ("INC-5", "dfars-7012", "", "", "discovery not recorded")]


def _get(d, cn):
    return get(d, f"cn={cn},ou=incidents,dc=ciam-ops")


def test_a_lock_counts_as_days_kept_and_only_monitoring_records_are_judged():
    beta = (detector(BETA), channel(BETA),
            entry(BETA, "security-alerts", "ciamLogDestination", ciamBindingRole="security-alerts",
                  ciamDestinationKind="workspace", ciamRetentionDays="30"),
            entry(BETA, "archive", "ciamObjectStore", ciamBindingRole="audit-archive", ciamStorageRef="s3://archive",
                  ciamStorageImmutability="compliance", ciamStorageLockDays="400"),
            entry(BETA, "cloudtrail", "ciamAuditTrail", ciamBindingRole="audit-trail", ciamAuditScope="account",
                  ciamLogDestinationRole="audit-archive"),
            entry(BETA, "recorder", "ciamSecurityService", ciamBindingRole="config-recording",
                  ciamSecurityKind="config-recording", ciamRetentionDays="7"))
    ctx, _ = _ctx(beta=beta, tree=(obligation(),), changes=(held(BETA, DFARS),))
    assert [b[1].split(": ")[1].split(". ")[0] for b in check_incident_reporting(ctx).blockers] == [
        "threat-detection `detector` 30 days"]
