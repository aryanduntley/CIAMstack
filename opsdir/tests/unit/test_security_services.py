"""Cloud security services (core estate): a target without a kind the source runs blocks the move for threat detection
and vulnerability scanning, for posture against a regulatory framework and for exported configuration history, else
gives an action; a target service whose findings go to a role it doesn't bind blocks; a narrower target gives actions,
blockers where its data is classified restricted; the security-services report."""
from opsdir.core.directory import make_entry
from opsdir.core.findings import findings
from opsdir.core.inventory import resource
from opsdir.domains.estate.security import (check_security, security_role, security_rows, security_services,
                                            service_coverage)
from network_fixtures import ALPHA, BETA, context, entry, model

PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
AREAS = ("control-plane", "network", "containers")


def service(env, cn, kind, findings_role="security-alerts", **more):
    return entry(env, cn, "ciamSecurityService", ciamBindingRole=kind, ciamSecurityKind=kind,
                 **({"ciamFindingsRole": findings_role} if findings_role else {}), **more)


def detector(env, areas=AREAS, **more):
    return service(env, "detector", "threat-detection", ciamSecurityCoverage=tuple(areas),
                   **{"ciamAuditScope": "account", "ciamAllRegions": "TRUE", **more})


def channel(env):
    return entry(env, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts", ciamChannelKind="topic")


def _ctx(alpha=(), beta=(), restricted=False):
    d, a, b = model(alpha=alpha, beta=beta, tree=OWNERS)
    if restricted:
        b = b._replace(env=make_entry(b.env.dn, (*b.env.classes, "ciamEnvironmentPlacement"),
                                      {**b.env.attrs, "ciamDataClassification": ("restricted",)}))
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_neither_environment_records_a_service():
    ctx, _ = _ctx()
    assert check_security(ctx) == findings()


def test_a_target_without_threat_detection_or_vulnerability_scanning_is_a_blocker():
    ctx, _ = _ctx(alpha=(detector(ALPHA), service(ALPHA, "scanner", "vulnerability-scanning"), channel(ALPHA)))
    f = check_security(ctx)
    assert [b[1] for b in f.blockers] == [
        "alpha/prod runs threat-detection (detector) and beta/prod runs none: threats to the target's cloud would go "
        "undetected. Record the target's (its own, or the organization's the landing zone keeps).",
        "alpha/prod runs vulnerability-scanning (scanner) and beta/prod runs none: the target's vulnerabilities would "
        "go unfound. Record the target's (its own, or the organization's the landing zone keeps)."]
    assert f.actions == ()


def test_posture_blocks_only_against_a_regulatory_framework_and_recording_only_when_exported():
    ctx, _ = _ctx(alpha=(service(ALPHA, "hub", "posture", ciamComplianceStandard=("nist-800-171-r2", "cis")),
                         service(ALPHA, "recorder", "config-recording"), channel(ALPHA)))
    f = check_security(ctx)
    assert [b[1] for b in f.blockers] == [
        "alpha/prod runs config-recording (recorder, exporting its history) and beta/prod runs none: changes to the "
        "target's resources would go unrecorded. Record the target's (its own, or the organization's the landing zone "
        "keeps).",
        "alpha/prod runs posture (hub, against nist-800-171-r2) and beta/prod runs none: the target's posture would go "
        "unassessed. Record the target's (its own, or the organization's the landing zone keeps)."]
    ctx, _ = _ctx(alpha=(service(ALPHA, "hub", "posture", findings_role=None, ciamComplianceStandard=("cis",)),
                         service(ALPHA, "recorder", "config-recording", findings_role=None)))
    f = check_security(ctx)
    assert f.blockers == () and [(a[1].split(":")[0], a[3]) for a in f.actions] == [
        ("alpha/prod runs config-recording (recorder) and beta/prod runs none", "2026-12-01"),
        ("alpha/prod runs posture (hub) and beta/prod runs none", "2026-12-01")]


def test_a_target_service_whose_findings_reach_no_one_is_a_blocker():
    ctx, _ = _ctx(alpha=(detector(ALPHA), channel(ALPHA)), beta=(detector(BETA),))
    assert [b[1] for b in check_security(ctx).blockers] == [
        "Security service `detector` in beta/prod sends its findings to role `security-alerts`, which beta/prod "
        "doesn't bind: they reach no one. Record where they go."]


def _narrow():
    return (dict(alpha=(detector(ALPHA, ciamAuditScope="organization", ciamRetentionDays="0"),
                        service(ALPHA, "hub", "posture", ciamComplianceStandard=("nist-800-53-r5",),
                                ciamSecurityBaseline=("aws-foundational",)), channel(ALPHA)),
                 beta=(detector(BETA, areas=("control-plane",), findings_role=None, ciamAllRegions="FALSE",
                                ciamRetentionDays="90"),
                       service(BETA, "defender", "posture", ciamComplianceStandard=("cis",)), channel(BETA))))


def test_a_narrower_target_gives_actions():
    ctx, _ = _ctx(**_narrow())
    f = check_security(ctx)
    assert f.blockers == () and [(a[1], a[3]) for a in f.actions] == [
        ("alpha/prod's threat-detection watches network, containers and beta/prod's doesn't: turn it on in the target "
         "(or record what watches it there).", "2026-12-01"),
        ("alpha/prod's threat-detection covers the whole organization and beta/prod's one account: accounts added "
         "later would go uncovered.", "2026-12-01"),
        ("alpha/prod's threat-detection runs in every region and beta/prod's in one: the target's other regions would "
         "go uncovered.", "2026-12-01"),
        ("alpha/prod's threat-detection sends its findings on and beta/prod's keeps them in the service: send them "
         "where someone acts on them.", "2026-12-01"),
        ("alpha/prod keeps its threat-detection records forever and beta/prod 90 days: keep the target's at least as "
         "long.", "2026-12-01"),
        ("alpha/prod is assessed against nist-800-53-r5 and beta/prod isn't: assess the target against it (or decide "
         "it no longer applies).", "2026-12-01"),
        ("alpha/prod is assessed against its cloud's own baseline (aws-foundational) and beta/prod against none: turn "
         "on the target cloud's.", "2026-12-01")]


def test_a_target_keeping_its_configuration_history_in_the_service_is_asked_to_export_it():
    ctx, _ = _ctx(alpha=(service(ALPHA, "recorder", "config-recording"), channel(ALPHA)),
                  beta=(service(BETA, "changes", "config-recording", findings_role=None),))
    assert [a[1] for a in check_security(ctx).actions] == [
        "alpha/prod exports its configuration history and beta/prod keeps it in the service only: export the "
        "target's (or decide the service's own history is enough)."]


def test_a_narrower_target_holding_restricted_data_is_blocked():
    ctx, _ = _ctx(**_narrow(), restricted=True)
    f = check_security(ctx)
    assert f.actions == () and len(f.blockers) == 7
    assert f.blockers[0][1].endswith("beta/prod's data is classified restricted: this blocks the move.")


def test_a_target_as_strong_as_the_source_is_ok():
    ctx, _ = _ctx(alpha=(detector(ALPHA), channel(ALPHA)), beta=(detector(BETA, areas=SECURITY_ALL), channel(BETA)))
    f = check_security(ctx)
    assert (f.blockers, f.actions, f.ok) == ((), (), ("Security services recorded in beta/prod: threat-detection.",))
    assert service_coverage(ctx.src, security_services(ctx.src)) == (AREAS, (), (), False, True, True, None)


SECURITY_ALL = ("control-plane", "identity", "network", "compute", "containers", "storage")


def test_the_report_and_the_import_role():
    _, d = _ctx(alpha=(detector(ALPHA, ciamRetentionDays="365"), channel(ALPHA)),
                beta=(service(BETA, "org-hub", "posture", findings_role=None, ciamManagedBy=PARTY,
                              ciamComplianceStandard=("cmmc-l2",), ciamSecurityBaseline=("mcsb",)),))
    assert security_rows(d) == [
        ("alpha/prod", "detector", "threat-detection", "account", "yes", "control-plane, network, containers", "",
         "security-alerts", "365", "platform"),
        ("beta/prod", "org-hub", "posture", "", "", "", "cmmc-l2, mcsb", "", "", "landing-zone")]
    assert security_role(resource("security", "arn:x", {"ciamSecurityKind": "posture"}), {}) == "posture"
