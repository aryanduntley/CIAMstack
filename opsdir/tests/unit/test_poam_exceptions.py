"""POA&M, exceptions and compliance assessments (core estate): an exception in force accepts the planner findings it
names for its environments (shown, not counted; never the unacceptable ones); an approved exception missing what makes
it stand blocks; expired, outliving its item, or the source's without a target counterpart give actions; POA&M items
overdue or open against a framework the target is assessed against give actions; CMMC Level 2 eligibility; a cloud's
suppression nobody's exception covers blocks, one wider than its exception gives an action; suppressions are local to
their environment; the reports."""
import datetime as dt

from opsdir.connectors.plan import _check_roles
from opsdir.core.directory import get
from opsdir.core.findings import findings
from opsdir.core.inventory import resource
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.poam import (accept_exceptions, acceptable, assessment_rows, check_poam, exception_of,
                                        exception_rows, in_force, poam_rows, requirement_number, suppression_prepare)
from network_fixtures import ALPHA, BETA, context, entry, model

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
AO = "cn=ao,ou=owners,dc=ciam-ops"
OWNER = "cn=ciam,ou=owners,dc=ciam-ops"
TREE = (OU.format("owners"), OU.format("exceptions"), OU.format("poam"), OU.format("assessments"),
        f"dn: {AO}\nobjectClass: top\nobjectClass: ciamParty\ncn: ao\nciamOwnerKind: team\n"
        "ciamDisplayName: Authorizing official\n",
        f"dn: {OWNER}\nobjectClass: top\nobjectClass: ciamParty\ncn: ciam\nciamOwnerKind: team\n")


def _ldif(dn, classes, attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))
    return f"dn: {dn}\nobjectClass: top\n" + "".join(f"objectClass: {c}\n" for c in classes) + lines


def exception(cn, envs=(BETA,), status="approved", expires="20270101000000Z", **more):
    attrs = {"cn": cn, "ciamExceptionKind": "risk-acceptance", "ciamExceptionStatus": status,
             "ciamAffectedEnvironment": tuple(envs), "ciamApprovedBy": "CAB 2026-09-18", "ciamRiskAuthority": AO,
             "ciamOwner": OWNER, **({"ciamExpiresAt": expires} if expires else {}), **more}
    return _ldif(f"cn={cn},ou=exceptions,dc=ciam-ops", ("ciamRiskException",), {k: v for k, v in attrs.items() if v})


def item(cn, envs=(BETA,), controls=("nist-800-171-r2:3.13.11",), status="open", scheduled="20261231000000Z", **more):
    return _ldif(f"cn={cn},ou=poam,dc=ciam-ops", ("ciamPoamItem",),
                 {"cn": cn, "ciamWeakness": f"{cn} weakness", "ciamPoamStatus": status,
                  "ciamAffectedEnvironment": tuple(envs), "ciamControlRef": tuple(controls),
                  "ciamScheduledCompletion": scheduled, **more})


def assessment(cn, score=100, status="conditional", at="20260801000000Z", envs=(BETA,), framework="cmmc-l2"):
    return _ldif(f"cn={cn},ou=assessments,dc=ciam-ops", ("ciamComplianceAssessment",),
                 {"cn": cn, "ciamFramework": framework, "ciamAssessmentKind": "c3pao", "ciamAssessedAt": at,
                  "ciamAssessmentScore": str(score), "ciamAssessmentMaxScore": "110", "ciamAssessmentStatus": status,
                  "ciamAffectedEnvironment": tuple(envs)})


def _ctx(tree=(), alpha=(), beta=()):
    d, a, b = model(alpha=alpha, beta=beta, tree=(*TREE, *tree))
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_the_record_holds_no_exception_item_assessment_or_suppression():
    ctx, _ = _ctx()
    assert check_poam(ctx) == findings()


def test_an_exception_in_force_accepts_the_findings_it_names_never_the_unacceptable_ones():
    ctx, d = _ctx(tree=(exception("EXC-1", ciamAcceptsFinding=("Budgets: has a budget", "Security: runs none",
                                                                "Binding: Role `budget`")),))
    blockers = [("Security", "alpha/prod runs posture and beta/prod runs none", "o"),
                ("Binding", "Role `budget` is bound in alpha/prod but not in beta/prod.", "o")]
    actions = [("Budgets", "alpha/prod has a budget and beta/prod none", "o", None), ("Tags", "untagged", "o", None)]
    b, a, accepted = accept_exceptions(ctx, blockers, actions)
    assert [x[0] for x in b] == ["Security"] and [x[0] for x in a] == ["Tags"]
    assert [(k, area, why) for k, area, _, _, why in accepted] == [
        ("blocker", "Binding", "EXC-1 (risk-acceptance) until 2027-01-01 by Authorizing official"),
        ("action", "Budgets", "EXC-1 (risk-acceptance) until 2027-01-01 by Authorizing official")]
    assert not acceptable("blocker", "PingFederate", "has withheld credentials but no credential role")
    assert acceptable("action", "Security", "watches containers")


def test_an_exception_accepts_nothing_for_other_environments_or_once_expired():
    for exc in (exception("EXC-1", envs=(ALPHA,), ciamAcceptsFinding="Tags: untagged"),
                exception("EXC-1", expires="20260901000000Z", ciamAcceptsFinding="Tags: untagged"),
                exception("EXC-1", status="requested", ciamAcceptsFinding="Tags: untagged")):
        ctx, _ = _ctx(tree=(exc,))
        assert accept_exceptions(ctx, [], [("Tags", "untagged", "o", None)])[2] == []


def test_an_approved_exception_missing_what_makes_it_stand_is_a_blocker():
    ctx, d = _ctx(tree=(exception("EXC-1", expires=None, ciamRiskAuthority=None),))
    assert [b[1] for b in check_poam(ctx).blockers] == [
        "Exception `EXC-1` for beta/prod is approved with no risk authority (ciamRiskAuthority), no expiry "
        "(ciamExpiresAt): an acceptance nobody can stand behind. Record it, or withdraw the exception."]
    assert not in_force(get(d, "cn=EXC-1,ou=exceptions,dc=ciam-ops"), dt.date(2026, 10, 1))


def test_expired_outliving_its_item_and_uncarried_exceptions_give_actions():
    ctx, _ = _ctx(tree=(exception("EXC-OLD", expires="20260901000000Z"),
                        item("POAM-1", scheduled="20261115000000Z"),
                        exception("EXC-LONG", ciamPoamRef="cn=POAM-1,ou=poam,dc=ciam-ops"),
                        exception("EXC-SRC", envs=(ALPHA,), ciamControlRef="nist-800-171-r2:3.1.1")))
    texts = [a[1] for a in check_poam(ctx).actions]
    assert texts[0] == ("Exception `EXC-OLD` for beta/prod expired on 2026-09-01: what it accepted counts again. "
                        "Renew it under its risk authority, or close it.")
    assert texts[1].startswith("Exception `EXC-LONG` runs until 2027-01-01, past POA&M item `POAM-1`'s scheduled "
                               "completion (2026-11-15)")
    assert texts[2] == ("alpha/prod's exception `EXC-SRC` (risk-acceptance: nist-800-171-r2:3.1.1) doesn't carry to "
                        "beta/prod: correct the weakness there, or have the risk authority decide for the target.")


def test_poam_items_overdue_or_open_against_an_assessed_framework_give_actions():
    ctx, _ = _ctx(tree=(item("POAM-1", scheduled="20260901000000Z"), item("POAM-2", controls=("pci-dss:8.3",)),
                        assessment("SPRS-1", framework="nist-800-171-r2", status="final"),
                        item("POAM-3", status="closed")))
    texts = [a[1] for a in check_poam(ctx).actions]
    assert texts == [
        "POA&M item `POAM-1` was to be corrected by 2026-09-01 and is still open: correct it, or replan it with its "
        "milestones.",
        "POA&M item `POAM-1` is open against nist-800-171-r2, which beta/prod is assessed against: POAM-1 weakness"]


def test_cmmc_eligibility():
    tree = (assessment("CMMC-1", score=85), item("POAM-A", controls=("cmmc-l2:AC.L2-3.1.20",), ciamPointValue=1),
            item("POAM-B", controls=("nist-800-171-r2:3.5.3",), ciamPointValue=5),
            item("POAM-C", controls=("cmmc-l2:SC.L2-3.13.11",), ciamPointValue=3),
            item("POAM-D", controls=("nist-800-171-r2:3.1.8",)))
    ctx, _ = _ctx(tree=tree)
    f = check_poam(ctx)
    assert [b[1].split(":")[0] for b in f.blockers] == [
        "POA&M item `POAM-A` holds requirement 3.1.20, which CMMC Level 2 never allows on a POA&M "
        "(32 CFR 170.21(a)(2)(iii))",
        "POA&M item `POAM-B` is worth 5 points",
        "Assessment `CMMC-1` scored 85 of 110, under the 0.8 a Conditional CMMC Level 2 status needs."]
    assert [(a[1].split(" (")[0], a[3]) for a in f.actions if "Close out" in a[1] or "no point" in a[1]] == [
        ("Close out `CMMC-1`'s POA&M by 2027-01-28", dt.date(2027, 1, 28)),
        ("POA&M item `POAM-D` records no point value: CMMC eligibility can't be checked", "2026-12-01")]
    ctx, _ = _ctx(tree=(assessment("CMMC-1", score=100, at="20260101000000Z"), item("POAM-D", ciamPointValue=1)))
    assert [b[1] for b in check_poam(ctx).blockers] == [
        "Assessment `CMMC-1`'s Conditional status passed its 180-day POA&M closeout on 2026-06-30 with items still "
        "open: the status has expired."]
    assert [requirement_number(r) for r in ("cmmc-l2:AC.L2-3.1.20", "nist-800-171-r2:3.1.20", "nist-800-53-r5:AC-2")] \
        == ["3.1.20", "3.1.20", None]


def _suppression(env, cn, refs, exc=None):
    return entry(env, cn, "ciamSuppression", ciamBindingRole=f"suppression-{cn}", ciamFindingRef=tuple(refs),
                 **({"ciamExceptionRef": f"cn={exc},ou=exceptions,dc=ciam-ops"} if exc else {}))


def test_suppressions_need_an_exception_in_force_and_no_wider_than_it():
    ctx, _ = _ctx(tree=(exception("EXC-1", ciamFindingRef="aws:securityhub:IAM.6"),
                        exception("EXC-OLD", expires="20260901000000Z")),
                  beta=(_suppression(BETA, "exc-EXC-1", ("aws:securityhub:IAM.6", "aws:securityhub:S3.1"), "EXC-1"),
                        _suppression(BETA, "muted", ("aws:guardduty:Recon",)),
                        _suppression(BETA, "exc-EXC-OLD", ("aws:securityhub:EC2.2",), "EXC-OLD")))
    f = check_poam(ctx)
    assert [b[1] for b in f.blockers] == [
        "Suppression `exc-EXC-OLD` in beta/prod hides aws:securityhub:EC2.2 and carries out exception `EXC-OLD`, which "
        "isn't in force for it: findings nobody approved hiding. Record the exception, or remove the suppression.",
        "Suppression `muted` in beta/prod hides aws:guardduty:Recon and no exception covers it: findings nobody "
        "approved hiding. Record the exception, or remove the suppression."]
    assert [a[1] for a in f.actions if a[1].startswith("Suppression")] == [
        "Suppression `exc-EXC-1` hides aws:securityhub:S3.1, which exception `EXC-1` doesn't cover: narrow it to the "
        "exception's findings."]


def test_suppressions_are_local_to_their_environment():
    ctx, _ = _ctx(alpha=(_suppression(ALPHA, "exc-EXC-1", ("aws:securityhub:IAM.6",)),))
    assert not [b for b in _check_roles(ctx).blockers if "suppression" in b[1]]


def test_a_suppression_read_from_a_cloud_links_its_exception_when_the_record_holds_it():
    _, d = _ctx(tree=(exception("EXC-1"),))
    held = resource("suppression", "arn:x", {"ciamExceptionRef": "EXC-1", "ciamFindingRef": ("aws:securityhub:IAM.6",)})
    gone = resource("suppression", "arn:y", {"ciamExceptionRef": "EXC-9"})
    assert suppression_prepare(d, BETA, held).attrs["ciamExceptionRef"] == ("cn=EXC-1,ou=exceptions,dc=ciam-ops",)
    assert "ciamExceptionRef" not in suppression_prepare(d, BETA, gone).attrs
    assert (exception_of("exc-EXC-1"), exception_of("muted")) == ("EXC-1", None)


def test_reports():
    ctx, d = _ctx(tree=(item("POAM-1", ciamRiskRating="moderate", ciamDiscoverySource="assessment",
                             ciamDiscoveredAt="20260801000000Z", ciamPointValue=3),
                        exception("EXC-1", ciamPoamRef="cn=POAM-1,ou=poam,dc=ciam-ops", ciamControlRef=(
                            "nist-800-171-r2:3.13.11",), ciamAcceptsFinding="Tags: untagged",
                            ciamApprovedAt="20260915000000Z"),
                        assessment("CMMC-1")))
    assert poam_rows(d, as_of=dt.date(2026, 10, 1)) == [
        ("POAM-1", "beta/prod", "nist-800-171-r2:3.13.11", "POAM-1 weakness", "moderate", "assessment 2026-08-01",
         "2026-12-31", "open", "3", "EXC-1")]
    assert exception_rows(d, as_of=dt.date(2026, 10, 1)) == [
        ("EXC-1", "risk-acceptance", "approved", "beta/prod", "nist-800-171-r2:3.13.11", "Tags: untagged",
         "Authorizing official", "CAB 2026-09-18 2026-09-15", "2027-01-01", "yes")]
    assert assessment_rows(d) == [("CMMC-1", "cmmc-l2", "c3pao", "100/110", "conditional", "2026-08-01", "2027-01-28",
                                   "", "beta/prod")]
