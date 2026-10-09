"""Cloud authorizations (core estate): a target that must rely on an authorization (a required level, restricted data)
and relies on none, on one below the level, or not in good standing is blocked; a stale in-scope list, an unmet
configuration and a target outside the source's system boundary give actions; a control the target's authorization
leaves to the customer that the source's covered and nothing meets blocks; services outside the boundary (the
adapters' check); the reports."""
import datetime as dt

from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.authorizations import (authorization_rows, boundary_findings, check_authorization, in_scope,
                                                  level_met, required_levels, responsibility_rows, services_used)
from network_fixtures import ALPHA, BETA, context, entry, model

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
AUTH = "ou=authorizations,dc=ciam-ops"


def _ldif(dn, classes, attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)) if v)
    return f"dn: {dn}\nobjectClass: top\n" + "".join(f"objectClass: {c}\n" for c in classes) + lines


def authorization(cn, levels=("fedramp-high",), status="certified", services=("Svc A", "Svc B [note]"),
                  as_of="20260826000000Z", **more):
    return _ldif(f"cn={cn},{AUTH}", ("ciamCloudAuthorization",),
                 {"cn": cn, "ciamPackageId": cn, "ciamAuthorizationLevel": tuple(levels),
                  "ciamAuthorizationStatus": status, "ciamInScopeService": tuple(services), "ciamScopeAsOf": as_of,
                  **more})


def responsibility(cn, auth, control, who, **more):
    return _ldif(f"cn={cn},ou=responsibilities,dc=ciam-ops", ("ciamControlResponsibility",),
                 {"cn": cn, "ciamAuthorizationRef": f"cn={auth},{AUTH}", "ciamControlRef": control,
                  "ciamResponsibility": who, **more})


def relies(env, auth=None, required=(), restricted=False, met=()):
    ops = (("add", "objectClass", ("ciamEnvironmentPlacement",)),
           *((("replace", "ciamAuthorizationRef", (f"cn={auth},{AUTH}",)),) if auth else ()),
           *((("replace", "ciamRequiredAuthorization", tuple(required)),) if required else ()),
           *((("replace", "ciamConfigurationMet", tuple(met)),) if met else ()),
           *((("replace", "ciamDataClassification", ("restricted",)),) if restricted else ()))
    return LdifRecord(env, "modify", {}, ops)


TREE = (OU.format("authorizations"), OU.format("responsibilities"), OU.format("boundaries"))


def _ctx(tree=(), changes=(), beta=()):
    d, a, b = model(tree=(*TREE, *tree), changes=changes, beta=beta)
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_no_authorization_is_named_or_needed():
    assert check_authorization(_ctx()[0]) == findings()


def test_a_target_that_must_rely_on_an_authorization_and_relies_on_none_is_a_blocker():
    ctx, _ = _ctx(changes=(relies(BETA, required=("fedramp-moderate",)),))
    assert [b[1] for b in check_authorization(ctx).blockers] == [
        "beta/prod relies on no cloud authorization and requires fedramp-moderate: record the authorization of the "
        "offering it runs on (ciamAuthorizationRef)."]
    ctx, _ = _ctx(changes=(relies(BETA, restricted=True),))
    assert check_authorization(ctx).blockers[0][1].endswith(
        "while its data is classified restricted: record the authorization of the offering it runs on "
        "(ciamAuthorizationRef).")


def test_below_level_not_standing_or_equivalent_without_evidence_are_blockers():
    ctx, _ = _ctx(tree=(authorization("AZ", levels=("fedramp-moderate",), status="in-process"),),
                  changes=(relies(BETA, "AZ", required=("fedramp-high", "dod-il4")),))
    assert [b[1].split(":")[0] for b in check_authorization(ctx).blockers] == [
        "beta/prod requires fedramp-high and relies on `AZ`, which grants fedramp-moderate",
        "beta/prod requires dod-il4 and relies on `AZ`, which grants fedramp-moderate",
        "Authorization `AZ` (beta/prod relies on it) is in-process"]
    ctx, _ = _ctx(tree=(authorization("EQ", levels=("fedramp-moderate",), status="equivalent"),),
                  changes=(relies(BETA, "EQ", required=("fedramp-moderate",)),))
    assert [b[1].split(" (")[0] for b in check_authorization(ctx).blockers] == [
        "Authorization `EQ` is recorded as equivalent to FedRAMP Moderate with no evidence"]
    assert level_met(("dod-il5",), "dod-il4") and not level_met(("fedramp-high",), "dod-il4")


def test_stale_scope_unmet_configuration_and_boundary_drift_give_actions():
    boundary = _ldif("cn=ssp,ou=boundaries,dc=ciam-ops", ("ciamSystemBoundary",),
                     {"cn": "ssp", "ciamSspRef": "SSP v4", "ciamAffectedEnvironment": ALPHA})
    ctx, _ = _ctx(tree=(authorization("G", as_of="20260101000000Z", ciamRequiresConfiguration=(
        "assured-workload", "us-person-support")), boundary),
        changes=(relies(BETA, "G", required=("fedramp-moderate",), met=("assured-workload",)),))
    f = check_authorization(ctx)
    assert f.blockers == () and [a[1] for a in f.actions] == [
        "Authorization `G`'s in-scope service list is as of 2026-01-01, more than 90 days ago: import the provider's "
        "current package overview.",
        "Authorization `G` requires us-person-support for a customer's use to be inside its boundary and beta/prod "
        "doesn't record it (ciamConfigurationMet).",
        "alpha/prod is inside system boundary `ssp` and beta/prod in none: update the system security plan to cover "
        "the target."]


def test_a_control_left_to_the_customer_that_the_source_covered_blocks_until_met():
    tree = (authorization("SRC"), authorization("DST"),
            responsibility("r1", "SRC", "nist-800-53-r5:SC-28", "inherited"),
            responsibility("r2", "DST", "nist-800-53-r5:SC-28", "customer", ciamCustomerAction="encrypt at rest"),
            responsibility("r3", "DST", "nist-800-53-r5:AC-2", "customer"))
    ctx, d = _ctx(tree=tree, changes=(relies(ALPHA, "SRC"), relies(BETA, "DST", required=("fedramp-high",))))
    assert [b[1] for b in check_authorization(ctx).blockers] == [
        "nist-800-53-r5:SC-28 is the customer's under `DST` and was covered by `SRC`: encrypt at rest. Record how it "
        "is met (ciamImplementation), or an exception or POA&M item."]
    assert responsibility_rows(d) == [("SRC", "nist-800-53-r5:SC-28", "inherited", "", ""),
                                      ("DST", "nist-800-53-r5:SC-28", "customer", "encrypt at rest",
                                       "nothing recorded"),
                                      ("DST", "nist-800-53-r5:AC-2", "customer", "", "nothing recorded")]


def test_services_outside_the_boundary():
    store = entry(BETA, "data", "ciamObjectStore", ciamBindingRole="data", ciamStorageRef="s3://x")
    ctx, _ = _ctx(tree=(authorization("DST"),), changes=(relies(BETA, "DST", required=("fedramp-high",)),),
                  beta=(store,))
    used = services_used(ctx.dst, {"ciamObjectStore": "Svc C"}, "Svc B")
    assert [u[0] for u in used] == ["Svc B", "Svc C"]
    assert [b[1].split(", which")[0] for b in boundary_findings(ctx, used).blockers] == [
        "beta/prod uses Svc C (data)"]
    assert in_scope("Svc B", {"Svc B [note]"}) and not in_scope("Svc", {"Svc B"})


def test_required_levels_come_from_the_environment_and_its_obligations_and_the_report():
    obligation = _ldif("cn=dfars-7012,ou=reporting-obligations,dc=ciam-ops", ("ciamReportingObligation",),
                       {"cn": "dfars-7012", "ciamReportingHours": "72",
                        "ciamRequiredAuthorization": "fedramp-moderate"})
    ctx, d = _ctx(tree=(OU.format("reporting-obligations"), obligation, authorization("DST")), changes=(
        relies(BETA, "DST", required=("dod-il4",)),
        LdifRecord(BETA, "modify", {}, (("replace", "ciamReportingObligationRef",
                                         ("cn=dfars-7012,ou=reporting-obligations,dc=ciam-ops",)),))))
    assert required_levels(ctx.dst) == ("dod-il4", "fedramp-moderate")
    assert authorization_rows(d, as_of=dt.date(2026, 10, 1)) == [
        ("DST", "", "", "fedramp-high", "certified", "", "", "2", "2026-08-26", "beta/prod")]
