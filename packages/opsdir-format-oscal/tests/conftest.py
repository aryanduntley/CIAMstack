"""The OSCAL tests' record (fixture oscal_record): system boundary `enclave` (SSP-ENCLAVE v2) holding alpha/prod and
beta/prod, both relying on authorization AZ; POA&M items keys-fips (beta, open, two controls, milestones, from
assessment cmmc-2026) and mfa-gap (alpha, closed); exceptions keys-deviation (approved, of keys-fips), lab-acceptance
(requested) and rejected-one (rejected); assessment cmmc-2026; AZ's control responsibilities; boundary `empty` holding
no environment. The `oscal` marker is registered here (OSCAL schema validation, skipped without the schema)."""
from types import SimpleNamespace

import pytest

from opsdir.core.interchange.ldif import LdifRecord
from network_fixtures import ALPHA, BETA, model

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
AO = "cn=ao,ou=owners,dc=ciam-ops"
OWNER = "cn=ciam,ou=owners,dc=ciam-ops"
AUTH = "cn=AZ,ou=authorizations,dc=ciam-ops"
POAM = "ou=poam,dc=ciam-ops"
ENCLAVE = "cn=enclave,ou=boundaries,dc=ciam-ops"


def ldif(dn, classes, attrs):
    lines = "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)) if v)
    return f"dn: {dn}\nobjectClass: top\nobjectClass: ciamObject\n" + "".join(f"objectClass: {c}\n"
                                                                                for c in classes) + lines


def _item(cn, envs, controls, status="open", **more):
    return ldif(f"cn={cn},{POAM}", ("ciamPoamItem",), {"cn": cn, "ciamWeakness": f"{cn} weakness",
                                                       "ciamPoamStatus": status, "ciamAffectedEnvironment": envs,
                                                       "ciamControlRef": controls, **more})


def _exception(cn, status, envs, **more):
    return ldif(f"cn={cn},ou=exceptions,dc=ciam-ops", ("ciamRiskException",), {
        "cn": cn, "ciamExceptionKind": "risk-acceptance", "ciamExceptionStatus": status,
        "ciamAffectedEnvironment": envs,
        "ciamRiskAuthority": AO, "ciamOwner": OWNER, **more})


def _responsibility(cn, control, who, **more):
    return ldif(f"cn={cn},ou=responsibilities,dc=ciam-ops", ("ciamControlResponsibility",), {
        "cn": cn, "ciamAuthorizationRef": AUTH, "ciamControlRef": control, "ciamResponsibility": who, **more})


TREE = (*(OU.format(o) for o in ("owners", "poam", "exceptions", "assessments", "authorizations", "responsibilities",
                                 "boundaries")),
        f"dn: {AO}\nobjectClass: top\nobjectClass: ciamParty\ncn: ao\nciamOwnerKind: team\n",
        f"dn: {OWNER}\nobjectClass: top\nobjectClass: ciamParty\ncn: ciam\nciamOwnerKind: team\n",
        ldif(ENCLAVE, ("ciamSystemBoundary",), {"cn": "enclave", "ciamSspRef": "SSP-ENCLAVE v2",
                                                "ciamAffectedEnvironment": (ALPHA, BETA), "ciamRiskAuthority": AO}),
        ldif("cn=empty,ou=boundaries,dc=ciam-ops", ("ciamSystemBoundary",), {"cn": "empty"}),
        _item("keys-fips", BETA, ("nist-800-171-r2:3.13.11", "nist-800-53-r5:SC-13"),
              ciamScheduledCompletion="20261231000000Z", ciamRiskRating="moderate", ciamPointValue="3",
              ciamDiscoverySource="assessment", ciamDiscoveredAt="20260801120000Z", ciamAssessmentRef="cmmc-2026",
              ciamVendorDependency="TRUE", ciamLastReviewedAt="20260910000000Z",
              ciamMilestone=("2026-11-30: keys moved to the HSM", "vendor sign-off")),
        _item("mfa-gap", ALPHA, ("nist-800-53-r5:IA-2(1)",), status="closed", ciamDiscoveredAt="20260601000000Z"),
        _exception("keys-deviation", "approved", BETA, ciamPoamRef=f"cn=keys-fips,{POAM}",
                   ciamJustification="FIPS module on order", ciamApprovedBy="CAB", ciamApprovedAt="20260905000000Z",
                   ciamExpiresAt="20270101000000Z", ciamControlRef="nist-800-53-r5:SC-13"),
        _exception("lab-acceptance", "requested", ALPHA),
        _exception("rejected-one", "rejected", BETA),
        ldif("cn=cmmc-2026,ou=assessments,dc=ciam-ops", ("ciamComplianceAssessment",), {
            "cn": "cmmc-2026", "ciamFramework": "cmmc-l2", "ciamAssessmentKind": "c3pao",
            "ciamAssessedAt": "20260801000000Z", "ciamAssessmentScore": "100", "ciamAssessmentMaxScore": "110",
            "ciamAssessmentStatus": "conditional", "ciamAffectedEnvironment": BETA,
            "ciamEvidenceRef": "https://evidence.example/cmmc-2026"}),
        ldif(AUTH, ("ciamCloudAuthorization",), {"cn": "AZ", "ciamPackageId": "AZ", "ciamOfferingName": "Example Gov",
                                                 "ciamScopeAsOf": "20260826000000Z"}),
        _responsibility("crm-sc13", "nist-800-53-r5:SC-13", "shared", ciamImplementation="Keys in the HSM"),
        _responsibility("crm-ac2", "nist-800-53-r5:AC-2", "inherited"),
        _responsibility("crm-ia2", ("nist-800-53-r5:IA-2(1)", "nist-800-171-r2:3.5.3"), "customer",
                        ciamCustomerAction="Enforce MFA"))


def relies(env):
    return LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                          ("replace", "ciamAuthorizationRef", (AUTH,))))


def build(tree=()):
    """(directory, alpha model, beta model) of the record, with more records added."""
    return model(tree=(*TREE, *tree), changes=(relies(ALPHA), relies(BETA)))


def pytest_configure(config):
    config.addinivalue_line("markers", "oscal: validates written OSCAL against NIST's schema "
                                       "(tools/oscal/<version>, opsdir/scripts/fetch-tools.sh); skipped without it")


@pytest.fixture(scope="session")
def oscal_record():
    """The record (d, alpha, beta), build(tree) for a variant, and the DNs the tests name."""
    d, alpha, beta = build()
    return SimpleNamespace(d=d, alpha=alpha, beta=beta, build=build, ldif=ldif, ENCLAVE=ENCLAVE, POAM=POAM,
                           ALPHA=ALPHA, BETA=BETA, AUTH=AUTH)
