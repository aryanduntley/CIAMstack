"""The access domain: permission sets (verbs on binding roles) and the principals holding them as intent, the cloud
identities, guardrails and ways in each environment binds, their reports, and the planner's findings when a principal
has nothing to act as, nobody owns or reviews it, a break-glass account couldn't be used, an identity nobody described
runs in the source, or the target lacks a guardrail's prevention or a way in the source has."""
import datetime as dt
import re

from opsdir.connectors.plan import plan, request_drafts
from opsdir.core.contract import PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.access.identities import access_path_rows, check_identities, guardrail_rows, identity_rows
from opsdir.domains.access.naming import PERMISSION_SETS, PERMIT, PRINCIPALS
from opsdir.domains.access.schema import ATTRIBUTES
from opsdir.domains.access.principals import check_principals, permits, principal_rows, principals
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS = "cn=ops,ou=owners,dc=ciam-ops"
RUNBOOK = "cn=WI-9,ou=runbooks,dc=ciam-ops"
AS_OF = dt.date(2026, 10, 1)


def _ou(dn, ou):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {ou}\n"


def _entry(dn, oc, attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _binding(env, cn, oc, role, attrs):
    return _entry(f"cn={cn},ou=bindings,{env}", oc, {"cn": cn, "ciamBindingRole": role, **attrs})


def _principal(cn, kind, identity, **attrs):
    return _entry(f"cn={cn},{PRINCIPALS}", "ciamPrincipal",
                  {"cn": cn, "ciamPrincipalKind": kind, "ciamIdentityRole": identity, **attrs})


RUNTIME, BACKUP = f"cn=pf-runtime,{PERMISSION_SETS}", f"cn=backup-writer,{PERMISSION_SETS}"
BASE = (
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    _ou("ou=runbooks,dc=ciam-ops", "runbooks"),
    f"dn: {RUNBOOK}\nobjectClass: top\nobjectClass: ciamRunbook\ncn: WI-9\nciamTitle: Break glass\n"
    "ciamLastReviewed: 20260101000000Z\n",
    _ou(PERMISSION_SETS, "permission-sets"),
    _entry(RUNTIME, "ciamPermissionSet", {"cn": "pf-runtime", "ciamPermits": ("read-secret pf-admin-password",
                                                                             "use-key disk-encryption")}),
    _entry(BACKUP, "ciamPermissionSet", {"cn": "backup-writer", "ciamPermits": "write-storage backup-target"}),
    _ou(PRINCIPALS, "principals"),
    _principal("pf-engine", "workload", "identity-pf-engine", ciamTargetRole="pf-engine", ciamHoldsSet=RUNTIME,
               ciamOwner=OPS, ciamReviewedOn="20260601000000Z"),
    _principal("ds-backup", "workload", "identity-ds-backup", ciamHoldsSet=BACKUP),
    _principal("ops-admins", "operator", "admin-sso", ciamHoldsSet=RUNTIME, ciamCondition="mfa", ciamOwner=OPS,
               ciamReviewedOn="20250101000000Z"),
    _principal("break-glass", "break-glass", "break-glass", ciamOwner=OPS, ciamReviewedOn="20260901000000Z",
               ciamUsesRole="bg-password", ciamLastTested="20260101000000Z"),
    *(_binding(env, "identity-pf-engine", "ciamIdentityBinding", "identity-pf-engine", attrs) for env, attrs in (
        (ALPHA, {"ciamProviderRef": "arn:aws:iam::111122223333:role/ciam-pf-engine", "ciamIdentityKind": "role",
                 "ciamTrustedBy": "ec2.amazonaws.com",
                 "ciamGrant": "secretsmanager:GetSecretValue on arn:aws:secretsmanager:r:1:secret:pf-admin"}),
        (BETA, {"ciamProviderRef": "/subscriptions/0/resourceGroups/rg/providers/Microsoft.ManagedIdentity/"
                                   "userAssignedIdentities/id-pf-engine", "ciamIdentityKind": "managed-identity"}))),
    _binding(ALPHA, "identity-legacy", "ciamIdentityBinding", "identity-legacy",
             {"ciamProviderRef": "arn:aws:iam::111122223333:role/legacy-reports", "ciamIdentityKind": "role"}),
    *(_binding(env, "admin-sso", "ciamIdentityBinding", "admin-sso",
               {"ciamProviderRef": ref, "ciamIdentityKind": kind}) for env, ref, kind in (
        (ALPHA, "arn:aws:sso:::permissionSet/ssoins-1/ps-1", "permission-set"), (BETA, "grp-ciam-admins", "group"))),
    *(_binding(env, "break-glass", "ciamIdentityBinding", "break-glass", {"ciamProviderRef": ref,
                                                                        "ciamIdentityKind": "user"})
      for env, ref in ((ALPHA, "arn:aws:iam::111122223333:user/break-glass"), (BETA, "bg-admin@example.test"))),
    _binding(ALPHA, "scp-baseline", "ciamGuardrail", "guardrail-baseline",
             {"ciamGuardrailKind": "service-control", "ciamProviderRef": "p-1",
              "ciamDenies": ("region-escape", "audit-log-disable")}),
    _binding(BETA, "policy-baseline", "ciamGuardrail", "guardrail-baseline",
             {"ciamGuardrailKind": "policy-assignment", "ciamDenies": "region-escape", "ciamOwner": OPS}),
    _binding(ALPHA, "sso", "ciamAccessPath", "admin-path", {"ciamAccessKind": "workforce-sso",
                                                            "ciamTrustedBy": "entra-id"}),
    _binding(ALPHA, "ssm", "ciamAccessPath", "admin-session", {"ciamAccessKind": "session",
                                                               "ciamGrant": "ssm:StartSession on instances"}),
    _binding(BETA, "sso", "ciamAccessPath", "admin-path", {"ciamAccessKind": "workforce-sso"}),
)


def _record(*extra):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*BASE, *extra)))))


def _plan(d, check):
    return check(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ()))


def test_permits_and_the_principals_report():
    d = _record()
    rows = {r[0]: r for r in principal_rows(d, None, AS_OF)}
    assert rows["pf-engine"] == ("pf-engine", "workload", "identity-pf-engine", "pf-engine", "pf-runtime",
                                 "read-secret pf-admin-password, use-key disk-encryption", "", "ops", "2026-06-01", "")
    assert rows["ds-backup"][-1] == "no owner; never reviewed"
    assert rows["ops-admins"][6] == "mfa" and rows["ops-admins"][-1] == \
        "review overdue (last 2025-01-01, every 365 days)"
    assert rows["break-glass"][-1] == "break-glass: no procedure; break-glass: last tested 2026-01-01"
    backup = next(p for p in principals(d) if p.dn.startswith("cn=ds-backup"))
    assert permits(d, backup) == ("write-storage backup-target",)


def test_identities_guardrails_and_access_paths_reports():
    d = _record()
    identities = {(r[0], r[1]): r for r in identity_rows(d)}
    assert identities[("alpha/prod", "identity-pf-engine")][3:6] == ("role", "pf-engine", "ec2.amazonaws.com")
    assert identities[("alpha/prod", "identity-legacy")][4] == ""                  # nobody acts as it
    assert guardrail_rows(d) == [("alpha/prod", "scp-baseline", "service-control", "region-escape, audit-log-disable",
                                  "p-1"),
                                 ("beta/prod", "policy-baseline", "policy-assignment", "region-escape", "")]
    assert [r[:3] for r in access_path_rows(d)] == [("alpha/prod", "ssm", "session"),        # by environment, name
                                                    ("alpha/prod", "sso", "workforce-sso"),
                                                    ("beta/prod", "sso", "workforce-sso")]


def test_principals_without_identity_owner_review_or_a_usable_break_glass_are_found():
    found = _plan(_record(), check_principals)
    assert [b[1] for b in found.blockers] == [
        "Principal `ds-backup` acts as role `identity-ds-backup`, which neither alpha/prod nor beta/prod binds: "
        "record the identity each environment gives it."]
    assert {a[1] for a in found.actions} == {
        "Principal `ds-backup`: no owner.", "Principal `ds-backup`: never reviewed.",
        "Principal `ops-admins`: review overdue (last 2025-01-01, every 365 days).",
        "Principal `break-glass`: break-glass: no procedure.",
        "Principal `break-glass`: break-glass: last tested 2026-01-01."}


def test_undescribed_identities_and_what_the_target_lacks_are_actions():
    found = _plan(_record(), check_identities)
    assert found.blockers == () and [a[1] for a in found.actions] == [
        "alpha/prod runs identity `identity-legacy` (arn:aws:iam::111122223333:role/legacy-reports), which no "
        "principal acts as (role `identity-legacy`): record who uses it and what it may do, or retire it.",
        "alpha/prod's guardrail `scp-baseline` prevents `audit-log-disable`; nothing in beta/prod does: ask its "
        "landing zone's owners for the same guardrail.",
        "Operators come into alpha/prod by session (`ssm`); beta/prod records no such way in: record it, or how "
        "operators reach it instead."]


def test_what_the_target_lacks_is_requested_from_its_landing_zones_keeper():
    d = _record()
    found = _plan(d, check_identities)
    assert [(party.dn, text) for party, _, text, _, _ in found.requests] == [
        (OPS, "A guardrail preventing `audit-log-disable` (as alpha/prod's `scp-baseline` does)."),
        (OPS, "A way for operators to come in by session (as alpha/prod's `ssm`).")]
    drafts = request_drafts(plan(d, "alpha/prod", "beta/prod", AS_OF, installed=(mini_estate.FAKE,)))
    draft = drafts["requests/ops.md"]
    assert draft.startswith("To: ops <n/a>\nSubject: Landing zone changes needed for beta/prod")
    assert "- A guardrail preventing `audit-log-disable`" in draft and "terraform/landing-zone/" in draft


def test_a_permit_is_a_known_verb_on_a_role():
    (rule,) = [x for a in ATTRIBUTES if a.name == "ciamPermits" for x in a.rules]     # the store enforces it
    assert rule == ("X-PATTERN", PERMIT)
    assert re.fullmatch(PERMIT, "read-secret pf-admin-password") and re.fullmatch(PERMIT, "manage service-names")
    assert not re.fullmatch(PERMIT, "delete-everything pf-admin-password") and not re.fullmatch(PERMIT, "use-key")
