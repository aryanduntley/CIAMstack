"""A cloud's grants read as the record's permissions, through a fake cloud's permission table: grants parsed, permits
granted or not (or not tellable), escalation and wildcard grants, and the planner's findings: what each environment's
identities are granted beyond or short of their principals' permissions, and what the target would lose."""
import datetime as dt

from opsdir.core.contract import AccessModel, Permission, PlanContext
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.connectors.access import access_check, access_model
from opsdir.domains.access.grants import covered, escalating, grant_of, granted, wildcard
from opsdir.domains.access.naming import PERMISSION_SETS, PRINCIPALS
from opsdir.domains.access.workloads import identity_of, workload_identities
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
OPS = "cn=ops,ou=owners,dc=ciam-ops"


def _covers(granted_resource, binding):
    """The fake cloud names a secret by its URI's path; a grant on a parent path covers it."""
    resource = (one(binding, "ciamRefUri") or "").split("://", 1)[-1]
    return granted_resource == resource or resource.startswith(granted_resource.rstrip("/") + "/")


MODEL = AccessModel(permissions=(Permission("read-secret", "ciamSecretRef", None, (("sm:Get",),), False),
                                 Permission("write-secret", "ciamSecretRef", None, (("sm:Put",), ("sm:Get",)), False),
                                 Permission("manage", "ciamSecretRef", None, (("roles/owner",),), False)),
                    escalations=("iam:PassRole", "roles/owner"), covers=_covers, resource=lambda b: None)
FAKE = mini_estate.FAKE._replace(access=MODEL)


def _entry(dn, oc, attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _binding(env, cn, oc, role, attrs):
    return _entry(f"cn={cn},ou=bindings,{env}", oc, {"cn": cn, "ciamBindingRole": role, **attrs})


def _record(alpha_grants, beta_grants, permits=("read-secret app-password", "read-secret unbound-secret"),
            beta_attrs=None):
    entries = (
        "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
        f"dn: {OPS}\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
        f"dn: {PERMISSION_SETS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
        _entry(f"cn=runtime,{PERMISSION_SETS}", "ciamPermissionSet",
               {"cn": "runtime", "ciamPermits": permits}),
        f"dn: {PRINCIPALS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
        _entry(f"cn=app,{PRINCIPALS}", "ciamPrincipal",
               {"cn": "app", "ciamPrincipalKind": "workload", "ciamIdentityRole": "identity-app",
                "ciamTargetRole": "web", "ciamHoldsSet": f"cn=runtime,{PERMISSION_SETS}", "ciamOwner": OPS}),
        _entry(f"cn=web-1,{ALPHA}", "ciamServer", {"cn": "web-1", "ciamServerRole": "web",
                                                    "ciamHostname": "web-1.alpha.example.test",
                                                    "ciamSubnet": f"cn=net,ou=bindings,{ALPHA}"}),
        *(_binding(env, "secret-app", "ciamSecretRef", "app-password", {"ciamRefUri": f"fake://{cloud}/app"})
          for env, cloud in ((ALPHA, "alpha"), (BETA, "beta"))),
        *(_binding(env, "identity-app", "ciamIdentityBinding", "identity-app",
                   {"ciamProviderRef": f"id-{cloud}", **({"ciamGrant": grants} if grants else {}), **extra})
          for env, cloud, grants, extra in ((ALPHA, "alpha", alpha_grants, {}),
                                            (BETA, "beta", beta_grants, beta_attrs or {}))))
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(entries))))


def _plan(d):
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, dt.date(2026, 10, 1), {}, {},
                      ())
    return access_check((FAKE,), (FAKE,))(ctx)


def test_grants_are_read_and_permits_granted_through_the_table():
    g = grant_of("sm:Get on alpha (resource policy)")
    assert (g.action, g.resource, g.resource_policy) == ("sm:Get", "alpha", True)
    d = _record(("sm:Get on alpha",), ())
    alpha = env_model(d, "alpha/prod")
    gs = (grant_of("sm:Get on alpha"),)
    assert granted(MODEL, alpha, "read-secret app-password", gs) == (True, gs)         # a parent path covers it
    assert granted(MODEL, alpha, "write-secret app-password", gs) == (False, ())        # sm:Put missing
    assert granted(MODEL, alpha, "read-secret unbound-secret", gs) == (None, ())        # not bound: can't tell
    assert granted(MODEL, alpha, "use-key app-password", gs) == (None, ())              # no row: can't tell
    assert granted(MODEL, alpha, "read-secret app-password", (grant_of("SM:* on alpha/app"),))[0] is True


def test_escalation_and_wildcard_grants():
    gs = tuple(grant_of(t) for t in ("iam:PassRole on *", "roles/owner on projects/p", "s3:* on bucket",
                                     "kms:GenerateDataKey* on key", "sm:Get on alpha"))
    assert [g.text for g in escalating(MODEL, gs)] == ["iam:PassRole on *", "roles/owner on projects/p"]
    assert [g.text for g in wildcard(gs)] == ["iam:PassRole on *", "s3:* on bucket"]      # a family isn't one
    assert covered("arn:secret:ciam/*", ("arn:secret:ciam/app-*",)) and covered("ARN:secret:ciam/app-AbC123",
                                                                                  ("arn:secret:ciam/app-*",))
    assert covered("projects/p", ("projects/p/secrets/s",)) and not covered("projects/q", ("projects/p/secrets/s",))
    assert access_model((mini_estate.FAKE,)) is None and access_model((FAKE,)) is MODEL


def test_least_privilege_and_what_the_target_would_lose():
    found = _plan(_record(("sm:Get on alpha/app", "iam:PassRole on *", "s3:* on bucket", "sm:Delete on alpha/app"),
                          ("sm:List on beta",)))
    assert [b[1] for b in found.blockers] == [
        "beta/prod: identity `identity-app` isn't granted `read-secret app-password`, which `app` may do in "
        "alpha/prod: grant it before the move."]
    assert [a[1] for a in found.actions] == [
        "alpha/prod: identity `identity-app` is granted `iam:PassRole on *`, which lets it raise its own access: "
        "grant only what its permissions need.",
        "alpha/prod: identity `identity-app` is granted `s3:* on bucket`, wider than any permission: scope it to the "
        "resources its permissions name.",
        "alpha/prod: identity `identity-app` is granted `sm:Delete on alpha/app`, which no permission of `app` "
        "explains: record the permission, or remove the grant.",
        "beta/prod: identity `identity-app` is granted `sm:List on beta`, which no permission of `app` explains: "
        "record the permission, or remove the grant."]


def test_an_escalating_grant_a_permission_explains_is_not_a_finding():
    found = _plan(_record(("roles/owner on alpha/app",), (), permits=("manage app-password",)))
    assert found.actions == ()                       # manage app-password explains it; beta records no grants


def test_the_workload_identities_an_environment_renders():
    d = _record((), ())
    (w,) = workload_identities(env_model(d, "alpha/prod"), MODEL)
    assert (w.principal, w.identity_role, w.server_role, w.name) == ("app", "identity-app", "web", "id-alpha")
    assert [(x, b.dn.split(",")[0], row.verb) for x, b, row in w.grants] == [
        ("read-secret app-password", "cn=secret-app", "read-secret")]
    assert w.notes == ("read-secret unbound-secret: role `unbound-secret` has no binding in this environment",)
    assert workload_identities(env_model(d, "beta/prod"), MODEL) == ()          # no server of role web there
    assert identity_of((w,), "web") == w and identity_of((w,), "db") is None


def test_a_denied_target_permission_blocks_and_an_unknown_one_is_to_verify():
    denied = _plan(_record((), ("sm:Get on beta",), beta_attrs={"ciamDenial": "sm:Get on beta/app"}))
    assert [b[1] for b in denied.blockers] == [
        "beta/prod: identity `identity-app` may not `read-secret app-password`, which `app` may do in alpha/prod: "
        "explicitly denied by `sm:Get on beta/app` (its own policies). Lift the deny before the move."]
    unknown = _plan(_record((), ("sm:Get on beta (if aws:SourceVpc=vpc-1)",)))
    assert unknown.blockers == () and [a[1] for a in unknown.actions] == [
        "beta/prod: whether identity `identity-app` may `read-secret app-password` can't be told: allowed only if "
        "aws:SourceVpc=vpc-1 (`sm:Get on beta (if aws:SourceVpc=vpc-1)`): what decides it wasn't imported. Verify "
        "it before the move (or record a cloud evaluator's verdict)."]


def test_identities_recording_no_grants_have_nothing_to_compare():
    found = _plan(_record((), ()))
    assert found.blockers == () and found.actions == ()
