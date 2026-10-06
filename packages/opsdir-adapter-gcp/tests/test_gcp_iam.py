"""Google Cloud IAM read from Terraform state into the record's identities, guardrails and access paths: service
accounts and the members of IAM resources at every level (conditions, custom roles, inheritance), workload identity
trust, deny policies, organization policies by what they prevent, IAP tunnels; and what the record then says of a
permission."""
import json
from types import SimpleNamespace

from opsdir.core.directory import make_directory, one
from opsdir.domains.access.grants import ALLOWED, DENIED, UNKNOWN, effective
from opsdir_adapter_gcp.access import ACCESS
from opsdir_adapter_gcp.iam import iam_resources, permission_v1
from opsdir_adapter_gcp.inventory import read_terraform_state
from support import BARE, SUPERS, imported_directory

P = "projects/ciam-prod"
SECRET = f"{P}/secrets/pf-admin-password"
SA = "ciam-prod-pf@ciam-prod.iam.gserviceaccount.com"
CI = "ciam-prod-deploy@ciam-prod.iam.gserviceaccount.com"
POOL = "projects/123/locations/global/workloadIdentityPools/ciam-prod-ci"
ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def _pairs(*extra):
    return [
        ("google_service_account", {"email": SA, "name": f"{P}/serviceAccounts/{SA}",
                                    "display_name": "pingfederate (identity-pf)"}),
        ("google_service_account", {"email": CI, "name": f"{P}/serviceAccounts/{CI}",
                                    "display_name": "deployer (identity-ci)"}),
        ("google_secret_manager_secret_iam_member", {"secret_id": SECRET, "project": "ciam-prod",
                                                     "role": "roles/secretmanager.secretAccessor",
                                                     "member": f"serviceAccount:{SA}"}),
        ("google_storage_bucket_iam_binding", {"bucket": "b/ciam-backups", "role": "roles/storage.objectCreator",
                                               "members": [f"serviceAccount:{SA}"],
                                               "condition": [{"title": "ds prefix only",
                                                              "expression": 'resource.name.startsWith("x")'}]}),
        ("google_folder_iam_member", {"folder": "folders/42", "role": "roles/logging.logWriter",
                                      "member": f"serviceAccount:{SA}"}),
        ("google_project_iam_custom_role", {"name": f"{P}/roles/ciamSecretWriter", "role_id": "ciamSecretWriter",
                                            "permissions": ["secretmanager.versions.add",
                                                            "secretmanager.secrets.get"]}),
        ("google_project_iam_policy", {"project": "ciam-prod", "policy_data": json.dumps({"bindings": [
            {"role": f"{P}/roles/ciamSecretWriter", "members": ["group:ciam-admins@example-aero.test"]},
            {"role": "roles/viewer", "members": ["allUsers"]}]})}),
        ("google_iam_workload_identity_pool_provider", {"workload_identity_pool_id": "ciam-prod-ci",
                                                        "oidc": [{"issuer_uri": "https://gitlab.example.test"}]}),
        ("google_service_account_iam_member", {"service_account_id": f"{P}/serviceAccounts/{CI}",
                                               "role": "roles/iam.workloadIdentityUser",
                                               "member": f"principal://iam.googleapis.com/{POOL}/subject/"
                                                         "project_path:ciam/deploy:ref_type:branch:ref:main"}),
        ("google_iam_deny_policy", {"parent": "cloudresourcemanager.googleapis.com%2Fprojects%2Fciam-prod", "rules": [
            {"deny_rule": [{"denied_principals": ["principalSet://goog/public:all"],
                            "exception_principals": [
                                f"principal://iam.googleapis.com/projects/-/serviceAccounts/{CI}"],
                            "denied_permissions": ["secretmanager.googleapis.com/versions.access"],
                            "denial_condition": [{"title": "outside office hours"}]}]}]}),
        ("google_org_policy_policy", {"name": f"{P}/policies/gcp.resourceLocations", "parent": P,
                                      "spec": [{"rules": [{"values": [{"allowed_values": ["in:us-locations"]}]}]}]}),
        ("google_org_policy_policy", {"name": f"{P}/policies/iam.disableServiceAccountKeyCreation", "parent": P,
                                      "spec": [{"rules": [{"enforce": "TRUE"}]}]}),
        ("google_iap_tunnel_iam_member", {"project": "ciam-prod", "role": "roles/iap.tunnelResourceAccessor",
                                          "member": "group:ciam-admins@example-aero.test"}),
        *extra]


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_service_accounts_and_members_with_what_they_are_granted():
    resources, notices = iam_resources(_pairs())
    pf = _one(resources, "identity", SA)
    assert pf.role == "identity-pf" and pf.attrs["ciamIdentityKind"] == ("service-account",)
    assert set(pf.attrs["ciamGrant"]) == {
        f"roles/secretmanager.secretAccessor on {SECRET}",
        "roles/storage.objectCreator on projects/_/buckets/ciam-backups (if ds prefix only)",
        "roles/logging.logWriter on folders/42"}                                     # inherited from the folder
    assert pf.attrs["ciamDenial"] == (f"secretmanager.versions.access on {P} (if outside office hours)",)
    ci = _one(resources, "identity", CI)
    assert ci.attrs["ciamIdentityKind"] == ("federated",) and "ciamDenial" not in ci.attrs     # an exception
    assert ci.attrs["ciamTrustedBy"] == (
        "https://gitlab.example.test project_path:ciam/deploy:ref_type:branch:ref:main",)
    admins = _one(resources, "identity", "ciam-admins@example-aero.test")
    assert admins.attrs["ciamIdentityKind"] == ("group",)
    assert set(admins.attrs["ciamGrant"]) == {
        f"secretmanager.versions.add on {P}", f"secretmanager.secrets.get on {P}",     # the custom role's permissions
        f"roles/iap.tunnelResourceAccessor on {P}/iap_tunnel"}
    fence = _one(resources, "guardrail", f"{P}/policies")
    assert fence.attrs["ciamDenies"] == ("region-escape", "service-account-keys")
    assert fence.role == "guardrail-org-policy-ciam-prod"
    iap = _one(resources, "access", f"{P}/iap_tunnel")
    assert iap.attrs["ciamTrustedBy"] == ("group:ciam-admins@example-aero.test",)
    assert notices == (f"roles/viewer on {P} is granted to every user (allUsers, allAuthenticatedUsers); "
                       "not recorded",)


def test_deny_policy_permissions_read_as_iam_names_them():
    assert permission_v1("secretmanager.googleapis.com/versions.access") == "secretmanager.versions.access"
    assert permission_v1("cloudresourcemanager.googleapis.com/projects.delete") == "resourcemanager.projects.delete"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _env(*extra):
    d = imported_directory((), SUPERS, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="gcp",
             ciamRegion="us-central1"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=pf-admin,{B}", ("ciamSecretRef",), cn="pf-admin", ciamBindingRole="pf-admin-password",
             ciamRefUri=f"gcp-sm://{SECRET}"),
        _row(f"cn=audit-logs,{B}", ("ciamLogDestination",), cn="audit-logs", ciamBindingRole="audit-logs",
             ciamDestinationKind="log-bucket", ciamProviderRef=f"{P}/locations/global/buckets/ciam-audit")))
    state = json.dumps({"version": 4, "resources": [
        {"mode": "managed", "type": t, "name": "x", "instances": [{"attributes": a}]} for t, a in _pairs(*extra)]})
    imported = read_terraform_state({"main/prod/terraform.tfstate": state}, d, ())
    entries = {**{e.norm: e for e in d.entries.values() if e.dn.lower().endswith(B.lower()) and e.dn != B},
               **{e.norm: e for _, es in imported.groups for e in es}}
    env = SimpleNamespace(d=BARE, bindings=tuple(entries.values()))
    return env, {one(e, "ciamBindingRole"): e for e in env.bindings}, imported.notices


def test_the_record_learns_what_each_identity_may_do():
    env, by_role, notices = _env()
    pf = by_role["identity-pf"]
    verdict = effective(ACCESS, env, "read-secret pf-admin-password", pf)
    assert verdict.state == UNKNOWN and "conditional deny" in verdict.why           # the deny policy's condition
    assert effective(ACCESS, env, "write-logs audit-logs", pf).state == ALLOWED     # inherited from the folder
    assert any("identity resource(s) not in the record" in n for n in notices)       # the group: a role map names it
    unconditional = ("google_iam_deny_policy", {
        "parent": "cloudresourcemanager.googleapis.com%2Fprojects%2Fciam-prod", "rules": [{"deny_rule": [{
            "denied_principals": [f"principal://iam.googleapis.com/projects/-/serviceAccounts/{SA}"],
            "denied_permissions": ["secretmanager.googleapis.com/versions.access"]}]}]})
    env, by_role, _ = _env(unconditional)
    assert effective(ACCESS, env, "read-secret pf-admin-password", by_role["identity-pf"]).state == DENIED
