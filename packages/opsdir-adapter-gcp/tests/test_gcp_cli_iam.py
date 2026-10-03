"""Google Cloud IAM read from Cloud Asset Inventory and gcloud, as from Terraform state: IAM policies of the
inventory on resources, folders and the project (project numbers read as IDs, buckets as IAM names them), service
accounts, custom roles, pool providers, deny policies, organization policies; Policy Troubleshooter's verdicts, asked
by the renderer's access/evaluate.sh (not for a group) and read back dated."""
import datetime as dt
import json

from opsdir.connectors.render import render_env
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.cli import cli_resources
from support import REGISTRY, build_directory

SA = "ciam-prod-pf@ciam-prod.iam.gserviceaccount.com"
AT = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)


def _outputs(**extra):
    return {
        "project.json": json.dumps({"projectId": "ciam-prod", "projectNumber": "123"}),
        "iam-policies.jsonl": "\n".join(json.dumps(x) for x in (
            {"name": "//secretmanager.googleapis.com/projects/123/secrets/pf-admin-password",
             "assetType": "secretmanager.googleapis.com/Secret",
             "iamPolicy": {"bindings": [{"role": "roles/secretmanager.secretAccessor",
                                         "members": [f"serviceAccount:{SA}"]}]}},
            {"name": "//storage.googleapis.com/ciam-backups", "assetType": "storage.googleapis.com/Bucket",
             "iamPolicy": {"bindings": [{"role": "roles/storage.objectCreator", "members": [f"serviceAccount:{SA}"],
                                         "condition": {"title": "ds only", "expression": "x"}}]}},
            {"name": "//iap.googleapis.com/projects/123/iap_tunnel", "assetType": "iap.googleapis.com/Tunnel",
             "iamPolicy": {"bindings": [{"role": "roles/iap.tunnelResourceAccessor",
                                         "members": ["group:ciam-admins@example-aero.test"]}]}})),
        "inherited.json": json.dumps([{"resource": "//cloudresourcemanager.googleapis.com/folders/42",
                                       "assetType": "cloudresourcemanager.googleapis.com/Folder",
                                       "policy": {"bindings": [{"role": "projects/ciam-prod/roles/ciamAudit",
                                                                "members": [f"serviceAccount:{SA}"]}]}}]),
        "accounts.json": json.dumps([{"email": SA, "name": f"projects/ciam-prod/serviceAccounts/{SA}",
                                      "displayName": "pingfederate (identity-pf)"}]),
        "role.json": json.dumps({"name": "projects/ciam-prod/roles/ciamAudit",
                                 "includedPermissions": ["logging.logEntries.create"]}),
        "providers.json": json.dumps([{"name": "projects/123/locations/global/workloadIdentityPools/ci/providers/gl",
                                       "oidc": {"issuerUri": "https://gitlab.example.test"}}]),
        "deny.json": json.dumps({"name": "policies/cloudresourcemanager.googleapis.com%2Fprojects%2F123/denypolicies/d",
                                 "kind": "DenyPolicy", "rules": [{"denyRule": {
                                     "deniedPrincipals": ["principalSet://goog/public:all"],
                                     "deniedPermissions": ["iam.googleapis.com/serviceAccountKeys.create"]}}]}),
        "org-policy.json": json.dumps({"name": "projects/123/policies/iam.disableServiceAccountKeyCreation",
                                       "spec": {"rules": [{"enforce": True}]}}),
        **extra}


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_iam_from_the_inventory_reads_as_from_state():
    resources, notices = cli_resources(_outputs(), AT)
    pf = _one(resources, "identity", SA)
    assert pf.role == "identity-pf" and pf.attrs["ciamIdentityKind"] == ("service-account",)
    assert set(pf.attrs["ciamGrant"]) == {
        "roles/secretmanager.secretAccessor on projects/ciam-prod/secrets/pf-admin-password",   # number read as ID
        "roles/storage.objectCreator on projects/_/buckets/ciam-backups (if ds only)",
        "logging.logEntries.create on folders/42"}                         # inherited, the custom role expanded
    assert pf.attrs["ciamDenial"] == ("iam.serviceAccountKeys.create on projects/ciam-prod",)
    assert _one(resources, "access", "projects/ciam-prod/iap_tunnel").attrs["ciamTrustedBy"] == (
        "group:ciam-admins@example-aero.test",)
    assert _one(resources, "guardrail", "projects/ciam-prod/policies").attrs["ciamDenies"] == ("service-account-keys",)
    assert not [n for n in notices if "not read" in n and "Image" not in n]


def test_troubleshooter_verdicts_are_read_back_dated():
    resources, _ = cli_resources(_outputs(**{
        "evaluations/ciam-prod-pf/read-secret__pf-admin-password.json": json.dumps(
            {"overallAccessState": "CAN_ACCESS"}),
        "evaluations/ciam-prod-pf/write-storage__backup-target.json": json.dumps(
            {"overallAccessState": "UNKNOWN_CONDITIONAL"}),
        "evaluations/ciam-prod-ci/read-secret__pf-admin-password.json": json.dumps(
            {"overallAccessState": "CANNOT_ACCESS"})}), AT)
    assert _one(resources, "identity", SA).attrs["ciamEvaluated"] == (
        "read-secret pf-admin-password: allowed (gcp-policy-troubleshooter 2026-10-02)",
        "write-storage backup-target: unknown (gcp-policy-troubleshooter 2026-10-02)")
    ci = _one(resources, "identity", "ciam-prod-ci")                       # asked about only: by its account id
    assert "ciamIdentityKind" not in ci.attrs
    assert ci.attrs["ciamEvaluated"] == (
        "read-secret pf-admin-password: denied (gcp-policy-troubleshooter 2026-10-02)",)


ENV = "env=prod,cloud=gcp,ou=environments,dc=ciam-ops"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items())


def test_the_renderer_writes_the_script_that_asks_the_troubleshooter():
    records = "\n".join((
        "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
        "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
        _entry("cloud=gcp,ou=environments,dc=ciam-ops", "ciamCloud", cloud="gcp", ciamCloudProvider="gcp",
               ciamRegion="us-central1"),
        _entry(ENV, "ciamEnvironment", env="prod"),
        _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
        _entry(f"cn=vpc,ou=bindings,{ENV}", "ciamNetwork", cn="vpc", ciamBindingRole="network",
               ciamCidr="10.20.0.0/16", ciamProviderRef="projects/ciam-prod/global/networks/ciam-vpc"),
        _entry(f"cn=secret,ou=bindings,{ENV}", "ciamSecretRef", cn="secret", ciamBindingRole="pf-admin-password",
               ciamRefUri="gcp-sm://projects/ciam-prod/secrets/pf-admin-password"),
        _entry(f"cn=identity-pf,ou=bindings,{ENV}", "ciamIdentityBinding", cn="identity-pf",
               ciamBindingRole="identity-pf", ciamProviderRef=SA, ciamIdentityKind="service-account"),
        _entry(f"cn=admins,ou=bindings,{ENV}", "ciamIdentityBinding", cn="admins", ciamBindingRole="admin-group",
               ciamProviderRef="ciam-admins@example-aero.test", ciamIdentityKind="group"),
        "dn: ou=permission-sets,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
        _entry("cn=pf,ou=permission-sets,dc=ciam-ops", "ciamPermissionSet", cn="pf",
               ciamPermits="read-secret pf-admin-password"),
        "dn: ou=principals,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
        _entry("cn=pingfederate,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="pingfederate",
               ciamPrincipalKind="service", ciamIdentityRole="identity-pf",
               ciamHoldsSet="cn=pf,ou=permission-sets,dc=ciam-ops"),
        _entry("cn=admins,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="admins", ciamPrincipalKind="operator",
               ciamIdentityRole="admin-group", ciamHoldsSet="cn=pf,ou=permission-sets,dc=ciam-ops")))
    _, files = render_env(build_directory(REGISTRY, tuple(parse(records))), "gcp/prod")
    script = files["access/evaluate.sh"]
    assert ("gcloud policy-intelligence troubleshoot-policy iam "
            "//secretmanager.googleapis.com/projects/ciam-prod/secrets/pf-admin-password "
            f"--principal-email={SA} --permission=secretmanager.versions.access --format=json "
            '> "$OUT/evaluations/ciam-prod-pf/read-secret__pf-admin-password.json"') in script
    assert "# identity admins" not in script                         # a group: the troubleshooter can't answer
