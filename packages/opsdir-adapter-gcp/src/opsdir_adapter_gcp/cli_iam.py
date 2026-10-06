"""What Cloud Asset Inventory and gcloud report about IAM, normalized to the attribute names of the matching
hashicorp/google resources so the same mapping (opsdir_adapter_gcp.iam) reads them as reads Terraform state. Pure.
Items are recognized one by one, as the other inventory items (opsdir_adapter_gcp.cli):

  gcloud asset export --content-type=iam-policy   IAM policies (iamPolicy) on the resources they name, the project,
  gcloud asset search-all-iam-policies            its folders and the organization included (search results:
    --scope=<organization or folder>              policy): every binding, conditions kept
  gcloud iam service-accounts list                service accounts (Cloud Asset Inventory: iam.googleapis.com/
                                                  ServiceAccount)
  gcloud iam roles describe <custom role>         a custom role's permissions (iam.googleapis.com/Role)
  gcloud iam workload-identity-pools providers    pool providers' OIDC issuers (iam.googleapis.com/
    list --workload-identity-pool=<pool>          WorkloadIdentityPoolProvider)
  gcloud iam policies get <policy> --kind=        deny policies (policies/<attachment point>/denypolicies/<id>)
    denypolicies --attachment-point=<resource>
  gcloud org-policies describe <constraint>       organization policies (<parent>/policies/<constraint>, spec)
  gcloud asset export --content-type=org-policy   organization policies of the inventory's form (orgPolicy)
  gcloud policy-intelligence troubleshoot-policy  Policy Troubleshooter's verdicts (overallAccessState), saved by the
    iam                                           renderer's access/evaluate.sh as evaluations/<account>/<verb>__<role>
                                                  .json (opsdir.domains.access.evaluations)
"""
import json
import re
from urllib.parse import unquote

from opsdir.domains.access.evaluations import evaluations_by_identity
from opsdir.domains.access.imports import short_name
from .access import troubleshooter_verdict
from .names import resource_id

EVALUATOR = "gcp-policy-troubleshooter"
KINDS = {"iam.googleapis.com/ServiceAccount": "service-account", "iam.googleapis.com/Role": "custom-role",
         "iam.googleapis.com/WorkloadIdentityPoolProvider": "pool-provider"}
NAMED = (("service-account", re.compile(r"^projects/[^/]+/serviceAccounts/[^/]+$")),
         ("custom-role", re.compile(r"^(projects|organizations)/[^/]+/roles/[^/]+$")),
         ("pool-provider", re.compile(r"^projects/[^/]+/locations/[^/]+/workloadIdentityPools/[^/]+/providers/[^/]+$")),
         ("deny-policy", re.compile(r"^policies/[^/]+/denypolicies/[^/]+$")),
         ("org-policy", re.compile(r"^(projects|folders|organizations)/[^/]+/policies/[^/]+$")))
_POOL = re.compile(r"/workloadIdentityPools/([^/]+)/providers/")


def iam_kind(item):
    """What an IAM item is ('iam-policy', 'org-policy-inventory', 'troubleshoot', or by NAMED), or None."""
    if not isinstance(item, dict):
        return None
    if "iamPolicy" in item or ("policy" in item and "resource" in item):
        return "iam-policy"
    if "orgPolicy" in item:
        return "org-policy-inventory"
    if "overallAccessState" in item:
        return "troubleshoot"
    found = next((k for k, pattern in NAMED if pattern.match(item.get("name") or "")), None)
    return found if found != "org-policy" or "spec" in item else None


def _resource(full, asset_type):
    """The resource name an inventory IAM policy is on: a bucket as IAM names it (projects/_/buckets/<b>)."""
    name = resource_id(full or "")
    return f"projects/_/buckets/{name}" if asset_type == "storage.googleapis.com/Bucket" \
        and not name.startswith("projects/") else name


def _rule(r):
    """An organization policy rule as Terraform holds it."""
    return {"enforce": "TRUE" if r.get("enforce") is True else r.get("enforce"), "values": r.get("values")}


def _org_inventory(d):
    """An inventory's organization policies (orgPolicy, the v1 form) as google_org_policy_policy."""
    parent = resource_id(d.get("name") or "")
    return [("google_org_policy_policy", {
                "name": f"{parent}/policies/{(p.get('constraint') or '').removeprefix('constraints/')}",
                "parent": parent,
                "spec": [{"rules": [{"enforce": "TRUE" if (p.get("booleanPolicy") or {}).get("enforced") else None,
                                     "values": p.get("listPolicy")}]}]})
            for p in d.get("orgPolicy") or ()]


def _deny(d):
    rules = [r.get("denyRule") or {} for r in d.get("rules") or ()]
    return ("google_iam_deny_policy", {
        "name": d.get("name"), "parent": unquote(d["name"].split("/denypolicies/", 1)[0].removeprefix("policies/")),
        "rules": [{"deny_rule": [{"denied_principals": r.get("deniedPrincipals") or [],
                                  "exception_principals": r.get("exceptionPrincipals") or [],
                                  "denied_permissions": r.get("deniedPermissions") or [],
                                  "exception_permissions": r.get("exceptionPermissions") or [],
                                  "denial_condition": [r["denialCondition"]] if r.get("denialCondition") else []}]}
                  for r in rules]})


def _with_evaluations(pairs, items, at):
    """The service accounts with Policy Troubleshooter's verdicts (one only asked about: by its account id)."""
    found = evaluations_by_identity([(p, d) for k, d, p in items if k == "troubleshoot"], troubleshooter_verdict,
                                    EVALUATOR, at.date().isoformat() if at else None)
    named = {short_name(a.get("email")) for t, a in pairs if t == "google_service_account"}
    return [*((t, {**a, "evaluated": found.get(short_name(a.get("email")), ())})
              if t == "google_service_account" else (t, a) for t, a in pairs),
            *(("google_service_account", {"email": who, "evaluated": verdicts})
              for who, verdicts in found.items() if who not in named)]


def iam_pairs(items, at=None):
    """Pairs of the IAM items among an environment's recognized items ((kind, data, origin), ...); at dates Policy
    Troubleshooter's verdicts (the import's time)."""
    def of(kind):
        return [d for k, d, _ in items if k == kind]
    pairs = [
        *(("google_cai_iam_policy", {"resource": _resource(d.get("name") or d.get("resource"), d.get("assetType")),
                                     "policy_data": json.dumps(d.get("iamPolicy") or d.get("policy") or {})})
          for d in of("iam-policy")),
        *(("google_service_account", {"email": d.get("email") or (d.get("name") or "").rsplit("/", 1)[-1] or None,
                                      "name": d.get("name"),
                                      "display_name": d.get("displayName")}) for d in of("service-account")),
        *(("google_project_iam_custom_role", {"name": d.get("name"), "permissions": d.get("includedPermissions") or []})
          for d in of("custom-role")),
        *(("google_iam_workload_identity_pool_provider", {
            "name": d.get("name"), "workload_identity_pool_id": _POOL.search(d.get("name") or "").group(1),
            "oidc": [{"issuer_uri": (d.get("oidc") or {}).get("issuerUri")}] if (d.get("oidc") or {}).get(
                "issuerUri") else []})
          for d in of("pool-provider") if _POOL.search(d.get("name") or "")),
        *(_deny(d) for d in of("deny-policy")),
        *(("google_org_policy_policy", {
            "name": d.get("name"), "parent": d["name"].split("/policies/", 1)[0],
            "spec": [{"rules": [_rule(r) for r in (d.get("spec") or {}).get("rules") or ()]}]})
          for d in of("org-policy")),
        *(p for d in of("org-policy-inventory") for p in _org_inventory(d))]
    return _with_evaluations(pairs, items, at)
