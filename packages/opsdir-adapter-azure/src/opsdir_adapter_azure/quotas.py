"""Azure's usage limits (core estate: quotas). A quota's id here is the usage's name.value as Azure reports it (a VM
family's standardDSv5Family, VirtualNetworks): what a need names as its ciamProviderRef when no quota kind fits. The
kinds:

  vcpus           the compute usage whose localized name is "Total Regional vCPUs" (Microsoft's VM quota page names it;
                  a VM must also fit its family's own vCPU quota: record that need by the family's name.value)
  public-ips      PublicIPAddresses        networks  VirtualNetworks        load-balancers  LoadBalancers
  (network usages, by name.value as Microsoft's REST reference shows them)

database-instances and kubernetes-clusters have no usage Azure reports (Azure SQL servers and AKS clusters per
subscription and region are raised by a support request): the planner names them as limits to confirm.

Fetched (`opsdir import azure/quotas --run`, under the operator's own Azure login) per region the record's Azure clouds
needing quotas run in: `az account show` (the subscription), `az vm list-usage --location <region>` and
`az network list-usages --location <region>`, saved as quotas/<region>/compute.json and quotas/<region>/network.json
(the compute output doesn't name its region, so the folder it is in does: keep <region>/compute.json when saving the
outputs by hand).

An increase the operator decided to request isn't a Terraform resource on Azure (azurerm has none): the environment's
root names it in a comment, to request through the Quota API (Microsoft.Quota, `az quota update`) or a support
request; Microsoft's pages don't say whether the Quota API serves Azure Government. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.directory import one
from opsdir.core.sources import json_document
from opsdir.domains.estate.quotas import (QuotaRow, limits_fetched, need_key, needed, quota_import, quota_needs,
                                          quota_regions)
from .account import subscription_id
from .inventory import PROVIDER

TOTAL_VCPUS = "Total Regional vCPUs"
NETWORK_KINDS = {"PublicIPAddresses": "public-ips", "VirtualNetworks": "networks", "LoadBalancers": "load-balancers"}
ACCOUNT = "quotas/account.json"


def quota_commands(d):
    """The provider commands fetching the limits of the record's Azure environments that need quotas: the
    subscription, then per region the compute and network usages."""
    regions = quota_regions(d, PROVIDER)
    return (((ACCOUNT, ("az", "account", "show", "-o", "json")),) if regions else ()) + tuple(
        (f"quotas/{r}/{kind}.json", argv) for r in regions
        for kind, argv in (("compute", ("az", "vm", "list-usage", "--location", r, "-o", "json")),
                           ("network", ("az", "network", "list-usages", "--location", r, "-o", "json"))))


def _kind(usage):
    name = usage.get("name") or {}
    return "vcpus" if name.get("localizedValue") == TOTAL_VCPUS else NETWORK_KINDS.get(name.get("value"))


def usage_rows(usages):
    """QuotaRows of a list-usage or list-usages output: id name.value, the limit, its localized name, the current
    value, the kind it answers."""
    return tuple(QuotaRow(u["name"]["value"], int(u["limit"]), u["name"].get("localizedValue"),
                          int(u["currentValue"]) if isinstance(u.get("currentValue"), (int, float)) else None,
                          _kind(u))
                 for u in usages if isinstance(u, dict) and isinstance(u.get("name"), dict) and u["name"].get("value")
                 and isinstance(u.get("limit"), (int, float)))


def _region(path, usages):
    """The region a usage output is of: the folder it is in (<region>/compute.json), else a network usage's id
    (.../locations/<region>/usages/...)."""
    parts = path.split("/")
    if len(parts) >= 2 and parts[-2] != "quotas":
        return parts[-2]
    ids = [u.get("id") or "" for u in usages if isinstance(u, dict)]
    return next((i.split("/locations/", 1)[1].split("/", 1)[0] for i in ids if "/locations/" in i), None)


def read_quotas(files, d, patterns, at=None):
    """Imported: the quota catalogs of the subscription the export is of (az account show) in each region its usage
    outputs are of. Refused when nothing tells the subscription; outputs whose region can't be told are named."""
    docs = {p: json_document(t) for p, t in sorted(files.items())}
    account = next((doc.get("id") for doc in docs.values() if isinstance(doc, dict) and doc.get("tenantId")), None)
    if account is None:
        raise SystemExit(f"azure/quotas: nothing in the export tells the subscription (add `az account show -o json > "
                         f"{ACCOUNT}`); nothing imported")
    lists = {p: doc for p, doc in docs.items() if isinstance(doc, list)}
    placed = {p: _region(p, doc) for p, doc in lists.items()}
    regions = dict.fromkeys(r for r in placed.values() if r)
    imported = quota_import(d, PROVIDER, {(account, r): tuple(row for p, doc in lists.items() if placed[p] == r
                                                              for row in usage_rows(doc)) for r in regions})
    return imported._replace(notices=(*imported.notices, *(f"{p}: its region can't be told (save it as "
                                                            "<region>/compute.json); not read"
                                                            for p, r in placed.items() if r is None),
                                      *(f"{p}: not usage output; not read" for p, doc in docs.items()
                                        if p not in lists and not (isinstance(doc, dict) and doc.get("tenantId")))))


QUOTAS = Importer("quotas", "the limits Azure grants the subscription in each region the record's Azure environments "
                            "needing quotas run in (compute and network usages)", read_quotas, quota_commands)
PREREQUISITE = Prerequisite("azure-quotas", "Azure's usage limits for the subscriptions and regions whose environments "
                                            "record quota needs, for the planner's quota check", QUOTAS.name,
                            partial(limits_fetched, provider=PROVIDER))


def quota_request_notes(m):
    """Comments naming each increase the operator decided to request for environment m (azurerm can't request
    one)."""
    region, sub = one(m.cloud, "ciamRegion"), subscription_id(m) or "(the subscription)"
    return tuple(f"# Quota request ({key}): raise it to {one(n, 'ciamQuotaRequested') or needed(m, key)} for "
                 f"subscription {sub} in {region} through the Quota API (`az quota update`, Microsoft.Quota) or a "
                 "support request: azurerm has no resource for it; Microsoft's pages don't say whether the Quota API "
                 "serves Azure Government"
                 for n in quota_needs(m) if one(n, "ciamQuotaDecision") == "request" for key in (need_key(n),))
