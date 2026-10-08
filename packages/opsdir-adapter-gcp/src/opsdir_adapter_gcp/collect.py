"""Google Cloud collectors (`opsdir collect`, core.contract Collector): the exact gcloud calls whose outputs
gcp/cli-inventory reads, and the Terraform state gcp/terraform-state reads, for one environment, read-only. Pure: the
core runs them.

Every call is `gcloud ... --format=json` under the operator's own login, naming the project explicitly. First `gcloud
config list`: its project must be the one the cloud records (ciamAccountRef) and an account must be signed in; else
nothing is read. The inventory follows the README's script: Cloud Asset Inventory's resources of the project (and the
Shared VPC host project's networks, the host named by the network binding's provider ref), then what it lacks
(instances with their metadata, backend health, record sets per zone, schedules, channels, databases, disks, backup
vaults and plans, edge lists, firewall policies, routes, attachments, tunnels, tag bindings per instance, IAM:
policies searched in the organization the cloud records or else the project, service accounts, custom roles,
workload identity providers, deny policies, effective org policies). What may carry secret material is trimmed in
memory before anything sees it (core.contract keep): instance metadata keeps only the keys the importer reads
(cli.METADATA: never startup scripts), scheduler jobs only their target's URI or topic (no bodies, headers or
messages), notification channels lose their labels (addresses, tokens). Secure tag values are listed for each tag key
a binding records (ciamTagKeyRef, a network firewall policy's) and, when the cloud records its organization, for each
firewall tag key (purpose GCE_FIREWALL) the organization holds (`gcloud resource-manager tags keys list`: gcloud
documents organization parents only; a project's keys come from the record). `gcloud asset export` writes to Cloud
Storage and is never run.

Terraform state: (a) by default the state object a collection source names (ciamCollectionSource, importer
gcp/terraform-state, ciamSourceRef gs://bucket/<prefix>/<workspace>.tfstate) read with `gcloud storage cat`: no init,
no lock, read access to one object (customer-supplied encryption keys are not supported); (b) with --terraform-dir,
`terraform state pull` in that initialized working directory."""
import json

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one, values
from opsdir.core.environment import one_role
from opsdir.domains.governance.collection import collection_sources
from .account import project_id
from .cli import METADATA

WORK = "_work/"


def _gcloud(*args, keep=None):
    return Command(("gcloud", *args, "--format=json"), keep=keep)


def _load(text, empty):
    try:
        found = json.loads(text or json.dumps(empty))
    except ValueError:
        return empty
    return found if isinstance(found, type(empty)) else empty


def _trim(text, each):
    """An output list with each item made by each(item) (pure)."""
    items = _load(text, [])
    return json.dumps([each(i) if isinstance(i, dict) else i for i in items])


def instance_metadata(text):
    """gcloud instances list output with each instance's metadata only the keys the importer reads."""
    return _trim(text, lambda i: {**i, "metadata": {**(i.get("metadata") or {}), "items": [
        x for x in ((i.get("metadata") or {}).get("items") or ()) if isinstance(x, dict) and x.get("key") in METADATA]}}
                    if "metadata" in i else i)


def scheduler_targets(text):
    """gcloud scheduler jobs list output with each job's target reduced to its URI or topic."""
    def job(i):
        http, pubsub = i.get("httpTarget"), i.get("pubsubTarget")
        rest = {k: v for k, v in i.items() if k not in ("httpTarget", "pubsubTarget", "appEngineHttpTarget")}
        return {**rest, **({"httpTarget": {"uri": http.get("uri")}} if isinstance(http, dict) else {}),
                **({"pubsubTarget": {"topicName": pubsub.get("topicName")}} if isinstance(pubsub, dict) else {})}
    return _trim(text, job)


def channel_labels(text):
    """gcloud monitoring channels list output without each channel's labels (addresses, tokens)."""
    return _trim(text, lambda i: {k: v for k, v in i.items() if k not in ("labels", "sensitiveLabels")})


def host_project(m):
    """The project environment m's network lives in (a Shared VPC host), from its provider ref, else its own."""
    net = one_role(m, "network")
    ref = one(net, "ciamProviderRef") if net is not None else None
    parts = (ref or "").split("/")
    return parts[1] if len(parts) > 1 and parts[0] == "projects" else project_id(m)


def _region_of(item):
    region = (item.get("region") or "").rsplit("/", 1)[-1]
    return ("--region", region) if region else ("--global",)


def _listings(m, p, host):
    pp, hp, region = f"--project={p}", f"--project={host}", one(m.cloud, "ciamRegion")
    org = (one(m.cloud, "ciamOrganizationRef") or "").rsplit("/", 1)[-1]
    attachment = f"cloudresourcemanager.googleapis.com/projects/{p}"
    return (
        ("assets.json", _gcloud("asset", "list", pp, "--content-type=resource")),
        *((("host-network.json", _gcloud("asset", "list", hp, "--content-type=resource", "--asset-types="
                                         "compute.googleapis.com/Network,compute.googleapis.com/Subnetwork")),)
          if host != p else ()),
        ("project.json", _gcloud("projects", "describe", p)),
        ("instances.json", _gcloud("compute", "instances", "list", pp, keep=instance_metadata)),
        (f"{WORK}backend-services.json", _gcloud("compute", "backend-services", "list", pp)),
        ("managed-zones.json", _gcloud("dns", "managed-zones", "list", hp)),
        *((("scheduler.json", _gcloud("scheduler", "jobs", "list", f"--location={region}", pp,
                                      keep=scheduler_targets)),) if region else ()),
        ("channels.json", _gcloud("beta", "monitoring", "channels", "list", pp, keep=channel_labels)),
        ("sql-instances.json", _gcloud("sql", "instances", "list", pp)),
        ("disks.json", _gcloud("compute", "disks", "list", pp)),
        ("resource-policies.json", _gcloud("compute", "resource-policies", "list", pp)),
        ("backup-vaults.json", _gcloud("backup-dr", "backup-vaults", "list", pp, "--location=-")),
        ("backup-plans.json", _gcloud("backup-dr", "backup-plans", "list", pp, "--location=-")),
        ("backup-plan-associations.json", _gcloud("backup-dr", "backup-plan-associations", "list", pp,
                                                  "--location=-")),
        *((f"{kind}.json", _gcloud("compute", kind, "list", pp))
          for kind in ("url-maps", "target-https-proxies", "ssl-policies", "health-checks", "security-policies")),
        (f"{WORK}network-firewall-policies.json", _gcloud("compute", "network-firewall-policies", "list", hp)),
        ("routes.json", _gcloud("compute", "routes", "list", hp)),
        ("service-attachments.json", _gcloud("compute", "service-attachments", "list", pp)),
        ("vpn-tunnels.json", _gcloud("compute", "vpn-tunnels", "list", hp)),
        *((f"tag-values-{key.rsplit('/', 1)[-1]}.json",
           _gcloud("resource-manager", "tags", "values", "list", f"--parent={key}"))
          for key in dict.fromkeys(v for b in m.bindings for v in values(b, "ciamTagKeyRef"))),
        *((("tag-keys.json", _gcloud("resource-manager", "tags", "keys", "list", f"--parent=organizations/{org}")),)
          if org else ()),
        ("iam-policies.json", _gcloud("asset", "search-all-iam-policies",
                                      f"--scope={f'organizations/{org}' if org else f'projects/{p}'}")),
        ("service-accounts.json", _gcloud("iam", "service-accounts", "list", pp)),
        (f"{WORK}roles.json", _gcloud("iam", "roles", "list", pp)),
        (f"{WORK}pools.json", _gcloud("iam", "workload-identity-pools", "list", "--location=global", pp)),
        (f"{WORK}deny-policies.json", _gcloud("iam", "policies", "list", f"--attachment-point={attachment}",
                                              "--kind=denypolicies")),
        (f"{WORK}org-policies.json", _gcloud("org-policies", "list", pp)))


def _details(m, p, host, done):
    pp, hp = f"--project={p}", f"--project={host}"
    attachment = f"cloudresourcemanager.googleapis.com/projects/{p}"
    items = lambda path: [i for i in _load(done.get(path), []) if isinstance(i, dict)]  # noqa: E731
    return (
        *((f"health/{b.get('name')}.json", _gcloud("compute", "backend-services", "get-health", b.get("name"),
                                                   *_region_of(b), pp))
          for b in items(f"{WORK}backend-services.json") if b.get("name")),
        *((f"dns/{z.get('name')}.json", _gcloud("dns", "record-sets", "list", f"--zone={z.get('name')}", hp))
          for z in items("managed-zones.json") if z.get("name")),
        *((f"policy-{fp.get('name')}.json", _gcloud("compute", "network-firewall-policies", "describe",
                                                     fp.get("name"), "--global", hp))
          for fp in items(f"{WORK}network-firewall-policies.json") if fp.get("name")),
        *((f"tag-bindings-{i.get('name')}.json",
           _gcloud("resource-manager", "tags", "bindings", "list", f"--location={zone}",
                   f"--parent=//compute.googleapis.com/projects/{p}/zones/{zone}/instances/{i.get('id')}"))
          for i in items("instances.json") for zone in ((i.get("zone") or "").rsplit("/", 1)[-1],)
          if i.get("name") and i.get("id") and zone),
        *((f"role-{r.get('name').rsplit('/', 1)[-1]}.json", _gcloud("iam", "roles", "describe", r.get("name")))
          for r in items(f"{WORK}roles.json") if r.get("name")),
        *((f"providers-{pool.rsplit('/', 1)[-1]}.json",
           _gcloud("iam", "workload-identity-pools", "providers", "list",
                   f"--workload-identity-pool={pool.rsplit('/', 1)[-1]}", "--location=global", pp))
          for pool in (x.get("name") for x in items(f"{WORK}pools.json")) if pool),
        *((f"deny-{d.rsplit('/', 1)[-1]}.json",
           _gcloud("iam", "policies", "get", d.rsplit("/", 1)[-1], f"--attachment-point={attachment}",
                   "--kind=denypolicies"))
          for d in (x.get("name") for x in items(f"{WORK}deny-policies.json")) if d),
        *((f"tag-values-{k.get('name').rsplit('/', 1)[-1]}.json",
           _gcloud("resource-manager", "tags", "values", "list", f"--parent={k.get('name')}"))
          for k in items("tag-keys.json") if k.get("name") and k.get("purpose") == "GCE_FIREWALL"),
        *((f"org-policy-{c.rsplit('/', 1)[-1]}.json",
           _gcloud("org-policies", "describe", c, pp, "--effective"))
          for c in (x.get("constraint") for x in items(f"{WORK}org-policies.json")) if c))


def _in_env(m, pairs):
    return tuple((p if p.startswith(WORK) else f"{m.label}/{p}", c) for p, c in pairs)


def _local(m, done):
    base = f"{m.label}/"
    return {(p[len(base):] if p.startswith(base) else p): t for p, t in done.items()}


def inventory_steps(d, m, done, options):
    """The cli-inventory calls still to make (core.contract Collector.steps): the listings, then their items."""
    p = project_id(m)
    if not p:
        return ()
    host = host_project(m)
    return _in_env(m, (*_listings(m, p, host), *_details(m, p, host, _local(m, done))))


def state_steps(d, m, done, options):
    """The terraform-state calls: `terraform state pull` in --terraform-dir, else each collection source's object."""
    if options.get("terraform_dir"):
        return ((f"{m.label}/terraform.tfstate",
                 Command(("terraform", f"-chdir={options['terraform_dir']}", "state", "pull"))),)
    return tuple((f"{m.label}/{loc.rsplit('/', 1)[-1] or 'terraform.tfstate'}",
                  Command(("gcloud", "storage", "cat", loc)))
                 for s in collection_sources(m, "gcp/terraform-state") for loc in s.locations
                 if loc.startswith("gs://"))


def identity_check(d, m):
    """`gcloud config list`, and whether its project is the one the cloud records and an account is signed in."""
    want = project_id(m)

    def check(out):
        core = _load(out, {}).get("core") or {}
        if not want:
            return "the cloud records no project (ciamAccountRef) to check the login against"
        if not core.get("account"):
            return "no account is signed in (gcloud auth login)"
        found = core.get("project")
        return None if found == want else \
            f"gcloud's project is {found}, the record names {want} (gcloud config set project)"
    return Command(("gcloud", "config", "list", "--format=json")), check


COLLECTORS = (Collector("cli-inventory", "environment", inventory_steps, identity_check),
              Collector("terraform-state", "environment", state_steps, identity_check))
