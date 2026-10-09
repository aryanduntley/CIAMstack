"""Google Cloud's Compute Engine quotas (core estate: quotas). A quota's id here is its metric as Compute Engine
reports it (CPUS, N2_CPUS, IN_USE_ADDRESSES), and a project-wide one's is global.<metric> (global.NETWORKS): what a
need names as its ciamProviderRef when no quota kind fits. The kinds:

  vcpus        CPUS               the region's CPUs (the N1/E2 pool: other machine families have their own metric,
                                  such as N2_CPUS; record that need by its id)
  public-ips   IN_USE_ADDRESSES   the region's in-use external addresses
  networks     global.NETWORKS    the project's VPC networks (a project-wide quota)

load-balancers has no single Compute quota (a load balancer is forwarding rules and backend services, each with its
own), database-instances none (Cloud SQL allows 1000 instances per project, raised by a support case) and
kubernetes-clusters none in Compute (GKE's own quotas): the planner names them as limits to confirm.

Fetched (`opsdir import gcp/quotas --run`, under the operator's own gcloud login and project) from
`gcloud compute project-info describe --format=json` (the project and its project-wide quotas) and, per region the
record's Google Cloud clouds needing quotas run in, `gcloud compute regions describe <region> --format=json`; a
region's catalog holds its regional quotas and the project-wide ones.

An increase the operator decided to request is rendered in the environment's root as
google_cloud_quotas_quota_preference (Cloud Quotas) for the quota ids Google documents, CPUS-per-project-region
(with the region as its dimension) for CPUS and NETWORKS-per-project for global.NETWORKS, at ciamQuotaRequested
(else the need), with deletion_policy ABANDON (destroying it leaves the granted quota alone); others are named in a
comment. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.directory import one, rdn_value
from opsdir.core.sources import json_document
from opsdir.domains.estate.quotas import (QuotaRow, limits_fetched, need_key, needed, quota_import, quota_needs,
                                          quota_regions)
from opsdir_format_terraform.hcl import Block, block, tf_name
from .inventory import PROVIDER

KIND_QUOTAS = {"vcpus": "CPUS", "public-ips": "IN_USE_ADDRESSES", "networks": "global.NETWORKS"}
QUOTA_KINDS = {q: k for k, q in KIND_QUOTAS.items()}
GLOBAL = "global."
PROJECT = "quotas/project.json"
PREFERENCE = "google_cloud_quotas_quota_preference"
# quota id here -> (Cloud Quotas quota id, whether its dimension is the region), as Google's Cloud Quotas pages give
# them
PREFERENCES = {"CPUS": ("CPUS-per-project-region", True), "global.NETWORKS": ("NETWORKS-per-project", False)}


def quota_commands(d):
    """The provider commands fetching the limits of the record's Google Cloud environments that need quotas: the
    project's (and its project-wide quotas), then each region's."""
    regions = quota_regions(d, PROVIDER)
    return (((PROJECT, ("gcloud", "compute", "project-info", "describe", "--format=json")),) if regions else ()) + \
        tuple((f"quotas/{r}.json", ("gcloud", "compute", "regions", "describe", r, "--format=json")) for r in regions)


def quota_rows_of(doc, prefix=""):
    """QuotaRows of a regions describe or project-info describe document's quotas (ids prefixed for project-wide
    ones)."""
    return tuple(QuotaRow(prefix + q["metric"], int(q["limit"]), None,
                          int(q["usage"]) if isinstance(q.get("usage"), (int, float)) else None,
                          QUOTA_KINDS.get(prefix + q["metric"]))
                 for q in doc.get("quotas") or () if isinstance(q, dict) and q.get("metric")
                 and isinstance(q.get("limit"), (int, float)))


def _project(doc):
    link = doc.get("selfLink") or ""
    return link.split("/projects/", 1)[1].split("/", 1)[0] if "/projects/" in link else None


def read_quotas(files, d, patterns, at=None):
    """Imported: the quota catalogs of the project (project-info describe) in each region a regions describe output is
    of, each with the project-wide quotas. Refused without the project's output."""
    docs = {p: json_document(t, dict) for p, t in sorted(files.items())}
    project = next((doc for doc in docs.values() if doc is not None and doc.get("kind") == "compute#project"), None)
    if project is None:
        raise SystemExit(f"gcp/quotas: the export has no project (add `gcloud compute project-info describe "
                         f"--format=json > {PROJECT}`); nothing imported")
    regions = {p: doc for p, doc in docs.items() if doc is not None and doc.get("kind") == "compute#region"}
    shared = quota_rows_of(project, GLOBAL)
    imported = quota_import(d, PROVIDER, {(project.get("name") or _project(project), doc["name"]):
                                          (*quota_rows_of(doc), *shared) for doc in regions.values()})
    return imported._replace(notices=(*imported.notices, *(f"{p}: not `gcloud compute` project or region output; "
                                                            "not read" for p, doc in docs.items()
                                                            if doc is not project and p not in regions)))


QUOTAS = Importer("quotas", "the Compute Engine quotas of the project in each region the record's Google Cloud "
                            "environments needing quotas run in (and its project-wide ones)", read_quotas,
                  quota_commands)
PREREQUISITE = Prerequisite("gcp-quotas", "Google Cloud's Compute Engine quotas for the projects and regions whose "
                                          "environments record quota needs, for the planner's quota check",
                            QUOTAS.name, partial(limits_fetched, provider=PROVIDER))


def quota_id(kind_or_id):
    """The quota id (metric, global.<metric>) a need key names: a kind's, or the key itself."""
    return KIND_QUOTAS.get(kind_or_id, kind_or_id)


def _request(m, n, key):
    value = int(one(n, "ciamQuotaRequested") or needed(m, key))
    qid, region = quota_id(key), one(m.cloud, "ciamRegion")
    if qid not in PREFERENCES:
        return (f"# Quota request ({key}): raise {qid} to {value} for the project in {region} (Cloud Quotas: no quota "
                "id documented for it here, so not rendered)",)
    quota, regional = PREFERENCES[qid]
    return (block("resource", [PREFERENCE, tf_name(f"{rdn_value(n)}_{key}")], [
        ("#", f"{key}: requested by decision (ciamQuotaDecision); the quota is the project's"),
        ("parent", "projects/${var.project_id}"), ("service", "compute.googleapis.com"), ("quota_id", quota),
        *((("dimensions", {"region": region}),) if regional else ()),
        ("quota_config", Block((("preferred_value", value),))), ("deletion_policy", "ABANDON")]),)


def render_quota_requests(m):
    """google_cloud_quotas_quota_preference (or a comment) for each of environment m's needs whose increase the
    operator decided to request."""
    return tuple(x for n in quota_needs(m) if one(n, "ciamQuotaDecision") == "request" for x in _request(m, n,
                                                                                                         need_key(n)))
