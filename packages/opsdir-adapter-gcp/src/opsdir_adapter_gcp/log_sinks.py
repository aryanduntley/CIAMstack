"""Log routes to Cloud Logging buckets (core observability: log routes): per route, a log sink taking the lines the
route ships from the environment's servers (ops_agent: their receivers' log names) and containers (container_logs:
their clusters, namespaces, pods and containers), and an exclusion keeping the _Default sink from storing them a second
time. Terraform. Pure.

google_logging_project_sink ciam-<env>-<route>: destination logging.googleapis.com/<the route's bucket>, the filter
(the parts any of which holds), a unique writer identity. google_logging_project_exclusion ciam-<env>-<route>: the
same filter, added to the _Default sink (the _Default sink itself isn't managed here: other exclusions on it stay).
docs.cloud.google.com/logging/docs/routing/overview, registry.terraform.io/providers/hashicorp/google/latest/docs/
resources/logging_project_sink, .../logging_project_exclusion (research note 2363).

Named instead, each a render note (log_sink_notes, flow 43) written as its comment: a route whose destination here
isn't a Cloud Logging bucket; one whose bucket is _Default (its
lines already land there); a filter past Cloud Logging's 20,000 characters; a bucket in another project (the sink's
writer identity needs roles/logging.bucketWriter there); and, for an environment under an Assured Workloads regime,
what Google's supported-products list doesn't name (the Ops Agent) or restrict per feature (log sinks, GKE workload
logging): to be confirmed.
"""
from opsdir.core.directory import rdn_value
from opsdir.core.notes import RECORD, note
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import own_shipments, shipments
from opsdir_format_terraform.hcl import tf_block, tf_name
from .account import project_id, regime
from .container_logs import container_filter, container_log_notes, container_shipments
from .logging_filter import LIMIT, any_of
from .observability import bucket_parts
from .ops_agent import host_filter, host_shipments, ops_agent_notes

SINK, EXCLUSION = "google_logging_project_sink", "google_logging_project_exclusion"


def route_filters(m, services):
    """((route, destination, filter), ...): each log route of environment m shipping lines to a Cloud Logging bucket,
    with the query taking them all."""
    sources = services.logs(m)
    parts = (*((x, host_filter(x)) for x in host_shipments(m, services)),
             *((x, container_filter(m, x, sources)) for x in container_shipments(m, services)))
    routes = {x.route.dn: (x.route, x.destination) for x, p in parts if p}
    return tuple((r, dest, any_of(tuple(p for x, p in parts if p and x.route.dn == dn)))
                 for dn, (r, dest) in routes.items())


def _kept(dest, query):
    return bucket_parts(dest)[2] != "_Default" and len(query) <= LIMIT


def render_log_sinks(m, services):
    """HCL for environment m's log routes to Cloud Logging buckets: per route its sink and _Default exclusion."""
    def blocks(r, dest, query):
        n, name = tf_name(f"logs_{rdn_value(r)}"), f"ciam-{rdn_value(m.env)}-{rdn_value(r)}"
        project, location, bucket = bucket_parts(dest)
        what = f"Log route {rdn_value(r)}: product logs to {rdn_value(dest)} (opsdir)"
        return (tf_block("resource", [SINK, n], [
                    ("name", name), ("description", what),
                    ("destination", f"logging.googleapis.com/projects/{project}/locations/{location}/buckets/{bucket}"),
                    ("filter", query), ("unique_writer_identity", True)]),
                tf_block("resource", [EXCLUSION, n], [
                    ("name", name), ("description", f"{what}: kept in {rdn_value(dest)}, not also in _Default"),
                    ("filter", query)]))
    return tuple(b for r, dest, query in route_filters(m, services) if _kept(dest, query)
                 for b in blocks(r, dest, query))


def _not_bucket(m, services):
    every = own_shipments(m, shipments(m, log_routes(m.d), services.logs(m)), services.siem_keeper, "gcp")
    return tuple(note("Logs", "blocker", f"log route {rdn_value(x.route)}", f"role {x.role}'s logs not shipped: its "
                      f"destination {rdn_value(x.destination)} isn't a Cloud Logging bucket "
                      "(projects/<p>/locations/<l>/buckets/<b>)",
                      (f"Bind the route's destination role to a log destination whose ciamProviderRef is a Cloud "
                       f"Logging bucket (projects/<p>/locations/<l>/buckets/<b>), {RECORD}",), x.route.dn, m.label)
                 for x in every if x.destination is not None and bucket_parts(x.destination) is None)


def log_sink_notes(m, services):
    """The render notes of what environment m's log routes don't ship to Cloud Logging buckets (blockers), ship
    differently (notes), or need by hand and to confirm (actions), the Ops Agent's and the containers' among them,
    each once (render_files writes their comments)."""
    found = route_filters(m, services)
    level = regime(m)
    return tuple(dict.fromkeys((
        *_not_bucket(m, services),
        *ops_agent_notes(m, services), *container_log_notes(m, services),
        *(note("Logs", "note", f"log route {rdn_value(r)}", "its lines already land in the _Default bucket (no sink "
               "rendered)", (), r.dn, m.label)
          for r, dest, _ in found if bucket_parts(dest)[2] == "_Default"),
        *(note("Logs", "blocker", f"log route {rdn_value(r)}", f"not rendered: its filter is {len(q)} characters, "
               f"past Cloud Logging's {LIMIT}",
               (f"Split the route into routes of fewer roles or kinds, each with a filter of {LIMIT} characters or "
                f"fewer, {RECORD}",), r.dn, m.label)
          for r, _, q in found if len(q) > LIMIT),
        *(note("Logs", "action", f"log route {rdn_value(r)}", f"bucket {rdn_value(dest)} is in project "
               f"{bucket_parts(dest)[0]}: grant the sink's writer identity roles/logging.bucketWriter there",
               (f"After the sink is applied, grant its writer identity (the sink's writer_identity output) "
                f"roles/logging.bucketWriter on bucket {rdn_value(dest)} in project {bucket_parts(dest)[0]}, by "
                "hand",), r.dn, f"project {bucket_parts(dest)[0]}")
          for r, dest, _ in found if bucket_parts(dest)[0] != project_id(m)),
        *((note("Logs", "action", f"Assured Workloads ({level})", "Cloud Logging, Compute Engine and GKE are supported "
                "products; the Ops Agent isn't listed on its own, and restrictions on log sinks and GKE workload "
                "logging under it are to be confirmed",
                ("Ask Google's account team whether the Ops Agent, log sinks and GKE workload logging may be used "
                 "under the workload's compliance regime before relying on them",), None, m.label),)
          if found and level else ()))))
