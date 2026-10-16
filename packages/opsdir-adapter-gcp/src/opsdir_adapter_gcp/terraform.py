"""Google Cloud adapter: render an environment's infrastructure bindings as Terraform (hashicorp/google ~> 8).

The landing zone owns the network and subnetworks (data sources; a Shared VPC host project is read from the
reference). Firewall rules are VPC-wide and target a network tag per server role (ciam-<env>-<role>), with
priorities pinned like Azure's; each description ends with the record's rule name, "(fw-name)", which the importers
group rules back by. Instances carry their role and product exactly in metadata (ciam-role, ciam-product: labels
allow only lowercase), which the importers read back. Each service name is a passthrough network load balancer
(internal for a private frontend address) over the role's servers in zonal instance groups, with a Cloud DNS record
and a firewall rule admitting Google Cloud's health-check probes.
Secrets are named, never read: the Secret Manager data sources hold metadata, not versions. Each workload principal
the servers run as gets a service account on those instances (scope cloud-platform: IAM decides) and resource-level IAM
members from its permissions (the Google Cloud permission table, opsdir_adapter_gcp.access): on the secret, the key,
the bucket, the topic; log writes on the project, the narrowest Google Cloud allows.
"""
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role, recorded, secret, subnet_of
from opsdir.domains.compute.hosts import own_groups
from opsdir.domains.compute.workloads import cluster_subnets, kubernetes_note, only_on_kubernetes
from opsdir.core.manifest import header
from opsdir.core.notes import note_comment
from opsdir.domains.infrastructure.firewall import priority_note, priority_notes, rule_priorities, rule_purpose
from opsdir.domains.access.evaluations import evaluation_files
from opsdir.domains.access.workloads import identity_notes, identity_of, workload_identities
from opsdir.domains.edge.exposure import is_internal, service_exposure
from opsdir.domains.edge.gateways import front_choice
from opsdir.domains.edge.kubernetes import kubernetes_notes
from opsdir.domains.edge.resolve import (inspected, inspection_notes, rendered_edges,
                                        service_edge)
from opsdir.domains.network.stack import firewall_model
from opsdir_adapter_gcp.access import ACCESS
from opsdir_adapter_gcp.databases import database_notes, render_databases
from opsdir_adapter_gcp.managed_ad import managed_ad_notes, render_managed_ad
from opsdir_adapter_gcp.storage import kept_buckets, render_object_stores
from opsdir_adapter_gcp.dns import failover_notes, forwarder_notes, forwarding_zones, records, service_record
from opsdir_adapter_gcp.edge import (alb_rendered, application_lb, category_notes, network_lb,
                                     private_cdn_note, servers_backend)
from opsdir_adapter_gcp.firewall_policy import health_check_rule, policy_firewall, policy_notes
from opsdir_adapter_gcp.identities import identity, project_of
from opsdir_adapter_gcp.ingress import gateway_front, gateway_negs
from opsdir_adapter_gcp.landing import STACK, landing_parts, placed_roots
from opsdir_format_terraform.placing import MAIN, PROVIDERS, carried_files
from opsdir.domains.governance.keepers import scope_folder
from opsdir_adapter_gcp.names import name_parts
from opsdir_adapter_gcp.names import NETWORK, PRIORITIES, REGION, label, network_tag
from opsdir_adapter_gcp.network import network_notes, render_network
from opsdir_adapter_gcp.plumbing import network_data, plumbing_notes
from opsdir_adapter_gcp.backups import backup_notes, render_backups
from opsdir_adapter_gcp.audit import audit_notes, render_trails
from opsdir_adapter_gcp.log_sinks import log_sink_notes, render_log_sinks
from opsdir_adapter_gcp.observability import alert_notes, render_buckets, render_policies
from opsdir_adapter_gcp.canaries import render_checks, uptime_notes
from opsdir_adapter_gcp.synthetic_monitors import monitor_notes, render_monitors
from opsdir_adapter_gcp.discovery import discovery_notes, render_discovery
from opsdir_adapter_gcp.boundary import workload_notes
from opsdir_adapter_gcp.guardrails import guardrail_notes
from opsdir_adapter_gcp.security import render_security, security_notes
from opsdir_adapter_gcp.suppressions import render_suppressions
from opsdir_adapter_gcp.quotas import quota_notes, render_quota_requests
from opsdir_adapter_gcp.budgets import budget_notes
from opsdir_adapter_gcp.volumes import boot_disk, render_snapshot_policies, server_volumes, volume_notes
from opsdir_adapter_gcp.compute_groups import group_notes, render_groups
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_name, unbound_comments, written
from .account import fips_note, project_variable, provider_block, required_providers

_tag, _label = network_tag, label


def _firewall_rule(m, fw, prio, pinned):
    if only_on_kubernetes(m, one(fw, "ciamTargetRole")):
        return (comment(note_comment(kubernetes_note(m, f"firewall rule `{rdn_value(fw)}`", one(fw, "ciamTargetRole"),
                                                     fw.dn))),)
    note = () if pinned else (comment(note_comment(priority_note(m, fw, prio))),)
    return (*note, tf_block("resource", ["google_compute_firewall", tf_name(rdn_value(fw))], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(fw)}"),
        ("description", f"{rule_purpose(m, fw)} ({rdn_value(fw)})"),
        ("network", NETWORK), ("direction", "INGRESS"), ("priority", prio),
        ("allow", Block((("protocol", one(fw, "ciamProtocol", "tcp")), ("ports", values(fw, "ciamPort"))))),
        ("source_ranges", values(fw, "ciamSourceCidr")),
        ("target_tags", [_tag(m, one(fw, "ciamTargetRole"))])]))


def firewall_notes(m):
    """The render notes of environment m's firewall rules given the next free priority: the network firewall policy's
    (firewall_policy.policy_notes) when that is the network's model, else each VPC rule it renders (not one for a role
    run only on Kubernetes)."""
    if firewall_model(m) == "policy":
        return policy_notes(m)
    rules = of_class(m, "ciamFirewallRule")
    return priority_notes(m, rules, rule_priorities(rules, *PRIORITIES),
                          lambda fw: only_on_kubernetes(m, one(fw, "ciamTargetRole")))


def _firewall(m):
    """The record's inbound rules: VPC firewall rules by network tag, or a network firewall policy's rules by secure
    tag (opsdir_adapter_gcp.firewall_policy) when the network's firewall model is policy."""
    if firewall_model(m) == "policy":
        return policy_firewall(m)
    rules = of_class(m, "ciamFirewallRule")
    prios = rule_priorities(rules, *PRIORITIES)
    return tuple(chain.from_iterable(_firewall_rule(m, fw, *prios[fw.dn]) for fw in rules))


def _instance(m, s, kms, identities=()):
    role = one(s, "ciamServerRole")
    w = identity_of(identities, role)
    notes, disk = boot_disk(m, s, kms)
    return (*notes, tf_block("resource", ["google_compute_instance", tf_name(rdn_value(s))], [
        ("name", rdn_value(s)), ("machine_type", recorded(s, "ciamInstanceSize", "size")),
        ("zone", recorded(s, "ciamZone", "zone")),
        ("hostname", one(s, "ciamHostname")), ("tags", [_tag(m, role)]),
        ("boot_disk", disk),
        ("network_interface", Block((
            ("subnetwork", ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(subnet_of(m, s)))}.self_link")),
            *((("network_ip", one(s, "ciamPrivateIp")),) if one(s, "ciamPrivateIp") else ())))),
        ("shielded_instance_config", Block((("enable_secure_boot", True), ("enable_vtpm", True),
                                            ("enable_integrity_monitoring", True)))),
        *((("service_account", Block((("email", ref(f"google_service_account.{tf_name(w.identity_role)}.email")),
                                      ("scopes", ["cloud-platform"])))),) if w else ()),
        ("metadata", {"enable-oslogin": "TRUE", "ciam-role": role, "ciam-product": one(s, "ciamProductVersion", "")}),
        ("labels", {"role": _label(role), "product": _label(one(s, "ciamProductVersion")),
                    "managed_by": "opsdir"})]), *server_volumes(m, s))


def _zones(targets):
    return tuple(sorted({one(t, "ciamZone") for t in targets}))


def _frontend(svc, n, ip, internal):
    """(data sources needed, the forwarding rule's address): a public frontend named by the service's provider ref
    is a reserved address read as data."""
    if internal or not one(svc, "ciamProviderRef"):
        return (), ip
    return ((tf_block("data", ["google_compute_address", n], [("name", one(svc, "ciamProviderRef")),
                                                              ("region", REGION)]),),
            ref(f"data.google_compute_address.{n}.address"))


def _service(m, svc, endpoints=()):
    """A stable service name: a passthrough network load balancer over the role's servers (zonal instance groups,
    a regional backend service with a TCP health check and the firewall rule its probes need, a forwarding rule) and
    its Cloud DNS record. An EXTERNAL backend service names its port (port_name, each group's named_port) and scales
    its backends' capacity; INTERNAL takes neither. A forwarding rule takes at most five ports, else all ports. For a
    role run only on Kubernetes, the Application Load Balancer before its cluster's gateway
    (opsdir_adapter_gcp.ingress), else a note; a note when its exposure is unknown (the core's
    edge.gateways.front_choice). Without a recorded address Google Cloud assigns one. The passthrough balancer is
    opsdir_adapter_gcp.edge.network_lb."""
    n, name = tf_name(rdn_value(svc)), f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"
    ip, ports = one(svc, "ciamFrontendIp"), values(svc, "ciamPort")
    target = one(svc, "ciamTargetRole")
    kind, *chosen = front_choice(m, svc)
    if kind == "note":
        return (comment(chosen[0]),)
    internal = is_internal(svc)
    if kind == "gateway":
        subnets = cluster_subnets(m, target)
        subnetwork = f"data.google_compute_subnetwork.{tf_name(rdn_value(subnets[0]))}.self_link" if subnets else None
        placement = (("subnetwork", ref(subnetwork)),) if internal and subnetwork else ()
        return gateway_front(m, svc, chosen[0], endpoints, _frontend(svc, n, ip, internal), placement)
    targets, subnets = chosen
    groups_ = own_groups(m, target)
    managed = tuple(ref(f"google_compute_region_instance_group_manager.{tf_name(rdn_value(g))}.instance_group")
                    for g in groups_)
    data, address = _frontend(svc, n, ip, internal)
    spec = service_edge(m, svc, endpoints)
    cdn = spec is not None and spec.cdn
    layer7 = spec is not None and (spec.layer7 or cdn)         # Cloud CDN is an Application Load Balancer's
    named = () if internal and not layer7 else (("named_port", Block((("name", "ciam"), ("port", int(ports[0]))))),)
    groups = tuple(tf_block("resource", ["google_compute_instance_group", f"{n}_{tf_name(zone)}"], [
        ("name", f"{name}-{zone}"), ("zone", zone),
        ("instances", [ref(f"google_compute_instance.{tf_name(rdn_value(t))}.self_link")
                       for t in targets if one(t, "ciamZone") == zone]), *named]) for zone in _zones(targets))
    placement = ((("network", NETWORK), ("subnetwork", ref(
        f"data.google_compute_subnetwork.{tf_name(rdn_value(subnets[0]))}.self_link")))
        if internal and subnets else ())
    record = service_record(m.d, m, svc, n, cdn)
    if layer7:
        admit = health_check_rule if firewall_model(m) == "policy" else None
        return (*groups, *application_lb(m, svc, spec,
                                         servers_backend(m, svc, tuple(f"{n}_{tf_name(z)}" for z in _zones(targets)),
                                                         managed),
                                         (data, address), placement[1:], admit), *record)
    return (*network_lb(m, svc, spec, groups, (*(ref(f"google_compute_instance_group.{n}_{tf_name(zone)}.self_link")
                                                 for zone in _zones(targets)), *managed),
                        (data, address), placement), *record)


def _ports(m, endpoints):
    """{server role: the ports the service names reaching it name 'ciam' on its instance groups}: the named port its
    compute groups' managed instance groups carry (an INTERNAL passthrough service names none)."""
    found = {}
    for svc in of_class(m, "ciamServiceName"):
        role, ports = one(svc, "ciamTargetRole"), values(svc, "ciamPort")
        if service_exposure(svc) is None or only_on_kubernetes(m, role) or not ports:
            continue
        spec = service_edge(m, svc, endpoints)
        if not is_internal(svc) or (spec is not None and (spec.layer7 or spec.cdn)):
            found.setdefault(role, []).append(int(ports[0]))
    return {role: tuple(p) for role, p in found.items()}


def _secret(b):
    path = name_parts(one(b, "ciamRefUri").split("://", 1)[1])
    regional = "locations" in path
    return tf_block("data", ["google_secret_manager_regional_secret" if regional else "google_secret_manager_secret",
                             tf_name(one(b, "ciamBindingRole"))], [
           ("#", "metadata only: no secret version (value) enters Terraform state"),
           ("secret_id", path.get("secrets")), *project_of(path),
           *((("location", path["locations"]),) if regional else ())])


def _references(m):
    """Data sources only: Secret Manager secrets, the backup bucket (unless the stack renders it: object stores); a
    comment for the egress the landing zone provides."""
    bk, eg = one_role(m, "backup-target"), one_role(m, "pf-egress")
    bk = None if bk is not None and bk.dn in {b.dn for b in kept_buckets(m)} else bk
    return (*(_secret(b) for b in of_class(m, "ciamSecretRef")
              if (one(b, "ciamRefUri") or "").startswith("gcp-sm://")),
            *((tf_block("data", ["google_storage_bucket", "ds_backups"],
                        [("name", one(bk, "ciamStorageRef").split("://", 1)[1].split("/", 1)[0])]),)
              if bk and (one(bk, "ciamStorageRef") or "").startswith("gs://") else ()),
            *((comment(f"Egress '{rdn_value(eg)}': Cloud NAT {one(eg, 'ciamProviderRef')} (landing zone; not managed "
                       "here)"),)
              if eg and one(eg, "ciamProviderRef") else ()))


def render_files(m, services):
    """{path: TfFile | text} of environment m's Google Cloud render: the Terraform roots as data (main, providers,
    the landing zone's roots), the workflow, synthetic monitor source and evaluation files they come with as text."""
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    kms, identities = secret(m, "disk-encryption"), workload_identities(m, ACCESS)
    discovery, workflows = render_discovery(m)
    monitors, sources = render_monitors(m, endpoints)
    out = (*network_data(m), *_firewall(m), *chain.from_iterable(identity(m, w) for w in identities),
           *chain.from_iterable(_instance(m, s, kms, identities) for s in m.servers),
           *render_groups(m, kms, identities, _ports(m, endpoints)),
           *render_snapshot_policies(m), *render_backups(m),
           *gateway_negs(m),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *render_databases(m), *render_managed_ad(m), *render_object_stores(m),
           *records(m.d, m),
           *forwarding_zones(m), *render_trails(m), *render_buckets(m),
           *(render_log_sinks(m, services) if services else ()),
           *(comment(note_comment(n)) for n in (log_sink_notes(m, services) if services else ())),
           *render_policies(m),
           *render_checks(m, endpoints), *monitors, *render_security(m),
           *discovery, *render_suppressions(m),
           *render_quota_requests(m), *(comment(note_comment(n)) for n in budget_notes(m)),
           *_references(m))
    providers = (
        required_providers(archive=bool(sources)),
        provider_block(m, ("project", ref("var.project_id")), ("region", REGION)),
        project_variable(m),
        tf_block("variable", ["region"], [("type", ref("string")), ("default", one(m.cloud, "ciamRegion"))]))
    landing, landing_dns = landing_parts(m)
    roots = placed_roots(m, ((PROVIDERS, providers), (MAIN, out), *landing), landing_dns, lambda name: (
        header(m, "Google Cloud infrastructure for the CIAM platform", HCL) + unbound_comments(m.unbound)
        if name == MAIN else header(m, "Providers and inputs", HCL)))
    carried = carried_files(roots, {**workflows, **sources}, STACK)
    if scope_folder(m) is not None:                 # a slice: its root and the files it reads, nothing of the stack's
        return {**roots, **carried}
    return {**roots, **workflows, **sources, **carried, **evaluation_files(m, ACCESS, "Google Cloud")}


def render(m, services):
    """Adapter render: environment m's Google Cloud files as text, each Terraform file written once from its
    TfFile."""
    return written(render_files(m, services))


def edge_notes(m, endpoints):
    """The render notes of environment m's service names' edges, each once: passthrough load balancers asked to
    inspect requests (core edge.resolve inspection_notes), CDNs before private addresses (edge.private_cdn_note), and
    the firewall categories Cloud Armor can't render (edge.category_notes) in the policies of the Application Load
    Balancers it renders (before a cluster gateway, layer 7 or with Cloud CDN; edge.alb_rendered)."""
    albs = tuple((svc, spec) for svc, spec, gw in rendered_edges(m, endpoints)
                 if spec is not None and (gw is not None or spec.layer7 or spec.cdn))
    return tuple(dict.fromkeys((
        *inspection_notes(m, endpoints), *(private_cdn_note(m, svc) for svc, spec in albs
                                           if spec.cdn and is_internal(svc)),
        *(n for svc, spec in albs if inspected(spec) and alb_rendered(m, svc, spec) for n in category_notes(spec)))))


def render_notes(m, services):
    """Adapter notes (core.notes, flow 43): what environment m's Google Cloud render leaves out or to a person, as
    data, each written as its comment: the synthetic checks it doesn't render (uptime checks, synthetic monitors), then
    the security services', audit trails', data discovery's, guardrails', Assured Workloads workload's, alert rules'
    identities' (core access.workloads), Kubernetes-only roles' (core edge.kubernetes) and unpinned rule priorities'
    notes, the network depth's and the landing zone plumbing's, and log shipping's (sinks, the Ops Agent,
    containers)."""
    endpoints = services.endpoints if services else ()
    return (*uptime_notes(m, endpoints), *monitor_notes(m, endpoints), *security_notes(m), *audit_notes(m),
            *discovery_notes(m), *guardrail_notes(m), *workload_notes(m), *alert_notes(m),
            *identity_notes(m, ACCESS), *kubernetes_notes(m, firewall=firewall_model(m) != "policy"),
            *firewall_notes(m), *budget_notes(m), *((fips_note(m),) if fips_note(m) else ()), *forwarder_notes(m),
            *database_notes(m), *managed_ad_notes(m), *backup_notes(m), *volume_notes(m), *group_notes(m),
            *edge_notes(m, endpoints),
            *failover_notes(m, endpoints), *quota_notes(m), *network_notes(m, endpoints), *plumbing_notes(m),
            *(log_sink_notes(m, services) if services else ()))
