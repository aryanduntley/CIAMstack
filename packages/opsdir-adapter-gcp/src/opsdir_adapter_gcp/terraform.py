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
from opsdir.core.environment import of_class, one_role, secret, servers_with_role, subnet_of
from opsdir.core.manifest import header
from opsdir.core.network import is_private
from opsdir.domains.infrastructure.firewall import rule_priorities, rule_purpose
from opsdir.domains.access.evaluations import evaluation_files
from opsdir.domains.access.workloads import identity_of, workload_identities
from opsdir.domains.edge.resolve import inspected, service_edge
from opsdir.domains.network.stack import firewall_model
from opsdir_adapter_gcp.access import ACCESS
from opsdir_adapter_gcp.dns import forwarding_zones, records, service_record
from opsdir_adapter_gcp.edge import application_lb, network_ddos
from opsdir_adapter_gcp.firewall_policy import health_check_rule, policy_firewall
from opsdir_adapter_gcp.health_checks import probe_ranges
from opsdir_adapter_gcp.identities import identity, project_of
from opsdir_adapter_gcp.landing import render_landing
from opsdir_adapter_gcp.names import name_parts
from opsdir_adapter_gcp.names import NETWORK, REGION, label, network_tag
from opsdir_adapter_gcp.network import render_network
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, block, ref, tf_name, unbound_comments

_tag, _label = network_tag, label


def _network(m):
    net = one_role(m, "network")
    path = name_parts(one(net, "ciamProviderRef"))
    return (block("data", ["google_compute_network", "main"],
                  [("name", path.get("networks", one(net, "ciamProviderRef"))), *project_of(path)]),
            *(_subnet(m, s) for s in of_class(m, "ciamSubnetBinding")))


def _subnet(m, s):
    path = name_parts(one(s, "ciamProviderRef"))
    return block("data", ["google_compute_subnetwork", tf_name(rdn_value(s))], [
        ("name", path.get("subnetworks", one(s, "ciamProviderRef"))),
        ("region", path.get("regions", one(m.cloud, "ciamRegion"))), *project_of(path)])


def _firewall_rule(m, fw, prio, pinned):
    note = () if pinned else (
        f"# NOTE: {rdn_value(fw)} has no pinned ciamRulePriority; assigned {prio}. Pin it in the directory.",)
    return (*note, block("resource", ["google_compute_firewall", tf_name(rdn_value(fw))], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(fw)}"),
        ("description", f"{rule_purpose(m, fw)} ({rdn_value(fw)})"),
        ("network", NETWORK), ("direction", "INGRESS"), ("priority", prio),
        ("allow", Block((("protocol", one(fw, "ciamProtocol", "tcp")), ("ports", values(fw, "ciamPort"))))),
        ("source_ranges", values(fw, "ciamSourceCidr")),
        ("target_tags", [_tag(m, one(fw, "ciamTargetRole"))])]))


def _firewall(m):
    """The record's inbound rules: VPC firewall rules by network tag, or a network firewall policy's rules by secure
    tag (opsdir_adapter_gcp.firewall_policy) when the network's firewall model is policy."""
    if firewall_model(m) == "policy":
        return policy_firewall(m)
    rules = of_class(m, "ciamFirewallRule")
    prios = rule_priorities(rules, 1000, 10, 65535)
    return tuple(chain.from_iterable(_firewall_rule(m, fw, *prios[fw.dn]) for fw in rules))


def _instance(m, s, kms, identities=()):
    role = one(s, "ciamServerRole")
    w = identity_of(identities, role)
    key = (("kms_key_self_link", kms.split("://", 1)[1]) if kms
           else ("#", "UNBOUND: no disk-encryption key binding in this environment"))
    return block("resource", ["google_compute_instance", tf_name(rdn_value(s))], [
        ("name", rdn_value(s)), ("machine_type", one(s, "ciamInstanceSize")), ("zone", one(s, "ciamZone")),
        ("hostname", one(s, "ciamHostname")), ("tags", [_tag(m, role)]),
        ("boot_disk", Block((("initialize_params", Block((("image", one(s, "ciamImageRef")),))), key))),
        ("network_interface", Block((
            ("subnetwork", ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(subnet_of(m, s)))}.self_link")),
            ("network_ip", one(s, "ciamPrivateIp"))))),
        ("shielded_instance_config", Block((("enable_secure_boot", True), ("enable_vtpm", True),
                                            ("enable_integrity_monitoring", True)))),
        *((("service_account", Block((("email", ref(f"google_service_account.{tf_name(w.identity_role)}.email")),
                                      ("scopes", ["cloud-platform"])))),) if w else ()),
        ("metadata", {"enable-oslogin": "TRUE", "ciam-role": role, "ciam-product": one(s, "ciamProductVersion", "")}),
        ("labels", {"role": _label(role), "product": _label(one(s, "ciamProductVersion")),
                    "managed_by": "opsdir"})])


def _zones(targets):
    return tuple(sorted({one(t, "ciamZone") for t in targets}))


def _frontend(svc, n, ip, internal):
    """(data sources needed, the forwarding rule's address): a public frontend named by the service's provider ref
    is a reserved address read as data."""
    if internal or not one(svc, "ciamProviderRef"):
        return (), ip
    return ((block("data", ["google_compute_address", n], [("name", one(svc, "ciamProviderRef")),
                                                           ("region", REGION)]),),
            ref(f"data.google_compute_address.{n}.address"))


def _health_check_rule(m, svc, n, name, scheme, port):
    """The firewall rule admitting Google Cloud's health-check probes to the service's servers on its checked port:
    part of the load balancer, not one of the record's rules (the importers leave it out). A policy rule under the
    policy model."""
    if firewall_model(m) == "policy":
        return health_check_rule(m, svc, n, probe_ranges(scheme), port)
    return block("resource", ["google_compute_firewall", f"{n}_health_checks"], [
        ("name", f"{name}-health-checks"), ("description", f"Google Cloud health checks for {rdn_value(svc)}"),
        ("network", NETWORK), ("direction", "INGRESS"),
        ("allow", Block((("protocol", "tcp"), ("ports", [port])))),
        ("source_ranges", list(probe_ranges(scheme))), ("target_tags", [_tag(m, one(svc, "ciamTargetRole"))])])


def _l4_tuning(spec):
    """(health check body, backend service settings) from a passthrough service's traffic policy."""
    if spec is None:
        return None, ()
    h = spec.health
    check = (*((("check_interval_sec", h.interval),) if h.interval else ()),
             *((("healthy_threshold", h.healthy),) if h.healthy else ()),
             *((("unhealthy_threshold", h.unhealthy),) if h.unhealthy else ()))
    kind = ((f"{h.protocol}_health_check", ((("request_path", h.path or "/"),))),) if h.protocol != "tcp" else ()
    affinity = (("session_affinity", "CLIENT_IP"),) if spec.stickiness == "source-ip" else ()
    drain = (("connection_draining_timeout_sec", spec.drain),) if spec.drain is not None else ()
    return (check, kind), (*affinity, *drain)


def _service(m, svc, endpoints=()):
    """A stable service name: a passthrough network load balancer over the role's servers (zonal instance groups,
    a regional backend service with a TCP health check and the firewall rule its probes need, a forwarding rule) and
    its Cloud DNS record. An EXTERNAL backend service names its port (port_name, each group's named_port) and scales
    its backends' capacity; INTERNAL takes neither. A forwarding rule takes at most five ports, else all ports."""
    n, name = tf_name(rdn_value(svc)), f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"
    ip, ports = one(svc, "ciamFrontendIp"), values(svc, "ciamPort")
    internal = is_private(ip)
    scheme = "INTERNAL" if internal else "EXTERNAL"
    targets = servers_with_role(m, one(svc, "ciamTargetRole"))
    data, address = _frontend(svc, n, ip, internal)
    spec = service_edge(m, svc, endpoints)
    cdn = spec is not None and spec.cdn
    layer7 = spec is not None and (spec.layer7 or cdn)         # Cloud CDN is an Application Load Balancer's
    named = () if internal and not layer7 else (("named_port", Block((("name", "ciam"), ("port", int(ports[0]))))),)
    groups = tuple(block("resource", ["google_compute_instance_group", f"{n}_{tf_name(zone)}"], [
        ("name", f"{name}-{zone}"), ("zone", zone),
        ("instances", [ref(f"google_compute_instance.{tf_name(rdn_value(t))}.self_link")
                       for t in targets if one(t, "ciamZone") == zone]), *named]) for zone in _zones(targets))
    placement = ((("network", NETWORK), ("subnetwork", ref(
        f"data.google_compute_subnetwork.{tf_name(rdn_value(subnet_of(m, targets[0])))}.self_link")))
        if internal and targets else ())
    record = service_record(m.d, m, svc, n, cdn)
    if layer7:
        admit = health_check_rule if firewall_model(m) == "policy" else None
        return (*groups, *application_lb(m, svc, spec, tuple(f"{n}_{tf_name(z)}" for z in _zones(targets)),
                                         (data, address), placement[1:], admit), *record)
    (check, kind), tuning = _l4_tuning(spec) if spec is not None else ((None, ()), ())
    health = kind[0] if kind else ("tcp_health_check", ())
    blind = ("# the protection policy's request inspection needs TLS terminated at the edge; not rendered",) \
        if spec is not None and inspected(spec) else ()
    capacity = () if internal else (("capacity_scaler", 1.0),)
    forwarded = ((("ports", ports),) if len(ports) <= 5 else
                 (("#", "more than five ports: all are forwarded; the firewall rules admit only the service's"),
                  ("all_ports", True)))
    return (*data, *blind, *groups,
            block("resource", ["google_compute_region_health_check", n], [
                ("name", name), ("region", REGION), *(check or ()),
                (health[0], Block((("port", int(ports[0])), *health[1])))]),
            _health_check_rule(m, svc, n, name, scheme, ports[0]),
            block("resource", ["google_compute_region_backend_service", n], [
                ("name", name), ("region", REGION), ("load_balancing_scheme", scheme), ("protocol", "TCP"),
                *((("port_name", "ciam"),) if not internal else ()),
                ("health_checks", [ref(f"google_compute_region_health_check.{n}.id")]), *tuning,
                *(("backend", Block((
                    ("group", ref(f"google_compute_instance_group.{n}_{tf_name(zone)}.self_link")),
                    ("balancing_mode", "CONNECTION"), *capacity)))
                  for zone in _zones(targets))]),
            block("resource", ["google_compute_forwarding_rule", n], [
                ("name", name), ("region", REGION), ("load_balancing_scheme", scheme), ("ip_protocol", "TCP"),
                *forwarded, ("ip_address", address),
                ("backend_service", ref(f"google_compute_region_backend_service.{n}.id")), *placement,
                ("labels", {"service": _label(one(svc, "ciamFqdn")), "managed_by": "opsdir"})]),
            *(network_ddos(m, n, spec) if spec is not None and not internal else ()), *record)


def _secret(b):
    path = name_parts(one(b, "ciamRefUri").split("://", 1)[1])
    regional = "locations" in path
    return block("data", ["google_secret_manager_regional_secret" if regional else "google_secret_manager_secret",
                          tf_name(one(b, "ciamBindingRole"))], [
        ("#", "metadata only: no secret version (value) enters Terraform state"),
        ("secret_id", path.get("secrets")), *project_of(path),
        *((("location", path["locations"]),) if regional else ())])


def _references(m):
    """Data sources only: Secret Manager secrets, the backup bucket; a comment for the egress the landing zone
    provides."""
    bk, eg = one_role(m, "backup-target"), one_role(m, "pf-egress")
    return (*(_secret(b) for b in of_class(m, "ciamSecretRef")
              if (one(b, "ciamRefUri") or "").startswith("gcp-sm://")),
            *((block("data", ["google_storage_bucket", "ds_backups"],
                     [("name", one(bk, "ciamStorageRef").split("://", 1)[1].split("/", 1)[0])]),)
              if bk and (one(bk, "ciamStorageRef") or "").startswith("gs://") else ()),
            *((f"# Egress '{rdn_value(eg)}': Cloud NAT {one(eg, 'ciamProviderRef')} (landing zone; not managed here)",)
              if eg and one(eg, "ciamProviderRef") else ()))


def render(m, services):
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    kms, identities = secret(m, "disk-encryption"), workload_identities(m, ACCESS)
    out = (*_network(m), *_firewall(m), *chain.from_iterable(identity(m, w) for w in identities),
           *(_instance(m, s, kms, identities) for s in m.servers),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *records(m.d, m), *forwarding_zones(m), *_references(m))
    main = header(m, "Google Cloud infrastructure for the CIAM platform", HCL) + unbound_comments(m.unbound) + "\n" \
        + "\n\n".join(out) + "\n"
    providers = header(m, "Providers and inputs", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("google", {"source": "hashicorp/google", "version": "~> 8.0"}),)))]),
        block("provider", ["google"], [("project", ref("var.project_id")), ("region", REGION)]),
        block("variable", ["project_id"], [("type", ref("string"))]),
        block("variable", ["region"], [("type", ref("string")), ("default", one(m.cloud, "ciamRegion"))]),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main, **render_landing(m),
            **evaluation_files(m, ACCESS, "Google Cloud")}
