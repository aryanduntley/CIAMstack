"""AWS adapter: render an environment's infrastructure bindings as Terraform (hashicorp/aws 6.x). Each workload
principal its servers run as gets an IAM role EC2 may assume, a least-privilege policy from its permissions (the AWS
permission table, opsdir_adapter_aws.access) and an instance profile on those servers."""
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role, recorded, secret, subnet_of
from opsdir.domains.compute.hosts import run_roles
from opsdir.domains.compute.workloads import kubernetes_note, only_on_kubernetes
from opsdir.core.manifest import header
from opsdir.core.notes import note_comment
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.domains.infrastructure.firewall import rule_purpose
from opsdir.domains.access.evaluations import evaluation_files
from opsdir.domains.access.workloads import identity_notes, identity_of, workload_identities
from opsdir.domains.edge.exposure import service_exposure
from opsdir.domains.edge.gateways import front_choice
from opsdir.domains.edge.kubernetes import kubernetes_notes
from opsdir.domains.edge.records import forwarders
from opsdir.domains.edge.resolve import (inspected, inspection_notes, rendered_edges,
                                        service_edge)
from opsdir_format_terraform.hcl import comment, ref, tf_block, tf_name, unbound_comments, written
from opsdir_format_terraform.placing import MAIN, PROVIDERS, carried_files
from opsdir.domains.governance.keepers import scope_folder
from .access import ACCESS
from .audit import audit_notes, render_trails
from .log_agent import log_notes
from .observability import alert_notes, log_group_notes, render_alarms, render_log_groups
from .mtls import mtls_notes, render_trust_stores
from .siem_forwarding import render_siem_forwarding, siem_forwarding_notes
from .siem_pull import render_siem_pull, siem_pull_notes
from .canaries import canary_notes, render_canaries
from .discovery import discovery_notes, render_discovery
from .security import every_region, region_alias, render_security, security_notes
from .suppressions import render_suppressions
from .compute_groups import group_notes, render_groups
from .budgets import BILLING, BILLING_REGION, budget_notes, needs_billing_provider, render_budgets
from .quotas import render_quota_requests
from .cdn import fronted, govcloud_note
from .cfn_types import cloudformation_files
from .dns import RESOLVER_ENDPOINT, forwarder_notes, records, resolver_rules, service_record
from .edge import (US_EAST_1, alb_service, network_lb, servers_backend, shield_note, takeover_note)
from .fluent_bit import fluent_bit_clusters, fluent_bit_notes, render_fluent_bit
from .identities import EC2_TRUST, eks_cluster_data, identity_clusters, notes, pod_trust, role
from .ingress import gateway_front
from .guardrails import guardrail_notes
from .landing import STACK, landing_parts, placed_roots
from .network import network_notes, render_network
from .backups import backup_notes, render_backups
from .account import govcloud, organization_providers, provider_block, required_providers, standard_account
from .volumes import render_snapshot_policies, root_block_device, server_volumes, volume_notes
from .databases import copy_alias, copy_regions, database_notes, render_databases
from .cognito import cognito_notes, render_cognito
from .directory import directory_notes, render_directories
from .storage import kept_buckets, render_object_stores
from .plumbing import network_data, plumbing_notes

WHAT = "AWS infrastructure for the CIAM platform"
TERRAFORM, CLOUDFORMATION = "terraform", "cloudformation"
# The infrastructure-as-code languages an environment's AWS render is written in (Adapter.render_targets; an
# environment chooses with its stack component's ciamRenderTarget, a render with --target aws=...).
TARGETS = ((TERRAFORM, "Terraform for the hashicorp/aws provider (terraform/)"),
           (CLOUDFORMATION, "AWS CloudFormation templates translated from it (cloudformation/), what CloudFormation "
                            "has no form for kept in a Terraform root beside each", False))
DEFAULT_TARGETS = tuple(t[0] for t in TARGETS if len(t) < 3)


def _security_groups(m):
    """One security group per server role run here (its servers' or its compute groups'); ingress rules from the
    firewall bindings."""
    roles = sorted(set(run_roles(m)))
    groups = (tf_block("resource", ["aws_security_group", tf_name(role)], [
        ("name", f"ciam-{rdn_value(m.env)}-{role}"), ("description", f"CIAM {role} ({m.label})"),
        ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]) for role in roles)
    return (*groups, *chain.from_iterable(_ingress_rules(m, fw) for fw in of_class(m, "ciamFirewallRule")))


def _ingress_rules(m, fw):
    if only_on_kubernetes(m, one(fw, "ciamTargetRole")):
        return (comment(note_comment(kubernetes_note(m, f"firewall rule `{rdn_value(fw)}`", one(fw, "ciamTargetRole"),
                                                     fw.dn))),)
    why = rule_purpose(m, fw)
    return tuple(tf_block("resource", ["aws_vpc_security_group_ingress_rule", tf_name(f"{rdn_value(fw)}_{i}_{port}")], [
        ("security_group_id", ref(f"aws_security_group.{tf_name(one(fw, 'ciamTargetRole'))}.id")),
        ("cidr_ipv4", cidr), ("from_port", int(port)), ("to_port", int(port)),
        ("ip_protocol", one(fw, "ciamProtocol", "tcp")), ("description", f"{why} ({rdn_value(fw)})")])
        for i, cidr in enumerate(values(fw, "ciamSourceCidr")) for port in values(fw, "ciamPort"))


def _identity(m, w):
    """A workload principal's IAM role (assumed by EC2 when its servers run here, and by the Kubernetes service
    accounts its workloads run as through their cluster's OIDC provider), its least-privilege policy and, for servers,
    its instance profile."""
    n = tf_name(w.identity_role)
    trust, unbound = pod_trust(w) if w.pods else (None, ())
    profile = (tf_block("resource", ["aws_iam_instance_profile", n], [("name", w.name),
                                                                      ("role", ref(f"aws_iam_role.{n}.name"))]),)
    return (*notes(w), *unbound, *((trust,) if trust else ()),
            *role(m, w, ref(f"data.aws_iam_policy_document.{n}_trust.json") if trust else EC2_TRUST),
            *(profile if w.servers else ()))


def _instance(m, s, kms, identities=()):
    role = one(s, "ciamServerRole")
    w = identity_of(identities, role)
    return tf_block("resource", ["aws_instance", tf_name(rdn_value(s))], [
        ("ami", recorded(s, "ciamImageRef", "image")), ("instance_type", recorded(s, "ciamInstanceSize", "size")),
        ("subnet_id", ref(f"data.aws_subnet.{tf_name(rdn_value(subnet_of(m, s)))}.id")),
        *((("private_ip", one(s, "ciamPrivateIp")),) if one(s, "ciamPrivateIp") else ()),
        *((("iam_instance_profile", ref(f"aws_iam_instance_profile.{tf_name(w.identity_role)}.name")),) if w else ()),
        ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
        root_block_device(m, s, kms),
        ("tags", {"Name": rdn_value(s), "Role": role, "Hostname": one(s, "ciamHostname"),
                  "Product": one(s, "ciamProductVersion", ""), "ManagedBy": "opsdir"})])


def _service(m, svc, endpoints=()):
    """A stable service name: a network load balancer with listeners per port (an application load balancer when its
    traffic policy terminates TLS at the edge; opsdir_adapter_aws.edge), and its DNS record; for a role run only on
    Kubernetes, the ALB before its cluster's gateway (opsdir_adapter_aws.ingress), else a note; a note when its
    exposure is unknown (the core's edge.gateways.front_choice)."""
    kind, *chosen = front_choice(m, svc)
    if kind == "note":
        return (comment(chosen[0]),)
    if kind == "gateway":
        return gateway_front(m, svc, chosen[0], endpoints)
    targets, found = chosen
    n = tf_name(rdn_value(svc))
    subnets = tuple(sub for _, sub in sorted({rdn_value(s): s for s in found}.items()))
    spec = service_edge(m, svc, endpoints)
    balancer = alb_service(m, svc, spec, servers_backend(svc, targets), subnets) \
        if spec is not None and spec.layer7 else network_lb(m, svc, spec, targets, subnets)
    cdn = spec is not None and spec.cdn
    return (*balancer, *(fronted(m, svc, spec, n) if cdn else service_record(m.d, m, svc, n)))


def _target_groups(m):
    """{server role: the target group ARNs (references) of the service names a load balancer here sends to it}: what
    its compute groups register their instances in."""
    found = {}
    for svc in of_class(m, "ciamServiceName"):
        role = one(svc, "ciamTargetRole")
        if service_exposure(svc) is not None and not only_on_kubernetes(m, role):
            found.setdefault(role, []).extend(ref(f"aws_lb_target_group.{tf_name(rdn_value(svc))}_{port}.arn")
                                              for port in values(svc, "ciamPort"))
    return {role: tuple(arns) for role, arns in found.items()}


def _references(m):
    """Data sources only: secrets, the backup bucket (unless the stack renders it: object stores), the egress NAT
    gateway."""
    bk = one_role(m, "backup-target")
    bk = None if bk is not None and bk.dn in {b.dn for b in kept_buckets(m)} else bk
    eg = one_role(m, "pf-egress")
    return (*(tf_block("data", ["aws_secretsmanager_secret", tf_name(one(b, "ciamBindingRole"))],
                       [("arn", one(b, "ciamRefUri").split("://", 1)[1])]) for b in of_class(m, "ciamSecretRef")),
            *((tf_block("data", ["aws_s3_bucket", "ds_backups"],
                        [("bucket", one(bk, "ciamStorageRef").split("://", 1)[1])]),) if bk else ()),
            *((tf_block("data", ["aws_nat_gateway", "pf_egress"], [("id", one(eg, "ciamProviderRef"))]),)
              if eg and one(eg, "ciamProviderRef") else ()))


def _us_east_1(m):
    """The provider CloudFront's certificates and web ACLs are created through: us-east-1 in the environment's account,
    or in GovCloud (where CloudFront isn't offered) the associated standard account's."""
    if govcloud(m):
        return provider_block(m, "us-east-1", US_EAST_1, "CloudFront isn't offered in GovCloud: its distribution, web "
                              "ACL, Shield protection and certificate are in the associated standard account, in "
                              "us-east-1 (standard AWS credentials)", account=standard_account(m))
    return provider_block(m, "us-east-1", US_EAST_1, "CloudFront's certificates and web ACLs live in us-east-1")


def _fronted(m, endpoints):
    """Whether a CDN fronts any of the environment's service names."""
    return any(spec is not None and spec.cdn
               for spec in (service_edge(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")))


def render_files(m, services):
    """{path: TfFile | text} of environment m's AWS render: the Terraform roots as data (main, providers, the landing
    zone's roots), the scripts and configuration files they package as text."""
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    kms, identities = secret(m, "disk-encryption"), workload_identities(m, ACCESS)
    canaries, scripts = render_canaries(m, endpoints)
    discovery, handlers = render_discovery(m)
    shipping, shipping_files = render_fluent_bit(m, services) if services else ((), {})
    clusters = (*identity_clusters(identities), *(fluent_bit_clusters(m, services) if services else ()))
    out = (*network_data(m), *_security_groups(m), *eks_cluster_data(clusters),
           *chain.from_iterable(_identity(m, w) for w in identities),
           *(_instance(m, s, kms, identities) for s in m.servers),
           *render_groups(m, kms, identities, _target_groups(m)),
           *chain.from_iterable(server_volumes(m, s) for s in m.servers), *render_snapshot_policies(m),
           *render_backups(m),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *render_databases(m), *render_object_stores(m), *records(m.d, m),
           *resolver_rules(m), *render_trails(m), *render_log_groups(m), *render_siem_forwarding(m, services),
           *render_siem_pull(m, services),
           *render_trust_stores(m),
           *(comment(note_comment(n)) for n in (log_notes(m, services) if services else ())), *shipping,
           *(comment(note_comment(n)) for n in (fluent_bit_notes(m, services) if services else ())),
           *render_alarms(m), *canaries,
           *render_security(m),
           *discovery, *render_suppressions(m),
           *render_budgets(m), *render_quota_requests(m),
           *_references(m), *render_cognito(m), *render_directories(m))
    providers = (
        required_providers(bool(scripts) or bool(handlers)),
        provider_block(m),
        *((_us_east_1(m),) if _fronted(m, endpoints) and (standard_account(m) or not govcloud(m)) else ()),
        *(provider_block(m, r, copy_alias(r), f"Copies of databases' automated backups in {r}")
          for r in copy_regions(m)),
        *((provider_block(m, BILLING_REGION, BILLING, "GovCloud's billing (AWS Budgets) is managed in its associated "
                          "standard account", account=standard_account(m)),) if needs_billing_provider(m) else ()),
        *organization_providers(m, every_region(m)),
        *(provider_block(m, r, region_alias(r), f"Security services in {r}") for r in every_region(m)),
        *((tf_block("variable", [RESOLVER_ENDPOINT], [
            ("description", "The landing zone's outbound Route 53 Resolver endpoint the forwarding rules use"),
            ("type", ref("string"))]),) if forwarders(m, hosted=False) else ()))
    landing, landing_dns = landing_parts(m)
    roots = placed_roots(m, ((PROVIDERS, providers), (MAIN, out), *landing), landing_dns, lambda name: (
        header(m, WHAT, HCL) + unbound_comments(m.unbound) if name == MAIN else header(m, "Providers", HCL)))
    carried = carried_files(roots, {**scripts, **handlers}, STACK)
    if scope_folder(m) is not None:                 # a slice: its root and the files it reads, nothing of the stack's
        return {**roots, **carried}
    return {**roots, **scripts, **handlers, **carried, **shipping_files, **evaluation_files(m, ACCESS, "AWS")}


def render(m, services, targets=DEFAULT_TARGETS):
    """Adapter render: environment m's AWS files as text in the render targets chosen: Terraform (terraform/), and/or
    CloudFormation translated from it (cloudformation/, cfn_types); the files that are neither (access scripts,
    Kubernetes configuration) either way. Each Terraform file written once from its TfFile."""
    files = render_files(m, services)
    terraform = {p: v for p, v in files.items() if p.startswith("terraform/")}
    native = cloudformation_files(m, files, WHAT) if CLOUDFORMATION in targets else {}
    return written({**{p: v for p, v in files.items() if p not in terraform},
                    **(terraform if TERRAFORM in targets else {}), **native})


def edge_notes(m, endpoints):
    """The render notes of environment m's service names' edges, each once: passthrough load balancers asked to
    inspect requests (core edge.resolve inspection_notes), web ACLs' account takeover protection (edge.takeover_note:
    on an ALB the policy doesn't put behind a CDN, or a CloudFront distribution) and Shield Advanced protection's
    subscription (edge.shield_note: the standard account's for CloudFront in GovCloud); nothing for CloudFront in
    GovCloud without a recorded standard account (neither is rendered)."""
    edges = tuple((spec, gw) for _, spec, gw in rendered_edges(m, endpoints) if spec is not None and not (
        spec.cdn and govcloud(m) and not standard_account(m)))
    acls = tuple(spec for spec, gw in edges if inspected(spec) and (gw is not None or spec.layer7 or spec.cdn))
    return tuple(dict.fromkeys((
        *inspection_notes(m, endpoints), *(n for n in (takeover_note(spec) for spec in acls) if n is not None),
        *(shield_note("the standard account's" if spec.cdn and govcloud(m) else "the account's")
          for spec, _ in edges if spec.ddos != "standard"))))


def render_notes(m, services):
    """Adapter notes (core.notes, flow 43): what environment m's AWS render leaves out or to a person, as data, each
    written as its comment: the canaries it doesn't render, then its security services', audit trails', data
    discovery's, guardrails', alert rules', log destinations', identities' (core access.workloads) and Kubernetes-only
    roles' (core edge.kubernetes) notes, the network depth's and the landing zone plumbing's, and log shipping's
    (servers, Fluent Bit)."""
    return (*canary_notes(m, services.endpoints if services else ()), *security_notes(m), *audit_notes(m),
            *discovery_notes(m), *guardrail_notes(m), *alert_notes(m), *log_group_notes(m),
            *identity_notes(m, ACCESS), *kubernetes_notes(m), *budget_notes(m), *forwarder_notes(m),
            *database_notes(m), *cognito_notes(m), *directory_notes(m), *backup_notes(m), *volume_notes(m),
            *group_notes(m),
            *edge_notes(m, services.endpoints if services else ()),
            *network_notes(m, services.endpoints if services else ()), *plumbing_notes(m),
            *((govcloud_note(m),) if govcloud(m) and _fronted(m, services.endpoints if services else ()) else ()),
            *((*log_notes(m, services), *fluent_bit_notes(m, services), *siem_forwarding_notes(m, services),
               *siem_pull_notes(m, services))
              if services else ()), *mtls_notes(m))
