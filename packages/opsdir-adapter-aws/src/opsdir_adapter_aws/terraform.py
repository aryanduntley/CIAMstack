"""AWS adapter: render an environment's infrastructure bindings as Terraform (hashicorp/aws ~> 5). Each workload
principal its servers run as gets an IAM role EC2 may assume, a least-privilege policy from its permissions (the AWS
permission table, opsdir_adapter_aws.access) and an instance profile on those servers."""
import ipaddress
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role, secret, servers_with_role, subnet_of
from opsdir.core.manifest import header
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.core.network import is_private
from opsdir.domains.infrastructure.firewall import rule_purpose
from opsdir.domains.access.evaluations import evaluation_files
from opsdir.domains.access.workloads import identity_of, workload_identities
from opsdir.domains.edge.records import forwarders
from opsdir.domains.edge.resolve import inspected, service_edge
from opsdir_format_terraform.hcl import Block, block, ref, tf_name, unbound_comments
from .access import ACCESS
from .audit import render_trails
from .security import render_security
from .suppressions import render_suppressions
from .budgets import BILLING, BILLING_REGION, billing_account, needs_billing_provider, render_budgets
from .quotas import render_quota_requests
from .cdn import alias, distribution
from .dns import RESOLVER_ENDPOINT, records, resolver_rules, service_record
from .edge import US_EAST_1, alb_service, health_check, shield, stickiness
from .identities import EC2_TRUST, notes, role
from .landing import render_landing
from .network import render_network
from .backups import render_backups
from .account import provider_block
from .volumes import render_snapshot_policies, root_block_device, server_volumes
from .databases import copy_alias, copy_regions, render_databases
from .storage import kept_buckets, render_object_stores
from .plumbing import network_data


def _security_groups(m):
    """One security group per server role; ingress rules from the firewall bindings."""
    roles = sorted({one(s, "ciamServerRole") for s in m.servers})
    groups = (block("resource", ["aws_security_group", tf_name(role)], [
        ("name", f"ciam-{rdn_value(m.env)}-{role}"), ("description", f"CIAM {role} ({m.label})"),
        ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]) for role in roles)
    return (*groups, *chain.from_iterable(_ingress_rules(m, fw) for fw in of_class(m, "ciamFirewallRule")))


def _ingress_rules(m, fw):
    why = rule_purpose(m, fw)
    return tuple(block("resource", ["aws_vpc_security_group_ingress_rule", tf_name(f"{rdn_value(fw)}_{i}_{port}")], [
        ("security_group_id", ref(f"aws_security_group.{tf_name(one(fw, 'ciamTargetRole'))}.id")),
        ("cidr_ipv4", cidr), ("from_port", int(port)), ("to_port", int(port)),
        ("ip_protocol", one(fw, "ciamProtocol", "tcp")), ("description", f"{why} ({rdn_value(fw)})")])
        for i, cidr in enumerate(values(fw, "ciamSourceCidr")) for port in values(fw, "ciamPort"))


def _identity(m, w):
    """A workload principal's IAM role EC2 may assume, its least-privilege policy and its instance profile."""
    n = tf_name(w.identity_role)
    return (*notes(w), *role(m, w, EC2_TRUST),
            block("resource", ["aws_iam_instance_profile", n], [("name", w.name),
                                                                 ("role", ref(f"aws_iam_role.{n}.name"))]))


def _instance(m, s, kms, identities=()):
    role = one(s, "ciamServerRole")
    w = identity_of(identities, role)
    return block("resource", ["aws_instance", tf_name(rdn_value(s))], [
        ("ami", one(s, "ciamImageRef")), ("instance_type", one(s, "ciamInstanceSize")),
        ("subnet_id", ref(f"data.aws_subnet.{tf_name(rdn_value(subnet_of(m, s)))}.id")),
        ("private_ip", one(s, "ciamPrivateIp")),
        *((("iam_instance_profile", ref(f"aws_iam_instance_profile.{tf_name(w.identity_role)}.name")),) if w else ()),
        ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
        root_block_device(m, s, kms),
        ("tags", {"Name": rdn_value(s), "Role": role, "Hostname": one(s, "ciamHostname"),
                  "Product": one(s, "ciamProductVersion", ""), "ManagedBy": "opsdir"})])


def _subnet_mapping(svc, ip, internal, i, sub):
    in_subnet = internal and ipaddress.ip_address(ip) in ipaddress.ip_network(one(sub, "ciamCidr"))
    eip = not internal and i == 0 and one(svc, "ciamProviderRef")
    return ("subnet_mapping", Block((("subnet_id", ref(f"data.aws_subnet.{tf_name(rdn_value(sub))}.id")),
                                     *((("private_ipv4_address", ip),) if in_subnet else ()),
                                     *((("allocation_id", one(svc, "ciamProviderRef")),) if eip else ()))))


def _listener(m, n, svc, port, targets, spec=None):
    tuning = ((*((("deregistration_delay", spec.drain),) if spec.drain is not None else ()),
               health_check(spec, False), *stickiness(spec, False)) if spec
              else (("health_check", Block((("protocol", "TCP"),))),))
    return (block("resource", ["aws_lb_target_group", f"{n}_{port}"], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}-{port}"), ("port", int(port)),
                ("protocol", "TCP"), ("vpc_id", ref("data.aws_vpc.main.id")), ("target_type", "instance"),
                *tuning]),
            *(block("resource", ["aws_lb_target_group_attachment", f"{n}_{port}_{tf_name(rdn_value(t))}"], [
                ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")),
                ("target_id", ref(f"aws_instance.{tf_name(rdn_value(t))}.id")), ("port", int(port))])
              for t in targets),
            block("resource", ["aws_lb_listener", f"{n}_{port}"], [
                ("load_balancer_arn", ref(f"aws_lb.{n}.arn")), ("port", int(port)), ("protocol", "TCP"),
                ("default_action", Block((("type", "forward"),
                                          ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")))))]))


def _service(m, svc, endpoints=()):
    """A stable service name: a network load balancer with listeners per port (an application load balancer when its
    traffic policy terminates TLS at the edge; opsdir_adapter_aws.edge), and its DNS record."""
    n = tf_name(rdn_value(svc))
    ip = one(svc, "ciamFrontendIp")
    internal = is_private(ip)
    targets = servers_with_role(m, one(svc, "ciamTargetRole"))
    subnets = sorted({rdn_value(subnet_of(m, t)): subnet_of(m, t) for t in targets}.items())
    spec = service_edge(m, svc, endpoints)
    if spec is not None and spec.layer7:
        balancer = alb_service(m, svc, spec, targets, tuple(sub for _, sub in subnets))
    else:
        mappings = tuple(_subnet_mapping(svc, ip, internal, i, sub) for i, (_, sub) in enumerate(subnets))
        blind = (("#", "the protection policy's request inspection needs TLS terminated at the edge; not rendered"),) \
            if spec is not None and inspected(spec) and not spec.cdn else ()
        balancer = (block("resource", ["aws_lb", n], [
                        *blind, ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("internal", internal),
                        ("load_balancer_type", "network"), *mappings,
                        ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
                    *chain.from_iterable(_listener(m, n, svc, port, targets, spec) for port in values(svc, "ciamPort")),
                    *(shield(n, spec, f"aws_lb.{n}.arn") if spec is not None and not spec.cdn else ()))
    cdn = spec is not None and spec.cdn
    return (*balancer, *(distribution(m, svc, spec, n) if cdn else ()),
            *service_record(m.d, m, svc, n, alias(n) if cdn else None))


def _references(m):
    """Data sources only: secrets, the backup bucket (unless the stack renders it: object stores), the egress NAT
    gateway."""
    bk = one_role(m, "backup-target")
    bk = None if bk is not None and bk.dn in {b.dn for b in kept_buckets(m)} else bk
    eg = one_role(m, "pf-egress")
    return (*(block("data", ["aws_secretsmanager_secret", tf_name(one(b, "ciamBindingRole"))],
                    [("arn", one(b, "ciamRefUri").split("://", 1)[1])]) for b in of_class(m, "ciamSecretRef")),
            *((block("data", ["aws_s3_bucket", "ds_backups"],
                     [("bucket", one(bk, "ciamStorageRef").split("://", 1)[1])]),) if bk else ()),
            *((block("data", ["aws_nat_gateway", "pf_egress"], [("id", one(eg, "ciamProviderRef"))]),)
              if eg and one(eg, "ciamProviderRef") else ()))


def _fronted(m, endpoints):
    """Whether a CDN fronts any of the environment's service names."""
    return any(spec is not None and spec.cdn
               for spec in (service_edge(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")))


def render(m, services):
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    kms, identities = secret(m, "disk-encryption"), workload_identities(m, ACCESS)
    out = (*network_data(m), *_security_groups(m), *chain.from_iterable(_identity(m, w) for w in identities),
           *(_instance(m, s, kms, identities) for s in m.servers),
           *chain.from_iterable(server_volumes(m, s) for s in m.servers), *render_snapshot_policies(m),
           *render_backups(m),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *render_databases(m), *render_object_stores(m), *records(m.d, m),
           *resolver_rules(m), *render_trails(m), *render_security(m), *render_suppressions(m), *render_budgets(m), *render_quota_requests(m),
           *_references(m))
    unbound = unbound_comments(m.unbound)
    main = header(m, "AWS infrastructure for the CIAM platform", HCL) + unbound + "\n" + "\n\n".join(out) + "\n"
    providers = header(m, "Providers", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("aws", {"source": "hashicorp/aws", "version": "~> 5.0"}),)))]),
        provider_block(m),
        *((provider_block(m, "us-east-1", US_EAST_1, "CloudFront's certificates and web ACLs live in us-east-1"),)
          if _fronted(m, endpoints) else ()),
        *(provider_block(m, r, copy_alias(r), f"Copies of databases' automated backups in {r}")
          for r in copy_regions(m)),
        *((provider_block(m, BILLING_REGION, BILLING, "GovCloud's billing (AWS Budgets) is managed in its associated "
                          "standard account", account=billing_account(m)),) if needs_billing_provider(m) else ()),
        *((block("variable", [RESOLVER_ENDPOINT], [
            ("description", "The landing zone's outbound Route 53 Resolver endpoint the forwarding rules use"),
            ("type", ref("string"))]),) if forwarders(m) else ()),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main, **render_landing(m),
            **evaluation_files(m, ACCESS, "AWS")}
