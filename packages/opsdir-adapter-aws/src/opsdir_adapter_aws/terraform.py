"""AWS adapter: render an environment's infrastructure bindings as Terraform (hashicorp/aws ~> 5)."""
import ipaddress
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role, secret, servers_with_role, subnet_of
from opsdir.core.manifest import header
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.core.network import is_private
from opsdir.domains.infrastructure.firewall import rule_purpose
from opsdir_format_terraform.hcl import Block, block, ref, tf_name, unbound_comments


def _network(m):
    net = one_role(m, "network")
    return (block("data", ["aws_vpc", "main"], [("id", one(net, "ciamProviderRef"))]),
            *(block("data", ["aws_subnet", tf_name(rdn_value(s))], [("id", one(s, "ciamProviderRef"))])
              for s in of_class(m, "ciamSubnetBinding")))


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


def _instance(m, s, kms):
    role = one(s, "ciamServerRole")
    key = (("kms_key_id", kms.split("://", 1)[1]) if kms
           else ("#", "UNBOUND: no disk-encryption key binding in this environment"))
    return block("resource", ["aws_instance", tf_name(rdn_value(s))], [
        ("ami", one(s, "ciamImageRef")), ("instance_type", one(s, "ciamInstanceSize")),
        ("subnet_id", ref(f"data.aws_subnet.{tf_name(rdn_value(subnet_of(m, s)))}.id")),
        ("private_ip", one(s, "ciamPrivateIp")),
        ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
        ("root_block_device", Block((("encrypted", True), key))),
        ("tags", {"Name": rdn_value(s), "Role": role, "Hostname": one(s, "ciamHostname"),
                  "Product": one(s, "ciamProductVersion", ""), "ManagedBy": "opsdir"})])


def _subnet_mapping(svc, ip, internal, i, sub):
    in_subnet = internal and ipaddress.ip_address(ip) in ipaddress.ip_network(one(sub, "ciamCidr"))
    eip = not internal and i == 0 and one(svc, "ciamProviderRef")
    return ("subnet_mapping", Block((("subnet_id", ref(f"data.aws_subnet.{tf_name(rdn_value(sub))}.id")),
                                     *((("private_ipv4_address", ip),) if in_subnet else ()),
                                     *((("allocation_id", one(svc, "ciamProviderRef")),) if eip else ()))))


def _listener(m, n, svc, port, targets):
    return (block("resource", ["aws_lb_target_group", f"{n}_{port}"], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}-{port}"), ("port", int(port)),
                ("protocol", "TCP"), ("vpc_id", ref("data.aws_vpc.main.id")), ("target_type", "instance"),
                ("health_check", Block((("protocol", "TCP"),)))]),
            *(block("resource", ["aws_lb_target_group_attachment", f"{n}_{port}_{tf_name(rdn_value(t))}"], [
                ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")),
                ("target_id", ref(f"aws_instance.{tf_name(rdn_value(t))}.id")), ("port", int(port))])
              for t in targets),
            block("resource", ["aws_lb_listener", f"{n}_{port}"], [
                ("load_balancer_arn", ref(f"aws_lb.{n}.arn")), ("port", int(port)), ("protocol", "TCP"),
                ("default_action", Block((("type", "forward"),
                                          ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")))))]))


def _service(m, svc):
    """A stable service name: network load balancer, listeners per port, and its DNS record."""
    n = tf_name(rdn_value(svc))
    ip = one(svc, "ciamFrontendIp")
    internal = is_private(ip)
    targets = servers_with_role(m, one(svc, "ciamTargetRole"))
    subnets = sorted({rdn_value(subnet_of(m, t)): subnet_of(m, t) for t in targets}.items())
    mappings = tuple(_subnet_mapping(svc, ip, internal, i, sub) for i, (_, sub) in enumerate(subnets))
    return (block("resource", ["aws_lb", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("internal", internal),
                ("load_balancer_type", "network"), *mappings,
                ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
            *chain.from_iterable(_listener(m, n, svc, port, targets) for port in values(svc, "ciamPort")),
            block("resource", ["aws_route53_record", n], [
                ("zone_id", one(svc, "ciamDnsZoneRef")), ("name", one(svc, "ciamFqdn")), ("type", "A"),
                ("alias", Block((("name", ref(f"aws_lb.{n}.dns_name")), ("zone_id", ref(f"aws_lb.{n}.zone_id")),
                                 ("evaluate_target_health", True))))]))


def _references(m):
    """Data sources only: secrets, the backup bucket, the egress NAT gateway."""
    bk = one_role(m, "backup-target")
    eg = one_role(m, "pf-egress")
    return (*(block("data", ["aws_secretsmanager_secret", tf_name(one(b, "ciamBindingRole"))],
                    [("arn", one(b, "ciamRefUri").split("://", 1)[1])]) for b in of_class(m, "ciamSecretRef")),
            *((block("data", ["aws_s3_bucket", "ds_backups"],
                     [("bucket", one(bk, "ciamStorageRef").split("://", 1)[1])]),) if bk else ()),
            *((block("data", ["aws_nat_gateway", "pf_egress"], [("id", one(eg, "ciamProviderRef"))]),)
              if eg and one(eg, "ciamProviderRef") else ()))


def render(m, services):
    kms = secret(m, "disk-encryption")
    out = (*_network(m), *_security_groups(m), *(_instance(m, s, kms) for s in m.servers),
           *chain.from_iterable(_service(m, svc) for svc in of_class(m, "ciamServiceName")), *_references(m))
    unbound = unbound_comments(m.unbound)
    main = header(m, "AWS infrastructure for the CIAM platform", HCL) + unbound + "\n" + "\n\n".join(out) + "\n"
    providers = header(m, "Providers", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("aws", {"source": "hashicorp/aws", "version": "~> 5.0"}),)))]),
        block("provider", ["aws"], [("region", one(m.cloud, "ciamRegion"))]),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main}
