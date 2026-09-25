"""Render an AWS environment as Terraform (hashicorp/aws ~> 5)."""
import ipaddress

from .model import Block, block, header, is_private, ref, tf_name


def render(m):
    d = m.d
    out = []
    net = m.one_role("network")

    out.append(block("data", ["aws_vpc", "main"], [("id", net.one("ciamProviderRef"))]))
    for s in m.of_class("ciamSubnetBinding"):
        out.append(block("data", ["aws_subnet", tf_name(s.name)], [("id", s.one("ciamProviderRef"))]))

    # security groups per server role, ingress rules from firewall bindings
    roles = sorted({s.one("ciamServerRole") for s in m.servers})
    for role in roles:
        out.append(block("resource", ["aws_security_group", tf_name(role)], [
            ("name", f"ciam-{m.env.name}-{role}"), ("description", f"CIAM {role} ({m.label})"),
            ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]))
    for fw in m.of_class("ciamFirewallRule"):
        consumer = d.ref(fw, "ciamAllowsConsumer")
        why = f"consumer {consumer.name}" if consumer else fw.one("ciamBindingRole")
        for i, cidr in enumerate(fw.all("ciamSourceCidr")):
            for port in fw.all("ciamPort"):
                out.append(block("resource", ["aws_vpc_security_group_ingress_rule",
                                              tf_name(f"{fw.name}_{i}_{port}")], [
                    ("security_group_id", ref(f"aws_security_group.{tf_name(fw.one('ciamTargetRole'))}.id")),
                    ("cidr_ipv4", cidr), ("from_port", int(port)), ("to_port", int(port)),
                    ("ip_protocol", fw.one("ciamProtocol", "tcp")), ("description", f"{why} ({fw.name})")]))

    kms = m.secret("disk-encryption")
    for s in m.servers:
        role = s.one("ciamServerRole")
        root = [("encrypted", True)]
        if kms:
            root.append(("kms_key_id", kms.split("://", 1)[1]))
        else:
            root.append(("#", "UNBOUND: no disk-encryption key binding in this environment"))
        out.append(block("resource", ["aws_instance", tf_name(s.name)], [
            ("ami", s.one("ciamImageRef")), ("instance_type", s.one("ciamInstanceSize")),
            ("subnet_id", ref(f"data.aws_subnet.{tf_name(m.subnet_of(s).name)}.id")),
            ("private_ip", s.one("ciamPrivateIp")),
            ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
            ("root_block_device", Block("root_block_device", root)),
            ("tags", {"Name": s.name, "Role": role, "Hostname": s.one("ciamHostname"),
                      "Product": s.one("ciamProductVersion", ""), "ManagedBy": "opsdir"})]))

    # stable service names: load balancer + DNS
    for svc in m.of_class("ciamServiceName"):
        n = tf_name(svc.name)
        ip = svc.one("ciamFrontendIp")
        internal = is_private(ip)
        targets = m.servers_with_role(svc.one("ciamTargetRole"))
        subnets = sorted({m.subnet_of(t).name: m.subnet_of(t) for t in targets}.items())
        mappings = []
        for i, (sn, sub) in enumerate(subnets):
            body = [("subnet_id", ref(f"data.aws_subnet.{tf_name(sn)}.id"))]
            if internal and ipaddress.ip_address(ip) in ipaddress.ip_network(sub.one("ciamCidr")):
                body.append(("private_ipv4_address", ip))
            if not internal and i == 0 and svc.one("ciamProviderRef"):
                body.append(("allocation_id", svc.one("ciamProviderRef")))
            mappings.append(("subnet_mapping", Block("subnet_mapping", body)))
        out.append(block("resource", ["aws_lb", n], [
            ("name", f"ciam-{m.env.name}-{svc.name}"), ("internal", internal), ("load_balancer_type", "network"),
            *mappings, ("tags", {"Service": svc.one("ciamFqdn"), "ManagedBy": "opsdir"})]))
        for port in svc.all("ciamPort"):
            out.append(block("resource", ["aws_lb_target_group", f"{n}_{port}"], [
                ("name", f"ciam-{m.env.name}-{svc.name}-{port}"), ("port", int(port)), ("protocol", "TCP"),
                ("vpc_id", ref("data.aws_vpc.main.id")), ("target_type", "instance"),
                ("health_check", Block("health_check", [("protocol", "TCP")]))]))
            for t in targets:
                out.append(block("resource", ["aws_lb_target_group_attachment", f"{n}_{port}_{tf_name(t.name)}"], [
                    ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")),
                    ("target_id", ref(f"aws_instance.{tf_name(t.name)}.id")), ("port", int(port))]))
            out.append(block("resource", ["aws_lb_listener", f"{n}_{port}"], [
                ("load_balancer_arn", ref(f"aws_lb.{n}.arn")), ("port", int(port)), ("protocol", "TCP"),
                ("default_action", Block("default_action", [
                    ("type", "forward"), ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn"))]))]))
        out.append(block("resource", ["aws_route53_record", n], [
            ("zone_id", svc.one("ciamDnsZoneRef")), ("name", svc.one("ciamFqdn")), ("type", "A"),
            ("alias", Block("alias", [("name", ref(f"aws_lb.{n}.dns_name")),
                                      ("zone_id", ref(f"aws_lb.{n}.zone_id")),
                                      ("evaluate_target_health", True)]))]))

    # references only: secrets, backups, egress
    for b in m.of_class("ciamSecretRef"):
        out.append(block("data", ["aws_secretsmanager_secret", tf_name(b.one("ciamBindingRole"))],
                         [("arn", b.one("ciamRefUri").split("://", 1)[1])]))
    bk = m.one_role("backup-target")
    if bk:
        out.append(block("data", ["aws_s3_bucket", "ds_backups"],
                         [("bucket", bk.one("ciamStorageRef").split("://", 1)[1])]))
    eg = m.one_role("pf-egress")
    if eg and eg.one("ciamProviderRef"):
        out.append(block("data", ["aws_nat_gateway", "pf_egress"], [("id", eg.one("ciamProviderRef"))]))

    unbound = "".join(f"# UNBOUND: required role '{r}' has no binding in this environment\n" for r in m.unbound)
    main = header(m, "AWS infrastructure for the CIAM platform") + unbound + "\n" + "\n\n".join(out) + "\n"
    providers = header(m, "Providers") + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block("required_providers", [
            ("aws", {"source": "hashicorp/aws", "version": "~> 5.0"})]))]),
        block("provider", ["aws"], [("region", m.cloud.one("ciamRegion"))]),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main}
