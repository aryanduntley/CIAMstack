"""Azure adapter: render an environment's infrastructure bindings as Terraform (hashicorp/azurerm ~> 4)."""
from functools import reduce
from itertools import chain

from opsdir.core.directory import follow, one, rdn_value, values
from opsdir.core.environment import of_class, one_role, servers_with_role, subnet_of
from opsdir.core.manifest import header
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.core.network import is_private
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

RG = ref("data.azurerm_resource_group.main.name")
LOC = ref("data.azurerm_resource_group.main.location")


def _record_name(fqdn, zone):
    return fqdn[: -len(zone) - 1] if fqdn.endswith("." + zone) else None


def _network(m):
    net = one_role(m, "network")
    return (block("data", ["azurerm_resource_group", "main"], [("name", one(net, "ciamResourceGroup"))]),
            block("data", ["azurerm_virtual_network", "main"],
                  [("name", one(net, "ciamProviderRef")), ("resource_group_name", RG)]),
            *(_subnet(s) for s in of_class(m, "ciamSubnetBinding")))


def _subnet(s):
    vnet, sub = one(s, "ciamProviderRef").split("/", 1)
    return block("data", ["azurerm_subnet", tf_name(rdn_value(s))], [
        ("name", sub), ("virtual_network_name", vnet), ("resource_group_name", RG)])


def _rule_priorities(rules):
    """NSG priorities are pinned in the directory (ciamRulePriority) so adding a rule never renumbers
    existing ones. Unpinned rules get the next free slot, in rule order. Returns {dn: (priority, pinned)}."""
    pinned = frozenset(int(one(f, "ciamRulePriority")) for f in rules if one(f, "ciamRulePriority"))

    def assign(acc, fw):
        assigned, used = acc
        if one(fw, "ciamRulePriority"):
            return {**assigned, fw.dn: (int(one(fw, "ciamRulePriority")), True)}, used
        prio = next(p for p in range(100, 4097, 10) if p not in used)
        return {**assigned, fw.dn: (prio, False)}, used | {prio}

    return reduce(assign, rules, ({}, pinned))[0]


def _security_rule(m, fw, prio, pinned):
    consumer = follow(m.d, fw, "ciamAllowsConsumer")
    why = f"consumer {rdn_value(consumer)}" if consumer else one(fw, "ciamBindingRole")
    note = () if pinned else (
        f"# NOTE: {rdn_value(fw)} has no pinned ciamRulePriority; assigned {prio}. Pin it in the directory.",)
    return (*note, block("resource", ["azurerm_network_security_rule", tf_name(rdn_value(fw))], [
        ("name", rdn_value(fw)), ("description", why), ("priority", prio), ("direction", "Inbound"),
        ("access", "Allow"), ("protocol", one(fw, "ciamProtocol", "tcp").capitalize()),
        ("source_port_range", "*"),
        ("destination_port_ranges", values(fw, "ciamPort")),
        ("source_address_prefixes", values(fw, "ciamSourceCidr")),
        ("destination_address_prefix", "*"), ("resource_group_name", RG),
        ("network_security_group_name",
         ref(f"azurerm_network_security_group.{tf_name(one(fw, 'ciamTargetRole'))}.name"))]))


def _security_groups(m):
    """One network security group per server role; rules from the firewall bindings."""
    roles = sorted({one(s, "ciamServerRole") for s in m.servers})
    rules = of_class(m, "ciamFirewallRule")
    prios = _rule_priorities(rules)
    return (*(block("resource", ["azurerm_network_security_group", tf_name(role)], [
                ("name", f"nsg-ciam-{rdn_value(m.env)}-{role}"), ("location", LOC), ("resource_group_name", RG),
                ("tags", {"ManagedBy": "opsdir"})]) for role in roles),
            *chain.from_iterable(_security_rule(m, fw, *prios[fw.dn]) for fw in rules))


def _server(m, s, des):
    n, role = tf_name(rdn_value(s)), one(s, "ciamServerRole")
    encryption = (("disk_encryption_set_id", one(des, "ciamProviderRef")) if des and one(des, "ciamProviderRef")
                  else ("#", "UNBOUND: no disk-encryption binding in this environment"))
    return (block("resource", ["azurerm_network_interface", n], [
                ("name", f"nic-{rdn_value(s)}"), ("location", LOC), ("resource_group_name", RG),
                ("ip_configuration", Block((
                    ("name", "primary"),
                    ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet_of(m, s)))}.id")),
                    ("private_ip_address_allocation", "Static"), ("private_ip_address", one(s, "ciamPrivateIp")))))]),
            block("resource", ["azurerm_network_interface_security_group_association", n], [
                ("network_interface_id", ref(f"azurerm_network_interface.{n}.id")),
                ("network_security_group_id", ref(f"azurerm_network_security_group.{tf_name(role)}.id"))]),
            block("resource", ["azurerm_linux_virtual_machine", n], [
                ("name", rdn_value(s)), ("computer_name", one(s, "ciamHostname").split(".")[0]),
                ("resource_group_name", RG), ("location", LOC), ("size", one(s, "ciamInstanceSize")),
                ("zone", one(s, "ciamZone")), ("admin_username", "ciamadmin"),
                ("network_interface_ids", [ref(f"azurerm_network_interface.{n}.id")]),
                ("source_image_id", one(s, "ciamImageRef")),
                ("admin_ssh_key", Block((("username", "ciamadmin"), ("public_key", ref("var.admin_ssh_public_key"))))),
                ("os_disk", Block((("caching", "ReadWrite"), ("storage_account_type", "Premium_LRS"), encryption))),
                ("tags", {"Role": role, "Hostname": one(s, "ciamHostname"),
                          "Product": one(s, "ciamProductVersion", ""), "ManagedBy": "opsdir"})]))


def _frontend(m, svc, n, ip, internal, targets):
    """(data sources needed, frontend_ip_configuration body)"""
    if internal:
        return (), (("name", "frontend"), ("zones", ["1", "2", "3"]),
                    ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet_of(m, targets[0])))}.id")),
                    ("private_ip_address_allocation", "Static"), ("private_ip_address", ip))
    return ((block("data", ["azurerm_public_ip", n], [("name", one(svc, "ciamProviderRef")),
                                                       ("resource_group_name", RG)]),),
            (("name", "frontend"), ("public_ip_address_id", ref(f"data.azurerm_public_ip.{n}.id"))))


def _lb_port(n, port):
    return (block("resource", ["azurerm_lb_probe", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")),
                ("protocol", "Tcp"), ("port", int(port))]),
            block("resource", ["azurerm_lb_rule", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")), ("protocol", "Tcp"),
                ("frontend_port", int(port)), ("backend_port", int(port)),
                ("frontend_ip_configuration_name", "frontend"),
                ("backend_address_pool_ids", [ref(f"azurerm_lb_backend_address_pool.{n}.id")]),
                ("probe_id", ref(f"azurerm_lb_probe.{n}_{port}.id"))]))


def _service(m, svc):
    """A stable service name: load balancer, backend pool, probes and rules per port, and its DNS record."""
    n = tf_name(rdn_value(svc))
    ip = one(svc, "ciamFrontendIp")
    internal = is_private(ip)
    targets = servers_with_role(m, one(svc, "ciamTargetRole"))
    data, fe = _frontend(m, svc, n, ip, internal, targets)
    zone = one(svc, "ciamDnsZone")
    rtype = "azurerm_private_dns_a_record" if internal else "azurerm_dns_a_record"
    return (*data,
            block("resource", ["azurerm_lb", n], [
                ("name", f"lb-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("location", LOC),
                ("resource_group_name", RG), ("sku", "Standard"), ("frontend_ip_configuration", Block(fe)),
                ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
            block("resource", ["azurerm_lb_backend_address_pool", n], [
                ("name", "servers"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id"))]),
            *(block("resource", ["azurerm_network_interface_backend_address_pool_association",
                                 f"{n}_{tf_name(rdn_value(t))}"], [
                ("network_interface_id", ref(f"azurerm_network_interface.{tf_name(rdn_value(t))}.id")),
                ("ip_configuration_name", "primary"),
                ("backend_address_pool_id", ref(f"azurerm_lb_backend_address_pool.{n}.id"))]) for t in targets),
            *chain.from_iterable(_lb_port(n, port) for port in values(svc, "ciamPort")),
            block("resource", [rtype, n], [
                ("name", _record_name(one(svc, "ciamFqdn"), zone)), ("zone_name", zone), ("resource_group_name", RG),
                ("ttl", 300), ("records", [ip])]))


def _key_vault_secrets(m):
    """Each Key Vault once (in order of first use) and a check that it holds the environment's secrets. The check reads
    the vault's secret names (azurerm_key_vault_secrets), never a secret: azurerm_key_vault_secret would copy each value
    into Terraform state. A missing secret fails the plan (a postcondition), naming its role."""
    refs = tuple((*one(b, "ciamRefUri").split("://", 1)[1].split("/", 1), one(b, "ciamBindingRole"))
                 for b in of_class(m, "ciamSecretRef"))
    vaults = dict.fromkeys(vault for vault, _, _ in refs)
    return tuple(chain.from_iterable(
        (block("data", ["azurerm_key_vault", tf_name(vault)], [("name", vault), ("resource_group_name", RG)]),
         block("data", ["azurerm_key_vault_secrets", tf_name(vault)], [
             ("#", "names only: no secret value enters Terraform state"),
             ("key_vault_id", ref(f"data.azurerm_key_vault.{tf_name(vault)}.id")),
             ("lifecycle", Block(tuple(("postcondition", Block((
                 ("condition", ref(f'contains(self.names, "{name}")')),
                 ("error_message", f"Key Vault {vault} has no secret {name} (role {role})"))))
                 for v, name, role in refs if v == vault)))]))
        for vault in vaults))


def _interconnect_note(m, ic):
    peer = follow(m.d, ic, "ciamPeerEnvironment")
    return (f"# Interconnect '{rdn_value(ic)}' to {peer.dn}: {one(ic, 'ciamInterconnectKind')}. "
            "Provided by the landing zone; not managed here.")


def render(m, services):
    des = one_role(m, "disk-encryption")
    out = (*_network(m), *_security_groups(m), *chain.from_iterable(_server(m, s, des) for s in m.servers),
           *chain.from_iterable(_service(m, svc) for svc in of_class(m, "ciamServiceName")),
           *_key_vault_secrets(m))
    notes = "\n".join(_interconnect_note(m, ic) for ic in of_class(m, "ciamInterconnect"))
    unbound = "".join(f"# UNBOUND: required role '{r}' has no binding in this environment\n" for r in m.unbound)
    main = header(m, "Azure infrastructure for the CIAM platform", HCL) + unbound + notes + "\n\n" \
        + "\n\n".join(out) + "\n"
    gov = (("environment", "usgovernment"),) if one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else ()
    providers = header(m, "Providers and inputs", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("azurerm", {"source": "hashicorp/azurerm", "version": "~> 4.0"}),)))]),
        block("provider", ["azurerm"], [("features", Block(())), ("subscription_id", ref("var.subscription_id")),
                                        *gov]),
        block("variable", ["subscription_id"], [("type", ref("string"))]),
        block("variable", ["admin_ssh_public_key"], [("type", ref("string"))]),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main}
