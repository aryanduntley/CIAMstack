"""Render an Azure environment as Terraform (hashicorp/azurerm ~> 4)."""
from .model import Block, block, header, is_private, ref, tf_name


def _record_name(fqdn, zone):
    return fqdn[: -len(zone) - 1] if fqdn.endswith("." + zone) else None


def render(m):
    d = m.d
    out = []
    net = m.one_role("network")
    rg = net.one("ciamResourceGroup")
    RG = ref("data.azurerm_resource_group.main.name")
    LOC = ref("data.azurerm_resource_group.main.location")

    out.append(block("data", ["azurerm_resource_group", "main"], [("name", rg)]))
    out.append(block("data", ["azurerm_virtual_network", "main"],
                     [("name", net.one("ciamProviderRef")), ("resource_group_name", RG)]))
    for s in m.of_class("ciamSubnetBinding"):
        vnet, sub = s.one("ciamProviderRef").split("/", 1)
        out.append(block("data", ["azurerm_subnet", tf_name(s.name)], [
            ("name", sub), ("virtual_network_name", vnet), ("resource_group_name", RG)]))

    # network security groups per server role, rules from firewall bindings
    roles = sorted({s.one("ciamServerRole") for s in m.servers})
    for role in roles:
        out.append(block("resource", ["azurerm_network_security_group", tf_name(role)], [
            ("name", f"nsg-ciam-{m.env.name}-{role}"), ("location", LOC), ("resource_group_name", RG),
            ("tags", {"ManagedBy": "opsdir"})]))
    # NSG priorities are pinned in the directory (ciamRulePriority) so adding a rule never renumbers
    # existing ones. Unpinned rules get the next free slot and a note asking to pin them.
    used = {int(f.one("ciamRulePriority")) for f in m.of_class("ciamFirewallRule") if f.one("ciamRulePriority")}
    for fw in m.of_class("ciamFirewallRule"):
        role = fw.one("ciamTargetRole")
        if fw.one("ciamRulePriority"):
            prio = int(fw.one("ciamRulePriority"))
        else:
            prio = next(p for p in range(100, 4097, 10) if p not in used)
            used.add(prio)
            out.append(f"# NOTE: {fw.name} has no pinned ciamRulePriority; assigned {prio}. Pin it in the directory.")
        consumer = d.ref(fw, "ciamAllowsConsumer")
        why = f"consumer {consumer.name}" if consumer else fw.one("ciamBindingRole")
        ports = fw.all("ciamPort")
        out.append(block("resource", ["azurerm_network_security_rule", tf_name(fw.name)], [
            ("name", fw.name), ("description", why), ("priority", prio), ("direction", "Inbound"),
            ("access", "Allow"), ("protocol", fw.one("ciamProtocol", "tcp").capitalize()),
            ("source_port_range", "*"),
            ("destination_port_ranges", ports),
            ("source_address_prefixes", fw.all("ciamSourceCidr")),
            ("destination_address_prefix", "*"), ("resource_group_name", RG),
            ("network_security_group_name", ref(f"azurerm_network_security_group.{tf_name(role)}.name"))]))

    des = m.one_role("disk-encryption")
    for s in m.servers:
        n, role = tf_name(s.name), s.one("ciamServerRole")
        out.append(block("resource", ["azurerm_network_interface", n], [
            ("name", f"nic-{s.name}"), ("location", LOC), ("resource_group_name", RG),
            ("ip_configuration", Block("ip_configuration", [
                ("name", "primary"), ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(m.subnet_of(s).name)}.id")),
                ("private_ip_address_allocation", "Static"), ("private_ip_address", s.one("ciamPrivateIp"))]))]))
        out.append(block("resource", ["azurerm_network_interface_security_group_association", n], [
            ("network_interface_id", ref(f"azurerm_network_interface.{n}.id")),
            ("network_security_group_id", ref(f"azurerm_network_security_group.{tf_name(role)}.id"))]))
        disk = [("caching", "ReadWrite"), ("storage_account_type", "Premium_LRS")]
        if des and des.one("ciamProviderRef"):
            disk.append(("disk_encryption_set_id", des.one("ciamProviderRef")))
        else:
            disk.append(("#", "UNBOUND: no disk-encryption binding in this environment"))
        out.append(block("resource", ["azurerm_linux_virtual_machine", n], [
            ("name", s.name), ("computer_name", s.one("ciamHostname").split(".")[0]),
            ("resource_group_name", RG), ("location", LOC), ("size", s.one("ciamInstanceSize")),
            ("zone", s.one("ciamZone")), ("admin_username", "ciamadmin"),
            ("network_interface_ids", [ref(f"azurerm_network_interface.{n}.id")]),
            ("source_image_id", s.one("ciamImageRef")),
            ("admin_ssh_key", Block("admin_ssh_key", [("username", "ciamadmin"),
                                                      ("public_key", ref("var.admin_ssh_public_key"))])),
            ("os_disk", Block("os_disk", disk)),
            ("tags", {"Role": role, "Hostname": s.one("ciamHostname"), "Product": s.one("ciamProductVersion", ""),
                      "ManagedBy": "opsdir"})]))

    # stable service names: load balancer + DNS
    for svc in m.of_class("ciamServiceName"):
        n = tf_name(svc.name)
        ip = svc.one("ciamFrontendIp")
        internal = is_private(ip)
        targets = m.servers_with_role(svc.one("ciamTargetRole"))
        if internal:
            fe = [("name", "frontend"), ("zones", ["1", "2", "3"]),
                  ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(m.subnet_of(targets[0]).name)}.id")),
                  ("private_ip_address_allocation", "Static"), ("private_ip_address", ip)]
        else:
            out.append(block("data", ["azurerm_public_ip", n], [("name", svc.one("ciamProviderRef")),
                                                               ("resource_group_name", RG)]))
            fe = [("name", "frontend"), ("public_ip_address_id", ref(f"data.azurerm_public_ip.{n}.id"))]
        out.append(block("resource", ["azurerm_lb", n], [
            ("name", f"lb-ciam-{m.env.name}-{svc.name}"), ("location", LOC), ("resource_group_name", RG),
            ("sku", "Standard"), ("frontend_ip_configuration", Block("frontend_ip_configuration", fe)),
            ("tags", {"Service": svc.one("ciamFqdn"), "ManagedBy": "opsdir"})]))
        out.append(block("resource", ["azurerm_lb_backend_address_pool", n], [
            ("name", "servers"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id"))]))
        for t in targets:
            out.append(block("resource", ["azurerm_network_interface_backend_address_pool_association",
                                          f"{n}_{tf_name(t.name)}"], [
                ("network_interface_id", ref(f"azurerm_network_interface.{tf_name(t.name)}.id")),
                ("ip_configuration_name", "primary"),
                ("backend_address_pool_id", ref(f"azurerm_lb_backend_address_pool.{n}.id"))]))
        for port in svc.all("ciamPort"):
            out.append(block("resource", ["azurerm_lb_probe", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")),
                ("protocol", "Tcp"), ("port", int(port))]))
            out.append(block("resource", ["azurerm_lb_rule", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")), ("protocol", "Tcp"),
                ("frontend_port", int(port)), ("backend_port", int(port)),
                ("frontend_ip_configuration_name", "frontend"),
                ("backend_address_pool_ids", [ref(f"azurerm_lb_backend_address_pool.{n}.id")]),
                ("probe_id", ref(f"azurerm_lb_probe.{n}_{port}.id"))]))
        zone = svc.one("ciamDnsZone")
        rtype = "azurerm_private_dns_a_record" if internal else "azurerm_dns_a_record"
        out.append(block("resource", [rtype, n], [
            ("name", _record_name(svc.one("ciamFqdn"), zone)), ("zone_name", zone), ("resource_group_name", RG),
            ("ttl", 300), ("records", [ip])]))

    # references only: key vault secrets
    vaults = {}
    for b in m.of_class("ciamSecretRef"):
        vault, name = b.one("ciamRefUri").split("://", 1)[1].split("/", 1)
        vaults.setdefault(vault, []).append((b.one("ciamBindingRole"), name))
    for vault, secrets in vaults.items():
        vn = tf_name(vault)
        out.append(block("data", ["azurerm_key_vault", vn], [("name", vault), ("resource_group_name", RG)]))
        for role, name in secrets:
            out.append(block("data", ["azurerm_key_vault_secret", tf_name(role)], [
                ("name", name), ("key_vault_id", ref(f"data.azurerm_key_vault.{vn}.id"))]))

    notes = []
    for ic in m.of_class("ciamInterconnect"):
        peer = d.ref(ic, "ciamPeerEnvironment")
        notes.append(f"# Interconnect '{ic.name}' to {peer.dn}: {ic.one('ciamInterconnectKind')}. "
                     "Provided by the landing zone; not managed here.")
    unbound = "".join(f"# UNBOUND: required role '{r}' has no binding in this environment\n" for r in m.unbound)
    main = header(m, "Azure infrastructure for the CIAM platform") + unbound + "\n".join(notes) + "\n\n" \
        + "\n\n".join(out) + "\n"
    prov = [("features", Block("features", [])), ("subscription_id", ref("var.subscription_id"))]
    if m.cloud.one("ciamCloudEnvironment") == "usgovernment":
        prov.append(("environment", "usgovernment"))
    providers = header(m, "Providers and inputs") + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block("required_providers", [
            ("azurerm", {"source": "hashicorp/azurerm", "version": "~> 4.0"})]))]),
        block("provider", ["azurerm"], prov),
        block("variable", ["subscription_id"], [("type", ref("string"))]),
        block("variable", ["admin_ssh_public_key"], [("type", ref("string"))]),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main}
