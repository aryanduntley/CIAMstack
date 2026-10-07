"""Azure adapter: render an environment's infrastructure bindings as Terraform (hashicorp/azurerm ~> 4). Each workload
principal its servers run as gets a user-assigned managed identity on those VMs and role assignments from its
permissions (the Azure permission table, opsdir_adapter_azure.access), each at the narrowest scope: the secret or key
in its vault (Key Vault's RBAC model), the storage container, the resource a provider ref names."""
from itertools import chain

from opsdir.core.directory import follow, one, rdn_value, values
from opsdir.core.environment import of_class, one_role, servers_with_role, subnet_of
from opsdir.core.manifest import header
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.core.network import is_private
from opsdir.domains.infrastructure.firewall import rule_priorities, rule_purpose
from opsdir.domains.access.workloads import identity_of, workload_identities
from opsdir.domains.edge.records import forwarders
from opsdir.domains.edge.resolve import inspected, service_edge
from opsdir_format_terraform.hcl import Block, block, ref, tf_name, unbound_comments
from .access import ACCESS
from .databases import render_databases
from .storage import render_object_stores
from .backups import render_backups
from .volumes import boot_tag, os_disk, server_volumes, snapshot_policy_notes
from .dns import FORWARDING_RULESET, forwarding_rules, records, service_record
from .edge import ddos_note, gateway_service
from .frontdoor import endpoint, front_door
from .identities import LOC, RG, identity, scope_data
from .landing import render_landing
from .network import render_network
from .plumbing import network_data
from .account import provider_block, subscription_variable, tagged

PRIORITIES = (100, 10, 4096)        # NSG rule priorities: first slot, step, last (pinned ones kept)


def _security_rule(m, fw, prio, pinned):
    why = rule_purpose(m, fw)
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
    prios = rule_priorities(rules, *PRIORITIES)
    return (*(block("resource", ["azurerm_network_security_group", tf_name(role)], [
                ("name", f"nsg-ciam-{rdn_value(m.env)}-{role}"), ("location", LOC), ("resource_group_name", RG),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]) for role in roles),
            *chain.from_iterable(_security_rule(m, fw, *prios[fw.dn]) for fw in rules))


def _server(m, s, des, identities=()):
    n, role = tf_name(rdn_value(s)), one(s, "ciamServerRole")
    w = identity_of(identities, role)
    disk_notes, disk = os_disk(m, s, des)
    return (*disk_notes, block("resource", ["azurerm_network_interface", n], [
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
                ("os_disk", disk),
                *((("identity", Block((("type", "UserAssigned"), ("identity_ids", [
                    ref(f"azurerm_user_assigned_identity.{tf_name(w.identity_role)}.id")])))),) if w else ()),
                ("tags", tagged(m, {"Role": role, "Hostname": one(s, "ciamHostname"),
                          "Product": one(s, "ciamProductVersion", ""), **boot_tag(m, s), "ManagedBy": "opsdir"}))]),
            *server_volumes(m, s))


def _frontend(m, svc, n, ip, internal, targets):
    """(data sources needed, frontend_ip_configuration body)"""
    if internal:
        return (), (("name", "frontend"), ("zones", ["1", "2", "3"]),
                    ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet_of(m, targets[0])))}.id")),
                    ("private_ip_address_allocation", "Static"), ("private_ip_address", ip))
    return ((block("data", ["azurerm_public_ip", n], [("name", one(svc, "ciamProviderRef")),
                                                       ("resource_group_name", RG)]),),
            (("name", "frontend"), ("public_ip_address_id", ref(f"data.azurerm_public_ip.{n}.id"))))


def _probe_body(spec):
    """The probe's protocol and settings from a service's traffic policy (a TCP connect without one)."""
    h = spec.health if spec is not None else None
    if h is None or h.protocol == "tcp":
        return (("protocol", "Tcp"),) + ((("interval_in_seconds", h.interval),) if h and h.interval else ())
    return (("protocol", h.protocol.capitalize()), ("request_path", h.path or "/"),
            *((("interval_in_seconds", h.interval),) if h.interval else ()),
            *((("number_of_probes", h.unhealthy),) if h.unhealthy else ()))


def _lb_port(n, port, spec=None):
    rule = (*((("idle_timeout_in_minutes", min(30, max(4, -(-spec.idle_timeout // 60)))),)
              if spec is not None and spec.idle_timeout else ()),
            *((("load_distribution", "SourceIP"),) if spec is not None and spec.stickiness == "source-ip" else ()))
    return (block("resource", ["azurerm_lb_probe", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")),
                *_probe_body(spec)[:1], ("port", int(port)), *_probe_body(spec)[1:]]),
            block("resource", ["azurerm_lb_rule", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")), ("protocol", "Tcp"),
                ("frontend_port", int(port)), ("backend_port", int(port)),
                ("frontend_ip_configuration_name", "frontend"),
                ("backend_address_pool_ids", [ref(f"azurerm_lb_backend_address_pool.{n}.id")]),
                ("probe_id", ref(f"azurerm_lb_probe.{n}_{port}.id")), *rule]))


def _service(m, svc, endpoints=()):
    """A stable service name: load balancer, backend pool, probes and rules per port (an Application Gateway when its
    traffic policy terminates TLS at the edge; opsdir_adapter_azure.edge), and its DNS record."""
    n = tf_name(rdn_value(svc))
    ip = one(svc, "ciamFrontendIp")
    internal = is_private(ip)
    targets = servers_with_role(m, one(svc, "ciamTargetRole"))
    spec = service_edge(m, svc, endpoints)
    cdn = spec is not None and spec.cdn
    fronted = front_door(m, svc, spec, n) if cdn else ()
    record = service_record(m.d, m, svc, n, endpoint(n) if cdn else None)
    if spec is not None and spec.layer7:
        return (*gateway_service(m, svc, spec, targets), *fronted, *record)
    data, fe = _frontend(m, svc, n, ip, internal, targets)
    blind = ("# the protection policy's request inspection needs TLS terminated at the edge; not rendered",) \
        if spec is not None and inspected(spec) and not cdn else ()
    return (*data, *blind, *(ddos_note(spec) if spec is not None else ()),
            block("resource", ["azurerm_lb", n], [
                ("name", f"lb-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("location", LOC),
                ("resource_group_name", RG), ("sku", "Standard"), ("frontend_ip_configuration", Block(fe)),
                ("tags", tagged(m, {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"}))]),
            block("resource", ["azurerm_lb_backend_address_pool", n], [
                ("name", "servers"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id"))]),
            *(block("resource", ["azurerm_network_interface_backend_address_pool_association",
                                 f"{n}_{tf_name(rdn_value(t))}"], [
                ("network_interface_id", ref(f"azurerm_network_interface.{tf_name(rdn_value(t))}.id")),
                ("ip_configuration_name", "primary"),
                ("backend_address_pool_id", ref(f"azurerm_lb_backend_address_pool.{n}.id"))]) for t in targets),
            *chain.from_iterable(_lb_port(n, port, spec) for port in values(svc, "ciamPort")), *fronted, *record)


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
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    des, identities = one_role(m, "disk-encryption"), workload_identities(m, ACCESS)
    out = (*network_data(m), *_security_groups(m), *chain.from_iterable(identity(m, w) for w in identities),
           *chain.from_iterable(_server(m, s, des, identities) for s in m.servers), *snapshot_policy_notes(m),
           *render_backups(m),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *render_databases(m), *render_object_stores(m), *records(m.d, m),
           *forwarding_rules(m),
           *_key_vault_secrets(m), *scope_data(m, identities))
    notes = "\n".join(_interconnect_note(m, ic) for ic in of_class(m, "ciamInterconnect"))
    unbound = unbound_comments(m.unbound)
    main = header(m, "Azure infrastructure for the CIAM platform", HCL) + unbound + notes + "\n\n" \
        + "\n\n".join(out) + "\n"
    providers = header(m, "Providers and inputs", HCL) + "\n" + "\n\n".join([
        block("terraform", [], [("required_providers", Block((
            ("azurerm", {"source": "hashicorp/azurerm", "version": "~> 4.0"}),)))]),
        provider_block(m),
        subscription_variable(m),
        block("variable", ["admin_ssh_public_key"], [("type", ref("string"))]),
        *((block("variable", [FORWARDING_RULESET], [
            ("description", "The landing zone's DNS forwarding ruleset the forwarding rules join"),
            ("type", ref("string"))]),) if forwarders(m) else ()),
    ]) + "\n"
    return {"terraform/providers.tf": providers, "terraform/main.tf": main, **render_landing(m)}
