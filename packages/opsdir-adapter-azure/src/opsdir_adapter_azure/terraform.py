"""Azure adapter: render an environment's infrastructure bindings as Terraform (hashicorp/azurerm 5.x). Each workload
principal its servers run as gets a user-assigned managed identity on those VMs and role assignments from its
permissions (the Azure permission table, opsdir_adapter_azure.access), each at the narrowest scope: the secret or key
in its vault (Key Vault's RBAC model), the storage container, the resource a provider ref names. A VM that gets the
Azure Monitor Agent from here (log_collection.agent_hosts) also gets a system-assigned identity, the agent's own."""
from itertools import chain

from opsdir.core.directory import follow, one, rdn_value, values
from opsdir.core.environment import UNBOUND, by_role, of_class, one_role, recorded, servers_with_role, subnet_of
from opsdir.domains.compute.hosts import group_subnets, own_groups, run_roles
from opsdir.domains.compute.workloads import kubernetes_note, only_on_kubernetes
from opsdir.core.manifest import header
from opsdir.core.notes import note_comment
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir.domains.infrastructure.firewall import priority_note, priority_notes, rule_priorities, rule_purpose
from opsdir.domains.access.workloads import identity_notes, identity_of, workload_identities
from opsdir.domains.edge.exposure import exposure_unknown, is_internal, service_exposure
from opsdir.domains.edge.gateways import role_gateway
from opsdir.domains.edge.kubernetes import kubernetes_notes
from opsdir.domains.edge.records import forwarders
from opsdir.domains.governance.keepers import keeper
from opsdir.domains.edge.resolve import inspected, inspection_note, inspection_notes, service_edge
from opsdir_format_terraform.hcl import (Block, TfFile, blocks_of, comment, ref, tf_block,
                                        tf_name, unbound_comments, written)
from .access import ACCESS
from .databases import database_notes, render_databases
from .storage import render_object_stores
from .audit import audit_notes, render_trails
from .container_logs import container_log_notes, render_container_logs
from .log_collection import agent_hosts, log_collection_notes, render_log_collection
from .observability import alert_notes, render_alerts, render_workspaces, workspace_notes
from .canaries import render_tests, test_notes
from .check_jobs import job_notes, render_jobs
from .budgets import budget_inputs, budget_notes, render_budgets
from .quotas import quota_notes, render_quota_requests
from .suppressions import azapi_provider, render_suppressions, suppression_notes, uses_azapi
from .discovery import discovery_notes, discovery_plans, render_discovery
from .purview import purview_inputs, render_purview, renders as purview_renders
from .security import render_security, security_notes
from .backups import backup_notes, render_backups
from .volumes import boot_tag, os_disk, server_volumes, snapshot_policy_notes, volume_notes
from .dns import (FORWARDING_RULESET, forwarder_notes, forwarding_rules, public_ip_name, records, service_record,
                  unrecorded_answer)
from .edge import EDGE_SUBNET, ddos_note, gateway_service, servers_backend
from .compute_groups import group_notes, render_groups
from .frontdoor import endpoint, front_door, frontdoor_notes
from .identities import LOC, RG, aks_data, identity, scope_data, vm_identity
from .ingress import gateway_front
from .guardrails import guardrail_notes
from .landing import STACK, landing_parts, placed_roots
from opsdir_format_terraform.placing import MAIN, PROVIDERS, carried_files
from opsdir.domains.governance.keepers import scope_folder
from .network import render_network
from .plumbing import network_data
from .account import azuread_provider, fips_note, provider_block, required_providers, subscription_variable, tagged
from .arm_types import arm_files
from .identity_protection import uses_azuread

PRIORITIES = (100, 10, 4096)        # NSG rule priorities: first slot, step, last (pinned ones kept)


def _security_rule(m, fw, prio, pinned):
    if only_on_kubernetes(m, one(fw, "ciamTargetRole")):
        return (comment(note_comment(kubernetes_note(m, f"firewall rule `{rdn_value(fw)}`", one(fw, "ciamTargetRole"),
                                                     fw.dn))),)
    why = rule_purpose(m, fw)
    note = () if pinned else (comment(note_comment(priority_note(m, fw, prio))),)
    return (*note, tf_block("resource", ["azurerm_network_security_rule", tf_name(rdn_value(fw))], [
        ("name", rdn_value(fw)), ("description", why), ("priority", prio), ("direction", "Inbound"),
        ("access", "Allow"), ("protocol", one(fw, "ciamProtocol", "tcp").capitalize()),
        ("source_port_range", "*"),
        ("destination_port_ranges", values(fw, "ciamPort")),
        ("source_address_prefixes", values(fw, "ciamSourceCidr")),
        ("destination_address_prefix", "*"), ("resource_group_name", RG),
        ("network_security_group_name",
         ref(f"azurerm_network_security_group.{tf_name(one(fw, 'ciamTargetRole'))}.name"))]))


def firewall_notes(m):
    """The render notes of environment m's network security rules given the next free priority (each rule it
    renders: not one for a role run only on Kubernetes)."""
    rules = of_class(m, "ciamFirewallRule")
    return priority_notes(m, rules, rule_priorities(rules, *PRIORITIES),
                          lambda fw: only_on_kubernetes(m, one(fw, "ciamTargetRole")))


def _security_groups(m):
    """One network security group per server role run here (its servers' or its compute groups'); rules from the
    firewall bindings."""
    roles = sorted(set(run_roles(m)))
    rules = of_class(m, "ciamFirewallRule")
    prios = rule_priorities(rules, *PRIORITIES)
    return (*(tf_block("resource", ["azurerm_network_security_group", tf_name(role)], [
                ("name", f"nsg-ciam-{rdn_value(m.env)}-{role}"), ("location", LOC), ("resource_group_name", RG),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]) for role in roles),
            *chain.from_iterable(_security_rule(m, fw, *prios[fw.dn]) for fw in rules))


def _server(m, s, des, identities=(), agents=frozenset()):
    n, role = tf_name(rdn_value(s)), one(s, "ciamServerRole")
    w = identity_of(identities, role)
    disk_notes, disk = os_disk(m, s, des)
    return (*disk_notes, tf_block("resource", ["azurerm_network_interface", n], [
                ("name", f"nic-{rdn_value(s)}"), ("location", LOC), ("resource_group_name", RG),
                ("ip_configuration", Block((
                    ("name", "primary"),
                    ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnet_of(m, s)))}.id")),
                    *((("private_ip_address_allocation", "Static"), ("private_ip_address", one(s, "ciamPrivateIp")))
                      if one(s, "ciamPrivateIp") else (("private_ip_address_allocation", "Dynamic"),))))),
                ("tags", tagged(m, {"Role": role, "ManagedBy": "opsdir"}))]),
            tf_block("resource", ["azurerm_network_interface_security_group_association", n], [
                ("network_interface_id", ref(f"azurerm_network_interface.{n}.id")),
                ("network_security_group_id", ref(f"azurerm_network_security_group.{tf_name(role)}.id"))]),
            tf_block("resource", ["azurerm_linux_virtual_machine", n], [
                ("name", rdn_value(s)), ("computer_name", one(s, "ciamHostname").split(".")[0]),
                ("resource_group_name", RG), ("location", LOC), ("size", recorded(s, "ciamInstanceSize", "size")),
                *((("zone", one(s, "ciamZone")),) if one(s, "ciamZone") else ()), ("admin_username", "ciamadmin"),
                ("network_interface_ids", [ref(f"azurerm_network_interface.{n}.id")]),
                ("source_image_id", recorded(s, "ciamImageRef", "image")),
                ("admin_ssh_key", Block((("username", "ciamadmin"), ("public_key", ref("var.admin_ssh_public_key"))))),
                ("os_disk", disk),
                *vm_identity(w, rdn_value(s) in agents),
                ("tags", tagged(m, {"Role": role, "Hostname": one(s, "ciamHostname"),
                          "Product": one(s, "ciamProductVersion", ""), **boot_tag(m, s), "ManagedBy": "opsdir"}))]),
            *server_volumes(m, s))


def _frontend(m, svc, n, ip, internal, subnets):
    """(data sources needed, frontend_ip_configuration body); an internal one sits in the first of its targets'
    subnets (its servers', then its compute groups')."""
    if internal:
        subnet = ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnets[0]))}.id") if subnets else \
            f"{UNBOUND}{one(svc, 'ciamTargetRole')}-subnet"
        return (), (("name", "frontend"), ("zones", ["1", "2", "3"]), ("subnet_id", subnet),
                    *((("private_ip_address_allocation", "Static"), ("private_ip_address", ip)) if ip else
                      (("private_ip_address_allocation", "Dynamic"),)))
    return ((tf_block("data", ["azurerm_public_ip", n], [("name", public_ip_name(svc)),
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


def _probed(spec, port):
    """The port a probe checks: the product's own health port (an admin port) when it declares one, else the rule's."""
    return spec.health.port if spec is not None and spec.health.port else port


def _lb_port(n, port, spec=None):
    rule = (*((("idle_timeout_in_minutes", min(30, max(4, -(-spec.idle_timeout // 60)))),)
              if spec is not None and spec.idle_timeout else ()),
            *((("load_distribution", "SourceIP"),) if spec is not None and spec.stickiness == "source-ip" else ()))
    return (tf_block("resource", ["azurerm_lb_probe", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")),
                *_probe_body(spec)[:1], ("port", int(_probed(spec, port))), *_probe_body(spec)[1:]]),
            tf_block("resource", ["azurerm_lb_rule", f"{n}_{port}"], [
                ("name", f"tcp-{port}"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id")), ("protocol", "Tcp"),
                ("frontend_port", int(port)), ("backend_port", int(port)),
                ("frontend_ip_configuration_name", "frontend"),
                ("backend_address_pool_ids", [ref(f"azurerm_lb_backend_address_pool.{n}.id")]),
                ("probe_id", ref(f"azurerm_lb_probe.{n}_{port}.id")), *rule]))


def _service(m, svc, endpoints=()):
    """A stable service name: load balancer, backend pool, probes and rules per port (an Application Gateway when its
    traffic policy terminates TLS at the edge; opsdir_adapter_azure.edge), and its DNS record; for a role run only on
    Kubernetes, the Application Gateway before its cluster's gateway (opsdir_adapter_azure.ingress), else a note; a
    note when its exposure is unknown (core edge.exposure)."""
    role = one(svc, "ciamTargetRole")
    gw = role_gateway(m, role) if only_on_kubernetes(m, role) else None
    if only_on_kubernetes(m, role) and gw is None:
        return (comment(note_comment(kubernetes_note(m, f"service name `{rdn_value(svc)}` ({one(svc, 'ciamFqdn')})",
                                                     role, svc.dn))),)
    if service_exposure(svc) is None:
        return (comment(exposure_unknown(svc)),)
    if gw is not None:
        return gateway_front(m, svc, gw, endpoints)
    n = tf_name(rdn_value(svc))
    ip = one(svc, "ciamFrontendIp")
    internal = is_internal(svc)
    targets = servers_with_role(m, role)
    spec = service_edge(m, svc, endpoints)
    cdn = spec is not None and spec.cdn
    layer7 = spec is not None and spec.layer7
    fronted = front_door(m, svc, spec, n) if cdn else ()
    record = service_record(m.d, m, svc, n, endpoint(n) if cdn else None, unrecorded_answer(svc, n, layer7))
    if layer7:
        return (*gateway_service(m, svc, spec, servers_backend(targets)), *fronted, *record)
    data, fe = _frontend(m, svc, n, ip, internal, (*(subnet_of(m, t) for t in targets),
                                                    *(s for g in own_groups(m, role) for s in group_subnets(m, g))))
    blind = (comment(note_comment(inspection_note(m, svc, spec))),) \
        if spec is not None and inspected(spec) and not cdn else ()
    return (*data, *blind, *(ddos_note(spec) if spec is not None else ()),
            tf_block("resource", ["azurerm_lb", n], [
                ("name", f"lb-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("location", LOC),
                ("resource_group_name", RG), ("sku", "Standard"), ("frontend_ip_configuration", Block(fe)),
                ("tags", tagged(m, {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"}))]),
            tf_block("resource", ["azurerm_lb_backend_address_pool", n], [
                ("name", "servers"), ("loadbalancer_id", ref(f"azurerm_lb.{n}.id"))]),
            *(tf_block("resource", ["azurerm_network_interface_backend_address_pool_association",
                                    f"{n}_{tf_name(rdn_value(t))}"], [
                   ("network_interface_id", ref(f"azurerm_network_interface.{tf_name(rdn_value(t))}.id")),
                   ("ip_configuration_name", "primary"),
                   ("backend_address_pool_id", ref(f"azurerm_lb_backend_address_pool.{n}.id"))]) for t in targets),
            *chain.from_iterable(_lb_port(n, port, spec) for port in values(svc, "ciamPort")), *fronted, *record)


def _pools(m, endpoints):
    """{server role: (load balancer backend pool IDs, Application Gateway backend pool IDs)} (references) of the
    service names that reach a role here: the pools its compute groups' instances join."""
    found = {}
    for svc in of_class(m, "ciamServiceName"):
        role, n = one(svc, "ciamTargetRole"), tf_name(rdn_value(svc))
        if service_exposure(svc) is None or only_on_kubernetes(m, role):
            continue
        spec = service_edge(m, svc, endpoints)
        lb, gateway = found.get(role, ((), ()))
        if spec is not None and spec.layer7:
            gateway += (f"{ref(f'azurerm_application_gateway.{n}.id')}/backendAddressPools/servers",) \
                if by_role(m, EDGE_SUBNET) else ()
        else:
            lb += (ref(f"azurerm_lb_backend_address_pool.{n}.id"),)
        found[role] = (lb, gateway)
    return found


def _key_vault_secrets(m):
    """Each Key Vault once (in order of first use) and a check that it holds the environment's secrets. The check reads
    the vault's secret names (azurerm_key_vault_secrets), never a secret: azurerm_key_vault_secret would copy each value
    into Terraform state. A missing secret fails the plan (a postcondition), naming its role."""
    refs = tuple((*one(b, "ciamRefUri").split("://", 1)[1].split("/", 1), one(b, "ciamBindingRole"))
                 for b in of_class(m, "ciamSecretRef"))
    vaults = dict.fromkeys(vault for vault, _, _ in refs)
    return tuple(chain.from_iterable(
        (tf_block("data", ["azurerm_key_vault", tf_name(vault)], [("name", vault), ("resource_group_name", RG)]),
         tf_block("data", ["azurerm_key_vault_secrets", tf_name(vault)], [
             ("#", "names only: no secret value enters Terraform state"),
             ("key_vault_id", ref(f"data.azurerm_key_vault.{tf_name(vault)}.id")),
             ("lifecycle", Block(tuple(("postcondition", Block((
                 ("condition", ref(f'contains(self.names, "{name}")')),
                 ("error_message", f"Key Vault {vault} has no secret {name} (role {role})"))))
                 for v, name, role in refs if v == vault)))]))
        for vault in vaults))


def _interconnect_note(m, ic):
    """The stack's header line for an interconnect: its keeper's (the landing zone's unless ciamManagedBy names
    another party), rendered in their root or asked of them."""
    peer, k = follow(m.d, ic, "ciamPeerEnvironment"), keeper(m, ic, landing_zone=True)
    where = "rendered in their root" if k.takes else "asked of them"
    return (f"# Interconnect '{rdn_value(ic)}' to {peer.dn}: {one(ic, 'ciamInterconnectKind')}. "
            f"Kept by {k.name} ({where}); not managed here.")


def render_files(m, services):
    """{path: TfFile | text} of environment m's Azure render: the Terraform roots as data (main, providers, the
    landing zone's roots), the configuration files they come with as text."""
    endpoints = services.endpoints if services else ()     # what the products serve (contract.Endpoint)
    des, identities = one_role(m, "disk-encryption"), workload_identities(m, ACCESS)
    agents = frozenset(agent_hosts(m, services)) if services else frozenset()
    containers, container_files = render_container_logs(m, services) if services else ((), {})
    jobs, scripts = render_jobs(m, endpoints)
    out = (*network_data(m), *_security_groups(m), *aks_data(identities),
           *chain.from_iterable(identity(m, w) for w in identities),
           *chain.from_iterable(_server(m, s, des, identities, agents) for s in m.servers),
           *render_groups(m, des, identities, _pools(m, endpoints)), *snapshot_policy_notes(m),
           *render_backups(m),
           *chain.from_iterable(_service(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")),
           *render_network(m, endpoints), *render_databases(m), *render_object_stores(m), *records(m.d, m),
           *forwarding_rules(m), *render_trails(m), *render_workspaces(m),
           *(render_log_collection(m, services) if services else ()),
           *(comment(note_comment(n)) for n in (log_collection_notes(m, services) if services else ())),
           *containers, *(comment(note_comment(n)) for n in (container_log_notes(m, services) if services else ())),
           *render_alerts(m),
           *render_tests(m, endpoints), *jobs,
           *render_security(m, discovery_plans(m)), *render_discovery(m), *render_purview(m),
           *render_suppressions(m), *render_budgets(m), *render_quota_requests(m),
           *_key_vault_secrets(m), *scope_data(m, identities))
    out = tuple(x for i, x in enumerate(out) if not (x in blocks_of(out[:i], "data")))     # a data source once
    notes = "\n".join(_interconnect_note(m, ic) for ic in of_class(m, "ciamInterconnect"))
    providers = (
        required_providers(uses_azapi(m) or purview_renders(m), uses_azuread(m)),
        provider_block(m),
        *((azapi_provider(m),) if uses_azapi(m) or purview_renders(m) else ()),
        *((azuread_provider(m),) if uses_azuread(m) else ()),
        subscription_variable(m),
        tf_block("variable", ["admin_ssh_public_key"], [("type", ref("string"))]),
        *budget_inputs(m),
        *purview_inputs(m),
        *((tf_block("variable", [FORWARDING_RULESET], [
            ("description", "The landing zone's DNS forwarding ruleset the forwarding rules join"),
            ("type", ref("string"))]),) if forwarders(m, hosted=False) else ()))
    landing, landing_dns = landing_parts(m)
    roots = placed_roots(m, ((PROVIDERS, providers), (MAIN, out), *landing), landing_dns, lambda name: (
        header(m, WHAT, HCL) + unbound_comments(m.unbound) + notes + "\n" if name == MAIN else
        header(m, "Providers and inputs", HCL)))
    carried = carried_files(roots, scripts, STACK)
    if scope_folder(m) is not None:                 # a slice: its root and the files it reads
        return {**roots, **carried}
    return {**roots, **container_files, **scripts, **carried}


WHAT = "Azure infrastructure for the CIAM platform"
TERRAFORM, BICEP, ARM_JSON = "terraform", "bicep", "arm"
# The infrastructure-as-code languages an environment's Azure render is written in (Adapter.render_targets; an
# environment chooses with its stack component's ciamRenderTarget, a render with --target azure=...).
TARGETS = ((TERRAFORM, "Terraform for the azurerm, azapi and azuread providers (terraform/)"),
           (BICEP, "Bicep translated from it (bicep/: a template per deployment scope), what ARM has no form for kept "
                   "in a Terraform root beside them", False),
           (ARM_JSON, "ARM template JSON translated from it (arm/), as bicep build compiles the Bicep", False))
DEFAULT_TARGETS = tuple(t[0] for t in TARGETS if len(t) < 3)


def render(m, services, targets=DEFAULT_TARGETS):
    """Adapter render: environment m's Azure files as text in the render targets chosen: Terraform (terraform/),
    and/or Bicep (bicep/) and ARM JSON (arm/) translated from it (arm_types); the files that are neither (Kubernetes
    configuration) either way, and the files a Terraform root beside the templates reads (the check scripts:
    placing.carried_files). Each Terraform file written once from its TfFile."""
    files = render_files(m, services)
    terraform = {p: v for p, v in files.items() if p.startswith("terraform/")}
    native = arm_files(m, files, WHAT, tuple(t for t in (BICEP, ARM_JSON) if t in targets)) \
        if BICEP in targets or ARM_JSON in targets else {}
    beside = carried_files({p: v for p, v in native.items() if isinstance(v, TfFile)},
                           {p: v for p, v in terraform.items() if isinstance(v, str)}, STACK)
    return written({**{p: v for p, v in files.items() if p not in terraform},
                    **(terraform if TERRAFORM in targets else {}), **native, **beside})


def render_notes(m, services):
    """Adapter notes (core.notes, flow 43): what environment m's Azure render leaves out or to a person, as data: the
    synthetic checks it doesn't render (availability tests, check jobs), the check jobs' subnet delegation and what to
    expect of their first runs; then the security services', audit trails', data discovery's, suppressions',
    guardrails', alert rules', workspaces', identities' (core access.workloads), Kubernetes-only roles' (core
    edge.kubernetes) and unpinned rule priorities' notes, and log shipping's (servers, containers); each written as its
    comment."""
    endpoints = services.endpoints if services else ()
    return (*test_notes(m, endpoints), *job_notes(m, endpoints), *security_notes(m, discovery_plans(m)),
            *audit_notes(m), *discovery_notes(m), *suppression_notes(m), *guardrail_notes(m), *alert_notes(m),
            *workspace_notes(m), *identity_notes(m, ACCESS), *kubernetes_notes(m), *firewall_notes(m),
            *budget_notes(m), *((fips_note(m),) if fips_note(m) else ()), *forwarder_notes(m), *backup_notes(m),
            *database_notes(m), *volume_notes(m), *group_notes(m), *inspection_notes(m, endpoints),
            *frontdoor_notes(m, endpoints), *quota_notes(m),
            *((*log_collection_notes(m, services), *container_log_notes(m, services)) if services else ()))
