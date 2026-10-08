"""What Azure says an environment runs, as the record's neutral resources (opsdir.core.inventory). Pure.

From Terraform state (terraform.tfstate, format version 4; hashicorp/azurerm), managed resources and data sources:

  azurerm_virtual_network                     -> network (role network): its name, first address space, resource group
  azurerm_subnet                              -> subnet <virtual network>/<subnet>
  azurerm_linux_virtual_machine,              -> server (name, role, hostname and product from its tags Name, Role,
    azurerm_windows_virtual_machine,             Hostname, Product; size, zone, image; the private address and subnet
    azurerm_virtual_machine                      of its primary network interface)
  azurerm_lb (+ rules, backend pools and      -> service: the DNS name of the A record holding its frontend address
    their NIC associations, azurerm_public_ip,   (or its tag Service), the zone, rule ports, the role of the VMs in
    azurerm_(private_)dns_a_record)              its pools, its private address or public IP (name and address)
  azurerm_network_security_rule and inline    -> firewall rules by name (inbound allow rules): sources, ports, protocol,
    azurerm_network_security_group rules         priority; the target role is that of the VMs whose interfaces or
                                                 subnets the group guards, else its tag Role, else its name's last part
  azurerm_key_vault_secret                    -> secret reference azkv://<vault>/<name>; its value is never read
  azurerm_key_vault_key                       -> key reference azkv-key://<vault>/keys/<name>: HSM or software, whether
    (+ azurerm_disk_encryption_set)              it rotates automatically, the disk encryption set that uses it
  azurerm_storage_container (+ its account,   -> storage azblob://<account>/<container> (role from its metadata key
    immutability, management and object          role), with its versioning, lock, key, lifecycle, public access and
    replication policies)                        replica (storage.py)
  azurerm_nat_gateway (+ its public IPs and   -> egress (by name): its public addresses
    prefixes)
  azurerm_linux_function_app,                 -> a job binding (what realizes a job: kind job, ciamJobBinding): the
    azurerm_windows_function_app                 function app's ID, its runtime (language and version), and the
    (+ azurerm_function_app_function)            schedules of its timer-triggered functions (NCRONTAB)
  azurerm_linux_virtual_machine_scale_set,    -> compute group (kind compute, ciamComputeGroup): the server role it runs
    azurerm_windows_virtual_machine_scale_set,   (tag Role), SKU, instances, zones, image; min/max from the
    azurerm_orchestrated_virtual_machine_        autoscale setting that targets it (azurerm_monitor_autoscale_setting)
    scale_set
  azurerm_kubernetes_cluster (+ azurerm_     -> cluster (kind cluster, ciamCluster): version, add-ons it enables, node
    kubernetes_cluster_node_pool)                pools (name: VM size, min-max), zones of its pools
  azurerm_email_communication_service_       -> sending identity (kind sending, ciamSendingIdentity) for a domain: DKIM
    domain (+ azurerm_dns_cname_record,          verified when the DKIM selectors its verification records name are
    azurerm_dns_txt_record)                      published in Azure DNS, SPF authorizing it (include:
                                                 spf.protection.outlook.com) and the DMARC policy, from the TXT records
  azurerm_servicebus_queue / _topic,          -> stream carriers (kind stream, ciamStreamBinding): queue, topic, event
    azurerm_eventhub, azurerm_eventgrid_topic    hub
  azurerm_monitor_action_group                -> alert channel (kind channel, ciamAlertChannel): action group
  azurerm_log_analytics_workspace             -> log destination (kind logs, ciamLogDestination): workspace, its
                                                 retention in days
  azurerm_monitor_metric_alert,               -> alarm (kind alarm, ciamAlarmBinding): what it evaluates (namespace and
    azurerm_monitor_scheduled_query_rules_       metric, or a log query), the action groups it notifies, the alert rule
    alert_v2                                     it realizes (tag Realizes)
  azurerm_application_insights_standard_     -> synthetic check (kind canary, ciamCanaryBinding): its frequency as an
    web_test                                     interval, the canary it realizes (tag Realizes)
  azurerm_postgresql_flexible_server,        -> database (kind database, ciamDatabase): engine, version, endpoint,
    azurerm_mysql_flexible_server (+ their       SKU, storage, zone, availability, TLS, backups, parameters, deletion
    _configuration, azurerm_management_lock)     protection (a lock), its subnet and key as roles; never its password:
                                                 see databases.py
  azurerm_monitor_diagnostic_setting on a   -> audit trail (kind audit, ciamAuditTrail): the subscription's Activity
    subscription                                 Log export: control-plane when Administrative is exported, every
                                                 region, where its records go (its storage account's
                                                 insights-activity-logs container or its workspace, as that object
                                                 store's or log destination's role): see audit.py
  azurerm_consumption_budget_resource_group, -> budget (kind budget, ciamBudget): amount, period, GreaterThan
    _subscription                                thresholds, the action group its alerts go to: see budgets.py
  access control: identities and their role assignments, access policies, policy assignments, bastions: see iam.py
Roles of resources the record doesn't have come from their tags Role (or BindingRole), or for storage containers from
their metadata (role); a compute group's binding role is its tag BindingRole, else compute-<its tag Role>, a
cluster's its tag BindingRole or Role, else cluster, and an alarm's or synthetic check's, else alarm-<Realizes> or
canary-<Realizes>. Subnets and individual security rules carry neither in Azure:
their roles come from the environment's role map (roles.json, opsdir.core.inventory), and without one new ones are
named in the notices.
"""
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.inventory import (cluster_role, compute_roles, duration_text, layout_import, of_types, per_file,
                                   realization_roles, resource, tagged_role)
from opsdir.core.sources import json_document
from opsdir.domains.messaging.dns import dmarc_policy, spf_authorizes
from opsdir_format_terraform.state import read_state
from .arm_ids import arm_segment, subnet_ref
from .network_inventory import network_resources
from .edge_inventory import (dns_resources, edge_services, fqdn, frontdoor_endpoints, frontdoor_origins,
                             gateway_facts, lb_facts, traffic_routing)
from .iam import iam_resources
from .databases import database_resources, database_security_groups, geo_backup_notices
from .nsg_rules import allows_in, group_rules, rule_ports, rule_sources, source_cidr
from .backups import backup_resources
from .volumes import volume_resources
from .storage import object_store_resources
from .audit import trail_resources
from .budgets import budget_resources
from .security import security_resources

PROVIDER = "azure"

SKIPPED = ("random_password", "tls_private_key", "azurerm_key_vault_certificate",
           "azurerm_mssql_server")  # secret values, or not modeled yet
VMS = ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine")


def _tags(a):
    return a.get("tags") or {}


def _role(a):
    return tagged_role(_tags(a))


def _first(xs):
    return (xs or (None,))[0]


def _low(x):
    return (x or "").lower()


def _networks(found):
    return tuple(resource("network", a.get("name"), {"ciamCidr": _first(a.get("address_space")),
                                                     "ciamResourceGroup": a.get("resource_group_name")},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a) or "network", tags=_tags(a))
                 for a in of_types(found, "azurerm_virtual_network") if a.get("name"))


def _subnets(found):
    return tuple(resource("subnet", f"{a.get('virtual_network_name')}/{a.get('name')}",
                          {"ciamCidr": _first(a.get("address_prefixes")) or a.get("address_prefix")},
                          name=a.get("name"), role=_role(a))       # subnets take no tags: not judged
                 for a in of_types(found, "azurerm_subnet") if a.get("name") and a.get("virtual_network_name"))


def _nics(found):
    """{NIC id (lower case): (private address, subnet ref)} from each interface's primary IP configuration."""
    def primary(nic):
        configs = nic.get("ip_configuration") or ()
        return next((c for c in configs if c.get("primary")), _first(configs)) or {}
    return {_low(n.get("id")): (primary(n).get("private_ip_address") or n.get("private_ip_address"),
                                subnet_ref(primary(n).get("subnet_id")))
            for n in of_types(found, "azurerm_network_interface") if n.get("id")}


def _vm_nics(vm):
    return tuple(_low(i) for i in (*(vm.get("network_interface_ids") or ()), vm.get("primary_network_interface_id"))
                 if i)


def _image(vm):
    ref = _first(vm.get("source_image_reference") or vm.get("storage_image_reference")) or {}
    urn = ":".join(ref.get(k) or "" for k in ("publisher", "offer", "sku", "version")) if ref.get("offer") else None
    return vm.get("source_image_id") or ref.get("id") or urn


def _hostname(vm):
    """Tag Hostname, else the computer name when it is a full name (a short one would replace the record's FQDN)."""
    name = vm.get("computer_name") or (_first(vm.get("os_profile")) or {}).get("computer_name")
    return _tags(vm).get("Hostname") or (name if name and "." in name else None)


def _servers(found):
    nics = _nics(found)

    def one_vm(vm):
        ip, subnet = next((nics[n] for n in _vm_nics(vm) if n in nics), (None, None))
        return resource("server", vm.get("id"),
                        {"ciamPrivateIp": vm.get("private_ip_address") or ip,
                         "ciamZone": vm.get("zone") or _first(vm.get("zones")),
                         "ciamInstanceSize": vm.get("size") or vm.get("vm_size"), "ciamImageRef": _image(vm),
                         "ciamHostname": _hostname(vm), "ciamProductVersion": _tags(vm).get("Product")},
                        links={"ciamSubnet": subnet}, name=_tags(vm).get("Name") or vm.get("name"),
                        role=_tags(vm).get("Role"), tags=_tags(vm))
    return tuple(one_vm(vm) for vm in of_types(found, *VMS))


def _nic_roles(found):
    """{NIC id (lower case): the Role tag of the VM using it}."""
    return {n: _tags(vm)["Role"] for vm in of_types(found, *VMS) if _tags(vm).get("Role") for n in _vm_nics(vm)}


def answer_record(found, ip, pip_id):
    """The DNS record answering for a frontend: an A record holding its address (or naming its public IP), else a
    CNAME to the Front Door endpoint whose origin it is, else a CNAME to the Traffic Manager profile routing to it."""
    a = next((r for r in of_types(found, "azurerm_dns_a_record", "azurerm_private_dns_a_record")
              if (ip and ip in (r.get("records") or ())) or (pip_id and _low(r.get("target_resource_id")) == pip_id)),
             None)
    if a is not None or not ip:
        return a
    profile = frontdoor_origins(found).get(ip)
    endpoint = {p: host for host, p in frontdoor_endpoints(found).items()}.get(profile)
    _, _, manager = traffic_routing(found, ip)
    targets = {t for t in (endpoint, (manager or {}).get("fqdn")) if t}
    return next((r for r in of_types(found, "azurerm_dns_cname_record") if (r.get("record") or "").rstrip(".") in
                 targets), None)


def _frontend_of(fe, pips):
    """(address, public IP) of a frontend IP configuration."""
    pip = pips.get(_low(fe.get("public_ip_address_id")))
    return (fe.get("private_ip_address") if not fe.get("public_ip_address_id") else (pip or {}).get("ip_address")), pip


def _service(kind_ref, name, role, found, ip, pip, ports, roles, facts, settings, tags):
    record = answer_record(found, ip, _low((pip or {}).get("id")))
    routed, _, _ = traffic_routing(found, ip)
    return resource("service", kind_ref, {
        "ciamFqdn": fqdn(record) if record else tags.get("Service"),
        "ciamDnsZone": (record or {}).get("zone_name"),
        "ciamPort": ports, "ciamTargetRole": roles.most_common(1)[0][0] if roles else None, "ciamFrontendIp": ip,
        "ciamProviderRef": (pip or {}).get("name"), "ciamTtlSeconds": (record or {}).get("ttl"),
        "ciamEdgeFact": facts, "ciamEdgeSetting": settings, **routed}, name=name, role=role, tags=tags)


def _services(found):
    """A service per load balancer and per Application Gateway: its DNS name, zone and TTL, ports, the role behind it,
    its frontend, and what its edge runs."""
    pips = {_low(p.get("id")): p for p in of_types(found, "azurerm_public_ip")}
    nic_roles, nics = _nic_roles(found), _nics(found)
    roles_by_ip = {ip: nic_roles[n] for n, (ip, _) in nics.items() if n in nic_roles and ip}

    def one_lb(lb):
        ip, pip = _frontend_of(_first(lb.get("frontend_ip_configuration")) or {}, pips)
        rules = [r for r in of_types(found, "azurerm_lb_rule") if _low(r.get("loadbalancer_id")) == _low(lb.get("id"))]
        pools = {_low(p.get("id")) for p in of_types(found, "azurerm_lb_backend_address_pool")
                 if _low(p.get("loadbalancer_id")) == _low(lb.get("id"))}
        roles = Counter(nic_roles.get(_low(a.get("network_interface_id")))
                        for a in of_types(found, "azurerm_network_interface_backend_address_pool_association")
                        if _low(a.get("backend_address_pool_id")) in pools
                        and nic_roles.get(_low(a.get("network_interface_id"))))
        facts, settings = lb_facts(lb, found)
        return _service(lb.get("id"), lb.get("name"), _role(lb), found, ip, pip,
                        sorted({str(r.get("frontend_port")) for r in rules if r.get("frontend_port")}), roles,
                        facts, settings, _tags(lb))

    def one_gateway(gw):
        ip, pip = _frontend_of(_first(gw.get("frontend_ip_configuration")) or {}, pips)
        roles = Counter(roles_by_ip[a] for p in gw.get("backend_address_pool") or ()
                        for a in p.get("ip_addresses") or () if a in roles_by_ip)
        facts, settings = gateway_facts(gw)
        return _service(gw.get("id"), gw.get("name"), _role(gw), found, ip, pip,
                        sorted({str(p.get("port")) for p in gw.get("frontend_port") or () if p.get("port")}), roles,
                        facts, settings, _tags(gw))
    return (*(one_lb(lb) for lb in of_types(found, "azurerm_lb")),
            *(one_gateway(gw) for gw in of_types(found, "azurerm_application_gateway")))


def _edge(found, services):
    """The edge services, zones, records and forwarders, and notices for the other environments' answers."""
    by_address = {s.attrs["ciamFrontendIp"][0]: s.ref for s in services if "ciamFrontendIp" in s.attrs}
    gateways = {_low(g.get("firewall_policy_id")): g.get("id") for g in of_types(found, "azurerm_application_gateway")
                if g.get("firewall_policy_id")}
    pips = {_low(p.get("id")): p for p in of_types(found, "azurerm_public_ip")}
    frontends = [_frontend_of(_first(x.get("frontend_ip_configuration")) or {}, pips)
                 for x in of_types(found, "azurerm_lb", "azurerm_application_gateway")]
    served = {id(r) for ip, pip in frontends for r in (answer_record(found, ip, _low((pip or {}).get("id"))),) if r}
    zones, records, forwarders = dns_resources(found, served)
    others = [(ip, t) for ip, _ in frontends for t in traffic_routing(found, ip)[1]]
    return ((*edge_services(found, by_address, gateways), *zones, *records, *forwarders),
            tuple(f"Traffic Manager endpoint {t} answers for another environment of the name {ip} serves: not recorded "
                  "here" for ip, t in others))


def _guarded_roles(found):
    """{NSG id (lower case): roles of the VMs it guards}, through NIC and subnet associations."""
    nics, nic_roles = _nics(found), _nic_roles(found)
    by_nic = [(_low(a.get("network_security_group_id")), nic_roles.get(_low(a.get("network_interface_id"))))
              for a in of_types(found, "azurerm_network_interface_security_group_association")]
    by_subnet = [(_low(a.get("network_security_group_id")), nic_roles.get(n))
                 for a in of_types(found, "azurerm_subnet_network_security_group_association")
                 for n, (_, subnet) in nics.items() if subnet and subnet == subnet_ref(a.get("subnet_id"))]
    pairs = [(g, r) for g, r in (*by_nic, *by_subnet) if r]
    return {g: tuple(r for g2, r in pairs if g2 == g) for g in dict.fromkeys(g for g, _ in pairs)}


def _target_role(nsg, guarded):
    roles = Counter(guarded.get(_low(nsg.get("id"))) or ())
    return (roles.most_common(1)[0][0] if roles else None) or _role(nsg) or \
        (nsg.get("name") or "").rsplit("-", 1)[-1] or None


# what claims a network security group, so its rules are its claimant's (a database's delegated subnet), not the
# record's firewall rules: each a function of the pairs -> the ids (lower case) of the groups it claims
CLAIMS = (database_security_groups,)


def _claimed(found):
    return frozenset().union(*(frozenset(claim(found)) for claim in CLAIMS))


def _firewall(found, claimed=frozenset()):
    """(firewall rules, notices): inbound allow rules of the security groups other readers don't claim, by rule
    name."""
    groups = {_low(g.get("id")): g for g in of_types(found, "azurerm_network_security_group")}
    guarded = _guarded_roles(found)
    separate = [(groups.get(k) or {}, r) for k, r in group_rules(found) if k not in claimed]
    allowed = [(g, r) for g, r in separate if r.get("name") and allows_in(r)]
    names = list(dict.fromkeys(r["name"] for _, r in allowed))

    def one_rule(name):
        mine = [(g, r) for g, r in allowed if r["name"] == name]
        protocol = next((_low(r.get("protocol")) for _, r in mine if _low(r.get("protocol")) in ("tcp", "udp")), None)
        return resource("firewall", name, {
            "ciamSourceCidr": sorted({source_cidr(p) for _, r in mine for p in rule_sources(r) if source_cidr(p)}),
            "ciamPort": sorted({p for _, r in mine for p in rule_ports(r) if p.isdigit()}, key=int),
            "ciamProtocol": protocol,
            "ciamRulePriority": next((r.get("priority") for _, r in mine if r.get("priority")), None),
            "ciamTargetRole": next((_target_role(g, guarded) for g, _ in mine if g), None)}, name=name)
    other = Counter(f"{_low(r.get('direction')) or '?'} {_low(r.get('access')) or '?'}"
                    for g, r in separate if (g, r) not in allowed)
    tags = sorted({(r["name"], p) for _, r in allowed for p in rule_sources(r) if not source_cidr(p)})
    ranges = sorted({(r["name"], p) for _, r in allowed for p in rule_ports(r) if not p.isdigit()})
    return (tuple(one_rule(n) for n in names),
            (*(f"security rules ({n} {kind}): not read (the record holds inbound allow rules)"
               for kind, n in sorted(other.items())),
             *(f"security rule {n}: source {p} is a service tag, not an address range; not recorded" for n, p in tags),
             *(f"security rule {n}: port {p} is not a single port; not recorded" for n, p in ranges)))


def _vault(a):
    return arm_segment(a.get("key_vault_id"), "vaults")


def _secrets(found):
    """Secret references from the secrets' vault and name alone; the value (and the version holding it) is never read."""
    return tuple(resource("secret", f"azkv://{_vault(a)}/{a.get('name')}",
                          {"ciamRefUri": f"azkv://{_vault(a)}/{a.get('name')}"},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "azurerm_key_vault_secret") if _vault(a) and a.get("name"))


def _key_url(url):
    """(vault, key name) of a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>[/<version>])."""
    host, _, path = (url or "").partition("://")[2].partition("/")
    parts = path.split("/")
    return (host.split(".")[0].lower(), parts[1].lower()) if len(parts) > 1 and parts[0] == "keys" else None


def _keys(found):
    sets = {_key_url(s.get("key_vault_key_id")): s.get("id") for s in of_types(found, "azurerm_disk_encryption_set")}

    def one_key(a):
        vault, name = _vault(a), a.get("name")
        policy = _first(a.get("rotation_policy")) or {}
        kind = a.get("key_type") or ""
        return resource("key", f"azkv-key://{vault}/keys/{name}", {
            "ciamRefUri": f"azkv-key://{vault}/keys/{name}",
            "ciamProtectionLevel": ("hsm" if kind.upper().endswith("-HSM") else "software") if kind else None,
            "ciamAutoRotate": ("TRUE" if policy.get("automatic") else "FALSE") if "rotation_policy" in a else None,
            "ciamProviderRef": sets.get((vault.lower(), name.lower()))},
            name=_tags(a).get("Name") or name, role=_role(a), tags=_tags(a))
    return tuple(one_key(a) for a in of_types(found, "azurerm_key_vault_key") if _vault(a) and a.get("name"))


def _egress(found):
    """NAT gateways by name, with the public addresses and prefixes associated with them (Standard public addresses:
    static)."""
    pips = {_low(p.get("id")): p.get("ip_address") for p in of_types(found, "azurerm_public_ip")}
    prefixes = {_low(p.get("id")): p.get("ip_prefix") for p in of_types(found, "azurerm_public_ip_prefix")}
    addresses = [(_low(a.get("nat_gateway_id")), f"{pips[_low(a.get('public_ip_address_id'))]}/32")
                 for a in of_types(found, "azurerm_nat_gateway_public_ip_association")
                 if pips.get(_low(a.get("public_ip_address_id")))]
    ranges = [(_low(a.get("nat_gateway_id")), prefixes[_low(a.get("public_ip_prefix_id"))])
              for a in of_types(found, "azurerm_nat_gateway_public_ip_prefix_association")
              if prefixes.get(_low(a.get("public_ip_prefix_id")))]
    def cidrs(nat):
        return sorted({c for g, c in (*addresses, *ranges) if g == _low(nat.get("id"))})
    return tuple(resource("egress", a.get("name"),
                          {"ciamCidr": cidrs(a), "ciamNatAllocation": "static" if cidrs(a) else None},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "azurerm_nat_gateway") if a.get("name"))


FUNCTION_APPS = ("azurerm_linux_function_app", "azurerm_windows_function_app")


def runtime(stack):
    """A function app's runtime from its application stack ({"python_version": "3.11"} -> "python 3.11")."""
    found = next(((k[:-len("_version")], v) for k, v in (stack or {}).items() if k.endswith("_version") and v), None)
    return f"{found[0]} {found[1]}" if found else None


def _timer_schedules(config_json):
    config = json_document(config_json, dict) if isinstance(config_json, str) else (config_json or {})
    return () if config is None else tuple(b.get("schedule") for b in config.get("bindings") or ()
                 if isinstance(b, dict) and _low(b.get("type")) == "timertrigger" and b.get("schedule"))


def _jobs(found):
    """Function apps, each with the schedules of its timer-triggered functions."""
    functions = [(_low(a.get("function_app_id")), _timer_schedules(a.get("config_json")))
                 for a in of_types(found, "azurerm_function_app_function")]

    def stack(a):
        config = _first(a.get("site_config")) or {}
        return _first(config.get("application_stack")) if isinstance(config, dict) else None
    return tuple(resource("job", a.get("id"), {"ciamRuntime": runtime(stack(a)),
                                               "ciamSchedule": sorted({s for app, ss in functions
                                                                       if app == _low(a.get("id")) for s in ss})},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, *FUNCTION_APPS) if a.get("id"))


SCALE_SETS = ("azurerm_linux_virtual_machine_scale_set", "azurerm_windows_virtual_machine_scale_set",
              "azurerm_orchestrated_virtual_machine_scale_set")
# AKS add-ons, by the argument that enables each: (argument, add-on name)
AKS_ADDONS = (("azure_policy_enabled", "azure-policy"), ("oms_agent", "oms-agent"),
              ("key_vault_secrets_provider", "key-vault-secrets-provider"),
              ("ingress_application_gateway", "ingress-application-gateway"),
              ("workload_identity_enabled", "workload-identity"), ("oidc_issuer_enabled", "oidc-issuer"),
              ("http_application_routing_enabled", "http-application-routing"),
              ("open_service_mesh_enabled", "open-service-mesh"), ("microsoft_defender", "defender"))


def _capacity(scale_set_id, found):
    """(minimum, maximum) of the autoscale setting targeting a scale set, or (None, None)."""
    setting = next((a for a in of_types(found, "azurerm_monitor_autoscale_setting")
                    if _low(a.get("target_resource_id")) == _low(scale_set_id)), {})
    cap = _first([c for p in setting.get("profile") or () for c in p.get("capacity") or ()]) or {}
    return cap.get("minimum"), cap.get("maximum")


def _compute(found):
    """Virtual machine scale sets as compute groups."""
    def group(a):
        binding, target = compute_roles(_tags(a))
        least, most = _capacity(a.get("id"), found)
        return resource("compute", a.get("id") or a.get("name"), {
            "ciamTargetRole": target, "ciamImageRef": _image(a), "ciamInstanceSize": a.get("sku") or a.get("sku_name"),
            "ciamMinSize": least, "ciamMaxSize": most, "ciamDesiredSize": a.get("instances"),
            "ciamSpansZone": sorted(a.get("zones") or ())}, name=a.get("name"), role=binding, tags=_tags(a))
    return tuple(group(a) for a in of_types(found, *SCALE_SETS) if a.get("id") or a.get("name"))


def _enabled(value):
    return value is True or (isinstance(value, list) and bool(value))


def _pool(p):
    return f"{p.get('name')}: {p.get('vm_size') or '?'}, {p.get('min_count') or p.get('node_count') or '?'}-" \
           f"{p.get('max_count') or p.get('node_count') or '?'}"


def _clusters(found):
    """AKS clusters, their node pools and enabled add-ons."""
    def cluster(c):
        pools = (*(c.get("default_node_pool") or ()),
                 *(p for p in of_types(found, "azurerm_kubernetes_cluster_node_pool")
                   if _low(p.get("kubernetes_cluster_id")) == _low(c.get("id"))))
        return resource("cluster", c.get("id") or c.get("name"), {
            "ciamClusterVersion": c.get("kubernetes_version"),
            "ciamClusterAddon": sorted(name for arg, name in AKS_ADDONS if _enabled(c.get(arg))),
            "ciamNodePool": sorted(_pool(p) for p in pools),
            "ciamSpansZone": sorted({z for p in pools for z in p.get("zones") or ()})},
            name=c.get("name"), role=cluster_role(_tags(c)), tags=_tags(c))
    return tuple(cluster(c) for c in of_types(found, "azurerm_kubernetes_cluster") if c.get("id") or c.get("name"))


ACS_SPF = "spf.protection.outlook.com"     # the SPF include that authorizes Azure Communication Services email
STREAM_TYPES = (("azurerm_servicebus_queue", "queue"), ("azurerm_servicebus_topic", "topic"),
                ("azurerm_eventhub", "event-hub"), ("azurerm_eventgrid_topic", "topic"))


def _fqdn(record):
    zone = (record.get("zone_name") or "").lower()
    return zone if record.get("name") == "@" else f"{(record.get('name') or '').lower()}.{zone}"


def _txt(found, name):
    return tuple(v for r in of_types(found, "azurerm_dns_txt_record") if _fqdn(r) == name.lower()
                 for rec in r.get("record") or () for v in ((rec.get("value"),) if isinstance(rec, dict) else ()) if v)


def _dkim(domain, found):
    """TRUE when every DKIM selector the domain's verification records name is a CNAME in Azure DNS, FALSE when one
    isn't, None when the domain names none."""
    records = _first(domain.get("verification_records")) or {}
    selectors = [r.get("name") for key in ("dkim", "dkim2") for r in records.get(key) or () if r.get("name")]
    if not selectors:
        return None
    zone = (domain.get("name") or "").lower()
    published = {_fqdn(c) for c in of_types(found, "azurerm_dns_cname_record")}
    return "TRUE" if all(f"{s.lower()}.{zone}" in published or s.lower() in published for s in selectors) else "FALSE"


def _sending(found):
    """Communication Services email domains (customer-managed) as sending identities."""
    def identity(a):
        domain = (a.get("name") or "").lower()
        return resource("sending", a.get("id") or domain, {
            "ciamSenderDomain": domain, "ciamDkimVerified": _dkim(a, found),
            "ciamSpfAuthorized": spf_authorizes(_txt(found, domain), ACS_SPF),
            "ciamDmarcPolicy": dmarc_policy(_txt(found, f"_dmarc.{domain}"))}, name=f"acs-{domain}", role=_role(a), tags=_tags(a))
    return tuple(identity(a) for a in of_types(found, "azurerm_email_communication_service_domain")
                 if a.get("domain_management") != "AzureManaged" and a.get("name"))


def _channels(found):
    """Action groups, as alert channels."""
    return tuple(resource("channel", a.get("id"), {"ciamChannelKind": "action-group"}, name=a.get("name"),
                          role=_role(a), tags=_tags(a))
                 for a in of_types(found, "azurerm_monitor_action_group") if a.get("id"))


def _log_destinations(found):
    """Log Analytics workspaces, with their retention."""
    return tuple(resource("logs", a.get("id"), {"ciamDestinationKind": "workspace",
                                                "ciamRetentionDays": a.get("retention_in_days")},
                          name=a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "azurerm_log_analytics_workspace") if a.get("id"))


def _metric_alarm(a):
    criteria = _first(a.get("criteria")) or _first(a.get("dynamic_criteria")) or {}
    named = " ".join(p for p in (criteria.get("metric_namespace"), criteria.get("metric_name")) if p)
    return named or None, sorted({x.get("action_group_id") for x in a.get("action") or () if x.get("action_group_id")})


def _query_alarm(a):
    return "log query", sorted({g for x in a.get("action") or () for g in x.get("action_groups") or ()})


ALARM_TYPES = (("azurerm_monitor_metric_alert", _metric_alarm),
               ("azurerm_monitor_scheduled_query_rules_alert_v2", _query_alarm))


def _alarms(found):
    """Metric and log-query alerts: what each evaluates, the action groups it notifies, the alert rule it realizes."""
    def alarm(a, read):
        role, realizes = realization_roles(_tags(a), "alarm")
        metric, notifies = read(a)
        return resource("alarm", a.get("id"), {"ciamMetric": metric, "ciamNotifies": notifies,
                                               "ciamRealizes": realizes}, name=a.get("name"), role=role,
                        tags=_tags(a))
    return tuple(alarm(a, read) for t, read in ALARM_TYPES for a in of_types(found, t) if a.get("id"))


def _canaries(found):
    """Application Insights standard web tests: how often each runs, the canary it realizes."""
    def canary(a):
        role, realizes = realization_roles(_tags(a), "canary")
        return resource("canary", a.get("id"), {"ciamInterval": duration_text(a.get("frequency")),
                                                "ciamRealizes": realizes}, name=a.get("name"), role=role,
                        tags=_tags(a))
    return tuple(canary(a) for a in of_types(found, "azurerm_application_insights_standard_web_test") if a.get("id"))


def _streams(found):
    """Service Bus queues and topics, Event Hubs and Event Grid topics as stream carriers."""
    return tuple(resource("stream", a.get("id"), {"ciamStreamKind": kind}, name=a.get("name"), role=_role(a), tags=_tags(a))
                 for t, kind in STREAM_TYPES for a in of_types(found, t) if a.get("id"))


def pairs_resources(pairs):
    """(resources, notices) of (Terraform resource type, attributes) pairs: what every Azure source is read into
    (Terraform state as it is; CLI output normalized to the same attribute names, opsdir_adapter_azure.cli)."""
    rules, rule_notices = _firewall(pairs, _claimed(pairs))
    iam, iam_notices = iam_resources(pairs)
    services = _services(pairs)
    edge, edge_notices = _edge(pairs, services)
    network, network_notices = network_resources(pairs)
    volumes, volume_notices = volume_resources(pairs)
    backups, backup_notices = backup_resources(pairs)
    return ((*_networks(pairs), *_subnets(pairs), *_servers(pairs), *services, *rules, *_secrets(pairs),
             *_keys(pairs), *object_store_resources(pairs), *_egress(pairs), *_jobs(pairs), *_compute(pairs),
             *_clusters(pairs),
             *_sending(pairs), *_streams(pairs), *_channels(pairs), *_log_destinations(pairs), *_alarms(pairs),
             *_canaries(pairs), *iam, *edge, *network, *database_resources(pairs), *volumes, *backups,
             *trail_resources(pairs), *security_resources(pairs), *budget_resources(pairs)),
            (*rule_notices, *iam_notices, *edge_notices, *network_notices, *volume_notices, *backup_notices,
             *geo_backup_notices(pairs)))


def state_resources(text):
    """(resources, notices) of an Azure Terraform state."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = [(r.type, r.attributes) for r in found]
    skipped = Counter(t for t, _ in pairs if t in SKIPPED)
    resources, notices = pairs_resources(pairs)
    return (resources,
            (*(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)" for t, n in sorted(skipped.items())),
             *notices))


def read_terraform_state(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the Azure Terraform states under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "Azure", per_file(state_resources), ".tfstate", "Terraform state",
                         "terraform.tfstate", summarize=("identity",))   # groups, users, service agents: counted


TERRAFORM_STATE = Importer("terraform-state", "Azure Terraform state (terraform.tfstate) under <cloud>/<env>/, as "
                                              "the environment's servers and bindings", read_terraform_state)
