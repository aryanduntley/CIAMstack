"""Azure: what the stack renders of its network depth (opsdir.domains.network.stack). Private endpoints to the
resources its bindings reach (a Key Vault, a storage account, a namespace: one endpoint per resource, the subresource
its service is reached by), in its subnet, with a static address when recorded and the private DNS zone group when it
answers the service's usual name. Private Link Services exposing a service name's Standard load balancer frontend: a
NAT address in the subnet recorded, visible to the subscriptions recorded, approved automatically for the allowed
principals unless each connection waits for acceptance; a service on an Application Gateway is not (it has its own
private link configuration). An egress firewall the stack keeps gets its allowlist as an application rule collection
group in its Firewall policy. What someone else keeps is a comment naming them. Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.network.stack import (allowlist, egress_firewalls, elsewhere, endpoint_services, private_endpoints,
                                          reached, subnets)
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .identities import LOC, RG

# the private link subresource (group id) a private endpoint to each kind of service connects to, and the private DNS
# zone that answers it
SUBRESOURCES = {"secrets": ("vault", "privatelink.vaultcore.azure.net"),
                "keys": ("vault", "privatelink.vaultcore.azure.net"),
                "object-storage": ("blob", "privatelink.blob.core.windows.net"),
                "messaging": ("namespace", "privatelink.servicebus.windows.net"),
                "registry": ("registry", "privatelink.azurecr.io")}


def binding_tags(b):
    """The tags a rendered binding carries: its role (what the importers read it back by) and opsdir's mark."""
    return {"Role": one(b, "ciamBindingRole"), "ManagedBy": "opsdir"}


def _resource(b, n):
    """(data blocks, resource id) of what a reached binding names: its provider ref when that is a resource id, the
    Key Vault of a secret or key, the storage account of a container; None when it names none of these."""
    pref, uri, store = one(b, "ciamProviderRef") or "", one(b, "ciamRefUri") or "", one(b, "ciamStorageRef") or ""
    if pref.startswith("/subscriptions/"):
        return (), pref
    if uri.startswith(("azkv://", "azkv-key://")):
        vault = uri.split("://", 1)[1].split("/", 1)[0]
        return ((block("data", ["azurerm_key_vault", f"{n}_{tf_name(vault)}"],
                       [("name", vault), ("resource_group_name", RG)]),),
                ref(f"data.azurerm_key_vault.{n}_{tf_name(vault)}.id"))
    if store.startswith("azblob://"):
        account = store.split("://", 1)[1].split("/", 1)[0]
        return ((block("data", ["azurerm_storage_account", f"{n}_{tf_name(account)}"],
                       [("name", account), ("resource_group_name", RG)]),),
                ref(f"data.azurerm_storage_account.{n}_{tf_name(account)}.id"))
    return None


def _endpoint(m, p, name, target, group, sub):
    zone = one(p, "ciamDnsZoneRef")
    dns = (() if one(p, "ciamPrivateDns") != "TRUE" else
           (("private_dns_zone_group", Block((("name", "default"), ("private_dns_zone_ids", [zone])))),) if zone else
           (("#", "UNBOUND: private DNS asked, but no private DNS zone ref (zone "
                  f"{one(p, 'ciamDnsZone') or SUBRESOURCES[one(p, 'ciamPrivateService')][1]})"),))
    ip = one(p, "ciamFrontendIp")
    return block("resource", ["azurerm_private_endpoint", name], [
        ("name", f"pe-ciam-{rdn_value(m.env)}-{rdn_value(p)}"), ("location", LOC), ("resource_group_name", RG),
        ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(sub))}.id")) if sub is not None
        else ("#", "UNBOUND: the endpoint names no subnet this environment binds"),
        ("private_service_connection", Block((
            ("name", rdn_value(p)), ("private_connection_resource_id", target), ("subresource_names", [group]),
            ("is_manual_connection", False)))),
        *((("ip_configuration", Block((("name", "primary"), ("private_ip_address", ip), ("subresource_name", group),
                                        ("member_name", "default")))),) if ip else ()),
        *dns, ("tags", binding_tags(p))])


def private_endpoint(m, p):
    """Private endpoints the stack keeps, one per resource its bindings reach (with the data sources naming them); a
    comment for a service or kind Azure doesn't reach this way."""
    n, kind, what = tf_name(rdn_value(p)), one(p, "ciamPrivateEndpointKind", "interface"), one(p, "ciamPrivateService")
    if kind != "interface":
        return (f"# Private endpoint '{rdn_value(p)}': Azure's private endpoints are interface endpoints ({kind} "
                "is another provider's kind, or a subnet's service endpoints, which the landing zone keeps). "
                "Not rendered.",)
    if what not in SUBRESOURCES:
        return (f"# Private endpoint '{rdn_value(p)}' to {what}: record the target's resource id as its provider ref "
                "and its subresource; not rendered.",)
    found = tuple(dict((r[1], r) for r in (_resource(b, n) for b in reached(m, p)) if r is not None).values())
    if not found:
        return (f"# UNBOUND: private endpoint '{rdn_value(p)}' reaches nothing this environment binds",)
    sub = next(iter(subnets(m, p)), None)
    return tuple(x for i, (data, target) in enumerate(found) for x in (
        *data, _endpoint(m, p, n if len(found) == 1 else f"{n}_{i}", target, SUBRESOURCES[what][0], sub)))


def link_service(m, e, svc, endpoints=()):
    """A Private Link Service on the Standard load balancer frontend of the service name it exposes; a comment when
    the name isn't bound or runs on an Application Gateway."""
    role = one(e, "ciamServiceRole")
    if svc is None:
        return (f"# UNBOUND: endpoint service '{rdn_value(e)}' exposes {role}, which this environment doesn't bind",)
    spec = service_edge(m, svc, endpoints)
    if spec is not None and (spec.layer7 or spec.cdn):
        return (f"# Endpoint service '{rdn_value(e)}': {rdn_value(svc)} runs on an Application Gateway (its own "
                "private link configuration); a Private Link Service needs a Standard load balancer frontend. "
                "Not rendered.",)
    sub = next(iter(subnets(m, e)), None)
    manual = one(e, "ciamAcceptanceRequired") == "TRUE"
    return (block("resource", ["azurerm_private_link_service", tf_name(rdn_value(e))], [
        ("name", f"pls-ciam-{rdn_value(m.env)}-{rdn_value(e)}"), ("location", LOC), ("resource_group_name", RG),
        ("load_balancer_frontend_ip_configuration_ids",
         [ref(f"azurerm_lb.{tf_name(rdn_value(svc))}.frontend_ip_configuration[0].id")]),
        ("nat_ip_configuration", Block((
            ("name", "primary"), ("primary", True),
            ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(sub))}.id")) if sub is not None
            else ("#", "UNBOUND: no NAT subnet recorded (ciamSubnetRole)")))),
        *((("visibility_subscription_ids", values(e, "ciamVisibleTo")),) if values(e, "ciamVisibleTo") else ()),
        *((("auto_approval_subscription_ids", values(e, "ciamAllowedPrincipal")),)
          if values(e, "ciamAllowedPrincipal") and not manual else ()),
        ("tags", binding_tags(e))]),)


WEB = {80: "Http", 443: "Https"}     # what application rules can match: web traffic by its host name


def application_rules(m, proxy):
    """An egress firewall's allowlist as a rule collection group in its Firewall policy, from the network's range:
    application rules for web ports (HTTP on 80, where certificate status is fetched; HTTPS on 443), network rules by
    FQDN for other ports (a mail relay), which need the firewall's DNS proxy."""
    n, policy = tf_name(rdn_value(proxy)), one(proxy, "ciamProviderRef")
    net = one_role(m, "network")
    sources = values(net, "ciamCidr") if net is not None else []
    sites = allowlist(proxy)
    web = tuple(("rule", Block((("name", f"sites-{port}"), ("protocols", Block((("type", WEB[port]), ("port", port)))),
                                ("source_addresses", sources), ("destination_fqdns", list(hosts)))))
                for port, hosts in sites if port in WEB)
    other = tuple(("rule", Block((("name", f"sites-{port}"), ("protocols", ["TCP"]), ("source_addresses", sources),
                                  ("destination_fqdns", list(hosts)), ("destination_ports", [str(port)]))))
                  for port, hosts in sites if port not in WEB)
    return (block("resource", ["azurerm_firewall_policy_rule_collection_group", f"{n}_sites"], [
        ("name", f"ciam-{rdn_value(m.env)}-sites"),
        ("firewall_policy_id", policy) if policy
        else ("#", "UNBOUND: the egress firewall's policy has no provider ref"),
        ("priority", 500),
        *((("application_rule_collection", Block((
            ("name", f"ciam-{rdn_value(m.env)}-sites"), ("priority", 500), ("action", "Allow"), *web))),)
          if web else ()),
        *((("network_rule_collection", Block((
            ("#", "FQDNs in network rules need the firewall policy's DNS proxy"),
            ("name", f"ciam-{rdn_value(m.env)}-sites-other"), ("priority", 510), ("action", "Allow"), *other))),)
          if other else ()),
    ]),)


def render_network(m, endpoints=()):
    """HCL blocks for environment m's network depth the stack keeps, after comments naming what others keep; () when
    the record has none."""
    return (*(f"# {s}" for s in elsewhere(m)),
            *(x for p in private_endpoints(m) for x in private_endpoint(m, p)),
            *(x for e, svc in endpoint_services(m) for x in link_service(m, e, svc, endpoints)),
            *(x for f in egress_firewalls(m) for x in application_rules(m, f)))
