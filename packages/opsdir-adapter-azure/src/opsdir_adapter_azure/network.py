"""Azure: what the stack renders of its network depth (opsdir.domains.network.stack). Private endpoints to the
resources its bindings reach (a Key Vault, a storage account, a namespace: one endpoint per resource, the subresource
its service is reached by), in its subnet, with a static address when recorded and the private DNS zone group when it
answers the service's usual name. Private Link Services exposing a service name's Standard load balancer frontend: a
NAT address in the subnet recorded, visible to the subscriptions recorded, approved automatically for the allowed
principals unless each connection waits for acceptance; a service on an Application Gateway is not (it has its own
private link configuration). An egress firewall the stack keeps gets its allowlist as an application rule collection
group in its Firewall policy. What someone else keeps is a comment naming them. What it leaves out or to a person is
a render note (core.notes, flow 43) written as its comment: endpoint_notes, link_service_note, firewall_notes, all of
them network_notes. Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.notes import RECORD, note_comment
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.network.plumbing import network_note
from opsdir.domains.network.stack import (allowlist, egress_firewalls, elsewhere, endpoint_services, private_endpoints,
                                          reached, subnets)
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_name
from .identities import LOC, RG
from .account import government, tagged

# the private link subresource (group id) a private endpoint to each kind of service connects to, and the private DNS
# zone that answers it (Azure's public cloud)
SUBRESOURCES = {"secrets": ("vault", "privatelink.vaultcore.azure.net"),
                "keys": ("vault", "privatelink.vaultcore.azure.net"),
                "object-storage": ("blob", "privatelink.blob.core.windows.net"),
                "messaging": ("namespace", "privatelink.servicebus.windows.net"),
                "registry": ("registry", "privatelink.azurecr.io")}
# the zone in Azure Government: Microsoft's private endpoint DNS zone values, Government section (research 2909;
# Container Registry's data endpoints answer in {region}.privatelink.azurecr.us too)
GOV_ZONES = {"secrets": "privatelink.vaultcore.usgovcloudapi.net", "keys": "privatelink.vaultcore.usgovcloudapi.net",
             "object-storage": "privatelink.blob.core.usgovcloudapi.net",
             "messaging": "privatelink.servicebus.usgovcloudapi.net", "registry": "privatelink.azurecr.us"}


def private_dns_zone(m, what):
    """The private DNS zone that answers a private endpoint to a kind of service in environment m's cloud (Azure
    Government's in usgovernment)."""
    return GOV_ZONES[what] if government(m) else SUBRESOURCES[what][1]


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
        return ((tf_block("data", ["azurerm_key_vault", f"{n}_{tf_name(vault)}"],
                          [("name", vault), ("resource_group_name", RG)]),),
                ref(f"data.azurerm_key_vault.{n}_{tf_name(vault)}.id"))
    if store.startswith("azblob://"):
        account = store.split("://", 1)[1].split("/", 1)[0]
        return ((tf_block("data", ["azurerm_storage_account", f"{n}_{tf_name(account)}"],
                          [("name", account), ("resource_group_name", RG)]),),
                ref(f"data.azurerm_storage_account.{n}_{tf_name(account)}.id"))
    return None


def _endpoint(m, p, name, target, group, sub):
    zone = one(p, "ciamDnsZoneRef")
    dns = (() if one(p, "ciamPrivateDns") != "TRUE" else
           (("private_dns_zone_group", Block((("name", "default"), ("private_dns_zone_ids", [zone])))),) if zone else
           (("#", "UNBOUND: private DNS asked, but no private DNS zone ref (zone "
                  f"{one(p, 'ciamDnsZone') or private_dns_zone(m, one(p, 'ciamPrivateService'))})"),))
    ip = one(p, "ciamFrontendIp")
    return tf_block("resource", ["azurerm_private_endpoint", name], [
        ("name", f"pe-ciam-{rdn_value(m.env)}-{rdn_value(p)}"), ("location", LOC), ("resource_group_name", RG),
        ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(sub))}.id")) if sub is not None
        else ("#", "UNBOUND: the endpoint names no subnet this environment binds"),
        ("private_service_connection", Block((
            ("name", rdn_value(p)), ("private_connection_resource_id", target), ("subresource_names", [group]),
            ("is_manual_connection", False)))),
        *((("ip_configuration", Block((("name", "primary"), ("private_ip_address", ip), ("subresource_name", group),
                                        ("member_name", "default")))),) if ip else ()),
        *dns, ("tags", tagged(m, binding_tags(p)))])


def endpoint_notes(m, p):
    """The render notes (blockers) of a private endpoint private_endpoint doesn't render: a kind other than
    interface (another provider's, or a subnet's service endpoints), a service it doesn't reach by private endpoint;
    () when it renders."""
    kind, what = one(p, "ciamPrivateEndpointKind", "interface"), one(p, "ciamPrivateService")
    if kind != "interface":
        return (network_note(m, p, "blocker", f"Azure's private endpoints are interface endpoints ({kind} is another "
                             "provider's kind, or a subnet's service endpoints, which the landing zone keeps): not "
                             "rendered", (f"Record it as an interface endpoint (ciamPrivateEndpointKind), or ask the "
                                          f"landing zone for the subnets' service endpoints, {RECORD}",)),)
    if what not in SUBRESOURCES:
        return (network_note(m, p, "blocker", f"{what} isn't a service this render reaches by private endpoint (Key "
                             "Vault, storage, Service Bus, Container Registry): not rendered",
                             ("Create the private endpoint by hand with the target's resource id and subresource",)),)
    return ()


def private_endpoint(m, p):
    """Private endpoints the stack keeps, one per resource its bindings reach (with the data sources naming them); its
    notes' comments for a service or kind Azure doesn't reach this way (endpoint_notes)."""
    n, what = tf_name(rdn_value(p)), one(p, "ciamPrivateService")
    noted = endpoint_notes(m, p)
    if noted:
        return tuple(comment(note_comment(x)) for x in noted)
    found = tuple(dict((r[1], r) for r in (_resource(b, n) for b in reached(m, p)) if r is not None).values())
    if not found:
        return (comment(f"UNBOUND: private endpoint '{rdn_value(p)}' reaches nothing this environment binds"),)
    sub = next(iter(subnets(m, p)), None)
    return tuple(x for i, (data, target) in enumerate(found) for x in (
        *data, _endpoint(m, p, n if len(found) == 1 else f"{n}_{i}", target, SUBRESOURCES[what][0], sub)))


def link_service_note(m, e, svc, endpoints=()):
    """The render note (a blocker) of an endpoint service whose service name runs on an Application Gateway (its
    traffic policy layer 7, or a CDN): a Private Link Service needs a Standard load balancer frontend; else None."""
    spec = service_edge(m, svc, endpoints) if svc is not None else None
    if spec is None or not (spec.layer7 or spec.cdn):
        return None
    return network_note(m, e, "blocker", f"{rdn_value(svc)} runs on an Application Gateway (its own private link "
                        "configuration); a Private Link Service needs a Standard load balancer frontend: not rendered",
                        ("Configure the Application Gateway's private link by hand, or expose a service name on a "
                         f"passthrough load balancer (layer 4, no CDN in its protection policy), {RECORD}",))


def link_service(m, e, svc, endpoints=()):
    """A Private Link Service on the Standard load balancer frontend of the service name it exposes; a comment when
    the name isn't bound, its note's when it runs on an Application Gateway (link_service_note)."""
    role = one(e, "ciamServiceRole")
    if svc is None:
        return (comment(f"UNBOUND: endpoint service '{rdn_value(e)}' exposes {role}, which this environment doesn't "
                        "bind"),)
    noted = link_service_note(m, e, svc, endpoints)
    if noted is not None:
        return (comment(note_comment(noted)),)
    sub = next(iter(subnets(m, e)), None)
    manual = one(e, "ciamAcceptanceRequired") == "TRUE"
    return (tf_block("resource", ["azurerm_private_link_service", tf_name(rdn_value(e))], [
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
        ("tags", tagged(m, binding_tags(e)))]),)


WEB = {80: "Http", 443: "Https"}     # what application rules can match: web traffic by its host name


def firewall_notes(m, proxy):
    """The render notes of an egress firewall's rule collection group: an action when sites on other ports than 80
    and 443 become network rules by FQDN, which need the firewall policy's DNS proxy."""
    other = tuple(f"{h}:{port}" for port, hosts in allowlist(proxy) if port not in WEB for h in hosts)
    return (network_note(m, proxy, "action", f"FQDNs in network rules ({', '.join(other)}) need the firewall policy's "
                         "DNS proxy", ("Turn on the firewall policy's DNS proxy where the policy is kept",)),) \
        if other else ()


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
    return (tf_block("resource", ["azurerm_firewall_policy_rule_collection_group", f"{n}_sites"], [
        ("name", f"ciam-{rdn_value(m.env)}-sites"),
        ("firewall_policy_id", policy) if policy
        else ("#", "UNBOUND: the egress firewall's policy has no provider ref"),
        ("priority", 500),
        *((("application_rule_collection", Block((
            ("name", f"ciam-{rdn_value(m.env)}-sites"), ("priority", 500), ("action", "Allow"), *web))),)
          if web else ()),
        *((("network_rule_collection", Block((
            *(("#", note_comment(x)) for x in firewall_notes(m, proxy)),
            ("name", f"ciam-{rdn_value(m.env)}-sites-other"), ("priority", 510), ("action", "Allow"), *other))),)
          if other else ()),
    ]),)


def network_notes(m, endpoints=()):
    """The render notes of environment m's network depth the stack renders (render_network): its own private
    endpoints', endpoint services' and egress firewalls'."""
    return (*(x for p in private_endpoints(m) for x in endpoint_notes(m, p)),
            *(x for e, svc in endpoint_services(m) for x in (link_service_note(m, e, svc, endpoints),)
              if x is not None),
            *(x for f in egress_firewalls(m) for x in firewall_notes(m, f)))


def render_network(m, endpoints=()):
    """HCL blocks for environment m's network depth the stack keeps, after comments naming what others keep; () when
    the record has none."""
    return (*(comment(s) for s in elsewhere(m)),
            *(x for p in private_endpoints(m) for x in private_endpoint(m, p)),
            *(x for e, svc in endpoint_services(m) for x in link_service(m, e, svc, endpoints)),
            *(x for f in egress_firewalls(m) for x in application_rules(m, f)))
