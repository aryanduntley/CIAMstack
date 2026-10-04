"""Azure edge: what the edge domain's terms mean on Azure, and the Terraform for a service whose policies ask for more
than a TCP passthrough. A service name whose TLS terminates at the edge is an Application Gateway v2 (WAF_v2 when a
protection policy asks for inspection) in the subnet the environment binds to role subnet-edge: listeners per port with
the TLS policy and the certificate the environment keeps in Key Vault (read by the gateway's own managed identity),
backend settings with the policy's health probe, cookie affinity, request timeout and draining. Its protection policy
is a WAF policy on the gateway: the Default Rule Set and Bot Manager, custom rules for rate limits aimed at the
products' endpoints, addresses and countries, and exclusions. A passthrough service stays a Standard load balancer, with
the policy's health probe, idle timeout and source-address affinity. Pure.

Known limits: Azure's WAF exclusions apply to every path, not only the endpoint kind named; a rate limit keyed by a
header is grouped by client address; DDoS Network Protection is a plan on the virtual network the landing zone keeps.
"""
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import by_role
from opsdir.core.network import is_private
from opsdir.domains.edge.resolve import inspected, path_regex, tls_policy
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .identities import LOC, RG

EDGE_SUBNET = "subnet-edge"            # the binding role of the subnet the gateways go in
# (min version, profile, predefined Application Gateway TLS policy, exact)
TLS_POLICIES = (("1.3", "modern", "AppGwSslPolicy20220101S", False),
                ("1.3", "intermediate", "AppGwSslPolicy20220101S", False),
                ("1.3", "compatible", "AppGwSslPolicy20220101S", False),
                ("1.2", "modern", "AppGwSslPolicy20220101S", True),
                ("1.2", "intermediate", "AppGwSslPolicy20220101", True),
                ("1.2", "compatible", "AppGwSslPolicy20170401S", False))
# WAF category -> (managed rule set, version) of an Application Gateway WAF policy; None: not offered (named in a
# comment)
WAF_RULE_SETS = {"core-rules": ("Microsoft_DefaultRuleSet", "2.1"),
                 "known-bad-inputs": ("Microsoft_DefaultRuleSet", "2.1"),
                 "bot-control": ("Microsoft_BotManagerRuleSet", "1.1"),
                 "ip-reputation": ("Microsoft_BotManagerRuleSet", "1.1"), "account-takeover": None,
                 "account-creation-fraud": None}
EXCLUDED_VARIABLE = {"body": "RequestArgNames", "query": "RequestArgNames", "header": "RequestHeaderNames",
                     "cookie": "RequestCookieNames"}


def rate(requests, seconds):
    """(threshold, duration) for a rate limit: one or five minutes, the requests scaled to it (rounded up)."""
    duration, span = ("OneMin", 60) if seconds <= 60 else ("FiveMins", 300)
    return max(1, -(-requests * span // seconds)), duration


def _custom_rules(spec):
    action = "Log" if spec.waf_mode == "detect" else "Block"
    rules, priority = [], 1

    def rule(name, kind, conditions, act, extra=()):
        nonlocal priority
        rules.append(("custom_rules", Block((("name", name), ("priority", priority), ("rule_type", kind),
                                             *extra, *conditions, ("action", act)))))
        priority += 1
    for i, (act, cidr) in enumerate(spec.ip_rules):
        rule(f"{act}addresses{i}", "MatchRule", (("match_conditions", Block((
            ("match_variables", Block((("variable_name", "RemoteAddr"),))), ("operator", "IPMatch"),
            ("match_values", [cidr])))),), "Allow" if act == "allow" else action)
    for i, (act, codes) in enumerate(spec.geo_rules):
        rule(f"geo{i}", "MatchRule", (("match_conditions", Block((
            ("match_variables", Block((("variable_name", "RemoteAddr"),))), ("operator", "GeoMatch"),
            ("negation_condition", act == "allow"), ("match_values", list(codes))))),), action)
    for r in spec.rate_limits:
        threshold, duration = rate(r.requests, r.seconds)
        paths = (("match_conditions", Block((("match_variables", Block((("variable_name", "RequestUri"),))),
                                             ("operator", "Regex"),
                                             ("match_values", [path_regex(p) for p in r.paths])))),) \
            if r.paths else (("match_conditions", Block((
                ("match_variables", Block((("variable_name", "RequestUri"),))), ("operator", "Any")))),)
        note = (("#", f"grouped by client address: Azure can't group by {r.key}"),) if r.key != "ip" else ()
        rule(f"rate{tf_name(r.kind).replace('_', '')}", "RateLimitRule", paths, action,
             (*note, ("rate_limit_duration", duration), ("rate_limit_threshold", threshold),
              ("group_rate_limit_by", "ClientAddr")))
    return tuple(rules)


def _managed_rules(spec):
    sets = dict.fromkeys(WAF_RULE_SETS[c] for c in spec.categories if WAF_RULE_SETS.get(c))
    missing = [c for c in spec.categories if not WAF_RULE_SETS.get(c)]
    exclusions = tuple(("exclusion", Block((
        ("match_variable", EXCLUDED_VARIABLE[x.part]), ("selector", x.name), ("selector_match_operator", "Equals"),
        *((("excluded_rule_set", Block((("type", WAF_RULE_SETS[x.category][0]),
                                        ("version", WAF_RULE_SETS[x.category][1])))),)
          if WAF_RULE_SETS.get(x.category) else ()))))
        for x in spec.exclusions)
    return ("managed_rules", Block((
        *((("#", f"not offered by Application Gateway WAF: {', '.join(missing)}"),) if missing else ()),
        *((("#", "exclusions apply on every path, not only the endpoint kind named"),) if exclusions else ()),
        *exclusions,
        *(("managed_rule_set", Block((("type", t), ("version", v)))) for t, v in sets or
          (("Microsoft_DefaultRuleSet", "2.1"),)))))


def waf_policy(m, n, spec):
    """The Application Gateway WAF policy a protection policy asks for."""
    return block("resource", ["azurerm_web_application_firewall_policy", n], [
        ("name", f"waf-ciam-{rdn_value(m.env)}-{n}"), ("resource_group_name", RG),
        ("location", LOC),
        ("policy_settings", Block((("enabled", True),
                                   ("mode", "Detection" if spec.waf_mode == "detect" else "Prevention"),
                                   ("request_body_check", True)))),
        *_custom_rules(spec), _managed_rules(spec), ("tags", {"ManagedBy": "opsdir"})])


def _key_vault(spec):
    """(vault, certificate name) of an azkv-cert reference, or None."""
    ref_uri = spec.certificate or ""
    return tuple(ref_uri.split("://", 1)[1].split("/", 1)) if ref_uri.startswith("azkv-cert://") else None


def _certificate(m, n, spec):
    """The gateway's identity able to read its certificate from Key Vault, and the ssl_certificate body."""
    kv = _key_vault(spec)
    if kv is None:
        return (), (("#", "UNBOUND: no Key Vault certificate holds this service's certificate in this "
                          "environment"),), ()
    vault, name = kv
    return ((block("resource", ["azurerm_user_assigned_identity", f"{n}_gateway"], [
                ("name", f"id-agw-ciam-{rdn_value(m.env)}-{n}"), ("resource_group_name", RG), ("location", LOC)]),
             block("data", ["azurerm_key_vault", f"{n}_tls"], [("name", vault), ("resource_group_name", RG)]),
             block("resource", ["azurerm_role_assignment", f"{n}_gateway_certificate"], [
                 ("scope", ref(f"data.azurerm_key_vault.{n}_tls.id")),
                 ("role_definition_name", "Key Vault Secrets User"),
                 ("principal_id", ref(f"azurerm_user_assigned_identity.{n}_gateway.principal_id"))])),
            (("ssl_certificate", Block((("name", "tls"), ("key_vault_secret_id", ref(
                f'"${{data.azurerm_key_vault.{n}_tls.vault_uri}}secrets/{name}"'))))),),
            (("identity", Block((("type", "UserAssigned"),
                                 ("identity_ids", [ref(f"azurerm_user_assigned_identity.{n}_gateway.id")])))),))


def _frontend(svc, n, ip, subnet):
    if ip and is_private(ip):
        return (("frontend_ip_configuration", Block((("name", "frontend"), ("subnet_id", subnet),
                                                     ("private_ip_address_allocation", "Static"),
                                                     ("private_ip_address", ip)))),)
    return (("frontend_ip_configuration", Block((("name", "frontend"),
                                                 ("public_ip_address_id", ref(f"data.azurerm_public_ip.{n}.id"))))),)


def _probe(svc, spec, port):
    h = spec.health
    protocol = "Https" if (h.protocol == "https" or (h.protocol == "tcp" and spec.mode == "reencrypt")) else "Http"
    return ("probe", Block((("name", f"health-{port}"), ("protocol", protocol), ("host", one(svc, "ciamFqdn")),
                            ("path", h.path or "/"), ("interval", h.interval or 30),
                            ("timeout", min(30, h.interval or 30)),
                            ("unhealthy_threshold", h.unhealthy or 3),
                            ("match", Block((("status_code", ["200-399"]),))))))


def gateway_service(m, svc, spec, targets):
    """An Application Gateway v2 for a service name whose TLS terminates at the edge, its certificate access, its
    WAF policy, and the DNS record's address; or comments naming what's unbound."""
    n, ip = tf_name(rdn_value(svc)), one(svc, "ciamFrontendIp")
    ports = tuple(values(svc, "ciamPort"))
    subnets = by_role(m, EDGE_SUBNET)
    if not subnets:
        return (f"# UNBOUND: `{one(svc, 'ciamFqdn')}` terminates TLS at an Application Gateway, which needs its own "
                f"subnet: bind role {EDGE_SUBNET} in this environment",)
    subnet = ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnets[0]))}.id")
    policy, exact = tls_policy(TLS_POLICIES, spec.tls_min, spec.tls_profile)
    access, certificate, identity = _certificate(m, n, spec)
    waf = inspected(spec) and not spec.cdn          # with a CDN in front, the CDN inspects
    backend = "Https" if spec.mode == "reencrypt" else "Http"
    sku = "WAF_v2" if waf else "Standard_v2"
    body = (
        ("name", f"agw-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("resource_group_name", RG), ("location", LOC),
        ("zones", ["1", "2", "3"]),
        ("sku", Block((("name", sku), ("tier", sku)))),
        ("autoscale_configuration", Block((("min_capacity", 2), ("max_capacity", 10)))),
        *identity,
        ("gateway_ip_configuration", Block((("name", "gateway"), ("subnet_id", subnet)))),
        *_frontend(svc, n, ip, subnet),
        *(("frontend_port", Block((("name", f"port-{p}"), ("port", int(p))))) for p in ports),
        ("backend_address_pool", Block((("name", "servers"),
                                        ("ip_addresses", [one(t, "ciamPrivateIp") for t in targets])))),
        *chain.from_iterable((
            ("backend_http_settings", Block((
                ("name", f"servers-{p}"), ("port", int(p)), ("protocol", backend),
                ("cookie_based_affinity", "Enabled" if spec.stickiness == "cookie" else "Disabled"),
                *((("#", f"{spec.stickiness} affinity isn't offered by Application Gateway"),)
                  if spec.stickiness == "source-ip" else ()),
                ("request_timeout", spec.idle_timeout or 30),
                *((("host_name", one(svc, "ciamFqdn")),) if backend == "Https" else ()),
                *((("#", "Application Gateway v2 validates the servers' certificates (chain and name)"),)
                  if backend == "Https" and spec.backend_validation == "none" else ()),
                ("probe_name", f"health-{p}"),
                *((("connection_draining", Block((("enabled", True), ("drain_timeout_sec", spec.drain)))),)
                  if spec.drain else ())))),
            _probe(svc, spec, p),
            ("http_listener", Block((("name", f"listener-{p}"), ("frontend_ip_configuration_name", "frontend"),
                                     ("frontend_port_name", f"port-{p}"), ("protocol", "Https"),
                                     *((("ssl_certificate_name", "tls"),) if certificate and
                                       certificate[0][0] == "ssl_certificate" else ())))),
            ("request_routing_rule", Block((("name", f"route-{p}"), ("priority", 100 + i), ("rule_type", "Basic"),
                                            ("http_listener_name", f"listener-{p}"),
                                            ("backend_address_pool_name", "servers"),
                                            ("backend_http_settings_name", f"servers-{p}")))))
            for i, p in enumerate(ports)),
        *certificate,
        ("ssl_policy", Block((("policy_type", "Predefined"), ("policy_name", policy),
                              *((("#", f"nearest policy to TLS {spec.tls_min} {spec.tls_profile}"),)
                                if not exact else ())))),
        *((("firewall_policy_id", ref(f"azurerm_web_application_firewall_policy.{n}.id")),) if waf else ()),
        ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"}),
        *((("depends_on", [ref(f"azurerm_role_assignment.{n}_gateway_certificate")]),) if access else ()))
    public = (block("data", ["azurerm_public_ip", n], [("name", one(svc, "ciamProviderRef")),
                                                       ("resource_group_name", RG)]),) \
        if not (ip and is_private(ip)) else ()
    return (*public, *access, *((waf_policy(m, n, spec),) if waf else ()),
            *ddos_note(spec), block("resource", ["azurerm_application_gateway", n], list(body)))


def ddos_note(spec):
    """DDoS protection beyond standard: a plan on the virtual network, which the landing zone keeps."""
    return () if spec.ddos == "standard" else (
        f"# DDoS {spec.ddos}: DDoS Network Protection is a plan linked to the virtual network the landing zone keeps "
        "(or IP Protection on the public address): ask its owners",)
