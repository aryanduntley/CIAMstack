"""Azure CDN: Front Door (Premium when it inspects requests, else Standard) in front of a service whose protection
policy turns the CDN on. Its origin is the Application Gateway when the service's TLS terminates at the edge, else the
service's Standard load balancer (TLS then ending at Front Door), each by its public address, with the service name as
host header and the origin's certificate name checked; the route sends everything over HTTPS without caching (sign-in
pages and tokens). The service name is a custom domain with the certificate the environment keeps in Key Vault (else a
Front Door managed certificate), validated by a _dnsauth TXT record, and its DNS record a CNAME to the endpoint. The
protection policy is a Front Door firewall policy on the domain; the gateway keeps none. Pure.

Known limits: Front Door reads the Key Vault certificate as its own service principal, which needs Key Vault Secrets
User on the vault (the landing zone's grant); an origin with a private address needs Private Link (not rendered); the
origins should admit only Front Door (service tag AzureFrontDoor.Backend and the X-Azure-FDID header), which is the
landing zone's network security group.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.edge.dns import zone_unknown
from opsdir.domains.edge.exposure import is_internal
from opsdir.domains.edge.resolve import inspected, path_regex
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .dns import record_name, service_zone
from .edge import WAF_RULE_SETS, rate
from .identities import RG
from .account import tagged

EXCLUDED_VARIABLE = {"body": "RequestBodyPostArgNames", "query": "QueryStringArgNames",
                     "header": "RequestHeaderNames", "cookie": "RequestCookieNames"}


def _custom_rules(spec):
    action = "Log" if spec.waf_mode == "detect" else "Block"
    rules = [
        *((f"{act}addresses{i}", "MatchRule", "Allow" if act == "allow" else action,
           (("match_variable", "RemoteAddr"), ("operator", "IPMatch"), ("match_values", [cidr])), ())
          for i, (act, cidr) in enumerate(spec.ip_rules)),
        *((f"geo{i}", "MatchRule", action,
           (("match_variable", "RemoteAddr"), ("operator", "GeoMatch"), ("negation_condition", act == "allow"),
            ("match_values", list(codes))), ())
          for i, (act, codes) in enumerate(spec.geo_rules)),
        *((f"rate{tf_name(r.kind).replace('_', '')}", "RateLimitRule", action,
           (("match_variable", "RequestUri"), ("operator", "RegEx"),
            ("match_values", [path_regex(p) for p in r.paths] or [".*"])),
           (("rate_limit_duration_in_minutes", 1 if duration == "OneMin" else 5),
            ("rate_limit_threshold", threshold)))
          for r in spec.rate_limits for threshold, duration in (rate(r.requests, r.seconds),))]
    return tuple(("custom_rule", Block((("name", name), ("enabled", True), ("priority", i + 1), ("type", kind),
                                        *extra, ("action", act), ("match_condition", Block(condition)))))
                 for i, (name, kind, act, condition, extra) in enumerate(rules))


def _managed_rules(spec):
    action = "Log" if spec.waf_mode == "detect" else "Block"
    sets = dict.fromkeys(WAF_RULE_SETS[c] for c in spec.categories if WAF_RULE_SETS.get(c))
    exclusions = tuple(("exclusion", Block((("match_variable", EXCLUDED_VARIABLE[x.part]), ("operator", "Equals"),
                                            ("selector", x.name)))) for x in spec.exclusions)
    return tuple(("managed_rule", Block((("type", t), ("version", v), ("action", action),
                                         *(exclusions if t == "Microsoft_DefaultRuleSet" else ()))))
                 for t, v in sets)


def _domain_tls(m, n, spec):
    """(resources, tls body): the custom domain's certificate from Key Vault, else Front Door's managed one."""
    ref_uri = spec.certificate or ""
    if not ref_uri.startswith("azkv-cert://"):
        return (), (("certificate_type", "ManagedCertificate"), ("minimum_tls_version", "TLS12"))
    vault, name = ref_uri.split("://", 1)[1].split("/", 1)
    return ((block("data", ["azurerm_key_vault", f"{n}_cdn_tls"], [("name", vault), ("resource_group_name", RG)]),
             block("resource", ["azurerm_cdn_frontdoor_secret", n], [
                 ("#", "Front Door's service principal needs Key Vault Secrets User on the vault (the landing zone)"),
                 ("name", f"{n}-tls"), ("cdn_frontdoor_profile_id", ref(f"azurerm_cdn_frontdoor_profile.{n}.id")),
                 ("secret", Block((("customer_certificate", Block((("key_vault_certificate_id", ref(
                     f'"${{data.azurerm_key_vault.{n}_cdn_tls.vault_uri}}certificates/{name}"')),))),)))])),
            (("certificate_type", "CustomerCertificate"),
             ("cdn_frontdoor_secret_id", ref(f"azurerm_cdn_frontdoor_secret.{n}.id")),
             ("minimum_tls_version", "TLS12")))


def front_door(m, svc, spec, n):
    """Front Door in front of a service: profile, endpoint, origin group and origin (the gateway or the load balancer
    by its public address), custom domain with its certificate and validation record, route, firewall and security
    policies, and the DNS CNAME to the endpoint."""
    name, zone = one(svc, "ciamFqdn"), service_zone(m, svc)
    if is_internal(svc):
        return (f"# `{name}`: a CDN in front of a private address needs Front Door Premium's Private Link origin; "
                "not rendered",)
    waf = inspected(spec)
    sku = "Premium_AzureFrontDoor" if waf else "Standard_AzureFrontDoor"
    h, port = spec.health, int(values(svc, "ciamPort")[0])
    certificate, tls = _domain_tls(m, n, spec)
    profile = ref(f"azurerm_cdn_frontdoor_profile.{n}.id")
    return (
        block("resource", ["azurerm_cdn_frontdoor_profile", n], [
            ("name", f"afd-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("resource_group_name", RG), ("sku_name", sku),
            ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),
        block("resource", ["azurerm_cdn_frontdoor_endpoint", n], [
            ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("cdn_frontdoor_profile_id", profile),
            ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),
        block("resource", ["azurerm_cdn_frontdoor_origin_group", n], [
            ("name", "servers"), ("cdn_frontdoor_profile_id", profile),
            ("session_affinity_enabled", spec.stickiness == "cookie"),
            ("load_balancing", Block((("sample_size", 4), ("successful_samples_required", 3)))),
            ("health_probe", Block((("protocol", "Http" if h.protocol == "http" else "Https"),
                                    ("path", h.path or "/"), ("interval_in_seconds", h.interval or 100),
                                    ("request_type", "GET"))))]),
        block("resource", ["azurerm_cdn_frontdoor_origin", n], [
            ("name", "load-balancer" if not spec.layer7 else "application-gateway"),
            ("cdn_frontdoor_origin_group_id", ref(f"azurerm_cdn_frontdoor_origin_group.{n}.id")), ("enabled", True),
            ("host_name", ref(f"data.azurerm_public_ip.{n}.ip_address")), ("origin_host_header", name),
            ("http_port", 80), ("https_port", port), ("certificate_name_check_enabled", True),
            ("priority", 1), ("weight", 1000)]),
        *certificate,
        block("resource", ["azurerm_cdn_frontdoor_custom_domain", n], [
            ("name", tf_name(name).replace("_", "-")), ("cdn_frontdoor_profile_id", profile), ("host_name", name),
            ("tls", Block(tls))]),
        block("resource", ["azurerm_cdn_frontdoor_route", n], [
            ("name", "all"), ("cdn_frontdoor_endpoint_id", ref(f"azurerm_cdn_frontdoor_endpoint.{n}.id")),
            ("cdn_frontdoor_origin_group_id", ref(f"azurerm_cdn_frontdoor_origin_group.{n}.id")),
            ("cdn_frontdoor_origin_ids", [ref(f"azurerm_cdn_frontdoor_origin.{n}.id")]),
            ("cdn_frontdoor_custom_domain_ids", [ref(f"azurerm_cdn_frontdoor_custom_domain.{n}.id")]),
            ("#", "no cache block: nothing is cached (sign-in pages and tokens)"),
            ("patterns_to_match", ["/*"]), ("supported_protocols", ["Http", "Https"]),
            ("https_redirect_enabled", True), ("forwarding_protocol", "HttpsOnly"), ("link_to_default_domain", False)]),
        block("resource", ["azurerm_cdn_frontdoor_custom_domain_association", n], [
            ("cdn_frontdoor_custom_domain_id", ref(f"azurerm_cdn_frontdoor_custom_domain.{n}.id")),
            ("cdn_frontdoor_route_ids", [ref(f"azurerm_cdn_frontdoor_route.{n}.id")])]),
        *((block("resource", ["azurerm_cdn_frontdoor_firewall_policy", n], [
              ("name", f"waf{tf_name(rdn_value(m.env)).replace('_', '')}{n.replace('_', '')}"),
              ("resource_group_name", RG), ("sku_name", sku), ("enabled", True),
              ("mode", "Detection" if spec.waf_mode == "detect" else "Prevention"),
              *_custom_rules(spec), *_managed_rules(spec),
              ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),
           block("resource", ["azurerm_cdn_frontdoor_security_policy", n], [
              ("name", f"{n.replace('_', '-')}-waf"), ("cdn_frontdoor_profile_id", profile),
              ("security_policies", Block((("firewall", Block((
                  ("cdn_frontdoor_firewall_policy_id", ref(f"azurerm_cdn_frontdoor_firewall_policy.{n}.id")),
                  ("association", Block((
                      ("domain", Block((("cdn_frontdoor_domain_id",
                                         ref(f"azurerm_cdn_frontdoor_custom_domain.{n}.id")),))),
                      ("patterns_to_match", ["/*"]))))))),)))])) if waf else ()),
        block("resource", ["azurerm_dns_txt_record", f"{n}_dnsauth"], [
            ("name", f"_dnsauth.{record_name(name, zone)}" if record_name(name, zone) != "@" else "_dnsauth"),
            ("zone_name", zone), ("resource_group_name", RG), ("ttl", 3600),
            ("record", Block((("value", ref(f"azurerm_cdn_frontdoor_custom_domain.{n}.validation_token")),))),
            ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))])
        if zone else zone_unknown(svc, "ciamDnsZone"))


def endpoint(n):
    """What a service's DNS name points at when Front Door fronts it."""
    return ref(f"azurerm_cdn_frontdoor_endpoint.{n}.host_name")
