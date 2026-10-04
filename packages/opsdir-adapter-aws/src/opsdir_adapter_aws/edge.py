"""AWS edge: what the edge domain's terms mean on AWS, and the Terraform for a service whose policies ask for more than
a TCP passthrough. A service name whose TLS terminates at the edge is an Application Load Balancer (HTTPS listener with
the TLS policy and the certificate the environment holds in ACM, HTTP or HTTPS target groups with the policy's health
check, stickiness and draining, its own security group); its protection policy is a WAFv2 web ACL on it (managed rule
groups, rate-based rules aimed at the products' endpoints, address and country rules) and Shield Advanced protection
when the policy asks for more than standard DDoS protection. A passthrough service stays a Network Load Balancer, with
the policy's health check and source-address stickiness. Pure.

Known limits: an ALB's addresses are AWS's (a recorded frontend address isn't kept); a managed rule group can't skip one
field, so an exclusion keeps the whole endpoint out of that group's scope; Shield Advanced needs the account's
subscription.
"""
from itertools import chain

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.network import is_private
from opsdir.domains.edge.resolve import inspected, path_regex, tls_policy
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

# (min version, profile, ELB security policy, exact): the intent's TLS terms as ALB/NLB TLS listener policies
TLS_POLICIES = (("1.3", "modern", "ELBSecurityPolicy-TLS13-1-3-2021-06", True),
                ("1.3", "intermediate", "ELBSecurityPolicy-TLS13-1-3-2021-06", True),
                ("1.3", "compatible", "ELBSecurityPolicy-TLS13-1-3-2021-06", True),
                ("1.2", "modern", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06", True),
                ("1.2", "intermediate", "ELBSecurityPolicy-TLS13-1-2-2021-06", True),
                ("1.2", "compatible", "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06", False))
# WAF category -> AWS managed rule group
WAF_GROUPS = {"core-rules": "AWSManagedRulesCommonRuleSet", "known-bad-inputs": "AWSManagedRulesKnownBadInputsRuleSet",
              "ip-reputation": "AWSManagedRulesAmazonIpReputationList", "bot-control": "AWSManagedRulesBotControlRuleSet",
              "account-takeover": "AWSManagedRulesATPRuleSet", "account-creation-fraud": "AWSManagedRulesACFPRuleSet"}
US_EAST_1 = "us_east_1"               # the provider alias CloudFront's certificate and web ACL are created through
WINDOWS = (60, 120, 300, 600)           # rate-based rule evaluation windows, seconds
_VISIBLE = (("cloudwatch_metrics_enabled", True), ("sampled_requests_enabled", True))


def _visibility(name):
    return ("visibility_config", Block((*_VISIBLE, ("metric_name", name))))


def rate(requests, seconds):
    """(limit, window) for a rate limit of requests per seconds: the same window when AWS has it, else the requests
    scaled to 300 seconds (rounded up; AWS's minimum limit is 10)."""
    window = seconds if seconds in WINDOWS else 300
    return max(10, -(-requests * window // seconds)), window


def _paths_statement(paths):
    """A statement matching requests whose path matches any of the globs."""
    def match(p):
        return ("regex_match_statement", Block(_regex(p)))
    if len(paths) == 1:
        return Block((match(paths[0]),))
    return Block((("or_statement", Block(tuple(("statement", Block((match(p),))) for p in paths))),))


def _regex(glob):
    return (("regex_string", path_regex(glob)), ("field_to_match", Block((("uri_path", Block(())),))),
            ("text_transformation", Block((("priority", 0), ("type", "NONE")))))


def _action(spec):
    return Block(((("count" if spec.waf_mode == "detect" else "block"), Block(())),))


def _rate_rule(n, spec, r, priority):
    limit, window = rate(r.requests, r.seconds)
    key = (("aggregate_key_type", "IP"),) if r.key == "ip" else (
        ("aggregate_key_type", "CUSTOM_KEYS"),
        ("custom_key", Block((("header", Block((("name", r.key.split(":", 1)[1]),
                                                ("text_transformation", Block((("priority", 0),
                                                                               ("type", "NONE")))))),),))))
    scope = (("scope_down_statement", _paths_statement(r.paths)),) if r.paths else \
        (("#", f"no {r.kind} endpoint is declared for these servers: the limit applies to every request"),)
    return ("rule", Block((("name", f"rate-{r.kind}"), ("priority", priority), ("action", _action(spec)),
                           ("statement", Block((("rate_based_statement", Block((
                               ("limit", limit), ("evaluation_window_sec", window), *key, *scope))),))),
                           _visibility(f"{n}-rate-{r.kind}"))))


def _managed_config(spec, category):
    """The managed_rule_group_configs a group needs, from the endpoints the products declare."""
    literal = (lambda kind: next((p for p in spec.endpoints.get(kind, ()) if "*" not in p), None))
    if category == "bot-control":
        return (("managed_rule_group_configs", Block((("aws_managed_rules_bot_control_rule_set",
                                                       Block((("inspection_level", "COMMON"),))),))),)
    if category == "account-takeover":
        login = literal("login")
        atp = Block((("login_path", login),
                     ("#", "add request_inspection (payload type, username and password fields) from the sign-in "
                           "form")))
        return (("managed_rule_group_configs", Block((("aws_managed_rules_atp_rule_set", atp),))),) if login else \
            (("#", "UNBOUND: account takeover protection needs a literal sign-in path (a policy's ciamEndpointPath)"),)
    if category == "account-creation-fraud":
        page = literal("registration")
        return (("managed_rule_group_configs", Block((("aws_managed_rules_acfp_rule_set", Block((
            ("creation_path", page), ("registration_page_path", page)))),))),) if page else \
            (("#", "UNBOUND: account creation fraud prevention needs a literal registration path"),)
    return ()


def _managed_rule(n, spec, category, priority):
    excluded = tuple(p for x in spec.exclusions if x.category == category for p in x.paths)
    scope = (("scope_down_statement", Block((("not_statement", Block((("statement", _paths_statement(excluded)),))),))),
             ("#", "exclusions: AWS can't skip one field of a managed group, so these endpoints are out of its scope")
             ) if excluded else ()
    return ("rule", Block((
        ("name", category), ("priority", priority),
        ("override_action", Block(((("count" if spec.waf_mode == "detect" else "none"), Block(())),))),
        ("statement", Block((("managed_rule_group_statement", Block((
            ("name", WAF_GROUPS[category]), ("vendor_name", "AWS"), *_managed_config(spec, category), *scope))),))),
        _visibility(f"{n}-{category}"))))


def _scope(cdn):
    """A WAF resource's scope: regional, or CloudFront's (created in us-east-1 through the provider alias)."""
    return (("provider", ref(f"aws.{US_EAST_1}")), ("scope", "CLOUDFRONT")) if cdn else (("scope", "REGIONAL"),)


def _ip_sets(m, n, spec, cdn=False):
    """WAF IP sets per action and address family."""
    groups = {}
    for action, cidr in spec.ip_rules:
        groups.setdefault((action, "IPV6" if ":" in cidr else "IPV4"), []).append(cidr)
    return {k: block("resource", ["aws_wafv2_ip_set", f"{n}_{k[0]}_{k[1].lower()}"], [
        ("name", f"ciam-{rdn_value(m.env)}-{n}-{k[0]}-{k[1].lower()}"), *_scope(cdn),
        ("ip_address_version", k[1]), ("addresses", sorted(v))]) for k, v in sorted(groups.items())}


def _address_rules(n, spec, sets, start):
    allow = [f"aws_wafv2_ip_set.{n}_allow_{fam.lower()}.arn" for (a, fam) in sets if a == "allow"]
    deny = [f"aws_wafv2_ip_set.{n}_deny_{fam.lower()}.arn" for (a, fam) in sets if a == "deny"]
    rules = [*(("allow-addresses", arn, Block((("allow", Block(())),))) for arn in allow),
             *(("deny-addresses", arn, _action(spec)) for arn in deny)]
    return tuple(("rule", Block((("name", f"{name}-{i}"), ("priority", start + i), ("action", action),
                                 ("statement", Block((("ip_set_reference_statement", Block((("arn", ref(arn)),))),))),
                                 _visibility(f"{n}-{name}-{i}"))))
                 for i, (name, arn, action) in enumerate(rules))


def _geo_rules(n, spec, start):
    def statement(action, codes):
        geo = Block((("geo_match_statement", Block((("country_codes", list(codes)),))),))
        return geo if action == "deny" else Block((("not_statement", Block((("statement", geo),))),))
    return tuple(("rule", Block((("name", f"geo-{i}"), ("priority", start + i), ("action", _action(spec)),
                                 ("statement", statement(action, codes)), _visibility(f"{n}-geo-{i}"))))
                 for i, (action, codes) in enumerate(spec.geo_rules))


def web_acl(m, n, spec, target_arn, cdn=False):
    """The WAFv2 web ACL a protection policy asks for, its IP sets and its association with the load balancer; for a
    CloudFront distribution (cdn), CloudFront-scoped and named by the distribution instead of associated."""
    sets = _ip_sets(m, n, spec, cdn)
    address = _address_rules(n, spec, sets, 0)
    geo = _geo_rules(n, spec, len(address))
    rates = tuple(_rate_rule(n, spec, r, len(address) + len(geo) + i) for i, r in enumerate(spec.rate_limits))
    start = len(address) + len(geo) + len(rates)
    managed = tuple(_managed_rule(n, spec, c, start + i) for i, c in enumerate(spec.categories))
    return (*sets.values(),
            block("resource", ["aws_wafv2_web_acl", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{n}"), *_scope(cdn),
                ("default_action", Block((("allow", Block(())),))),
                *address, *geo, *rates, *managed, _visibility(f"{n}-web-acl"),
                ("tags", {"ManagedBy": "opsdir"})]),
            *(() if cdn else (block("resource", ["aws_wafv2_web_acl_association", n], [
                ("resource_arn", ref(target_arn)), ("web_acl_arn", ref(f"aws_wafv2_web_acl.{n}.arn"))]),)))


def shield(n, spec, target_arn, attached=None):
    """Shield Advanced protection (and automatic layer 7 mitigation) when the policy asks for more than standard.
    attached: what attaches the web ACL to the target (its association, else the CloudFront distribution)."""
    if spec.ddos == "standard":
        return ()
    return (block("resource", ["aws_shield_protection", n], [
                ("#", "needs the account's Shield Advanced subscription"),
                ("name", n), ("resource_arn", ref(target_arn))]),
            *((block("resource", ["aws_shield_application_layer_automatic_response", n], [
                ("resource_arn", ref(target_arn)),
                ("action", "COUNT" if spec.waf_mode == "detect" else "BLOCK"),
                ("depends_on", [ref(f"aws_shield_protection.{n}"),
                                ref(attached or f"aws_wafv2_web_acl_association.{n}")])]),)
              if spec.ddos == "application-advanced" and inspected(spec) else ()))


def health_check(spec, layer7):
    """The target group's health_check block from the spec (an ALB checks over HTTP or HTTPS only)."""
    h = spec.health
    protocol = h.protocol.upper() if not layer7 or h.protocol != "tcp" else \
        ("HTTPS" if spec.mode == "reencrypt" else "HTTP")
    return ("health_check", Block((("protocol", protocol),
                                   *((("path", h.path or "/"), ("matcher", "200")) if protocol != "TCP" else ()),
                                   *((("interval", h.interval),) if h.interval else ()),
                                   *((("healthy_threshold", h.healthy),) if h.healthy else ()),
                                   *((("unhealthy_threshold", h.unhealthy),) if h.unhealthy else ()))))


def stickiness(spec, layer7):
    """The target group's stickiness block, when the policy asks for one the load balancer type offers."""
    if spec.stickiness == "cookie" and layer7:
        return (("stickiness", Block((("type", "lb_cookie"), ("enabled", True),
                                      *((("cookie_duration", spec.stickiness_seconds),)
                                        if spec.stickiness_seconds else ())))),)
    if spec.stickiness == "source-ip" and not layer7:
        return (("stickiness", Block((("type", "source_ip"), ("enabled", True))),),)
    return (("#", f"{spec.stickiness} stickiness isn't offered by this load balancer type"),) \
        if spec.stickiness != "none" else ()


def _cloudfront_ingress(n, ports):
    """The ALB admitting only CloudFront's origin-facing addresses (AWS's managed prefix list)."""
    return (block("data", ["aws_ec2_managed_prefix_list", f"{n}_cloudfront"], [
                ("name", "com.amazonaws.global.cloudfront.origin-facing")]),
            *(block("resource", ["aws_vpc_security_group_ingress_rule", f"{n}_alb_cloudfront_{port}"], [
                ("security_group_id", ref(f"aws_security_group.{n}_alb.id")),
                ("prefix_list_id", ref(f"data.aws_ec2_managed_prefix_list.{n}_cloudfront.id")),
                ("from_port", int(port)), ("to_port", int(port)), ("ip_protocol", "tcp"),
                ("description", "CloudFront origin-facing")]) for port in ports))


def _alb_security_group(m, n, svc, ports, cdn=False):
    """The ALB's security group: clients in by the firewall rules that admit them to the service's servers and ports
    (only CloudFront when a CDN fronts it), out to the servers; and the servers in from it."""
    role = one(svc, "ciamTargetRole")
    rules = [] if cdn else [(fw, cidr, port) for fw in m.bindings if "ciamFirewallRule" in fw.classes
                            and one(fw, "ciamTargetRole") == role for cidr in values(fw, "ciamSourceCidr")
                            for port in values(fw, "ciamPort") if port in ports]
    return (block("resource", ["aws_security_group", f"{n}_alb"], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}-alb"),
                ("description", f"CIAM {one(svc, 'ciamFqdn')} load balancer ({m.label})"),
                ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]),
            *(block("resource", ["aws_vpc_security_group_ingress_rule", tf_name(f"{n}_alb_{rdn_value(fw)}_{i}_{port}")],
                    [("security_group_id", ref(f"aws_security_group.{n}_alb.id")), ("cidr_ipv4", cidr),
                     ("from_port", int(port)), ("to_port", int(port)), ("ip_protocol", "tcp"),
                     ("description", f"clients ({rdn_value(fw)})")])
              for i, (fw, cidr, port) in enumerate(rules)),
            *(_cloudfront_ingress(n, ports) if cdn else ()),
            *chain.from_iterable((
                block("resource", ["aws_vpc_security_group_egress_rule", f"{n}_alb_to_servers_{port}"], [
                    ("security_group_id", ref(f"aws_security_group.{n}_alb.id")),
                    ("referenced_security_group_id", ref(f"aws_security_group.{tf_name(role)}.id")),
                    ("from_port", int(port)), ("to_port", int(port)), ("ip_protocol", "tcp"),
                    ("description", "to the servers")]),
                block("resource", ["aws_vpc_security_group_ingress_rule", f"{n}_servers_from_alb_{port}"], [
                    ("security_group_id", ref(f"aws_security_group.{tf_name(role)}.id")),
                    ("referenced_security_group_id", ref(f"aws_security_group.{n}_alb.id")),
                    ("from_port", int(port)), ("to_port", int(port)), ("ip_protocol", "tcp"),
                    ("description", f"from the {one(svc, 'ciamFqdn')} load balancer")])) for port in ports))


def alb_service(m, svc, spec, targets, subnets):
    """An ALB for a service name whose TLS terminates at the edge: listeners per port with the TLS policy and the
    environment's certificate, target groups, its security group, the DNS alias, and the web ACL and Shield
    protection its protection policy asks for. targets: the servers; subnets: their subnet bindings."""
    n, ip = tf_name(rdn_value(svc)), one(svc, "ciamFrontendIp")
    ports = tuple(values(svc, "ciamPort"))
    policy, exact = tls_policy(TLS_POLICIES, spec.tls_min, spec.tls_profile)
    cert = spec.certificate.split("://", 1)[1] if spec.certificate and spec.certificate.startswith("aws-acm://") \
        else None
    backend = "HTTPS" if spec.mode == "reencrypt" else "HTTP"
    groups = chain.from_iterable((
        block("resource", ["aws_lb_target_group", f"{n}_{port}"], [
            ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}-{port}"), ("port", int(port)), ("protocol", backend),
            ("vpc_id", ref("data.aws_vpc.main.id")), ("target_type", "instance"),
            *((("deregistration_delay", spec.drain),) if spec.drain is not None else ()),
            health_check(spec, True), *stickiness(spec, True)]),
        *(block("resource", ["aws_lb_target_group_attachment", f"{n}_{port}_{tf_name(rdn_value(t))}"], [
            ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")),
            ("target_id", ref(f"aws_instance.{tf_name(rdn_value(t))}.id")), ("port", int(port))]) for t in targets),
        block("resource", ["aws_lb_listener", f"{n}_{port}"], [
            ("load_balancer_arn", ref(f"aws_lb.{n}.arn")), ("port", int(port)), ("protocol", "HTTPS"),
            ("ssl_policy", policy),
            *((("#", f"nearest policy to TLS {spec.tls_min} {spec.tls_profile}"),) if not exact else ()),
            *((("certificate_arn", cert),) if cert else
              (("#", "UNBOUND: no ACM certificate holds this service's certificate in this environment"),)),
            ("default_action", Block((("type", "forward"),
                                      ("target_group_arn", ref(f"aws_lb_target_group.{n}_{port}.arn")))))]))
        for port in ports)
    return (*_alb_security_group(m, n, svc, ports, spec.cdn),
            block("resource", ["aws_lb", n], [
                *((("#", f"an ALB's addresses are AWS's: frontend address {ip} isn't kept"),) if ip else ()),
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("internal", bool(ip) and is_private(ip)),
                ("load_balancer_type", "application"),
                ("security_groups", [ref(f"aws_security_group.{n}_alb.id")]),
                ("subnets", [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id") for s in subnets]),
                ("drop_invalid_header_fields", True),
                *((("idle_timeout", spec.idle_timeout),) if spec.idle_timeout else ()),
                ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
            *groups,
            *(web_acl(m, n, spec, f"aws_lb.{n}.arn") if inspected(spec) and not spec.cdn else ()),
            *(shield(n, spec, f"aws_lb.{n}.arn") if not spec.cdn else ()))
