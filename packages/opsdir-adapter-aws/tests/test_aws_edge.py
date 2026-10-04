"""A service whose policies terminate TLS at the edge as AWS Terraform: an ALB with the TLS policy nearest the intent,
the environment's ACM certificate, target groups with the policy's health check, stickiness and draining, a security
group admitting the clients the firewall rules admit; a WAFv2 web ACL with the rate limits aimed at the products'
endpoints, address and country rules and managed groups; Shield Advanced when asked. A passthrough service keeps its
NLB, tuned by its policy."""
from opsdir.domains.edge.resolve import Health, RateLimit, tls_level, tls_policy
from opsdir_adapter_aws.edge import TLS_POLICIES, alb_service, health_check, rate, shield, stickiness, web_acl
from opsdir_format_terraform.hcl import Block
from edge_fixtures import environment, firewall, server, service, spec, subnet

CERT = "arn:aws:acm:us-east-1:111122223333:certificate/abcd"


def _alb(s, ip="198.51.100.20"):
    svc = service(ip)
    m = environment(svc, firewall("fw-sso-public", ["0.0.0.0/0"], ["443"]), firewall("fw-other", ["10.0.0.0/8"], ["22"]))
    return "\n".join(alb_service(m, svc, s, (server("pf-1", "10.20.2.10"),),
                                 (subnet("subnet-pf-a", "subnet-pf", "10.20.2.0/24"),)))


def test_tls_terms_map_to_elb_policies_and_back():
    assert tls_policy(TLS_POLICIES, "1.2", "intermediate") == ("ELBSecurityPolicy-TLS13-1-2-2021-06", True)
    assert tls_policy(TLS_POLICIES, "1.2", "compatible") == ("ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06", False)
    assert tls_level(TLS_POLICIES, "ELBSecurityPolicy-TLS13-1-3-2021-06") == ("1.3", "modern")
    assert tls_level(TLS_POLICIES, "ELBSecurityPolicy-2016-08") is None


def test_an_alb_with_listener_policy_certificate_target_group_and_security_group():
    out = _alb(spec(certificate=f"aws-acm://{CERT}"))
    assert 'load_balancer_type         = "application"' in out and "drop_invalid_header_fields = true" in out
    assert "# an ALB's addresses are AWS's: frontend address 198.51.100.20 isn't kept" in out
    assert 'ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"' in out and f'certificate_arn   = "{CERT}"' in out
    assert 'protocol             = "HTTPS"' in out and "deregistration_delay = 30" in out      # reencrypt, drain
    assert 'path                = "/pf/heartbeat.ping"' in out and 'type            = "lb_cookie"' in out
    assert 'resource "aws_vpc_security_group_ingress_rule" "sso_alb_fw_sso_public_0_443"' in out
    assert "fw_other" not in out                                      # another port: not the ALB's
    assert "referenced_security_group_id = aws_security_group.pf_engine.id" in out   # ALB -> servers
    assert "idle_timeout               = 120" in out


def test_an_alb_without_a_certificate_in_acm_says_so_and_terminate_speaks_http_to_the_servers():
    out = _alb(spec(mode="terminate", health=Health("tcp", None, None, None, None)))
    assert "# UNBOUND: no ACM certificate holds this service's certificate in this environment" in out
    assert 'protocol             = "HTTP"' in out
    assert 'protocol = "HTTP"' in out.replace("protocol            =", "protocol =")      # an ALB checks over HTTP


def test_the_web_acl_rules_aim_at_the_endpoints():
    out = "\n".join(web_acl(environment(), "sso", spec(), "aws_lb.sso.arn"))
    assert 'resource "aws_wafv2_ip_set" "sso_deny_ipv4"' in out and 'addresses          = ["203.0.113.0/24"]' in out
    assert 'country_codes = ["KP"]' in out
    assert "limit                 = 100" in out and "evaluation_window_sec = 300" in out
    assert 'regex_string = "^/as/token\\\\.oauth2$"' in out
    assert 'name        = "AWSManagedRulesCommonRuleSet"' in out
    assert 'regex_string = "^/idp/SSO\\\\.saml2$"' in out                   # the excluded endpoint, out of scope
    assert "resource_arn = aws_lb.sso.arn" in out


def test_detect_mode_counts_and_account_takeover_needs_a_literal_sign_in_path():
    out = "\n".join(web_acl(environment(), "sso", spec(waf_mode="detect", categories=("account-takeover",),
                                                         endpoints={"login": ("/am/json/realms/*/authenticate",)}),
                            "aws_lb.sso.arn"))
    assert "count {" in out and "block {" not in out
    assert "# UNBOUND: account takeover protection needs a literal sign-in path" in out
    out = "\n".join(web_acl(environment(), "sso", spec(categories=("account-takeover",)), "aws_lb.sso.arn"))
    assert 'login_path = "/as/authorization.oauth2"' in out


def test_rate_limits_take_an_aws_window_and_header_keys():
    assert rate(100, 300) == (100, 300) and rate(50, 30) == (500, 300) and rate(5, 60) == (10, 60)
    out = "\n".join(web_acl(environment(), "sso", spec(rate_limits=(RateLimit("login", 20, 60, "header:X-Key", ()),)),
                            "aws_lb.sso.arn"))
    assert 'aggregate_key_type    = "CUSTOM_KEYS"' in out and 'name = "X-Key"' in out
    assert "# no login endpoint is declared for these servers: the limit applies to every request" in out


def test_shield_only_beyond_standard():
    assert shield("sso", spec(), "aws_lb.sso.arn") == ()
    out = "\n".join(shield("sso", spec(ddos="application-advanced"), "aws_lb.sso.arn"))
    assert 'resource "aws_shield_protection" "sso"' in out
    assert 'resource "aws_shield_application_layer_automatic_response" "sso"' in out
    assert "automatic_response" not in "\n".join(shield("sso", spec(ddos="network-advanced"), "aws_lb.sso.arn"))


def test_a_passthrough_target_group_takes_the_policys_health_check_and_source_stickiness():
    s = spec(mode="passthrough", layer7=False, health=Health("tcp", None, 15, None, None), stickiness="source-ip")
    assert health_check(s, False) == ("health_check", Block((("protocol", "TCP"), ("interval", 15))))
    assert stickiness(s, False) == (("stickiness", Block((("type", "source_ip"), ("enabled", True)))),)
    assert stickiness(spec(), False)[0][0] == "#"                           # cookies need an ALB
