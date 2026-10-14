"""What a cloud renders of a canary: the URL its flow requests on the checked service name (the products' endpoint
path, through the edge's policies; a SAML sign-in's start naming its service provider; an LDAPS bind), its name (the
canary binding realizing it), interval and credentials, and where an internal service's check runs from; and why a
canary isn't rendered (a flow nothing describes, no credentials, no concrete path, no service provider)."""
from opsdir.core.contract import Endpoint
from opsdir.domains.observability.canaries import canary_specs
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.observability.naming import CANARIES
from network_fixtures import ALPHA, entry, model, rule

ENDPOINTS = (Endpoint("health", "/ping", "web"), Endpoint("token", "/as/token.oauth2", "web"),
             Endpoint("login", "/am/json/realms/*/authenticate", "web"),
             Endpoint("saml-start", "/idp/startSSO.ping", "web", query="PartnerSpId={entity}"))


def _canary(cn, **attrs):
    return entry(CANARIES, cn, "ciamCanary", **attrs).replace("objectClass: ciamCanary",
                                                               "objectClass: ciamObject\nobjectClass: ciamCanary")


TREE = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
        _canary("alive", ciamCheckedService="sso", ciamCanaryFlow="health"),
        _canary("token", ciamCheckedService="sso", ciamCanaryFlow="oidc-token", ciamInterval="10m",
                ciamUsesRole=("unbound-creds", "canary-creds")),
        _canary("no-creds", ciamCheckedService="sso", ciamCanaryFlow="oidc-token"),
        _canary("login", ciamCheckedService="sso", ciamCanaryFlow="login-page"),
        _canary("saml", ciamCheckedService="sso", ciamCanaryFlow="saml-sso"),
        _canary("saml-portal", ciamCheckedService="sso", ciamCanaryFlow="saml-sso",
                ciamStartsFrom=f"cn=portal,{INTEGRATIONS}"),
        _canary("saml-app", ciamCheckedService="sso", ciamCanaryFlow="saml-sso",
                ciamStartsFrom=f"cn=app,{INTEGRATIONS}"),
        _canary("bind", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind"),
        _canary("bind-plain", ciamCheckedService="ldap", ciamCanaryFlow="ldap-bind", ciamUsesRole="canary-creds"),
        _canary("elsewhere", ciamCheckedService="nowhere", ciamCanaryFlow="ldap-bind"),
        _canary("vague", ciamCheckedService="sso", ciamCanaryFlow="other"),
        f"dn: {INTEGRATIONS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
        entry(INTEGRATIONS, "portal", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamEntityId="https://portal.example.test/saml/sp").replace(
            "objectClass: ciamIntegration", "objectClass: ciamObject\nobjectClass: ciamIntegration"),
        entry(INTEGRATIONS, "app", "ciamIntegration", ciamProtocolType="oidc-client").replace(
            "objectClass: ciamIntegration", "objectClass: ciamObject\nobjectClass: ciamIntegration"))
ALPHA_BINDINGS = (
    entry(ALPHA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test", ciamPort="8443",
          ciamTargetRole="web"),
    entry(ALPHA, "creds", "ciamSecretRef", ciamBindingRole="canary-creds",
          ciamRefUri="aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:canary"),
    entry(ALPHA, "ciam-alive", "ciamCanaryBinding", ciamBindingRole="canary-alive", ciamRealizes="alive",
          ciamProviderRef="arn:aws:synthetics:us-east-1:111122223333:canary:ciam-alive", ciamInterval="1m"),
    entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ldaps", ciamFqdn="ldap.example.test",
          ciamPort="1636", ciamTargetRole="ds", ciamFrontendIp="10.1.1.100"),
    entry(ALPHA, "svc-ldap", "ciamServiceName", ciamBindingRole="ldap", ciamFqdn="ldap.example.test", ciamPort="389",
          ciamTargetRole="ds", ciamExposure="internal"),
    rule(ALPHA, "fw-web-ds", ("10.1.2.0/24", "fd00::/64"), "1636", "ds"))


def test_each_canary_the_environment_can_run_becomes_a_request_or_says_why_not():
    _, alpha, _ = model(alpha=ALPHA_BINDINGS, tree=TREE)
    specs = {s.canary.dn.split(",", 1)[0][3:]: s for s in canary_specs(alpha, ENDPOINTS)}
    assert set(specs) == {"alive", "token", "no-creds", "login", "saml", "saml-portal", "saml-app", "bind",
                          "bind-plain", "vague"}                            # nowhere isn't bound: not here
    alive, token = specs["alive"], specs["token"]
    assert (alive.name, alive.url, alive.every, alive.why) == ("ciam-alive", "https://sso.example.test:8443/ping",
                                                               60, None)
    assert (token.name, token.url, token.every, token.why) == ("token", "https://sso.example.test:8443/as/token.oauth2",
                                                               600, None)
    assert token.secret is not None and token.secret.dn.startswith("cn=creds,")
    assert specs["no-creds"].why == "an oidc-token check needs credentials and none of its ciamUsesRole is bound here"
    assert specs["login"].why == "the products serving web name no login path without wildcards"
    assert specs["saml"].why == "a SAML sign-in check names no SAML integration to start from (ciamStartsFrom)"
    assert specs["saml-app"].why.startswith("integration app isn't a SAML service provider with an entity ID")
    portal = specs["saml-portal"]
    assert (portal.url, portal.why, portal.exposure, portal.subnets) == (
        "https://sso.example.test:8443/idp/startSSO.ping?PartnerSpId=https%3A%2F%2Fportal.example.test%2Fsaml%2Fsp",
        None, None, ())
    assert specs["vague"].why == "its flow (other) says nothing a check could request"


def test_an_ldap_bind_check_binds_over_tls_from_a_subnet_the_firewall_admits():
    _, alpha, _ = model(alpha=ALPHA_BINDINGS, tree=TREE)
    specs = {s.canary.dn.split(",", 1)[0][3:]: s for s in canary_specs(alpha, ENDPOINTS)}
    bind = specs["bind"]
    assert (bind.url, bind.why, bind.secret, bind.exposure) == ("ldaps://ldap.example.test:1636", None, None,
                                                                "internal")
    assert [s.dn.split(",", 1)[0] for s in bind.subnets] == ["cn=subnet-web"]
    assert specs["bind-plain"].why.startswith("service name svc-ldap serves plain LDAP (port 389)")


def test_a_canary_binding_names_the_subnets_its_check_runs_from():
    named = entry(ALPHA, "ciam-bind", "ciamCanaryBinding", ciamBindingRole="canary-bind", ciamRealizes="bind",
                  ciamProviderRef="arn:aws:synthetics:us-east-1:111122223333:canary:ciam-bind",
                  ciamSubnetRole="subnet-ds")
    _, alpha, _ = model(alpha=(*ALPHA_BINDINGS, named), tree=TREE)
    bind = next(s for s in canary_specs(alpha, ENDPOINTS) if s.name == "ciam-bind")
    assert [s.dn.split(",", 1)[0] for s in bind.subnets] == ["cn=subnet-ds"]
