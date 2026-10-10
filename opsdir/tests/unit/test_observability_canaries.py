"""What a cloud renders of a canary: the URL its flow requests on the checked service name (the products' endpoint
path, through the edge's policies), its name (the canary binding realizing it), interval and credentials; and why a
canary isn't rendered (a flow no single request describes, no credentials, no concrete path)."""
from opsdir.core.contract import Endpoint
from opsdir.domains.observability.canaries import canary_specs
from opsdir.domains.observability.naming import CANARIES
from network_fixtures import ALPHA, entry, model

ENDPOINTS = (Endpoint("health", "/ping", "web"), Endpoint("token", "/as/token.oauth2", "web"),
             Endpoint("login", "/am/json/realms/*/authenticate", "web"))


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
        _canary("elsewhere", ciamCheckedService="ldaps", ciamCanaryFlow="ldap-bind"))
ALPHA_BINDINGS = (
    entry(ALPHA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test", ciamPort="8443",
          ciamTargetRole="web"),
    entry(ALPHA, "creds", "ciamSecretRef", ciamBindingRole="canary-creds",
          ciamRefUri="aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:canary"),
    entry(ALPHA, "ciam-alive", "ciamCanaryBinding", ciamBindingRole="canary-alive", ciamRealizes="alive",
          ciamProviderRef="arn:aws:synthetics:us-east-1:111122223333:canary:ciam-alive", ciamInterval="1m"))


def test_each_canary_the_environment_can_run_becomes_a_request_or_says_why_not():
    _, alpha, _ = model(alpha=ALPHA_BINDINGS, tree=TREE)
    specs = {s.canary.dn.split(",", 1)[0][3:]: s for s in canary_specs(alpha, ENDPOINTS)}
    assert set(specs) == {"alive", "token", "no-creds", "login", "saml"}     # ldaps isn't bound: not here
    alive, token = specs["alive"], specs["token"]
    assert (alive.name, alive.url, alive.every, alive.why) == ("ciam-alive", "https://sso.example.test:8443/ping",
                                                               60, None)
    assert (token.name, token.url, token.every, token.why) == ("token", "https://sso.example.test:8443/as/token.oauth2",
                                                               600, None)
    assert token.secret is not None and token.secret.dn.startswith("cn=creds,")
    assert specs["no-creds"].why == "an oidc-token check needs credentials and none of its ciamUsesRole is bound here"
    assert specs["login"].why == "the products serving web name no login path without wildcards"
    assert specs["saml"].why.startswith("a SAML sign-in needs a service provider")
