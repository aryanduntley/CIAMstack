"""What a cloud renders of a canary: the URL its flow requests on the checked service name (the products' endpoint
path, through the edge's policies; a SAML sign-in's start naming its service provider; an LDAPS bind), its name (the
canary binding realizing it), interval and credentials, and where an internal service's check runs from; and why a
canary isn't rendered (a flow nothing describes, no credentials, no concrete path, no service provider)."""
import base64

from opsdir.core.contract import Endpoint
from opsdir.domains.observability.canaries import canary_specs, unrendered_note
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir.domains.observability.naming import CANARIES
from network_fixtures import ALPHA, entry, model, rule
from pki_samples import CA_PEM, CERTIFICATES

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


# A private CA hierarchy: the LDAPS service name presents a certificate the issuing CA issued under the root
def _private_ca(root_pem=None):
    certificate = (lambda cn, purpose, **attrs: entry(CERTIFICATES, cn, "ciamCertificate", ciamCertPurpose=purpose,
                                                      ciamFingerprint="AA:BB", ciamNotAfter="20310115000000Z",
                                                      **attrs).replace("objectClass: ciamCertificate",
                                                                       "objectClass: ciamObject\n"
                                                                       "objectClass: ciamCertificate"))
    pem = f"ciamCertificatePem:: {base64.b64encode(CA_PEM.encode()).decode()}\n" if root_pem else ""
    return (f"dn: {CERTIFICATES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
            certificate("corp-root", "ca", ciamSubject="CN=Corp Root CA", ciamIssuer="CN=Corp Root CA") + pem,
            certificate("issuing", "ca", ciamSubject="CN=Issuing CA", ciamIssuer="CN=Corp Root CA",
                        ciamIssuedBy=f"cn=corp-root,{CERTIFICATES}"),
            certificate("ldaps-cert", "tls-server", ciamIssuer="CN=Issuing CA",
                        ciamIssuedBy=f"cn=issuing,{CERTIFICATES}"))


def _ldaps_presenting_a_private_certificate():
    return tuple(b.replace("ciamFrontendIp: 10.1.1.100\n",
                           f"ciamFrontendIp: 10.1.1.100\nciamTlsCertificate: cn=ldaps-cert,{CERTIFICATES}\n")
                 if b.startswith("dn: cn=svc-ldaps,") else b for b in ALPHA_BINDINGS)


def _bind(root_pem):
    _, alpha, _ = model(alpha=_ldaps_presenting_a_private_certificate(), tree=(*TREE, *_private_ca(root_pem)))
    return next(s for s in canary_specs(alpha, ENDPOINTS) if s.canary.dn.startswith("cn=bind,"))


def test_a_check_of_a_service_a_private_ca_certified_is_given_the_ca_the_record_holds():
    bind = _bind(root_pem=True)
    assert (bind.why, bind.trust.pem, bind.trust.partial) == (None, CA_PEM, False)
    # a service name presenting no certificate, or one no recorded CA issued: the runtime's trust store decides
    alive = next(s for s in canary_specs(model(alpha=ALPHA_BINDINGS, tree=TREE)[1], ENDPOINTS)
                 if s.canary.dn.startswith("cn=alive,"))
    assert alive.trust is None


def test_a_check_whose_private_ca_the_record_holds_no_pem_of_isnt_rendered():
    bind = _bind(root_pem=False)
    assert bind.why == ("service name svc-ldaps presents certificate ldaps-cert, issued by CA issuing (issuing -> "
                        "corp-root), and the record holds the certificate (PEM) of none of those CAs: its runtime "
                        "wouldn't trust it")
    assert bind.how == ("Record the CA certificate itself (public material, never a key) on corp-root (owner: "
                        "**NO OWNER**), or else issuing (owner: **NO OWNER**) as the check's anchor: "
                        "ciamCertificatePem, under an approved change, and re-render; the check is then given it to "
                        "trust",)
    note = unrendered_note(model(alpha=_ldaps_presenting_a_private_certificate(),
                                 tree=(*TREE, *_private_ca()))[1], bind)
    assert (note.severity, note.subject) == ("action", "canary bind")
