"""Client certificates checked at the BIG-IPs (core pki trust policies enforced at the edge, milestone 122, decision
3302; research docs/research m120 section 5; AS3 schema 3.54.0, the BIG-IP iRules reference). Pure.

A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting role a service name of this environment
reaches through a terminating or re-encrypting virtual server (Service_HTTPS) gets, in that service name's
application:
  client_ca              a CA_Bundle holding the policy's bundle (core trust.policy_bundle: its approved anchors and
                         the followed bundles' subordinate CAs chaining to them; public certificates, in the
                         declaration)
  tls_server             authenticationMode require (no connection without a client certificate the bundle
                         validates), authenticationTrustCA client_ca, retainCertificateEnabled (the iRule reads the
                         certificate in HTTP_REQUEST)
  forward_client_cert    an iRule on the virtual server removing any HEADER the client sent and inserting the verified
                         certificate, [b64encode [SSL::cert 0]] (the BIG-IP iRules reference's own example: der-base64,
                         core CERT_ENCODINGS); the products trust that header only from the BIG-IPs' sources
                         (cert_forwarding)
What AS3 can't do from the record is a note: revocation (TLS_Server's crlFile names a CRL file already on the BIG-IP,
which the record doesn't hold; OCSP for client certificates is an SSL OCSP authentication profile, which AS3 doesn't
declare), the policy's certificate policies, key usages and identity mapping (the product checks them on the forwarded
certificate), and confirming on a BIG-IP that the header is the certificate's DER (the iRules reference doesn't say
which binary form SSL::cert returns). A policy with no anchor PEM, or a service name under it whose TLS passes
through (Service_TCP: nothing checks the certificate), is a blocker."""
from opsdir.core.contract import CertForwarding
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import note
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.infrastructure.appliances import appliances
from opsdir.domains.pki.trust import accepting_services, edge_policies, edge_policy_for, policy_bundle

AREA = "Trust"
HEADER = "X-SSL-Client-Cert"
ENCODING = "der-base64"          # [b64encode [SSL::cert 0]] (core CERT_ENCODINGS)
IRULE = "forward_client_cert"
IRULE_TEXT = ("when HTTP_REQUEST {\n"
              f"    HTTP::header remove {HEADER}\n"
              f"    HTTP::header insert {HEADER} [b64encode [SSL::cert 0]]\n"
              "}\n")


def verifying_policy(m, svc, spec):
    """The edge trust policy the BIG-IPs check a service name's client certificates under (spec: its EdgeSpec), or
    None: none applies, its virtual server passes TLS through, or no anchor records a PEM."""
    p = edge_policy_for(m, svc)
    return p if p is not None and spec is not None and spec.layer7 and policy_bundle(m.d, p) is not None else None


def client_authentication(m, svc, spec):
    """(TLS_Server properties, application objects, virtual server properties) checking a service name's client
    certificates under its edge trust policy and forwarding the verified one; ({}, {}, {}) when nothing is checked."""
    p = verifying_policy(m, svc, spec)
    if p is None:
        return {}, {}, {}
    return ({"authenticationMode": "require", "authenticationTrustCA": "client_ca", "retainCertificateEnabled": True},
            {"client_ca": {"class": "CA_Bundle", "bundle": policy_bundle(m.d, p)},
             IRULE: {"class": "iRule", "iRule": IRULE_TEXT}},
            {"iRules": [IRULE]})


def cert_forwarding(m, svc, stack_role):
    """Adapter cert_forwarding (stack_role: the BIG-IPs' stack role, bound by the adapter): the CertForwarding of the
    virtual server verifying a service name's client certificates (the leaf, der-base64, from the BIG-IPs' recorded
    sources, ciamApplianceSource), or None when none does."""
    if verifying_policy(m, svc, service_edge(m, svc, ())) is None:
        return None
    return CertForwarding(HEADER, ENCODING, "leaf", tuple(dict.fromkeys(
        c for a in appliances(m, stack_role) for c in values(a, "ciamApplianceSource"))))


def _lacking(m, p):
    """What a policy's virtual servers lack for the BIG-IPs to check its certificates."""
    plain = [one(s, "ciamFqdn") or rdn_value(s) for s in accepting_services(m, p)
             if (spec := service_edge(m, s, ())) is None or not spec.layer7]
    return (*(("an anchor recording its certificate (ciamCertificatePem)",) if policy_bundle(m.d, p) is None else ()),
            *((f"TLS terminated at the BIG-IPs for {', '.join(plain)} (it passes through: Service_TCP)",)
              if plain else ()))


def client_certificate_notes(m, services):
    """Render notes (Adapter.notes) per edge trust policy of environment m: a blocker when the BIG-IPs can't check it;
    else what they leave to people or products (revocation, the policy's restrictions, the header's encoding)."""
    def of(p):
        where, lacking = f"trust policy {rdn_value(p)}", _lacking(m, p)
        if lacking:
            return (note(AREA, "blocker", where, f"not enforced at {m.label}'s BIG-IPs: it needs {'; '.join(lacking)}",
                         ("Record what is missing (ciamTlsMode terminate or reencrypt on the service name's traffic "
                          "policy), or check the certificates at the product (ciamTrustEnforcedAt product)",),
                         p.dn, m.label),)
        mode = one(p, "ciamRevocationMode") or "none"
        return (
            *((note(AREA, "action", where, "the BIG-IPs' client SSL profiles check revocation only against a CRL file "
                    "already on the BIG-IP (crlFile) or an SSL OCSP authentication profile, neither of which the "
                    f"declaration can give from the record: revocation ({mode}, the policy's) isn't checked at the "
                    "load balancer", ("Check revocation at the product, or import the CAs' CRLs (or an SSL OCSP "
                                      "profile) on the BIG-IPs, keep them current and attach them to the "
                                      "virtual servers' client SSL profiles (outside opsdir's render)",),
                    p.dn, m.label),) if mode != "none" else ()),
            note(AREA, "note", where, "the BIG-IPs check the chain only: the policy's certificate policies, key usages "
                 f"and identity mapping are checked by the product on the certificate the BIG-IPs forward ({HEADER})",
                 (), p.dn, m.label),
            note(AREA, "action", where, f"the iRule {IRULE} forwards [b64encode [SSL::cert 0]] in {HEADER}, declared "
                 f"to the products as {ENCODING}; the iRules reference doesn't state that SSL::cert's binary form is "
                 "DER", (f"On a BIG-IP, base64-decode {HEADER} of a request the virtual server forwards and parse it "
                         "as DER (openssl x509 -inform der); if it isn't DER, report it to the platform team",),
                 p.dn, m.label))
    return tuple(n for p in edge_policies(m) for n in of(p))
