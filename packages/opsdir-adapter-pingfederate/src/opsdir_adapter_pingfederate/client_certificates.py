"""PingFederate's part of the client-certificate trust policies (core pki trust, milestone 122; research
2026-10-17-m122-forwarded-certs section B and 2026-10-17-m120 section 5). Pure, but for the spec it loads.

A client-auth trust policy whose accepting roles (ciamAcceptedByRole) include a PingFederate role the environment runs
becomes Admin API requests, which the admin-api, terraform and bulk-config targets render like every other request
(admin_api.requests):

  POST /certificates/ca/import        each CA certificate the policy's consumers trust (trust.bundle_certificates:
                                      its anchors and the followed bundles' subordinate CAs chaining to them), once
                                      across the policies, as a trusted CA: id <name>-<SHA-256 prefix>, fileData its
                                      DER in base64 (public material; the provider's validation refuses PEM armour);
                                      terraform pingfederate_certificate_ca; not in the bulk document (its resource
                                      type and item form there aren't established)
  PUT /certificates/revocation/settings
                                      the policies' ciamRevocationMode and failure policy (one setting per
                                      PingFederate: policies that disagree render none):
                                        ocsp            ocspSettings, its three actions FAIL (reject, cached) or
                                                        CONTINUE (allow); cached: responseCachePeriod its hours
                                        crl             crlSettings, treatNonRetrievableCrlAsRevoked unless allow,
                                                        verifyCrlSignature
                                        ocsp-then-crl   both, the OCSP actions FAILOVER (to the CRL)
                                        crl-then-ocsp   none: PingFederate fails over from OCSP only (an action)
                                        none            none: PingFederate's settings stay as they are
                                      with the environment's explicit proxy (proxySettings), which a PUT would clear
  PUT /incomingProxySettings          for a policy checked at the edge: client certificate header authentication on,
                                      the header the load balancer forwards the certificate in
                                      (Services.cert_forwarding) and its encoding: url-pem as NGINX (PingFederate's
                                      nginx example forwards $ssl_client_escaped_cert, URL-encoded PEM), pem as
                                      APACHE_MOD_SSL (its Apache example forwards %{SSL_CLIENT_CERT}s); a property the
                                      version's spec lacks is left
                                      out and named

Settings held as is from an export (generic.held_resources) are kept: the policy's properties replace theirs in one
request. What the render leaves to people is render notes (trust_notes): the X.509 Certificate IdP Adapter instance
(its plugin class and field names aren't established: configure it by hand, the issuer DNs given), the certificate
policies, key usages and identity mapping PingFederate isn't given, confirming the CA import and the header's decoding
with a real request, restricting the engines' listener to the edge's sources (PingFederate has no allowlist for the
header: anyone reaching it directly can set it), and blockers where nothing verifies at the edge or nothing is trusted.
"""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import RECORD, note
from opsdir.domains.compute.workloads import runs_here
from opsdir.domains.network.proxies import proxy_settings
from opsdir.domains.pki.trust import (CLIENT_AUTH, accepting_services, bundle_certificates, enforced_at, fp,
                                      policy_anchors, trust_policies)
from .admin_api_spec import load_spec, spec_version
from .naming import SERVER_ROLES
from .versions import pingfederate_version

AREA = "Trust"
CA_IMPORT = "/certificates/ca/import"
REVOCATION = "/certificates/revocation/settings"
INCOMING_PROXY = "/incomingProxySettings"
TRUST_SETTINGS = (REVOCATION, INCOMING_PROXY)     # read back from a render, they hold no new fact (importer)
# CertForwarding.encoding -> PingFederate's clientCertHeaderEncodingFormat (the others it doesn't document)
ENCODINGS = {"url-pem": "NGINX", "pem": "APACHE_MOD_SSL"}
# the properties of each settings object the trust policies decide (a held object's others are kept)
HEADER_KEYS = ("enableClientCertHeaderAuth", "clientCertSSLHeaderName", "clientCertHeaderEncodingFormat")
REVOCATION_KEYS = ("crlSettings", "ocspSettings")
_ACTIONS = ("actionOnResponderUnavailable", "actionOnStatusUnknown", "actionOnUnsuccessfulResponse")
_UNSAFE = re.compile(r"[^a-z0-9._-]+")
# how the X.509 adapter's attributes carry each identity mapping (Ping's adapter documentation: the optional
# userPrincipalName and RFC822Name attributes, the subject DN's components)
MAPPINGS = {"san-upn": "userPrincipalName attribute (the SAN's UPN)", "san-email": "RFC822Name attribute (the SAN's "
            "email)", "subject-dn": "subject DN", "subject-cn": "subject DN's CN component"}


def pf_policies(m):
    """The client-auth trust policies accepted by a PingFederate role environment m runs, in record order."""
    return tuple(p for p in trust_policies(m.d) if one(p, "ciamTrustPurpose") == CLIENT_AUTH
                 and any(r in SERVER_ROLES and runs_here(m, r) for r in values(p, "ciamAcceptedByRole")))


def ca_id(cert):
    """The id a CA certificate is imported under: its name in PingFederate's id characters ([a-z0-9._-]), with the
    first 8 hex digits of its SHA-256 fingerprint when it records one (at most 32 characters)."""
    name = _UNSAFE.sub("-", rdn_value(cert).lower()).strip("-")[:23] or "ca"
    digest = fp(cert).replace(":", "").lower()[:8]
    return f"{name}-{digest}" if digest else name


def trusted_cas(m):
    """The CA certificates environment m's PingFederate trusts for its trust policies: each policy's
    bundle_certificates with a PEM, once by fingerprint, in policy order."""
    seen = {}
    for c in (c for p in pf_policies(m) for c in bundle_certificates(m.d, p) if one(c, "ciamCertificatePem")):
        seen.setdefault(fp(c) or c.norm, c)
    return tuple(seen.values())


def ca_import_body(cert):
    """The /certificates/ca/import body of a CA certificate: its id, and as fileData its DER in base64 (its PEM's body,
    without the armour and line breaks: the provider takes base64 only, and Ping describes the value as PEM with its
    line breaks omitted)."""
    pem = one(cert, "ciamCertificatePem")
    return {"id": ca_id(cert), "fileData": "".join(line.strip() for line in pem.splitlines()
                                                   if line.strip() and not line.startswith("-----"))}


def revocation_settings(p):
    """{crlSettings?, ocspSettings?} of a policy's revocation mode and failure policy, or None when PingFederate can't
    say it (crl-then-ocsp) or the policy checks none."""
    mode, failure = one(p, "ciamRevocationMode"), one(p, "ciamRevocationFailure") or "reject"
    hours = one(p, "ciamRevocationCacheHours")
    if mode not in ("ocsp", "crl", "ocsp-then-crl"):
        return None
    action = "FAILOVER" if mode == "ocsp-then-crl" else "CONTINUE" if failure == "allow" else "FAIL"
    ocsp = {**{a: action for a in _ACTIONS},
            **({"responseCachePeriod": int(hours)} if failure == "cached" and hours else {})}
    crl = {"treatNonRetrievableCrlAsRevoked": failure != "allow", "verifyCrlSignature": True}
    return {**({"crlSettings": crl} if mode != "ocsp" else {}), **({"ocspSettings": ocsp} if mode != "crl" else {})}


def revocation_body(m):
    """The /certificates/revocation/settings body environment m's trust policies agree on (with its explicit proxy),
    or None (no policy checks revocation in a way PingFederate takes, or they disagree)."""
    said = tuple(s for s in map(revocation_settings, pf_policies(m)) if s)
    if len({repr(s) for s in said}) != 1:
        return None
    proxy = proxy_settings(m)
    return {**said[0], **({"proxySettings": {"host": proxy.host, "port": proxy.port}} if proxy else {})}


def edge_services(m, p):
    """The service names of environment m in front of a policy's PingFederate roles."""
    return tuple(s for s in accepting_services(m, p) if one(s, "ciamTargetRole") in SERVER_ROLES)


def forwardings(m, services):
    """((policy, service name, CertForwarding or None), ...) of environment m's edge-checked PingFederate policies."""
    if services is None:
        return ()
    return tuple((p, s, services.cert_forwarding(m, s)) for p in pf_policies(m) if enforced_at(p) == "edge"
                 for s in edge_services(m, p))


def _spec_keys(m, schema):
    """The properties a schema has in the Admin API spec of environment m's version, or None (no spec vendored)."""
    vendored = spec_version(pingfederate_version(m)[0])
    return set(load_spec(vendored)["schemas"][schema].get("properties") or ()) if vendored else None


def header_settings(m, services):
    """(the /incomingProxySettings properties of environment m's edge-checked policies, or None; the properties the
    version's spec lacks, left out): rendered when every service name in front of a PingFederate role forwards the
    certificate the same way, in an encoding PingFederate decodes."""
    found = tuple(dict.fromkeys((f.header, f.encoding) for _, _, f in forwardings(m, services) if f))
    if len(found) != 1 or found[0][1] not in ENCODINGS:
        return None, ()
    header, encoding = found[0]
    body = {"enableClientCertHeaderAuth": True, "clientCertSSLHeaderName": header,
            "clientCertHeaderEncodingFormat": ENCODINGS[encoding]}
    keys = _spec_keys(m, "IncomingProxySettings")
    return {k: v for k, v in body.items() if keys is None or k in keys}, \
        tuple(k for k in body if keys is not None and k not in keys)


def trust_settings(m, services=None):
    """((path, body, the properties it decides), ...) of the settings environment m's trust policies set: revocation,
    and, with the Services (for the edge's forwarding), the incoming proxy's certificate header."""
    if not pf_policies(m):
        return ()
    revocation = revocation_body(m)
    header, _ = header_settings(m, services)
    proxied = ("proxySettings",) if revocation and "proxySettings" in revocation else ()
    return (*(((REVOCATION, revocation, (*REVOCATION_KEYS, *proxied)),) if revocation else ()),
            *(((INCOMING_PROXY, header, HEADER_KEYS),) if header else ()))


def merged(held, body, decided):
    """A settings body: the held one's properties but those the trust policies decide, then theirs."""
    return {**{k: v for k, v in (held or {}).items() if k not in decided}, **body}


# ------------------------------------------------------------------ render notes
def _named(p):
    return f"trust policy {rdn_value(p)}"


def _subjects(m, p):
    return tuple(one(a, "ciamSubject") for a in policy_anchors(m.d, p) if one(a, "ciamSubject"))


def _policy_notes(m, p):
    """What one policy leaves to a person in PingFederate: nothing to trust, the X.509 adapter, what it isn't
    given."""
    issuers = _subjects(m, p)
    oids, ekus, mapping = values(p, "ciamAllowedPolicyOid"), values(p, "ciamRequiredEku"), one(p, "ciamIdentityMapping")
    edge = enforced_at(p) == "edge"
    return (
        *((note(AREA, "blocker", _named(p), "PingFederate is given no CA certificate to trust: none of its anchors "
                "and followed bundles' CAs records a PEM", ("Record the anchors' PEM (ciamCertificatePem), " + RECORD,),
                p.dn, m.label),) if not any(one(c, "ciamCertificatePem") for c in bundle_certificates(m.d, p)) else ()),
        note(AREA, "action", _named(p), "the X.509 Certificate IdP Adapter instance that signs users in with these "
             "certificates is not rendered: its plugin class and field names aren't established",
             (f"In {m.label}'s PingFederate, create an X.509 Certificate IdP Adapter instance"
              + (" (the certificate arrives in the header the load balancer sets: Incoming Proxy Settings)" if edge
                 else " with a Client Auth Port PingFederate's TLS listener asks for client certificates on"),
              "Constrain Acceptable Root Issuers, Issuer DN: " + ("; ".join(issuers) or "(the anchors record no "
                                                                   "subject: read them from the CA certificates)"),
              "Use it in the authentication policy of the applications the policy is for"), p.dn, m.label),
        *((note(AREA, "action", _named(p), "PingFederate is not given the policy's "
                + " and ".join(w for w, v in (("certificate policies (" + ", ".join(oids) + ")", oids),
                                              ("extended key usages (" + ", ".join(ekus) + ")", ekus)) if v)
                + ": no established adapter setting checks them, so it accepts any certificate the trusted CAs issue",
                ("Check them in the authentication policy (an issuance criterion on the adapter's attributes) or at "
                 "a component that can, and record where",), p.dn, m.label),) if oids or ekus else ()),
        *((note(AREA, "action", _named(p), f"its identity mapping ({mapping}) is not rendered",
                (f"Map the account from the X.509 adapter's {MAPPINGS.get(mapping, mapping)} in the authentication "
                 "policy's contract fulfilment",), p.dn, m.label),) if mapping and mapping != "none" else ()))


def _revocation_notes(m):
    policies = pf_policies(m)
    said = {rdn_value(p): revocation_settings(p) for p in policies}
    distinct = tuple(dict.fromkeys(repr(s) for s in said.values() if s))
    return (
        *(note(AREA, "action", _named(p), "PingFederate can't check CRLs before OCSP (it fails over from OCSP to the "
               "CRL only): its revocation settings are not rendered",
               ("Choose ocsp-then-crl, or set PingFederate's Certificate Revocation Checking by hand",), p.dn, m.label)
          for p in policies if one(p, "ciamRevocationMode") == "crl-then-ocsp"),
        *((note(AREA, "action", "certificate revocation checking", "PingFederate has one revocation setting, and its "
                f"trust policies disagree ({', '.join(n for n, s in said.items() if s)}): none is rendered",
                ("Give the policies PingFederate accepts the same ciamRevocationMode and failure policy, " + RECORD,),
                None, m.label),) if len(distinct) > 1 else ()),
        *((note(AREA, "note", _named(p), "it sets no failure policy (ciamRevocationFailure): PingFederate is told to "
                "reject a certificate whose revocation can't be checked", (), p.dn, m.label)
           for p in policies if revocation_settings(p) and not one(p, "ciamRevocationFailure"))),
        *(note(AREA, "note", _named(p), "it accepts cached revocation answers: PingFederate caches OCSP answers for "
               "the policy's hours (responseCachePeriod), and is told to reject when no answer comes; that it answers "
               "from its cache while the responder is down, and how long it keeps a CRL, aren't established", (),
               p.dn, m.label)
          for p in policies if revocation_settings(p) and one(p, "ciamRevocationFailure") == "cached"))


def _header_notes(m, services):
    """What the edge's forwarding leaves: nothing verifies, an encoding PingFederate doesn't decode or isn't confirmed
    to, forwardings that disagree, and the engines' listener to restrict."""
    found = forwardings(m, services)
    pairs = tuple(dict.fromkeys((f.header, f.encoding) for _, _, f in found if f))
    _, missing = header_settings(m, services)
    return (
        *(note(AREA, "blocker", f"service name {rdn_value(s)}", f"{_named(p)} is checked at the edge, but nothing in "
               f"front of `{one(s, 'ciamTargetRole')}` verifies client certificates: PingFederate gets none",
               ("Record the load balancer that verifies them (the cloud adapter's mTLS), or check them at the product "
                "(ciamTrustEnforcedAt product), " + RECORD,), p.dn, m.label) for p, s, f in found if f is None),
        *(note(AREA, "blocker", f"service name {rdn_value(s)}", f"its load balancer forwards the certificate in "
               f"{f.header} as {f.encoding}, which PingFederate doesn't document decoding (it decodes the "
               "nginx and Apache mod_ssl forms): client certificate header authentication is not rendered",
               ("Forward the certificate URL-encoded (nginx) or as PEM (Apache), or check it at the product",),
               p.dn, m.label) for p, s, f in found if f and f.encoding not in ENCODINGS),
        *((note(AREA, "blocker", "incoming proxy settings", "PingFederate reads the client certificate from one "
                "header, and its load balancers forward it differently ("
                + "; ".join(f"{h} as {e}" for h, e in pairs) + "): not rendered",
                ("Forward it the same way at every load balancer in front of PingFederate",),
                None, m.label),) if len(pairs) > 1 else ()),
        *(note(AREA, "action", "incoming proxy settings", f"PingFederate reads the certificate in {h}"
               + (f" as {ENCODINGS[e]}" if "clientCertHeaderEncodingFormat" not in missing else "")
               + f"; that it decodes the load balancer's {e} is not confirmed"
               + (" (an ALB leaves '+' unescaped, a form decoder reads it as a space)" if e == "url-pem" else
                  " (how the PEM's line breaks travel is not established)"),
               ("Sign in through the load balancer with a test certificate and check PingFederate's server log shows "
                "the certificate's subject",), None, m.label)
          for h, e in pairs if e in ENCODINGS and len(pairs) == 1),
        *((note(AREA, "action", "incoming proxy settings", f"the Admin API of {pingfederate_version(m)[0]} has no "
                f"{', '.join(missing)}: left out", ("Confirm it reads the certificate header at all, or upgrade "
                                                           "PingFederate",), None, m.label),) if missing else ()),
        *(note(AREA, "action", f"service name {rdn_value(s)}", "PingFederate trusts the certificate header from "
               f"anyone who reaches it (it has no allowlist): restrict `{one(s, 'ciamTargetRole')}`'s listener to the "
               "load balancer's sources" + (f" ({', '.join(f.sources)})" if f.sources else
                                            " (the record doesn't say which: its subnets)"),
               ("Allow only those sources to the PingFederate engines' port in the security group, NSG or firewall "
                "in front of them",), p.dn, m.label) for p, s, f in found if f and f.encoding in ENCODINGS))


def trust_notes(m, services):
    """Adapter notes: what environment m's PingFederate render of its client-certificate trust policies leaves to a
    person (core.notes), () when no policy is accepted by a PingFederate role it runs."""
    policies = pf_policies(m)
    if not policies:
        return ()
    return (*(n for p in policies for n in _policy_notes(m, p)), *_revocation_notes(m), *_header_notes(m, services),
            *((note(AREA, "action", "trusted CA certificates", f"{_count(len(trusted_cas(m)), 'CA certificate')} "
                    "imported, fileData the DER in base64 (a form Ping's references don't confirm); the bulk "
                    "document leaves them out (its form for them isn't established)",
                    ("After applying, compare each imported CA's SHA-256 fingerprint in PingFederate (Trusted CAs) "
                     "with the record's; apply the admin-api or terraform target where the bulk document is used",),
                    None, m.label),) if trusted_cas(m) else ()))


def _count(n, word):
    return f"{n} {word}{'s' * (n != 1)}"
