"""Certificate sign-in at PingAM (core pki trust policies, milestone 122; research docs/research m122 forwarded
certificates and m120 section 5). Pure.

A client-auth trust policy an AM role accepts (ciamAcceptedByRole am) gets, per environment, a certificate journey in
each realm it names (ciamAcceptedByService) that AM serves; naming none, it gets no journey and an action asking which
realms accept it (a realm is never inferred from hosts):
  am/realms/<realm>/AuthTree/certificate-<policy>.json         the journey, disabled: its outcomes are a person's to
                                                                wire (AM's outcome IDs aren't established)
  am/realms/<realm>/CertificateCollectorNode/<id>.json          an edge-enforced policy: the header the edge forwards
                                                                the certificate in (Services.cert_forwarding), and as
                                                                trustedRemoteHosts the edge's sources that are single
                                                                addresses (AM documents an IP list; never "any")
  am/realms/<realm>/CertificateValidationNode/<id>.json         checkCertificateExpiry, and matchCertificateToCRL and
                                                                ocspValidationEnabled from ciamRevocationMode
  am/realms/<realm>/CertificateUserExtractorNode/<id>.json      the user extractor (its settings are notes)
Node IDs are derived from the realm, the policy and the node (UUID v5), so a render is the same every time. The literals
AM 8.1's reference doesn't establish (the collection method's and the extractor's enum values, the outcome IDs) are not
rendered: an action names the value to choose. So is what has no rendered surface: AM's truststore holding the policy's
CAs (an unconfigured Validation node returns True), OCSP's server defaults, CRL matching's directory settings, the web
container requesting client certificates (product-enforced), and how AM decodes the forwarded header. An edge policy
whose edge forwards no certificate is a blocker and gets no journey. The read-back of a render leaves these journeys out
(amster_read_back): they are the trust policy's render, not AM's own journeys.
"""
import ipaddress
import uuid

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.jsondata import indented
from opsdir.core.notes import note
from opsdir.domains.pki.trust import (CLIENT_AUTH, accepting_services, bundle_certificates, enforced_at, fp,
                                      policy_services, trust_policies)
from .realms import SERVER_ROLES, export_dir, realm_path, realms
from .render import entity

AREA = "Trust"
COLLECTOR, VALIDATION, EXTRACTOR = "CertificateCollectorNode", "CertificateValidationNode", \
    "CertificateUserExtractorNode"
NODES = ((COLLECTOR, "Collect certificate"), (VALIDATION, "Validate certificate"), (EXTRACTOR, "Find the user"))
# the identity mapping as AM 8.1's user extractor offers it (the reference's choices; their JSON values aren't
# established): (Certificate Field Used to Access User Profile, SubjectAltNameExt Value Type to Access User Profile)
EXTRACTOR_CHOICES = {"subject-dn": ("Subject DN", "None"), "subject-cn": ("Subject CN", "None"),
                     "san-email": (None, "RFC822Name"), "san-upn": (None, "UPN")}
WIRING = ("Collected -> Validate certificate, Not Collected -> failure; Validate certificate True -> Find the user, "
          "False, Not found, Expired, Path Validation Failed and Revoked -> failure; Find the user Extracted -> "
          "success, Not Extracted -> failure")


def certificate_policies(d):
    """The client-auth trust policies an AM role accepts."""
    return tuple(p for p in trust_policies(d) if one(p, "ciamTrustPurpose") == CLIENT_AUTH
                 and set(values(p, "ciamAcceptedByRole")) & set(SERVER_ROLES))


def journey_name(policy):
    return f"certificate-{rdn_value(policy)}"


def _am_services(m, policy):
    """The service names of environment m accepting a policy that front AM."""
    return tuple(s for s in accepting_services(m, policy) if one(s, "ciamTargetRole") in SERVER_ROLES)


def policy_realms(d, policy):
    """The realms a policy accepts certificates in: the identity services it names (ciamAcceptedByService) that AM
    serves, in the policy's order."""
    served = {r.norm for r in realms(d)}
    return tuple(s for s in policy_services(d, policy) if s.norm in served)


def node_id(path, policy, kind):
    """A certificate journey node's ID: a UUID derived from the realm path, the policy and the node type."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"opsdir:pingam:{path}:{rdn_value(policy)}:{kind}"))


def forwardings(m, services, policy):
    """((service name, CertForwarding or None), ...) of the service names fronting AM under an edge policy."""
    return tuple((s, services.cert_forwarding(m, s)) for s in _am_services(m, policy))


def trusted_hosts(sources):
    """(the addresses AM can list: the sources that are single IPv4 or IPv6 addresses (/32, /128), the other
    sources)."""
    nets = tuple((c, ipaddress.ip_network(c, strict=False)) for c in sources)
    return (tuple(str(n.network_address) for _, n in nets if n.num_addresses == 1),
            tuple(c for c, n in nets if n.num_addresses != 1))


def _forwarded(m, services, policy):
    """The CertForwardings of an edge policy's AM service names that forward a certificate, distinct, in order."""
    return tuple(dict.fromkeys(f for _, f in forwardings(m, services, policy) if f is not None))


def _collector(m, services, policy):
    if enforced_at(policy) != "edge":
        return {}
    found = _forwarded(m, services, policy)
    sources = tuple(dict.fromkeys(c for f in found if f.header == found[0].header for c in f.sources))
    return {"clientCertificateHttpHeaderName": found[0].header, "trustedRemoteHosts": list(trusted_hosts(sources)[0])}


def _validation(policy):
    mode = one(policy, "ciamRevocationMode") or "none"
    return {"checkCertificateExpiry": True, "matchCertificateToCRL": "crl" in mode,
            "ocspValidationEnabled": "ocsp" in mode}


def _journey(m, services, policy, realm):
    path = realm_path(realm)
    base = f"am/{export_dir(path)}"
    ids = {kind: node_id(path, policy, kind) for kind, _ in NODES}
    settings = {COLLECTOR: _collector(m, services, policy), VALIDATION: _validation(policy), EXTRACTOR: {}}
    tree = entity(path, "AuthTree", journey_name(policy), {
        "entryNodeId": ids[COLLECTOR], "enabled": False,
        "description": f"Client certificates under trust policy {rdn_value(policy)} (rendered by opsdir)",
        "nodes": {ids[kind]: {"nodeType": kind, "displayName": label, "connections": {}} for kind, label in NODES}})
    return {f"{base}/AuthTree/{journey_name(policy)}.json": indented(tree),
            **{f"{base}/{kind}/{ids[kind]}.json": indented(entity(path, kind, ids[kind], {
                **settings[kind], "_type": {"_id": kind}})) for kind, _ in NODES}}


def _blocked(m, services, policy):
    """Whether an edge policy's edge forwards no certificate to AM (nothing to collect)."""
    return enforced_at(policy) == "edge" and not _forwarded(m, services, policy)


def render_certificate_journeys(m, services):
    """{path: text}: the certificate journeys of environment m (render_env)."""
    return {path: text for p in certificate_policies(m.d) if not _blocked(m, services, p)
            for r in policy_realms(m.d, p) for path, text in _journey(m, services, p, r).items()}


def certificate_paths(d):
    """The Amster export paths (below am/) a certificate journey can take in any environment: its tree and nodes in
    every realm AM serves."""
    return frozenset(path for p in certificate_policies(d) for r in realms(d) for path in (
        f"{export_dir(realm_path(r))}/AuthTree/{journey_name(p)}.json",
        *(f"{export_dir(realm_path(r))}/{kind}/{node_id(realm_path(r), p, kind)}.json" for kind, _ in NODES)))


def amster_read_back(files, d, environment=None):
    """The rendered Amster files without the certificate journeys (Adapter.reads_back's prepare): they are the trust
    policies' render, and reading them back would make them AM's own journeys."""
    rendered = certificate_paths(d)
    return {path: text for path, text in files.items() if path not in rendered}


# ------------------------------------------------------------------ notes
def _finish(m, policy, where):
    """The action naming the journey's settings whose JSON values aren't established, and its wiring."""
    field, extension = EXTRACTOR_CHOICES.get(one(policy, "ciamIdentityMapping") or "none", (None, None))
    method = "Header" if enforced_at(policy) == "edge" else "Request"
    extractor = (f"Find the user: Certificate Field Used to Access User Profile `{field or 'None'}` and "
                 f"SubjectAltNameExt Value Type to Access User Profile `{extension}`" if extension else
                 "Find the user: the policy records no identity mapping (ciamIdentityMapping), and AM signs in a "
                 "user: record how a certificate maps to an account")
    return note(AREA, "action", where,
                "AM's reference doesn't establish the JSON values of the certificate nodes' choices or of their "
                "outcomes, so the journey is rendered disabled with them unset",
                (f"In the journey, set Collect certificate: Certificate Collection Method `{method}`; {extractor}",
                 f"Wire its outcomes: {WIRING}; then enable it, and export it so the record's render can hold the "
                 "values"), policy.dn, m.label)


def _truststore(m, policy, where):
    cas = "; ".join(f"{one(c, 'ciamSubject') or rdn_value(c)} (SHA-256 {fp(c)})"
                    for c in bundle_certificates(m.d, policy))
    return note(AREA, "action", where,
                "AM validates the chain against its truststore, which must hold the policy's CA certificates "
                f"({cas or 'none recorded'}); how it is provisioned isn't established, and an unconfigured Validation "
                "node returns True",
                ("Import the CA certificates into the truststore the certificate nodes use (AM documents its web "
                 "container's javax.net.ssl.trustStore; confirm the nodes read it), keep it in step with the policy, "
                 "and test that a certificate from another CA is refused",), policy.dn, m.label)


def _revocation(m, policy, where):
    mode = one(policy, "ciamRevocationMode") or "none"
    failure = one(policy, "ciamRevocationFailure")
    return (*((note(AREA, "action", where, "OCSP checking also needs AM's server defaults",
                    ("Configure -> Server Defaults -> Security -> Online Certificate Status Protocol Check: enable it "
                     "(and the responder, where certificates name none)",), policy.dn, m.label),)
              if "ocsp" in mode else ()),
            *((note(AREA, "action", where, "CRL matching reads CRLs from a directory the node names",
                    ("Set the Validation node's crlMatchingCertificateAttribute, updateCRLsFromDistributionPoint and "
                     "its directory settings (certificateLdapServers, ldapSearchStartDN, userBindDN; the bind password "
                     "from the environment)",), policy.dn, m.label),) if "crl" in mode else ()),
            *((note(AREA, "note", where, f"the policy's revocation mode {mode} orders OCSP and CRLs, and on failure "
                    f"{failure or 'unset'}: AM's Validation node enables each check, with no order or failure policy "
                    "established", (), policy.dn, m.label),) if "-then-" in mode or failure else ()))


def _edge(m, services, policy, where):
    """Notes about the certificate an edge forwards: none forwarded (blocker), several headers, sources AM can't list,
    the header's encoding."""
    found = forwardings(m, services, policy)
    forwarded = _forwarded(m, services, policy)
    if not forwarded:
        names = ", ".join(one(s, "ciamFqdn") or rdn_value(s) for s, _ in found) or "no service name"
        return (note(AREA, "blocker", where, f"checked at the edge, but the edge in front of AM ({names}) forwards no "
                     "client certificate: no certificate journey is rendered",
                     ("Terminate TLS at a load balancer that verifies client certificates, or check them at the "
                      "product (ciamTrustEnforcedAt product)",), policy.dn, m.label),)
    header = forwarded[0].header
    _, unlisted = trusted_hosts(tuple(c for f in forwarded if f.header == header for c in f.sources))
    plain = [one(s, "ciamFqdn") or rdn_value(s) for s, f in found if f is None]
    headers = ", ".join(dict.fromkeys(f.header for f in forwarded))
    return (*((note(AREA, "action", where, f"the edge forwards the certificate in {headers}: the journey reads "
                    f"{header} only", ("Forward it in one header for every service name",),
                    policy.dn, m.label),) if len({f.header for f in forwarded}) > 1 else ()),
            *((note(AREA, "action", where, f"{', '.join(plain)} forward no client certificate: a certificate sign-in "
                    "through them fails", ("Verify client certificates there too, or stop accepting the policy "
                                            "there",), policy.dn, m.label),) if plain else ()),
            *((note(AREA, "action", where, "AM trusts the certificate header only from the addresses it lists "
                    f"(trustedRemoteHosts, documented as IP addresses), and the edge's requests come from "
                    f"{', '.join(unlisted)}: none of them is listed, so AM refuses the header from them",
                    ("List the edge's own addresses (its load balancer nodes' private addresses) in Collect "
                     "certificate's trustedRemoteHosts; never `any`",), policy.dn, m.label),) if unlisted else ()),
            *((note(AREA, "action", where, "the edge's requests come from no recorded addresses: AM refuses the "
                    "certificate header from everyone", ("Record the edge's subnets, or list its addresses in "
                                                         "trustedRemoteHosts",), policy.dn, m.label),)
              if not any(f.sources for f in forwarded) else ()),
            note(AREA, "action", where, f"the edge forwards the certificate {forwarded[0].encoding} "
                 f"({forwarded[0].holds}); how AM's collector decodes a header (URL-encoded PEM keeping a literal "
                 "`+`, line breaks) isn't established", ("Sign in with a test certificate through the edge before "
                                                         "relying on the journey",), policy.dn, m.label))


def _unnamed(m, policy, where):
    """The action for a policy naming no realm AM serves (no journey): which realms to choose from."""
    named = [rdn_value(s) for s in policy_services(m.d, policy)]
    offered = ", ".join(f"{rdn_value(r)} ({realm_path(r)})" for r in realms(m.d)) or "none recorded"
    return note(AREA, "action", where,
                (f"it names {', '.join(named)} (ciamAcceptedByService), none of them a realm AM serves" if named else
                 "it names no realm that accepts its certificates (ciamAcceptedByService)")
                + ": no certificate journey is rendered",
                (f"Record which realm(s) accept the policy (ciamAcceptedByService: the realm's identity service; AM "
                 f"serves {offered})",), policy.dn, m.label)


def _policy_notes(m, services, policy):
    where = f"trust policy {rdn_value(policy)}"
    unnamed = () if policy_realms(m.d, policy) else (_unnamed(m, policy, where),)
    if _blocked(m, services, policy) or unnamed:
        return (*(_edge(m, services, policy, where) if _blocked(m, services, policy) else ()), *unnamed)
    unchecked = [*values(policy, "ciamAllowedPolicyOid"), *values(policy, "ciamRequiredEku")]
    return (_finish(m, policy, where), _truststore(m, policy, where), *_revocation(m, policy, where),
            *(_edge(m, services, policy, where) if enforced_at(policy) == "edge" else
              (note(AREA, "action", where, "AM collects the certificate from the request: TLS must reach AM with "
                    "client authentication", ("Have AM's web container request client certificates on its HTTPS "
                                              "connector, trusting the policy's CAs",), policy.dn, m.label),)),
            *((note(AREA, "note", where, f"AM's certificate nodes don't check certificate policies or key usages "
                    f"({', '.join(unchecked)})", ("Check them where the certificate is issued, or at the edge",),
                    policy.dn, m.label),) if unchecked else ()))


def certificate_notes(m, services):
    """Render notes (Adapter.notes) for each client-auth trust policy an AM role accepts in environment m: what its
    certificate journey leaves to people, and a blocker where its edge forwards no certificate."""
    return tuple(n for p in certificate_policies(m.d) for n in _policy_notes(m, services, p))
