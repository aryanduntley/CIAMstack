"""Client certificates at PingGateway (core pki trust policies, milestone 122; research docs/research m122 forwarded
certificates and m120 section 5; PingGateway 2026 reference). Pure.

A client-auth trust policy the gateway role (ig) accepts is checked where the policy says:
  product (TLS reaches the gateway)
    pinggateway/secrets/client-ca/<policy>/<policy>.client-ca.pem    the policy's bundle (core trust.policy_bundle:
                                                                    public certificates), placed under the instance's
                                                                    secrets/ by the product profile
    pinggateway/admin-tls/<policy>.json                             what admin.json needs (a captured file this render
                                                                    doesn't rewrite: an action says to merge it): a
                                                                    SecretsProvider whose FileSystemSecretStore reads
                                                                    that file (suffix .pem, PLAIN, PemPropertyFormat),
                                                                    and the HTTPS connector's ServerTlsOptions with
                                                                    clientAuth REQUIRED and a SecretsTrustManager on it
                                                                    (checkRevocation unless the policy checks none)
  edge (the load balancer verifies and forwards the certificate, Services.cert_forwarding)
    every route's handler wrapped in a Chain (GUARD) whose ConditionEnforcementFilter refuses (403) a request carrying
    the forwarded header unless it comes from the edge's sources: empty request.headers['<header>'] or
    ipMatch(contexts.client.remoteAddress, '<CIDR>') ... (no sources recorded: refused from everyone)
What isn't established is an action: whether a PEM file of several CAs loads every one, how checkRevocation checks
revocation and fails, and how to decode the forwarded header (AWS's URL-encoded PEM keeps a literal `+`, which
urlDecode, a form decoder, turns into a space). What the gateway doesn't check (certificate policies, key usages) is a
note; an edge policy whose edge forwards no certificate is a blocker. The read-back of a render unwraps the guard and
leaves these files out (unguarded): they are the trust policies' render, not the gateway's own routes.
"""
import json

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import note
from opsdir.domains.pki.trust import (CLIENT_AUTH, accepting_services, bundle_certificates, enforced_at, policy_bundle,
                                      trust_policies)
from .listeners import HTTPS
from .naming import SERVER_ROLES
from .routes import ENFORCE

AREA = "Trust"
GUARD = "client-certificate-guard"           # the Chain a route's handler is wrapped in (unwrapped on read-back)
SECRETS_DIR = "secrets/client-ca"            # under the instance directory (&{ig.instance.dir})
TLS_DIR, PEM_DIR = "pinggateway/admin-tls", f"pinggateway/{SECRETS_DIR}"
# what a forwarded header holds, read in an expression (PingGateway 2026 Functions): (expression, what to confirm)
DECODING = {
    "url-pem": ("pemCertificate(urlDecodePathElement(request.headers['{h}'][0]))",
                "urlDecodePathElement decodes as RFC 3986 (a literal `+` stays); never urlDecode, a form decoder that "
                "turns the `+` the edge leaves in the base64 into a space. The reference doesn't state `+` handling: "
                "test with a certificate whose base64 holds a `+`"),
    "pem": ("pemCertificate(request.headers['{h}'][0])",
            "how the edge serializes the PEM's line breaks in a header isn't established: test with a real "
            "certificate")}


def gateway_policies(d):
    """The client-auth trust policies the gateway role accepts."""
    return tuple(p for p in trust_policies(d) if one(p, "ciamTrustPurpose") == CLIENT_AUTH
                 and set(values(p, "ciamAcceptedByRole")) & set(SERVER_ROLES))


def _ig_services(m, policy):
    return tuple(s for s in accepting_services(m, policy) if one(s, "ciamTargetRole") in SERVER_ROLES)


def secret_id(policy):
    return f"{rdn_value(policy)}.client-ca"


def tls_fragment(policy):
    """The admin.json objects checking client certificates under a product-enforced policy: its heap's secrets provider
    and the HTTPS connector's TLS options."""
    name = rdn_value(policy)
    provider = f"{name}-client-ca"
    return {"heap": [{"name": provider, "type": "SecretsProvider", "config": {"stores": [{
                "type": "FileSystemSecretStore", "config": {
                    "directory": f"&{{ig.instance.dir}}/{SECRETS_DIR}/{name}", "suffix": ".pem", "format": "PLAIN",
                    "mappings": [{"secretId": secret_id(policy), "format": {"type": "PemPropertyFormat"}}]}}]}}],
            "connectors": [{"port": HTTPS.port, "tls": {"type": "ServerTlsOptions", "config": {
                "clientAuth": "REQUIRED", "trustManager": {"type": "SecretsTrustManager", "config": {
                    "certificateVerificationSecretId": secret_id(policy), "secretsProvider": provider,
                    "checkRevocation": (one(policy, "ciamRevocationMode") or "none") != "none"}}}}}]}


def _product(d):
    return tuple(p for p in gateway_policies(d) if enforced_at(p) != "edge")


def client_tls_files(m):
    """{path: text}: each product-enforced policy's bundle and admin.json objects (those with a bundle)."""
    return {path: text for p in _product(m.d) if policy_bundle(m.d, p) is not None for path, text in (
        (f"{TLS_DIR}/{rdn_value(p)}.json", json.dumps(tls_fragment(p), indent=2) + "\n"),
        (f"{PEM_DIR}/{rdn_value(p)}/{secret_id(p)}.pem", policy_bundle(m.d, p)))}


def forwardings(m, services, policy):
    """((service name, CertForwarding or None), ...) of the gateway's service names under an edge policy."""
    return tuple((s, services.cert_forwarding(m, s)) for s in _ig_services(m, policy))


def _forwarded(m, services):
    """The CertForwardings reaching the gateway under its edge policies, distinct, in order."""
    return tuple(dict.fromkeys(f for p in gateway_policies(m.d) if enforced_at(p) == "edge"
                               for _, f in forwardings(m, services, p) if f is not None))


def guard_condition(forwarded):
    """The expression admitting a request only when each forwarded header it carries comes from that header's edge
    sources."""
    headers = tuple(dict.fromkeys(f.header for f in forwarded))
    tests = tuple(" or ".join((f"empty request.headers['{h}']",
                               *(f"ipMatch(contexts.client.remoteAddress, '{c}')"
                                 for c in dict.fromkeys(c for f in forwarded if f.header == h for c in f.sources))))
                  for h in headers)
    return "${" + (tests[0] if len(tests) == 1 else " and ".join(f"({t})" for t in tests)) + "}"


def guarded(route, forwarded):
    """A route (JSON object) with its handler wrapped in the GUARD chain; as it is with nothing forwarded or no
    handler."""
    if not forwarded or "handler" not in route:
        return route
    return {**route, "handler": {"name": GUARD, "type": "Chain", "config": {
        "filters": [{"type": ENFORCE, "config": {"condition": guard_condition(forwarded)}}],
        "handler": route["handler"]}}}


def guard_routes(m, services, routes):
    """{path: route} with every route guarded by environment m's edge-forwarded certificate headers (none without
    services)."""
    forwarded = _forwarded(m, services) if services is not None else ()
    return {path: guarded(r, forwarded) for path, r in routes.items()}


def _unwrapped(text):
    route = json.loads(text)
    handler = route.get("handler") if isinstance(route, dict) else None
    if not (isinstance(handler, dict) and handler.get("name") == GUARD):
        return text
    return json.dumps({**route, "handler": handler["config"]["handler"]}, indent=2) + "\n"


def unguarded(files):
    """The rendered gateway files (paths below pinggateway/) as the gateway's own: routes without the GUARD chain, the
    client-certificate files left out."""
    return {path: _unwrapped(text) if path.startswith("routes/") and path.endswith(".json") else text
            for path, text in files.items() if not path.startswith(("admin-tls/", f"{SECRETS_DIR}/"))}


# ------------------------------------------------------------------ notes
def _unchecked(m, policy, where, by):
    found = [*values(policy, "ciamAllowedPolicyOid"), *values(policy, "ciamRequiredEku")]
    return ((note(AREA, "note", where, f"{by} doesn't check certificate policies or key usages ({', '.join(found)})",
                  ("Check them where the certificate is issued, or in a filter reading it",), policy.dn, m.label),)
            if found else ())


def _product_notes(m, policy, where):
    if policy_bundle(m.d, policy) is None:
        return (note(AREA, "blocker", where, "not enforced at the gateway: it needs an anchor recording its "
                     "certificate (ciamCertificatePem)", ("Record what is missing",), policy.dn, m.label),)
    count = len(bundle_certificates(m.d, policy))
    mode = one(policy, "ciamRevocationMode") or "none"
    return (note(AREA, "action", f"{TLS_DIR}/{rdn_value(policy)}.json",
                 "admin.json is a captured file this render doesn't rewrite: the client certificate check is rendered "
                 "beside it", ("Merge its heap object into admin.json's heap and its tls config (clientAuth, "
                               f"trustManager) into the HTTPS connector on {HTTPS.port}, keeping that connector's "
                               "keyManager; deploy the PEM beside it (the product profile places it under "
                               f"{SECRETS_DIR}/)",), policy.dn, m.label),
            *((note(AREA, "action", where, f"its bundle holds {count} CA certificates in one PEM file; that a "
                    "FileSystemSecretStore's PemPropertyFormat loads every one of them isn't established",
                    ("Test that a certificate under each CA is accepted, or split the bundle",), policy.dn, m.label),)
              if count > 1 else ()),
            *((note(AREA, "action", where, f"the policy checks revocation ({mode}, on failure "
                    f"{one(policy, 'ciamRevocationFailure') or 'unset'}); the SecretsTrustManager's checkRevocation "
                    "is on, but how it checks (OCSP, CRLs) and what it does when it can't isn't established",
                    ("Test with a revoked certificate and an unreachable responder",), policy.dn, m.label),)
              if mode != "none" else ()),
            *_unchecked(m, policy, where, "PingGateway's trust manager"))


def _edge_notes(m, services, policy, where):
    found = forwardings(m, services, policy)
    forwarded = tuple(dict.fromkeys(f for _, f in found if f is not None))
    if not forwarded:
        names = ", ".join(one(s, "ciamFqdn") or rdn_value(s) for s, _ in found) or "no service name"
        return (note(AREA, "blocker", where, f"checked at the edge, but the edge in front of the gateway ({names}) "
                     "forwards no client certificate", ("Terminate TLS at a load balancer that verifies client "
                                                        "certificates, or check them at the product "
                                                        "(ciamTrustEnforcedAt product)",), policy.dn, m.label),)
    plain = [one(s, "ciamFqdn") or rdn_value(s) for s, f in found if f is None]
    return (*((note(AREA, "action", where, f"{', '.join(plain)} forward no client certificate: the routes see none "
                    "through them", ("Verify client certificates there too, or stop accepting the policy there",),
                    policy.dn, m.label),) if plain else ()),
            *(note(AREA, "action", where, f"the edge's requests carrying {f.header} come from no recorded addresses: "
                   "every route refuses the header from everyone", ("Record the edge's subnets",), policy.dn, m.label)
              for f in forwarded if not f.sources),
            *(note(AREA, "action", where, f"the edge forwards the certificate in {f.header}, {f.encoding} ({f.holds})"
                   + (f": read it as {DECODING[f.encoding][0].format(h=f.header)}; {DECODING[f.encoding][1]}"
                      if f.encoding in DECODING else
                      ": no PingGateway function is established to read that encoding (derCertificate takes RFC "
                      "9440's colon-wrapped base64)"),
                   ("Confirm before a filter relies on the certificate",), policy.dn, m.label) for f in forwarded),
            *_unchecked(m, policy, where, "Neither the edge nor PingGateway"))


def client_certificate_notes(m, services):
    """Render notes for each client-auth trust policy the gateway role accepts in environment m."""
    product = tuple(p for p in _product(m.d) if policy_bundle(m.d, p) is not None)
    return (*(n for p in gateway_policies(m.d) for n in (
                _edge_notes(m, services, p, f"trust policy {rdn_value(p)}") if enforced_at(p) == "edge" else
                _product_notes(m, p, f"trust policy {rdn_value(p)}"))),
            *((note(AREA, "action", "PingGateway HTTPS connector", "the gateway checks client certificates under "
                    f"{', '.join(rdn_value(p) for p in product)}, but its HTTPS connector has one trust manager",
                    ("Make them one trust policy, or give each its own connector",)),) if len(product) > 1 else ()))
