"""What an Azure edge runs of the client-certificate trust policies checked there (client_certificates.py renders them),
read back against the record (milestone 122, task 585). Pure.

Every source is normalized to Terraform state's names (cli_edge maps the Azure CLI's gateways and ARM templates to
them): an azurerm_application_gateway's trusted_client_certificate (name, data: the certificate file, base64),
ssl_profile (name, trusted_client_certificate_names, client_authentication_mode), http_listener (name, protocol,
ssl_profile_name), request_routing_rule (http_listener_name, rewrite_rule_set_name) and rewrite_rule_set (its rules'
request headers). A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting service names the
environment fronts with an Application Gateway is compared on each HTTPS listener of the gateway answering for the
service name (its tag Service, else the name the render gives it) with what its render makes there (a service name
whose TLS passes through a load balancer has no gateway: its render's blocker says so):
  - the listener names an SSL profile, the policy's (mtls-<policy>), which verifies (client_authentication_mode not
    Passthrough) against trusted client certificates;
  - those certificates, by SHA-256 fingerprint, are the policy bundle's (trust.policy_bundle; a file holds PEM, or one
    DER certificate);
  - the routing rule of the listener passes the verified certificate on (a rewrite setting CLIENT_CERT_HEADER to
    {var_client_certificate}): the products behind it read the certificate there.
Each difference is an import notice for the policy's owners, naming what to do: render and apply the edge again, or
find what changed it. A gateway the source doesn't hold is left to the import's own notices. A render read back
matches, and nothing is said.
"""
import base64
import hashlib
import re

from opsdir.core.directory import fingerprint, get, one, rdn_value
from opsdir.core.environment import env_dn, env_model, of_class
from opsdir.core.inventory import of_types
from opsdir.core.sources import under
from opsdir.domains.pki.pem import pem_fingerprint
from opsdir.domains.pki.trust import bundle_certificates, edge_policies, edge_policy_for, policy_bundle
from .client_certificates import CLIENT_CERT_HEADER, profile_name

FORWARDED = "{var_client_certificate}"          # the rewrite's value: the certificate the gateway verified
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def _low(x):
    return (x or "").lower()


def _named(blocks, name):
    return next((b for b in blocks or () if _low(b.get("name")) == _low(name)), None)


# ------------------------------------------------------------------ fingerprints
def bundle_fingerprints(text):
    """The SHA-256 fingerprints of the PEM certificates in a bundle, in order; None when it holds none it can read."""
    try:
        found = tuple(dict.fromkeys(pem_fingerprint(b) for b in _PEM.findall(text or "")))
    except ValueError:                   # a block that isn't base64 (binascii.Error)
        return None
    return found or None


def file_fingerprints(data):
    """The SHA-256 fingerprints of a trusted client certificate file (its data: base64 of PEM, or of one DER
    certificate); () when it isn't base64."""
    try:
        raw = base64.b64decode(data or "", validate=True)
    except ValueError:
        return ()
    text = raw.decode("ascii", "replace")
    return bundle_fingerprints(text) or () if "-----BEGIN CERTIFICATE-----" in text else \
        ((fingerprint(hashlib.sha256(raw).hexdigest()),) if raw else ())


def _subjects(m, p):
    """{fingerprint of a recorded PEM: its certificate's subject (else name)} of a policy's bundle."""
    return {f: one(c, "ciamSubject") or rdn_value(c) for c in bundle_certificates(m.d, p)
            if one(c, "ciamCertificatePem") for f in (bundle_fingerprints(one(c, "ciamCertificatePem")) or ())[:1]}


def _listed(fps, names=None):
    """Fingerprints as a notice lists them, each after its certificate's subject when names gives one."""
    return "; ".join(f"{names[f]} (SHA-256 {f})" if names and names.get(f) else f"SHA-256 {f}" for f in fps)


# ------------------------------------------------------------------ the check
def _gateway(pairs, m, svc):
    """The Application Gateway answering for a service name: tag Service its name, else the render's name for it."""
    fqdn = _low(one(svc, "ciamFqdn")).rstrip(".")
    return next((g for g in of_types(pairs, "azurerm_application_gateway")
                 if (fqdn and _low((g.get("tags") or {}).get("Service")).rstrip(".") == fqdn)
                 or _low(g.get("name")) == f"agw-ciam-{rdn_value(m.env)}-{rdn_value(svc)}".lower()), None)


def _certificate_notices(m, p, gw, profile, fix):
    """What differs between the certificates an SSL profile trusts and policy p's bundle."""
    files = [_named(gw.get("trusted_client_certificate"), n) for n in profile.get("trusted_client_certificate_names")
             or ()]
    about = f"{m.label}: {gw.get('name')} SSL profile {profile.get('name')} (trust policy {rdn_value(p)})"
    if not files or any(f is None or not f.get("data") for f in files):
        return (f"{about}: its trusted client certificates aren't all in this source; compare them with the policy's "
                "bundle by hand",) if files else ()
    want = bundle_fingerprints(policy_bundle(m.d, p)) or ()
    held = tuple(dict.fromkeys(x for f in files for x in file_fingerprints(f.get("data"))))
    extra, missing = [f for f in held if f not in want], [f for f in want if f not in held]
    differs = (*((f"trusts {len(extra)} CA certificate(s) the policy doesn't: {_listed(extra)}",) if extra else ()),
               *((f"lacks {len(missing)} the policy trusts: {_listed(missing, _subjects(m, p))}",) if missing else ()))
    return (f"{about} {'; '.join(differs)}{fix}",) if differs else ()


def _forwarded(gw, listener):
    """Whether the routing rules of a listener pass the verified certificate on in CLIENT_CERT_HEADER."""
    sets = [_named(gw.get("rewrite_rule_set"), r.get("rewrite_rule_set_name"))
            for r in gw.get("request_routing_rule") or () if _low(r.get("http_listener_name")) == _low(listener)]
    return bool(sets) and all(s is not None and any(
        _low(h.get("header_name")) == CLIENT_CERT_HEADER.lower() and h.get("header_value") == FORWARDED
        for rule in s.get("rewrite_rule") or () for h in rule.get("request_header_configuration") or ())
        for s in sets)


def _listener_notices(m, p, svc, gw):
    fix = ": render and apply the edge again, or find what changed it"

    def of(ls):
        where = f"{m.label}: {gw.get('name')} listener {ls.get('name')} ({one(svc, 'ciamFqdn')}, trust policy " \
                f"{rdn_value(p)})"
        name, expected = ls.get("ssl_profile_name"), profile_name(p)
        profile = _named(gw.get("ssl_profile"), name) if name else None
        mode = profile.get("client_authentication_mode") if profile is not None else None
        if not name or (profile is not None and not profile.get("trusted_client_certificate_names")):
            return (f"{where} checks no client certificate where the record has them verified at the edge{fix}",)
        if profile is None:
            return (f"{where} names SSL profile {name}, which this source doesn't hold: its certificates aren't "
                    "compared",)
        if _low(name) != _low(expected):
            return (f"{where} verifies with SSL profile {name}, not trust policy {rdn_value(p)}'s ({expected}){fix}",)
        return (*((f"{where} passes client certificates on unchecked (client authentication {mode}) where the record "
                   f"has them verified at the edge{fix}",) if _low(mode) == "passthrough" else ()),
                *((f"{where} doesn't pass the verified certificate on in {CLIENT_CERT_HEADER}: the products behind "
                   f"it can't read it{fix}",) if not _forwarded(gw, ls.get("name")) else ()),
                *_certificate_notices(m, p, gw, profile, fix))
    return tuple(n for ls in gw.get("http_listener") or () if _low(ls.get("protocol")) == "https" for n in of(ls))


def mtls_notices(m, pairs):
    """Import notices of environment m's edge trust policies against (Terraform resource type, attributes) pairs read
    from it: each HTTPS listener of an Application Gateway in front of a service under one that doesn't verify, verifies
    with another SSL profile, doesn't pass the certificate on, or trusts certificates other than the policy's bundle;
    () when they match."""
    checked = ((p, svc) for svc in of_class(m, "ciamServiceName") for p in (edge_policy_for(m, svc),)
               if p is not None and policy_bundle(m.d, p) is not None)
    return tuple(dict.fromkeys(n for p, svc in checked for gw in (_gateway(pairs, m, svc),) if gw is not None
                               for n in _listener_notices(m, p, svc, gw)))


def with_mtls_notices(imported, files, d, suffixes, read_pairs):
    """An import (core Imported) with mtls_notices of each Azure environment under <cloud>/<env>/ in files whose record
    has an edge trust policy; read_pairs({path within the folder: text}) -> the folder's pairs (files ending in one of
    suffixes)."""
    specs = sorted({"/".join(p.split("/")[:2]) for p in files if p.count("/") >= 2})
    models = tuple(env_model(d, env_dn(s)) for s in specs if get(d, env_dn(s)) is not None)
    wanted = tuple(m for m in models if one(m.cloud, "ciamCloudProvider") == "azure" and edge_policies(m))
    found = tuple(n for m in wanted for n in mtls_notices(m, read_pairs(
        {p: t for p, t in under(files, m.label).items() if p.endswith(suffixes)})))
    return imported._replace(notices=(*imported.notices, *found)) if found else imported
