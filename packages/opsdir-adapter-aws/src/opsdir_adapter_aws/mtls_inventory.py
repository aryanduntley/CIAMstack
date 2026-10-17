"""What an AWS edge runs of the client-certificate trust policies checked there (mtls.py renders them), read back
against the record (milestone 122, task 585). Pure.

Every source is normalized to Terraform state's names (the CLI and CloudFormation readers map to them here):
  aws_lb_listener.mutual_authentication   mode (off, passthrough, verify) and trust_store_arn: the CLI's
                                          MutualAuthentication, a template's Listener MutualAuthentication
  aws_lb_trust_store                      name, tags, where its bundle was loaded from (ca_certificates_bundle_s3_bucket
                                          and _key): a template's AWS::ElasticLoadBalancingV2::TrustStore; from the CLI
                                          (elbv2 describe-trust-stores: TrustStores) its name and number of CA
                                          certificates (ca_certificate_count) only
  aws_s3_object                           the bundle object's content (PEM): Terraform state only
A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting service names the environment fronts
with an ALB (mtls.cert_forwarding) is compared on each HTTPS listener of the load balancer answering for the service
name (its tag Service, or a Route 53 alias naming it) with what its render makes there:
  - the listener's mode is verify (off: nothing checks a certificate; passthrough: the ALB forwards any certificate
    unchecked, while the products trust the forwarded certificate as checked);
  - its trust store is the policy's (tag TrustPolicy, else the name the render gives it);
  - the trust store's CA certificates, by SHA-256 fingerprint, are the policy bundle's (trust.policy_bundle): read from
    the bundle object at the location the trust store was loaded from, when the source holds its content; else only
    their number is compared, and the fingerprints are left to a person (get-trust-store-ca-certificates-bundle answers
    with a download link only, which nothing here fetches).
Each difference is an import notice for the policy's owners, naming what to do: render and apply the edge again, or
find what changed it. A load balancer the source doesn't hold, and a service name another adapter fronts, are left to
the import's own notices. A render read back matches, and nothing is said.
"""
import base64
import re

from opsdir.core.directory import get, one, rdn_value
from opsdir.core.environment import env_dn, env_model, of_class
from opsdir.core.inventory import of_types
from opsdir.core.sources import under
from opsdir.domains.pki.pem import pem_fingerprint
from opsdir.domains.pki.trust import bundle_certificates, edge_policies, edge_policy_for, policy_bundle
from .cli_outputs import items
from .edge_inventory import aliased_names
from .mtls import POLICY_TAG, cert_forwarding, lacking, trust_store_name
from .tags import state_tags

TRUST_STORE = "AWS::ElasticLoadBalancingV2::TrustStore"
TRUST_TYPES = (TRUST_STORE,)                   # what the CloudFormation reader reads here
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def _first(v):
    return (v[0] if v else {}) if isinstance(v, list) else (v or {})


# ------------------------------------------------------------------ the sources, in Terraform state's names
def mutual_authentication(given):
    """A listener's MutualAuthentication (CLI output, or a template's resolved property) as Terraform state's block."""
    return [{"mode": given.get("Mode"), "trust_store_arn": given.get("TrustStoreArn")}] \
        if isinstance(given, dict) and given else []


def cli_trust_pairs(outs):
    """(aws_lb_trust_store, attributes) pairs of the CLI's describe-trust-stores outputs (recognized outputs)."""
    return [("aws_lb_trust_store", {"arn": t.get("TrustStoreArn"), "name": t.get("Name"),
                                    "ca_certificate_count": t.get("NumberOfCaCertificates")})
            for t in items(outs, "TrustStores") if isinstance(t, dict) and t.get("TrustStoreArn")]


def stack_trust_pairs(declared, tags):
    """(aws_lb_trust_store, attributes) pairs of a stack's declared trust stores; tags: a Tags list as a dict."""
    return [("aws_lb_trust_store", {"arn": pid, "name": p.get("Name"), "tags": tags(p.get("Tags")),
                                    "ca_certificates_bundle_s3_bucket": p.get("CaCertificatesBundleS3Bucket"),
                                    "ca_certificates_bundle_s3_key": p.get("CaCertificatesBundleS3Key")})
            for _, t, p, _, pid in declared if t == TRUST_STORE]


# ------------------------------------------------------------------ fingerprints
def bundle_fingerprints(text):
    """The SHA-256 fingerprints of the PEM certificates in a bundle, in order; None when it holds none it can read."""
    try:
        found = tuple(dict.fromkeys(pem_fingerprint(b) for b in _PEM.findall(text or "")))
    except ValueError:                   # a block that isn't base64 (binascii.Error)
        return None
    return found or None


def _pem_subjects(m, p):
    """{fingerprint of a recorded PEM: its certificate's subject (else name)} of a policy's bundle."""
    return {f: one(c, "ciamSubject") or rdn_value(c) for c in bundle_certificates(m.d, p)
            if one(c, "ciamCertificatePem") for f in (bundle_fingerprints(one(c, "ciamCertificatePem")) or ())[:1]}


def _listed(fps, names=None):
    """Fingerprints as a notice lists them, each after its certificate's subject when names gives one."""
    return "; ".join(f"{names[f]} (SHA-256 {f})" if names and names.get(f) else f"SHA-256 {f}" for f in fps)


# ------------------------------------------------------------------ the check
def _load_balancer(pairs, svc):
    """The load balancer answering for a service name: tag Service its name, or a Route 53 alias named it."""
    fqdn = (one(svc, "ciamFqdn") or "").lower().rstrip(".")
    aliased = {(al.get("name") or "").lower().rstrip(".") for r in of_types(pairs, "aws_route53_record")
               if (r.get("fqdn") or r.get("name") or "").lower().rstrip(".") == fqdn for al in r.get("alias") or ()}
    return next((lb for lb in of_types(pairs, "aws_lb", "aws_alb") if fqdn and (
        (state_tags(lb).get("Service") or "").lower() == fqdn
        or {n.lower().rstrip(".") for n in aliased_names(pairs, lb) if n} & aliased)), None)


def _store_notices(m, p, store, pairs, where):
    """What differs between a trust store a listener verifies with and policy p's."""
    expected, name = trust_store_name(m, p), store.get("name") or store.get("arn")
    owner = state_tags(store).get(POLICY_TAG)
    if (owner.lower() != rdn_value(p).lower()) if owner else name != expected:
        return (f"{where} verifies with trust store {name}"
                + (f" (of trust policy {owner})" if owner else "") + f", not trust policy {rdn_value(p)}'s "
                f"({expected}): render and apply the edge again, or find what changed it",)
    want = bundle_fingerprints(policy_bundle(m.d, p)) or ()
    content = _bundle_text(next((o for o in of_types(pairs, "aws_s3_object")
                                 if o.get("bucket") == store.get("ca_certificates_bundle_s3_bucket")
                                 and o.get("key") == store.get("ca_certificates_bundle_s3_key")), None))
    about, fix = f"{m.label}: trust store {name} (trust policy {rdn_value(p)})", \
        ": render and apply the edge again, or find what changed it"
    if content is not None:
        held = bundle_fingerprints(content) or ()
        extra, missing = [f for f in held if f not in want], [f for f in want if f not in held]
        differs = (*((f"holds {len(extra)} CA certificate(s) the policy doesn't trust: {_listed(extra)}",)
                     if extra else ()),
                   *((f"lacks {len(missing)} it trusts: {_listed(missing, _pem_subjects(m, p))}",)
                     if missing else ()))
        return (f"{about} {'; '.join(differs)}{fix}",) if differs else ()
    count = store.get("ca_certificate_count")
    return (*((f"{about} holds {count} CA certificate(s), the policy's bundle holds {len(want)}{fix}",)
              if count is not None and str(count) != str(len(want)) else ()),
            f"{about}: its CA certificates' fingerprints aren't in this source; compare them with the policy's "
            "bundle by hand (aws elbv2 get-trust-store-ca-certificates-bundle gives a link to download its bundle)")


def _bundle_text(obj):
    """The text of a bundle object as the source holds it (content, or content_base64 decoded), else None."""
    if obj is None or obj.get("content") is not None:
        return (obj or {}).get("content")
    try:
        return base64.b64decode(obj.get("content_base64") or "", validate=True).decode("utf-8", "replace") \
            if obj.get("content_base64") else None
    except ValueError:                   # not base64 (binascii.Error)
        return None


def _listener_notices(m, p, svc, lb, pairs):
    stores = {s.get("arn"): s for s in of_types(pairs, "aws_lb_trust_store") if s.get("arn")}

    def of(ls):
        where = f"{m.label}: {lb.get('name') or lb.get('arn')} listener {ls.get('port')} ({one(svc, 'ciamFqdn')}, " \
                f"trust policy {rdn_value(p)})"
        auth = _first(ls.get("mutual_authentication"))
        mode = (auth.get("mode") or "off").lower()
        does = "checks no client certificate" if mode == "off" else "passes client certificates on unchecked"
        if mode != "verify":
            return (f"{where} {does} (mutual TLS {mode}) where the record has them verified at the edge: render and "
                    "apply the edge again, or find what changed it",)
        store = stores.get(auth.get("trust_store_arn"))
        if store is None:
            return (f"{where} verifies with trust store {auth.get('trust_store_arn')}, which this source doesn't hold: "
                    "its CA certificates aren't compared",)
        return _store_notices(m, p, store, pairs, where)
    return tuple(n for ls in of_types(pairs, "aws_lb_listener") if ls.get("load_balancer_arn") == lb.get("arn")
                 and (ls.get("protocol") or "").upper() == "HTTPS" for n in of(ls))


def mtls_notices(m, pairs):
    """Import notices of environment m's edge trust policies against (Terraform resource type, attributes) pairs read
    from it: each listener of an ALB in front of a service under one that doesn't verify, verifies with another trust
    store, or whose trust store's CA certificates differ from the policy's bundle; () when they match."""
    checked = ((p, svc) for svc in of_class(m, "ciamServiceName") for p in (edge_policy_for(m, svc),)
               if p is not None and not lacking(m, p) and cert_forwarding(m, svc) is not None)
    return tuple(dict.fromkeys(n for p, svc in checked for lb in (_load_balancer(pairs, svc),) if lb is not None
                               for n in _listener_notices(m, p, svc, lb, pairs)))


def with_mtls_notices(imported, files, d, suffixes, read_pairs):
    """An import (core Imported) with mtls_notices of each AWS environment under <cloud>/<env>/ in files whose record
    has an edge trust policy; read_pairs({path within the folder: text}) -> the folder's pairs (files ending in one of
    suffixes)."""
    specs = sorted({"/".join(p.split("/")[:2]) for p in files if p.count("/") >= 2})
    models = tuple(env_model(d, env_dn(s)) for s in specs if get(d, env_dn(s)) is not None)
    wanted = tuple(m for m in models if one(m.cloud, "ciamCloudProvider") == "aws" and edge_policies(m))
    found = tuple(n for m in wanted for n in mtls_notices(m, read_pairs(
        {p: t for p, t in under(files, m.label).items() if p.endswith(suffixes)})))
    return imported._replace(notices=(*imported.notices, *found)) if found else imported
