"""Client certificates checked at an Application Load Balancer (core pki trust policies enforced at the edge, milestone
122, decision 3302; research docs/research m120 section 5). Pure.

A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting roles a service name of this
environment fronts with an ALB gets, once per environment:
  aws_s3_object         the policy's bundle (core trust.policy_bundle: its approved anchors and the followed bundles'
                        subordinate CAs chaining to them; public certificates) at <prefix>trust/<policy>.pem in the
                        bucket its ciamTrustStoreRole binds (an object store, ciamStorageRef s3://bucket[/prefix])
  aws_lb_trust_store    reading that object
and each HTTPS listener of those ALBs mutual_authentication mode verify with the trust store: the ALB validates the
client certificate and passes it to the targets in X-Amzn-Mtls-Clientcert-Leaf (the products trust that header only
from the ALB: their render's). What ALB mTLS can't do is a note: revocation only against CRLs uploaded into the trust
store (no OCSP), 25 CA certificates per trust store by default (a quota), and the policy's certificate policies, key
usages and identity mapping (the product checks them on the forwarded certificate). A policy without a bundle or a trust
store location is a blocker.

How the ALB passes the certificate on (cert_forwarding, the Adapter hook the product adapters read through their
Services) is derived here, never recorded: the header is the ALB's own, and its sources are the ALB's subnets.
"""
from opsdir.core.contract import CertForwarding
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.domains.compute.workloads import cluster_subnets
from opsdir.domains.edge.gateways import front_choice
from opsdir.domains.edge.resolve import service_edge
from opsdir.core.notes import note, note_comment
from opsdir.domains.pki.trust import bundle_certificates, edge_policies, edge_policy_for, policy_bundle
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name

AREA = "Trust"
CA_QUOTA = 25            # CA certificates per ALB trust store (Elastic Load Balancing quotas, adjustable)
LEAF_HEADER = "X-Amzn-Mtls-Clientcert-Leaf"     # verify mode: the client's certificate, URL-encoded PEM


def _store(m, p):
    """(bucket, prefix) the policy's ciamTrustStoreRole binds in m, or None."""
    b = one_role(m, one(p, "ciamTrustStoreRole") or "")
    location = one(b, "ciamStorageRef") if b is not None else None
    if not (location or "").startswith("s3://") or len(location) <= 5:
        return None
    bucket, _, prefix = location[5:].partition("/")
    return bucket, (prefix.rstrip("/") + "/" if prefix else "")


def lacking(m, p):
    return tuple(why for why, missing in (
        ("a bundle (approved anchors with their PEMs)", policy_bundle(m.d, p) is None),
        ("where the ALB reads it (ciamTrustStoreRole naming an object store with an s3:// ciamStorageRef)",
         _store(m, p) is None)) if missing)


def _blocked(m, p):
    return note(AREA, "blocker", f"trust policy {rdn_value(p)}",
                f"not enforced at {m.label}'s load balancers: it needs {'; '.join(lacking(m, p))}",
                ("Record what is missing, or check the certificates at the product (ciamTrustEnforcedAt product)",),
                p.dn, m.label)


def mutual_authentication(m, svc):
    """The listener's mutual_authentication block for a service name under an edge policy, or ()."""
    p = edge_policy_for(m, svc)
    if p is None or lacking(m, p):
        return ()
    return (("mutual_authentication", Block((("mode", "verify"),
                                             ("trust_store_arn", ref(f"aws_lb_trust_store.{tf_name(rdn_value(p))}.arn"))
                                             ))),)


def _alb_subnets(m, svc):
    """The subnets (bindings) the ALB of a service name sits in (as the render places it), or None when this render
    fronts it with no ALB (a network load balancer passes TLS through: nothing checks the certificate there)."""
    kind, *chosen = front_choice(m, svc)
    if kind == "gateway":
        return cluster_subnets(m, one(svc, "ciamTargetRole"))
    spec = service_edge(m, svc, ()) if kind == "servers" else None
    if spec is None or not spec.layer7:
        return None
    return tuple({rdn_value(s): s for s in chosen[1] if s is not None}.values())


def cert_forwarding(m, svc):
    """Adapter cert_forwarding: the CertForwarding of the ALB verifying a service name's client certificates under its
    edge trust policy (the leaf, URL-encoded PEM, from the ALB's subnets' CIDRs), or None when none does."""
    p = edge_policy_for(m, svc)
    subnets = _alb_subnets(m, svc) if p is not None and not lacking(m, p) else None
    if subnets is None:
        return None
    return CertForwarding(LEAF_HEADER, "url-pem", "leaf", tuple(c for s in subnets for c in values(s, "ciamCidr")))


def _trust_store(m, p):
    n, (bucket, prefix) = tf_name(rdn_value(p)), _store(m, p)
    key = f"{prefix}trust/{rdn_value(p)}.pem"
    return (tf_block("resource", ["aws_s3_object", f"{n}_trust_bundle"], [
                ("bucket", bucket), ("key", key), ("content", policy_bundle(m.d, p)),
                ("content_type", "application/x-pem-file")]),
            tf_block("resource", ["aws_lb_trust_store", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(p)}"[:32]),
                ("ca_certificates_bundle_s3_bucket", bucket),
                ("ca_certificates_bundle_s3_key", ref(f"aws_s3_object.{n}_trust_bundle.key")),
                ("tags", {"TrustPolicy": rdn_value(p), "ManagedBy": "opsdir"})]))


def render_trust_stores(m):
    """HCL (and comments) for environment m's ALB trust stores, one per edge trust policy, stamped with the policy."""
    return tuple(x for p in edge_policies(m) for x in from_entry(p.dn, (
        (comment(note_comment(_blocked(m, p))),) if lacking(m, p) else _trust_store(m, p))))


def mtls_notes(m):
    """Per edge trust policy: a blocker when it can't be rendered; else what ALB mTLS leaves to people or products."""
    def of(p):
        if lacking(m, p):
            return (_blocked(m, p),)
        count = len(bundle_certificates(m.d, p))
        return (
            note(AREA, "action", f"trust policy {rdn_value(p)}",
                 "the ALBs check revocation only against CRLs uploaded into the trust store (no OCSP): "
                 f"{one(p, 'ciamRevocationMode') or 'no revocation'} is the policy's",
                 ("Upload the issuing CAs' CRLs (aws_lb_trust_store_revocation) and keep them current, or check "
                  "revocation at the product",), p.dn, m.label),
            note(AREA, "note", f"trust policy {rdn_value(p)}",
                 "the ALBs check the chain only: the policy's certificate policies, key usages and identity mapping "
                 f"are checked by the product on the certificate the ALB forwards ({LEAF_HEADER})",
                 (), p.dn, m.label),
            *((note(AREA, "action", f"trust policy {rdn_value(p)}",
                    f"its bundle holds {count} CA certificates; an ALB trust store takes {CA_QUOTA} by default",
                    ("Request a higher 'CA certificates per trust store' quota for the account and region",),
                    p.dn, m.label),) if count > CA_QUOTA else ()))
    return tuple(n for p in edge_policies(m) for n in of(p))
