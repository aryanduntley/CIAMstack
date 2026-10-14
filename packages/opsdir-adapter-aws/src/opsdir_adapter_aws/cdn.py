"""AWS CDN: a CloudFront distribution in front of a service whose protection policy turns the CDN on. Its origin is the
service's load balancer (the ALB when TLS terminates at the edge, else the NLB, TLS then ending at CloudFront), reached
over HTTPS with the viewer's Host header (so the origin's certificate for the service name matches); nothing is cached
(sign-in pages and tokens: AWS's CachingDisabled and AllViewer policies). The protection policy's web ACL is
CloudFront-scoped and named by the distribution, Shield protects the distribution, and the service's DNS alias points
at it. The viewer certificate must be in ACM in us-east-1.

CloudFront isn't offered in AWS GovCloud (US): there, every CloudFront piece (the distribution, its managed policies,
the CloudFront-scoped web ACL, Shield) is created in the associated standard account (account.standard_account)
through the us-east-1 provider configured for it, with a comment that CloudFront is outside the GovCloud (ITAR)
boundary and its FedRAMP/DoD scope; its viewer certificate must be in that account's ACM in us-east-1; the service name
gets a CNAME (a GovCloud zone can't alias CloudFront). Without a recorded standard account, a comment says what is
missing and neither the distribution nor the name's record is rendered. Pure.
"""
from opsdir.core.directory import one, values
from opsdir.core.notes import note, note_comment
from opsdir.domains.edge.resolve import inspected
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block
from .account import govcloud, standard_account
from .dns import service_record
from .edge import US_EAST_1, shield, web_acl

ALL_METHODS = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
MINIMUM_PROTOCOL = {"1.2": "TLSv1.2_2021", "1.3": "TLSv1.2_2021"}       # CloudFront's minimum viewer protocols
GOVCLOUD_NOTE = ("not offered in AWS GovCloud (US): this distribution, its web ACL and Shield protection are in the "
                 "associated standard account (standard AWS credentials). CloudFront is outside the "
                 "GovCloud (US) boundary: no ITAR-controlled data in it (its configuration, logs or cache); AWS's "
                 "services-in-scope pages (2026-10) list CloudFront for FedRAMP Moderate (US East/West) and DoD IL2 "
                 "only: confirm it suits the mission")


def govcloud_note(m):
    """The render note of environment m's CloudFront distributions in GovCloud: outside its boundary, in the
    associated standard account (an action: keep ITAR-controlled data out, confirm it suits the mission); each
    distribution writes its comment."""
    return note("Edge", "action", "CloudFront", GOVCLOUD_NOTE,
                ("Keep ITAR-controlled data out of the distributions (their configuration, logs and cache)",
                 "Confirm with the authorizing official that CloudFront's authorizations (FedRAMP Moderate, DoD IL2) "
                 "suit the mission, or front the service names without a CDN"), None, m.label)


def _viewer_certificate(m, spec):
    ref_uri = spec.certificate or ""
    arn = ref_uri.split("://", 1)[1] if ref_uri.startswith("aws-acm://") else None
    exact = () if spec.tls_min == "1.2" else (("#", f"nearest to TLS {spec.tls_min}: CloudFront's minimum"),)
    parts = (arn or "").split(":")
    if arn is None:
        problem = "no ACM certificate holds this service's certificate in this environment"
    elif parts[3] != "us-east-1":
        problem = f"CloudFront needs the certificate in ACM in us-east-1 (this one is in {parts[3]})"
    elif govcloud(m) and (parts[1] != "aws" or parts[4] != standard_account(m)):
        problem = (f"CloudFront needs the certificate in the standard account's ACM ({standard_account(m)}, "
                   f"us-east-1); this one is in {parts[1]} account {parts[4]}")
    else:
        problem = None
    return ("viewer_certificate", Block((
        *((("acm_certificate_arn", arn),) if problem is None else (("#", f"UNBOUND: {problem}"),)),
        ("ssl_support_method", "sni-only"), ("minimum_protocol_version", MINIMUM_PROTOCOL[spec.tls_min]), *exact)))


def _provider(m):
    """The provider argument of CloudFront's pieces: the standard account's us-east-1 provider in GovCloud, else the
    root's default (CloudFront is global)."""
    return (("provider", ref(f"aws.{US_EAST_1}")),) if govcloud(m) else ()


def distribution(m, svc, spec, n):
    """The CloudFront distribution, its managed policies, the CloudFront-scoped web ACL and Shield protection; the
    origin is aws_lb.<n>."""
    port = int(values(svc, "ciamPort")[0])
    waf, provider = inspected(spec), _provider(m)
    return (*((comment(note_comment(govcloud_note(m))),) if govcloud(m) else ()),
            tf_block("data", ["aws_cloudfront_cache_policy", f"{n}_caching_disabled"],
                     [*provider, ("name", "Managed-CachingDisabled")]),
            tf_block("data", ["aws_cloudfront_origin_request_policy", f"{n}_all_viewer"],
                     [*provider, ("name", "Managed-AllViewer")]),
            *(web_acl(m, n, spec, None, cdn=True) if waf else ()),
            tf_block("resource", ["aws_cloudfront_distribution", n], [
                *provider, ("enabled", True), ("comment", f"CIAM {one(svc, 'ciamFqdn')} ({m.label})"),
                ("aliases", [one(svc, "ciamFqdn")]), ("http_version", "http2and3"),
                *((("web_acl_id", ref(f"aws_wafv2_web_acl.{n}.arn")),) if waf else ()),
                ("origin", Block((("domain_name", ref(f"aws_lb.{n}.dns_name")), ("origin_id", "load-balancer"),
                                  ("custom_origin_config", Block((
                                      ("http_port", 80), ("https_port", port), ("origin_protocol_policy", "https-only"),
                                      ("origin_ssl_protocols", ["TLSv1.2"]))))))),
                ("default_cache_behavior", Block((
                    ("target_origin_id", "load-balancer"), ("viewer_protocol_policy", "redirect-to-https"),
                    ("allowed_methods", ALL_METHODS), ("cached_methods", ["GET", "HEAD"]), ("compress", True),
                    ("cache_policy_id", ref(f"data.aws_cloudfront_cache_policy.{n}_caching_disabled.id")),
                    ("origin_request_policy_id",
                     ref(f"data.aws_cloudfront_origin_request_policy.{n}_all_viewer.id"))))),
                ("restrictions", Block((("geo_restriction", Block((("restriction_type", "none"),))),))),
                _viewer_certificate(m, spec),
                ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
            *shield(n, spec, f"aws_cloudfront_distribution.{n}.arn", f"aws_cloudfront_distribution.{n}", provider,
                    "the standard account's" if govcloud(m) else "the account's"))


def alias(n):
    """The DNS alias target of a service a CloudFront distribution fronts."""
    return (ref(f"aws_cloudfront_distribution.{n}.domain_name"),
            ref(f"aws_cloudfront_distribution.{n}.hosted_zone_id"))


def fronted(m, svc, spec, n):
    """A service a CDN fronts: its CloudFront distribution (and web ACL, Shield) and its name's record pointing at it:
    an alias, or in GovCloud a CNAME from the standard account's distribution; in GovCloud without a recorded standard
    account, a comment instead of both."""
    if govcloud(m) and not standard_account(m):
        return (comment(f"UNBOUND: `{one(svc, 'ciamFqdn')}`: CloudFront isn't offered in AWS GovCloud (US) and runs "
                        "from the associated standard account, which the cloud doesn't record (ciamBillingAccountRef): "
                        "neither the distribution nor the name's record is rendered"),)
    record = service_record(m.d, m, svc, n, cname=ref(f"aws_cloudfront_distribution.{n}.domain_name")) \
        if govcloud(m) else service_record(m.d, m, svc, n, alias(n))
    return (*distribution(m, svc, spec, n), *record)
