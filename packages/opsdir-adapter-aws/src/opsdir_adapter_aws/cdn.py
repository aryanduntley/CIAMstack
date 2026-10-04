"""AWS CDN: a CloudFront distribution in front of a service whose protection policy turns the CDN on. Its origin is the
service's load balancer (the ALB when TLS terminates at the edge, else the NLB, TLS then ending at CloudFront), reached
over HTTPS with the viewer's Host header (so the origin's certificate for the service name matches); nothing is cached
(sign-in pages and tokens: AWS's CachingDisabled and AllViewer policies). The protection policy's web ACL is
CloudFront-scoped and named by the distribution, Shield protects the distribution, and the service's DNS alias points
at it. The viewer certificate must be in ACM in us-east-1. Pure.
"""
from opsdir.core.directory import one, values
from opsdir.domains.edge.resolve import inspected
from opsdir_format_terraform.hcl import Block, block, ref
from .edge import shield, web_acl

ALL_METHODS = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
MINIMUM_PROTOCOL = {"1.2": "TLSv1.2_2021", "1.3": "TLSv1.2_2021"}       # CloudFront's minimum viewer protocols


def _viewer_certificate(spec):
    ref_uri = spec.certificate or ""
    arn = ref_uri.split("://", 1)[1] if ref_uri.startswith("aws-acm://") else None
    exact = () if spec.tls_min == "1.2" else (("#", f"nearest to TLS {spec.tls_min}: CloudFront's minimum"),)
    if arn is None:
        problem = "no ACM certificate holds this service's certificate in this environment"
    elif arn.split(":")[3] != "us-east-1":
        problem = f"CloudFront needs the certificate in ACM in us-east-1 (this one is in {arn.split(':')[3]})"
    else:
        problem = None
    return ("viewer_certificate", Block((
        *((("acm_certificate_arn", arn),) if problem is None else (("#", f"UNBOUND: {problem}"),)),
        ("ssl_support_method", "sni-only"), ("minimum_protocol_version", MINIMUM_PROTOCOL[spec.tls_min]), *exact)))


def distribution(m, svc, spec, n):
    """The CloudFront distribution, its managed policies, the CloudFront-scoped web ACL and Shield protection; the
    origin is aws_lb.<n>."""
    port = int(values(svc, "ciamPort")[0])
    waf = inspected(spec)
    return (block("data", ["aws_cloudfront_cache_policy", f"{n}_caching_disabled"],
                  [("name", "Managed-CachingDisabled")]),
            block("data", ["aws_cloudfront_origin_request_policy", f"{n}_all_viewer"],
                  [("name", "Managed-AllViewer")]),
            *(web_acl(m, n, spec, None, cdn=True) if waf else ()),
            block("resource", ["aws_cloudfront_distribution", n], [
                ("enabled", True), ("comment", f"CIAM {one(svc, 'ciamFqdn')} ({m.label})"),
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
                _viewer_certificate(spec),
                ("tags", {"Service": one(svc, "ciamFqdn"), "ManagedBy": "opsdir"})]),
            *shield(n, spec, f"aws_cloudfront_distribution.{n}.arn", f"aws_cloudfront_distribution.{n}"))


def alias(n):
    """The DNS alias target of a service a CloudFront distribution fronts."""
    return (ref(f"aws_cloudfront_distribution.{n}.domain_name"),
            ref(f"aws_cloudfront_distribution.{n}.hosted_zone_id"))
