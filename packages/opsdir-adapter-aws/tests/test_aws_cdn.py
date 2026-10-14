"""A CDN in front of a service as AWS Terraform: a CloudFront distribution over its load balancer (nothing cached, the
viewer's Host forwarded, HTTPS to the origin), the viewer certificate from ACM in us-east-1, the protection policy's
web ACL CloudFront-scoped through the us-east-1 provider and named by the distribution, Shield on the distribution;
the ALB then admits only CloudFront and carries no web ACL of its own."""
import re

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.cdn import alias, distribution, fronted
from opsdir_adapter_aws.edge import alb_service, servers_backend
from edge_fixtures import environment, firewall, server, service, spec, subnet

CERT = "aws-acm://arn:aws:acm:us-east-1:111122223333:certificate/abcd"
GOV = {"ciamRegion": ("us-gov-west-1",), "ciamBillingAccountRef": ("111122223333",)}


def _cdn(s):
    svc = service()
    return "\n".join(as_text(distribution(environment(svc), svc, s, "sso")))


def test_a_distribution_over_the_load_balancer_with_a_cloudfront_web_acl():
    out = _cdn(spec(cdn=True, certificate=CERT, ddos="application-advanced"))
    assert 'name = "Managed-CachingDisabled"' in out and 'name = "Managed-AllViewer"' in out
    assert "domain_name = aws_lb.sso.dns_name" in out and 'origin_protocol_policy = "https-only"' in out
    assert re.search(r'aliases\s+= \["sso.example.test"\]', out)
    assert 'acm_certificate_arn      = "arn:aws:acm:us-east-1:111122223333:certificate/abcd"' in out
    assert "provider = aws.us_east_1" in out and 'scope    = "CLOUDFRONT"' in out
    assert "aws_wafv2_web_acl_association" not in out and re.search(r"web_acl_id\s+= aws_wafv2_web_acl.sso.arn", out)
    assert "resource_arn = aws_cloudfront_distribution.sso.arn" in out
    assert "depends_on   = [aws_shield_protection.sso, aws_cloudfront_distribution.sso]" in out
    assert alias("sso") == ("${aws_cloudfront_distribution.sso.domain_name}",
                            "${aws_cloudfront_distribution.sso.hosted_zone_id}")


def test_the_viewer_certificate_must_be_in_us_east_1():
    out = _cdn(spec(cdn=True, certificate=CERT.replace("us-east-1", "eu-west-1")))
    assert "# UNBOUND: CloudFront needs the certificate in ACM in us-east-1 (this one is in eu-west-1)" in out
    assert "# UNBOUND: no ACM certificate holds this service's certificate" in _cdn(spec(cdn=True))


def test_in_govcloud_cloudfront_runs_from_the_standard_account_and_the_name_is_a_cname():
    svc = service(ciamDnsZoneRef="Z0GOVZONE")
    m = environment(svc, cloud=GOV)
    out = "\n".join(as_text(fronted(m, svc, spec(cdn=True, certificate=CERT, ddos="application-advanced"), "sso")))
    assert "# NOTE: CloudFront: not offered in AWS GovCloud (US)" in out and "no ITAR-controlled data in it" in out
    from opsdir_adapter_aws.cdn import govcloud_note
    assert govcloud_note(m).severity == "action"
    dist = out[out.index('resource "aws_cloudfront_distribution" "sso"'):]
    assert dist.split("\n")[1].strip().startswith("provider") and "aws.us_east_1" in dist.split("\n")[1]
    assert out.count("provider = aws.us_east_1") >= 3                # managed policies, web ACL (and Shield below)
    assert "# NOTE: Shield Advanced: its protections need the standard account's subscription" in out
    assert 'type    = "CNAME"' in out and "records = [aws_cloudfront_distribution.sso.domain_name]" in out
    assert "alias {" not in out


def test_in_govcloud_the_certificate_must_be_the_standard_accounts_and_the_account_recorded():
    svc = service(ciamDnsZoneRef="Z0GOVZONE")
    gov_cert = "aws-acm://arn:aws-us-gov:acm:us-east-1:444455556666:certificate/abcd"
    out = "\n".join(as_text(distribution(environment(svc, cloud=GOV), svc, spec(cdn=True, certificate=gov_cert),
                                         "sso")))
    assert "CloudFront needs the certificate in the standard account's ACM (111122223333, us-east-1)" in out
    bare = as_text(fronted(environment(svc, cloud={"ciamRegion": ("us-gov-west-1",)}), svc, spec(cdn=True), "sso"))
    assert len(bare) == 1 and bare[0].startswith("# UNBOUND: `sso.example.test`: CloudFront isn't offered in AWS "
                                                 "GovCloud (US)")


def test_an_alb_behind_cloudfront_admits_only_cloudfront_and_has_no_web_acl():
    svc = service()
    out = "\n".join(as_text(alb_service(environment(svc, firewall("fw-sso-public", ["0.0.0.0/0"], ["443"])), svc,
                                spec(cdn=True, ddos="network-advanced"),
                                servers_backend(svc, (server("pf-1", "10.20.2.10"),)),
                                (subnet("subnet-pf-a", "subnet-pf", "10.20.2.0/24"),))))
    assert 'name = "com.amazonaws.global.cloudfront.origin-facing"' in out
    assert "prefix_list_id    = data.aws_ec2_managed_prefix_list.sso_cloudfront.id" in out
    assert "0.0.0.0/0" not in out and "aws_wafv2" not in out and "aws_shield" not in out
