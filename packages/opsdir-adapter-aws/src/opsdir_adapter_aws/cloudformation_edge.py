"""The edge CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping reads
(opsdir_adapter_aws.edge_inventory). CloudFormation's properties follow the AWS API, as the CLI's outputs do, so the
CLI reader's shaping is reused (cli_edge.terraform_shape: a WAF rule's statements as Terraform blocks). Properties
come resolved (Ref to physical IDs, Fn::GetAtt where it follows from one). Pure.

  AWS::WAFv2::WebACL, IPSet, WebACLAssociation   -> aws_wafv2_web_acl (its rules), aws_wafv2_ip_set,
                                                    aws_wafv2_web_acl_association
  AWS::Shield::Protection                        -> aws_shield_protection (+ the layer 7 automatic response when
                                                    enabled)
  AWS::CloudFront::Distribution                  -> aws_cloudfront_distribution (origins, web ACL, TLS minimum)
  AWS::Route53Resolver::ResolverRule             -> aws_route53_resolver_rule
  AWS::Route53::HostedZone                       -> aws_route53_zone (its Ref is its zone id; private when it names
                                                    VPCs; HostedZoneTags)
"""
from .cli_edge import terraform_shape
from .cloudformation_values import dns_target, tag_map

EDGE_TYPES = ("AWS::WAFv2::WebACL", "AWS::WAFv2::IPSet", "AWS::WAFv2::WebACLAssociation", "AWS::Shield::Protection",
              "AWS::CloudFront::Distribution", "AWS::Route53Resolver::ResolverRule", "AWS::Route53::HostedZone")


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _arn(names, lid, pid):
    """A resource's ARN: its Fn::GetAtt Arn, else its physical id when that is one."""
    return names.get(f"{lid}.Arn") or (pid if str(pid).startswith("arn:") else None)


def _waf(declared, names):
    return [*(("aws_wafv2_web_acl", {"arn": _arn(names, lid, pid), "name": p.get("Name"),
                                     "rule": [terraform_shape(r)[0] for r in p.get("Rules") or ()
                                              if isinstance(r, dict)]})
              for lid, p, pid in _of(declared, "AWS::WAFv2::WebACL")),
            *(("aws_wafv2_ip_set", {"arn": _arn(names, lid, pid), "name": p.get("Name"),
                                    "addresses": list(p.get("Addresses") or ())})
              for lid, p, pid in _of(declared, "AWS::WAFv2::IPSet")),
            *(("aws_wafv2_web_acl_association", {"web_acl_arn": p.get("WebACLArn"),
                                                 "resource_arn": p.get("ResourceArn")})
              for _, p, _ in _of(declared, "AWS::WAFv2::WebACLAssociation"))]


def _shield(declared, names):
    protections = _of(declared, "AWS::Shield::Protection")
    return [*(("aws_shield_protection", {"id": pid, "arn": _arn(names, lid, pid), "name": p.get("Name"),
                                         "resource_arn": p.get("ResourceArn")}) for lid, p, pid in protections),
            *(("aws_shield_application_layer_automatic_response", {"resource_arn": p.get("ResourceArn")})
              for _, p, _ in protections
              if (p.get("ApplicationLayerAutomaticResponseConfiguration") or {}).get("Status") == "ENABLED")]


def _distributions(declared, names, dns):
    def one(lid, p, raw, pid):
        c, given = p.get("DistributionConfig") or {}, (raw.get("DistributionConfig") or {}).get("Origins") or ()
        return ("aws_cloudfront_distribution", {
            "arn": _arn(names, lid, pid), "id": pid,
            "domain_name": dns(names.get(f"{lid}.DomainName")) or f"cfn:{lid}",      # as a stack's alias names it
            "comment": c.get("Comment"), "web_acl_id": c.get("WebACLId") or None,
            "origin": [{"domain_name": dns_target(r.get("DomainName"), o.get("DomainName")), "origin_id": o.get("Id")}
                       for o, r in zip(c.get("Origins") or (), given) if isinstance(o, dict) and isinstance(r, dict)],
            "viewer_certificate": [{"minimum_protocol_version":
                                    (c.get("ViewerCertificate") or {}).get("MinimumProtocolVersion")}]})
    return [one(lid, p, raw, pid) for lid, t, p, raw, pid in declared if t == "AWS::CloudFront::Distribution"]


def _resolver_rules(declared):
    return [("aws_route53_resolver_rule", {"id": pid, "name": p.get("Name"), "rule_type": p.get("RuleType"),
                                           "domain_name": p.get("DomainName"),
                                           "target_ip": [{"ip": t.get("Ip"), "port": t.get("Port")}
                                                         for t in p.get("TargetIps") or () if isinstance(t, dict)]})
            for _, p, pid in _of(declared, "AWS::Route53Resolver::ResolverRule")]


def _zones(declared, dns):
    return [("aws_route53_zone", {"zone_id": pid, "name": dns(p.get("Name")), "vpc": [{}] if p.get("VPCs") else [],
                                  "tags": tag_map(p.get("HostedZoneTags"))})
            for _, p, pid in _of(declared, "AWS::Route53::HostedZone")]


def edge_stack_pairs(declared, names, dns):
    """(Terraform resource type, attributes) pairs of the edge among a stack's declared resources ((logical ID, type,
    resolved properties, raw properties, physical ID), ...); names: what references resolve to; dns normalizes a DNS
    name."""
    return [*_waf(declared, names), *_shield(declared, names), *_distributions(declared, names, dns),
            *_resolver_rules(declared), *_zones(declared, dns)]
