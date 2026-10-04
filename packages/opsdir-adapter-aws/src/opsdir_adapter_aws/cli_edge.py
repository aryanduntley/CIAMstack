"""What the AWS CLI reports about an environment's edge, normalized to the Terraform attribute names the shared mapping
reads (opsdir_adapter_aws.edge_inventory). Pure.

  elbv2 describe-load-balancer-attributes   Attributes        -> the load balancer's idle timeout; the output doesn't
                                                                  name it: save it as lb-attributes/<load balancer
                                                                  name>.json
  elbv2 describe-target-group-attributes    Attributes        -> the target group's stickiness and deregistration
                                                                  delay; save it as tg-attributes/<target group
                                                                  name>.json
  wafv2 get-web-acl                         WebACL            -> aws_wafv2_web_acl (its rules)
  wafv2 list-resources-for-web-acl          ResourceArns      -> aws_wafv2_web_acl_association; save it as
                                                                  waf-resources/<web ACL name>.json
  wafv2 get-ip-set                          IPSet             -> aws_wafv2_ip_set
  shield list-protections                   Protections       -> aws_shield_protection (+ automatic response when
                                                                  layer 7 automatic response is enabled)
  cloudfront list-distributions             DistributionList  -> aws_cloudfront_distribution
  route53 list-hosted-zones                 HostedZones       -> aws_route53_zone (private: a VPC association)
  route53resolver list-resolver-rules       ResolverRules     -> aws_route53_resolver_rule
The listener, target group and record set outputs the main reader already recognizes carry their protocols, TLS
policies, health checks, TTLs and routing (opsdir_adapter_aws.cli).
"""
import re

KEYS = ("WebACL", "ResourceArns", "IPSet", "Protections", "DistributionList", "HostedZones", "ResolverRules",
        "Attributes")
_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def _stem(path):
    return path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def _folder(path):
    return path.rsplit("/", 1)[0].rsplit("/", 1)[-1] if "/" in path else ""


def _snake(name):
    """A CLI key as Terraform names it: RateBasedStatement -> rate_based_statement, IPSet... -> ip_set..."""
    plain = name.replace("IPSet", "IpSet").replace("ARN", "Arn").replace("CustomKeys", "CustomKey")
    return _CAMEL.sub("_", plain).lower()


def terraform_shape(value):
    """A CLI structure in Terraform's state shape: keys in snake case, nested objects as one-element lists (blocks),
    lists of objects as lists of blocks."""
    if isinstance(value, dict):
        return [{_snake(k): (terraform_shape(v) if isinstance(v, (dict, list)) else v) for k, v in value.items()}]
    if isinstance(value, list):
        return [x for v in value for x in (terraform_shape(v) if isinstance(v, dict) else [v])]
    return value


def attributes(outs, folder):
    """{the named resource: {attribute key: value}} of the Attributes outputs saved under folder/<name>.json."""
    return {_stem(p): {a.get("Key"): a.get("Value") for a in doc.get("Attributes") or () if isinstance(a, dict)}
            for p, k, doc in outs if k == "Attributes" and _folder(p) == folder}


def _web_acls(outs):
    acls = [doc["WebACL"] for _, k, doc in outs if k == "WebACL" and isinstance(doc.get("WebACL"), dict)]
    by_name = {a.get("Name"): a.get("ARN") for a in acls}
    return [*(("aws_wafv2_web_acl", {"arn": a.get("ARN"), "name": a.get("Name"),
                                     "rule": [terraform_shape(r)[0] for r in a.get("Rules") or ()]}) for a in acls),
            *(("aws_wafv2_web_acl_association", {"web_acl_arn": by_name.get(_stem(p)), "resource_arn": arn})
              for p, k, doc in outs if k == "ResourceArns" and _stem(p) in by_name
              for arn in doc.get("ResourceArns") or ()),
            *(("aws_wafv2_ip_set", {"arn": s.get("ARN"), "name": s.get("Name"), "addresses": s.get("Addresses") or []})
              for _, k, doc in outs if k == "IPSet" for s in (doc.get("IPSet") or {},) if s.get("ARN"))]


def _shield(outs):
    protections = [p for _, k, doc in outs if k == "Protections" for p in doc.get("Protections") or ()]
    return [*(("aws_shield_protection", {"id": p.get("Id"), "name": p.get("Name"),
                                         "resource_arn": p.get("ResourceArn")}) for p in protections),
            *(("aws_shield_application_layer_automatic_response", {"resource_arn": p.get("ResourceArn")})
              for p in protections
              if (p.get("ApplicationLayerAutomaticResponseConfiguration") or {}).get("Status") == "ENABLED")]


def _dns(name):
    return (name or "").lower().rstrip(".")


def _distributions(outs, dns):
    return [("aws_cloudfront_distribution", {
                "arn": d.get("ARN"), "id": d.get("Id"), "domain_name": dns(d.get("DomainName")),
                "comment": d.get("Comment"), "web_acl_id": d.get("WebACLId") or None,
                "origin": [{"domain_name": dns(o.get("DomainName")), "origin_id": o.get("Id")}
                           for o in (d.get("Origins") or {}).get("Items") or ()],
                "viewer_certificate": [{"minimum_protocol_version":
                                        (d.get("ViewerCertificate") or {}).get("MinimumProtocolVersion")}]})
            for _, k, doc in outs if k == "DistributionList"
            for d in (doc.get("DistributionList") or {}).get("Items") or ()]


def edge_pairs(outs, dns):
    """(Terraform resource type, attributes) pairs of the edge outputs; dns normalizes a DNS name."""
    return [*_web_acls(outs), *_shield(outs), *_distributions(outs, dns),
            *(("aws_route53_zone", {"zone_id": z.get("Id", "").rsplit("/", 1)[-1], "name": _dns(z.get("Name")),
                                    "vpc": [{}] if (z.get("Config") or {}).get("PrivateZone") else []})
              for _, k, doc in outs if k == "HostedZones" for z in doc.get("HostedZones") or ()),
            *(("aws_route53_resolver_rule", {"id": r.get("Id"), "name": r.get("Name"), "rule_type": r.get("RuleType"),
                                             "domain_name": r.get("DomainName"),
                                             "target_ip": [{"ip": t.get("Ip"), "port": t.get("Port")}
                                                           for t in r.get("TargetIps") or ()]})
              for _, k, doc in outs if k == "ResolverRules" for r in doc.get("ResolverRules") or ())]


def record_attributes(r):
    """A record set's TTL, values (TXT unquoted) and routing in Terraform's names."""
    return {"ttl": r.get("TTL"),
            "records": [v.get("Value").strip('"') if r.get("Type") == "TXT" else v.get("Value")
                        for v in r.get("ResourceRecords") or () if v.get("Value")],
            "set_identifier": r.get("SetIdentifier"),
            "failover_routing_policy": [{"type": r["Failover"]}] if r.get("Failover") else [],
            "weighted_routing_policy": [{"weight": r["Weight"]}] if r.get("Weight") is not None else []}
