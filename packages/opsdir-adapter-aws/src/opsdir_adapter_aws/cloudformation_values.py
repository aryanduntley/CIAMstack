"""Template values the CloudFormation readers share. Pure.

  getatt(v)                     (logical ID, attribute) of a Fn::GetAtt, else None
  tag_map(tags)                 {key: value} of a CloudFormation Tags list (a Tags map as given)
  stack_arn(names, service, resource, region)
                                an ARN in the stack's partition, region and account (its pseudo parameters)
  truth(v)                      a boolean property (true, "true", "True"), None when absent
  number(v)                     a digit string as an int (a parameter's value), else as given
  dns_target(raw, resolved)     a DNS name a value gives (an alias's target, a distribution's origin) as the stack's
                                load balancers and distributions are named: cfn:<logical ID> when it is the DNSName or
                                DomainName of one of the stack's resources, else the resolved name, lowercased
"""


def getatt(v):
    """(logical ID, attribute) of a Fn::GetAtt, else None."""
    if isinstance(v, dict) and len(v) == 1 and "Fn::GetAtt" in v:
        arg = v["Fn::GetAtt"]
        parts = arg.split(".", 1) if isinstance(arg, str) else list(arg)
        return tuple(parts) if len(parts) == 2 else None
    return None


def tag_map(tags):
    """{key: value} of a CloudFormation Tags list ([{Key, Value}, ...]); a Tags map (an EKS node group's) as given."""
    if isinstance(tags, dict):
        return dict(tags)
    return {t.get("Key"): t.get("Value") for t in tags or () if isinstance(t, dict) and t.get("Key")}


def stack_arn(names, service, resource, region=True):
    """arn:<partition>:<service>:<region>:<account>:<resource> from the stack's pseudo parameters (names holds them);
    no region for a global service's ARN."""
    partition, account = names.get("AWS::Partition") or "aws", names.get("AWS::AccountId") or ""
    where = (names.get("AWS::Region") or "") if region else ""
    return f"arn:{partition}:{service}:{where}:{account}:{resource}"


def truth(v):
    """A boolean property as given (true, "true", "True"), None when absent."""
    return None if v is None else str(v).lower() == "true"


def number(v):
    """A digit string (a parameter's value) as an int, else the value as given."""
    return int(v) if isinstance(v, str) and v.isdigit() else v


def dns_target(raw, resolved):
    """A DNS name as the stack's load balancers and distributions are named (cfn:<logical ID> when it is the DNSName
    or DomainName of one of them, also when another stack's output passes it), else the resolved name lowercased."""
    ref = getatt(raw)
    if ref and ref[1] in ("DNSName", "DomainName"):
        return f"cfn:{ref[0]}"
    return resolved if str(resolved).startswith("cfn:") else (resolved or "").lower().rstrip(".") or None
