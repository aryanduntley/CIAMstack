"""Template values the CloudFormation readers share. Pure.

  getatt(v)                     (logical ID, attribute) of a Fn::GetAtt, else None
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


def dns_target(raw, resolved):
    """A DNS name as the stack's load balancers and distributions are named (cfn:<logical ID> when it is the DNSName
    or DomainName of one of them, also when another stack's output passes it), else the resolved name lowercased."""
    ref = getatt(raw)
    if ref and ref[1] in ("DNSName", "DomainName"):
        return f"cfn:{ref[0]}"
    return resolved if str(resolved).startswith("cfn:") else (resolved or "").lower().rstrip(".") or None
