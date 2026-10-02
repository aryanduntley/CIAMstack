"""What a domain's DNS says about mail sent as it: SPF and DMARC, read from its TXT records. Pure and vendor-neutral:
every cloud adapter reads its own DNS records into TXT values and asks these. A cloud's sending service names the SPF
include that authorizes it (amazonses.com, spf.protection.outlook.com, ...)."""
import re

_SPF = re.compile(r"^v=spf1(\s|$)", re.I)
_DMARC_POLICY = re.compile(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)", re.I)


def _unquoted(value):
    """A TXT value as one string: DNS splits long values into quoted chunks ("a" "b")."""
    parts = re.findall(r'"([^"]*)"', value or "")
    return "".join(parts) if parts else (value or "").strip()


def spf_authorizes(texts, include):
    """Whether the SPF record among a domain's TXT values authorizes a service by its include: TRUE / FALSE, or None
    when the domain publishes no SPF record."""
    spf = next((t for t in map(_unquoted, texts) if _SPF.match(t)), None)
    if spf is None:
        return None
    return "TRUE" if f"include:{include.lower()}" in spf.lower().split() else "FALSE"


def dmarc_policy(texts):
    """The policy (none, quarantine, reject) a domain's _dmarc TXT values ask for, or None."""
    found = next((m.group(1).lower() for t in map(_unquoted, texts) if t.lower().startswith("v=dmarc1")
                  for m in (_DMARC_POLICY.search(t),) if m), None)
    return found
