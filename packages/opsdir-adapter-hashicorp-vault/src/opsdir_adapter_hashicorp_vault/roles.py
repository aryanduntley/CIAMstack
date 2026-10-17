"""A Vault PKI role read as a certificate template the record judges (the core pki domain's template facts): the
longest validity it issues, the extended key usages it puts in certificates, and what it lets requesters do. Pure.

Vault always takes a certificate's names from the request, within what the role allows: the requester names the
subject (ciamSubjectFromRequest TRUE) unless every name the role allows is templated from the requester's own identity
(allowed_domains_template with only {{identity...}} domains, and not allow_any_name). No role waits for an approval or
needs an authorized signature (FALSE, 0). The extended key usages are its flags' (server_flag, client_flag,
code_signing_flag, email_protection_flag: Vault's defaults set the first two), its ext_key_usage names (Go's
crypto/x509 ExtKeyUsage names without the prefix) and its ext_key_usage_oids; none at all is a certificate without the
extension (any purpose). The role describes what it issues now, not what it issued before it was changed."""
import math

from opsdir.core.inventory import duration_seconds

DAY = 86400
FLAG_USAGES = (("server_flag", "1.3.6.1.5.5.7.3.1"), ("client_flag", "1.3.6.1.5.5.7.3.2"),
               ("code_signing_flag", "1.3.6.1.5.5.7.3.3"), ("email_protection_flag", "1.3.6.1.5.5.7.3.4"))
# Go crypto/x509 ExtKeyUsage names (as Vault takes them in ext_key_usage, without "ExtKeyUsage"), lowercase
NAMED_USAGES = {"any": "2.5.29.37.0", "serverauth": "1.3.6.1.5.5.7.3.1", "clientauth": "1.3.6.1.5.5.7.3.2",
                "codesigning": "1.3.6.1.5.5.7.3.3", "emailprotection": "1.3.6.1.5.5.7.3.4",
                "ipsecendsystem": "1.3.6.1.5.5.7.3.5", "ipsectunnel": "1.3.6.1.5.5.7.3.6",
                "ipsecuser": "1.3.6.1.5.5.7.3.7", "timestamping": "1.3.6.1.5.5.7.3.8",
                "ocspsigning": "1.3.6.1.5.5.7.3.9", "microsoftservergatedcrypto": "1.3.6.1.4.1.311.10.3.3",
                "netscapeservergatedcrypto": "2.16.840.1.113730.4.1",
                "microsoftcommercialcodesigning": "1.3.6.1.4.1.311.2.1.22",
                "microsoftkernelcodesigning": "1.3.6.1.4.1.311.61.1.1"}


def seconds(v):
    """A Vault duration (an integer of seconds, its text, or 72h / 30m / 1d) in seconds, or None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    text = str(v or "").strip()
    return int(text) if text.isdigit() else duration_seconds(text)


def max_validity_days(role):
    """(whole days, rounded up, of a role's max_ttl, or None; why not, or None): 0 or none is the mount's maximum,
    which the role doesn't say."""
    s = seconds(role.get("max_ttl"))
    if s is None and role.get("max_ttl") not in (None, ""):
        return None, f"max_ttl {role.get('max_ttl')!r} isn't a duration"
    return (math.ceil(s / DAY), None) if s else (None, "max_ttl 0: the mount's maximum, which the role doesn't say")


def role_usages(role):
    """(the extended key usage OIDs a role puts in its certificates, the ext_key_usage names it doesn't know)."""
    names = tuple(str(n) for n in role.get("ext_key_usage") or ())
    key = lambda n: n.lower().removeprefix("extkeyusage")       # noqa: E731
    return (tuple(dict.fromkeys((*(oid for flag, oid in FLAG_USAGES if role.get(flag)),
                                 *(NAMED_USAGES[key(n)] for n in names if key(n) in NAMED_USAGES),
                                 *(str(o) for o in role.get("ext_key_usage_oids") or ())))),
            tuple(n for n in names if key(n) not in NAMED_USAGES))


def subject_from_request(role):
    """Whether a role lets the requester name the subject: always, unless every name it allows is templated from the
    requester's identity (allowed_domains_template, only {{identity...}} domains, not allow_any_name)."""
    domains = tuple(str(x) for x in role.get("allowed_domains") or ())
    return not (not role.get("allow_any_name") and role.get("allowed_domains_template") and domains
                and all("{{identity." in x for x in domains))
