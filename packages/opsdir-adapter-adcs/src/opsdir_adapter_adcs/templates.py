"""The forest's certificate templates, read from an LDIF export of CN=Certificate Templates,CN=Public Key Services,
CN=Services,CN=Configuration,<forest> (the collector's ldapsearch, or ldifde: RFC 2849, binary and non-ASCII values
base64 after `::`, folded lines joined), into the record's templates (domains.pki.issued). Pure.

Read per pKICertificateTemplate: cn (the template's name), displayName, msPKI-Cert-Template-OID (its own OID, not its
key usages), pKIExtendedKeyUsage (OIDs) and pKIExpirationPeriod: 8 bytes of a FILETIME interval, signed little-endian
and negative, in 100-nanosecond units (MS-CRTD 2.11; the sign convention is derived from Microsoft's default templates,
00 40 39 87 2E E1 FE FF = 365 days, README Known limits). A period that isn't 8 bytes, isn't negative or isn't a whole
number of days is left out with a notice, never rounded.

What a template lets requesters do (MS-CRTD; the flags are signed 32-bit integers, negative when bit 31 is set, tested
on their 32 bits): msPKI-Certificate-Name-Flag 0x1 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: the request names the subject
and alternative names; 0x10000 alone the CA ignores, MS-WCCE), msPKI-Enrollment-Flag 0x2 (CT_FLAG_PEND_ALL_REQUESTS: a
CA manager approves each request), msPKI-RA-Signature (authorized signatures a request needs) and
msPKI-Template-Schema-Version. What it issues: from schema version 2 on, msPKI-Certificate-Application-Policy when it
has any (the application policies the CA puts in the certificate), else pKIExtendedKeyUsage; when both are there and
differ, a notice. Who may enroll: its nTSecurityDescriptor (security.py); without one, unknown, with a notice. A value
missing from the export is recorded as not read, never as a default.
"""
from fractions import Fraction

from opsdir.core.interchange.ldif import content_entries
from opsdir.core.naming import rdn_safe
from .security import enrollees

TEMPLATE_CLASS = "pkicertificatetemplate"
TICKS_PER_DAY = 10_000_000 * 86_400
SUPPLIES_SUBJECT, PEND_ALL_REQUESTS = 0x1, 0x2
FLAG_RANGE = range(-2 ** 31, 2 ** 32)


def _text(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _first(attrs, name):
    vals = attrs.get(name.lower(), ())
    return _text(vals[0]).strip() if vals else None


def validity_days(raw):
    """(days, problem) of a pKIExpirationPeriod value (8 bytes): the whole number of days of its negative interval,
    or (None, why not)."""
    if not isinstance(raw, bytes) or len(raw) != 8:
        return None, "isn't 8 bytes (a base64 value)"
    interval = int.from_bytes(raw, "little", signed=True)
    if interval >= 0:
        return None, "isn't a negative interval"
    days = Fraction(-interval, TICKS_PER_DAY)
    return (int(days), None) if days.denominator == 1 else (None, f"is {float(days):.4f} days, not a whole number")


def flag_value(text):
    """(value, problem) of a template's integer attribute as LDAP gives it (signed decimal): its 32 bits as an
    unsigned value (a negative value has bit 31 set), or (None, why not); (None, None) when it is absent."""
    if text is None:
        return None, None
    try:
        value = int(text)
    except ValueError:
        return None, f"{text!r} isn't an integer"
    return (value & 0xFFFFFFFF, None) if value in FLAG_RANGE else (None, f"{text!r} isn't a 32-bit integer")


def template_rights(name, attrs):
    """(usages, rights, notices) of a template entry's attributes: the usages it issues (its application policies
    from schema version 2 on, else its extended key usages), what it lets requesters do and who may enroll
    ({record attribute: value, None when not read}, domains.pki.issued TEMPLATE_RIGHTS), and what couldn't be read."""
    read = {k: flag_value(_first(attrs, k)) for k in ("msPKI-Template-Schema-Version", "msPKI-Certificate-Name-Flag",
                                                         "msPKI-Enrollment-Flag", "msPKI-RA-Signature")}
    version, names, enrolling, signatures = (read[k][0] for k in read)
    keys = tuple(_text(v).strip() for v in attrs.get("pkiextendedkeyusage", ()))
    policies = tuple(_text(v).strip() for v in attrs.get("mspki-certificate-application-policy", ()))
    from_policies = bool(policies) and (version or 0) >= 2
    usages = policies if from_policies else keys
    sd = (attrs.get("ntsecuritydescriptor") or (None,))[0]
    trustees, scope, problem = enrollees(sd if isinstance(sd, bytes) or sd is None else _text(sd).encode())
    notices = (*(f"template {name}: {k} {p}: not recorded" for k, (_, p) in read.items() if p),
               *((f"template {name}: its application policies ({', '.join(policies)}) differ from its "
                  f"pKIExtendedKeyUsage ({', '.join(keys) or 'none'}): the application policies are recorded as what "
                  "it issues",) if from_policies and keys and set(keys) != set(policies) else ()),
               *((f"template {name}: nTSecurityDescriptor {problem}: who may enroll is unknown",) if problem else ()))
    rights = {"ciamSubjectFromRequest": None if names is None else bool(names & SUPPLIES_SUBJECT),
              "ciamApprovalRequired": None if enrolling is None else bool(enrolling & PEND_ALL_REQUESTS),
              "ciamRequiredSignatures": signatures, "ciamTemplateVersion": version,
              "ciamEnrollee": trustees, "ciamEnrollmentScope": scope}
    return usages, rights, notices


def read_templates(text):
    """(templates, notices): {name: {"display", "oid", "days", "usages", "rights"}} of every pKICertificateTemplate
    entry in the LDIF text (template_rights), and what was left out or couldn't be read."""
    entries = [(dn, attrs) for dn, attrs in content_entries(text.splitlines())
               if TEMPLATE_CLASS in {_text(v).lower() for v in attrs.get("objectclass", ())}]
    named = [(dn, attrs, _first(attrs, "cn")) for dn, attrs in entries]
    periods = {name: validity_days(attrs["pkiexpirationperiod"][0]) if attrs.get("pkiexpirationperiod")
               else (None, None) for _, attrs, name in named if name}
    judged = {name: template_rights(name, attrs) for _, attrs, name in named if name and rdn_safe(name)}
    templates = {name: {"display": _first(attrs, "displayName"), "oid": _first(attrs, "msPKI-Cert-Template-OID"),
                        "days": periods[name][0], "usages": judged[name][0], "rights": judged[name][1]}
                 for _, attrs, name in named if name in judged}
    unread = sorted(n for _, attrs, n in named if n in judged and not attrs.get("ntsecuritydescriptor"))
    notices = (*(f"template {dn}: no cn, or one that can't be named in the record: left out"
                 for dn, _, name in named if not name or not rdn_safe(name)),
               *(f"template {name}: pKIExpirationPeriod {problem}: its validity isn't recorded"
                 for name, (_, problem) in periods.items() if problem and name in templates),
               *(n for _, _, ns in judged.values() for n in ns),
               *((f"templates: {len(unread)} template(s) ({', '.join(unread)}): access rights (nTSecurityDescriptor) "
                  "not in the export: who may enroll is unknown",) if unread else ()))
    return templates, notices


def resolver(templates):
    """(value) -> template name of a CA's template value: a template's name, display name or OID (case-insensitive
    for names), else None."""
    index = {**{(t["display"] or "").lower(): n for n, t in templates.items() if t["display"]},
             **{n.lower(): n for n in templates}, **{t["oid"]: n for n, t in templates.items() if t["oid"]}}
    return lambda value: index.get(value) or index.get(str(value or "").lower())
