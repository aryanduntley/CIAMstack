"""The forest's certificate templates, read from an LDIF export of CN=Certificate Templates,CN=Public Key Services,
CN=Services,CN=Configuration,<forest> (ldifde, or ldapsearch: RFC 2849, binary and non-ASCII values base64 after `::`,
folded lines joined), into the record's templates (domains.pki.issued). Pure.

Read per pKICertificateTemplate: cn (the template's name), displayName, msPKI-Cert-Template-OID (its own OID, not its
key usages), pKIExtendedKeyUsage (OIDs) and pKIExpirationPeriod: 8 bytes of a FILETIME interval, signed little-endian
and negative, in 100-nanosecond units (MS-CRTD 2.11; the sign convention is derived from Microsoft's default templates,
00 40 39 87 2E E1 FE FF = 365 days, README Known limits). A period that isn't 8 bytes, isn't negative or isn't a whole
number of days is left out with a notice, never rounded.
"""
from fractions import Fraction

from opsdir.core.interchange.ldif import content_entries
from opsdir.core.naming import rdn_safe

TEMPLATE_CLASS = "pkicertificatetemplate"
TICKS_PER_DAY = 10_000_000 * 86_400


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


def read_templates(text):
    """(templates, notices): {name: {"display", "oid", "days", "usages"}} of every pKICertificateTemplate entry in
    the LDIF text, and what was left out."""
    entries = [(dn, attrs) for dn, attrs in content_entries(text.splitlines())
               if TEMPLATE_CLASS in {_text(v).lower() for v in attrs.get("objectclass", ())}]
    named = [(dn, attrs, _first(attrs, "cn")) for dn, attrs in entries]
    periods = {name: validity_days(attrs["pkiexpirationperiod"][0]) if attrs.get("pkiexpirationperiod")
               else (None, None) for _, attrs, name in named if name}
    templates = {name: {"display": _first(attrs, "displayName"), "oid": _first(attrs, "msPKI-Cert-Template-OID"),
                        "days": periods[name][0],
                        "usages": tuple(_text(v).strip() for v in attrs.get("pkiextendedkeyusage", ()))}
                 for _, attrs, name in named if name and rdn_safe(name)}
    notices = (*(f"template {dn}: no cn, or one that can't be named in the record: left out"
                 for dn, _, name in named if not name or not rdn_safe(name)),
               *(f"template {name}: pKIExpirationPeriod {problem}: its validity isn't recorded"
                 for name, (_, problem) in periods.items() if problem and name in templates))
    return templates, notices


def resolver(templates):
    """(value) -> template name of a CA's template value: a template's name, display name or OID (case-insensitive
    for names), else None."""
    index = {**{(t["display"] or "").lower(): n for n, t in templates.items() if t["display"]},
             **{n.lower(): n for n in templates}, **{t["oid"]: n for n, t in templates.items() if t["oid"]}}
    return lambda value: index.get(value) or index.get(str(value or "").lower())
