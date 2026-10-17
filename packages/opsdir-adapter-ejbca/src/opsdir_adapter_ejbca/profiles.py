"""An EJBCA certificate profile read as a CA-scoped certificate template the record judges (the core pki domain's
template facts), from GET /v2/certificate/profile/{name}: the longest validity it issues and the extended key usages
it puts in certificates. Pure.

A certificate profile is EJBCA-wide and offered to the CAs its available_cas names (ANY_CA: every CA); each CA that
issued from it has its own template '<CA>/<profile>' (ciamTemplateAuthority), as a Vault role is its mount's. What a
profile lets requesters do and who may request from it aren't read: EJBCA Community's REST API exposes no roles,
approval profiles or the profile's subject DN override, so the template's rights are left unknown (None), and named.
The end entity profiles the CA's certificates came through are named in the template's description: Community's REST
API has no end entity profile resource. The profile describes what it issues now, not what it issued before it was
changed."""
import math
import re

from opsdir.domains.pki.issued import template_entry

DAY = 86400
ANY_CA = "ANY_CA"
# EJBCA's validity notation (SimpleTime): a year is 365 days, a month 30
UNITS = {"y": 365 * DAY, "mo": 30 * DAY, "d": DAY, "h": 3600, "m": 60, "s": 1, "ms": 0.001}
PART = re.compile(r"(\d+)\s*(ms|mo|y|d|h|m|s)")
RIGHTS_UNREAD = ("who may request from the EJBCA templates and what they let requesters do aren't read: EJBCA's REST "
                 "API exposes no roles, approval profiles or subject DN override: unknown")


def validity_days(text):
    """(whole days, rounded up, of a profile's validity, or None; why not, or None): EJBCA's notation 1y 6mo 3d 12h;
    an absolute end date isn't a length."""
    t = str(text or "").strip().lower()
    parts = PART.findall(t)
    if not t:
        return None, "no validity"
    if not parts or PART.sub("", t).strip():
        return None, f"validity {text!r} isn't a length (an end date?)"
    return math.ceil(sum(int(n) * UNITS[u] for n, u in parts) / DAY), None


def offered_to(profile, ca):
    """Whether a profile offers the CA (its EJBCA name) to issue from: available_cas names it, or ANY_CA."""
    cas = tuple(str(c) for c in profile.get("available_cas") or ())
    return ANY_CA in cas or ca in cas


def profile_template(d, ca, ejbca_ca, name, profile, ee_profiles):
    """(the CA's template entry for a certificate profile it issued from, or None when the profile no longer offers
    the CA; notices)."""
    template = f"{ca}/{name}"
    if not offered_to(profile, ejbca_ca):
        return None, (f"{template}: certificate profile {name} no longer offers {ejbca_ca}: left out",)
    days, why = validity_days(profile.get("validity"))
    usages = tuple(str(u) for u in profile.get("extended_key_usages") or ())
    through = f" (end entity profiles {', '.join(ee_profiles)})" if ee_profiles else ""
    entry = template_entry(d, template, f"EJBCA certificate profile {name}{through}", None, days, usages, None,
                           authority=ca)
    return entry, ((f"{template}: {why}",) if why else ())
