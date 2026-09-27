"""PKI planner checks."""
import datetime as dt

from ...core.directory import children, follow, gtime_date, one, rdn_value, referrers
from ...core.findings import findings, owner_label
from .domain import CERTIFICATES

# attributes through which an entry depends on a certificate (integrations; service names presenting it)
CERTIFICATE_USE = ("ciamUsesCertificate", "ciamTlsCertificate")


def _certificate_action(d, as_of, c):
    exp = gtime_date(one(c, "ciamNotAfter"))
    partner = follow(d, c, "ciamPartnerContact")
    rb = follow(d, c, "ciamRotationRunbook")
    used = list(dict.fromkeys(rdn_value(u) for attr in CERTIFICATE_USE for _, u in referrers(d, c, attr)))
    text = (f"Certificate `{rdn_value(c)}` expires {exp} ({(exp - as_of).days} days), before cutover + 30 days. "
            f"Used by: {', '.join(used) or 'nothing recorded'}."
            + (f" Coordinate with partner {rdn_value(partner)}." if partner else "")
            + (f" Runbook {rdn_value(rb)}." if rb else ""))
    return ("Certificate", text, owner_label(d, c), exp - dt.timedelta(days=30))


def check_certificates(ctx):
    """Certificates that expire before cutover (or the as-of date) + 30 days."""
    horizon = (ctx.cutover or ctx.as_of) + dt.timedelta(days=30)
    return findings(actions=[_certificate_action(ctx.d, ctx.as_of, c)
                             for c in children(ctx.d, CERTIFICATES, "ciamCertificate")
                             if gtime_date(one(c, "ciamNotAfter")) <= horizon])
