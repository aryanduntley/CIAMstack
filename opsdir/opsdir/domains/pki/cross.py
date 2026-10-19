"""Cross-certificates: one CA certifying another PKI's CA, recorded as facts of the graph, never as trust. Pure.

A cross-certificate (ou=cross-certificates) names its issuer CA and the CA it certifies (subject) by distinguished
name, what it joins (ciamCrossRole: peer, bridge-to-member, member-to-bridge), the policy mappings it carries
(issuerDomainPolicy=subjectDomainPolicy), its validity and, when observed, its fingerprint, serial and PEM. A reader of
certificates (opsdir-adapter-x509's x509/certificates importer) records one it recognises: a CA certificate whose
issuer is another CA and whose subject is a root the record holds (a self-issued CA certificate under ou=certificates,
or a root a trust bundle holds); operators record the rest by hand.

What is trusted stays a trust policy's approved anchors (trust.py): nothing here builds or validates a path. The graph
is read by name, issuer to subject: from each anchor, the CAs its cross-certificates reach and through which (the
cross-certificates report). The planner (check_cross_certificates) warns, as actions, where a policy's anchor reaches a
CA only through cross-certificates (a consumer given them, or fetching them, would accept what that CA issues though
the policy never approved it), where a cross-certificate has expired or expires within the certificate expiry margin,
and where one is also held as a record certificate (chains followed by name could run through it). Nothing is said
while the record holds no cross-certificate."""
import datetime as dt
import re
from typing import NamedTuple

from ...core.directory import (children, date_of, fingerprint, get, gtime_date, make_entry, merged_attrs, norm_dn, one,
                               rdn_value, values)
from ...core.findings import findings, merge_findings, owner_label
from ...core.settings import setting_value
from .chain import ca_certificates, issuer_chain, self_issued
from .naming import CERTIFICATES, CROSS_CERTIFICATES, cross_certificate_dn
from .settings import EXPIRY_MARGIN_DAYS
from .trust import bundle_members, fp, is_root, policy_anchors, trust_bundles, trust_policies

CROSS_CLASS = "ciamCrossCertificate"
AREA = "Trust"
# what a reader of the cross-certificate itself owns on its entry (its role, owners and description are the record's)
CROSS_FACTS = ("ciamIssuer", "ciamSubject", "ciamNotBefore", "ciamNotAfter", "ciamFingerprint", "ciamSerialNumber",
               "ciamCertificatePem", "ciamCertPolicyOid", "ciamPolicyMapping", "ciamSubjectKeyId",
               "ciamAuthorityKeyId", "ciamPathLength")

# A CA reachable from an anchor: the anchor (record CA certificate entry), the CA reached (its subject DN as the last
# cross-certificate names it) and the cross-certificates the way runs through, issuer first.
Reach = NamedTuple("Reach", [("anchor", object), ("ca", str), ("path", tuple)])


# ------------------------------------------------------------------ entries
def cross_certificates(d):
    """The cross-certificates the record holds, in record order."""
    return children(d, CROSS_CERTIFICATES, CROSS_CLASS)


def cross_of(d, sha256):
    """The cross-certificate recorded with that SHA-256 fingerprint, or None."""
    key = fingerprint(sha256 or "")
    return next((x for x in cross_certificates(d) if key and fp(x) == key), None)


def _common_name(dn):
    found = re.search(r"(?i)(?:^|,)\s*CN=((?:\\.|[^,])+)", dn or "")
    return (found.group(1) if found else dn or "").replace("\\", "").strip()


def _rdn_safe(text):
    return re.sub(r"\s+", " ", re.sub(r'[,+="\\<>;#]', " ", text)).strip()


def cross_name(d, subject, issuer, sha256=None):
    """The name a cross-certificate is recorded under: the one already recorded with its fingerprint, else '<subject's
    common name> by <issuer's common name>' (an entry of that name recorded by hand without a fingerprint is taken to
    be it), made unique by its fingerprint when another cross-certificate holds that name."""
    held = cross_of(d, sha256) if sha256 else None
    if held is not None:
        return rdn_value(held)
    name = _rdn_safe(f"{_common_name(subject)} by {_common_name(issuer)}")
    taken = get(d, cross_certificate_dn(name))
    return (name if taken is None or not sha256 or not fp(taken)
            else f"{name} {fingerprint(sha256).replace(':', '')[:8]}")


def cross_entry(d, name, facts):
    """A cross-certificate's entry named `name`; facts {attribute of CROSS_FACTS: a value, a tuple of values, or
    None} replace what a reader owns, and what the record adds (its role, owners, description) is kept."""
    dn = cross_certificate_dn(name)
    owned = {"cn": (name,), **{k: v if isinstance(v, tuple) else (v,) for k, v in facts.items() if k in CROSS_FACTS}}
    return make_entry(dn, ("top", "ciamObject", CROSS_CLASS), merged_attrs(get(d, dn), owned, ("cn", *CROSS_FACTS)))


def certified_root(d, subject, issuer, ca):
    """The root a certificate with that subject and issuer (DNs) cross-certifies, when it is a cross-certificate: a CA
    certificate (ca: its basic constraints say so) whose issuer isn't its subject and whose subject is that of a
    self-issued CA certificate under ou=certificates, or of a root a trust bundle holds (that entry); else None."""
    name, by = norm_dn(subject or ""), norm_dn(issuer or "")
    if ca is not True or not name or not by or name == by:
        return None
    roots = (*(c for c in ca_certificates(d) if self_issued(c)),
             *(m for b in trust_bundles(d) for m in bundle_members(d, b) if is_root(m)))
    return next((r for r in roots if norm_dn(one(r, "ciamSubject") or "") == name), None)


# ------------------------------------------------------------------ the graph
def _subject(e):
    return norm_dn(one(e, "ciamSubject") or "")


def _issuer(e):
    return norm_dn(one(e, "ciamIssuer") or "")


def reachable(d, anchor, approved=(), crosses=None):
    """The CAs an anchor reaches through cross-certificates (Reach, nearest first, each CA once by its shortest way),
    issuer to subject by name; approved: further subjects (normalised DNs, a policy's other anchors) not counted as
    reached."""
    crosses = cross_certificates(d) if crosses is None else crosses

    def walk(frontier, seen, found):
        step = {}
        for at, path in frontier:
            for x in crosses:
                if _issuer(x) == at and _subject(x) not in seen and _subject(x) not in step:
                    step[_subject(x)] = (*path, x)
        return found if not step else walk(tuple(step.items()), seen | set(step),
                                           (*found, *(Reach(anchor, one(p[-1], "ciamSubject"), p)
                                                      for p in step.values())))
    start = _subject(anchor)
    return walk(((start, ()),), {start, *approved}, ()) if start else ()


def _anchors(d):
    """Every trust policy's anchors, each once in policy order, with the policies accepting it."""
    by_anchor = {}
    for p in trust_policies(d):
        for a in policy_anchors(d, p):
            by_anchor.setdefault(a.norm, (a, []))[1].append(p)
    return tuple((a, tuple(ps)) for a, ps in by_anchor.values())


def _through(path):
    return " -> ".join(rdn_value(x) + (f" ({one(x, 'ciamCrossRole')})" if one(x, "ciamCrossRole") else "")
                       for x in path)


def _mappings(path):
    return ", ".join(m for x in path for m in values(x, "ciamPolicyMapping"))


def _earliest(path):
    dates = [date_of(x, "ciamNotAfter") for x in path if date_of(x, "ciamNotAfter") is not None]
    return min(dates) if dates else None


def issued_under(d, subject):
    """The record certificates (ou=certificates) issued under the CA of that subject (a DN): its subject is their
    issuer's, or one of the CA certificates their chain runs through has it; in record order."""
    name = norm_dn(subject or "")
    return tuple(c for c in children(d, CERTIFICATES, "ciamCertificate")
                 if _subject(c) != name and (_issuer(c) == name or any(_subject(x) == name
                                                                        for x in issuer_chain(d, c))))


# ------------------------------------------------------------------ checks
def _reach_text(d, policy, r):
    held = issued_under(d, r.ca)
    mappings = _mappings(r.path)
    return (f"Trust policy `{rdn_value(policy)}` accepts anchor `{rdn_value(r.anchor)}`, from which CA `{r.ca}` is "
            f"reachable only through cross-certificate{'s' if len(r.path) > 1 else ''} {_through(r.path)}"
            + (f" (policy mappings {mappings})" if mappings else "")
            + (f"; the record holds certificates issued under it: {', '.join(rdn_value(c) for c in held)}"
               if held else "")
            + ". The policy never approved that CA: a consumer given the cross-certificates (or fetching them through "
              "authority information access) and building paths through them would accept what it issues. Approve "
              "the CA as an anchor if the policy should accept it; otherwise keep the cross-certificates from the "
              "policy's consumers and restrict its certificate policies (ciamAllowedPolicyOid).")


def _only_through(d, policy, crosses):
    """The CAs a policy's anchors reach only through cross-certificates (none of its anchors), each once (Reach)."""
    anchors = policy_anchors(d, policy)
    approved = {_subject(a) for a in anchors}
    reached = {}
    for a in anchors:
        for r in reachable(d, a, approved, crosses):
            reached.setdefault(norm_dn(r.ca), r)
    return tuple(reached.values())


def _reach_actions(d, crosses):
    """Per trust policy, each CA its anchors reach only through cross-certificates (not itself one of its anchors)."""
    return findings(actions=[(AREA, _reach_text(d, p, r), owner_label(d, p), None)
                             for p in trust_policies(d) for r in _only_through(d, p, crosses)])


def _expiry_text(x, end, as_of, used):
    reach = (f"anchors reaching through it: {', '.join(f'`{rdn_value(a)}` ({rdn_value(p)})' for a, p in used)}"
             if used else "no trust policy's anchor reaches through it")
    return (f"Cross-certificate `{rdn_value(x)}` ({one(x, 'ciamIssuer')} -> {one(x, 'ciamSubject')}) "
            + (f"expired {end}" if end < as_of else f"expires {end} ({(end - as_of).days} days)") + f"; {reach}. "
            "Paths built through it fail once it has expired: obtain its successor from the issuing PKI and record it "
            "(opsdir import x509/certificates, or by hand under ou=cross-certificates), or remove it if the PKIs no "
            "longer cross-certify.")


def _expiry_actions(d, crosses, as_of, horizon):
    """Cross-certificates expired, or expiring before the horizon, with the anchors (and their policies) reaching
    through them; owned by the cross-certificate's owners, else the first such policy's."""
    anchors = _anchors(d)

    def users(x):
        found = {(a.norm, p.norm): (a, p) for a, ps in anchors for r in reachable(d, a, (), crosses)
                 if x.norm in {y.norm for y in r.path} for p in ps}
        return tuple(found.values())
    due = [(x, gtime_date(one(x, "ciamNotAfter")), users(x)) for x in crosses if one(x, "ciamNotAfter")]
    return findings(actions=[(AREA, _expiry_text(x, end, as_of, used),
                              owner_label(d, used[0][1]) if used and not values(x, "ciamOwner") else owner_label(d, x),
                              end)
                             for x, end, used in due if end <= horizon])


def _held_as_certificate(d, crosses):
    """Cross-certificates the record also holds as a record certificate (same fingerprint)."""
    held = [(x, c) for x in crosses if fp(x) for c in children(d, CERTIFICATES, "ciamCertificate") if fp(c) == fp(x)]
    return findings(actions=[
        (AREA, f"Cross-certificate `{rdn_value(x)}` is also recorded as certificate `{rdn_value(c)}` "
         "(ou=certificates): chains the record follows by name (what clients are given to trust) could run through "
         "it. Remove the record certificate; the cross-certificate stays recorded under ou=cross-certificates.",
         owner_label(d, c), None)
        for x, c in held])


def check_cross_certificates(ctx):
    """The cross-certificates against the trust policies (nothing while the record holds none): CAs a policy's
    anchors reach only through them, those expired or expiring within certificate-expiry-margin-days of cutover (or
    today), and those also held as record certificates; actions, never blockers (trust is the anchors')."""
    d = ctx.d
    crosses = cross_certificates(d)
    if not crosses:
        return findings()
    horizon = (ctx.cutover or ctx.as_of) + dt.timedelta(days=setting_value(d, EXPIRY_MARGIN_DAYS))
    return merge_findings([_reach_actions(d, crosses), _expiry_actions(d, crosses, ctx.as_of, horizon),
                           _held_as_certificate(d, crosses)])


# ------------------------------------------------------------------ report
CROSS_HEADERS = ("anchor", "reaches", "through", "hops", "expires", "policy_mappings", "policies", "approved")


def cross_rows(d, dn=None):
    """The cross-certificate graph: per trust policy anchor, each CA it reaches through cross-certificates (the way,
    hops, the earliest expiry along it, the policy mappings carried, the policies accepting the anchor and whether the
    CA reached is itself one of their anchors); then each cross-certificate no anchor reaches through, as its own
    issuer -> subject."""
    crosses = cross_certificates(d)
    if not crosses:
        return []
    anchors = _anchors(d)

    def approved(r, ps):
        direct = {_subject(a) for p in ps for a in policy_anchors(d, p)}
        return "anchor" if norm_dn(r.ca) in direct else "cross-certificate only"
    reached = [(r, ps) for a, ps in anchors for r in reachable(d, a, (), crosses)]
    used = {x.norm for r, _ in reached for x in r.path}
    return [*((rdn_value(r.anchor), r.ca, _through(r.path), str(len(r.path)), str(_earliest(r.path) or ""),
               _mappings(r.path), ", ".join(rdn_value(p) for p in ps), approved(r, ps)) for r, ps in reached),
            *(("", one(x, "ciamSubject") or "", _through((x,)), "1", str(date_of(x, "ciamNotAfter") or ""),
               _mappings((x,)), "", "not reached from an anchor") for x in crosses if x.norm not in used)]
