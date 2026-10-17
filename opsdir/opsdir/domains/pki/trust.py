"""Partner trust: which outside PKIs the platform accepts certificates from. Pure.

A trust bundle (ou=trust-bundles) is a publisher's set of CA certificates (DISA's DoD and ECA PKCS#7 bundles) as last
imported, observed: its release, where it came from, how its integrity was established (bundle importers judge it:
verified, signed-unanchored, digests-only, failed) and its CA certificates as children. Being in a bundle never makes a
CA trusted. A trust policy (ou=trust-policies) is what the platform accepts certificates under for one purpose: its
anchors are record CA certificates (purpose ca, under ou=certificates) a person approved, the bundles it follows supply
the subordinate CAs that complete their chains and propose new roots, and it says which certificate policies and key
usages it requires, how an accepted certificate maps to an account, how revocation is checked and what happens when it
can't be, and which server roles accept certificates under it.

The planner (check_trust) watches the policies against the bundles they follow, matched by SHA-256 fingerprint: a root
a followed bundle holds that is neither an anchor nor declined is proposed for review (approve: the certificate
recorded and made an anchor; decline: its fingerprint recorded); an anchor no followed bundle holds any more is flagged
with its removal; a followed bundle whose integrity failed blocks, one not verified or not imported for too long is an
action; anchors expiring within the horizon, and policies that accept anything their anchors issue (no policy OIDs,
key usages or identity mapping for client authentication) or don't check revocation, are actions. Nothing is said
while the record holds no trust policy."""
import datetime as dt

from ...core.changeset import add_values, delete_values, new_entry
from ...core.directory import (children, date_of, fingerprint, follow_all, get, make_entry, merged_attrs, one,
                               rdn_of, rdn_value, values)
from ...core.findings import Fix, Option, findings, merge_findings, owner_label
from ...core.settings import setting_value
from .chain import self_issued
from .naming import CERTIFICATES, TRUST_BUNDLES, TRUST_POLICIES, trust_bundle_dn
from .settings import ANCHOR_HORIZON_DAYS, BUNDLE_MAX_AGE_DAYS

BUNDLE_CLASS, MEMBER_CLASS, POLICY_CLASS = "ciamTrustBundle", "ciamBundleCertificate", "ciamTrustPolicy"
BUNDLE_ATTRS = ("cn", "ciamInventoryAt", "ciamBundleVerification", "ciamTrustBundleRelease", "ciamBundleSource",
                "ciamBundleDigest", "ciamBundleSigner", "ciamSignerAnchor", "ciamInventoryProblem", "ciamProviderRef")
MEMBER_ATTRS = ("cn", "ciamFingerprint", "ciamNotAfter", "ciamSubject", "ciamIssuer", "ciamNotBefore",
                "ciamSerialNumber", "ciamCaType", "ciamCertificatePem", "ciamCertPolicyOid", "ciamBundleGroup")
VERIFIED, UNANCHORED, DIGESTS_ONLY, FAILED = "verified", "signed-unanchored", "digests-only", "failed"
CLIENT_AUTH = "client-auth"
AREA = "Trust"
# what a promoted anchor carries over from the bundle member it is approved from
ANCHOR_FACTS = ("ciamFingerprint", "ciamNotAfter", "ciamNotBefore", "ciamSubject", "ciamIssuer", "ciamSerialNumber",
                "ciamCertificatePem", "ciamCertPolicyOid")


# ------------------------------------------------------------------ entries (bundle importers)
def bundle_entry(d, name, at, verification, facts):
    """A trust bundle's entry as imported at `at` (GeneralizedTime) with its verification; facts {attribute of
    BUNDLE_ATTRS: a value, a tuple of values, or None}; what the record adds (owners) kept."""
    owned = {"cn": (name,), "ciamInventoryAt": (at,), "ciamBundleVerification": (verification,),
             **{k: v if isinstance(v, tuple) else (v,) for k, v in facts.items() if k in BUNDLE_ATTRS}}
    dn = trust_bundle_dn(name)
    return make_entry(dn, ("top", "ciamObject", BUNDLE_CLASS), merged_attrs(get(d, dn), owned, BUNDLE_ATTRS))


def member_entry(d, bundle, name, facts):
    """A CA certificate a bundle holds, named `name` under the bundle's entry; facts {attribute of MEMBER_ATTRS: a
    value, a tuple of values, or None}."""
    dn = f"cn={name},{bundle.dn}"
    owned = {"cn": (name,), **{k: v if isinstance(v, tuple) else (v,) for k, v in facts.items()
                               if k in MEMBER_ATTRS and k != "cn"}}
    return make_entry(dn, ("top", "ciamObject", MEMBER_CLASS), merged_attrs(get(d, dn), owned, MEMBER_ATTRS))


def bundle_group(bundle, members):
    """An Imported group: the bundle's subtree made exactly its entry and its members (CAs gone from the bundle leave
    the record; anchors approved from them are record certificates and stay)."""
    return bundle.dn, (bundle, *sorted(members, key=lambda e: e.norm))


# ------------------------------------------------------------------ reading the record
def trust_bundles(d):
    return children(d, TRUST_BUNDLES, BUNDLE_CLASS)


def trust_policies(d):
    return children(d, TRUST_POLICIES, POLICY_CLASS)


def bundle_members(d, bundle):
    return children(d, bundle.dn, MEMBER_CLASS)


def fp(e):
    """An entry's SHA-256 fingerprint as the record writes it ('' when it has none)."""
    return fingerprint(one(e, "ciamFingerprint") or "")


def is_root(member):
    """Whether a bundle's CA certificate is a root (the bundle says so, or it is self-issued)."""
    return one(member, "ciamCaType") == "root" or self_issued(member)


def policy_anchors(d, policy):
    return tuple(a for a in follow_all(d, policy, "ciamTrustAnchor") if a is not None)


def followed_bundles(d, policy):
    return tuple(b for b in follow_all(d, policy, "ciamTrustBundleRef") if b is not None)


# ------------------------------------------------------------------ fixes
def _anchor_name(d, member):
    """The record certificate name a promoted root takes: the member's own, made unique by its fingerprint when
    another certificate holds that name."""
    taken = get(d, f"cn={rdn_value(member)},{CERTIFICATES}")
    return (rdn_value(member) if taken is None or fp(taken) == fp(member)
            else f"{rdn_value(member)} {fp(member).replace(':', '')[:8]}")


def _approve_records(d, policy, member):
    """Change records making a bundle's root an anchor of a policy: the CA certificate recorded under ou=certificates
    (unless the record already holds one with its fingerprint) with the policy's owners, then named an anchor."""
    held = next((c for c in children(d, CERTIFICATES, "ciamCertificate") if fp(c) == fp(member)), None)
    dn = held.dn if held is not None else f"cn={_anchor_name(d, member)},{CERTIFICATES}"
    created = () if held is not None else (new_entry(dn, ("top", "ciamObject", "ciamCertificate"), {
        "cn": (rdn_of(dn),), "ciamCertPurpose": ("ca",),
        **{k: values(member, k) for k in ANCHOR_FACTS if values(member, k)},
        **({"ciamOwner": values(policy, "ciamOwner")} if values(policy, "ciamOwner") else {})}),)
    return (*created, add_values(policy, "ciamTrustAnchor", (dn,)))


def _review_fix(d, policy, bundle, member):
    """Approve a bundle's root as a policy's anchor, or decline it (its fingerprint recorded on the policy)."""
    name = rdn_value(member)
    return Fix(f"trust-anchor:{rdn_value(policy)}:{fp(member)}", AREA,
               f"Decide whether trust policy `{rdn_value(policy)}` accepts root `{name}` from bundle "
               f"`{rdn_value(bundle)}`", (),
               (f"Before approving, compare the root's SHA-256 fingerprint {fp(member)} with the one its publisher "
                "publishes (DoD and ECA roots: crl.disa.mil).",),
               (), (Option("approve", f"approve `{name}` as an anchor", _approve_records(d, policy, member),
                           ("Every consumer of the policy accepts certificates issued under it once re-rendered.",)),
                    Option("decline", f"decline `{name}`",
                           (add_values(policy, "ciamDeclinedAnchor", (fp(member),)),),
                           ("Certificates issued under it are refused; it isn't proposed again.",))))


def _remove_fix(policy, anchor):
    return Fix(f"trust-anchor-dropped:{rdn_value(policy)}:{fp(anchor)}", AREA,
               f"Stop trust policy `{rdn_value(policy)}` accepting `{rdn_value(anchor)}`",
               (delete_values(policy, "ciamTrustAnchor", (anchor.dn,)),),
               ("Re-render the policy's consumers so they stop trusting it.",),
               ("Certificates issued under it are refused once its consumers are re-rendered; keep it only if it "
                "comes from somewhere the policy's bundles don't cover.",))


# ------------------------------------------------------------------ checks
def _review(d, policy, bundles):
    """Roots the policy's followed bundles hold (failed ones aside) that are neither its anchors nor declined."""
    known = {fp(a) for a in policy_anchors(d, policy)} | {fingerprint(v) for v in values(policy, "ciamDeclinedAnchor")}
    new = [(b, m) for b in bundles if one(b, "ciamBundleVerification") != FAILED
           for m in bundle_members(d, b) if is_root(m) and fp(m) not in known]
    return findings(actions=[(AREA, f"Trust policy `{rdn_value(policy)}`: bundle `{rdn_value(b)}` "
                              f"{one(b, 'ciamTrustBundleRelease') or ''} holds root `{rdn_value(m)}` (expires "
                              f"{date_of(m, 'ciamNotAfter')}) that the policy neither accepts nor declined: review "
                              "it.", owner_label(d, policy), None) for b, m in new],
                    fixes=[_review_fix(d, policy, b, m) for b, m in new])


def _dropped(d, policy, bundles):
    """Anchors none of the policy's followed bundles holds (only when every followed bundle was read: failed ones
    can't say what they hold)."""
    if not bundles or any(one(b, "ciamBundleVerification") == FAILED for b in bundles):
        return findings()
    held = {fp(m) for b in bundles for m in bundle_members(d, b)}
    gone = [a for a in policy_anchors(d, policy) if fp(a) not in held]
    return findings(actions=[(AREA, f"Trust policy `{rdn_value(policy)}` accepts `{rdn_value(a)}`, which none of the "
                              f"bundles it follows ({', '.join(rdn_value(b) for b in bundles)}) holds: its publisher "
                              "dropped it, or it comes from elsewhere. Remove it, or record where it comes from.",
                              owner_label(d, policy), None) for a in gone],
                    fixes=[_remove_fix(policy, a) for a in gone])


def _integrity(d, bundle, policies, as_of, max_age):
    """A followed bundle whose integrity failed (blocker), one not verified or imported too long ago (actions)."""
    name, users = rdn_value(bundle), ", ".join(f"`{rdn_value(p)}`" for p in policies)
    state, owner = one(bundle, "ciamBundleVerification"), owner_label(d, policies[0])
    problems = "; ".join(values(bundle, "ciamInventoryProblem"))
    imported = date_of(bundle, "ciamInventoryAt")
    signer = one(bundle, "ciamSignerAnchor")
    blockers = [(AREA, f"Trust bundle `{name}` (followed by {users}) failed its integrity check"
                 f"{f': {problems}' if problems else ''}. Download it from its publisher again and import it before "
                 "approving anything from it.", owner)] if state == FAILED else []
    held = signer is not None and any(fp(c) == fingerprint(signer) for c in children(d, CERTIFICATES,
                                                                                     "ciamCertificate"))
    actions = [*([(AREA, f"Trust bundle `{name}` (followed by {users}) is signed, but its signer chains to a root the "
                   + ("record now holds: import the bundle again to have it verified." if held else
                      f"record doesn't hold (SHA-256 {signer}): confirm that fingerprint with the publisher and "
                      "approve the root as an anchor; the next import is then verified."), owner, None)]
                 if state == UNANCHORED else []),
               *([(AREA, f"Trust bundle `{name}` (followed by {users}) matches its manifest's digests, but the "
                   "manifest's signature wasn't checked: import it with its signature verified.", owner, None)]
                 if state == DIGESTS_ONLY else []),
               *([(AREA, f"Trust bundle `{name}` (followed by {users}) was last imported {imported}, more than "
                   f"{max_age} days ago: import its current release.", owner, None)]
                 if imported is not None and (as_of - imported).days > max_age else [])]
    return findings(blockers=blockers, actions=actions)


def _expiring(d, policies, as_of, horizon):
    """Anchors expiring within the horizon, each once with the policies accepting it."""
    by_anchor = {}
    for p in policies:
        for a in policy_anchors(d, p):
            by_anchor.setdefault(a.norm, (a, []))[1].append(p)
    due = [(a, ps) for a, ps in by_anchor.values()
           if date_of(a, "ciamNotAfter") is not None and date_of(a, "ciamNotAfter") <= as_of + horizon]
    return findings(actions=[(AREA, f"Anchor `{rdn_value(a)}` expires {date_of(a, 'ciamNotAfter')} "
                              f"({(date_of(a, 'ciamNotAfter') - as_of).days} days); trust policies "
                              f"{', '.join(f'`{rdn_value(p)}`' for p in ps)} accept it. Nothing that chains only to "
                              "it validates after that: approve its successor (proposed when a followed bundle holds "
                              "it) and re-render the policies' consumers well before.",
                              owner_label(d, a) if values(a, "ciamOwner") else owner_label(d, ps[0]),
                              date_of(a, "ciamNotAfter")) for a, ps in due])


def _listed(items):
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} or {items[-1]}"


def _policy_gaps(d, policy):
    """What a policy leaves open: no anchors; for client authentication no certificate policies, key usages or
    identity mapping; no revocation checking, failing open, or a cached answer of unbounded age."""
    name, purpose = rdn_value(policy), one(policy, "ciamTrustPurpose")
    open_for = [what for what, attr in (("certificate policies", "ciamAllowedPolicyOid"),
                                        ("extended key usages", "ciamRequiredEku"),
                                        ("an identity mapping", "ciamIdentityMapping"))
                if purpose == CLIENT_AUTH and not values(policy, attr)]
    mode, failure = one(policy, "ciamRevocationMode"), one(policy, "ciamRevocationFailure")
    gaps = [*(["it has no anchors, so its consumers accept nothing (approve anchors from the bundles it follows)"]
              if not values(policy, "ciamTrustAnchor") else []),
            *([f"it sets no {_listed(open_for)}: its consumers accept any certificate its anchors' CAs issue "
               "(software, email and device certificates included) for client authentication"] if open_for else []),
            *(["it doesn't check revocation"] if mode in (None, "none") else []),
            *(["it accepts certificates whose revocation can't be checked (fails open)"] if failure == "allow" else []),
            *(["it relies on cached revocation answers without saying how old (ciamRevocationCacheHours)"]
              if failure == "cached" and one(policy, "ciamRevocationCacheHours") is None else [])]
    return findings(actions=[(AREA, f"Trust policy `{name}` ({purpose}): {gap}.", owner_label(d, policy), None)
                             for gap in gaps])


def check_trust(ctx):
    """The trust policies against the bundles they follow (nothing while the record holds no trust policy): roots to
    review (approve or decline), anchors no followed bundle holds any more, followed bundles that failed their
    integrity check (blockers), weren't verified or are stale, anchors expiring within trust-anchor-horizon-days, and
    the gaps each policy leaves open."""
    d = ctx.d
    policies = trust_policies(d)
    if not policies:
        return findings()
    horizon = dt.timedelta(days=setting_value(d, ANCHOR_HORIZON_DAYS))
    max_age = setting_value(d, BUNDLE_MAX_AGE_DAYS)
    followers = {}
    for p in policies:
        for b in followed_bundles(d, p):
            followers.setdefault(b.norm, (b, []))[1].append(p)
    return merge_findings([*(f for p in policies for f in (_review(d, p, followed_bundles(d, p)),
                                                           _dropped(d, p, followed_bundles(d, p)),
                                                           _policy_gaps(d, p))),
                           *(_integrity(d, b, ps, ctx.as_of, max_age) for b, ps in followers.values()),
                           _expiring(d, policies, ctx.as_of, horizon)])


# ------------------------------------------------------------------ reports
BUNDLE_HEADERS = ("bundle", "version", "imported", "verification", "signer_root", "cas", "roots", "problems")
POLICY_HEADERS = ("policy", "purpose", "anchors", "bundles", "policy_oids", "ekus", "identity", "revocation",
                  "accepted_by", "owners")


def bundle_rows(d, dn=None):
    """One row per trust bundle: its release, when it was imported and how it was verified, the root its signer
    chains to, how many CA certificates it holds, its roots (with expiry) and what went wrong."""
    def row(b):
        members = bundle_members(d, b)
        return (rdn_value(b), one(b, "ciamTrustBundleRelease") or "", str(date_of(b, "ciamInventoryAt") or ""),
                one(b, "ciamBundleVerification") or "", one(b, "ciamSignerAnchor") or "", str(len(members)),
                ", ".join(f"{rdn_value(m)} ({date_of(m, 'ciamNotAfter')})" for m in members if is_root(m)),
                "; ".join(values(b, "ciamInventoryProblem")))
    return [row(b) for b in trust_bundles(d)]


def policy_rows(d, dn=None):
    """One row per trust policy: its purpose, anchors (with expiry), followed bundles, restrictions, identity mapping,
    revocation checking, the roles accepting it and its owners."""
    def row(p):
        failure, hours = one(p, "ciamRevocationFailure"), one(p, "ciamRevocationCacheHours")
        return (rdn_value(p), one(p, "ciamTrustPurpose") or "",
                ", ".join(f"{rdn_value(a)} ({date_of(a, 'ciamNotAfter')})" for a in policy_anchors(d, p)),
                ", ".join(rdn_value(b) for b in followed_bundles(d, p)),
                ", ".join(values(p, "ciamAllowedPolicyOid")), ", ".join(values(p, "ciamRequiredEku")),
                one(p, "ciamIdentityMapping") or "",
                " ".join(v for v in (one(p, "ciamRevocationMode"), failure and f"on failure {failure}",
                                     hours and f"({hours} h)") if v),
                ", ".join(values(p, "ciamAcceptedByRole")),
                ", ".join(rdn_value(get(d, o)) for o in values(p, "ciamOwner") if get(d, o) is not None))
    return [row(p) for p in trust_policies(d)]
