"""Certificate managers' inventories reconciled with the record's certificates: pure functions of a snapshot.

A manager's inventory (ciamManagedInventory under ou=managed-certificates, cn: the collection source's name) is what a
certificate manager said it holds when its importer read it, metadata only: complete, incomplete or denied for the
folders it lists (ciamInventoryPrefix), with the certificates found as its children (ciamManagedCertificate, cn: the
manager's id for each). A manager holds what it discovered on the networks it scans, was given, or enrolls itself: it
is never a CA's issuance record, so a certificate it doesn't hold isn't missing anywhere, even when its inventory is
complete (that says only that its folders were listed in full). The core names no manager: each adapter reads its own
(a Venafi policy folder, a key vault's certificates) into these two classes.

A record certificate is found in each inventory by its SHA-256 fingerprint, else by the SHA-1 thumbprint of the PEM
the record holds of it (for managers giving no SHA-256), else by serial number with its issuer (its subject when either
side records no issuer), else by subject and validity. Each inventory is judged on its own (two managers often hold
the same certificate: one provisions it into the other), and the certificate is in one state at each manager holding it
or what it was renewed as (not-managed only when none does):

  managed      found, and the manager reports nothing wrong with it
  renewed      the manager holds a newer certificate for it that no record certificate is: it was renewed, and the
               record still names the old one (found or not). Exact when the manager links its versions (the earlier
               one found names the certificate that replaced it: ciamRenewedAs), else inferred: a newer certificate
               for the same subject (and issuer)
  revoked      found, and the manager says it was revoked
  disabled     found, but its management is disabled: the manager no longer renews or watches it
  in-error     found, and the manager reports something wrong with it now (a failed renewal or installation)
  not-managed  not found: nothing the manager holds says anything about it

Every certificate in service (current, not revoked, management not disabled, not an earlier version) the
inventories hold that no record certificate was found or renewed as is unrecorded; the planner judges those naming a
host name the record holds (a record certificate's alternative name, a service name), the report lists them all.
Observations are never written onto the record's certificates: the reconciliation is computed here, each time.
"""
from typing import NamedTuple

from ...core.directory import (children, date_of, fingerprint, get, make_entry, merged_attrs, norm_dn, one, rdn_value,
                               sorted_by_dn, values)
from ...core.environment import environment_of
from ...core.findings import findings, merge_findings, owner_label, responsible
from .checks import certificate_users
from .issued import REVOKED, SCHEDULED, SUPERSEDED, is_active, is_revoked, reconciled, serial_key
from .naming import CERTIFICATES, MANAGED, managed_inventory_dn
from .pem import certificate_pem, pem_thumbprint

MANAGED_STATE, RENEWED, DISABLED, IN_ERROR, NOT_MANAGED, UNRECORDED = (
    "managed", "renewed", "disabled", "in-error", "not-managed", "unrecorded")
INVENTORY_CLASS, CERT_CLASS = "ciamManagedInventory", "ciamManagedCertificate"
INVENTORY_ATTRS = ("cn", "ciamInventoryAt", "ciamInventoryState", "ciamInventoryProblem", "ciamInventoryPrefix",
                   "ciamProviderRef")
MANAGED_ATTRS = ("cn", "ciamSerialNumber", "ciamFingerprint", "ciamThumbprint", "ciamSubject", "ciamIssuer",
                 "ciamNotBefore", "ciamNotAfter", "ciamCertificateName", "ciamManagerPath", "ciamManagement",
                 "ciamManagedOrigin", "ciamManagerContact", "ciamInstalledAt", "ciamManagerProblem",
                 "ciamManagedAuthority", "ciamRevokedAt", "ciamRevocationReason", "ciamObjectState",
                 "ciamManagerAction", "ciamRenewedAs")
LISTED = ("ciamCertificateName", "ciamManagerContact", "ciamInstalledAt", "ciamManagerProblem",       # multi-valued
          "ciamManagerAction")
SELF_SIGNED = "self-signed"          # how the record writes the issuer of a self-signed certificate
AREA = "Certificate"

# A record certificate reconciled with the managers' inventories: the inventory holding what was found or renewed
# (None: neither), the managed certificate found (None: not found), its state, and the newer managed certificate the
# manager renewed it as (None: none).
ManagedReconciled = NamedTuple("ManagedReconciled", [("cert", object), ("inventory", object), ("found", object),
                                                     ("state", str), ("newer", object)])


# ------------------------------------------------------------------ what importers write
def managed_inventory_entry(d, name, at, state, problems=(), prefixes=(), provider_ref=None):
    """The inventory of the certificate manager source named name: taken at `at` (GeneralizedTime), complete,
    incomplete or denied, with why, the folders it lists and the manager's address (what the operator adds kept)."""
    dn = managed_inventory_dn(name)
    owned = {"cn": (name,), "ciamInventoryAt": (at,), "ciamInventoryState": (state,),
             "ciamInventoryProblem": tuple(dict.fromkeys(problems)),
             "ciamInventoryPrefix": tuple(dict.fromkeys(prefixes)), "ciamProviderRef": (provider_ref,)}
    return make_entry(dn, ("top", "ciamObject", INVENTORY_CLASS), merged_attrs(get(d, dn), owned, INVENTORY_ATTRS))


def managed_entry(d, inventory, key, facts):
    """A certificate the inventory named inventory holds, by the manager's id for it: facts {attribute of
    MANAGED_ATTRS: value, a tuple for those of LISTED, or None (the manager didn't say)}."""
    dn = f"cn={key},{managed_inventory_dn(inventory)}"
    owned = {"cn": (str(key),), **{k: tuple(dict.fromkeys(v or ())) if k in LISTED else (v,)
                                   for k, v in facts.items() if k in MANAGED_ATTRS and k != "cn"}}
    return make_entry(dn, ("top", "ciamObject", CERT_CLASS), merged_attrs(get(d, dn), owned, MANAGED_ATTRS))


# ------------------------------------------------------------------ reading the record
def managed_inventories(d):
    """The certificate manager inventories the record holds."""
    return children(d, MANAGED, INVENTORY_CLASS)


def managed_of(d, inventory):
    """The certificates a manager's inventory holds, by the manager's id."""
    return children(d, inventory.dn, CERT_CLASS)


def in_service(managed, as_of):
    """Whether a managed certificate is in service on as_of: current, not revoked, its management not disabled, and
    not an earlier version the manager says was replaced (ciamRenewedAs)."""
    return (is_active(managed, as_of) and one(managed, "ciamObjectState") != "disabled"
            and not one(managed, "ciamRenewedAs"))


def covers(pattern, name):
    """Whether a name a certificate names covers a host name: the same name, or a wildcard (*.zone) for one label
    directly under the zone; case-insensitive."""
    p, n = (pattern or "").lower().rstrip("."), (name or "").lower().rstrip(".")
    label, _, zone = n.partition(".")
    return bool(p and n) and (p == n or (p.startswith("*.") and bool(label) and zone == p[2:]))


def _subject(e):
    return norm_dn(one(e, "ciamSubject") or "")


def _issuer(e):
    issuer = one(e, "ciamIssuer") or ""
    return _subject(e) if issuer.lower() == SELF_SIGNED else norm_dn(issuer)


def _serial_match(cert, r):
    serial = serial_key(one(cert, "ciamSerialNumber"))
    if not serial or serial_key(one(r, "ciamSerialNumber")) != serial:
        return False
    if _issuer(cert) and _issuer(r):
        return _issuer(cert) == _issuer(r)
    return bool(_subject(cert)) and _subject(cert) == _subject(r)


def find_managed(cert, rows):
    """The managed certificate among rows matching a record certificate: by SHA-256 fingerprint, else by the SHA-1
    thumbprint of the record's PEM, else by serial number with its issuer (its subject when either records no issuer),
    else by subject, start and end of validity; None when none matches."""
    fp = fingerprint(one(cert, "ciamFingerprint"))
    pem = certificate_pem(cert)
    sha1 = pem_thumbprint(pem) if pem else ""
    validity = (_subject(cert), date_of(cert, "ciamNotBefore"), date_of(cert, "ciamNotAfter"))
    return (next((r for r in rows if fp and fingerprint(one(r, "ciamFingerprint")) == fp), None)
            or next((r for r in rows if sha1 and fingerprint(one(r, "ciamThumbprint")) == sha1), None)
            or next((r for r in rows if _serial_match(cert, r)), None)
            or next((r for r in rows if all(validity)
                     and (_subject(r), date_of(r, "ciamNotBefore"), date_of(r, "ciamNotAfter")) == validity), None))


def same_subject(cert, managed):
    """Whether a managed certificate is for what a record certificate is for: the same subject when both record one,
    else every alternative name the record certificate has among the names it names; and the same issuer when both
    record one."""
    issuers = (_issuer(cert), _issuer(managed))
    names = {n.lower() for n in values(cert, "ciamSubjectAltName")}
    held = {n.lower() for n in values(managed, "ciamCertificateName")}
    same = (_subject(cert) == _subject(managed) if _subject(cert) and _subject(managed)
            else bool(names) and names <= held)
    return same and (not all(issuers) or issuers[0] == issuers[1])


def _issued_after(r, ref):
    starts = (one(r, "ciamNotBefore"), one(ref, "ciamNotBefore"))
    return starts[0] > starts[1] if all(starts) else (one(r, "ciamNotAfter") or "") > (one(ref, "ciamNotAfter") or "")


def renewed_as(found, rows):
    """The managed certificate among rows that an earlier version found names as what replaced it (ciamRenewedAs:
    its cn in the same inventory), or None (found names none, or it isn't among rows)."""
    key = one(found, "ciamRenewedAs") if found is not None else None
    dn = norm_dn(f"cn={key},{found.dn.split(',', 1)[1]}") if key else None
    return next((r for r in rows if r.norm == dn), None) if dn else None


def renewal_of(cert, found, rows, as_of):
    """What the manager renewed a record certificate as, among rows (those no record certificate matches), or None:
    when the one found for it is an earlier version the manager links, the certificate it names (if in service);
    else the latest in service for the same subject, issued after it (after the one found for it, when found)."""
    if found is not None and one(found, "ciamRenewedAs"):
        newer = renewed_as(found, rows)
        return newer if newer is not None and in_service(newer, as_of) else None
    ref = found if found is not None else cert
    later = [r for r in rows if (found is None or r.norm != found.norm) and in_service(r, as_of)
             and same_subject(cert, r) and _issued_after(r, ref)]
    return max(later, key=lambda r: (one(r, "ciamNotBefore") or "", one(r, "ciamNotAfter") or "")) if later else None


def _state(found, newer):
    if found is not None and is_revoked(found):
        return REVOKED
    if newer is not None:
        return RENEWED
    if found is None:
        return NOT_MANAGED
    if one(found, "ciamObjectState") == "disabled":
        return DISABLED
    return IN_ERROR if values(found, "ciamManagerProblem") else MANAGED_STATE


def _reconciled_in(d, inventory, certs, as_of):
    """{record certificate's DN: its reconciliation with one inventory}, for those the inventory holds or renewed."""
    rows = managed_of(d, inventory)
    found = tuple((c, find_managed(c, rows)) for c in certs)
    matched = {f.norm for _, f in found if f is not None}
    free = tuple(r for r in rows if r.norm not in matched)
    return {c.norm: ManagedReconciled(c, inventory, f, _state(f, n), n)
            for c, f in found for n in (renewal_of(c, f, free, as_of),) if f is not None or n is not None}


def reconcile_managed(d, as_of):
    """Every record certificate reconciled with the certificate managers' inventories (empty when the record holds
    none), once per inventory holding it or holding what it was renewed as (each manager judged on its own: what one
    says never hides what another says), else once as not-managed; never missing."""
    held = managed_inventories(d)
    if not held:
        return ()
    certs = children(d, CERTIFICATES, "ciamCertificate")
    per = tuple(_reconciled_in(d, inv, certs, as_of) for inv in held)
    return tuple(r for c in certs for rs in (tuple(p[c.norm] for p in per if c.norm in p),)
                 for r in (rs or (ManagedReconciled(c, None, None, NOT_MANAGED, None),)))


def unrecorded(d, done, as_of):
    """((inventory, managed certificate), ...): every managed certificate in service that no reconciled record
    certificate (done) was found or renewed as."""
    claimed = {e.norm for r in done for e in (r.found, r.newer) if e is not None}
    return tuple((inv, r) for inv in managed_inventories(d) for r in managed_of(d, inv)
                 if r.norm not in claimed and in_service(r, as_of))


def record_names(d):
    """{host name, lowercase: the record entry naming it}: every record certificate's alternative names, then every
    name a service is reached at (ciamFqdn); the first entry naming one kept."""
    pairs = (*((n.lower(), c) for c in children(d, CERTIFICATES, "ciamCertificate")
               for n in values(c, "ciamSubjectAltName")),
             *((one(e, "ciamFqdn").lower(), e) for e in sorted_by_dn(d.entries.values()) if one(e, "ciamFqdn")))
    return {n: e for n, e in reversed(pairs)}


# ------------------------------------------------------------------ the planner's findings
def _label(r):
    return f"`{one(r, 'ciamManagerPath') or rdn_value(r)}`"


def _uses(d, cert):
    used = tuple(dict.fromkeys(rdn_value(u) for u in certificate_users(d, cert)))
    return used, (f"used by {', '.join(used)}" if used else "nothing recorded uses it")


def _state_finding(d, r, ca_state):
    """(kind, finding) of a reconciled record certificate in a state that needs someone, or None; what issued.py
    already says of it (revoked or superseded at its CA: ca_state) isn't said again."""
    cn, owner, manager = f"`{rdn_value(r.cert)}`", owner_label(d, r.cert), rdn_value(r.inventory) if r.inventory else ""
    used, uses = _uses(d, r.cert)
    expires = date_of(r.cert, "ciamNotAfter")
    if r.state == REVOKED and ca_state not in (REVOKED, SCHEDULED):
        said = (f"Certificate {cn} was revoked, as {manager} reports ({_label(r.found)}: "
                f"{one(r.found, 'ciamRevocationReason')}, {date_of(r.found, 'ciamRevokedAt') or 'date unrecorded'})")
        return (("blocker", (AREA, f"{said}, but the record still uses it ({uses}): whatever checks its revocation "
                                   "refuses it. Deploy its replacement and record it.", owner)) if used else
                ("action", (AREA, f"{said}; {uses}. Record its replacement, or remove it from the record.", owner,
                            None)))
    text = (f"Certificate {cn} was renewed by {manager}: it holds a newer certificate for the same subject "
            f"({_label(r.newer)}, valid until {date_of(r.newer, 'ciamNotAfter')}) the record doesn't; {uses}. Record "
            "the new one and move its users to it." if r.state == RENEWED and ca_state != SUPERSEDED else
            f"Certificate {cn}: {manager} reports a problem with it ({_label(r.found)}): "
            f"{'; '.join(values(r.found, 'ciamManagerProblem'))}. Have it fixed in {manager}, or renew it another way "
            f"before it expires ({expires})." if r.state == IN_ERROR else
            f"Certificate {cn}'s management is disabled in {manager} ({_label(r.found)}), but the record uses it "
            f"({uses}): nothing renews or watches it there. Re-enable it, or record who renews it." if
            r.state == DISABLED and used else None)
    return ("action", (AREA, text, owner, expires)) if text else None


def _owner(d, e):
    """Who owns a record entry naming a host name: its owners, else (a binding: a service name) its environment's."""
    return responsible(d, e, *((get(d, environment_of(e)),) if ",ou=bindings," in e.norm else ()))


def _named(names, managed):
    """((record host name, entry naming it), ...) of the record's names a managed certificate's names cover."""
    return tuple((n, e) for n, e in names.items() if any(covers(p, n) for p in values(managed, "ciamCertificateName")))


def _unrecorded_findings(d, done, as_of):
    names = record_names(d)
    judged = tuple((inv, r, named) for inv, r in unrecorded(d, done, as_of) for named in (_named(names, r),) if named)
    key = lambda inv, named: (rdn_value(inv), _owner(d, named[0][1]))       # noqa: E731
    def finding(manager, owner):
        rows = tuple((r, named) for inv, r, named in judged if key(inv, named) == (manager, owner))
        listed = ", ".join(f"{_label(r)} for {', '.join(sorted(n for n, _ in named))} (until "
                           f"{date_of(r, 'ciamNotAfter')})" for r, named in rows)
        return (AREA, f"{manager} holds {len(rows)} certificate(s) in service for names the record holds, of which "
                      f"the record has none: {listed}. Record the ones in use (ou=certificates), or have them "
                      "removed.", owner,
                min((x for x in (date_of(r, "ciamNotAfter") for r, _ in rows) if x), default=None))
    return tuple(finding(m, o) for m, o in dict.fromkeys(key(inv, named) for inv, _, named in judged))


def _why(inventory):
    problems = values(inventory, "ciamInventoryProblem")
    return f" ({'; '.join(problems)})" if problems else ""


def _inventory_findings(d):
    def finding(inv):
        state, name, at = one(inv, "ciamInventoryState"), rdn_value(inv), date_of(inv, "ciamInventoryAt")
        text = (f"Certificate manager inventory `{name}` was refused{_why(inv)}: nothing it manages could be compared "
                "with the record. Grant what the problem names and collect it again." if state == "denied" else
                f"Certificate manager inventory `{name}` of {at} is incomplete{_why(inv)}: renewals and certificates "
                "the record lacks may be missing from the comparison. Collect it again completely.")
        return AREA, text, responsible(d, inv), None
    return tuple(finding(inv) for inv in managed_inventories(d) if one(inv, "ciamInventoryState") != "complete")


def check_managed_certificates(ctx):
    """The record's certificates against the certificate managers' inventories (nothing when the record holds none):
    a certificate the manager says was revoked that the record still uses is a blocker; one revoked but unused,
    renewed by the manager (the record names the old one), in error at the manager, or disabled there while the record
    uses it an action, owned by its owners and due when it expires; so is each manager's set of certificates in
    service for host names the record holds that the record has none of (owned by whoever owns the name), and each
    inventory incomplete or refused. What a CA's inventory already says (revoked, superseded) isn't said again, and a
    certificate a manager doesn't hold is never a finding. Managed certificates are counted."""
    d = ctx.d
    if not managed_inventories(d):
        return findings()
    done = reconcile_managed(d, ctx.as_of)
    at_ca = {r.cert.norm: r.state for r in reconciled(d, ctx.as_of)}
    states = tuple(f for r in done for f in (_state_finding(d, r, at_ca.get(r.cert.norm)),) if f)
    managed = len({r.cert.norm for r in done if r.state == MANAGED_STATE})
    return merge_findings([findings(blockers=[f for k, f in states if k == "blocker"],
                                    actions=[f for k, f in states if k == "action"]),
                           findings(actions=[*_unrecorded_findings(d, done, ctx.as_of), *_inventory_findings(d)],
                                    ok=[f"{managed} certificate(s) of the record managed by a certificate manager "
                                        "with nothing wrong reported."] if managed else [])])


# ------------------------------------------------------------------ the report
MANAGED_HEADERS = ("certificate", "manager", "managed as", "management", "contacts", "installed at", "not after",
                   "state", "renewal owner", "detail")


def _detail(r):
    found = r.found
    return "; ".join(x for x in (
        f"revoked {date_of(found, 'ciamRevokedAt') or ''}".strip() if found is not None and is_revoked(found) else "",
        f"renewed as {_label(r.newer)} (until {date_of(r.newer, 'ciamNotAfter')})" if r.newer is not None else "",
        "management disabled" if found is not None and one(found, "ciamObjectState") == "disabled" else "",
        *(values(found, "ciamManagerProblem") if found is not None else ())) if x)


def _managed_row(d, cert, inventory, shown, state, owner, detail):
    said = (lambda a: ", ".join(values(shown, a))) if shown is not None else (lambda a: "")      # noqa: E731
    return (rdn_value(cert) if cert is not None else "", rdn_value(inventory) if inventory is not None else "",
            (one(shown, "ciamManagerPath") or rdn_value(shown)) if shown is not None else "", said("ciamManagement"),
            said("ciamManagerContact"), said("ciamInstalledAt"),
            str(date_of(cert if cert is not None else shown, "ciamNotAfter") or ""), state, owner, detail)


def managed_rows(d, dn, as_of):
    """One row per record certificate and manager holding it, or one when none does (its state; the managed certificate
    found, else (none found, or an earlier version found) the one it was renewed as; how it is managed, who is
    notified, where it is installed, its renewal owner and what is wrong), then one per unrecorded certificate in
    service the inventories hold, with the names it names (those the record holds said)."""
    done = reconcile_managed(d, as_of)
    names = record_names(d)
    owner = lambda c: owner_label(d, c) if values(c, "ciamOwner") else ""       # noqa: E731
    def stray(inv, r):
        named = _named(names, r)
        held = f"; the record's {', '.join(sorted(n for n, _ in named))}" if named else ""
        return _managed_row(d, None, inv, r, UNRECORDED, _owner(d, named[0][1]) if named else "",
                            ", ".join(values(r, "ciamCertificateName")) + held)
    shown = lambda r: (r.newer if r.newer is not None and (r.found is None or one(r.found, "ciamRenewedAs"))   # noqa: E731
                       else r.found)
    return [*(_managed_row(d, r.cert, r.inventory, shown(r), r.state, owner(r.cert), _detail(r)) for r in done),
            *(stray(inv, r) for inv, r in unrecorded(d, done, as_of))]
