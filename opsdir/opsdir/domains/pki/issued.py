"""Certification authorities' issued-certificate inventories reconciled with the record's certificates: pure functions
of a snapshot.

A CA's inventory (ciamCertInventory under ou=issued-certificates, cn: the CA's name) is what its database said it
issued when its importer read it, metadata only: complete, incomplete or denied (inventory.py's states), with the
certificates found as its children (ciamIssuedCertificate, cn: the request id, or the serial number for a CA that
keeps none). The CA itself (ciamCertAuthority under ou=certificate-authorities, the same name) holds its revocation
endpoints and the templates it issues from; templates (ciamCertTemplate under ou=certificate-templates) say who renews
what they issue (ciamRenewalOwner). A template is either shared by every CA a directory serves (AD CS's forest
templates, replaced by the directory's list) or one CA's own (ciamTemplateAuthority: a Vault PKI role, named
<CA>/<role>, replaced by that CA's list alone).

A record certificate's CA is the one listing the certificate it was issued by (ciamIssuedBy) among its own
(ciamCaCertificate), else the one whose own certificate's subject is its issuer (ciamIssuer), else the one named as
its issuer's common name (an AD CS CA's certificate is named after the CA). It is found in an inventory by its SHA-256
fingerprint (in any CA's), else by serial number, else by subject and validity (in its CA's), and is in one state:

  present               found, current and not revoked
  revoked               found, revoked (its revocation in effect on the day evaluated)
  revocation-scheduled  found, its revocation dated after the day evaluated (a CA may date it ahead)
  superseded            found and current, but its CA issued the same subject a newer certificate from the same
                        template since (it was renewed; the record still names the old one)
  confirmed-missing     its CA's inventory is complete and doesn't hold it
  inventory-incomplete  the inventory may have missed it
  inaccessible          the CA refused the inventory
  not-inventoried       its CA has no inventory

A certificate no CA is found for (a public CA's, a self-signed one) isn't judged. Every active certificate (current,
not revoked) an inventory holds that no record certificate matches is untracked; the planner judges those of the
templates the record cares about (a template recording a renewal owner or a purpose, or one a record certificate was
issued from), the report lists them all. Observations are never written onto the record's certificates: the
reconciliation is computed here, each time.

A CA's product may say what state the CA is in (ciamCaState, a cloud private CA's importer; AD CS, Vault and EJBCA
say none) and which CA is above it (ciamParentAuthority). A certificate whose CA, or a CA above it, isn't active
(disabled, pending, expired, deleted, failed) can't be renewed there, and a deleted or expired CA's certificates stop
validating or passing revocation checks: the planner judges each one it finds, a CA that reports no state never.
"""
import re
from typing import NamedTuple

from ...core.directory import (children, date_of, fingerprint, follow, follow_all, get, make_entry, merged_attrs,
                               norm_dn, one, ou_entry, rdn_of, rdn_value, values)
from ...core.environment import applies_in, environment_of
from ...core.findings import findings, merge_findings, owner_label
from ...core.settings import setting_text
from .checks import certificate_users
from .inventory import INACCESSIBLE, INCOMPLETE, MISSING, NOT_INVENTORIED, PRESENT
from .naming import (AUTHORITIES, CERTIFICATES, ISSUED, TEMPLATES, authority_dn, issued_inventory_dn,
                     template_dn)

REVOKED, SCHEDULED, SUPERSEDED, UNTRACKED = "revoked", "revocation-scheduled", "superseded", "untracked"
AUTHORITY_CLASS, TEMPLATE_CLASS, ENDPOINT_CLASS = "ciamCertAuthority", "ciamCertTemplate", "ciamRevocationEndpoint"
CERT_INVENTORY_CLASS, ISSUED_CLASS = "ciamCertInventory", "ciamIssuedCertificate"
# what importers own of each entry (the rest, an authority's own certificates, owners, a template's purpose and
# renewal owner, is the operator's and kept)
AUTHORITY_ATTRS = ("cn", "ciamProviderRef", "ciamTemplateName")
# what a CA's product says of the CA itself, written only by an importer that reads them (a cloud private CA's)
AUTHORITY_FACTS = ("ciamCaType", "ciamCaState", "ciamCaKeyAlgorithm", "ciamCaKeyStorage", "ciamCaKeyRef",
                   "ciamParentAuthority", "ciamCaRestorableUntil")
# the states (ciamCaState) of a CA that issues nothing
INACTIVE_CA = ("disabled", "pending", "expired", "deleted", "failed")
# what a template lets requesters do and who may request from it (templates.py judges the risk)
TEMPLATE_RIGHTS = ("ciamSubjectFromRequest", "ciamApprovalRequired", "ciamRequiredSignatures", "ciamTemplateVersion",
                   "ciamEnrollee", "ciamEnrollmentScope")
TEMPLATE_ATTRS = ("cn", "description", "ciamTemplateOid", "ciamMaxValidityDays", "ciamExtendedKeyUsage",
                  *TEMPLATE_RIGHTS, "ciamTemplateAuthority")
ENDPOINT_ATTRS = ("cn", "ciamRevocationKind", "ciamEndpointUrl", "description")
CERT_INVENTORY_ATTRS = ("cn", "ciamInventoryAt", "ciamInventoryState", "ciamInventoryProblem", "ciamProviderRef")
ISSUED_ATTRS = ("cn", "ciamSerialNumber", "ciamFingerprint", "ciamSubject", "ciamNotBefore", "ciamNotAfter",
                "ciamTemplateName", "ciamRequester", "ciamRevokedAt", "ciamRevocationReason")
# RFC 5280 section 5.3.1 CRLReason (7 is unused)
REASONS = {0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
           5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn",
           10: "aACompromise"}
REVOCATION_CHECKS = ("crl", "ocsp")             # the endpoint kinds a relying party checks revocation with
TEMPLATE_KEPT = "the CA's template: "           # an endpoint's description when its URL still holds variables
AREA = "Certificate"

# A record certificate reconciled with the inventories: the CA it was found for (None: none), that CA's inventory
# (None: none), the certificate the inventory holds (None: not found), its state, and the newer certificate its CA
# issued its subject from the same template since (None: none), superseded or revoked.
Reconciled = NamedTuple("Reconciled", [("cert", object), ("authority", object), ("inventory", object),
                                       ("found", object), ("state", str), ("newer", object)])


# ------------------------------------------------------------------ what importers write
def _observed(d, dn, oc, owned, names):
    return make_entry(dn, ("top", "ciamObject", oc), merged_attrs(get(d, dn), owned, names))


def revocation_reason(code):
    """The RFC 5280 name of a CA's revocation reason code, else the value as it is (a CA's own, such as Microsoft's
    -1 for a certificate released from hold, is never taken for an RFC reason)."""
    return REASONS.get(code, str(code)) if isinstance(code, int) and not isinstance(code, bool) else str(code)


def authority_entry(d, name, provider_ref=None, templates=(), facts=None):
    """A certification authority's entry (what the record adds to it, its own certificates and owners, kept): how its
    product names it and the templates it issues from; facts {attribute of AUTHORITY_FACTS: value or None} what the
    product says of the CA itself (ciamParentAuthority: the parent CA's name; ciamCaRestorableUntil: when a deleted
    CA can no longer be restored, GeneralizedTime), owned only when given."""
    told = {k: v for k, v in (facts or {}).items() if k in AUTHORITY_FACTS}
    owned = {"cn": (name,), "ciamProviderRef": (provider_ref,), "ciamTemplateName": tuple(dict.fromkeys(templates)),
             **{k: (authority_dn(v) if k == "ciamParentAuthority" and v else v,) for k, v in told.items()}}
    return _observed(d, authority_dn(name), AUTHORITY_CLASS, owned,
                     (*AUTHORITY_ATTRS, *(AUTHORITY_FACTS if facts is not None else ())))


def endpoint_entry(d, authority, kind, n, url, template=None):
    """The n-th revocation endpoint of a kind of the CA named authority: its URL, and the CA's own template for it when
    the URL still holds variables nobody could fill (description)."""
    dn = f"cn={kind}-{n},{authority_dn(authority)}"
    owned = {"cn": (f"{kind}-{n}",), "ciamRevocationKind": (kind,), "ciamEndpointUrl": (url,),
             "description": (f"{TEMPLATE_KEPT}{template}" if template else None,)}
    return _observed(d, dn, ENDPOINT_CLASS, owned, ENDPOINT_ATTRS)


def template_entry(d, name, display=None, oid=None, max_days=None, usages=(), rights=None, authority=None):
    """A certificate template's entry (its purpose and renewal owner, the operator's, kept): display name, OID, the
    longest validity it issues in days, its extended key usages and rights {attribute of TEMPLATE_RIGHTS: value, or
    a tuple of values for ciamEnrollee; None: not read} (what it lets requesters do and who may request from it), and
    the name of the CA whose own template it is (a CA-scoped template; None: one a directory shares with every CA)."""
    told = {k: v for k, v in (rights or {}).items() if k in TEMPLATE_RIGHTS}
    owned = {"cn": (name,), "description": (display,), "ciamTemplateOid": (oid,),
             "ciamTemplateAuthority": (authority_dn(authority) if authority else None,),
             "ciamMaxValidityDays": (None if max_days is None else str(max_days),),
             "ciamExtendedKeyUsage": tuple(dict.fromkeys(usages)),
             **{k: tuple(dict.fromkeys(v)) if isinstance(v, tuple) else (None if v is None else setting_text(v),)
                for k, v in told.items()}}
    return _observed(d, template_dn(name), TEMPLATE_CLASS, owned, TEMPLATE_ATTRS)


def cert_inventory_entry(d, authority, at, state, problems=(), provider_ref=None):
    """The CA named authority's issued-certificate inventory: taken at `at` (GeneralizedTime), complete, incomplete
    or denied, with why, and how its product names the CA."""
    owned = {"cn": (authority,), "ciamInventoryAt": (at,), "ciamInventoryState": (state,),
             "ciamInventoryProblem": tuple(dict.fromkeys(problems)), "ciamProviderRef": (provider_ref,)}
    return _observed(d, issued_inventory_dn(authority), CERT_INVENTORY_CLASS, owned, CERT_INVENTORY_ATTRS)


def issued_entry(d, authority, request, facts):
    """A certificate the CA named authority's inventory found, by request id: facts {attribute of ISSUED_ATTRS: value
    or None} (None: the CA didn't say)."""
    dn = f"cn={request},{issued_inventory_dn(authority)}"
    owned = {"cn": (str(request),), **{k: (v,) for k, v in facts.items() if k in ISSUED_ATTRS and k != "cn"}}
    return _observed(d, dn, ISSUED_CLASS, owned, ISSUED_ATTRS)


def is_ca_scoped(template):
    """Whether a template is one CA's own (ciamTemplateAuthority), not one a directory shares with every CA."""
    return one(template, "ciamTemplateAuthority") is not None


def templates_group(d, templates):
    """An Imported group: ou=certificate-templates made exactly these directory-wide templates (the record's container
    and every CA's own templates kept; a template gone from the directory leaves the record)."""
    made = {e.norm: e for e in templates}
    kept = tuple(t for t in children(d, TEMPLATES, TEMPLATE_CLASS) if is_ca_scoped(t) and t.norm not in made)
    return TEMPLATES, (get(d, TEMPLATES) or ou_entry(TEMPLATES), *sorted((*made.values(), *kept),
                                                                       key=lambda e: e.norm))


def ca_templates_groups(d, authority, templates):
    """Imported groups making the CA named authority's own templates exactly these (each made as given; one the
    record holds as that CA's that it no longer has leaves the record), every other template kept."""
    made = {e.norm: e for e in templates}
    gone = tuple(t for t in children(d, TEMPLATES, TEMPLATE_CLASS) if t.norm not in made
                 and norm_dn(one(t, "ciamTemplateAuthority") or "") == norm_dn(authority_dn(authority)))
    return (*((e.dn, (e,)) for e in sorted(made.values(), key=lambda e: e.norm)), *((t.dn, ()) for t in gone))


# ------------------------------------------------------------------ reading the record
def authorities(d):
    """The certification authorities the record holds."""
    return children(d, AUTHORITIES, AUTHORITY_CLASS)


def endpoints(d, authority):
    """A CA's revocation endpoints."""
    return children(d, authority.dn, ENDPOINT_CLASS)


def cert_inventories(d):
    """{CA name, lowercase: its issued-certificate inventory} of every CA inventory the record holds."""
    return {rdn_value(e).lower(): e for e in children(d, ISSUED, CERT_INVENTORY_CLASS)}


def issued_of(d, inventory):
    """The certificates a CA's inventory found, by request id (numerically when it is a number)."""
    return tuple(sorted(children(d, inventory.dn, ISSUED_CLASS),
                        key=lambda e: (0, int(rdn_value(e)), "") if rdn_value(e).isdigit() else (1, 0, rdn_value(e))))


def common_name(subject):
    """The CN of a distinguished name as text (CN=Example CA, O=Example -> Example CA), or None."""
    m = re.search(r"(?:^|,)\s*cn\s*=\s*([^,]+)", subject or "", re.IGNORECASE)
    return m.group(1).strip() if m else None


def authority_of(d, cert, cas):
    """The CA (of cas) a record certificate was issued by, or None: the one listing its ciamIssuedBy certificate as
    its own, else the one whose own certificate's subject is its ciamIssuer, else the one its issuer's CN names. A CA's
    own certificate isn't one it issued: it gets None from its own CA."""
    issuer = follow(d, cert, "ciamIssuedBy")
    own = lambda a: tuple(c for c in follow_all(d, a, "ciamCaCertificate") if c is not None)      # noqa: E731
    named = norm_dn(one(cert, "ciamIssuer") or "")
    found = (next((a for a in cas if issuer is not None and issuer.norm in {c.norm for c in own(a)}), None)
             or next((a for a in cas if named and any(norm_dn(one(c, "ciamSubject") or "") == named for c in own(a))),
                     None)
             or next((a for a in cas if (common_name(one(cert, "ciamIssuer")) or "").lower()
                      == rdn_value(a).lower()), None))
    return None if found is not None and cert.norm in {c.norm for c in own(found)} else found


def serial_key(v):
    """A serial number as compared: hex digits only, lowercase, without leading zeros."""
    return re.sub(r"[^0-9a-f]", "", (v or "").lower()).lstrip("0")


def is_revoked(issued):
    """Whether a CA recorded an issued certificate as revoked (every revoked one carries a reason)."""
    return one(issued, "ciamRevocationReason") is not None


def is_active(issued, as_of):
    """Whether an issued certificate is current on as_of and not revoked."""
    expires = date_of(issued, "ciamNotAfter")
    return not is_revoked(issued) and (expires is None or expires >= as_of)


def find_issued(cert, rows, everywhere):
    """The issued certificate matching a record certificate: by fingerprint among everywhere (every inventory's),
    else by serial number, else by subject, start and end of validity among rows (its CA's), or None."""
    fp = fingerprint(one(cert, "ciamFingerprint"))
    serial = serial_key(one(cert, "ciamSerialNumber"))
    validity = (norm_dn(one(cert, "ciamSubject") or ""), date_of(cert, "ciamNotBefore"), date_of(cert, "ciamNotAfter"))
    return (next((r for r in everywhere if fp and fingerprint(one(r, "ciamFingerprint")) == fp), None)
            or next((r for r in rows if serial and serial_key(one(r, "ciamSerialNumber")) == serial), None)
            or next((r for r in rows if validity[0] and all(validity)
                     and (norm_dn(one(r, "ciamSubject") or ""), date_of(r, "ciamNotBefore"),
                          date_of(r, "ciamNotAfter")) == validity), None))


def newer_issue(found, rows, as_of):
    """The latest active certificate among rows (its CA's) issued after found to the same subject from the same
    template: what superseded it, or None."""
    subject, template = norm_dn(one(found, "ciamSubject") or ""), (one(found, "ciamTemplateName") or "").lower()
    later = [r for r in rows if r.norm != found.norm and subject and is_active(r, as_of)
             and norm_dn(one(r, "ciamSubject") or "") == subject
             and (one(r, "ciamTemplateName") or "").lower() == template
             and (one(r, "ciamNotBefore") or "") > (one(found, "ciamNotBefore") or "")]
    return max(later, key=lambda r: one(r, "ciamNotBefore")) if later else None


def _state(found, rows, inventory, as_of):
    if found is None:
        return (MISSING if one(inventory, "ciamInventoryState") == "complete" else INCOMPLETE), None
    newer = newer_issue(found, rows, as_of)
    if is_revoked(found):
        effective = date_of(found, "ciamRevokedAt")
        return (SCHEDULED if effective is not None and effective > as_of else REVOKED), newer
    return (SUPERSEDED, newer) if newer is not None else (PRESENT, None)


def inventory_name(issued):
    """The name of the CA whose inventory holds an issued certificate."""
    return rdn_of(issued.dn.split(",", 1)[1])


def reconcile(d, cert, cas, held, as_of):
    """A record certificate's Reconciled state against the CA inventories held ({CA name, lowercase: inventory}), or
    None when no CA is found for it."""
    everywhere = tuple(r for inv in held.values() for r in issued_of(d, inv))
    by_fingerprint = find_issued(cert, (), everywhere)
    ca = authority_of(d, cert, cas) if by_fingerprint is None else None
    name = inventory_name(by_fingerprint) if by_fingerprint is not None else rdn_value(ca) if ca is not None else None
    if name is None:
        return None
    authority = ca if ca is not None else get(d, authority_dn(name))
    inventory = held.get(name.lower())
    if inventory is None:
        return Reconciled(cert, authority, None, None, NOT_INVENTORIED, None)
    if one(inventory, "ciamInventoryState") == "denied":
        return Reconciled(cert, authority, inventory, None, INACCESSIBLE, None)
    rows = issued_of(d, inventory)
    found = by_fingerprint or find_issued(cert, rows, ())
    state, newer = _state(found, rows, inventory, as_of)
    return Reconciled(cert, authority, inventory, found, state, newer)


def reconciled(d, as_of):
    """Every record certificate a CA is found for, reconciled with the inventories the record holds."""
    cas, held = authorities(d), cert_inventories(d)
    return tuple(r for c in children(d, CERTIFICATES, "ciamCertificate") for r in (reconcile(d, c, cas, held, as_of),)
                 if r is not None)


def untracked(d, done, as_of):
    """((inventory, issued certificate), ...): every active certificate the inventories hold that no reconciled
    record certificate (done) was found as."""
    matched = {r.found.norm for r in done if r.found is not None}
    return tuple((inv, r) for inv in cert_inventories(d).values() for r in issued_of(d, inv)
                 if r.norm not in matched and is_active(r, as_of))


def template_of(d, issued):
    """The template entry an issued certificate was issued from, or None (not recorded, or unknown)."""
    name = one(issued, "ciamTemplateName")
    return get(d, template_dn(name)) if name and "," not in name and "=" not in name else None


def cared_templates(d, done):
    """The template names (lowercase) the record cares about: those recording a renewal owner or a purpose, and those
    a record certificate was issued from."""
    return {*(rdn_value(t).lower() for t in children(d, TEMPLATES, TEMPLATE_CLASS)
              if one(t, "ciamRenewalOwner") or one(t, "ciamCertPurpose")),
            *((one(r.found, "ciamTemplateName") or "").lower() for r in done if r.found is not None)} - {""}


def renewal_owner(d, cert, issued):
    """Who renews a certificate: a record certificate's owners, else its template's renewal owner; None when neither
    is recorded."""
    if cert is not None and values(cert, "ciamOwner"):
        return owner_label(d, cert)
    template = template_of(d, issued) if issued is not None else None
    owner = one(template, "ciamRenewalOwner") if template is not None else None
    return rdn_of(owner) if owner else None


def authority_chain(d, authority):
    """A CA, then the CAs above it as their products name them (ciamParentAuthority), nearest first, each once: a
    parent the record doesn't hold, or one seen already, ends it."""
    def walk(a, seen):
        parent = follow(d, a, "ciamParentAuthority")
        return (a, *(walk(parent, seen | {a.norm}) if parent is not None and parent.norm not in seen | {a.norm}
                     else ()))
    return walk(authority, frozenset())


def inactive_authority(d, authority):
    """The first CA of a CA's chain (itself, then those above it) whose product says it isn't active (INACTIVE_CA),
    or None: a CA whose product says nothing of its state (AD CS, Vault, EJBCA) is never one."""
    return next((a for a in authority_chain(d, authority) if one(a, "ciamCaState") in INACTIVE_CA),
                None) if authority is not None else None


def users_in(d, cert, m):
    """The entries using a certificate (certificate_users) that environment m relies on: bindings of m or of a base
    it inherits from, and shared entries that apply in m (applies_in)."""
    lineage = {e.norm for e in m.lineage}
    return tuple(u for u in certificate_users(d, cert)
                 if (norm_dn(environment_of(u)) in lineage if ",ou=bindings," in u.norm else applies_in(u, m)))


# ------------------------------------------------------------------ the planner's findings
def _used_by(d, cert):
    return tuple(dict.fromkeys(rdn_value(u) for u in certificate_users(d, cert)))


def _inventoried(r):
    return f"{rdn_value(r.inventory)}'s inventory of {date_of(r.inventory, 'ciamInventoryAt')}"


def _why(inventory):
    problems = values(inventory, "ciamInventoryProblem")
    return f" ({'; '.join(problems)})" if problems else ""


def issue_label(issued):
    """How a finding names a certificate an inventory holds: `request <id>` (a CA naming them by request id), else
    `serial <serial>` (one naming them by serial)."""
    return f"request {rdn_value(issued)}" if rdn_value(issued).isdigit() else f"serial {rdn_value(issued)}"


def _revoked_text(r):
    return (f"was revoked by {rdn_value(r.inventory)} ({issue_label(r.found)}: "
            f"{one(r.found, 'ciamRevocationReason')}, effective {date_of(r.found, 'ciamRevokedAt') or 'unrecorded'})")


def _replacement(r):
    return (f"its replacement ({issue_label(r.newer)}, valid until {date_of(r.newer, 'ciamNotAfter')})"
            if r.newer is not None else "its replacement")


def _from_template(issued):
    template = one(issued, "ciamTemplateName")
    return f" from `{template}`" if template else ""


def _state_finding(d, r):
    """(kind, finding) of a reconciled record certificate in a state that needs someone, or None."""
    cn, owner, used = f"`{rdn_value(r.cert)}`", owner_label(d, r.cert), _used_by(d, r.cert)
    uses = f"used by {', '.join(used)}" if used else "nothing recorded uses it"
    if r.state == REVOKED and used:
        return "blocker", (AREA, f"Certificate {cn} {_revoked_text(r)}, but the record still uses it ({uses}): "
                                 f"whatever checks its revocation refuses it. Deploy {_replacement(r)} and record it.",
                           owner)
    text = (f"Certificate {cn} {_revoked_text(r)}; {uses}. Record {_replacement(r)}, or remove it from the record."
            if r.state == REVOKED else
            f"Certificate {cn}'s revocation by {rdn_value(r.inventory)} takes effect "
            f"{date_of(r.found, 'ciamRevokedAt')} ({one(r.found, 'ciamRevocationReason')}); {uses}. Replace it with "
            f"{_replacement(r)} before then." if r.state == SCHEDULED else
            f"Certificate {cn} was superseded: {rdn_value(r.inventory)} issued its subject a newer certificate"
            f"{_from_template(r.newer)} ({issue_label(r.newer)}, valid until "
            f"{date_of(r.newer, 'ciamNotAfter')}) the record doesn't hold; {uses}. Record the new one and move its "
            "users to it." if r.state == SUPERSEDED else
            f"Certificate {cn} names {rdn_value(r.authority)} as its issuer, but {_inventoried(r)} is complete and "
            "holds no such certificate: correct its issuer or fingerprint." if r.state == MISSING else
            f"Certificate {cn} can't be found at its CA: {_inventoried(r)} is incomplete{_why(r.inventory)}. Export "
            "it again completely." if r.state == INCOMPLETE else
            f"Certificate {cn} can't be found at its CA: {rdn_value(r.inventory)} refused the inventory"
            f"{_why(r.inventory)}. Grant the exporter's account Read on the CA and export it again."
            if r.state == INACCESSIBLE else None)
    due = date_of(r.found, "ciamRevokedAt") if r.state == SCHEDULED else None
    return ("action", (AREA, text, owner, due)) if text else None


def _restorable(ca):
    return date_of(ca, "ciamCaRestorableUntil") if one(ca, "ciamCaState") == "deleted" else None


def _crls(d, ca):
    urls = tuple(one(e, "ciamEndpointUrl") for e in endpoints(d, ca) if one(e, "ciamRevocationKind") == "crl")
    return f" ({', '.join(urls)})" if urls else ""


def _inactive_said(d, ca, issuer):
    """How a finding says what a CA that isn't active (ca) means for what issuer, it or a CA below it, issued."""
    until = _restorable(ca)
    restore = f"restorable until {until}" if until else "until when it can be restored is unrecorded"
    what = {"disabled": "is disabled: it issues nothing",
            "pending": "isn't activated (pending: awaiting its certificate or its activation): it issues nothing",
            "expired": "has expired: it issues nothing, and what chains to it no longer validates",
            "deleted": f"was deleted ({restore}): it issues nothing and no longer publishes its CRL{_crls(d, ca)}, so "
                       "whatever checks revocation refuses what chains to it once its last CRL lapses",
            "failed": "failed (its creation failed): it never issued anything"}[one(ca, "ciamCaState")]
    return (f"{rdn_value(ca)}, which {what}" if issuer.norm == ca.norm else
            f"{rdn_value(issuer)}, below {rdn_value(ca)}, which {what}")


def _inactive_how(d, ca, these="it"):
    """What to do about certificates (these: it, or the ones in use) whose chain holds a CA that isn't active."""
    state, until = one(ca, "ciamCaState"), _restorable(ca)
    who = owner_label(d, ca) if values(ca, "ciamOwner") else "none recorded: record the CA's ciamOwner"
    fix = {"disabled": "re-enable the CA", "pending": "activate the CA",
           "deleted": f"restore the CA{f' before {until}' if until else ''}"}.get(state)
    record = "it" if these == "it" else "them"
    return ((f"Correct its issuer in the record, or reissue {these} from an active CA and record {record}"
             if state == "failed" else f"Reissue {these} from an active CA and record {record}")
            + (f", or have {rdn_value(ca)}'s owner ({who}) {fix}" if fix else "") + ".")


def _ca_state_finding(ctx, r):
    """(kind, finding) of a reconciled record certificate (not revoked, not expired) whose CA, or a CA above it,
    isn't active, or None: a blocker when the target relies on it, else an action due by the earlier of the CA's
    restorable-until and the certificate's expiry."""
    d, expires = ctx.d, date_of(r.cert, "ciamNotAfter")
    ca = inactive_authority(d, r.authority)
    if ca is None or r.state in (REVOKED, SCHEDULED) or (expires is not None and expires < ctx.as_of):
        return None
    said, owner = f"Certificate `{rdn_value(r.cert)}` comes from {_inactive_said(d, ca, r.authority)}", \
        renewal_owner(d, r.cert, r.found) or "**NO OWNER**"
    relied = tuple(dict.fromkeys(rdn_value(u) for u in users_in(d, r.cert, ctx.dst)))
    if relied:
        return "blocker", (AREA, f"{said}; {ctx.dst.label} relies on it ({', '.join(relied)}). {_inactive_how(d, ca)}",
                           owner)
    used = _used_by(d, r.cert)
    uses = f"used by {', '.join(used)}" if used else "nothing recorded uses it"
    return "action", (AREA, f"{said}; {uses}. {_inactive_how(d, ca)}", owner,
                      min((x for x in (_restorable(ca), expires) if x), default=None))


def _untracked_finding(d, authority, template, rows):
    owner = renewal_owner(d, None, rows[0])
    listed = ", ".join(f"{issue_label(r)} {one(r, 'ciamSubject') or '(no subject)'} (until "
                       f"{date_of(r, 'ciamNotAfter')})" for r in rows)
    who = (f"{owner} renews them." if owner else
           "Nobody is recorded to renew them: record the template's renewal owner (ciamRenewalOwner).")
    issuer = get(d, authority_dn(authority))
    ca = inactive_authority(d, issuer)
    stopped = (f" They come from {_inactive_said(d, ca, issuer)}. {_inactive_how(d, ca, 'the ones in use')}"
               if ca is not None else "")
    first = min((x for x in (date_of(r, "ciamNotAfter") for r in rows) if x), default=None)
    return (AREA, f"{authority} issued {len(rows)} active certificate(s) from template `{template}` the record holds "
                  f"none of: {listed}. Record the ones in use, or have them revoked. {who}{stopped}",
            owner or "**NO OWNER**",
            min((x for x in (_restorable(ca) if ca is not None else None, first) if x), default=None))


def _untracked_findings(d, done, as_of):
    cared = cared_templates(d, done)
    stray = tuple((inv, r) for inv, r in untracked(d, done, as_of) if (one(r, "ciamTemplateName") or "").lower()
                  in cared)
    key = lambda inv, r: (rdn_value(inv), one(r, "ciamTemplateName"))       # noqa: E731
    return tuple(_untracked_finding(d, ca, t, tuple(r for inv, r in stray if key(inv, r) == (ca, t)))
                 for ca, t in dict.fromkeys(key(inv, r) for inv, r in stray))


def _unchecked_authorities(d):
    held = cert_inventories(d)
    return tuple((AREA, f"Certification authority `{rdn_value(a)}` publishes no CRL distribution point or OCSP "
                        "responder in the certificates it issues: nothing can check their revocation. Publish one, "
                        "or record why not.", owner_label(d, a), None)
                 for a in authorities(d) if rdn_value(a).lower() in held
                 and not {one(e, "ciamRevocationKind") for e in endpoints(d, a)} & set(REVOCATION_CHECKS))


def check_issued_certificates(ctx):
    """The record's certificates against their CAs' issued-certificate inventories (nothing when the record holds
    none): a revoked certificate the record still uses is a blocker; one revoked but unused, revoked from a later
    date, superseded by a newer issue, confirmed missing, or not confirmable (inventory incomplete or refused) an
    action; so is each (CA, template the record cares about) whose active certificates the record holds none of,
    owned by the template's renewal owner and due when the first expires, and each inventoried CA that publishes no
    CRL or OCSP endpoint. A certificate (not revoked or expired) whose CA, or a CA above it, its product says isn't
    active is a blocker when the target relies on it, else an action owned by who renews it and due by the earlier of
    the CA's restorable-until and its expiry (an untracked set's action says so too). Present certificates are
    counted."""
    if not cert_inventories(ctx.d):
        return findings()
    done = reconciled(ctx.d, ctx.as_of)
    states = tuple(f for r in done for f in (_state_finding(ctx.d, r), _ca_state_finding(ctx, r)) if f)
    present = sum(1 for r in done if r.state == PRESENT)
    return merge_findings([findings(blockers=[f for k, f in states if k == "blocker"],
                                    actions=[f for k, f in states if k == "action"]),
                           findings(actions=[*_untracked_findings(ctx.d, done, ctx.as_of),
                                             *_unchecked_authorities(ctx.d)],
                                    ok=[f"{present} certificate(s) of the record found current at their CA."]
                                    if present else [])])


# ------------------------------------------------------------------ the reports
AUTHORITY_HEADERS = ("authority", "config", "state", "key", "issued by", "certificates", "templates", "endpoints",
                     "inventoried", "owner")
ISSUED_HEADERS = ("certificate", "authority", "request", "serial", "template", "requester", "not after", "state",
                  "renewal owner", "detail")


def _issuer_of(d, ca_cert, cas):
    if norm_dn(one(ca_cert, "ciamIssuer") or "") == norm_dn(one(ca_cert, "ciamSubject") or "-"):
        return "self-signed"
    parent = authority_of(d, ca_cert, cas)
    issuer = follow(d, ca_cert, "ciamIssuedBy")
    return (rdn_value(parent) if parent is not None else rdn_value(issuer) if issuer is not None
            else one(ca_cert, "ciamIssuer") or "")


def authority_rows(d, dn=None):
    """One row per certification authority: how its product names it, what its product says of it (root or
    subordinate and its state, a deleted one's restorable-until; its signing key's algorithm, storage and key
    reference), who issued its own certificates (the CA above it, or self-signed; else the CA its product names above
    it), those certificates, the templates it issues from, its revocation endpoints, its inventory (when, and whether
    complete) and its owners."""
    cas, held = authorities(d), cert_inventories(d)
    def row(a):
        own = tuple(c for c in follow_all(d, a, "ciamCaCertificate") if c is not None)
        inv = held.get(rdn_value(a).lower())
        parent = one(a, "ciamParentAuthority")
        return (rdn_value(a), one(a, "ciamProviderRef") or "",
                " ".join(v for v in (one(a, "ciamCaType"), one(a, "ciamCaState"),
                                     f"(restorable until {_restorable(a)})" if _restorable(a) else None) if v),
                ", ".join(v for v in (one(a, "ciamCaKeyAlgorithm"), one(a, "ciamCaKeyStorage"), one(a, "ciamCaKeyRef"))
                          if v),
                ", ".join(dict.fromkeys(_issuer_of(d, c, cas) for c in own)) or (rdn_of(parent) if parent else ""),
                ", ".join(rdn_value(c) for c in own),
                ", ".join(values(a, "ciamTemplateName")),
                "; ".join(f"{one(e, 'ciamRevocationKind')} {one(e, 'ciamEndpointUrl')}" for e in endpoints(d, a)),
                f"{date_of(inv, 'ciamInventoryAt')} {one(inv, 'ciamInventoryState')}" if inv is not None else "",
                ", ".join(rdn_of(o) for o in values(a, "ciamOwner")))
    return [row(a) for a in cas]


def _detail(r):
    problems = "; ".join(values(r.inventory, "ciamInventoryProblem")) if r.inventory is not None else ""
    found = r.found
    return "; ".join(x for x in (
        f"{one(found, 'ciamRevocationReason')}, effective {date_of(found, 'ciamRevokedAt') or 'unrecorded'}"
        if found is not None and is_revoked(found) else "",
        f"renewed as {issue_label(r.newer)} (until {date_of(r.newer, 'ciamNotAfter')})" if r.newer else "",
        problems) if x)


def _issued_row(d, cert, ca, found, state, detail):
    said = (lambda a: one(found, a, "")) if found is not None else (lambda a: "")      # noqa: E731
    return (rdn_value(cert) if cert is not None else "", ca, rdn_value(found) if found is not None else "",
            said("ciamSerialNumber"), said("ciamTemplateName"), said("ciamRequester"),
            str(date_of(found if found is not None else cert, "ciamNotAfter") or ""), state,
            renewal_owner(d, cert, found) or "", detail)


def issued_rows(d, dn, as_of):
    """One row per record certificate a CA is found for (its state, the certificate found, its renewal owner and
    what is wrong), then one per untracked active certificate the inventories hold, of every template."""
    done = reconciled(d, as_of)
    return [*(_issued_row(d, r.cert, rdn_value(r.authority) if r.authority is not None else "", r.found, r.state,
                          _detail(r)) for r in done),
            *(_issued_row(d, None, rdn_value(inv), r, UNTRACKED, "") for inv, r in untracked(d, done, as_of))]
