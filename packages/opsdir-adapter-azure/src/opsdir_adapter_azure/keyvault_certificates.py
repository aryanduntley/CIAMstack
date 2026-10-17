"""Azure Key Vault certificates as a certificate manager's inventory (the importer `azure/keyvault-certificates`): the
certificates a vault holds, every version of each, read into the core pki domain as a certificate manager's inventory
(domains.pki.managed), metadata only: never a key, never the secret behind a certificate, and never a CA's issuance
record (a certificate the vault doesn't hold isn't missing anywhere). Pure.

The export holds, per collection source (one vault), Key Vault's REST answers as `opsdir collect` saves them
(keyvault_collect.py), each reduced to what is read here:
  keyvault/<source>/certificates-<n>.json               GET /certificates?includePending=true pages (value, nextLink),
                                                        with the vault's address they were read from (Vault); an error
                                                        instead of value when the listing was refused
  keyvault/<source>/versions/<name>-<n>.json            GET /certificates/{name}/versions pages
  keyvault/<source>/certificates/<name>/<version>.json  GET /certificates/{name}/{version}: id, x5t, cer, attributes
  keyvault/<source>/policies/<name>.json                GET /certificates/{name}/policy
  keyvault/<source>/pending/<name>.json                 GET /certificates/{name}/pending, when one is pending
  keyvault/<source>/contacts.json                       GET /certificates/contacts, when the vault has contacts
  keyvault/<source>/issuers.json                        GET /certificates/issuers
A source is one inventory (cn: its name; ciamInventoryPrefix the vault's name, ciamProviderRef its address). Each
version of each certificate is one managed certificate (cn: <certificate name>/<version>; ciamManagerPath
<vault>/<name>/<version>), read from its public certificate (cer: serial, SHA-256, subject, issuer, validity, names,
by opsdir-adapter-x509's certificate_facts) and, where that wasn't read, from its version listing (the SHA-1
thumbprint x5t, validity, enabled). Key Vault keeps a renewed certificate's earlier versions: each names the version
that replaced it (ciamRenewedAs: the next one to start being valid, else to be created), so a record certificate still
naming one is found as it, and renewed as its successor.

The certificate's policy says how the vault manages every version of it: renews it itself (an AutoRenew lifetime
action: enrolled), only emails its contacts before it expires (EmailContacts: monitored) or neither (unassigned);
the issuer it renews through (ciamManagedAuthority: Self, Unknown (issued outside the vault: the vault can't renew
it) or a configured issuer, with its provider (DigiCert, GlobalSign) when the vault names it); the vault's certificate
contacts are who it notifies (ciamManagerContact, by email) when the policy has a lifetime action (Key Vault emails
them before a renewal is due, and of an automatic renewal's result); when each action fires (ciamManagerAction).
Reading the contacts takes the managecontacts permission, which also changes them: a vault whose contacts weren't read
names none (a notice says so). A version disabled in the vault is disabled; what the vault reports wrong now is a
pending operation on the certificate that failed or was canceled (on its current version). Key Vault records no
revocation.

The inventory is denied when the listing holds an error (the listing was refused: what to grant is named),
incomplete when a page isn't one, a listing names a next page the export lacks, or some certificates' versions,
policies or versions' certificates weren't read, else complete.
"""
import base64
import datetime as dt
import re
from urllib.parse import unquote, urlsplit

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import fingerprint, gtime, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.managed import managed_entry, managed_inventory_entry
from opsdir.domains.pki.naming import MANAGED
from opsdir_adapter_x509.certificates import certificate_facts, der_pem

ROOT, PAGE = "keyvault/", "certificates-"
# Key Vault's lifetime action types, lower case (its REST reference writes AutoRenew, its concepts autoRenew) -> the
# record's ciamManagement (the strongest one a policy has wins)
MANAGEMENT = (("autorenew", "enrolled"), ("emailcontacts", "monitored"))
UNKNOWN_ISSUER = "Unknown"         # Key Vault's issuer name for certificates issued outside the vault
PENDING_PROBLEMS = ("failed", "canceled", "cancelled")     # a pending operation's statuses that say it didn't issue
# What the collector's identity needs to list and read certificates' metadata, never a secret's value (the private key)
GRANT = ("grant the collector's identity the Key Vault Reader role on the vault (Azure RBAC: certificates and issuers "
         "read, secrets' metadata only), or with access policies the certificate permissions get, list, getissuers "
         "and listissuers; not Key Vault Certificate User, nor the secret permission get: both read private keys")


def page_path(source, n):
    """Where a source's certificate listing page n (0: the first) is kept in the export."""
    return f"{ROOT}{source}/{PAGE}{n}.json"


def versions_path(source, name, n):
    """Where page n of a certificate's version listing is kept."""
    return f"{ROOT}{source}/versions/{name}-{n}.json"


def version_path(source, name, version):
    """Where a certificate version's answer (its public certificate) is kept."""
    return f"{ROOT}{source}/certificates/{name}/{version}.json"


def policy_path(source, name):
    """Where a certificate's policy is kept."""
    return f"{ROOT}{source}/policies/{name}.json"


def pending_path(source, name):
    """Where a certificate's pending operation is kept (absent: none pending)."""
    return f"{ROOT}{source}/pending/{name}.json"


def vault_path(source, what):
    """Where a vault-wide answer (contacts, issuers) is kept."""
    return f"{ROOT}{source}/{what}.json"


def sources(files):
    """The collection sources an export holds (each with a first listing page), in order."""
    first = re.compile(rf"^{re.escape(ROOT)}([^/]+)/{PAGE}0\.json$")
    return tuple(sorted({m.group(1) for p in files for m in (first.match(p),) if m}))


def id_parts(kid):
    """(certificate name, version or None) a Key Vault certificate id names (https://<vault>/certificates/<name>[/
    <version>]), or None when it names none."""
    parts = unquote(urlsplit(str(kid or "")).path).strip("/").split("/")
    return ((parts[1], parts[2] if len(parts) > 2 else None)
            if len(parts) in (2, 3) and parts[0] == "certificates" and all(parts[1:]) else None)


def pages(files, path_of):
    """((n, the page's document or None), ...) of a paged listing whose page n is kept at path_of(n), from the first
    up to the first page missing."""
    def walk(n):
        text = files.get(path_of(n))
        return () if text is None else ((n, json_document(text, dict)), *walk(n + 1))
    return walk(0)


def _items(listed):
    return tuple(i for _, doc in listed if doc and isinstance(doc.get("value"), list)
                 for i in doc["value"] if isinstance(i, dict))


def _truncated(listed):
    """Whether a paged listing names a next page the export lacks, or holds a page that isn't one."""
    return bool(listed) and (listed[-1][1] is None or bool(listed[-1][1].get("nextLink"))
                             or any(doc is None or not isinstance(doc.get("value"), list) for _, doc in listed))


def thumbprint(x5t):
    """A certificate's SHA-1 thumbprint as ciamThumbprint writes it, from Key Vault's x5t (base64url), or None."""
    try:
        raw = base64.urlsafe_b64decode(str(x5t or "") + "=" * (-len(str(x5t or "")) % 4))
    except ValueError:
        return None
    return fingerprint(raw.hex()) if len(raw) == 20 else None


def epoch_time(v):
    """GeneralizedTime of Key Vault's seconds since 1970 (nbf, exp), or None."""
    ok = isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0
    return gtime(dt.datetime.fromtimestamp(v, dt.timezone.utc)) if ok else None


def lifetime_actions(policy):
    """((action type, when), ...) of a certificate policy's lifetime actions, when in words (80% of its lifetime,
    30 days before expiry, or None when the action names no trigger)."""
    def when(trigger):
        pct, days = trigger.get("lifetime_percentage"), trigger.get("days_before_expiry")
        return (f"{pct}% of its lifetime" if isinstance(pct, int) else
                f"{days} days before expiry" if isinstance(days, int) else None)
    return tuple(((a.get("action") or {}).get("action_type"), when(a.get("trigger") or {}))
                 for a in (policy or {}).get("lifetime_actions") or () if isinstance(a, dict)
                 and isinstance(a.get("action"), dict) and (a.get("action") or {}).get("action_type"))


def management(policy):
    """What the vault does for a certificate, as ciamManagement says it: enrolled (it renews it), monitored (it only
    emails its contacts) or unassigned (neither); None when the policy wasn't read."""
    if policy is None:
        return None
    kinds = {str(k).lower() for k, _ in lifetime_actions(policy)}
    return next((m for k, m in MANAGEMENT if k in kinds), "unassigned")


def authority(policy, providers):
    """The issuer a certificate's policy renews it through, as the vault names it (Self, Unknown, or a configured
    issuer's name with its provider when the vault's issuers name one), or None."""
    name = ((policy or {}).get("issuer") or {}).get("name")
    provider = providers.get(name) if name else None
    return f"{name} ({provider})" if name and provider else name or None


def issuer_providers(doc):
    """{issuer name: provider} of the vault's configured certificate issuers."""
    return {parts[-1]: i.get("provider") for i in (doc or {}).get("value") or () if isinstance(i, dict)
            and isinstance(i.get("provider"), str) for parts in (str(i.get("id") or "").rstrip("/").split("/"),)
            if parts[-1]}


def contact_emails(doc):
    """The email addresses of the vault's certificate contacts."""
    return tuple(dict.fromkeys(c["email"] for c in (doc or {}).get("contacts") or () if isinstance(c, dict)
                               and isinstance(c.get("email"), str) and c["email"].strip()))


def pending_problems(doc):
    """What a certificate's pending operation reports wrong now (failed or cancelled, in Key Vault's words), or ()."""
    status = str((doc or {}).get("status") or "")
    if status.lower() not in PENDING_PROBLEMS:
        return ()
    error = (doc or {}).get("error") if isinstance((doc or {}).get("error"), dict) else {}
    said = "; ".join(x for x in (doc.get("status_details"), error.get("code"), error.get("message")) if x)
    issuer = ((doc or {}).get("issuer") or {}).get("name")
    return (f"the pending request{f' to {issuer}' if issuer else ''} {status.lower()}" + (f": {said}" if said else ""),)


def policy_facts(policy, providers, contacts):
    """The managed certificate facts a certificate's policy (None: not read) gives every version of it."""
    actions = lifetime_actions(policy)
    return {"ciamManagement": management(policy), "ciamManagedAuthority": authority(policy, providers),
            "ciamManagerContact": contacts if actions else (),
            "ciamManagerAction": tuple(f"{k} at {w}" if w else k for k, w in actions),
            "ciamManagedOrigin": "added"}


def version_facts(vault, name, version, item, detail):
    """The managed certificate facts of one version: from its public certificate when its answer (detail) was read,
    else from its version listing item (thumbprint, validity)."""
    x = certificate_facts(der_pem((detail or {}).get("cer"))) or {}
    attrs = (detail or {}).get("attributes") or (item or {}).get("attributes") or {}
    x5t = (detail or {}).get("x5t") or (item or {}).get("x5t")
    return {"ciamSerialNumber": x.get("serial"), "ciamFingerprint": x.get("sha256"),
            "ciamThumbprint": thumbprint(x5t), "ciamSubject": x.get("subject"), "ciamIssuer": x.get("issuer"),
            "ciamNotBefore": x.get("not_before") or epoch_time(attrs.get("nbf")),
            "ciamNotAfter": x.get("not_after") or epoch_time(attrs.get("exp")),
            "ciamCertificateName": x.get("names") or (), "ciamManagerPath": f"{vault}/{name}/{version}",
            "ciamObjectState": "disabled" if attrs.get("enabled") is False else "active"}


def _issued(item, detail):
    """A version's place among its certificate's versions: when it starts to be valid, then when it was created."""
    attrs = (detail or {}).get("attributes") or (item or {}).get("attributes") or {}
    start = (certificate_facts(der_pem((detail or {}).get("cer"))) or {}).get("not_before") or epoch_time(
        attrs.get("nbf"))
    created = attrs.get("created")
    return start or "", created if isinstance(created, (int, float)) and not isinstance(created, bool) else 0


def certificate_rows(files, source, vault, name, current, providers, contacts):
    """(((cn, facts), ...) of every version of one certificate, oldest first, (versions unread, version answers
    unread, policy unread)): the certificate's policy facts on each; on each but the newest, the version that replaced
    it (ciamRenewedAs: its cn); what its pending operation reports on its current version (the one the listing's x5t
    names)."""
    listed = pages(files, lambda n: versions_path(source, name, n))
    items = {v: i for i in _items(listed) for _, v in (id_parts(i.get("id")) or (None, None),) if v}
    policy = json_document(files.get(policy_path(source, name)) or "", dict)
    shared = policy_facts(policy, providers, contacts)
    problems = pending_problems(json_document(files.get(pending_path(source, name)) or "", dict))
    details = {v: json_document(files.get(version_path(source, name, v)) or "", dict) for v in items}
    facts = tuple((f"{name}/{v}", {**version_facts(vault, name, v, i, details[v]), **shared,
                                   "ciamManagerProblem": problems if i.get("x5t") == current else ()})
                  for v, i in sorted(items.items(), key=lambda vi: _issued(vi[1], details[vi[0]]))
                  if rdn_safe(f"{name}/{v}"))
    rows = tuple((cn, {**f, "ciamRenewedAs": facts[n + 1][0] if n + 1 < len(facts) else None})
                 for n, (cn, f) in enumerate(facts))
    return rows, (not listed or _truncated(listed), sum(1 for d in details.values() if d is None), policy is None)


def read_source(d, source, files, when):
    """(Imported group, notices) of one collection source: its vault's inventory and every version of every
    certificate it holds."""
    listed = pages(files, lambda n: page_path(source, n))
    first = listed[0][1] or {}
    address, error = first.get("Vault"), first.get("error")
    vault = urlsplit(str(address or "")).hostname or ""
    vault = vault.split(".", 1)[0]
    names = tuple(dict.fromkeys((parts[0], i.get("x5t")) for i in _items(listed)
                                for parts in (id_parts(i.get("id")),) if parts and i.get("x5t")))
    unnamed = tuple(n for n, _ in names if not rdn_safe(n))
    providers = issuer_providers(json_document(files.get(vault_path(source, "issuers")) or "", dict))
    contacts_read = json_document(files.get(vault_path(source, "contacts")) or "", dict)
    contacts = contact_emails(contacts_read)
    read = tuple((n, *certificate_rows(files, source, vault, n, x5t, providers, contacts))
                 for n, x5t in names if n not in unnamed)
    count = lambda k: sum(1 for _, _, gaps in read if gaps[k])                      # noqa: E731
    unread_answers = sum(gaps[1] for _, _, gaps in read)
    message = (error or {}).get("message") if isinstance(error, dict) else error
    problems = ((f"the listing of the vault's certificates was refused ({message}): {GRANT}",) if error else
                (*(("the certificate listing is incomplete (a page isn't one, or the next page wasn't read)",)
                   if _truncated(listed) else ()),
                 *((f"versions of {count(0)} certificate(s) not all listed",) if count(0) else ()),
                 *((f"{unread_answers} certificate version(s) not read (only the thumbprint and validity are known)",)
                   if unread_answers else ()),
                 *((f"policies of {count(2)} certificate(s) not read (how the vault manages them is unknown)",)
                   if count(2) else ()),
                 *((f"{len(unnamed)} certificate name(s) can't be named in the record",) if unnamed else ())))
    state = "denied" if error else "incomplete" if problems else "complete"
    rows = () if error else tuple(r for _, found, _ in read for r in found)
    inventory = inventory_group(
        managed_inventory_entry(d, source, when, state, problems, (vault,) if vault else (), address),
        tuple(managed_entry(d, source, cn, facts) for cn, facts in rows))
    return inventory, (f"{source} ({vault or 'vault unknown'}): {len(rows)} version(s) of {len(read)} "
                       f"certificate(s), {state}" + (f" ({'; '.join(problems)})" if problems else ""),
                       *((f"{source}: the vault's certificate contacts weren't read (none set, or the identity lacks "
                          "managecontacts): who it notifies is unknown",) if contacts_read is None and not error
                         else ()))


def read_keyvault_certificates(files, d, patterns, at=None):
    """Imported: per collection source in the export, its vault's certificate manager inventory, replacing the
    record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the vault was read)",))
    read = tuple(read_source(d, s, files, gtime(at)) for s in sources(files) if rdn_safe(s))
    return Imported(containers=(ou_entry(MANAGED),), groups=tuple(g for g, _ in read),
                    notices=(*(n for _, notices in read for n in notices),
                             *(f"source {s} can't be named in the record: left out" for s in sources(files)
                               if not rdn_safe(s)),
                             *(("no listings (keyvault/<source>/certificates-0.json, as `opsdir collect` saves "
                                "them)",) if not sources(files) else ())))


KEYVAULT_CERTIFICATES = Importer("keyvault-certificates", "Azure Key Vault certificates (every version) as a "
                                                          "certificate manager's inventory, metadata only (Key Vault's "
                                                          "REST answers as `opsdir collect` saves them)",
                                 read_keyvault_certificates)
