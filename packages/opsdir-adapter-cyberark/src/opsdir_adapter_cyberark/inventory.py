"""CyberArk account inventory (the importer `cyberark/accounts`): what the vault's safes hold, metadata only, read from
the PVWA REST API's account listing (GET /PasswordVault/API/Accounts, self-hosted PVWA 10.4+ and Privilege Cloud), into
the record's secret-store inventory (domains.pki.inventory). Pure.

The export holds one listing per safe: accounts/<safe>.json (one answer), or accounts/<safe>/<offset>.json (its pages,
as `opsdir collect` saves them). Each answer is the API's {"value": [accounts], "count": n, "nextLink": ...}; an
answer that is the API's error ({"ErrorCode", "ErrorMessage"}) records the safe as denied. A safe is complete when its
pages hold as many distinct accounts as the count says; anything else (no count, fewer accounts, a page that isn't
JSON) records it incomplete with why. The vault's MaxDisplayedRecords may cap a listing without saying so: page
exhaustion can't prove completeness beyond the count the vault reports (README, Known limits).

Only metadata fields are read (ACCOUNT_FIELDS, MANAGEMENT_FIELDS): an account's name (the Object a reference
names), its safe, platform and times, and its secretManagement block. A field that could carry a value (`secret`,
a password) is never read; one present is named in a notice. Rotation: ciamLastRotated only from
secretManagement.lastModifiedTime with status Success (a CPM change that worked); the status itself (Success,
Failure, inProcess), whether the CPM manages the account and why not are kept apart, and so are the verification
time and when the account's properties changed (categoryModificationTime, ciamStoreModified). Times are taken as
epoch seconds (or milliseconds) or ISO 8601, as versions differ, and under both of the API's names
(lastModifiedTime and lastModifiedDateTime).
"""
import datetime as dt
import json

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import gtime, gtime_of_iso, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.domains.pki.inventory import inventory_entry, inventory_group, object_entry
from opsdir.domains.pki.naming import SECRET_INVENTORY, inventory_scheme_dn

SCHEME = "cyberark"
ROOT = "accounts/"
ACCOUNT_FIELDS = ("id", "safeName", "name", "platformId", "createdTime", "categoryModificationTime")
MANAGEMENT_FIELDS = ("automaticManagementEnabled", "manualManagementReason", "status", "lastModifiedTime",
                     "lastModifiedDateTime", "lastReconciledTime", "lastReconciledDateTime", "lastVerifiedTime",
                     "lastVerifiedDateTime")
ANSWER_FIELDS = ("count", "nextLink", "ErrorCode", "ErrorMessage")
VALUE_FIELDS = frozenset({"secret", "password", "secretvalue", "content", "key", "privatekey"})
STATUS = {"success": "success", "failure": "failure", "inprocess": "in-progress"}


def locate(rest):
    """Where a cyberark://<app-id>/<safe>/<object> reference points: (safe, object), or None."""
    parts = rest.split("/", 2)
    return (parts[1], parts[2]) if len(parts) == 3 and all(parts) else None


def _account(a):
    management = a.get("secretManagement") if isinstance(a.get("secretManagement"), dict) else {}
    return {**{k: a[k] for k in ACCOUNT_FIELDS if k in a},
            **({"secretManagement": {k: management[k] for k in MANAGEMENT_FIELDS if k in management}}
               if management else {})}


def metadata_only(text):
    """An account listing answer with nothing but the metadata the importer reads (ANSWER_FIELDS, and each account's
    ACCOUNT_FIELDS and MANAGEMENT_FIELDS): what `opsdir collect` keeps of each page before anything else sees it.
    Text that isn't a JSON object is kept as it is (the importer says it isn't a listing)."""
    try:
        doc = json.loads(text)
    except ValueError:
        return text
    if not isinstance(doc, dict):
        return text
    accounts = doc.get("value") if isinstance(doc.get("value"), list) else None
    return json.dumps({**{k: doc[k] for k in ANSWER_FIELDS if k in doc},
                       **({"value": [_account(a) for a in accounts if isinstance(a, dict)]}
                          if accounts is not None else {})}, indent=1, sort_keys=True)


def _time(v):
    """GeneralizedTime of an API time (epoch seconds or milliseconds, as a number or digits, or ISO 8601), or None."""
    if isinstance(v, bool) or v in (None, "", 0):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
        seconds = float(v)
        return gtime(dt.datetime.fromtimestamp(seconds / 1000 if seconds > 1e11 else seconds, dt.timezone.utc))
    return gtime_of_iso(v)


def _first(m, *names):
    return next((m[n] for n in names if m.get(n) not in (None, "")), None)


def account_facts(a):
    """The secret object facts of one account (domains.pki.inventory OBJECT_ATTRS)."""
    m = a.get("secretManagement") if isinstance(a.get("secretManagement"), dict) else {}
    status = STATUS.get(str(m.get("status") or "").replace(" ", "").lower())
    managed = m.get("automaticManagementEnabled")
    return {"ciamRotationManaged": {True: "TRUE", False: "FALSE"}.get(managed),
            "ciamRotationStatus": status,
            "ciamLastRotated": _time(_first(m, "lastModifiedTime", "lastModifiedDateTime"))
            if status == "success" else None,
            "ciamStoreModified": _time(a.get("categoryModificationTime")),
            "ciamLastVerified": _time(_first(m, "lastVerifiedTime", "lastVerifiedDateTime")),
            "ciamManualReason": (m.get("manualManagementReason") or None) if managed is False else None}


def _value_fields(a, where):
    """A notice naming the fields of an account that could carry a value (never read), or none."""
    management = a.get("secretManagement") if isinstance(a.get("secretManagement"), dict) else {}
    found = sorted({k for k in (*a, *management) if str(k).lower() in VALUE_FIELDS})
    return (f"{where}: account `{a.get('name')}` carries {', '.join(found)}: not read (metadata only)",) \
        if found else ()


def _doc(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _pages(files):
    """{safe: ((path, text), ...)} of the export's listings, pages in offset order."""
    def safe_of(path):
        rest = path[len(ROOT):]
        return rest[:-5] if "/" not in rest else rest.split("/", 1)[0]
    def offset(path):
        tail = path.rsplit("/", 1)[1][:-5]
        return int(tail) if tail.isdigit() else -1
    listed = sorted(p for p in files if p.startswith(ROOT) and p.endswith(".json"))
    return {s: tuple((p, files[p]) for p in sorted((p for p in listed if safe_of(p) == s), key=offset))
            for s in dict.fromkeys(safe_of(p) for p in listed)}


def safe_listing(safe, pages):
    """(state, problems, accounts, notices) of one safe's listing pages."""
    docs = [(p, _doc(t)) for p, t in pages]
    errors = [f"{d.get('ErrorCode', 'error')}: {d.get('ErrorMessage', '')}".strip() for _, d in docs
              if isinstance(d, dict) and not isinstance(d.get("value"), list)
              and (d.get("ErrorCode") or d.get("ErrorMessage"))]
    if errors:
        return "denied", tuple(errors), (), ()
    unread = [p for p, d in docs if not isinstance(d, dict) or not isinstance(d.get("value"), list)]
    accounts = tuple({a.get("id") or a.get("name"): a for _, d in docs if isinstance(d, dict)
                      for a in d.get("value") or () if isinstance(a, dict) and a.get("name")}.values())
    other = [a for a in accounts if a.get("safeName") not in (None, safe)]
    counts = [d["count"] for _, d in docs if isinstance(d, dict) and isinstance(d.get("count"), int)]
    total = max(counts) if counts else None
    problems = (*(f"{p} isn't an account listing" for p in unread),
                *(("the listing gives no count, so it can't be shown complete",) if total is None else ()),
                *((f"{len(accounts)} of {total} accounts listed",) if total is not None and len(accounts) < total
                  else ()))
    notices = tuple(f"{safe}: account `{a.get('name')}` is in safe {a.get('safeName')}: left out" for a in other)
    kept = tuple(a for a in accounts if a not in other)
    return ("incomplete" if problems else "complete"), problems, kept, notices


def read_accounts(files, d, patterns, at=None):
    """Imported: one inventory per safe in the export (its accounts as secret objects), replacing that safe's."""
    pages = _pages(files)
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the listing was taken)",))
    when = gtime(at)
    groups, notices = [], []
    for safe, safe_pages in pages.items():
        if not rdn_safe(safe):
            notices.append(f"safe {safe!r} can't be named in the record: left out")
            continue
        state, problems, accounts, more = safe_listing(safe, safe_pages)
        unnamed = tuple(a["name"] for a in accounts if not rdn_safe(a["name"]))
        problems = (*problems, *((f"{len(unnamed)} account name(s) can't be named in the record",) if unnamed else ()))
        state = "incomplete" if unnamed and state == "complete" else state
        objects = tuple(object_entry(d, SCHEME, safe, a["name"], account_facts(a)) for a in accounts
                        if a["name"] not in unnamed)
        groups.append(inventory_group(inventory_entry(d, SCHEME, safe, when, state, problems), objects))
        notices.extend((*more, *(n for a in accounts for n in _value_fields(a, safe)),
                        f"{safe}: {len(objects)} account(s), {state}" + (f" ({'; '.join(problems)})" if problems
                                                                          else "")))
    return Imported(containers=(ou_entry(SECRET_INVENTORY), ou_entry(inventory_scheme_dn(SCHEME))),
                    groups=tuple(groups),
                    notices=(*notices, *(("no account listings (accounts/<safe>.json, or accounts/<safe>/<offset>.json "
                                          "pages)",) if not pages else ())))


ACCOUNTS_IMPORTER = Importer("accounts", "CyberArk safes' account inventory, metadata only (PVWA /API/Accounts "
                                         "listings: accounts/<safe>.json or its pages)", read_accounts, reference=True)
