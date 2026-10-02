"""The shape of an environment's user data, values-free: what a move's risk, cleanup scope and consumer impact come
from (STACK.md section 3). Pure.

profile(records, as_of, terms) reads directory entries once, as a stream, and keeps counts only:

  entries, and per container (branch) the entries directly under it, by object class
  per attribute: the entries holding it, the most values one entry holds, the size of its largest value (operational
    attributes the server keeps for itself left out)
  password values by hashing scheme: only schemes `terms` names are recorded by name; any other prefix is
    `unrecognized`, so a clear-text password that happens to start with "{" never reaches the record
  the time since each account's last login and last password change, in buckets (an account: an entry with a
    password, or a login or password-change time)
  locked, disabled and pending entries, and holders of challenge questions (KBA)
  static groups: how many, how many are empty, the largest, and member DNs that aren't among the entries read

No value is kept. A branch is named by its DN with every RDN that isn't a container's (ou, o, dc, c, l, st) masked
(uid=*), so a user entry with entries under it never gives its name to the record.

Which attributes mean what (the last login, a disabled flag, challenge questions) differs per product: Terms holds
that, STANDARD what the LDAP standards define (RFC 4519 groups, the password policy draft's operational attributes,
RFC 3112 authPassword); product adapters extend it.

The stream is read in chunks; each chunk is counted on its own and the counts are merged pairwise, so memory holds
one chunk of entries plus the DNs that groups refer to.

profile_json is the file `opsdir data-profile` writes (counts only) and read_profile reads it back for the import,
checking again that it holds no value: branches masked, schemes, attribute and class names as names, counts as
numbers. profile_entries turns a Profile into the record's entries under ou=data-profile; profile_rows and
attribute_rows are the reports, check_data_profile the planner's check.
"""
import datetime as dt
import re
from collections import Counter
from itertools import batched, groupby
from operator import itemgetter
from types import MappingProxyType
from typing import Mapping, NamedTuple, Optional

from ...core.directory import children, gtime, gtime_date, make_entry, norm_dn, one, ou_entry, values
from ...core.environment import env_dn
from ...core.findings import findings, responsible
from ...core.jsondata import indented
from ...core.naming import env_label
from ...core.sources import json_document
from .naming import DATA_PROFILE, DECLARED, DIRECTORY_SERVER_ROLE, USER_SCHEMA

CHUNK = 10_000                                         # entries counted at a time
CONTAINER_RDNS = frozenset({"ou", "o", "dc", "c", "l", "st"})
AGES = ((30, "<30d"), (90, "30-90d"), (365, "90-365d"), (730, "1-2y"))   # (days below, bucket)
OLDEST, NEVER, UNREADABLE = ">2y", "never", "unreadable"
BUCKETS = (*(b for _, b in AGES), OLDEST, NEVER, UNREADABLE)
NO_SCHEME, UNRECOGNIZED = "none", "unrecognized"
_PREFIX = re.compile(r"\{([^}]{1,40})\}")
_RDN_SEP = re.compile(r"(?<!\\),")

# What a product's (or an estate's) attributes mean. password: attributes holding hashed passwords; schemes: the
# hashing schemes recorded by name; last_login, password_changed: time attributes (the first one present counts);
# locked, disabled, pending: (attribute, value) tests, a value of None meaning the attribute is present; kba:
# attributes holding challenge questions; member, group_classes: static groups; operational: attributes the server
# keeps for itself (a trailing * names a prefix), read for the tests above but not counted as user data.
Terms = NamedTuple("Terms", [("password", tuple), ("schemes", frozenset), ("last_login", tuple),
                             ("password_changed", tuple), ("locked", tuple), ("disabled", tuple), ("pending", tuple),
                             ("kba", tuple), ("member", tuple), ("group_classes", tuple), ("operational", tuple)])

STANDARD = Terms(
    password=("userPassword", "authPassword"),
    schemes=frozenset({"CLEAR", "BASE64", "CRYPT", "MD5", "SMD5", "SHA", "SSHA", "SHA256", "SSHA256", "SHA384",
                       "SSHA384", "SHA512", "SSHA512", "PBKDF2", "PBKDF2-SHA1", "PBKDF2-SHA256", "PBKDF2-SHA512",
                       "PBKDF2-HMAC-SHA256", "PBKDF2-HMAC-SHA512", "PKCS5S2", "BCRYPT", "SCRYPT", "ARGON2",
                       "ARGON2I", "ARGON2ID", "3DES", "AES", "BLOWFISH", "RC4"}),
    last_login=("pwdLastSuccess",), password_changed=("pwdChangedTime",), locked=(("pwdAccountLockedTime", None),),
    disabled=(), pending=(), kba=(), member=("member", "uniqueMember"),
    group_classes=("groupOfNames", "groupOfUniqueNames"),
    operational=("createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName", "subschemaSubentry",
                 "structuralObjectClass", "governingStructureRule", "hasSubordinates", "numSubordinates",
                 "entryUUID", "entryDN", "pwdChangedTime", "pwdAccountLockedTime", "pwdFailureTime", "pwdHistory",
                 "pwdGraceUseTime", "pwdReset", "pwdPolicySubentry", "pwdLastSuccess", "pwdStartTime", "pwdEndTime"))
# --term names (opsdir data-profile) -> the Terms field they extend
TERM_NAMES = MappingProxyType({"password": "password", "scheme": "schemes", "last-login": "last_login",
                               "password-changed": "password_changed", "locked": "locked", "disabled": "disabled",
                               "pending": "pending", "kba": "kba", "member": "member", "group-class": "group_classes",
                               "operational": "operational"})
TESTS = frozenset({"locked", "disabled", "pending"})        # fields whose terms are (attribute, value) tests

# What one entry contributes, values already reduced away: its DN's hash (to find dangling members), its branch, its
# object classes, (attribute, number of values, largest value's size) per attribute, its size, the schemes of its
# password values, its login and password-change buckets (None: not an account, i.e. no password and no login or
# password-change time), its states, and its members' DN hashes (None: not a group).
Facts = NamedTuple("Facts", [("dn", int), ("branch", Optional[str]), ("classes", tuple), ("attributes", tuple),
                             ("size", int), ("schemes", tuple), ("login", Optional[str]), ("changed", Optional[str]),
                             ("locked", bool),
                             ("disabled", bool), ("pending", bool), ("kba", bool), ("members", Optional[tuple])])

BranchStat = NamedTuple("BranchStat", [("entries", int), ("classes", Mapping)])
AttributeStat = NamedTuple("AttributeStat", [("holders", int), ("most_values", int), ("largest_bytes", int)])
# The profile of a directory's data: counts and distributions only.
Profile = NamedTuple("Profile", [("entries", int), ("branches", Mapping), ("attributes", Mapping), ("schemes", Mapping),
                                 ("last_login", Mapping), ("password_age", Mapping), ("locked", int),
                                 ("disabled", int), ("pending", int), ("kba", int), ("groups", int),
                                 ("empty_groups", int), ("largest_group", int), ("dangling_members", int),
                                 ("largest_entry", int)])

# Counts of a part of the stream, merged pairwise into the whole.
_Counts = NamedTuple("_Counts", [("entries", int), ("branches", Counter), ("classes", Counter), ("holders", Counter),
                                 ("most", Mapping), ("largest", Mapping), ("schemes", Counter), ("logins", Counter),
                                 ("changes", Counter), ("locked", int), ("disabled", int), ("pending", int),
                                 ("kba", int), ("groups", int), ("empty", int), ("largest_group", int),
                                 ("largest_entry", int), ("dns", frozenset), ("targets", frozenset)])


def _is_operational(name, operational):
    return any(name == o or (o.endswith("*") and name.startswith(o[:-1])) for o in operational)


def _term_value(field, text):
    attribute, _, value = text.partition("=")
    return (attribute, value or None) if field in TESTS else text


def defined_terms(definitions):
    """Terms an operator defines for an estate (`opsdir data-profile --term NAME=ATTRIBUTE[=VALUE]`, e.g.
    last-login=lastLoginTime, pending=registrationStatus=pending, kba=challengeAnswer), and the definitions that aren't
    any (unknown name, nothing after it)."""
    parsed = tuple((d, n.strip(), v.strip()) for d in definitions for n, _, v in (d.partition("="),))
    good = tuple((TERM_NAMES[n], v) for _, n, v in parsed if n in TERM_NAMES and v)
    return Terms(*(frozenset(v.upper() for f, v in good if f == field) if field == "schemes"
                   else tuple(_term_value(field, v) for f, v in good if f == field) for field in Terms._fields)), \
        tuple(d for d, n, v in parsed if n not in TERM_NAMES or not v)


def combined(*terms):
    """Terms that mean what all of the given ones mean (a product adapter's on top of STANDARD)."""
    return Terms(*(frozenset().union(*parts) if isinstance(parts[0], frozenset)
                   else tuple(dict.fromkeys(x for p in parts for x in p))
                   for parts in zip(*terms)))


# ------------------------------------------------------------------ one entry
def _text(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _size(v):
    return len(v) if isinstance(v, bytes) else len(v.encode("utf-8"))


def _rdn_attr(rdn):
    return rdn.split("=", 1)[0].strip().lower()


def branch_of(dn):
    """The masked DN of the container an entry is directly under (uid=*,ou=people,dc=example,dc=com), or None for an
    entry at the top."""
    parent = _RDN_SEP.split(dn)[1:]
    return ",".join(r.strip().lower() if _rdn_attr(r) in CONTAINER_RDNS else f"{_rdn_attr(r)}=*"
                    for r in parent) or None


def scheme_of(attribute, value, schemes):
    """The hashing scheme of a password value ({SSHA512}..., or RFC 3112 SCHEME$...): its name when `schemes` has it,
    `unrecognized` otherwise, `none` when the value carries no scheme."""
    text = value if isinstance(value, str) else value.decode("latin-1")
    found = (text.split("$", 1)[0] if "$" in text else "") if attribute == "authpassword" else \
        (m.group(1) if (m := _PREFIX.match(text)) else "")
    name = found.strip().upper()
    return NO_SCHEME if not name else name if name in schemes else UNRECOGNIZED


def age_bucket(stamp, as_of):
    """The bucket of a GeneralizedTime stamp's age on date as_of: <30d, 30-90d, 90-365d, 1-2y, >2y; never for no
    stamp, unreadable for one that isn't a time."""
    if stamp is None:
        return NEVER
    try:
        days = (as_of - gtime_date(_text(stamp).strip())).days
    except ValueError:
        return UNREADABLE
    return next((b for limit, b in AGES if days < limit), OLDEST)


def _first(attrs, names):
    return next((attrs[n.lower()][0] for n in names if attrs.get(n.lower())), None)


def _matches(attrs, tests):
    return any(attrs.get(a.lower()) and (v is None or v.lower() in {_text(x).lower() for x in attrs[a.lower()]})
               for a, v in tests)


def entry_facts(record, as_of, terms=STANDARD):
    """What one directory entry, (dn, {attribute: values}), contributes to the profile."""
    dn, raw = record
    attrs = {k.lower(): tuple(v) for k, v in raw.items()}
    classes = tuple(_text(c) for c in attrs.get("objectclass", ()))
    group = {g.lower() for g in terms.group_classes} & {c.lower() for c in classes}
    account = any(attrs.get(a.lower()) for a in (*terms.password, *terms.last_login, *terms.password_changed))
    operational = tuple(o.lower() for o in terms.operational)
    return Facts(
        dn=hash(norm_dn(dn)), branch=branch_of(dn), classes=classes,
        attributes=tuple((k, len(vs), max(map(_size, vs), default=0)) for k, vs in attrs.items()
                         if vs and not _is_operational(k, operational)),
        size=sum(len(k) + _size(v) for k, vs in attrs.items() for v in vs),
        schemes=tuple(scheme_of(a.lower(), v, terms.schemes) for a in terms.password for v in attrs.get(a.lower(), ())),
        login=age_bucket(_first(attrs, terms.last_login), as_of) if account else None,
        changed=age_bucket(_first(attrs, terms.password_changed), as_of) if account else None,
        locked=_matches(attrs, terms.locked), disabled=_matches(attrs, terms.disabled),
        pending=_matches(attrs, terms.pending), kba=any(attrs.get(a.lower()) for a in terms.kba),
        members=tuple(hash(norm_dn(_text(m))) for a in terms.member for m in attrs.get(a.lower(), ()))
        if group else None)


# ------------------------------------------------------------------ the stream
def _maxima(pairs):
    return {k: max(v for _, v in g) for k, g in groupby(sorted(pairs, key=itemgetter(0)), key=itemgetter(0))}


def _counted(facts):
    groups = tuple(f.members for f in facts if f.members is not None)
    return _Counts(
        entries=len(facts), branches=Counter(f.branch for f in facts if f.branch),
        classes=Counter((f.branch, c) for f in facts if f.branch for c in f.classes),
        holders=Counter(a for f in facts for a, _, _ in f.attributes),
        most=_maxima((a, n) for f in facts for a, n, _ in f.attributes),
        largest=_maxima((a, b) for f in facts for a, _, b in f.attributes),
        schemes=Counter(s for f in facts for s in f.schemes), logins=Counter(f.login for f in facts if f.login),
        changes=Counter(f.changed for f in facts if f.changed), locked=sum(f.locked for f in facts),
        disabled=sum(f.disabled for f in facts), pending=sum(f.pending for f in facts), kba=sum(f.kba for f in facts),
        groups=len(groups), empty=sum(1 for g in groups if not g), largest_group=max(map(len, groups), default=0),
        largest_entry=max((f.size for f in facts), default=0), dns=frozenset(f.dn for f in facts),
        targets=frozenset(t for g in groups for t in g))


def _larger(a, b):
    return {k: max(a.get(k, 0), b.get(k, 0)) for k in a.keys() | b.keys()}


def _merged(a, b):
    return _Counts(
        entries=a.entries + b.entries, branches=a.branches + b.branches, classes=a.classes + b.classes,
        holders=a.holders + b.holders, most=_larger(a.most, b.most), largest=_larger(a.largest, b.largest),
        schemes=a.schemes + b.schemes, logins=a.logins + b.logins, changes=a.changes + b.changes,
        locked=a.locked + b.locked, disabled=a.disabled + b.disabled, pending=a.pending + b.pending,
        kba=a.kba + b.kba, groups=a.groups + b.groups, empty=a.empty + b.empty,
        largest_group=max(a.largest_group, b.largest_group), largest_entry=max(a.largest_entry, b.largest_entry),
        dns=a.dns | b.dns, targets=a.targets | b.targets)


def _all(parts):
    return parts[0] if len(parts) == 1 else _merged(_all(parts[:len(parts) // 2]), _all(parts[len(parts) // 2:]))


def _frozen(mapping):
    return MappingProxyType(dict(sorted(mapping.items())))


def _bucketed(counter):
    return MappingProxyType({b: counter[b] for b in BUCKETS if counter[b]})


def profile(records, as_of, terms=STANDARD, chunk=CHUNK):
    """The Profile of a stream of directory entries ((dn, {attribute: values}), read once), with ages counted on date
    as_of."""
    parts = tuple(_counted(tuple(entry_facts(r, as_of, terms) for r in part)) for part in batched(records, chunk))
    c = _all(parts) if parts else _counted(())
    return Profile(
        entries=c.entries,
        branches=_frozen({b: BranchStat(n, _frozen({cl: k for (br, cl), k in c.classes.items() if br == b}))
                          for b, n in c.branches.items()}),
        attributes=_frozen({a: AttributeStat(n, c.most[a], c.largest[a]) for a, n in c.holders.items()}),
        schemes=_frozen(c.schemes), last_login=_bucketed(c.logins), password_age=_bucketed(c.changes),
        locked=c.locked, disabled=c.disabled, pending=c.pending, kba=c.kba, groups=c.groups, empty_groups=c.empty,
        largest_group=c.largest_group, dangling_members=len(c.targets - c.dns), largest_entry=c.largest_entry)


# ------------------------------------------------------------------ the profile file
FORMAT = "opsdir-data-profile/1"
STATES = ("locked", "disabled", "pending", "kba", "groups", "empty_groups", "largest_group", "dangling_members",
          "largest_entry")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")                      # an attribute or object class name
_SCHEME = re.compile(r"^(?:[A-Z0-9][A-Z0-9_.-]{0,39}|none|unrecognized)$")
_LABEL = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_MASKED_RDN = re.compile(r"^([a-z][a-z0-9-]*)=(.+)$")

# A profile file read back: the environment it describes ('cloud/env'), when it was taken, the profile.
ProfileFile = NamedTuple("ProfileFile", [("label", str), ("captured", dt.datetime), ("profile", Profile)])


def profile_json(p, label, captured):
    """The profile file: counts only, with the environment it describes and when it was taken."""
    return indented({"format": FORMAT, "environment": label, "captured": gtime(captured), "entries": p.entries,
                     "branches": {b: {"entries": s.entries, "classes": dict(s.classes)} for b, s in p.branches.items()},
                     "attributes": {a: s._asdict() for a, s in p.attributes.items()}, "schemes": dict(p.schemes),
                     "last_login": dict(p.last_login), "password_age": dict(p.password_age),
                     **{k: getattr(p, k) for k in STATES}})


def masked(branch):
    """Whether a branch DN names containers only, every other RDN masked (attr=*)."""
    rdns = tuple(_MASKED_RDN.match(r) for r in _RDN_SEP.split(branch))
    return all(m and (m.group(1) in CONTAINER_RDNS or m.group(2) == "*") for m in rdns)


def _count(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _counts_of(mapping, key_ok):
    return isinstance(mapping, dict) and all(key_ok(k) and _count(n) for k, n in mapping.items())


def _problem(doc):
    """Why a parsed profile file isn't one opsdir can record (None when it is)."""
    checks = (
        (doc.get("format") == FORMAT, f"format is not {FORMAT}"),
        (isinstance(doc.get("environment"), str) and _LABEL.match(doc["environment"]),
         "environment is not cloud/env"),
        (isinstance(doc.get("captured"), str) and re.fullmatch(r"\d{14}Z", doc["captured"]),
         "captured is not a time (YYYYMMDDhhmmssZ)"),
        (_count(doc.get("entries")) and all(_count(doc.get(k)) for k in STATES), "a count is not a number"),
        (isinstance(doc.get("branches"), dict) and all(
            isinstance(b, str) and masked(b) and isinstance(s, dict) and _count(s.get("entries"))
            and _counts_of(s.get("classes"), _NAME.match) for b, s in doc["branches"].items()),
         "a branch names a value (only containers and attr=* may appear) or isn't counted"),
        (isinstance(doc.get("attributes"), dict) and all(
            _NAME.match(a) and isinstance(s, dict) and all(_count(s.get(f)) for f in AttributeStat._fields)
            for a, s in doc["attributes"].items()), "an attribute isn't a name with counts"),
        (_counts_of(doc.get("schemes"), _SCHEME.match), "a password scheme isn't a scheme name with a count"),
        (all(_counts_of(doc.get(k), BUCKETS.__contains__) for k in ("last_login", "password_age")),
         "an age bucket is unknown"))
    return next((why for ok, why in checks if not ok), None)


def read_profile(text):
    """(ProfileFile, None) of a profile file's text, or (None, why it can't be recorded)."""
    doc = json_document(text, dict)
    why = "not a JSON object" if doc is None else _problem(doc)
    if why:
        return None, why
    return ProfileFile(doc["environment"], dt.datetime.strptime(doc["captured"], "%Y%m%d%H%M%SZ").replace(
        tzinfo=dt.timezone.utc), Profile(
        entries=doc["entries"],
        branches=_frozen({b: BranchStat(s["entries"], _frozen(s["classes"])) for b, s in doc["branches"].items()}),
        attributes=_frozen({a: AttributeStat(*(s[f] for f in AttributeStat._fields))
                            for a, s in doc["attributes"].items()}),
        schemes=_frozen(doc["schemes"]), last_login=_bucketed(Counter(doc["last_login"])),
        password_age=_bucketed(Counter(doc["password_age"])), **{k: doc[k] for k in STATES})), None


# ------------------------------------------------------------------ the record
def profile_dn(label):
    """DN of the data profile of environment 'cloud/env'."""
    return f"cn={label.replace('/', '-')},{DATA_PROFILE}"


def _pairs(mapping):
    return tuple(f"{k}={n}" for k, n in mapping.items())


def _slugs(branches):
    """A cn per branch: its RDN values joined by dots (masked ones as <attr>-any), numbered when two would clash."""
    plain = tuple(".".join(r.split("=", 1)[1] if not r.endswith("=*") else f"{_rdn_attr(r)}-any"
                           for r in _RDN_SEP.split(b)) for b in branches)
    return tuple(s if not plain[:i].count(s) else f"{s}-{plain[:i].count(s) + 1}" for i, s in enumerate(plain))


def described(d):
    """{attribute name, lowercase: DN of the ou=user-schema record describing it}."""
    return {one(e, "ciamLdapName").lower(): e.dn for e in children(d, USER_SCHEMA, "ciamUserAttribute")
            if one(e, "ciamLdapName")}


def profile_entries(d, label, p, captured):
    """(scope DN, entries): environment 'cloud/env's data profile p, captured at datetime `captured`, as the record's
    entries: the profile, its branches under ou=branches and its attributes under ou=attributes."""
    dn = profile_dn(label)
    counts = {"ciamLockedCount": p.locked, "ciamDisabledCount": p.disabled, "ciamPendingCount": p.pending,
              "ciamKbaCount": p.kba, "ciamGroupCount": p.groups, "ciamEmptyGroupCount": p.empty_groups,
              "ciamDanglingMemberCount": p.dangling_members, "ciamLargestGroup": p.largest_group,
              "ciamLargestEntryBytes": p.largest_entry}
    head = make_entry(dn, ("top", "ciamObject", "ciamDataProfile"), {
        "cn": (label.replace("/", "-"),), "ciamProfiledEnvironment": (env_dn(label),),
        "ciamCapturedAt": (gtime(captured),),
        "ciamEntryCount": (str(p.entries),), "ciamHashSchemeCount": _pairs(p.schemes),
        "ciamLastLoginAge": _pairs(p.last_login), "ciamPasswordAge": _pairs(p.password_age),
        **{k: (str(v),) for k, v in counts.items()}})
    known = described(d)
    branches = tuple(make_entry(f"cn={slug},ou=branches,{dn}", ("top", "ciamObject", "ciamBranchProfile"),
                                {"cn": (slug,), "ciamProfiledBranch": (b,), "ciamEntryCount": (str(s.entries),),
                                 "ciamClassCount": _pairs(s.classes)})
                     for slug, (b, s) in zip(_slugs(tuple(p.branches)), p.branches.items()))
    attributes = tuple(make_entry(f"cn={a},ou=attributes,{dn}", ("top", "ciamObject", "ciamAttributeProfile"),
                                  {"cn": (a,), "ciamLdapName": (a,), "ciamHolderCount": (str(s.holders),),
                                   "ciamMostValues": (str(s.most_values),),
                                   "ciamLargestValueBytes": (str(s.largest_bytes),),
                                   **({"ciamProfiledAttribute": (known[a],)} if a in known else {})})
                       for a, s in p.attributes.items())
    return dn, (head, ou_entry(f"ou=branches,{dn}"), *branches, ou_entry(f"ou=attributes,{dn}"), *attributes)


# ------------------------------------------------------------------ reports
PROFILE_HEADERS = ("environment", "captured", "entries", "password schemes", "last login", "password age", "locked",
                   "disabled", "pending", "kba", "groups", "empty groups", "largest group", "dangling members",
                   "largest entry")
ATTRIBUTE_HEADERS = ("environment", "attribute", "holders", "fill", "most values", "largest value", "described")


def profiles(d):
    return children(d, DATA_PROFILE, "ciamDataProfile")


def profile_rows(d, dn=None):
    """One row per profiled environment."""
    return [(env_label(one(p, "ciamProfiledEnvironment")), one(p, "ciamCapturedAt")[:8], one(p, "ciamEntryCount"),
             ", ".join(values(p, "ciamHashSchemeCount")), ", ".join(values(p, "ciamLastLoginAge")),
             ", ".join(values(p, "ciamPasswordAge")),
             *(one(p, a) or "" for a in ("ciamLockedCount", "ciamDisabledCount", "ciamPendingCount", "ciamKbaCount",
                                         "ciamGroupCount", "ciamEmptyGroupCount", "ciamLargestGroup",
                                         "ciamDanglingMemberCount", "ciamLargestEntryBytes")))
            for p in profiles(d)]


def attribute_rows(d, dn=None):
    """One row per attribute of each profile: how many entries hold it (and what share), its most values and largest
    value, and whether the record describes it."""
    return [(env_label(one(p, "ciamProfiledEnvironment")), one(a, "ciamLdapName"), one(a, "ciamHolderCount"),
             f"{100 * int(one(a, 'ciamHolderCount')) / max(int(one(p, 'ciamEntryCount')), 1):.1f}%",
             one(a, "ciamMostValues") or "", one(a, "ciamLargestValueBytes") or "",
             "yes" if one(a, "ciamProfiledAttribute") else "no")
            for p in profiles(d) for a in children(d, f"ou=attributes,{p.dn}", "ciamAttributeProfile")]


# ------------------------------------------------------------------ planner
def canonical_scheme(name):
    """A storage scheme's name compared across spellings: {SSHA512} and Salted SHA-512 are the same scheme."""
    s = re.sub(r"^SALTED", "S", re.sub(r"[^A-Z0-9]", "", (name or "").upper()))
    return {"SHA1": "SHA", "SSHA1": "SSHA"}.get(s, s)


def counts(p, attr):
    """((name, count), ...) of a profile's name=count attribute."""
    return tuple((k, int(n)) for k, _, n in (v.rpartition("=") for v in values(p, attr)))


# attributes the data's structure and the password mechanism use, not user data the record should describe
MECHANISM = frozenset(a.lower() for a in ("objectClass", *CONTAINER_RDNS, *STANDARD.password, *STANDARD.last_login,
                                          *STANDARD.password_changed, *(a for a, _ in STANDARD.locked),
                                          *STANDARD.member))


def _undescribed(d, p):
    return tuple((one(a, "ciamLdapName"), one(a, "ciamHolderCount"))
                 for a in children(d, f"ou=attributes,{p.dn}", "ciamAttributeProfile")
                 if not one(a, "ciamProfiledAttribute") and one(a, "ciamLdapName").lower() not in MECHANISM)


def check_data_profile(ctx):
    """The source's user data, from its profile: password schemes no declared policy uses (legacy hashes the target
    must keep accepting, or rehash on login), password values without a scheme, attributes the record doesn't describe
    (no PII class), group members pointing at entries that don't exist, challenge questions; all actions. No profile
    while the source has directory servers is an action too: the data's shape is unknown."""
    d, src = ctx.d, ctx.src
    p = next((p for p in profiles(d) if norm_dn(one(p, "ciamProfiledEnvironment")) == src.env.norm), None)
    owner = responsible(d, src.env)
    if p is None:
        has_ds = any(one(s, "ciamServerRole") == DIRECTORY_SERVER_ROLE for s in src.servers)
        return findings(actions=[("Data", f"The shape of {src.label}'s user data is unknown: profile it "
                                  "(ldapsearch ... | opsdir data-profile) to size the move and find legacy password "
                                  "schemes and attributes the record doesn't describe.", owner, None)]) \
            if has_ds else findings()
    policies = {canonical_scheme(one(pp, "ciamStorageScheme"))
                for pp in children(d, f"ou=password-policies,{DECLARED}", "ciamPasswordPolicy")}
    schemes = counts(p, "ciamHashSchemeCount")
    undescribed = _undescribed(d, p)
    dangling, kba = int(one(p, "ciamDanglingMemberCount", "0")), int(one(p, "ciamKbaCount", "0"))
    actions = [
        *(("Data", f"{n} password value(s) in {src.label} are hashed with {s}, which no declared password policy uses "
           f"as its default storage scheme: keep {s} enabled on {ctx.dst.label}'s servers, or rehash on login "
           "(a deprecated storage scheme).", owner, None)
          for s, n in schemes if s not in (NO_SCHEME, UNRECOGNIZED) and canonical_scheme(s) not in policies),
        *(("Data", f"{n} password value(s) in {src.label} carry no storage scheme (possibly clear text): find and "
           "rehash them before the move.", owner, None) for s, n in schemes if s == NO_SCHEME),
        *(("Data", f"{n} password value(s) in {src.label} use a storage scheme the profile doesn't know: name it in "
           "the product's terms.", owner, None) for s, n in schemes if s == UNRECOGNIZED),
        *((("Data", f"{len(undescribed)} attribute(s) in {src.label}'s user data have no ou=user-schema record, so "
            f"no PII class: {', '.join(f'{a} ({n})' for a, n in undescribed)}. Describe them before the move.",
            owner, None),) if undescribed else ()),
        *((("Data", f"{dangling} member DN(s) of {src.label}'s groups name entries that don't exist (or weren't "
            "profiled): clean them up before the move.", owner, None),) if dangling else ()),
        *((("Data", f"{kba} entries in {src.label} hold challenge questions (KBA), which NIST SP 800-63B no longer "
            "accepts as an authenticator: plan their retirement.", owner, None),) if kba else ())]
    ages = dict(counts(p, "ciamLastLoginAge"))
    idle = ages.get("1-2y", 0) + ages.get(OLDEST, 0)
    return findings(actions=actions, ok=[
        f"{src.label}'s user data was profiled on {one(p, 'ciamCapturedAt')[:8]}: {one(p, 'ciamEntryCount')} "
        f"entries, {idle} not logged in for a year or more, {ages.get(NEVER, 0)} never."])
