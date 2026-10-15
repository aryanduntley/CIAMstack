"""What every OSCAL document opsdir writes or reads shares: the OSCAL version it is written against, opsdir's own
property namespace, identifiers derived from the record (never random, so a document is the same every time it is
written from the same record), times, metadata, control ids between the record's form and OSCAL's, and the notes that
name what the record doesn't hold. Pure.

A field OSCAL requires that the record doesn't hold is written as UNBOUND:<what> (opsdir's mark for a value nothing in
the record supplies) and named in a note for the team that owns it, never invented."""
import datetime as dt
import re
import uuid
from typing import NamedTuple

from opsdir.core.directory import gtime_at, norm_dn, one
from opsdir.core.environment import UNBOUND
from opsdir.core.notes import note

OSCAL_VERSION = "1.2.3"            # the OSCAL release the writers target (readers accept any 1.x)
NS = "urn:opsdir:oscal"            # the namespace of the properties opsdir writes and reads back
AREA = "Compliance"
EPOCH = "1970-01-01T00:00:00Z"     # last-modified of a document whose entries hold no date and no day was given
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, NS)
_NIST_53 = ("nist-800-53", "fedramp-")      # frameworks whose controls are SP 800-53's
_ENHANCEMENT = re.compile(r"\((\w+)\)")
_TOKEN = re.compile(r"^[^\W\d][\w.-]*$")
_SLUG = re.compile(r"[^a-z0-9]+")


# A document opsdir wrote: the OSCAL JSON value, and the RenderNotes naming what it holds as UNBOUND (or leaves out).
OscalDoc = NamedTuple("OscalDoc", [("document", dict), ("notes", tuple)])


def uid(*parts):
    """A UUID (version 5) of the parts: the same parts give the same id."""
    return str(uuid.uuid5(_NAMESPACE, "\x1f".join(parts)))


def entry_uid(kind, e, *more):
    """The UUID of what an entry is written as (kind: poam-item, risk, finding, ...), by its DN as the record compares
    DNs: the same entry is the same object in every document and every revision."""
    return uid(kind, norm_dn(e.dn), *more)


def unbound(what):
    """The mark written where OSCAL requires a value the record doesn't hold."""
    return f"{UNBOUND}{what}"


def slug(text):
    """A file or container name of free text: lower case, runs of other characters as '-'."""
    return _SLUG.sub("-", str(text).lower()).strip("-") or "unnamed"


def iso(gt):
    """The OSCAL date-time of a GeneralizedTime (20261102000000Z -> 2026-11-02T00:00:00Z), or None."""
    return gtime_at(gt).strftime("%Y-%m-%dT%H:%M:%SZ") if gt else None


def day_iso(day):
    """The OSCAL date-time of a day (midnight UTC)."""
    return f"{day.isoformat()}T00:00:00Z" if isinstance(day, dt.date) else None


def last_modified(entries, attrs, as_of=None):
    """When the documented entries last changed, as the record dates them (the latest of their attrs), else the day
    given, else EPOCH: never the time of writing."""
    held = sorted(v for e in entries for a in attrs for v in (one(e, a),) if v)
    return iso(held[-1]) if held else day_iso(as_of) or EPOCH


def metadata(title, modified, version=None):
    """An OSCAL metadata block: the document's version is the one the record names, else when it last changed."""
    return {"title": title, "last-modified": modified, "version": version or modified, "oscal-version": OSCAL_VERSION}


def prop(name, value):
    """An opsdir property (namespace NS)."""
    return {"name": name, "ns": NS, "value": str(value)}


def props(pairs):
    """opsdir properties of (name, value) pairs whose value is held, in order."""
    return [prop(n, v) for n, v in pairs if v not in (None, "")]


def prop_values(obj, name):
    """The values of an object's opsdir properties of a name (a document's own NS, or none, which a person writes)."""
    return tuple(p.get("value") for p in obj.get("props") or () if isinstance(p, dict) and p.get("name") == name
                 and p.get("ns") in (NS, None) and p.get("value"))


def prop_value(obj, name):
    """The first value of an object's opsdir property of a name, or None."""
    found = prop_values(obj, name)
    return found[0] if found else None


def is_53(framework):
    """Whether a framework's controls are SP 800-53's (its catalog's lower-case ids, enhancements dotted)."""
    return framework.startswith(_NIST_53)


def control_id(ref):
    """(framework, OSCAL control id) of a record control ref (framework:control). SP 800-53's are lower case with
    enhancements dotted (SC-13 -> sc-13, AC-2(1) -> ac-2.1); a digit-led id (SP 800-171's 3.13.11) is not an OSCAL
    token and is written behind '_' (_3.13.11, interim: the catalogs' own ids differ); others as recorded."""
    framework, control = ref.split(":", 1)
    oscal = _ENHANCEMENT.sub(r".\1", control).lower() if is_53(framework) else control
    return framework, f"_{oscal}" if oscal[:1].isdigit() else oscal


def control_ref(framework, oscal):
    """The record control ref of an OSCAL control id under a framework: control_id's inverse."""
    plain = oscal[1:] if oscal.startswith("_") else oscal
    if is_53(framework):
        base, _, enhancement = plain.partition(".")
        plain = base.upper() + (f"({enhancement})" if enhancement else "")
    return f"{framework}:{plain}"


def is_token(text):
    """Whether text is an OSCAL token (an XML NCName): what a control id must be."""
    return bool(_TOKEN.match(text))


def oscal_version_major(doc):
    """The major OSCAL version a document's metadata states, or None."""
    version = str((doc.get("metadata") or {}).get("oscal-version") or "")
    return version.split(".")[0] or None


def unbound_note(subject, entry, fields, how):
    """The note naming the UNBOUND fields of a document, for the owner of the entry it documents."""
    return note(AREA, "action", subject, f"written with UNBOUND values the record doesn't hold: {', '.join(fields)}",
                how, entry=entry)
