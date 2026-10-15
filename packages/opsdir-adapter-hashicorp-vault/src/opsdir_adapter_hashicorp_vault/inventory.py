"""Vault KV inventory (the importer `hashicorp-vault/kv-metadata`): what a key/value mount holds, metadata only, read
from the Vault CLI's listings and KV version 2 metadata into the record's secret-store inventory
(domains.pki.inventory). Pure.

The export holds, per mount, its listings and its paths' metadata, as `opsdir collect` saves them:
  list/<mount>/<prefix>_keys.json   `vault kv list -format=json -mount=<mount> <prefix>`: the keys under a prefix
                                    (the mount's root: list/<mount>/_keys.json; a key ending in / is a folder)
  metadata/<mount>/<path>.json      `vault kv metadata get -format=json -mount=<mount> <path>` (KV 2 only)
A mount is complete when every folder its listings name was listed and, for KV 2, every path has its metadata;
otherwise incomplete, with why. A listing the store refused (Vault's "permission denied") records the mount as
denied. The prefixes listed first are the inventory's prefixes (none when the mount's root was listed). Without any
metadata a mount is a KV 1 store's (listing only): its paths are recorded with no facts.

From the metadata: a path whose current version is deleted (its deletion_time passed by when the inventory was taken)
or destroyed is recorded deleted; updated_time is when the store last changed it (ciamStoreModified), never rotation
(a KV write is not proof the material rotated), so no KV object carries rotation facts and the planner says its
rotation isn't observable. Custom metadata, who changed it and every value are never read.
"""
import json

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import gtime, gtime_of_iso, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.domains.pki.inventory import inventory_entry, inventory_group, object_entry
from opsdir.domains.pki.naming import SECRET_INVENTORY, inventory_scheme_dn

SCHEME = "vault"
KEYS = "_keys.json"
METADATA_FIELDS = ("created_time", "updated_time", "current_version", "oldest_version")
VERSION_FIELDS = ("created_time", "deletion_time", "destroyed")


def locate(rest):
    """Where a vault://<mount>/<path> reference points: (mount, path), or None."""
    mount, _, path = rest.partition("/")
    return (mount, path) if mount and path else None


def listing_path(mount, prefix):
    return f"list/{mount}/{prefix}{KEYS}"


def metadata_path(mount, path):
    return f"metadata/{mount}/{path}.json"


def metadata_only(text):
    """`vault kv metadata get -format=json` output with nothing but what the importer reads (METADATA_FIELDS and each
    version's VERSION_FIELDS): what `opsdir collect` keeps before anything else sees it."""
    try:
        data = json.loads(text).get("data") or {}
    except (ValueError, AttributeError):
        return text
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    return json.dumps({"data": {**{k: data[k] for k in METADATA_FIELDS if k in data},
                                "versions": {n: {k: v[k] for k in VERSION_FIELDS if k in v}
                                             for n, v in versions.items() if isinstance(v, dict)}}},
                      indent=1, sort_keys=True)


def _keys(text):
    """The keys of a listing, or None when it isn't one."""
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return tuple(k for k in doc if isinstance(k, str)) if isinstance(doc, list) else None


def _listings(files):
    """{mount: {prefix: text}} of the export's listings."""
    found = [(*p[len("list/"):-len(KEYS)].partition("/")[::2], files[p]) for p in sorted(files)
             if p.startswith("list/") and p.endswith(KEYS)]
    return {m: {prefix: t for m2, prefix, t in found if m2 == m} for m in dict.fromkeys(m for m, _, _ in found)}


def _metadata(files, mount):
    """{path: metadata data} of a mount's metadata files (None for one that isn't metadata)."""
    head = f"metadata/{mount}/"
    def data(text):
        try:
            return json.loads(text).get("data")
        except (ValueError, AttributeError):
            return None
    return {p[len(head):-len(".json")]: data(files[p]) for p in sorted(files)
            if p.startswith(head) and p.endswith(".json")}


def path_facts(meta, at):
    """The secret object facts of one KV 2 path's metadata, as of the inventory's time."""
    if not isinstance(meta, dict):
        return {}
    current = (meta.get("versions") or {}).get(str(meta.get("current_version"))) or {}
    gone = gtime_of_iso(current.get("deletion_time")) if current.get("deletion_time") else None
    deleted = bool(current.get("destroyed")) or (gone is not None and gone <= at)
    return {"ciamObjectState": "deleted" if deleted else "active",
            "ciamStoreModified": gtime_of_iso(meta.get("updated_time"))}


def mount_listing(listings, meta):
    """(state, problems, prefixes, paths) of one mount: its listings ({prefix: text}) and metadata ({path: data})."""
    denied = [p for p, t in listings.items() if "permission denied" in t]
    if denied:
        return "denied", tuple(f"listing {p or '/'} refused: permission denied" for p in denied), (), ()
    keys = {p: _keys(t) for p, t in listings.items()}
    folders = {p + k for p, ks in keys.items() for k in ks or () if k.endswith("/")}
    paths = tuple(p + k for p, ks in keys.items() for k in ks or () if not k.endswith("/"))
    roots = tuple(p for p in listings if p not in folders)
    unlisted = sorted(folders - set(listings))
    bad = [p for p, ks in keys.items() if ks is None]
    no_meta = [p for p in paths if meta and not isinstance(meta.get(p), dict)]
    problems = (*(f"listing {p or '/'} isn't a key list" for p in bad),
                *((f"{len(unlisted)} folder(s) not listed: {', '.join(unlisted)}",) if unlisted else ()),
                *((f"{len(no_meta)} path(s) without metadata",) if no_meta else ()))
    return ("incomplete" if problems else "complete"), problems, (() if roots == ("",) else roots), paths


def read_kv_metadata(files, d, patterns, at=None):
    """Imported: one inventory per mount in the export (its paths as secret objects), replacing that mount's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the listing was taken)",))
    when = gtime(at)
    groups, notices = [], []
    for mount, listings in _listings(files).items():
        if not rdn_safe(mount):
            notices.append(f"mount {mount!r} can't be named in the record: left out")
            continue
        meta = _metadata(files, mount)
        state, problems, prefixes, paths = mount_listing(listings, meta)
        unnamed = tuple(p for p in paths if not rdn_safe(p))
        problems = (*problems, *((f"{len(unnamed)} path(s) can't be named in the record",) if unnamed else ()))
        state = "incomplete" if unnamed and state == "complete" else state
        objects = tuple(object_entry(d, SCHEME, mount, p, path_facts(meta.get(p), when)) for p in paths
                        if p not in unnamed)
        groups.append(inventory_group(inventory_entry(d, SCHEME, mount, when, state, problems, prefixes), objects))
        notices.append(f"{mount}: {len(objects)} path(s), {state}" + (" (listing only: KV 1)" if not meta else "")
                       + (f" ({'; '.join(problems)})" if problems else ""))
    return Imported(containers=(ou_entry(SECRET_INVENTORY), ou_entry(inventory_scheme_dn(SCHEME))),
                    groups=tuple(groups),
                    notices=(*notices, *(("no listings (list/<mount>/_keys.json, as `opsdir collect` saves them)",)
                                         if not groups and not notices else ())))


KV_METADATA_IMPORTER = Importer("kv-metadata", "Vault key/value mounts' inventory, metadata only (`vault kv list` "
                                               "and `vault kv metadata get` output)", read_kv_metadata)
