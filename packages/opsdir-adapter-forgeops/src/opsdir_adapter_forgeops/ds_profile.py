"""ForgeOps' DS image inputs (render target config-profiles, milestone 114), and what ForgeOps' DS can't take from the
record, as render notes. Pure.

ForgeOps runs DS (ds-idrepo, ds-cts) from one image built from its docker/ds folder. DS has no config profile: the
image carries custom schema (config/schema/*.ldif) and LDAP entries per backend (ldif-ext/<folder>/*.ldif), which a
pod loads when it sets up an empty volume, and only then. From PingDS's profile (its ldap/schema.ldif and
ldap/dit.ldif, core.profiles), per namespace running DS with ForgeOps, forgeops/config-profiles/<ns>/ds/ holds:

  config/schema/90-opsdir.ldif   the record's schema definitions as one cn=schema entry (DS's schema-file form, as
                                 ForgeOps' sample config/schema/99-ext.ldif)
  ldif-ext/<folder>/opsdir.ldif  the record's tree entries below the base DN of the backend serving the folder (the
                                 base entry itself is the setup profile's)
  append-ldif-ext.sh             run by the Dockerfile: each LDIF appended to the base-entries template its
                                 backend's setup profile imports, as ds-setup.sh does (release.DS_BACKENDS: the
                                 highest version of the profile's folder holding one, chosen in the image), without
                                 the entries that template already creates (a duplicate fails the import)
  Dockerfile                     FROM the record's DS image (built from ForgeOps' docker/ds): the schema into the
                                 custom-schema folder, then append-ldif-ext.sh

The two folders are docker/ds's own too: copied into a ForgeOps checkout, `forgeops build ds` builds the same.

Render notes (Adapter.notes), wherever ForgeOps runs DS, each written in the namespace's DS Dockerfile when it is
rendered: a record backend under none of ForgeOps' base DNs (its entries are in no image: ForgeOps' DS sets up only
its own backends), and the record's DS configuration and ACIs (the PingDS render's ds/dsconfig.batch and
ds/acis.ldif), to apply online once the pods run: the identity-platform chart mounts its own setup scripts over the
image's, so no image can carry them.
"""
from opsdir.core.directory import get, norm_dn, one, rdn_value, subtree, within
from opsdir.core.formats import DOCKERFILE, LDIF, SHELL
from opsdir.core.interchange.ldif import parse, write_entry
from opsdir.core.manifest import header
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.directory.naming import ACIS, DECLARED
from .components import DS_STORES, image_of, placements
from .release import (CONFIG_PROFILES, DS_APPEND, DS_BACKENDS, DS_CONTEXT, DS_CUSTOM_SCHEMA, DS_LDIF_FILE,
                      DS_PRODUCT, DS_SCHEMA_FILE, DS_TEMPLATES, VERSION)

AREA = "ForgeOps"
_SCHEMA_TYPES = ("attributeTypes", "objectClasses")
_SCHEMA_CLASSES = ("top", "ldapSubentry", "subschema")
_STAGE = "/tmp/opsdir-ldif-ext"
# The build step's body: append FOLDER PROFILE FILL appends ldif-ext/FOLDER/<file> to the highest version of the
# setup profile's folder holding base-entries.ldif, leaving out each entry whose DN the template already has (its
# &{...} parameter read as FILL; DNs unfolded, compared lower-cased without spaces around , and =).
_APPEND = r"""set -eu
here=$(dirname "$0")
append() {
  t=$(ls "@TEMPLATES@/$2"/*/base-entries.ldif | sort -V | tail -n 1)
  awk -v fill="$3" '
    BEGIN { RS = ""; ORS = "\n\n" }
    { r = $0; gsub(/\n /, "", r); d = ""; n = split(r, l, "\n")
      for (i = 1; i <= n; i++) if (tolower(substr(l[i], 1, 3)) == "dn:") { d = tolower(substr(l[i], 4)); break }
      gsub(/&\{[^}]*\}/, tolower(fill), d); gsub(/ /, "", d) }
    FNR == NR { if (d != "") seen[d] = 1; next }
    d == "" || !(d in seen) { print }
  ' "$t" "$here/ldif-ext/$1/@LDIF@" > "$here/$1.add"
  printf '\n' >> "$t"
  cat "$here/$1.add" >> "$t"
}
"""
# what the record declares that the PingDS render writes into ds/dsconfig.batch: (object class, what it is)
_DECLARED = (("ciamIndex", "indexes"), ("ciamPasswordPolicy", "password policies"),
             ("ciamConnectionHandler", "connection handlers"), ("ciamLogPublisher", "log publishers"))


def schema_entry(text):
    """The definitions a subschema modify LDIF adds (ldap/schema.ldif) as one cn=schema entry, DS's schema-file form
    (attribute types, then object classes, each in the order given), or None when it adds none."""
    found = {t: tuple(v for r in parse(text) for op, attr, vals in r.mods
                      if op == "add" and attr.lower() == t.lower() for v in vals) for t in _SCHEMA_TYPES}
    held = {t: vals for t, vals in found.items() if vals}
    return write_entry("cn=schema", _SCHEMA_CLASSES, {"cn": ("schema",), **held}) if held else None


def backend_of(dn):
    """The ForgeOps DS backend (release.DsBackend) whose base DN holds dn, or None."""
    return next((b for b in DS_BACKENDS if within(dn, b.base_dn)), None)


def ldif_ext(text):
    """{ldif-ext folder: (entry LDIF, ...)}: the content entries of a tree LDIF (ldap/dit.ldif) below a ForgeOps
    backend's base DN, in the order given, by the folder of that backend; base entries and entries no backend holds
    are left out."""
    placed = [(b.folder, write_entry(r.dn, r.attrs.get("objectClass", ()),
                                     {k: v for k, v in r.attrs.items() if k != "objectClass"}))
              for r in parse(text) if r.changetype == "add"
              for b in (backend_of(r.dn),) if b and norm_dn(r.dn) != norm_dn(b.base_dn)]
    return {f: tuple(e for g, e in placed if g == f) for f in dict.fromkeys(f for f, _ in placed)}


def record_backends(d):
    """The user directory's declared backends (ciamBackend under ou=backends of the declared configuration)."""
    return subtree(d, f"ou=backends,{DECLARED}", "ciamBackend")


def _bases():
    return ", ".join(b.base_dn for b in DS_BACKENDS)


def _unserved_note(m, p, be):
    base, name = one(be, "ciamBaseDn"), rdn_value(be)
    return note(AREA, "action", f"backend {name}",
                f"ForgeOps' DS in {m.label} (namespace {p.namespace}) sets up only {_bases()}: backend {name} "
                f"({base}) is none of them, so its entries (ldap/dit.ldif) are in no DS image",
                (f"create backend {name} for {base} on the DS pods once they run (dsconfig create-backend) and add its "
                 "entries online (ldapadd -c -f ldap/dit.ldif)",
                 f"or give the backend a base DN ForgeOps serves ({_bases()}) {RECORD}"),
                entry=be.dn, scope=f"namespace {p.namespace}")


def declared_config(d):
    """What the record declares that the PingDS render writes as ds/dsconfig.batch and ds/acis.ldif, by kind
    (indexes, password policies, connection handlers, log publishers, replication, ACIs), in that order."""
    topology = get(d, f"cn=topology,ou=replication,{DECLARED}")
    return (*(what for cls, what in _DECLARED if subtree(d, DECLARED, cls)),
            *(("replication",) if topology and one(topology, "ciamReplicationPurgeDelay") else ()),
            *(("ACIs",) if subtree(d, ACIS, "ciamAci") else ()))


def renamed(d):
    """((record backend name, ForgeOps backend name), ...): record backends at a ForgeOps base DN under another name
    (the batch's create-backend-index lines name the record's)."""
    return tuple((rdn_value(be), b.name) for be in record_backends(d) for b in DS_BACKENDS
                 if norm_dn(one(be, "ciamBaseDn") or "") == norm_dn(b.base_dn) and rdn_value(be) != b.name)


def _config_note(m, p, kinds):
    names = renamed(m.d)
    rename = (f"the batch's create-backend-index lines name the record's backends: name ForgeOps' instead "
              f"({', '.join(f'{r} is {f}' for r, f in names)}), or rename the record's {RECORD}",) if names else ()
    return note(AREA, "action", "DS configuration",
                f"ForgeOps' DS in {m.label} (namespace {p.namespace}) takes the record's {', '.join(kinds)} from no "
                "image (the identity-platform chart mounts its own setup scripts over the image's): apply the "
                "PingDS render's ds/dsconfig.batch and ds/acis.ldif online once the pods run",
                ("dsconfig --hostname <ds pod> --port 4444 --bindDN uid=admin --bindPasswordFile <file> --trustAll "
                 "--batchFilePath ds/dsconfig.batch --no-prompt",
                 "ldapmodify --hostname <ds pod> --port 1636 --useSsl --bindDN uid=admin --bindPasswordFile <file> "
                 "ds/acis.ldif",
                 *rename,
                 "apply them again wherever a pod sets up an empty volume (a new replica, a restore)"),
                entry=DECLARED, scope=f"namespace {p.namespace}")


def placement_notes(m, p):
    """The render notes of a placement running DS (ds-idrepo or ds-cts): each record backend ForgeOps' DS doesn't
    serve, and the record's DS configuration and ACIs to apply online; () when ForgeOps runs no DS there."""
    if not set(DS_STORES) & set(p.on):
        return ()
    kinds = declared_config(m.d)
    return (*(_unserved_note(m, p, be) for be in record_backends(m.d) if not backend_of(one(be, "ciamBaseDn") or "")),
            *((_config_note(m, p, kinds),) if kinds else ()))


def ds_notes(m, services):
    """Adapter.notes of the ForgeOps adapter: every placement's DS render notes (placement_notes)."""
    return tuple(n for p in placements(m) for n in placement_notes(m, p))


def _append_script(m, p, folders):
    """The build step appending each ldif-ext folder's LDIF to its setup profile's template (_APPEND)."""
    by_folder = {b.folder: b for b in DS_BACKENDS}
    calls = "".join(f"append {f} {by_folder[f].template} {by_folder[f].fill}\n" for f in folders)
    return ("#!/bin/sh\n" + header(m, f"ForgeOps {VERSION} DS build step for namespace {p.namespace}: append the "
                                       "record's entries to the setup profiles' base-entries templates", SHELL)
            + _APPEND.replace("@TEMPLATES@", DS_TEMPLATES).replace("@LDIF@", DS_LDIF_FILE) + calls)


def _dockerfile(m, p, schema, folders):
    store = next(c for c in DS_STORES if c in p.on)
    what = (f"ForgeOps {VERSION} DS image inputs for namespace {p.namespace}: build this folder with --build-arg "
            f"BASE_IMAGE=<the DS image built from ForgeOps' docker/ds: {image_of(m, p, store)} is what the release "
            "runs> and push it as the image the record names for ds-idrepo and ds-cts")
    notes = "".join(f"# {note_comment(n)}\n" for n in placement_notes(m, p))
    return (header(m, what, DOCKERFILE) + notes + "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n\n"
            + (f"COPY --chown=forgerock:root config/schema/ {DS_CUSTOM_SCHEMA}/\n" if schema else "")
            + (f"COPY --chown=forgerock:root ldif-ext/ {_STAGE}/ldif-ext/\n"
               f"COPY --chown=forgerock:root {DS_APPEND} {_STAGE}/\n"
               f"RUN sh {_STAGE}/{DS_APPEND} && rm -rf {_STAGE}\n" if folders else ""))


def ds_context(m, p, profiles):
    """{path: text}: a placement's DS image inputs (forgeops/config-profiles/<ns>/ds/: config/schema/90-opsdir.ldif,
    ldif-ext/<folder>/opsdir.ldif, the Dockerfile) from PingDS's profile tree among the products' (ldap/schema.ldif,
    ldap/dit.ldif); {} when ForgeOps runs no DS there or the record gives it neither schema nor entries."""
    tree = profiles.get(DS_PRODUCT) or {}
    if not set(DS_STORES) & set(p.on) or not tree:
        return {}
    schema = schema_entry(tree.get("ldap/schema.ldif", ""))
    entries = ldif_ext(tree.get("ldap/dit.ldif", ""))
    if not schema and not entries:
        return {}
    root = f"forgeops/{CONFIG_PROFILES}/{p.namespace}/{DS_CONTEXT}"
    head = (lambda what: header(m, f"ForgeOps {VERSION} DS {what} for namespace {p.namespace}", LDIF))
    folders = tuple(b.folder for b in DS_BACKENDS if b.folder in entries)
    return {f"{root}/Dockerfile": _dockerfile(m, p, schema, folders),
            **({f"{root}/{DS_APPEND}": _append_script(m, p, folders)} if folders else {}),
            **({f"{root}/config/schema/{DS_SCHEMA_FILE}": head("custom schema") + "\n" + schema} if schema else {}),
            **{f"{root}/ldif-ext/{f}/{DS_LDIF_FILE}": head(f"entries for the {f} backend") + "\n"
               + "\n".join(entries[f]) for f in folders}}

