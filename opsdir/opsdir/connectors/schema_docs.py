"""The schema reference (documentation/SCHEMA.md and documentation/schema/): how the record stores data, generated
from the same schema fragments the store is built from, so it can't fall behind them (scripts/gen-schema-docs.py
writes it; a unit test compares it with what is committed).

Two layers. The storage layer is a handful of PostgreSQL tables (STORAGE_TABLES, described here by hand and checked
against the migrations): every record entry is one row of `entry`, its attributes a JSON object. The record layer is
what those rows hold: an LDAP-style tree of entries, each with object classes that say which attributes it must and may
have, every attribute typed and classed by portability. One page per part that defines them: the core, each domain,
each installed adapter package that adds definitions under its own OID arc.
"""
import importlib
from typing import NamedTuple

from ..core.naming import SUFFIX
from ..core.standard import ARC, CORE, CUSTOM_ARC, STANDARD_ATTRIBUTES, STANDARD_CLASSES, attribute_oid, class_oid
from .registry import ADAPTERS, DOMAINS, branches_named, core_branches

# One part of the schema with a page: its slug (the page's file name), title, kind (core, domain or package), the
# fragment it defines, what its module says about it, and the branches (container DNs) it names.
Part = NamedTuple("Part", [("slug", str), ("title", str), ("kind", str), ("fragment", object), ("about", str),
                           ("branches", tuple)])

INDEX = "SCHEMA.md"
TITLES = {"pki": "PKI", "webaccess": "Web access"}    # domain titles that aren't the name capitalized
PAGES = "schema"
STANDARD = "standard"             # the anchor prefix of the standard LDAP definitions on the index page

# The storage layer: (table, what it holds, ((column, type, what it holds), ...)), as the migrations create them
# (opsdir/store/sql/migrations; the unit test checks that every table they create is here).
STORAGE_TABLES = (
    ("entry", "Every entry of the record, one row each: its DN, parent, object classes and attributes.", (
        ("id", "bigserial", "primary key"),
        ("dn", "text", "the entry's DN as written"),
        ("dn_norm", "text", "the DN normalized (lower case, no spaces around separators); unique"),
        ("rdn", "text", "its first RDN"),
        ("parent_id", "bigint", "the parent entry (an entry with children can't be deleted); none for a naming "
                                "context"),
        ("object_classes", "text[]", "its object classes, in the order written"),
        ("attrs", "jsonb", "its attributes: {\"attribute\": [\"value\", ...]}, every value checked against the "
                           "attribute's type, rules and vocabulary on write"),
        ("created_at", "timestamptz", "when it was added"),
        ("modified_at", "timestamptz", "when it was last written"),
        ("modified_by", "text", "the login that last wrote it"),
        ("change_id", "text", "the change record it was last written under (`cn=<change>,ou=changes`)"))),
    ("entry_ref", "Every DN-valued attribute value that points at another entry: what keeps references intact (an "
                  "entry something points at can't be deleted).", (
        ("from_id", "bigint", "the entry holding the reference"),
        ("attr", "text", "the attribute holding it"),
        ("to_id", "bigint", "the entry it points at"))),
    ("entry_history", "Append-only history: one row per write to an entry, added only by the store's write trigger "
                      "(which sets who and when), never updated or deleted.", (
        ("id", "bigserial", "primary key"),
        ("dn", "text", "the entry written"),
        ("op", "text", "add, modify or delete"),
        ("old_attrs", "jsonb", "its attributes before"),
        ("new_attrs", "jsonb", "its attributes after"),
        ("old_classes", "text[]", "its object classes before"),
        ("new_classes", "text[]", "its object classes after"),
        ("change_id", "text", "the approved change it was written under"),
        ("at", "timestamptz", "when"),
        ("db_user", "text", "who wrote it: the person the HTTP API acts for when written through the API login "
                            "(the api-login setting), else the session's own login, whatever role it set"),
        ("client", "text", "the API client it came through (the token's azp or client_id); empty for a direct login"),
        ("teams", "text[]", "the teams mapped to identity provider groups the person held through their token; empty "
                            "for a direct login"))),
    ("attribute_type", "The schema registry's attribute types: the standard LDAP ones the record uses and every "
                       "one this reference lists, synced from the schema fragments on every upgrade.", (
        ("name", "text", "canonical name (primary key)"),
        ("lname", "text", "the name in lower case; unique"),
        ("oid", "text", "its OID; unique"),
        ("syntax_oid", "text", "the LDAP syntax"),
        ("equality", "text", "the LDAP equality matching rule"),
        ("value_type", "text", "X-VALUE-TYPE: what a value must look like"),
        ("portability", "text", "X-PORTABILITY: intent, contract, binding, secret-ref, observed or meta"),
        ("single_value", "boolean", "at most one value"),
        ("description", "text", "what it holds"),
        ("origin", "text", "the part that defines it"),
        ("rules", "jsonb", "value rules beyond the type: X-MIN, X-MAX, X-PATTERN, X-MAX-LENGTH, X-OVERRIDABLE"))),
    ("object_class", "The schema registry's object classes.", (
        ("name", "text", "canonical name (primary key)"),
        ("lname", "text", "the name in lower case; unique"),
        ("oid", "text", "its OID; unique"),
        ("sup", "text", "its superclass"),
        ("kind", "text", "ABSTRACT, STRUCTURAL or AUXILIARY"),
        ("must", "text[]", "the attributes an entry of the class must have"),
        ("may", "text[]", "the attributes it may have"),
        ("description", "text", "what it is"),
        ("origin", "text", "the part that defines it"))),
    ("vocabulary", "The values a `vocab` attribute accepts, each declared by an installed domain or adapter.", (
        ("attr", "text", "the attribute"),
        ("value", "text", "a value it accepts"),
        ("owner", "text", "the domain or adapter that declares it"))),
    ("secret_pattern", "The forms secret material takes, refused in every value (no secret is ever stored).", (
        ("name", "text", "primary key"),
        ("pattern", "text", "a regular expression"),
        ("owner", "text", "the core, or the adapter that registers it"),
        ("description", "text", "what it catches"))),
    ("ref_scheme", "The reference schemes (`aws-sm://`, `vault://`, ...) the installed adapters own: a `ref-uri` "
                   "value must use one.", (
        ("scheme", "text", "primary key"),)),
    ("suffix", "The naming contexts: the roots of the tree (`dc=ciam-ops`).", (
        ("dn_norm", "text", "primary key"),)),
    ("schema_migration", "The migrations applied, each once, with its checksum.", (
        ("version", "int", "primary key"),
        ("name", "text", "the migration's name"),
        ("checksum", "text", "its SHA-256 when applied"),
        ("applied_at", "timestamptz", "when"))),
    ("workspace_base", "Only in a migration workspace database: the live snapshot it was copied from (one row).", (
        ("id", "int", "always 1"),
        ("source", "text", "the live database it was copied from (no password)"),
        ("created_at", "timestamptz", "when"),
        ("fingerprint", "text", "SHA-256 of base_ldif"),
        ("base_ldif", "text", "the live record as exported then"))),
)
# The storage layer's references: (from table, to table, label)
STORAGE_LINKS = (("entry", "entry", "parent_id"), ("entry", "entry_ref", "from_id / to_id"),
                 ("attribute_type", "entry_ref", "attr"), ("attribute_type", "vocabulary", "attr"),
                 ("object_class", "object_class", "sup"))


def _doc(module_name):
    """The docstring of a module, '' when it has none or can't be imported."""
    try:
        return (importlib.import_module(module_name).__doc__ or "").strip()
    except ImportError:
        return ""


def _about(doc):
    """What a schema module's docstring says about its part: all of it but a first line that only says it is a schema
    fragment."""
    first, _, rest = doc.partition("\n")
    boilerplate = "schema fragment: its attribute types and object classes" in first
    return " ".join((rest if boilerplate else doc).split())


def documented_parts(domains=DOMAINS, adapters=ADAPTERS):
    """(Part, ...) of the schema reference: the core (with the branches core.naming and core.settings name), each
    domain (its schema module's docstring, its naming module's branches), then each adapter that defines its own
    attributes or classes (its product's name, its schema module's docstring). Reads the modules' docstrings and
    constants."""
    core = Part("core", "Core", "core", CORE, "The definitions every entry builds on.", core_branches())
    own = tuple(Part(d.name, TITLES.get(d.name, d.name.capitalize()), "domain", d.schema,
                     _about(_doc(f"opsdir.domains.{d.name}.schema")), branches_named(f"opsdir.domains.{d.name}.naming"))
                for d in domains)
    packages = tuple(Part(a.name, f"{a.products[0][0] if a.products else a.name} (opsdir-adapter-{a.name})", "package",
                          a.schema, _about(_doc(f"opsdir_adapter_{a.name.replace('-', '_')}.schema")), ())
                     for a in adapters if a.schema and (a.schema.attributes or a.schema.classes))
    return (core, *own, *packages)


def _cell(text):
    return " ".join(str(text).split()).replace("|", "\\|")


def _code(text):
    return f"`{_cell(text)}`" if text else ""


def _row(cells):
    return "| " + " | ".join(cells) + " |"


def _table(headers, rows):
    return (_row(headers), _row(tuple("---" for _ in headers)), *(_row(r) for r in rows))


def _anchor(prefix, name):
    return f"{prefix}-{name.lower()}"


def _where(parts):
    """{attribute or class name (lower case): (kind 'a' or 'c', page slug, canonical name)} of every definition, the
    standard ones on the index page."""
    standard = {**{n.lower(): ("a", None, n) for n, *_ in STANDARD_ATTRIBUTES},
                **{n.lower(): ("c", None, n) for n, *_ in STANDARD_CLASSES}}
    return {**standard, **{a.name.lower(): ("a", p.slug, a.name) for p in parts for a in p.fragment.attributes},
            **{c.name.lower(): ("c", p.slug, c.name) for p in parts for c in p.fragment.classes}}


def _link(where, name, here):
    """A Markdown link to a definition from the page of slug here."""
    found = where.get(name.lower())
    if found is None:
        return _code(name)
    kind, slug, canonical = found
    anchor = _anchor(STANDARD if slug is None else kind, canonical)
    if slug == here:
        target = ""
    elif slug is None:
        target = f"../{INDEX}"
    else:
        target = f"{slug}.md"
    return f"[`{canonical}`]({target}#{anchor})"


def _type(a, values):
    """An attribute's value type as shown: an enum's values listed, a vocab attribute's registered values with who
    declares them."""
    if a.value_type.startswith("enum:"):
        return "enum: " + ", ".join(_code(v) for v in a.value_type[5:].split("|"))
    if a.value_type == "vocab":
        held = values.get(a.name, ())
        return "vocab" + (": " + ", ".join(f"{_code(v)} ({o})" for v, o in held) if held else "")
    return _code(a.value_type)


def _rules(a):
    return "; ".join(f"{k} {_code(v)}" for k, v in a.rules)


def _definitions(parts):
    """{attribute name (lower case): (value type, single or multi, description)} of every attribute, the standard
    ones included."""
    return {**{n.lower(): (vt, "", d) for n, vt, _, d in STANDARD_ATTRIBUTES},
            **{a.name.lower(): (a.value_type, "single" if a.single_value else "multi", a.description)
               for p in parts for a in p.fragment.attributes}}


def _shown_type(value_type):
    return "enum" if value_type.startswith("enum:") else value_type


def _class_section(part, c, where, defined):
    def fields(names, required):
        return tuple((_link(where, n, part.slug), "yes" if required else "",
                      _code(_shown_type(defined.get(n.lower(), ("", "", ""))[0])),
                      defined.get(n.lower(), ("", "", ""))[1], _cell(defined.get(n.lower(), ("", "", ""))[2]))
                     for n in names if n.lower() != "objectclass")
    inherited = f" · inherits {_link(where, c.sup, part.slug)}" if c.sup and c.sup != "top" else ""
    rows = (*fields(c.must, True), *fields(c.may, False))
    return (f'<a id="{_anchor("c", c.name)}"></a>', f"### {c.name}", "",
            _cell(c.description), "",
            f"OID `{class_oid(part.fragment, c)}` · {c.kind.lower()}{inherited}", "",
            *((*_table(("Field", "Required", "Type", "Values", "Description"), rows), "") if rows else ()))


def _attribute_rows(part, values):
    return tuple((f'<a id="{_anchor("a", a.name)}"></a>`{a.name}`', _code(attribute_oid(part.fragment, a)),
                  _type(a, values), a.portability, "single" if a.single_value else "multi", _rules(a),
                  _cell(a.description))
                 for a in sorted(part.fragment.attributes, key=lambda a: a.name.lower()))


def part_page(part, where, values, defined):
    """The Markdown page of one part: what it is, its arc, branches, object classes (each field linked to its
    definition) and attributes."""
    f = part.fragment
    classes = sorted(f.classes, key=lambda c: c.name.lower())
    head = (f"# {part.title}", "",
            f"*{part.kind.capitalize()} · OID arc `{f.arc}` · {len(classes)} object classes · {len(f.attributes)} "
            f"attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit "
            f"by hand. How to read it: [{INDEX}](../{INDEX}).*", "",
            *((part.about, "") if part.about else ()),
            *(("**Branches:** " + ", ".join(_code(b) for b in part.branches), "") if part.branches else ()))
    sections = tuple(line for c in classes for line in _class_section(part, c, where, defined))
    body = (*(("## Object classes", "", *sections) if classes else ()),
            *(("## Attributes", "",
               *_table(("Attribute", "OID", "Type", "Portability", "Values", "Rules", "Description"),
                       _attribute_rows(part, values)), "") if f.attributes else ()))
    return "\n".join((*head, *body)).rstrip() + "\n"


def _mermaid_id(text):
    return "".join(ch if ch.isalnum() else "_" for ch in text)


def _er_diagram():
    def entity(name, columns):
        return (f"    {name} {{", *(f'        {kind.replace("[]", "_array")} {column}' for column, kind, _ in columns),
                "    }")
    return ("```mermaid", "erDiagram",
            *(f'    {a} ||--o{{ {b} : "{label}"' for a, b, label in STORAGE_LINKS),
            *(line for name, _, columns in STORAGE_TABLES for line in entity(name, columns)), "```")


def _tree(parts):
    """The directory tree as a Mermaid flowchart: the suffix, then every branch the parts name under its parent."""
    branches = sorted({b for p in parts for b in p.branches}, key=lambda dn: tuple(reversed(dn.lower().split(","))))
    held = {b.lower() for b in branches}

    def parent(dn):
        up = dn.split(",", 1)[1]
        return up if up.lower() in held else SUFFIX
    return ("```mermaid", "flowchart LR", f'    {_mermaid_id(SUFFIX)}["{SUFFIX}"]',
            *(f'    {_mermaid_id(parent(b))} --> {_mermaid_id(b)}["{b.split(",", 1)[0]}"]' for b in branches), "```")


def _storage_section():
    return ("## The storage layer (PostgreSQL)", "",
            "The record is one PostgreSQL schema, `opsdir`. Every entry is a row of `entry`, its attributes a JSON "
            "object; the registry tables say what a valid entry is, and the store checks every write against them "
            "(triggers: schema, tree, references, vocabulary, value rules, no secret material, an approved change, the "
            "writer's grants) and appends it to `entry_history`. Views and report functions are re-created on every "
            "upgrade (`opsdir/store/sql/definitions`); the tables only change through a new migration "
            "(`opsdir/store/sql/migrations`).", "", *_er_diagram(), "",
            *(line for name, what, columns in STORAGE_TABLES
              for line in (f"### {name}", "", what, "", *_table(("Column", "Type", "Holds"),
                                                                  tuple((f"`{c}`", f"`{t}`", _cell(h))
                                                                        for c, t, h in columns)), "")))


def _standard_section():
    attrs = tuple((f'<a id="{_anchor(STANDARD, n)}"></a>`{n}`', _code(vt), p, _cell(d))
                  for n, vt, p, d in STANDARD_ATTRIBUTES)
    classes = tuple((f'<a id="{_anchor(STANDARD, n)}"></a>`{n}`', _cell(d)) for n, d in STANDARD_CLASSES)
    return ("## Standard LDAP definitions the record uses", "",
            "Defined by the LDAP standards (RFC 4512, 4519, 4524), not by CIAMstack: the record uses them as the "
            "standards define them and adds a value type and a portability class to each attribute.", "",
            *_table(("Attribute", "Type", "Portability", "Description"), attrs), "",
            *_table(("Object class", "Description"), classes), "")


def index_page(parts):
    """SCHEMA.md: how to read the reference, the storage layer, the directory tree, the standard definitions used and
    an index of the parts."""
    counts = (sum(len(p.fragment.attributes) for p in parts), sum(len(p.fragment.classes) for p in parts))
    rows = tuple((f"[{p.title}]({PAGES}/{p.slug}.md)", p.kind, _code(p.fragment.arc), str(len(p.fragment.classes)),
                  str(len(p.fragment.attributes))) for p in parts)
    branch_rows = tuple((_code(b), f"[{p.title}]({PAGES}/{p.slug}.md)") for p in parts for b in p.branches)
    return "\n".join((
        "# The record's schema", "",
        "*Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand.*", "",
        "How CIAMstack stores the platform's record, in two layers: a few PostgreSQL tables (the storage layer), and "
        "the entries those tables hold (the record layer), shaped like an LDAP directory. Every entry sits at a DN in "
        f"one tree under `{SUFFIX}`, has object classes that say which attributes it must and may have, and every "
        "attribute has a value type and a portability class. The published LDAP form of the same definitions is "
        "`opsdir/schema/ciam-ops.schema.ldif`; the rules the store enforces are in "
        "[`opsdir/SPEC.md`](../opsdir/SPEC.md).",
        "",
        f"This reference covers the core, its domains and the installed adapter packages that add definitions: "
        f"{counts[1]} object classes and {counts[0]} attributes. Fields and record types an operator defines live in "
        f"the record itself (`ou=custom-schema`, OIDs under `{CUSTOM_ARC}`), so they differ per record and aren't "
        "listed here.", "",
        "## How to read it", "",
        "- **Object classes** list their fields: *required* ones (MUST) and the rest (MAY). A class inherits its "
        "superclass's fields.",
        f"- **OIDs** are the arc of the part that defines them, then `.1.<n>` for attributes and `.2.<n>` for "
        f"classes. The core and its domains share `{ARC}`; each adapter package has its own arc.",
        "- **Portability** says what happens to a value between environments and in a move: `intent` (the same "
        "everywhere), `contract` (names others depend on: must not change), `binding` (rewritten per environment), "
        "`secret-ref` (a reference to a secret, never the secret), `observed` (measured from the live system: "
        "evidence, never rendered), `meta` (ownership, status, dates, history). See SPEC §3.1.",
        "- **Type** is stricter than an LDAP syntax: `string`, `int`, `bool`, `time` (`YYYYMMDDhhmmssZ`), `dn` (an "
        "entry of the record), `extdn` (a DN in another directory), `cidr`, `ip`, `fqdn`, `url`, `port`, `ref-uri` (a "
        "secret reference in a scheme an installed adapter owns), `json`, `enum` (the values listed) or `vocab` (the "
        "values installed domains and adapters declare). See SPEC §3.2.",
        "- **Values** is single or multi-valued. **Rules** are checked on every value: `X-MIN`, `X-MAX`, "
        "`X-PATTERN`, `X-MAX-LENGTH`; `X-OVERRIDABLE` marks intent an environment may override.", "",
        *_storage_section(),
        "## The record layer: the directory tree", "",
        f"The branches the core and its domains name, under the suffix `{SUFFIX}`. Environments hold their own "
        "subtree (`env=<env>,cloud=<cloud>,ou=environments`, with `ou=bindings` for what is bound there); adapter "
        "packages add branches of their own (see their pages).", "",
        *_tree(parts), "",
        *_table(("Branch", "Defined by"), branch_rows), "",
        "## The parts", "",
        *_table(("Part", "Kind", "OID arc", "Object classes", "Attributes"), rows), "",
        *_standard_section())).rstrip() + "\n"


def schema_pages(parts, vocabulary=()):
    """{path relative to documentation/: Markdown} of the schema reference: the index page and one page per part.
    vocabulary: (attribute, value, owner) of every registered `vocab` value (registry.vocabulary)."""
    where = _where(parts)
    values = {attr: tuple((v, o) for a, v, o in vocabulary if a == attr)
              for attr in dict.fromkeys(a for a, _, _ in vocabulary)}
    defined = _definitions(parts)
    return {INDEX: index_page(parts),
            **{f"{PAGES}/{p.slug}.md": part_page(p, where, values, defined) for p in parts}}
