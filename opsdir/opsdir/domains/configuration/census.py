"""The census: where the record's values are copied into files (config files, templates, scripts, exports). Pure.

Every value the record holds that other systems copy (hostnames, IP addresses and networks, service names, bind and
base DNs, URLs and entity IDs, certificate fingerprints, cloud resource IDs, client IDs) is a needle. A scanned file
is recorded under ou=census with, under it, one occurrence per value found: the entry the value belongs to, the
attribute, the lines. The values themselves are never copied into the census, and what in a file may be secret
material is recorded by line and kind only. Changing a value then becomes a query: every file and line it is in.
"""
import hashlib
import re
from itertools import groupby
from typing import NamedTuple

from ...core.directory import children, get, make_entry, norm_dn, one, rdn_value, values
from ...core.findings import findings, merge_findings, responsible
from ...core.secrets import text_concerns
from .naming import CENSUS

# value types the census looks for, and attributes it looks for whatever their type
VALUE_TYPES = ("fqdn", "ip", "cidr", "extdn", "url")
ATTRIBUTES = ("ciamFingerprint", "ciamProviderRef", "ciamClientId")
PORTABILITY = ("intent", "contract", "binding")      # observed values and bookkeeping are not copied by other systems
MIN_LENGTH = 6                                        # shorter values match too much to mean anything
CENSUS_HEADERS = ("file", "server", "value of", "attribute", "lines", "concerns")

# A value to look for: its text, the entry and attribute it belongs to, and the pattern that finds it
Needle = NamedTuple("Needle", [("value", str), ("owner", str), ("attr", str), ("pattern", object)])


def _pattern(value, kind, attr):
    """A regex finding the value as a whole token: an IP not inside a longer one, a name not inside a longer name, a
    DN with or without spaces after its commas, a fingerprint with or without its colons."""
    if attr == "ciamFingerprint":
        hexes = re.sub(r"[^0-9A-Fa-f]", "", value)
        return re.compile(rf"(?<![0-9A-Fa-f:]){':?'.join(re.escape(hexes[i:i + 2]) for i in range(0, len(hexes), 2))}"
                          rf"(?![0-9A-Fa-f])", re.I)
    if kind in ("ip", "cidr"):
        return re.compile(rf"(?<![\d.]){re.escape(value)}(?!\d|\.\d)")
    if kind == "extdn":
        return re.compile(r"\s*,\s*".join(re.escape(part.strip()) for part in value.split(",")), re.I)
    if kind == "url":
        return re.compile(rf"(?<![\w.-]){re.escape(value.rstrip('/'))}(?![\w.-])", re.I)
    return re.compile(rf"(?<![\w.-]){re.escape(value)}(?![\w-]|\.\w)", re.I)


def _looked_for(d, attr):
    t = d.types.get(attr) or {}
    return attr in ATTRIBUTES or (t.get("value_type") in VALUE_TYPES and t.get("portability") in PORTABILITY)


def needles(d, exclude=()):
    """Every value of the record the census looks for; entries under the census itself and under the branches
    excluded (observations other systems don't copy, such as configuration snapshots) are left out."""
    skipped = tuple(norm_dn(b) for b in (CENSUS, *exclude))
    return tuple(Needle(v, e.dn, attr, _pattern(v, (d.types.get(attr) or {}).get("value_type"), attr))
                 for e in d.entries.values() if not any(e.norm == b or e.norm.endswith("," + b) for b in skipped)
                 for attr, vals in e.attrs.items() if _looked_for(d, attr)
                 for v in vals if len(v) >= MIN_LENGTH)


def found_in(text, all_needles):
    """{(owner, attribute): line numbers} of the needles found in a text."""
    lines = text.split("\n")
    hits = sorted(((n.owner, n.attr), i) for n in all_needles for i, line in enumerate(lines, 1)
                  if n.pattern.search(line))
    return {k: tuple(sorted({i for _, i in group})) for k, group in groupby(hits, key=lambda h: h[0])}


def _digest(*parts):
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def file_dn(server, path):
    """The DN recording a scanned file: named by a digest of the server it came from and its path."""
    return f"cn={_digest(server or '', path)},{CENSUS}"


def scanned_entries(path, text, server, all_needles, patterns):
    """The entries recording one scanned file: the file (its path, digest, server, secret concerns by line) and one
    occurrence per value of the record found in it."""
    name = _digest(server.dn if server else "", path)
    dn = f"cn={name},{CENSUS}"
    concerns = tuple(f"line {n}: {c}" for n, c in text_concerns(text, patterns))
    file_entry = make_entry(dn, ("top", "ciamScannedFile"), {
        "cn": (name,), "ciamRepoPath": (path,),
        "ciamSha256": (hashlib.sha256(text.encode()).hexdigest(),),
        **({"ciamOnServer": (server.dn,)} if server else {}), **({"ciamConcern": concerns} if concerns else {})})
    found = found_in(text, all_needles)
    return (file_entry, *(make_entry(f"cn={_digest(owner, attr)},{dn}", ("top", "ciamOccurrence"),
                                     {"cn": (_digest(owner, attr),), "ciamOccurrenceOf": (owner,),
                                      "ciamOccurringAttr": (attr,), "ciamLineNumber": tuple(map(str, lines))})
                          for (owner, attr), lines in sorted(found.items())))


def _server_of(d, path):
    """(server entry the file was taken from, path within it): the export's top folder when it is a server's
    hostname or name (unambiguous), else no server."""
    top, _, rest = path.partition("/")
    if not rest:
        return None, path
    named = [e for e in d.entries.values() if "ciamServer" in e.classes
             and top.lower() in ((one(e, "ciamHostname") or "").lower(), rdn_value(e).lower())]
    return (named[0], rest) if len(named) == 1 else (None, path)


def census_groups(d, files, patterns, exclude=()):
    """((file DN, its entries), ...) and notices for every scanned file; exclude: branches whose values aren't looked
    for."""
    all_needles = needles(d, exclude)
    placed = tuple((path, *_server_of(d, path)) for path in sorted(files))
    groups = tuple((file_dn(server.dn if server else None, rel),
                    scanned_entries(rel, files[path], server, all_needles, patterns)) for path, server, rel in placed)
    found = sum(len(entries) - 1 for _, entries in groups)
    concerned = [one(entries[0], "ciamRepoPath") for _, entries in groups if values(entries[0], "ciamConcern")]
    return groups, (f"{len(groups)} file(s) scanned for {len(all_needles)} values of the record: {found} found",
                    *(f"{p}: may hold secret material (see its concerns; nothing of it is stored)" for p in concerned))


# ------------------------------------------------------------------ report and planner check
def census_rows(d, dn=None):
    """Every value found: the file, the server it came from, whose value, which attribute, the lines, the file's
    secret concerns; one entry's occurrences when dn is given."""
    files = sorted(children(d, CENSUS, "ciamScannedFile"), key=lambda f: one(f, "ciamRepoPath"))
    in_order = lambda f: sorted(children(d, f.dn, "ciamOccurrence"),  # noqa: E731
                                key=lambda o: (int(one(o, "ciamLineNumber", "0")), one(o, "ciamOccurringAttr"),
                                               one(o, "ciamOccurrenceOf")))
    return [(one(f, "ciamRepoPath"), rdn_value(get(d, one(f, "ciamOnServer"))) if one(f, "ciamOnServer") else "",
             one(o, "ciamOccurrenceOf"), one(o, "ciamOccurringAttr"), ", ".join(values(o, "ciamLineNumber")),
             "; ".join(values(f, "ciamConcern")))
            for f in files for o in in_order(f)
            if dn is None or norm_dn(one(o, "ciamOccurrenceOf")) == norm_dn(dn)] + \
        [(one(f, "ciamRepoPath"), rdn_value(get(d, one(f, "ciamOnServer"))) if one(f, "ciamOnServer") else "",
          "", "", "", "; ".join(values(f, "ciamConcern")))
         for f in files if dn is None and values(f, "ciamConcern") and not children(d, f.dn, "ciamOccurrence")]


def _environment_values(m):
    return {(attr, v.lower()) for e in (*m.servers, *m.bindings) for attr, vals in e.attrs.items() for v in vals}


def check_census(ctx):
    """Files that hard-code a value of the source environment the target doesn't keep (a server's hostname or
    address, a binding): each has to change when the platform moves."""
    source = {e.norm: e for e in (*ctx.src.servers, *ctx.src.bindings)}
    kept = _environment_values(ctx.dst)

    def one_file(f):
        stale = [(get(ctx.d, one(o, "ciamOccurrenceOf")), one(o, "ciamOccurringAttr"), values(o, "ciamLineNumber"))
                 for o in children(ctx.d, f.dn, "ciamOccurrence")
                 if norm_dn(one(o, "ciamOccurrenceOf")) in source]
        changing = sorted(((e, attr, lines) for e, attr, lines in stale if e is not None
                           and not all((attr, v.lower()) in kept for v in values(e, attr))),
                          key=lambda c: (int(c[2][0]) if c[2] else 0, c[1]))
        if not changing:
            return findings()
        what = "; ".join(f"{rdn_value(e)} {attr} (line {', '.join(lines)})" for e, attr, lines in changing)
        where = f" on {rdn_value(get(ctx.d, one(f, 'ciamOnServer')))}" if one(f, "ciamOnServer") else ""
        return findings(actions=[("Hard-coded", f"`{one(f, 'ciamRepoPath')}`{where} holds {ctx.src.label} values that "
                                                f"change in {ctx.dst.label}: {what}.",
                                  responsible(ctx.d, *(e for e, _, _ in changing)), None)])
    return merge_findings([one_file(f) for f in children(ctx.d, CENSUS, "ciamScannedFile")])
