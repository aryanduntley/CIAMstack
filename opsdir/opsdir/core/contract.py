"""The contracts that let each part of the stack plug in without touching core or connectors.

A Domain is a vendor-neutral part of the stack (infrastructure, directory, federation, pki, governance):
the roles every environment must bind for it, its SQL views, its reports and its planner checks. A domain
depends on core only: its reports are data (SQL text or a pure function of the directory snapshot) that
connectors run against the store. An Adapter is one product,
cloud provider or secret store: it decides from directory data whether it applies to an environment, and
declares the roles it needs, what it renders, the planner checks it adds and the secret-reference schemes
it can resolve; a package may also add schema definitions of its own (a fragment under its own OID arc). Both are
plain records of data and functions; connectors compose them.
"""
from collections import namedtuple
from typing import Callable, Mapping, NamedTuple, Optional

from .directory import Directory
from .environment import EnvModel

# A report's rows come from exactly one source: `sql` (run against the store; the report's DN argument is its one
# parameter when needs_dn), `from_directory(directory, dn)` (a pure function of the snapshot), or `fetch(conn, dn)`
# (a store-level query; for the store's own reports, never a domain's).
Report = NamedTuple("Report", [("headers", tuple), ("sql", Optional[str]), ("from_directory", Optional[Callable]),
                               ("fetch", Optional[Callable]), ("needs_dn", bool),
                               ("dated", bool)])   # from_directory(d, dn, as_of): it evaluates dates as of a day


def sql_report(headers, sql, needs_dn=False):
    return Report(tuple(headers), sql, None, None, needs_dn, False)


def directory_report(headers, from_directory, needs_dn=False, dated=False):
    return Report(tuple(headers), None, from_directory, None, needs_dn, dated)


def fetch_report(headers, fetch, needs_dn=False):
    return Report(tuple(headers), None, None, fetch, needs_dn, False)


# How one kind of resource the cloud importers report is read into the record (core.inventory places it); declared
# by the domain whose object class it is, so the core names none. kind: the importers' name for it; object_class: the
# record's; required: what a new entry must have beyond cn and its role. match: what an entry of the kind is matched
# by: "ref" (its provider ref, kept as ciamProviderRef), "name" (its cn, case aside), an attribute (its first value;
# lower: case aside), or a function (attrs) -> key applied to the entry's and the resource's attributes alike.
# first: placed before the other kinds (what they link to). role: a function (resource, {provider ref: role}) -> the
# role of a new one whose source names none (from what it links to), or None. alias: a function (provider ref) ->
# the name an entry is matched by when nothing else matches it. prepare: a function (directory, environment DN,
# resource) -> resource, run before placing. resolve: a function (attrs, {provider ref: role}) -> {attr: values} for
# values naming another resource by its provider ref (a route's target). ported: attributes whose values may carry a
# port a source can't express. server: placed as a server (ciamServerRole, under the environment) and matched also by
# hostname or private address.
ImportKind = namedtuple("ImportKind", ("kind", "object_class", "required", "match", "lower", "first", "role", "alias",
                                       "prepare", "resolve", "ported", "server"),
                        defaults=((), "ref", False, False, None, None, None, None, frozenset(), False))

Domain = namedtuple("Domain", (
    "name", "schema",           # its SchemaFragment
    "required_roles",
    "sql",                      # SQL definitions (views, functions), re-applied on every upgrade
    "reports",                  # report name -> Report
    "checks",                   # planner checks: (PlanContext) -> Findings
    "order",                    # domains run and report in ascending order
    "vocabulary",               # {vocab attribute: values it defines}
    "import_kinds",             # ImportKinds: the resources the cloud importers read into its classes
    "role_links"),              # {attribute naming a binding's role: the import kind of what it names}
    defaults=((), {}))

# A language or file format opsdir renders or reads: registered (entry point group opsdir.formats) by the core for the
# standard ones and by any package for its own, so what a managed system is written in is data, never an assumption.
# comment: how the format writes a comment: (line prefix,) such as ("#",), (start, end) such as ("<!--", "-->"), or ()
# when it has none (JSON). read (text -> data) and write (data -> text) are the package's, when it provides them.
Format = NamedTuple("Format", [("name", str), ("title", str), ("media_type", str), ("extensions", tuple),
                               ("comment", tuple), ("read", Optional[Callable]), ("write", Optional[Callable]),
                               ("codec", Optional[object])])       # its Codec, when files in it can be captured

# How a config file in a format is captured into the record and rebuilt from it byte for byte (core.capture):
# split(text) -> the file as a tuple of literal text (str) and settings ((locator, raw), where raw is the setting's
# text exactly as it appears in the file); decode(raw) -> the setting's value; encode(value, raw) -> the text that
# writes a changed value, in the style of the original raw text (its quoting, its type). Locators are unique in a file.
# add(text, locator) -> (before, after): the literal text around a new setting's place when a setting is appended to a
# file's text (its own line, key and separator); None for a format that can't place a new setting on its own.
Codec = namedtuple("Codec", ("split", "decode", "encode", "add"), defaults=(None,))

# A form secret material takes (a private key block, a vendor's access key, ...): the store refuses any value that
# matches, so no write can put a secret in the record (SPEC R4). pattern is a regular expression in the dialect Python
# and PostgreSQL share (core.secrets.dialect_problems); the core registers the generic forms, adapters their vendors'.
SecretPattern = NamedTuple("SecretPattern", [("name", str), ("pattern", str), ("description", str)])

# How an adapter reads a product's own export (an admin tool's export directory, an API dump) into the record:
# read(files, d, patterns, at) -> Imported. files: {relative path: text}; d: the record as it is (an importer merges
# with what it holds, keeping attributes and entries it doesn't own); patterns: the SecretPatterns the store refuses (an
# importer withholds matching values and says so in its notices); at: when the import runs (a UTC datetime, or None
# when not given), for importers that date what they observe. Pure: the connectors diff and the store applies.
Importer = NamedTuple("Importer", [("name", str), ("description", str), ("read", Callable)])
# What an import yields: containers (branch entries to create when missing, never changed otherwise); groups: ((scope
# DN, entries that should exist in that subtree), ...), each replacing the record's subtree at its scope; notices.
Imported = NamedTuple("Imported", [("containers", tuple), ("groups", tuple), ("notices", tuple)])

# What connectors provide to adapters while rendering: secret_command(ref-uri) -> shell command that resolves it;
# endpoints: the installed adapters' Endpoints (what the edge aims health checks, rate limits and exclusions at)
Services = NamedTuple("Services", [("secret_command", Callable), ("endpoints", tuple)])

# One row of a cloud's permission table: what a neutral verb (read-secret, use-key, ...) on a binding of a class
# (ciamSecretRef, ciamKeyRef, ...; kind: a stream's kind, or None for any) needs in the cloud's terms. needs is a tuple
# of requirements, each a tuple of alternatives (actions or roles; the first is what renderers grant); broad when the
# cloud can't scope it to the one resource (log writes in some clouds), so a wider grant is expected, not a finding.
# related: ((link attribute, needs), ...): what is also needed on the binding whose role the binding's link attribute
# names, when it names one (a secret encrypted by a customer managed key: kms:Decrypt on that key).
Permission = namedtuple("Permission", ("verb", "binding_class", "kind", "needs", "broad", "related"), defaults=((),))
# What a cloud adapter knows about access: its permission table, the actions or roles that let an identity raise its
# own access (patterns: iam:PassRole, roles/owner, ...), whether a granted resource covers a binding's resource
# (covers(granted, binding) -> bool: equal, a parent scope, or a pattern), and the resource as the cloud names it
# (resource(binding) -> str | None); and, when the cloud has an evaluator for any principal, the commands that ask it
# about one permission (evaluator(m, identity binding, binding, row) -> (shell command, ...), each printing JSON;
# () when it can't answer for that identity).
AccessModel = namedtuple("AccessModel", ("permissions", "escalations", "covers", "resource", "evaluator"),
                         defaults=(None,))

# An endpoint a product serves that the edge treats specially: kind is one of the edge domain's endpoint kinds (login,
# token, password-reset, registration, saml-post, health), path a URL path where '*' stands for one or more path
# segments (/am/json/realms/*/authenticate), server_role the role of the servers serving it. Products declare their
# defaults; a policy's ciamEndpointPath says where an estate moved one.
Endpoint = namedtuple("Endpoint", ("kind", "path", "server_role"))

# A port a product's servers listen on: server_role the role of the servers, port and protocol (tcp or udp), purpose in
# words (LDAPS, replication, cluster), peers who connects: any of clients (consumers, directly or through service
# names), peers (other servers of the same role), admin (the operators' ways in), and server roles by name. Products
# derive them from the record where it says (a connection handler's port, a node's run.properties), else their
# defaults; the connectors turn them into the ports matrix the firewall rules are checked against.
Listener = namedtuple("Listener", ("server_role", "port", "protocol", "purpose", "peers"))

# A setting a product needs so its outside traffic goes through an environment's explicit proxy (network.proxies):
# server_role the servers that need it, place where it is set (a file, an admin setting, the JVM options) in words,
# file the path a captured file of that place ends with (None when the place isn't a file), locator the setting's
# name (its locator in that file), value what it must say, link the value derived from the proxy binding it is (a
# network.proxies derivation: proxy:host, proxy:bypass, ...; None for a literal the same everywhere). The connectors
# compare them with the captured files the environment receives, and offer to add or link them (core.findings.Fix).
ProxySetting = namedtuple("ProxySetting", ("server_role", "place", "file", "locator", "value", "link"),
                          defaults=(None,))

# An adapter's fields; an older adapter that names no endpoints declares none, one that names no listeners or proxy
# settings None.
Adapter = namedtuple("Adapter", (
    "name",
    "kind",                 # provider | product | host | delivery | secret-store
    "applies",              # (EnvModel) -> bool, from directory data only; None = declaration-only (connectors.stack)
    "required_roles",
    "render_neutral",       # (Directory) -> {path: text}, same everywhere
    "render_env",           # (EnvModel, Services) -> {path: text}
    "checks",               # planner checks: (PlanContext) -> Findings
    "ref_schemes",          # ref-uri schemes it owns (secrets, keys, storage)
    "secret_schemes",       # ref-uri scheme -> (rest of uri) -> shell command
    "renders",              # what its environment-specific output is, in words
    "neutral_label",        # short name of its environment-neutral config
    "vocabulary",           # {vocab attribute: values it defines}
    "schema",               # its SchemaFragment (own OID arc), or None
    "formats",              # ((path glob, format name), ...): the format of every file it renders (first match wins)
    "products",             # ((product, PEP 440 range), ...): the product versions it renders and reads
    "secret_patterns",      # SecretPatterns: its vendor's credential forms
    "importers",            # Importers: the product exports it reads
    "profile_terms",        # what its directory attributes mean to the data profile (directory profile.Terms), or None
    "access",               # a cloud's AccessModel: what its actions and roles mean as neutral permissions, or None
    "endpoints",            # Endpoints: what its products serve that the edge protects, checks or never caches
    "listeners",            # (EnvModel) -> Listeners: the ports its servers listen on in an environment, or None
    "proxy_settings"),      # (EnvModel, ProxySettings) -> ProxySettings its servers need for an explicit proxy, or None
    defaults=((), None, None))

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
