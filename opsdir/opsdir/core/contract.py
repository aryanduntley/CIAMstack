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

# An estate setting a domain declares: a value the platform's managers may change for the whole estate (a governed
# entry under ou=settings, read by core.settings). kind: "int", "bool" or "string"; default: the value when the record
# holds none (or one that isn't valid); minimum, maximum: the bounds of an int; choices: the values a string may take
# (None: any non-empty text). Domains and installed adapters declare them.
Setting = namedtuple("Setting", ("name", "kind", "default", "description", "minimum", "maximum", "choices"),
                     defaults=(None, None, None))

Domain = namedtuple("Domain", (
    "name", "schema",           # its SchemaFragment
    "required_roles",
    "sql",                      # SQL definitions (views, functions), re-applied on every upgrade
    "reports",                  # report name -> Report
    "checks",                   # planner checks: (PlanContext) -> Findings
    "order",                    # domains run and report in ascending order
    "vocabulary",               # {vocab attribute: values it defines}
    "import_kinds",             # ImportKinds: the resources the cloud importers read into its classes
    "role_links",               # {attribute naming a binding's role: the import kind (or kinds) of what it names}
    "settings",                 # Settings: the estate settings it declares (core.settings)
    "import_checks",            # (directory, environment spec, Resources) -> notices, run on every cloud import
    "local_classes",            # binding classes local to their environment's cloud (a cloud's suppression of
                                # findings): the planner doesn't ask the target to bind what the source's do
    "accept"),                  # (PlanContext, blockers, actions) -> (blockers, actions, accepted): the findings the
                                # record's approved decisions accept, each accepted one as (kind, area, text, owner,
                                # why), shown in the plan, not counted; None: it accepts none
    defaults=((), {}, (), (), (), None))

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
# commands: ((relative path, argv), ...): the provider commands whose output is the export (each command's standard
# output read as the file at its path), for `opsdir import --run`, which runs them under the operator's own login to
# the provider (the credentials stay the provider tool's; opsdir never sees or stores them); () when the export can't
# be produced by a command; or a function (d) -> such pairs, the commands derived from the record (one per region its
# clouds run in), for exports that depend on what the record holds (connectors.importing.import_commands).
Importer = namedtuple("Importer", ("name", "description", "read", "commands"), defaults=((),))
# What an import yields: containers (branch entries to create when missing, never changed otherwise); groups: ((scope
# DN, entries that should exist in that subtree), ...), each replacing the record's subtree at its scope; notices.
Imported = NamedTuple("Imported", [("containers", tuple), ("groups", tuple), ("notices", tuple)])

# How a Kubernetes workload assumes a cloud identity, from the provider adapter that owns the cloud: annotations on its
# service account and labels on its pods, as ((name, value), ...); a value the record can't give is UNBOUND:<what>.
K8sIdentity = NamedTuple("K8sIdentity", [("annotations", tuple), ("pod_labels", tuple)])

# How Kubernetes reads the secrets a ref-uri scheme names, from the adapter that owns the scheme (refs are passed as the
# rest of the uri, after <scheme>://; store: the environment's ciamSecretStore for the scheme, or None; a value the
# record can't give is UNBOUND:<what>):
#   store_key(rest) -> which store of the scheme a reference lives in ('' when the scheme has one): a Key Vault's
#     name, a Vault KV mount, a project; one SecretStore / SecretProviderClass serves one key
#   eso_provider(m, store, key, service_account, cluster) -> an External Secrets Operator SecretStore's spec.provider
#     block (cluster: the ciamCluster the workload runs in, or None)
#   eso_ref(rest) -> an ExternalSecret's remoteRef for one reference
#   csi_provider: the Secrets Store CSI driver provider name
#   csi_parameters(m, store, key, objects, identity) -> a SecretProviderClass's spec.parameters; objects ((object
#     name, rest), ...), identity the workload's ciamIdentityBinding or None
SecretDelivery = NamedTuple("SecretDelivery", [("store_key", Callable), ("eso_provider", Callable),
                                               ("eso_ref", Callable), ("csi_provider", str),
                                               ("csi_parameters", Callable)])

# What connectors provide to adapters while rendering: secret_command(ref-uri) -> shell command that resolves it;
# endpoints: the installed adapters' Endpoints (what the edge aims health checks, rate limits and exclusions at);
# listeners(m): the ports the installed adapters' products listen on in an environment; workload_identity(m, binding):
# the K8sIdentity of an identity binding from the provider adapter that applies to m, or None; secret_delivery(scheme):
# the SecretDelivery of the adapter owning a ref-uri scheme, or None; routes(m): the HTTP routes the installed
# deployment kits declare in an environment; gateway_plug(m, gateway, service): the GatewayPlug of a cluster gateway
# binding (its data-plane Service as (name, ports), from opsdir-adapter-kubernetes) from the provider adapter that
# applies to m, or None
Services = NamedTuple("Services", [("secret_command", Callable), ("endpoints", tuple), ("listeners", Callable),
                                   ("workload_identity", Callable), ("secret_delivery", Callable),
                                   ("routes", Callable), ("gateway_plug", Callable)])

# How a cloud's L7 front reaches a cluster's in-cluster gateway, from the provider adapter that owns the cloud:
# annotations on the gateway's Service ((name, value), ...), further Kubernetes objects the plug needs (dicts, e.g. a
# target group binding), and the Service's type (ClusterIP, or LoadBalancer for an internal load balancer the front
# targets); a value the record can't give is UNBOUND:<what>.
GatewayPlug = namedtuple("GatewayPlug", ("annotations", "objects", "service_type"), defaults=("ClusterIP",))

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
# defaults; the connectors turn them into the ports matrix the firewall rules are checked against. on: where it
# listens, None wherever the role runs (servers and Kubernetes pods alike), "servers" only on servers, "kubernetes"
# only in pods: a deployment kit's container ports, which replace the product's for the role's pods.
Listener = namedtuple("Listener", ("server_role", "port", "protocol", "purpose", "peers", "on"), defaults=(None,))

# An HTTP route a deployment kit serves a role's traffic through when a cluster gateway fronts it: server_role the role
# whose service name's host it is reached on, path and match (prefix | exact), service and port the Kubernetes Service
# that answers (in the role's workload's namespace), rewrite the prefix the path is replaced with before it reaches the
# Service (None: unchanged), tls whether the Service's port speaks TLS (the gateway then re-encrypts to it). Kits
# declare them from their release's layout; opsdir-adapter-kubernetes renders them.
Route = namedtuple("Route", ("server_role", "path", "match", "service", "port", "rewrite", "tls"),
                   defaults=(None, False))

# A setting a product needs so its outside traffic goes through an environment's explicit proxy (network.proxies):
# server_role the servers that need it, place where it is set (a file, an admin setting, the JVM options) in words,
# file the path a captured file of that place ends with (None when the place isn't a file), locator the setting's
# name (its locator in that file), value what it must say, link the value derived from the proxy binding it is (a
# network.proxies derivation: proxy:host, proxy:bypass, ...; None for a literal the same everywhere). The connectors
# compare them with the captured files the environment receives, and offer to add or link them (core.findings.Fix).
ProxySetting = namedtuple("ProxySetting", ("server_role", "place", "file", "locator", "value", "link"),
                          defaults=(None,))

# Data an adapter needs from its provider before the record is complete (a provider's region catalog): fetched with one
# of its importers (by name; its commands say how), met when met(directory) says the record holds it. Needed once the
# adapter applies to an environment; `opsdir prerequisites` lists what is pending.
Prerequisite = namedtuple("Prerequisite", ("name", "description", "importer", "met"))

# How `opsdir collect` reads the live system for one importer, read-only (connectors.collecting): calls whose outputs
# are the importer's export, file by file.
# A provider tool run: argv (exact: never a credential), secrets the credential references it needs, stdin a function
# ({reference: value}) -> the text it reads on standard input (where a credential reaches it: never argv, environment
# or disk), env extra environment ((name, value), ...: switches such as FIPS endpoints, never a credential), absent
# what its error output says when there is nothing to read (NoSuchBucketPolicy): then the file is left out, not a
# failure; keep a pure function (output) -> output trimming what the importer never reads and may be secret (startup
# scripts in instance metadata) before anything else sees it: the export, the evidence's hash, --save. workdir: the tool
# writes files instead of printing (Amster's export-config): the runner makes a private directory, writes inputs
# ((name, text), ...: a script, never a credential) there, replaces {dir} in argv and inputs with its path, and the
# output is the files the tool wrote under {dir}/export ({relative path: text}); the directory is removed after. digest:
# a pure function of the output's lines (an iterator) -> the text kept, applied while the output streams, so what the
# tool prints is never held whole nor written anywhere (a directory's user data profiled into counts).
Command = namedtuple("Command", ("argv", "secrets", "stdin", "env", "absent", "keep", "workdir", "inputs", "digest"),
                     defaults=((), None, (), (), None, False, (), None))
# An HTTP GET opsdir makes itself (no other method exists): url, headers ((name, value), ...: never a credential),
# credential (scheme 'basic', 'bearer' or 'headers', the reference to resolve, the login name, and for 'headers' the
# names of the header carrying the login and of the one carrying the secret: PingIDM's X-OpenIDM-Username and
# X-OpenIDM-Password) or None, ca the reference
# to the certificate (PEM) the endpoint is trusted by, or None for the system's trust store; absent the HTTP statuses
# that mean nothing to read (404); keep as a Command's.
Request = namedtuple("Request", ("url", "headers", "credential", "ca", "absent", "keep"),
                     defaults=((), None, None, (), None))
# A collector: the importer (by name) whose export it produces; scope "environment" (one environment's, `--env`) or
# "estate" (provider-wide data: regions, quota limits); steps(d, m, done, options) -> ((relative path, Command |
# Request | problem text), ...): the calls still to make given what was collected so far (done: {path: output}), a
# problem text in place of a call when an output says the collection must stop (a profile signed in to another
# organization): the collection is then incomplete with it; m the environment's
# EnvModel (None for estate scope), options what the operator gave at run time ({name: value}: a Terraform working
# directory); called again until it asks for nothing new (a list, then each item's details), so it never repeats a
# path. Paths under _work/ are what only the collector reads (the list it takes the items from): kept out of the
# export, kept in the evidence. problems(d, m, options) -> (problem, ...) or None: why it can't collect here (a
# collection source's credential role unbound, an option missing), shown instead of collecting. verify(d, m) ->
# (call, check) or None: the identity check run first, check(output) -> a problem (the provider
# login isn't the account, subscription or project the record names) or None.
Collector = namedtuple("Collector", ("importer", "scope", "steps", "verify", "problems"),
                       defaults=("environment", None, None, None))

# An adapter's fields; an older adapter that names no endpoints declares none, one that names no listeners or proxy
# settings None, one that names no prerequisites none.
Adapter = namedtuple("Adapter", (
    "name",
    "kind",                 # provider | platform | product | host | delivery | secret-store | compliance
    "applies",              # (EnvModel) -> bool, from directory data only; None = declaration-only (connectors.stack)
    "required_roles",
    "render_neutral",       # (Directory) -> {path: text}, same everywhere
    "render_env",           # (EnvModel, Services) -> {path: text}; (EnvModel, Services, targets) with render_targets
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
    "proxy_settings",       # (EnvModel, ProxySettings) -> ProxySettings its servers need for an explicit proxy, or None
    "prerequisites",        # Prerequisites: data it needs fetched from its provider
    "collectors",           # Collectors: how `opsdir collect` reads its importers' exports from the live system
    "render_targets",       # ((name, what it renders[, False: only when asked]), ...): the outputs an operator may
                            # choose between at render time (`opsdir render --target`); render_env gets the names
                            # chosen (by default every one not marked only-when-asked)
    "workload_identity",    # (EnvModel, identity binding) -> K8sIdentity: its cloud's workload identity, or None
    "secret_delivery",      # {ref-uri scheme: SecretDelivery}: how Kubernetes reads its schemes' secrets, or None
    "routes",               # (EnvModel) -> Routes: the HTTP routes its deployment kit serves through a cluster gateway
    "gateway_plug",         # (EnvModel, cluster gateway binding, (Service name, ports)) -> GatewayPlug: its cloud's
                            # front to the gateway's data-plane Service
    "settings"),            # Settings: the estate settings it declares (core.settings), beside the domains'
    defaults=((), None, None, (), (), (), None, None, None, None, ()))

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
