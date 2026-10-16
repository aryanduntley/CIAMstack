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

# One use of a binding role by a record entry an environment runs (Domain and Adapter roles_used): the role and what
# uses it in words (connector `hrdb`), for the keys report.
RoleUse = namedtuple("RoleUse", ("role", "by"))

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
    "accept",                   # (PlanContext, blockers, actions) -> (blockers, actions, accepted): the findings the
                                # record's approved decisions accept, each accepted one as (kind, area, text, owner,
                                # why), shown in the plan, not counted; None: it accepts none
    "roles_used"),              # (EnvModel) -> (RoleUse, ...): the binding roles its entries the environment runs use
                                # (a connector's credential), for the keys report, or None
    defaults=((), {}, (), (), (), None, None))

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
# What one of an adapter's own importers reads back of its render (the round-trip guarantee, connectors.roundtrip): the
# rendered files whose paths match paths (an fnmatch glob, '*' crossing '/'), each with the prefix strip removed (''
# keeps the path as rendered) and the prefix place put in front ({environment}: the cloud/env rendered, for importers
# that read an environment's files from its own folder), read by the importer named; reading them back must change
# nothing. optional: the render holds these files only for some environments (PingFederate's cluster discovery, only
# where the nodes cluster), so a render that has none of them has nothing to read back, not a gap. prepare: (files,
# record, environment) -> the files the importer reads, when they aren't the rendered files themselves (a cloud's
# rendered Terraform roots become the states applying them would record; the record the render was made from gives what
# the provider assigns); None reads the files as they are. intent: the render is the record's intent (a cloud's
# policies applied), not a projection of it, so where the record still holds what was observed, reading the render back
# records what applying it would change: then only copies (an entry added for a role the environment already binds with
# that class, or one deleted) are drift, and the render must be a fixed point (connectors.roundtrip.fixed_point).
ReadBack = namedtuple("ReadBack", ("importer", "paths", "strip", "place", "optional", "prepare", "intent"),
                      defaults=("", "", False, None, False))

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
# applies to m, or None; ansible_lookup(m, ref-uri): the native lookup expression configuration management reads a
# reference with at run time (its scheme owner's), or None (it runs the scheme's resolver command instead);
# deployable_config(m): ((target role, deploy path, repo path, text), ...) of the captured files m receives that say
# where they go on its servers; signals(m): the Signals the adapters rendering environment m declare; logs(m): the
# LogSources they declare; host_files(m): the HostFiles they render for m's servers; render_targets(adapter name): the
# render targets chosen for that adapter in this render (() outside a render, or when it declares none);
# mounts_secrets(m, workload): whether a deployment kit rendering m mounts the workload's SecretProviderClasses in its
# pods (Adapter.mounts_secrets); installed_logs: the LogSources every installed adapter declares (a kit's resolved),
# whether or not it renders the environment: what a kit reads its products' log files from; siem_keeper(m,
# destination): the name of the adapter rendering m that keeps a log destination of kind siem-index (its retention,
# its detections and, where it ships logs to it itself, their forwarding: Adapter.siem_indexes), or None; a provider
# adapter leaves a destination another adapter keeps to it
Services = NamedTuple("Services", [("secret_command", Callable), ("endpoints", tuple), ("listeners", Callable),
                                   ("workload_identity", Callable), ("secret_delivery", Callable),
                                   ("routes", Callable), ("gateway_plug", Callable), ("ansible_lookup", Callable),
                                   ("deployable_config", Callable), ("signals", Callable), ("logs", Callable),
                                   ("host_files", Callable), ("render_targets", Callable),
                                   ("mounts_secrets", Callable), ("installed_logs", tuple),
                                   ("siem_keeper", Callable)])

# A cloud-managed identity service an adapter declares (Adapter.managed_identity), as data with its sources, for the
# planner's managed identity check (connectors.managed_identity). name: the ciamManagedService value; title: it in
# words; partition: (EnvModel) -> the partition label an environment is in (aws / aws-us-gov, public / usgovernment);
# available / absent: {partition: source} where the vendor documents it exists / doesn't exist (anywhere else: not
# established); supported / unsupported: {capability: source} (capabilities: issue:oidc, issue:saml, trust:oidc,
# trust:saml, grant:<grant type>, token-auth:<method>, dpop-bound, pkce-required, signing-alg:<alg>, custom-domain,
# custom-issuer, mfa-per-client, claim-transform; one in neither is not established by the vendor's documentation);
# partition_unsupported: {partition: {capability: source}}, what a partition lacks beyond them; conditions:
# {capability: what it needs (an add-on, a tier)}: supported on a condition, an action; notes: {partition or "*":
# ((topic, text, how), ...)}: what a target there must know (an action each); users: how user accounts and passwords
# move onto it (an action for every target: the configuration doesn't carry them).
ManagedService = NamedTuple("ManagedService", [("name", str), ("title", str), ("partition", Callable),
                                               ("available", Mapping), ("absent", Mapping), ("supported", Mapping),
                                               ("unsupported", Mapping), ("partition_unsupported", Mapping),
                                               ("conditions", Mapping), ("notes", Mapping), ("users", str)])

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
# token, password-reset, registration, saml-post, saml-start, health), path a URL path where '*' stands for one or more
# path segments (/am/json/realms/*/authenticate), server_role the role of the servers serving it, versions the product
# versions serving it there (a PEP 440 range, versions.holds), None for every version, port the port it is served on
# when not the service's (a product's separate admin port, which a health check then probes), else None, query the
# query string a request to it carries, where {entity} stands for a partner's entity ID, URL-encoded (saml-start: the
# identity provider's own start of a sign-in to a service provider, PartnerSpId={entity}), else None. Products
# declare their defaults; a policy's ciamEndpointPath says where an estate moved one.
Endpoint = namedtuple("Endpoint", ("kind", "path", "server_role", "versions", "port", "query"),
                      defaults=(None, None, None))

# A neutral signal a product's servers expose (domains/observability: what an alert rule's ciamSignal names): signal
# the neutral name (replication-delay), server_role the role of the servers exposing it, expr the PromQL expression
# over the product's own Prometheus metrics giving one value per server or scope (a rate for counters), unit the unit
# of that value (s, bytes, /s, ratio: what a rule's threshold is converted to), description what it measures, versions
# the product versions exposing it so (a PEP 440 range, versions.holds), None for every version: a product whose
# metric names change between releases declares one Signal per range. Products declare only what their documentation
# names; a rule on a signal no product declares needs the metric its environment's cloud runs (its alarm binding's
# ciamMetric).
Signal = namedtuple("Signal", ("signal", "server_role", "expr", "unit", "description", "versions"), defaults=(None,))

# A log a product's servers write (domains/observability.sources: what a log route's ciamLogKind picks lines from):
# server_role the role of the servers writing it; on "servers" (a file under the server's install root) or "kubernetes"
# (the standard output and error of the role's containers, as a deployment kit runs them); path the file's glob
# relative to the install root (None on kubernetes); format "json-lines" (one JSON object per line), "text", or "mixed"
# (JSON lines among text lines); kind the log kind of every line no match rule classifies (every line when there are
# none); match ((JSON field, value prefix, kind), ...): the first rule whose field's value starts with the prefix gives
# a JSON line's kind ("" for any value: the field is there); line_start the regular expression a record's first line
# starts with, when records span lines (stack traces), else None; requires the product setting that must be on for the
# log to exist, in words, or None; container (on kubernetes) the container of the role's pods whose output it is (a
# kit's log sidecar), None for the role's containers no other of its sources names; versions the product versions
# writing it (a PEP 440 range, versions.holds), None for every version. Products and kits declare only what their
# documentation states.
LogSource = namedtuple("LogSource", ("server_role", "on", "path", "format", "kind", "match", "line_start",
                                     "requires", "container", "versions"), defaults=((), None, None, None, None))

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

# A file an adapter renders for an environment's servers of a role that configuration management places on them (an
# agent's configuration: the CloudWatch agent's, the Ops Agent's): server_role the servers that receive it, path where
# it goes on them (absolute), text its content (a secret placeholder ${secret:<ref-uri>} is read at run time, as in a
# captured file), reload the command that makes what reads it take it up (run when the file changes; argv words, no
# shell), or None; mode the file's permissions; hosts the names of the role's servers that receive it (their record
# names), () for every one (a file whose text differs per server, as each server's install root does, is one HostFile
# per group of servers it is the same for). Configure-only: what reads it is installed by the host's baseline.
HostFile = namedtuple("HostFile", ("server_role", "path", "text", "reload", "mode", "hosts"),
                      defaults=(None, "0644", ()))

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
# credential (scheme 'basic', 'bearer', 'token' (sent as the Authorization header's whole value: a session token a
# product's own logon issued), 'headers' or 'api-key', the reference to resolve, the login name (None for token and
# api-key), and for 'headers' the names of the header carrying the login and of the one carrying the secret
# (PingIDM's X-OpenIDM-Username and X-OpenIDM-Password), for 'api-key' the name of the header carrying the secret
# alone (PAN-OS's X-PAN-KEY): ('api-key', reference, None, 'X-PAN-KEY')) or None, ca the reference to the
# certificate (PEM) the endpoint is trusted by, or None for the system's trust store; absent the HTTP statuses that
# mean nothing to read (404); keep as a Command's.
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
# login isn't the account, subscription or project the record names) or None. options: the CollectOptions it takes
# (what `opsdir collect` offers as flags; the operator's values reach steps and problems in options).
Collector = namedtuple("Collector", ("importer", "scope", "steps", "verify", "problems", "options"),
                       defaults=("environment", None, None, None, ()))
# A run-time option a collector takes: flag (--terraform-dir), metavar (DIR), help, and order (its place among the
# collect flags, lowest first). Data only, never a secret value; the collector reads the operator's value under the
# flag without dashes, dashes as underscores (terraform_dir). An option several adapters share is declared once by the
# library that reads it and reused, so its declarations are identical (connectors.registry.collect_options refuses
# two different declarations of one flag).
CollectOption = namedtuple("CollectOption", ("flag", "metavar", "help", "order"))

# A change between two releases of a product an adapter renders and reads (decision 2375: a migration may upgrade
# within the adapter's range, and the planner names what changes): has the versions that have it (a PEP 440 range, or
# a tuple of ranges for parallel maintenance lines: (">=7.5.3,<8", ">=8.0.2")), so a move from a version without it to
# one with it crosses it; change what changed, affects which parts of the record it concerns (in words), effect what a
# crossing is when the record holds what it touches (blocker: the record uses something removed; action: something
# to change or test; info: worth knowing), fix what to do. touches(d, m, role) -> names of what the record holds that
# it changes, for a server role environment m runs (() when nothing: the change is counted, not listed), or None for a
# change to whatever runs the role (always listed). An adapter's products are one lineage, compared by version number
# (ForgeRock AM 7.5 -> PingAM 8.1). Adapters declare only what the vendor's release notes state.
VersionChange = namedtuple("VersionChange", ("has", "change", "affects", "effect", "fix", "touches"),
                           defaults=(None,))

# An adapter's fields; an older adapter that names no endpoints declares none, one that names no listeners or proxy
# settings None, one that names no prerequisites none.
Adapter = namedtuple("Adapter", (
    "name",
    "kind",                 # provider | platform | product | host | delivery | secret-store | pki | compliance | itsm
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
    "settings",             # Settings: the estate settings it declares (core.settings), beside the domains'
    "ansible_lookup",       # {ref-uri scheme: (EnvModel, secret store binding or None, rest) -> a Jinja expression
                            # reading the secret at run time (core.interchange.jinja), or None to fall back to its
                            # resolver command}: how configuration management reads its schemes' secrets
    "signals",              # Signals: the neutral signals its products' servers expose as Prometheus metrics
    "logs",                 # LogSources: the logs its products' servers (or, for a kit, the role's containers) write;
                            # or (installed adapters' static LogSources, their product roles ((product, kind,
                            # role), ...)) -> LogSources, for a kit deriving its own from the products' (resolved
                            # once when the registry loads the adapters: connectors.registry.resolved_logs)
    "host_files",           # (EnvModel, Services) -> HostFiles: files configuration management places on the
                            # environment's servers (agents' configuration), or None
    "places_host_files",    # whether it places the other adapters' HostFiles on an environment's servers (the
                            # configuration-management adapter does): without one in the stack they go nowhere
    "version_changes",      # VersionChanges: what changes between the releases of its products (the planner's
                            # upgrade check)
    "reads_back",           # ReadBacks: which of its importers read which of its rendered files back (round trip)
    "profile",              # ProductProfile (core.profiles): which of its rendered files are its product's own
                            # instance files and where, for a deployment kit's profiles, or None
    "render_profiles",      # (EnvModel, {product: {instance path: text}}, targets chosen) -> {path: text}: a kit's
                            # render of the products' profiles in its layout (after every adapter's render_env), or None
    "notes",                # (EnvModel, Services) -> (RenderNote, ...) (core.notes): what its render of the environment
                            # leaves out or to a person, as data (each also written as the comment note_comment gives),
                            # or None (its NOTE comments are then collected as notes to review)
    "renders_synthetic_checks",     # whether it renders an environment's synthetic checks (canaries): where no
                                    # adapter rendering an environment does, its canaries are render notes of their own
    "roles_used",           # (EnvModel) -> (RoleUse, ...): the binding roles its products' entries use in an
                            # environment (a connector's or data store's credential), whether or not it applies there
                            # (the keys report says which product would use them), or None
    "mounts_secrets",       # (EnvModel, workload) -> bool: whether its pods (a deployment kit's) mount the
                            # SecretProviderClasses of a workload it deploys, or None (it mounts none)
    "roles",                # ((kind, (role, ...)), ...): the roles its products use, by kind (ROLE_KINDS), so a kit
                            # deploying them finds them by product (core.environment.roles_for), never by name
    "cluster_discovery",    # (EnvModel) -> (DiscoveryAnswer, ...): what a deployment kit's chart answers for its
                            # products' cluster discovery in an environment, for the product's own check
                            # (core.environment discovery_answers), or None
    "inventory_locator",   # {ref-uri scheme: (rest of uri) -> (container, object) or None}: where in its store's
                            # inventory a reference of the scheme points (a safe and an account, a mount and a path),
                            # for reconciling the record's references with the inventory its importers record
                            # (domains.pki.inventory), or None (its stores aren't inventoried)
    "siem_indexes",         # (EnvModel, ciamLogDestination binding of kind siem-index) -> bool: whether its render
                            # keeps that SIEM index (its retention, the detections searching it and, where it ships
                            # logs to it itself, their forwarding), or None (it keeps none)
    "source_checks",        # planner checks an adapter runs when it applies to the SOURCE environment of a plan
    "managed_identity"),    # ManagedServices: the cloud-managed identity services it declares (their
                            # ciamManagedService values are in its vocabulary)
    defaults=((), None, None, (), (), (), None, None, None, None, (), None, (), (), None, False, (), (), None, None,
              None, False, None, None, (), None, None, None, (), ()))

# The kinds of role a product adapter declares (Adapter.roles): server (its ciamServerRole / ciamTargetRole values),
# keystore (the secret role holding a server's keystore), service (the service name's binding role clients reach it
# by), cluster-discovery (the binding role its nodes find each other through).
ROLE_KINDS = ("server", "keystore", "service", "cluster-discovery")

# What a deployment kit's chart answers for a product's cluster discovery in one namespace (Adapter.cluster_discovery):
# the product (as its adapter's products name it), the namespace, the DNS name its pods find each other through, the
# kit (its adapter name) and the setting its values pass the product's discovery binding as.
DiscoveryAnswer = NamedTuple("DiscoveryAnswer", [("product", str), ("namespace", str), ("name", str), ("kit", str),
                                                 ("setting", str)])

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
