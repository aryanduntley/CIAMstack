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
from typing import Callable, Mapping, NamedTuple, Optional

from .directory import Directory
from .environment import EnvModel

# A report's rows come from exactly one source: `sql` (run against the store; the report's DN argument is its one
# parameter when needs_dn), `from_directory(directory, dn)` (a pure function of the snapshot), or `fetch(conn, dn)`
# (a store-level query; for the store's own reports, never a domain's).
Report = NamedTuple("Report", [("headers", tuple), ("sql", Optional[str]), ("from_directory", Optional[Callable]),
                               ("fetch", Optional[Callable]), ("needs_dn", bool)])


def sql_report(headers, sql, needs_dn=False):
    return Report(tuple(headers), sql, None, None, needs_dn)


def directory_report(headers, from_directory, needs_dn=False):
    return Report(tuple(headers), None, from_directory, None, needs_dn)


def fetch_report(headers, fetch, needs_dn=False):
    return Report(tuple(headers), None, None, fetch, needs_dn)


Domain = NamedTuple("Domain", [("name", str), ("schema", object),     # its SchemaFragment
                               ("required_roles", tuple),
                               ("sql", tuple),          # SQL definitions (views, functions), re-applied on every upgrade
                               ("reports", Mapping),    # report name -> Report
                               ("checks", tuple),       # planner checks: (PlanContext) -> Findings
                               ("order", int),          # domains run and report in ascending order
                               ("vocabulary", Mapping)])  # {vocab attribute: values it defines}

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
Codec = NamedTuple("Codec", [("split", Callable), ("decode", Callable), ("encode", Callable)])

# A form secret material takes (a private key block, a vendor's access key, ...): the store refuses any value that
# matches, so no write can put a secret in the record (SPEC R4). pattern is a regular expression in the dialect Python
# and PostgreSQL share (core.secrets.dialect_problems); the core registers the generic forms, adapters their vendors'.
SecretPattern = NamedTuple("SecretPattern", [("name", str), ("pattern", str), ("description", str)])

# What connectors provide to adapters while rendering: secret_command(ref-uri) -> shell command that resolves it
Services = NamedTuple("Services", [("secret_command", Callable)])

Adapter = NamedTuple("Adapter", [("name", str),
                                 ("kind", str),                       # provider | product | secret-store
                                 ("applies", Optional[Callable]),     # (EnvModel) -> bool, from directory data only;
                                                                      # None = declaration-only (see connectors.stack)
                                 ("required_roles", tuple),
                                 ("render_neutral", Optional[Callable]),  # (Directory) -> {path: text}, same everywhere
                                 ("render_env", Optional[Callable]),      # (EnvModel, Services) -> {path: text}
                                 ("checks", tuple),                   # planner checks: (PlanContext) -> Findings
                                 ("ref_schemes", tuple),              # ref-uri schemes it owns (secrets, keys, storage)
                                 ("secret_schemes", Mapping),         # ref-uri scheme -> (rest of uri) -> shell command
                                 ("renders", Optional[str]),          # what its environment-specific output is, in words
                                 ("neutral_label", Optional[str]),    # short name of its environment-neutral config
                                 ("vocabulary", Mapping),             # {vocab attribute: values it defines}
                                 ("schema", Optional[object]),        # its SchemaFragment (own OID arc), or None
                                 ("formats", tuple),                  # ((path glob, format name), ...): the format
                                                                      # of every file it renders (first match wins)
                                 ("products", tuple),                 # ((product, PEP 440 range), ...): the product
                                                                      # versions it renders and reads
                                 ("secret_patterns", tuple)])         # SecretPatterns: its vendor's credential forms

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
