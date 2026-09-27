"""The contracts that let each part of the stack plug in without touching core or connectors.

A Domain is a vendor-neutral part of the stack (infrastructure, directory, federation, pki, governance):
the roles every environment must bind for it, its SQL views, its reports and its planner checks. A domain
depends on core only: its reports are data (SQL text or a pure function of the directory snapshot) that
connectors run against the store. An Adapter is one product,
cloud provider or secret store: it decides from directory data whether it applies to an environment, and
declares the roles it needs, what it renders, the planner checks it adds and the secret-reference schemes
it can resolve. Both are plain records of data and functions; connectors compose them.
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

# What connectors provide to adapters while rendering: secret_command(ref-uri) -> shell command that resolves it
Services = NamedTuple("Services", [("secret_command", Callable)])

Adapter = NamedTuple("Adapter", [("name", str),
                                 ("kind", str),                       # provider | product | secret-store
                                 ("applies", Callable),               # (EnvModel) -> bool, from directory data only
                                 ("required_roles", tuple),
                                 ("render_neutral", Optional[Callable]),  # (Directory) -> {path: text}, same everywhere
                                 ("render_env", Optional[Callable]),      # (EnvModel, Services) -> {path: text}
                                 ("checks", tuple),                   # planner checks: (PlanContext) -> Findings
                                 ("ref_schemes", tuple),              # ref-uri schemes it owns (secrets, keys, storage)
                                 ("secret_schemes", Mapping),         # ref-uri scheme -> (rest of uri) -> shell command
                                 ("renders", Optional[str]),          # what its environment-specific output is, in words
                                 ("neutral_label", Optional[str]),    # short name of its environment-neutral config
                                 ("vocabulary", Mapping)])            # {vocab attribute: values it defines}

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
