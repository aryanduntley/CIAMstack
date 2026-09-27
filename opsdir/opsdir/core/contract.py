"""The contracts that let each part of the stack plug in without touching core or connectors.

A Domain is a vendor-neutral part of the stack (infrastructure, directory, federation, pki, governance):
the roles every environment must bind for it, its SQL views and its reports. An Adapter is one product,
cloud provider or secret store: it decides from directory data whether it applies to an environment, and
declares the roles it needs, what it renders, the planner checks it adds and the secret-reference schemes
it can resolve. Both are plain records of data and functions; connectors compose them.
"""
from typing import Callable, Mapping, NamedTuple, Optional

from .directory import Directory
from .environment import EnvModel

# fetch(conn, dn) -> rows
Report = NamedTuple("Report", [("headers", tuple), ("fetch", Callable)])

Domain = NamedTuple("Domain", [("name", str), ("schema", object),     # its SchemaFragment
                               ("required_roles", tuple),
                               ("sql", tuple),          # SQL files (views, functions) this domain adds to the store
                               ("reports", Mapping)])   # report name -> Report

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
                                 ("neutral_label", Optional[str])])   # short name of its environment-neutral config

# What every planner check receives.
PlanContext = NamedTuple("PlanContext", [("d", Directory), ("src", EnvModel), ("dst", EnvModel),
                                         ("cutover", Optional[object]), ("as_of", object),
                                         ("src_files", dict), ("dst_files", dict), ("neutral_paths", tuple)])
