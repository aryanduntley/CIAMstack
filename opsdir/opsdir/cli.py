"""opsdir command line: parses arguments, calls operations (opsdir.operations), presents their results.

  opsdir init                          DROP the opsdir schema and create it from nothing (all migrations)
  opsdir upgrade                       upgrade the schema in place (pending migrations), keeping data and history
  opsdir load FILE...                  load LDIF content under change BOOTSTRAP
  opsdir check [ENV...]                each environment's declared stack against the installed adapters (and the
                                       provider prerequisites still pending)
  opsdir prerequisites                 data the installed adapters need fetched from their providers (a provider's
                                       region catalog): met, pending or not needed yet, and how to fetch each
  opsdir search [-b base] [-s scope] FILTER [attr...]
  opsdir report NAME [DN]              portability, unowned, blast-radius DN, and every domain's reports (expiring,
                                       keys ENV, …)
  opsdir render ENV [-o dir] [--target ADAPTER=T[,T]]... [--keeper PARTY | --kind CLASS... | --binding DN...]
                [--as REQUESTER]
                                       e.g. prod environment of a cloud: CLOUD/ENV (default out/ here); --target
                                       picks the outputs of an adapter that offers several (pingfederate=admin-api,
                                       terraform); default all, recorded in MANIFEST.json. --keeper / --kind /
                                       --binding: only that slice's infrastructure, complete in its own root (a
                                       keeper's whatever it takes); --as: who asks (default the database login)
  opsdir plan FROM TO [-o dir]         migration plan + change-request drafts for external parties
  opsdir migrate FROM TO [-o dir] [--as REQUESTER]
                                       check both stacks, plan, render the target (--as: who runs it, recorded in
                                       its MANIFEST); exit 1 unless ready
  opsdir fix list FROM TO              the record changes the plan's findings offer (assisted fixes)
  opsdir fix show FROM TO KEY          one fix: the change records, the steps outside the record, what it could hide
  opsdir fix propose FROM TO KEY --change CHG-… [--option O] [--input K=V …] [--title T]
                                       record it as change CHG-… with status proposed, for a person to approve
                                       (a fix that is a choice needs --option: one of those `fix show` lists; one
                                       that takes inputs, --input for each it needs: repeat a key for several values,
                                       K= leaves the attribute out)
  opsdir fix apply FROM TO KEY --change CHG-… [--option O] [--input K=V …]   apply it under an approved change
  opsdir fix approved --change CHG-…   apply the records a proposed change holds, once approved (marks it applied)
  opsdir modify --change CHG-… FILE    apply LDIF change records under an approved change
  opsdir capture --change CHG-… FILE [--name N] [--repo-path P] [--format F] [--role R] [--deploy-path D]
                                       hold a config file in the record (setting by setting; whole when it can't be
                                       parsed; only a reference when it may hold secrets, unless --accept-concerns)
  opsdir file NAME [--env ENV] [-o PATH]  rebuild a captured file from the record (links resolved for ENV)
  opsdir bundle --change CHG-… --kind K PATH [--root R] [--name N] [--version V] [--format F] [--role R]
                                       record code, scripts, templates or a package (a file or a directory under the
                                       repo checkout R) by repo path and SHA-256; its content is not stored
  opsdir verify [--root R]             bundles and captured files against a repo checkout (exit 1 if anything differs)
  opsdir onboard setup [-o FILE]       guided onboarding: asks about the record's identity, teams, settings, each
                                       environment's cloud and stack, whether you will be migrating (the target's stack
                                       starts as the source's: change only what moves) and the original exports, then
                                       writes the answers file (default onboarding.toml) and shows it; nothing else
  opsdir onboard apply FILE [--change CHG-…] [--dry-run]
                                       write the answers into the record: the standard branches, identity, teams,
                                       clouds, environments, declared stacks, the migration target; only adds and sets
                                       (what the record holds beyond the answers stays, and is named). A new record
                                       (after `init`) takes it as its initial load, as `load` does (the schema owner
                                       only); any other needs an approved --change
  opsdir onboard import FILE [--change CHG-…] [--dry-run] [--take K|all] [--keep K|all]
                                       import each original export the answers name ([[source]]), as `opsdir import`
  opsdir onboard verify (--source ADAPTER/IMPORTER=PATH ... | --saved DIR | --answers FILE) [--at YYYYMMDDhhmmssZ]
                [--all] [--diff] [--json]
                                       onboarding verification: render every environment, read it back, and compare it
                                       with what the original exports say, entry by entry and attribute by attribute
                                       (identical, equivalent, gap filled, decided, not rendered by design, loss,
                                       altered, uncovered); exit 1 on any loss, alteration or uncovered part. --source
                                       per export as given to `opsdir import` (repeat), --saved: what `collect --save`
                                       kept; the files are checked against the hashes their import recorded; --diff:
                                       text diffs of rendered files that differ from their originals (secrets masked)
  opsdir import [--change CHG-…] ADAPTER[/IMPORTER] PATH|--run [--dry-run] [--at YYYYMMDDhhmmssZ] [--take K|all]
                [--keep K|all]         read a product's export (a directory or a file) into the record with an
                                       adapter's importer; without --change (or with --dry-run) only lists the changes
                                       and conflicts (values the record holds that the import would replace or
                                       remove): each is decided, the live value taken or the record's kept; an
                                       applied import records when each scope it read was last imported; --run: run
                                       the importer's provider command(s) for the export instead of reading PATH,
                                       under your own login to the provider (opsdir never sees the credentials)
  <collect usage>
                                       read the live system for the installed adapters' importers, read-only: each
                                       collector's calls (your own provider login; credentials the record references
                                       resolved for the run, never stored), after a check that the login is the
                                       account the record names; a complete export goes through the import as
                                       `import` does (an incomplete one is never imported), and an applied one records
                                       how it was collected; with --change every attempt is recorded, failed ones
                                       with their problems (`report collections`); without --env: provider-wide
                                       data (regions, quotas);
                                       --list: the calls each collector starts with, nothing run; --save: keep the
                                       raw export (it may hold sensitive configuration: keep it on encrypted storage)
  opsdir data-profile --env CLOUD/ENV [LDIF] [--term NAME=ATTRIBUTE[=VALUE]]... [--at YYYYMMDDhhmmssZ] [-o FILE]
                                       the shape of a directory's user data, values-free: reads LDIF (ldapsearch
                                       output or an export; default standard input) once and writes counts only, for
                                       `opsdir import ldap/data-profile`; needs no database
  opsdir census [--change CHG-…] PATH [--dry-run] [--replace]
                                       where the record's values (hostnames, addresses, DNs, fingerprints, census
                                       terms operators define, ...) occur in files: each file and line, secret
                                       material flagged by line, never stored; --replace: PATH is the whole census
                                       (recorded files not under it are removed)
  opsdir evidence --boundary B [--control C]... [-o dir] [--change CHG-…] [--kept-at URL]
                                       a system boundary's evidence package as of --as-of: per control its evidence
                                       queries' outputs (CSV, JSON) and MANIFEST.json; --change: record the run on the
                                       boundary (--kept-at: where the package is kept)
  opsdir export [-b base]              dump entries as LDIF (for Git review)
  opsdir history [DN]                  change history
  opsdir application DN|NAME [--env CLOUD/ENV] [--format text|json]
                                       everything an entry touches, in sections (identity, directory, edge and service
                                       names, secrets and keys, certificates, network, monitoring, changes and
                                       incidents, owners), each row naming its entry; NAME: an application's
                                       (ou=applications); --env: the roles' bindings in that environment only
  opsdir graph DN|NAME [--direction down|up|both] [--depth N] [--env CLOUD/ENV] [--format text|json|dot]
                                       what an entry depends on and what depends on it (DN and role references)
  opsdir summary [FROM TO] [--format text|json]
                                       the estate in counts, each with its evidence; with FROM TO the plan's too
  opsdir workspace create [--replace]  copy the live record (OPSDIR_DSN) into the migration workspace
  opsdir workspace status|diff         what the workspace changed since its copy (diff: as LDIF change records)
  opsdir workspace cutover --change CHG-…   apply the workspace's changes to the live record, then re-copy
  opsdir --workspace COMMAND …         run any command against the workspace (OPSDIR_WORKSPACE_DSN)
"""
import argparse
import datetime as dt
import gzip
import io
import json
import os
import pathlib
import re
import subprocess
import sys
from functools import reduce
from types import MappingProxyType

from . import live, operations as ops
from .connectors import answers as answersmod, collecting, fixes as fixmod, importing, migration, onboarding
from .connectors import registry, workspace
from .connectors.application import HEADERS as VIEW_HEADERS, view_document
from .connectors.graph import graph_document, graph_dot, graph_lines
from .connectors.prerequisites import command_line
from .connectors.registry import ADAPTER_VERSIONS, ADAPTERS, COLLECT_OPTIONS, option_key
from .connectors.stack import STATUS_HEADERS
from .core.changeset import describe
from .core import search as ldap_search
from .core.directory import gtime_at, values
from .core.environment import ENVIRONMENT, Scope
from .domains.governance.authorization import Area
from .domains.governance.naming import OWNERS
from .core.findings import fix_inputs
from .core.interchange import ldif
from .core.interchange.export import export_text  # noqa: F401  (callers import it from here)
from .core.naming import SUFFIX
from .core.notes import summary
from .domains.governance.collection import declared_adapters
from .domains.governance.imports import file_evidence
from .store import postgres as db
from .store.policy import db_target
from .store.roles import DEFAULTS as ROLE_DEFAULTS, LOGINS, db_roles, db_roles_sql

# subcommand → ((argument flags, argparse options), …)
SUBCOMMANDS = (
    ("init", ()),
    ("upgrade", ()),
    ("load", ((("files",), {"nargs": "+"}),)),
    ("check", ((("envs",), {"nargs": "*"}),)),
    ("prerequisites", ()),
    ("search", ((("-b", "--base"), {"default": SUFFIX}),
                (("-s", "--scope"), {"default": "sub", "choices": ["base", "one", "sub"]}),
                (("filter",), {}), (("attrs",), {"nargs": "*"}))),
    ("report", ((("name",), {}), (("dn",), {"nargs": "?"}),
                (("--mine",), {"action": "store_true", "help": "only my teams' rows (by owner or keeper)"}))),
    ("mine", ()),
    ("render", ((("env",), {}), (("-o", "--out"), {}),
                (("--target",), {"action": "append", "default": [], "metavar": "ADAPTER=T[,T]",
                                 "help": "the render targets of an adapter (pingfederate=admin-api,terraform); "
                                         "default: all"}),
                (("--keeper",), {"metavar": "PARTY", "help": "only what this party keeps (its cn or DN), its root "
                                                             "whatever it takes"}),
                (("--kind",), {"action": "append", "default": [], "metavar": "CLASS",
                               "help": "only the entries of this object class (repeat for several)"}),
                (("--binding",), {"action": "append", "default": [], "metavar": "DN",
                                  "help": "only these bindings (repeat for several)"}),
                (("--as",), {"dest": "requester", "metavar": "REQUESTER",
                             "help": "who asks for the render (recorded in MANIFEST.json; default the database "
                                     "login)"}))),
    ("plan", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}),
              (("--mine",), {"action": "store_true", "help": "only my teams' blockers and actions"}))),
    ("tickets", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}),
                 (("--mine",), {"action": "store_true", "help": "only my teams' drafts"}))),
    ("migrate", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}),
                 (("--as",), {"dest": "requester", "metavar": "REQUESTER",
                              "help": "who runs the migration (recorded in the target's MANIFEST.json; default the "
                                      "database login)"}))),
    ("fix", ((("action",), {"choices": ["list", "show", "propose", "apply", "approved"]}), (("src",), {"nargs": "?"}),
             (("dst",), {"nargs": "?"}), (("key",), {"nargs": "?"}), (("--change",), {}), (("--title",), {}),
             (("--option",), {"help": "the choice, for a fix that offers options"}),
             (("--input",), {"action": "append", "default": [], "metavar": "KEY=VALUE",
                             "help": "a value a fix takes (repeat a key for several values; KEY= for none)"}),
             (("--mine",), {"action": "store_true", "help": "list: only fixes changing what my teams own or keep"}))),
    ("modify", ((("--change",), {"required": True}), (("file",), {}))),
    ("capture", ((("--change",), {"required": True}), (("file",), {}), (("--name",), {}), (("--repo-path",), {}),
                 (("--format",), {}), (("--role",), {}), (("--deploy-path",), {}),
                 (("--accept-concerns",), {"action": "store_true",
                                           "help": "store a text flagged as possibly secret (after review)"}))),
    ("file", ((("name",), {}), (("--env",), {}), (("-o", "--out"), {}))),
    ("bundle", ((("--change",), {"required": True}), (("path",), {}), (("--root",), {}), (("--name",), {}),
                (("--kind",), {"required": True, "choices": ["code", "script", "template", "package", "dashboard",
                                                             "other"]}),
                (("--version",), {}), (("--format",), {}), (("--role",), {}), (("--deploy-path",), {}))),
    ("verify", ((("--root",), {}),)),
    ("onboard", ((("action",), {"choices": ["setup", "apply", "import", "verify"]}),
                 (("file",), {"nargs": "?", "help": "apply, import: the answers file"}),
                 (("-o", "--out"), {"default": "onboarding.toml", "help": "setup: the answers file to write"}),
                 (("--answers",), {"metavar": "FILE", "help": "verify: the original exports the answers name"}),
                 (("--change",), {}),
                 (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}),
                 (("--take",), {"action": "append", "default": [], "metavar": "KEY",
                                "help": "import: a conflict where the live value goes in (KEY as listed, or all)"}),
                 (("--keep",), {"action": "append", "default": [], "metavar": "KEY",
                                "help": "import: a conflict where the record's value stays (KEY as listed, or all)"}),
                 (("--source",), {"action": "append", "default": [], "metavar": "ADAPTER/IMPORTER=PATH",
                                  "help": "an original export as given to `opsdir import` (repeat for each)"}),
                 (("--saved",), {"metavar": "DIR", "help": "the exports `opsdir collect --save DIR` kept"}),
                 (("--at",), {"help": "when the originals were taken, YYYYMMDDhhmmssZ (UTC; default: now)"}),
                 (("--all",), {"action": "store_true", "help": "list every difference (default: 10 per importer and "
                                                              "kind)"}),
                 (("--diff",), {"action": "store_true", "help": "text diffs of rendered files that differ from "
                                                               "their originals"}),
                 (("--json",), {"action": "store_true", "help": "the whole verification as JSON"}))),
    ("census", ((("--change",), {}), (("path",), {}),
                (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}),
                (("--replace",), {"action": "store_true",
                                  "help": "the scan is the whole census: recorded files not in it are removed"}))),
    ("import", ((("--change",), {}), (("importer",), {"help": "adapter[/importer]"}),
                (("path",), {"nargs": "?", "help": "the export (a directory or a file); not with --run"}),
                (("--run",), {"action": "store_true",
                              "help": "run the importer's provider command(s) for the export, under your own login"}),
                (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}),
                (("--at",), {"help": "when the export was taken, YYYYMMDDhhmmssZ (UTC; default: now)"}),
                (("--take",), {"action": "append", "default": [], "metavar": "KEY",
                               "help": "a conflict where the live value goes in (KEY as listed, or all)"}),
                (("--keep",), {"action": "append", "default": [], "metavar": "KEY",
                               "help": "a conflict where the record's value stays (KEY as listed, or all)"}))),
    ("collect", ((("--env",), {"help": "CLOUD/ENV to read (default: provider-wide data: regions, quotas)"}),
                 (("--adapter",), {"help": "only this adapter[/importer]"}), (("--change",), {}),
                 (("--list",), {"action": "store_true", "help": "the calls each collector starts with; run nothing"}),
                 (("--dry-run",), {"action": "store_true",
                                   "help": "collect and list the change records; apply nothing"}),
                 (("--save",), {"metavar": "DIR", "help": "keep the raw export under DIR (may hold sensitive config)"}),
                 # the installed collectors' own options (Collector.options), in their order
                 *(((o.flag,), {"metavar": o.metavar, "help": o.help}) for o in COLLECT_OPTIONS),
                 (("--at",), {"help": "when the export is taken, YYYYMMDDhhmmssZ (UTC; default: now)"}),
                 (("--take",), {"action": "append", "default": [], "metavar": "KEY",
                                "help": "a conflict where the live value goes in (KEY as listed, or all)"}),
                 (("--keep",), {"action": "append", "default": [], "metavar": "KEY",
                                "help": "a conflict where the record's value stays (KEY as listed, or all)"}))),
    ("posture", ()),
    ("db-roles", ((("--owner",), {"default": ROLE_DEFAULTS["owner"], "help": "the role owning the schema (no login)"}),
                  (("--migrator",), {"default": ROLE_DEFAULTS["migrator"],
                                     "help": "the login running init and upgrade"}),
                  (("--runtime",), {"default": ROLE_DEFAULTS["runtime"], "help": "the login opsdir runs as"}),
                  (("--database",), {"default": "opsdir"}),
                  (("--login",), {"default": "password", "choices": list(LOGINS),
                                  "help": "how the logins sign in"}),
                  (("--person",), {"action": "append", "default": [],
                                   "help": "a person's own login, a member of the runtime login; repeat"}))),
    ("grant", ((("name",), {}), (("--action",), {"action": "append", "default": [], "help": "an action it gives"}),
               (("--to",), {"action": "append", "default": [], "metavar": "LOGIN|TEAM",
                            "help": "a person (their login) or a team it is for; repeat"}),
               (("--env",), {"action": "append", "default": [], "metavar": "CLOUD/ENV",
                             "help": "limit it to an environment; repeat (none: every environment)"}),
               (("--owner",), {"action": "append", "default": [], "metavar": "TEAM",
                               "help": "limit it to what a team owns or keeps; repeat (none: every area)"}),
               (("--change",), {}),
               (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}))),
    ("change", ((("action",), {"choices": ["new", "approve", "reject", "show"]}), (("id",), {}),
                (("--title",), {}), (("--ticket",), {"help": "the ITSM ticket it is tracked by, <adapter>:<number>"}))),
    ("person", ((("login",), {"help": "the person's own database login"}), (("--name",), {}), (("--mail",), {}),
                (("--team",), {"action": "append", "help": "a team (ou=owners) they belong to; repeat for several"}),
                (("--change",), {}),
                (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}))),
    ("identity", ((("--org",), {"help": "the org code of the company this record belongs to (fixed once set)"}),
                  (("--parent",), {"help": "the org code of its group (\"\" removes it)"}),
                  (("--name",), {"help": "the company's name (\"\" removes it)"}), (("--change",), {}),
                  (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}))),
    ("setting", ((("name",), {"help": "an estate setting (opsdir report settings lists them)"}), (("value",), {}),
                 (("--change",), {}),
                 (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}))),
    ("data-profile", ((("--env",), {"required": True, "help": "CLOUD/ENV whose directory the data is from"}),
                      (("path",), {"nargs": "?", "default": "-", "help": "LDIF to read (default: standard input)"}),
                      (("--at",), {"help": "when the data was read, YYYYMMDDhhmmssZ (UTC; default: now)"}),
                      (("--term",), {"action": "append", "default": [], "metavar": "NAME=ATTRIBUTE[=VALUE]",
                                     "help": "what one of the estate's attributes means (last-login=lastLoginTime, "
                                             "pending=registrationStatus=pending, kba=challengeAnswer, ...)"}),
                      (("-o", "--out"), {"help": "write the profile here (default: standard output)"}))),
    ("evidence", ((("--boundary",), {"required": True, "help": "the system boundary (its cn or DN)"}),
                  (("--control",), {"action": "append", "default": [], "metavar": "C",
                                    "help": "only this control (framework:control; repeat for several)"}),
                  (("-o", "--out"), {}), (("--change",), {"help": "record the run under this approved change"}),
                  (("--kept-at",), {"metavar": "URL", "help": "where the package is kept (recorded with the run)"}))),
    ("export", ((("-b", "--base"), {"default": SUFFIX}),)),
    ("history", ((("dn",), {"nargs": "?"}),)),
    ("application", ((("dn",), {"metavar": "DN|NAME"}), (("--env",), {"metavar": "CLOUD/ENV"}),
                     (("--format",), {"default": "text", "choices": ["text", "json"]}),
                     (("--mine",), {"action": "store_true", "help": "only what my teams own or keep"}))),
    ("graph", ((("dn",), {"metavar": "DN|NAME"}),
               (("--direction",), {"default": "both", "choices": ["down", "up", "both"]}),
               (("--depth",), {"type": int, "default": 3}), (("--env",), {"metavar": "CLOUD/ENV"}),
               (("--format",), {"default": "text", "choices": ["text", "json", "dot"]}))),
    ("summary", ((("src",), {"nargs": "?", "metavar": "FROM"}), (("dst",), {"nargs": "?", "metavar": "TO"}),
                 (("--format",), {"default": "text", "choices": ["text", "json"]}))),
    ("workspace", ((("action",), {"choices": ["create", "status", "diff", "cutover"]}),
                   (("--change",), {}), (("--replace",), {"action": "store_true"}))),
)


def format_table(rows, headers):
    """Rows as aligned text columns with a row count: each column capped at 70 characters but the last, which nothing
    follows (it is often the one to read in full: what to check, why, a detail)."""
    cells = [[("" if v is None else str(v)) for v in r] for r in rows]
    last = len(headers) - 1
    widths = [min(max([len(h)] + [len(r[i]) for r in cells]), 70) for i, h in enumerate(headers)]
    fmt = lambda r: "  ".join(c if i == last else c[:70].ljust(widths[i]) for i, c in enumerate(r)).rstrip()  # noqa: E731
    return "\n".join((fmt(headers), "  ".join("-" * w for w in widths), *(fmt(r) for r in cells),
                      f"({len(cells)} rows)"))


def write_tree(outdir, files):
    """Effect: write {relative path: content} under outdir; shell scripts are made executable."""
    outdir = pathlib.Path(outdir)
    for p, content in files.items():
        f = outdir / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8", newline="\n")
        if p.endswith(".sh"):
            f.chmod(0o755)
    return outdir


def entries_text(entries, attrs=()):
    """Entries as a table of the requested attributes, or as LDIF with an entry count when none are given."""
    if attrs:
        return format_table([[e.dn] + ["|".join(values(e, x)) for x in attrs] for e in entries], ["dn", *attrs])
    return "\n".join((*(ldif.write_entry(e.dn, e.classes, e.attrs) for e in entries), f"# {len(entries)} entries"))


def search_text(d, base, filt, scope="sub", attrs=()):
    """Search hits as a table of the requested attributes, or as LDIF with an entry count when none are given."""
    return entries_text(ldap_search.search(d, base, filt, scope), attrs)


def stack_text(result):
    """(text, exit status) of a stack check."""
    return f"{format_table(result.rows, result.headers)}\n{result.problems} problem(s)", (1 if result.problems else 0)


def check_text(d, specs):
    """(text, exit status): every environment's declared stack against the installed adapters."""
    return stack_text(ops.stack_check(d, specs))


def migrate_text(d, src, dst, as_of, out):
    """(text, files to write, exit status) of `opsdir migrate`."""
    r = migration.run(d, src, dst, as_of, ADAPTERS, ADAPTER_VERSIONS)
    return migrated_text(r, out), migration.output_files(r), (0 if r.ready else 1)


def migrated_text(r, out):
    return f"{format_table(r.stack_rows, STATUS_HEADERS)}\n{migration.summary(r, out)}"


def capture_name(path):
    """A captured file's default name: its file name, with anything but letters, digits, '.', '_' and '-' as '-'."""
    return re.sub(r"[^A-Za-z0-9._-]", "-", pathlib.Path(path).name)


# ------------------------------------------------------------------ commands: parse, call an operation, present
def db_password(dsn=None):
    """Effect (runs the token command): the sign-in token for the record's database when OPSDIR_DB_AUTH names a
    scheme an installed adapter declares (a cloud database token for dsn, else OPSDIR_DSN), else None."""
    scheme = os.environ.get("OPSDIR_DB_AUTH")
    if not scheme:
        return None
    target = db_target(dsn or os.environ.get("OPSDIR_DSN"), os.environ)
    return live.db_token(registry.db_token_command(scheme, target))


def env_roles():
    """Effect (reads the environment): the database roles init, upgrade and workspace create apply
    (OPSDIR_DB_OWNER, OPSDIR_DB_RUNTIME; store.roles), or None."""
    try:
        return db_roles(os.environ)
    except ValueError as e:
        raise SystemExit(str(e)) from None


def _cmd_posture(conn, a, as_of):
    r, failures = ops.posture(conn, os.environ.get("OPSDIR_DB_TLS"), os.environ.get("OPSDIR_DB_AUTH"))
    table = format_table(r.rows, r.headers)
    return (f"{table}\n{failures} check(s) failed" if failures else table), (1 if failures else 0)


def _cmd_db_roles(conn, a, as_of):
    try:
        return db_roles_sql(a.owner, a.migrator, a.runtime, a.database, a.login, tuple(a.person)).rstrip("\n")
    except ValueError as e:
        raise SystemExit(str(e)) from None


def _cmd_init(conn, a, as_of):
    r = ops.init(conn, env_roles())
    later = [row[0] for row in ops.prerequisites(conn).rows if row[2] != "met"]    # met: nothing needs it yet
    return "\n".join((f"initialized: {r.attribute_types} attribute types, {r.object_classes} object classes",
                      *((f"provider prerequisites to fetch once an environment uses their adapter: {', '.join(later)} "
                         "(`opsdir prerequisites`)",) if later else ())))


def _cmd_upgrade(conn, a, as_of):
    r = ops.upgrade(conn, env_roles())
    return "\n".join((*(f"applied migration {label}" for label in r.applied),
                      f"schema at migration {r.version:04d}{'' if r.applied else ' (up to date)'}: "
                      f"{r.attribute_types} attribute types, {r.object_classes} object classes",
                      *pending_text(ops.pending_prerequisites(conn).rows)))


def _cmd_load(conn, a, as_of):
    r = ops.load(conn, db.read_ldif_files(a.files))
    return f"loaded {r.entries} entries from {len(a.files)} files; {r.references} DN references verified"


def pending_text(rows):
    """Lines naming the provider prerequisites still pending and how to fetch each (none when nothing is)."""
    return tuple(f"prerequisite pending: {name} ({adapter}): `{fetch}`, or run `{command}` and import its output"
                 for name, adapter, _, fetch, command in rows)


def _cmd_check(conn, a, as_of):
    text, status = stack_text(ops.check(conn, a.envs))
    pending = pending_text(ops.pending_prerequisites(conn).rows)
    return "\n".join((text, *pending)), status


def _cmd_prerequisites(conn, a, as_of):
    r = ops.prerequisites(conn)
    return format_table(r.rows, r.headers)


def _cmd_search(conn, a, as_of):
    return entries_text(ops.search(conn, a.base, a.filter, a.scope), a.attrs)


def _cmd_report(conn, a, as_of):
    if not a.mine:
        r = ops.report(conn, a.name, a.dn, as_of)
        return format_table(r.rows, r.headers)
    r, note = ops.my_report(conn, a.name, a.dn, as_of)
    return format_table(r.rows, r.headers) + (f"\n({note})" if note else "")


def _cmd_mine(conn, a, as_of):
    return "\n\n".join(f"{title}:\n" + ("\n".join(f"  {line}" for line in lines) or "  none")
                         for title, lines in ops.mine(conn))


def render_targets(given):
    """{adapter: (target, ...)} of --target values (ADAPTER=T[,T]); refused when one isn't of that form."""
    bad = [g for g in given if "=" not in g or not g.split("=", 1)[1]]
    if bad:
        raise SystemExit(f"--target takes ADAPTER=TARGET[,TARGET]: {', '.join(bad)}")
    return {k: tuple(t for t in v.split(",") if t) for k, v in (g.split("=", 1) for g in given)}


def render_scope(keeper, kinds, bindings):
    """The Scope of render's --keeper (a party's cn or DN), --kind and --binding options: the whole environment when
    none is given; refused when more than one kind of scope is."""
    given = [s for s in (("keeper", (keeper,) if keeper else ()), ("class", tuple(kinds)),
                         ("bindings", tuple(bindings))) if s[1]]
    if len(given) > 1:
        raise SystemExit("render takes one of --keeper, --kind or --binding")
    if not given:
        return ENVIRONMENT
    kind, value = given[0]
    return Scope(kind, tuple(v if kind != "keeper" or "=" in v else f"cn={v},{OWNERS}" for v in value))


def _cmd_render(conn, a, as_of):
    r = ops.render(conn, a.env, render_targets(a.target) or None, render_scope(a.keeper, a.kind, a.binding),
                   a.requester)
    out = write_tree(a.out or pathlib.Path("out") / r.label.replace("/", "-"), r.files)
    return "\n".join((f"rendered {len(r.files)} files for {r.dn} ({r.provider}) → {out}",
                      *(f"  UNBOUND role: {role}" for role in r.unbound),
                      f"notes: {summary(r.notes)}" + (f" (see {out}/NOTES.md)" if r.notes else ""),
                      *(f"  BLOCKER {n.subject}: {n.text} [{', '.join(n.owners) or 'NO OWNER'}]"
                        for n in r.notes if n.severity == "blocker")))


def _cmd_plan(conn, a, as_of):
    r = ops.plan(conn, a.src, a.dst, as_of, a.mine)
    label = f"plan-{r.plan.src.label.replace('/', '-')}-to-{r.plan.dst.label.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    write_tree(out, {"PLAN.md": r.markdown, **r.drafts})
    return r.markdown + f"\n\n(written to {out}/PLAN.md and {len(r.plan.requests)} request drafts in {out}/requests/)"


def _cmd_tickets(conn, a, as_of):
    files = ops.tickets(conn, a.src, a.dst, as_of, a.mine)
    out = pathlib.Path(a.out or pathlib.Path("out") / f"tickets-{a.src.replace('/', '-')}-to-{a.dst.replace('/', '-')}")
    write_tree(out, files)
    drafts = sorted(p for p in files if not p.endswith("README.md"))
    return "\n".join((f"{len(drafts)} work-ticket draft(s) written to {out}/ (nothing was sent to ITSM):",
                      *(f"  {p}" for p in drafts), f"how to file them, and what is missing: {out}/tickets/README.md"))


def _cmd_migrate(conn, a, as_of):
    label = f"migration-{a.src.replace('/', '-')}-to-{a.dst.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    r = ops.migrate(conn, a.src, a.dst, as_of, a.requester)
    write_tree(out, r.files)
    return migrated_text(r.run, out), (0 if r.run.ready else 1)


def _applied_text(r):
    return "\n".join(f"{r.change_id}: {line}" for line in r.lines)


def _cmd_modify(conn, a, as_of):
    return _applied_text(ops.modify(conn, db.read_ldif_files([a.file]), a.change))


def _cmd_capture(conn, a, as_of):
    preview = ops.preview_capture(conn, pathlib.Path(a.file).read_text(encoding="utf-8"),
                                  a.name or capture_name(a.file), a.repo_path or a.file, a.format, a.role,
                                  a.deploy_path, a.accept_concerns)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*preview.notices, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def read_content(path):
    """Effect: a bundle's content, {relative path: bytes} ({"": bytes} for a single file), or None when absent."""
    p = pathlib.Path(path)
    if p.is_file():
        return {"": p.read_bytes()}
    if p.is_dir():
        return {f.relative_to(p).as_posix(): f.read_bytes() for f in sorted(p.rglob("*")) if f.is_file()}
    return None


def _cmd_bundle(conn, a, as_of):
    root = pathlib.Path(a.root or ".")
    content = read_content(root / a.path)
    if content is None:
        raise SystemExit(f"nothing at {root / a.path}")
    preview = ops.preview_bundle(conn, a.name or capture_name(a.path), a.path, a.kind, content, a.format, a.version,
                                 a.role, a.deploy_path)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*preview.notices, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def read_texts(path):
    """Effect: an export's files as text, {relative path: text} ({name: text} for a single file); a gzip-compressed
    file is read decompressed, under its name without .gz; files that aren't UTF-8 text are left out and named."""
    p = pathlib.Path(path)
    files = ({p.name: p} if p.is_file() else
             {f.relative_to(p).as_posix(): f for f in sorted(p.rglob("*")) if f.is_file()} if p.is_dir() else None)
    if files is None:
        raise SystemExit(f"nothing at {p}")
    read = {_plain_name(rel): _text(f) for rel, f in files.items()}
    return {rel: t for rel, t in read.items() if t is not None}, tuple(rel for rel, t in read.items() if t is None)


def _plain_name(rel):
    return rel[:-3] if rel.endswith(".gz") else rel


def _text(f):
    try:
        raw = f.read_bytes()
        return (gzip.decompress(raw) if f.name.endswith(".gz") else raw).decode("utf-8")
    except (UnicodeDecodeError, OSError, EOFError):
        return None


def import_time(text=None):
    """When an import's export was taken: text as YYYYMMDDhhmmssZ (UTC), else now (whole seconds)."""
    if text is None:
        return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    try:
        return gtime_at(text)
    except ValueError:
        raise SystemExit(f"--at {text}: give the time as YYYYMMDDhhmmssZ (UTC), e.g. 20260930141500Z") from None


def _not_applied(notes, changes, dry_run):
    """A preview's notices, each change with what it modifies, and the count (nothing applied)."""
    return "\n".join((*notes, *(line for r in changes for line in describe(r)),
                      f"{len(changes)} change(s) (not applied{'' if dry_run else '; give --change to apply'})"))


def _given(pairs):
    """{key: values} from KEY=VALUE arguments (a key repeated gives several values; KEY= none)."""
    bad = [p for p in pairs if "=" not in p]
    if bad:
        raise SystemExit(f"--input {bad[0]}: give KEY=VALUE")
    split = [p.split("=", 1) for p in pairs]
    return {k: tuple(v for key, v in split if key == k and v) for k in dict.fromkeys(k for k, _ in split)}


def _input_lines(records):
    return tuple(f"  {i.key}: {i.label}" + (f" (default: {' | '.join(i.default)})" if i.default else "")
                 + (f" (e.g. {' | '.join(i.example)})" if i.example and i.example != i.default else "")
                 + (f" (matching {i.pattern})" if i.pattern else "") for i in fix_inputs(records))


def _record_lines(r):
    """A change record for review: a modify as describe gives it, an add with the attributes it sets."""
    return describe(r) if r.changetype != "add" else (
        f"add {r.dn}", *(f"    {k}: {' | '.join(v)}" for k, v in r.attrs.items() if k != "objectClass"))


def _fix_lines(fix):
    return (f"{fix.key} ({fix.area}): {fix.title}",
            *(("", *(x for r in fixmod.previewed(fix.records) for x in _record_lines(r))) if fix.records else ()),
            *(("", "Give (--input KEY=VALUE):", *_input_lines(fix.records)) if fix_inputs(fix.records) else ()),
            *(("", "Choose one (--option):", *(line for o in fix.options for line in (
                f"  {o.key}: {o.label}",
                *(f"      {x}" for r in fixmod.previewed(o.records) for x in _record_lines(r)),
                *(("      give (--input KEY=VALUE):", *(f"    {x}" for x in _input_lines(o.records)))
                  if fix_inputs(o.records) else ()),
                *(f"      risk: {k}" for k in o.risks)))) if fix.options else ()),
            *(("", "First (propose and apply wait for it):", *(f"  - {r.why}: an import of what it changes, taken "
                                                                "after the last change to it" for r in fix.requires))
              if fix.requires else ()),
            *(("", "Outside the record:", *(f"  - {m}" for m in fix.manual)) if fix.manual else ()),
            *(("", "What it could hide:", *(f"  - {r}" for r in fix.risks)) if fix.risks else ()))


def _fix_size(f):
    """What a fix changes, for the list: its options, or its records and the inputs they take."""
    inputs = fix_inputs(f.records)
    return f"{len(f.options)} options" if f.options else \
        f"{len(f.records)}" + (f" ({len(inputs)} input{'s' if len(inputs) > 1 else ''})" if inputs else "")


def _cmd_fix(conn, a, as_of):
    if a.mine and a.action != "list":
        raise SystemExit("--mine narrows opsdir fix list only")
    needs = {"list": ("src", "dst"), "show": ("src", "dst", "key"), "propose": ("src", "dst", "key", "change"),
             "apply": ("src", "dst", "key", "change"), "approved": ("change",)}[a.action]
    missing = [n for n in needs if not getattr(a, n)]
    if missing:
        raise SystemExit(f"opsdir fix {a.action} needs {', '.join(missing)}")
    if a.action == "approved":
        r = ops.apply_proposed(conn, a.change)
        return f"{a.change}: {len(r.lines) - 1} change(s) applied; marked applied"
    found = ops.fixes(conn, a.src, a.dst, as_of, a.mine)
    if a.action == "list":
        return format_table([(f.key, f.area, _fix_size(f),
                              len(f.manual), f.title) for f in found],
                            ("key", "area", "records", "manual steps", "what it does"))
    try:
        fix = fixmod.find_fix(found, a.key)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.action == "show":
        return "\n".join(_fix_lines(fix))
    given = _given(a.input)
    try:
        picked = fixmod.chosen(fix, a.option, given)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.action == "propose":
        try:
            ops.propose_fix(conn, a.src, a.dst, as_of, a.key, a.change, a.title, a.option, given)
        except ValueError as e:
            raise SystemExit(str(e)) from None
        return f"{a.change}: proposed ({len(picked.records)} change(s) held for approval)"
    try:
        r = ops.apply_fix(conn, a.src, a.dst, as_of, a.key, a.change, a.option, given)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    return f"{a.change}: {len(r.lines)} change(s) applied"


def _conflict_lines(conflicts):
    """Each conflict an import has with the record: its key, what the record holds and what the live system has."""
    def shown(vals):
        return " | ".join(vals) or "nothing"
    return tuple(f"conflict {c.key}: record {shown(c.held)} -> live {shown(c.live)}" for c in conflicts)


def run_export(spec, d=None):
    """Effect: an importer's export produced by running its provider commands (Importer.commands, derived from the
    record d when they depend on it) under the operator's own login to the provider, {relative path: standard output}.
    Refused when the importer has no command (or the record gives it nothing to fetch), the provider's tool isn't
    installed or a command fails (its error output named)."""
    _, importer = importing.importer_named(spec, ADAPTERS)
    if not importer.commands:
        raise SystemExit(f"{spec} has no provider command: give the export's path instead of --run")
    commands = importing.import_commands(importer, d)
    if not commands:
        raise SystemExit(f"{spec}: the record gives it nothing to fetch ({importer.description})")
    return {path: _run(path, argv) for path, argv in commands}


def _run(path, argv):
    try:
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", check=False)
    except FileNotFoundError:
        raise SystemExit(f"{argv[0]} is not installed here: install it and sign in to the provider, or run "
                         f"`{command_line(path, argv)}` where you can and import that file") from None
    if done.returncode:
        raise SystemExit(f"`{command_line(path, argv)}` failed (exit {done.returncode}): "
                         f"{done.stderr.strip()[-600:] or 'no error output'}")
    return done.stdout


def _cmd_import(conn, a, as_of):
    if a.run == bool(a.path):
        raise SystemExit("give the export's PATH or --run (not both)")
    files, skipped = (run_export(a.importer, db.load_directory(conn)), ()) if a.run else read_texts(a.path)
    plan = ops.preview_import(conn, a.importer, files, import_time(a.at))
    notes = (*(f"skipped (not UTF-8 text): {rel}" for rel in skipped), *plan.notices, *_conflict_lines(plan.conflicts))
    if a.dry_run or not a.change:
        return _not_applied(notes, plan.changes, a.dry_run)
    try:
        r = ops.apply_import(conn, plan, a.change, a.take, a.keep, file_evidence(files))
    except ValueError as e:
        raise SystemExit("\n".join((*_conflict_lines(plan.conflicts), str(e)))) from None
    return "\n".join((*notes, f"{a.change}: {len(r.lines)} change(s) applied, the import run among them"))


def _targets(d, a):
    """((adapter, collector), environment model or None) of a collect: the environment's applicable adapters'
    environment collectors, or every installed adapter's estate ones."""
    if a.env:
        m, adapters = registry.environment(d, a.env)
        named = declared_adapters(m)
        opted = tuple(x for x in ADAPTERS if x.name in named and x not in adapters)
        return collecting.chosen((*adapters, *opted), "environment", a.adapter, m), m
    return collecting.chosen(ADAPTERS, "estate", a.adapter), None


def _identity(adapter, collector, d, m, resolve):
    """(identity seen, problem) of a collector's identity check (None, None without one)."""
    check = collector.verify(d, m) if collector.verify else None
    if check is None:
        return None, None
    call, judge = check
    out, problem = live.run_call(call, resolve)
    if problem:
        return None, f"{adapter.name}: identity check `{collecting.provenance(call)}` failed: {problem}"
    found = judge(out)
    return " ".join(out.split())[:300], (f"{adapter.name}: {found}: nothing read" if found else None)


def _save(root, c):
    """Effect: the raw export of a complete collection and its manifest under root/<adapter>/<importer>/."""
    base = pathlib.Path(root) / c.importer
    for rel, text in c.files.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text, encoding="utf-8", newline="\n")
    (base / "MANIFEST.txt").write_text("".join(f"{x.sha256} {x.path} <- {x.provenance}\n" for x in c.calls),
                                       encoding="utf-8", newline="\n")
    return f"saved {len(c.files)} file(s) under {base} (raw provider output: keep it on encrypted storage)"


def _collected(conn, a, c):
    """What one collection leads to: its problems (not imported), or its import previewed or applied."""
    if c.problems:
        return (f"{c.importer}: incomplete, not imported", *(f"  {p}" for p in c.problems))
    if not c.calls:
        return (f"{c.importer}: nothing to collect here (its collection sources: ciamCollectionSource)",)
    saved = (_save(a.save, c),) if a.save else ()
    plan = ops.preview_import(conn, c.importer, c.files, import_time(a.at))
    head = (f"{c.importer}: {len(c.calls)} call(s) as {c.identity or 'your provider login'}", *saved,
            *plan.notices, *_conflict_lines(plan.conflicts))
    if a.dry_run or not a.change:
        return (_not_applied(head, plan.changes, a.dry_run),)
    try:
        r = ops.apply_import(conn, plan, a.change, a.take, a.keep, collecting.evidence(c))
    except ValueError as e:
        return (*head, f"{c.importer}: not applied: {e}")
    return (*head, f"{a.change}: {len(r.lines)} change(s) applied for {c.importer}, the import run among them")


def _listed(d, m, targets, options):
    return "\n".join(line for adapter, c in targets for line in (
        f"{adapter.name}/{c.importer}:",
        *((f"  check  {collecting.provenance(c.verify(d, m)[0])}",) if c.verify and c.verify(d, m) else ()),
        *(f"  {path}  {collecting.provenance(call)}" for path, call in collecting.first_calls(c, d, m, options))))


def _cmd_collect(conn, a, as_of):
    d = db.load_directory(conn)
    targets, m = _targets(d, a)
    if not targets:
        raise SystemExit(f"nothing to collect {'for ' + a.env if a.env else 'provider-wide'}"
                         f"{' with ' + a.adapter if a.adapter else ''}")
    captured = import_time(a.at)
    given = {k: v for k, v in ((option_key(o), getattr(a, option_key(o))) for o in COLLECT_OPTIONS) if v}
    options = {**given, "profile": lambda lines: ops.data_profile(lines, a.env, captured.date(), captured)} \
        if a.env else given
    if a.list:
        return _listed(d, m, targets, options)
    resolve = live.resolver()
    checking = {adapter.name: (adapter, c) for adapter, c in reversed(targets) if c.verify}
    checked = {name: _identity(adapter, c, d, m, resolve) for name, (adapter, c) in checking.items()}
    seen = {name: (None, None) for name in {adapter.name for adapter, _ in targets}} | checked
    outcomes = [(adapter, c, seen[adapter.name][1] or collecting.collect(
                    f"{adapter.name}/{c.importer}", c, d, m, lambda call: live.run_call(call, resolve), options,
                    seen[adapter.name][0])) for adapter, c in targets]
    lines = [line for adapter, c, o in outcomes for line in (
        (f"{adapter.name}/{c.importer}: skipped: {o}",) if isinstance(o, str) else _collected(conn, a, o))]
    attempts = tuple(x for x in (collecting.attempt(f"{adapter.name}/{c.importer}", o, m.dn if m else None)
                                 for adapter, c, o in outcomes) if x)
    failed = any(isinstance(o, str) or o.problems for _, _, o in outcomes)
    return "\n".join((*lines, *_attempts_recorded(conn, a, attempts, captured))), (1 if failed else 0)


def _attempts_recorded(conn, a, attempts, at):
    """What becomes of a collect's attempts: recorded under --change (not a dry run), else a word on the failed ones."""
    if a.dry_run or not a.change:
        failed = sum(x.outcome != "complete" for x in attempts)
        return (f"{failed} failed collection(s) not recorded ({'dry run' if a.dry_run else 'no --change'})",) \
            if failed else ()
    if not attempts:
        return ()
    ops.record_attempts(conn, attempts, at, a.change)
    return (f"{a.change}: {len(attempts)} collection attempt(s) recorded (opsdir report collections)",)


def _cmd_census(conn, a, as_of):
    files, skipped = read_texts(a.path)
    preview = ops.preview_census(conn, files, a.replace)
    notes = (*(f"skipped (not UTF-8 text): {rel}" for rel in skipped), *preview.notices)
    if a.dry_run or not a.change:
        return _not_applied(notes, preview.changes, a.dry_run)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*notes, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def _cmd_setting(conn, a, as_of):
    try:
        preview = ops.preview_setting(conn, a.name, a.value)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.dry_run or not a.change:
        return _not_applied(preview.notices, preview.changes, a.dry_run)
    r = ops.apply_preview(conn, preview, a.change)
    return f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else f"{a.name} already holds {a.value}"


def _cmd_change(conn, a, as_of):
    try:
        if a.action == "show":
            return "\n".join(ops.change_lines(conn, a.id))
        if a.action == "new":
            if not a.title:
                raise SystemExit("--title is required for a new change")
            ops.new_change(conn, a.id, a.title, a.ticket)
            return f"{a.id}: proposed; someone other than you approves it (opsdir change approve {a.id})"
        status = {"approve": "approved", "reject": "rejected"}[a.action]
        ops.change_status(conn, a.id, status)
        return f"{a.id}: {status}"
    except ValueError as e:
        raise SystemExit(str(e)) from None


def _cmd_grant(conn, a, as_of):
    try:
        preview = ops.preview_grant(conn, a.name, tuple(a.action), tuple(a.to), tuple(a.env), tuple(a.owner))
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.dry_run or not a.change:
        return _not_applied(preview.notices, preview.changes, a.dry_run)
    r = ops.apply_preview(conn, preview, a.change)
    return f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else f"grant {a.name} already holds this"


# The permission catalog's action each command is (governance.grants): reads, administration (left to the database's
# privileges), or what it does; a command that only previews without --change is a read.
FIXED_ACTIONS = MappingProxyType({
    **dict.fromkeys(("init", "upgrade", "load"), "admin"),
    **dict.fromkeys(("check", "search", "report", "export", "history", "application", "graph", "summary",
                     "prerequisites", "verify", "file", "posture", "mine"), "read"),
    "render": "render", "plan": "plan", "tickets": "plan", "migrate": "migrate", "modify": "apply",
    "workspace": "workspace"})
WHEN_CHANGED = MappingProxyType({**dict.fromkeys(("capture", "bundle", "census", "import", "collect", "evidence"),
                                                 "apply"),
                                 **dict.fromkeys(("setting", "identity", "person", "grant"), "settings")})
FIX_ACTIONS = MappingProxyType({"list": "plan", "show": "plan", "propose": "propose", "apply": "apply",
                                "approved": "apply"})
CHANGE_ACTIONS = MappingProxyType({"new": "propose", "approve": "approve", "reject": "approve", "show": "read"})
# what `opsdir onboard ACTION` is when it writes (with --change, not --dry-run); a read otherwise (a new record's
# initial load is the schema owner's, as `load`, and checked by the store)
ONBOARD_ACTIONS = MappingProxyType({"setup": "read", "apply": "apply", "import": "apply", "verify": "read"})


def command_action(a):
    """The catalog action a parsed command is."""
    if a.cmd in FIXED_ACTIONS:
        return FIXED_ACTIONS[a.cmd]
    if a.cmd == "fix":
        return FIX_ACTIONS[a.action]
    if a.cmd == "change":
        return CHANGE_ACTIONS[a.action]
    if a.cmd == "onboard":
        return ONBOARD_ACTIONS[a.action] if a.change and not a.dry_run else "read"
    return WHEN_CHANGED[a.cmd] if getattr(a, "change", None) and not getattr(a, "dry_run", False) else "read"


def command_area(a):
    """The Area a parsed command acts on (governance.authorization): render's environment and scope, a plan's or
    migration's target from its source, or the --env an option names; the whole record otherwise ("")."""
    if a.cmd == "render":
        return Area(a.env, render_scope(a.keeper, a.kind, a.binding))
    if getattr(a, "dst", None):
        return Area(a.dst, ENVIRONMENT, getattr(a, "src", None))
    return Area(getattr(a, "env", None) or "")


def _cmd_person(conn, a, as_of):
    if a.name is None and a.mail is None and a.team is None:
        found = ops.person_lines(conn, a.login)
        return "\n".join(found) if found else f"no person {a.login} (ou=people)"
    try:
        preview = ops.preview_person(conn, a.login, a.name, a.mail, a.team)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.dry_run or not a.change:
        return _not_applied(preview.notices, preview.changes, a.dry_run)
    r = ops.apply_preview(conn, preview, a.change)
    return f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else f"{a.login} already holds this"


def _cmd_identity(conn, a, as_of):
    if not a.org:
        if a.parent is not None or a.name is not None:
            raise SystemExit("--org is required to set the identity (the record's own org code)")
        held = ops.identity(conn)
        return identity_text(held) if held else "no record identity yet: opsdir identity --org CODE --change CHG"
    try:
        preview = ops.preview_identity(conn, a.org, a.parent, a.name)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.dry_run or not a.change:
        return _not_applied(preview.notices, preview.changes, a.dry_run)
    r = ops.apply_preview(conn, preview, a.change)
    return f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "the record already has this identity"


def identity_text(identity):
    """The record's identity as lines: org code, record ID, group, name."""
    return "\n".join((f"org code   {identity.org}", f"record id  {identity.record_id}",
                      *((f"group      {identity.parent}",) if identity.parent else ()),
                      *((f"name       {identity.name}",) if identity.name else ())))


def onboard_sources(given, saved=None, answered=()):
    """Effect (reads the files): ((spec, {relative path: text}), ...) of the original exports: each --source
    ADAPTER/IMPORTER=PATH (read as `opsdir import` reads it), then each export `opsdir collect --save DIR` kept under
    DIR/<adapter>/<importer>/ (its MANIFEST.txt left out), then those an answers file names (answered: (spec, path)
    pairs, answer_sources). Refused when none is given or one is malformed."""
    def source(text):
        spec, eq, path = text.partition("=")
        if not eq or not spec or not path:
            raise SystemExit(f"--source {text}: give ADAPTER[/IMPORTER]=PATH")
        return spec, read_texts(path)[0]
    root = pathlib.Path(saved) if saved else None
    kept = tuple((f"{a.name}/{i.name}", {p: t for p, t in read_texts(i)[0].items() if p != "MANIFEST.txt"})
                 for a in sorted(root.iterdir()) if a.is_dir() for i in sorted(a.iterdir()) if i.is_dir()) \
        if root else ()
    found = (*(source(s) for s in given), *kept, *((spec, read_texts(path)[0]) for spec, path in answered))
    if not found:
        raise SystemExit("give the original exports: --source ADAPTER/IMPORTER=PATH (repeat), --saved DIR or "
                         "--answers FILE")
    return found


def read_answers_file(path):
    """Effect (reads the file): the Answers in an onboarding answers file (connectors.answers); refused, naming every
    problem with its shape, when it isn't one."""
    p = pathlib.Path(path)
    if not p.is_file():
        raise SystemExit(f"no answers file at {p}")
    found, problems = answersmod.parse_answers(p.read_text(encoding="utf-8"))
    if problems:
        raise SystemExit("\n".join((f"{p}:", *(f"  {x}" for x in problems))))
    return found


def answer_sources(answers, path):
    """((importer, path), ...) of the original exports an answers file names, each path taken from the file's own
    folder unless absolute."""
    base = pathlib.Path(path).parent
    return tuple((s.importer, str(base / s.path)) for s in answers.sources)


def _onboard_apply(conn, a):
    answers = read_answers_file(a.file)
    try:
        preview = ops.preview_setup(conn, answers)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if a.dry_run:
        return _not_applied(preview.notices, preview.changes, True)
    if ops.new_record(conn):
        r = ops.apply_preview(conn, preview, "BOOTSTRAP")
        return "\n".join((*preview.notices, f"initial load: {len(r.lines)} change(s) applied",
                          f"next: `opsdir change new` a change for the imports, have it approved, then "
                          f"`opsdir onboard import {a.file} --change <it>` and `opsdir onboard verify --answers "
                          f"{a.file}`"))
    if not a.change:
        return _not_applied(preview.notices, preview.changes, False)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*preview.notices, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else
                      "the record already says all of it"))


def terminal_ask(prompt, default=""):
    """Effect: one question asked on the terminal, its answer stripped (the default when blank or at end of input)."""
    try:
        reply = input(f"{prompt}{f' [{default}]' if default else ''}: ")
    except EOFError:
        reply = ""
    return reply.strip() or default


def _repeat(one, so_far=()):
    """The items one(so_far) gives, asked again until it gives None."""
    item = one(so_far)
    return so_far if item is None else _repeat(one, (*so_far, item))


def _asked_stack(ask, prompt, default=""):
    """A stack typed on one line (connectors.answers.stack_text), asked again until it reads."""
    try:
        return answersmod.stack_text(ask(prompt, default))
    except ValueError as e:
        print(f"  {e}")
        return _asked_stack(ask, prompt, default)


def _asked_where(ask, prompt, default=""):
    """(cloud, env) typed as cloud/env, asked again until it is one; None when blank."""
    where = ask(prompt, default)
    if not where:
        return None
    cloud, _, env = where.partition("/")
    if cloud and env:
        return cloud, env
    print("  give it as cloud/env (aws-east/prod)")
    return _asked_where(ask, prompt, default)


def _asked_environment(ask, providers, adapters, so_far):
    where = _asked_where(ask, "An environment that runs today, as cloud/env (blank when done)")
    if where is None:
        return None
    cloud, env = where
    known = next((e for e in so_far if e.cloud == cloud), None)
    provider = known.provider if known else ask(f"{cloud}'s provider ({', '.join(sorted(providers))})")
    region = known.region if known else ask(f"{cloud}'s region")
    account = known.account if known else ask(f"{cloud}'s account, subscription or project (blank: not recorded)")
    stack = _asked_stack(ask, f"{cloud}/{env}'s stack: role=adapter[@adapter versions] separated by ';', such as "
                              f"directory=pingds; federation=pingfederate (installed: {', '.join(adapters)})")
    own = stack if any(c.role == "provider" for c in stack) else (
        answersmod.Component("provider", providers.get(provider, provider), None), *stack)
    return answersmod.Environment(cloud, env, provider, region, None, account or None,
                                  ask(f"{cloud}/{env}'s lifecycle (active, building, retiring)", "active"), own)


def _asked_migration(ask, environments, providers):
    if not environments or not ask("Will you be migrating? (y/N)", "n").lower().startswith("y"):
        return None
    specs = [answersmod.spec(e) for e in environments]
    source_spec = ask(f"Which environment moves ({', '.join(specs)})", specs[0])
    source = next((e for e in environments if answersmod.spec(e) == source_spec), environments[0])
    cloud, env = _asked_where(ask, "The target, as cloud/env", "") or (source.cloud + "-target", source.env)
    known = next((e for e in environments if e.cloud == cloud), None)
    provider = known.provider if known else ask(f"{cloud}'s provider ({', '.join(sorted(providers))})",
                                                source.provider)
    region = known.region if known else ask(f"{cloud}'s region", source.region if provider == source.provider else "")
    clear = ask("Start the target's stack empty instead of a copy of the source's? (y/N)", "n").lower() \
        .startswith("y")
    moved = "" if clear or provider == source.provider else f"provider={providers.get(provider, provider)}"
    changes = _asked_stack(ask, f"What changes (source's stack: {answersmod.stack_line(source.stack)}); "
                                f"role=adapter[@versions], role= leaves one out", moved)
    target = answersmod.Environment(cloud, env, None if known else provider, None if known else region, None, None,
                                    "building", ())
    return answersmod.Migration(answersmod.spec(source), target, clear, changes)


def _asked_source(ask, so_far):
    text = ask("An original export to import, as adapter/importer=path (blank when done)")
    if not text:
        return None
    importer, eq, path = text.partition("=")
    if eq and importer and path:
        return answersmod.Source(importer.strip(), path.strip())
    print("  give it as adapter/importer=path")
    return _asked_source(ask, so_far)


def prompted_answers(ask, installed=ADAPTERS):
    """The onboarding Answers from questions asked through ask(prompt, default) -> str: the record's identity, the
    teams (the one operating the platform first), each environment that runs today with its cloud and stack, whether
    you will be migrating (the target's stack starts as the source's, and only what moves is asked), the original
    exports; for a one-person install, approval-separation off. The questions only build the document; nothing is
    written."""
    providers = {v: a.name for a in installed if a.kind == "provider"
                 for v in a.vocabulary.get("ciamCloudProvider", ())}      # provider value -> its adapter
    adapters = sorted(a.name for a in installed if a.kind != "provider")
    org = ask("The record's org code (lowercase letters and digits, such as exa; blank: none yet)")
    identity = answersmod.Identity(org, ask("The organization's name") or None, None) if org else None
    operator = ask("The team that operates the platform (blank: none yet)")
    first = (answersmod.Team(operator, None, ask(f"{operator}'s mail") or None, True),) if operator else ()

    def team(so_far):
        name = ask("Another team (blank when done)")
        return answersmod.Team(name, None, ask(f"{name}'s mail") or None, False) if name else None
    teams = _repeat(team, first)
    alone = ask("Is this a one-person install, where an author may approve their own changes? (y/N)", "n")
    environments = _repeat(lambda so_far: _asked_environment(ask, providers, adapters, so_far))
    return answersmod.Answers(answersmod.VERSION, identity, teams, environments,
                              _asked_migration(ask, environments, providers),
                              _repeat(lambda so_far: _asked_source(ask, so_far)),
                              (("approval-separation", "FALSE"),) if alone.lower().startswith("y") else ())


def _onboard_setup(a, ask=terminal_ask):
    out = pathlib.Path(a.out)
    if out.exists() and not ask(f"{out} exists: replace it? (y/N)", "n").lower().startswith("y"):
        raise SystemExit(f"{out} kept; give another file with -o")
    answers = prompted_answers(ask)
    text = answersmod.answers_toml(answers)
    out.write_text(text, encoding="utf-8", newline="\n")
    problems = answersmod.answers_problems(answers)
    return "\n".join((text, f"written to {out}",
                      *((("to fix before applying (edit the file):", *(f"  {p}" for p in problems))) if problems else
                        (f"next: `opsdir onboard apply {out} --dry-run`, then without --dry-run",))))


def _decided_keys(keys, conflicts):
    """The --take/--keep keys that concern one import: those naming its conflicts, and 'all'."""
    known = {c.key for c in conflicts}
    return tuple(k for k in keys if k == importing.ALL or k in known)


def _onboard_import(conn, a):
    answers = read_answers_file(a.file)
    if not answers.sources:
        raise SystemExit(f"{a.file} names no original exports ([[source]] importer = ..., path = ...)")
    at = import_time(a.at)

    def one(importer, path):
        files, skipped = read_texts(path)
        plan = ops.preview_import(conn, importer, files, at)
        head = (f"{importer} <- {path}:", *(f"  skipped (not UTF-8 text): {rel}" for rel in skipped),
                *(f"  {n}" for n in (*plan.notices, *_conflict_lines(plan.conflicts))))
        if a.dry_run or not a.change:
            return (*head, f"  {len(plan.changes)} change(s) (not applied)"), 0
        try:
            r = ops.apply_import(conn, plan, a.change, _decided_keys(a.take, plan.conflicts),
                                 _decided_keys(a.keep, plan.conflicts), file_evidence(files))
        except ValueError as e:
            return (*head, f"  not applied: {e}"), 1
        return (*head, f"  {a.change}: {len(r.lines)} change(s) applied, the import run among them"), 0
    done = tuple(one(importer, path) for importer, path in answer_sources(answers, a.file))
    return "\n".join(line for lines, _ in done for line in lines), max(status for _, status in done)


def onboard_text(v, every=False, diffs=False):
    """A verification as text: its status and failing counts, the table of exports checked, the provenance
    warnings, the differences (connectors.onboarding.difference_rows), the files that differ from their originals
    (their text diffs with diffs) and the notices."""
    failing = onboarding.failing_counts(v)
    head = f"onboarding verification: {v.status.upper()}" + (
        f" ({', '.join(f'{k} {n}' for k, n in failing.items())})" if failing else "")
    warnings = tuple(w for c in v.checked for w in c.warnings)
    rows = onboarding.difference_rows(v, every)
    return "\n".join((
        head, "", format_table(onboarding.summary_rows(v), onboarding.SUMMARY_HEADERS),
        *(("", f"warnings ({len(warnings)}):", *(f"  {w}" for w in warnings)) if warnings else ()),
        *(("", f"differences ({len(rows)} of {len(v.differences)} listed{'' if every else '; --all lists every one'}):",
           format_table(rows, onboarding.DIFFERENCE_HEADERS)) if v.differences else ()),
        *(("", f"rendered files that differ from their originals ({len(v.pairs)}"
               f"{'' if diffs else '; --diff shows them'}):",
           *(line for p in v.pairs for line in ((*onboarding.text_diff(p), "") if diffs else
                                               (f"  {p.importer}  {p.path}  ({p.environment})"
                                                f"{'  layout only' if p.layout_only else ''}",)))) if v.pairs
          else ()),
        *(("", f"notices ({len(v.notices)}):", *(f"  {n}" for n in v.notices)) if v.notices else ())))


def _cmd_onboard(conn, a, as_of):
    if a.action in ("apply", "import") and not a.file:
        raise SystemExit(f"usage: opsdir onboard {a.action} FILE (the answers file `opsdir onboard setup` writes)")
    if a.action == "setup":
        return _onboard_setup(a)
    if a.action == "apply":
        return _onboard_apply(conn, a)
    if a.action == "import":
        return _onboard_import(conn, a)
    answered = answer_sources(read_answers_file(a.answers), a.answers) if a.answers else ()
    v = ops.onboard_verify(conn, onboard_sources(a.source, a.saved, answered), import_time(a.at))
    text = _json(onboarding.report_document(v)) if a.json else onboard_text(v, a.all, a.diff)
    return text, (1 if v.status == "fail" else 0)


def _cmd_verify(conn, a, as_of):
    root = pathlib.Path(a.root or ".")
    r = ops.verify(conn, {path: read_content(root / path) for path in ops.verify_paths(conn)})
    fine = ("unchanged", "same as the record")
    problems = sum(row[3] not in fine or bool(row[4]) for row in r.rows)
    return f"{format_table(r.rows, r.headers)}\n{problems} to look at", (1 if problems else 0)


def _cmd_file(conn, a, as_of):
    r = ops.rebuild_file(conn, a.name, a.env)
    if not a.out:
        return r.text.rstrip("\n") if r.text.endswith("\n") else r.text
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(r.text, encoding="utf-8", newline="\n")
    return f"rebuilt {a.name} ({r.repo_path}) → {out}"


def read_lines(path):
    """Effect: the lines of a file, or of standard input for -, opened when the first line is read; UTF-8 either
    way, whatever the locale."""
    if path == "-":
        yield from io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
        return
    with open(path, encoding="utf-8", errors="replace") as lines:
        yield from lines


def _cmd_data_profile(conn, a, as_of):
    if "/" not in a.env:
        raise SystemExit(f"--env {a.env}: give the environment as CLOUD/ENV, e.g. source/prod")
    try:
        text = ops.data_profile(read_lines(a.path), a.env, as_of, import_time(a.at), a.term)
    except ValueError as e:
        raise SystemExit(f"--term: {e}") from None
    if not a.out:
        return text.rstrip("\n")
    pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.out).write_text(text, encoding="utf-8", newline="\n")
    return f"wrote {a.out}"


def _cmd_export(conn, a, as_of):
    return ops.export(conn, a.base)


def _cmd_evidence(conn, a, as_of):
    try:
        r = ops.evidence(conn, a.boundary, as_of, a.control, a.change, a.kept_at)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    out = write_tree(a.out or pathlib.Path("out") / f"evidence-{a.boundary.split(',')[0].split('=')[-1]}", r.files)
    return "\n".join((f"evidence of {r.boundary} as of {as_of}: {len(r.files) - 1} files and MANIFEST.json → {out}",
                      *((f"{r.applied.change_id}: {line}" for line in r.applied.lines) if r.applied else
                        ("not recorded (no --change)",))))


def _cmd_history(conn, a, as_of):
    r = ops.history(conn, a.dn)
    return format_table(r.rows, r.headers)


def _json(document):
    """A document as JSON for a person and a diff: sorted keys, indented by two."""
    return json.dumps(document, indent=2, sort_keys=True)


def _cmd_application(conn, a, as_of):
    v = ops.application(conn, a.dn, as_of, a.env, a.mine)
    if a.format == "json":
        return _json(view_document(v))
    head = (f"{v.name} ({v.root})" + (f", in {v.environment}" if v.environment else "")
            + (f"\nparts: {', '.join(v.parts)}" if v.parts != (v.root,) else "")
            + (f"\nroles: {', '.join(v.roles)}" if v.roles else ""))
    return "\n\n".join((head, *(f"{s.name}\n" + (format_table(s.rows, VIEW_HEADERS) if s.rows else "(none)")
                                 for s in v.sections)))


def _cmd_graph(conn, a, as_of):
    g = ops.dependencies(conn, a.dn, a.direction, a.depth, a.env)
    return {"json": lambda: _json(graph_document(g)), "dot": lambda: graph_dot(g).rstrip("\n"),
            "text": lambda: graph_lines(g).rstrip("\n")}[a.format]()


def _cmd_summary(conn, a, as_of):
    if bool(a.src) != bool(a.dst):
        raise SystemExit("give both FROM and TO for the plan's counts, or neither")
    counts = ops.summary(conn, as_of, a.src, a.dst)
    if a.format == "json":
        return _json([c._asdict() | {"evidence": list(c.evidence)} for c in counts])
    def named(evidence):          # an entry by its name (the JSON form names it by DN), a command as it is
        return evidence.split(",", 1)[0].split("=", 1)[1] if "=" in evidence.split(",", 1)[0] else evidence
    return format_table([(c.what, c.count, ", ".join(named(x) for x in c.evidence)) for c in counts],
                        ("what", "count", "evidence"))


def _cmd_workspace(conn, a, as_of):
    if a.workspace:
        raise SystemExit("workspace commands run against the live record (OPSDIR_DSN); drop --workspace")
    ws_dsn = workspace.workspace_dsn()
    ws, source = db.connect(ws_dsn, db_password(ws_dsn)), os.environ["OPSDIR_DSN"]
    if a.action == "create":
        n = ops.workspace_create(conn, ws, source, a.replace, env_roles())
        return f"workspace created: {n} entries copied from {workspace.safe_source(source)}"
    if a.action == "status":
        return workspace.status_text(*ops.workspace_state(conn, ws))
    if a.action == "diff":
        return ldif.write_records(ops.workspace_state(conn, ws).changes) or "# no changes"
    if not a.change:
        raise SystemExit("usage: opsdir workspace cutover --change CHG-… (an approved change in the live record)")
    r = ops.workspace_cutover(conn, ws, source, a.change)
    return "\n".join((*(f"{a.change}: {line}" for line in r.lines),
                      f"cutover: {len(r.lines)} change(s) applied to the live record; workspace re-copied"))


COMMANDS = MappingProxyType({"init": _cmd_init, "upgrade": _cmd_upgrade, "load": _cmd_load, "check": _cmd_check,
                             "search": _cmd_search, "report": _cmd_report, "render": _cmd_render, "plan": _cmd_plan,
                             "migrate": _cmd_migrate, "tickets": _cmd_tickets, "fix": _cmd_fix, "modify": _cmd_modify,
                             "export": _cmd_export,
                             "history": _cmd_history, "application": _cmd_application, "graph": _cmd_graph,
                             "summary": _cmd_summary, "evidence": _cmd_evidence, "capture": _cmd_capture,
                             "import": _cmd_import, "collect": _cmd_collect, "file": _cmd_file,
                             "prerequisites": _cmd_prerequisites,
                             "bundle": _cmd_bundle, "verify": _cmd_verify, "onboard": _cmd_onboard,
                             "census": _cmd_census,
                             "setting": _cmd_setting, "identity": _cmd_identity, "db-roles": _cmd_db_roles,
                             "posture": _cmd_posture, "change": _cmd_change, "person": _cmd_person, "grant": _cmd_grant,
                             "mine": _cmd_mine,
                             "data-profile": _cmd_data_profile, "workspace": _cmd_workspace})
NO_DATABASE_ACTIONS = frozenset({("onboard", "setup")})   # asks questions and writes a local file
NO_DATABASE = frozenset({"data-profile",           # commands that run where only the source is reachable
                         "db-roles"})               # or before the record's database is set up


COLLECT_HEAD = ("[--env CLOUD/ENV]", "[--adapter A[/I]]", "[--list]", "[--dry-run]", "[--change CHG-…]", "[--save DIR]")
COLLECT_TAIL = ("[--at YYYYMMDDhhmmssZ]", "[--take K|all]", "[--keep K|all]")


def collect_usage(options, indent="  "):
    """The `opsdir collect` usage lines of the help at an indent (the description's, as the module docstring holds
    it): its own options, the installed collectors' after --save (in their order), wrapped at 108 characters past the
    indent, continued under the first option."""
    def wrapped(lines, token):
        last = lines[-1]
        return (*lines[:-1], f"{last} {token}") if len(last) + 1 + len(token) <= len(indent) + 108 else \
            (*lines, indent + " " * 15 + token)
    tokens = (*COLLECT_HEAD, *(f"[{o.flag} {o.metavar}]" for o in options), *COLLECT_TAIL)
    return "\n".join(reduce(wrapped, tokens[1:], (f"{indent}opsdir collect {tokens[0]}",)))


def description():
    """The help's description: the module docstring with the collect usage of the installed collectors' options."""
    return re.sub(r"^( *)<collect usage>$", lambda found: collect_usage(COLLECT_OPTIONS, found.group(1)), __doc__,
                  flags=re.M)


def parser():
    ap = argparse.ArgumentParser(prog="opsdir", description=description(),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as-of", help="evaluate dates as of YYYY-MM-DD (default: today)")
    ap.add_argument("--workspace", action="store_true",
                    help="run against the migration workspace (OPSDIR_WORKSPACE_DSN) instead of the live record")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, arguments in SUBCOMMANDS:
        command = sub.add_parser(name)
        for flags, options in arguments:
            command.add_argument(*flags, **options)
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    as_of = dt.date.fromisoformat(a.as_of) if a.as_of else dt.date.today()
    dsn = workspace.workspace_dsn() if a.workspace else None
    conn = None if a.cmd in NO_DATABASE or (a.cmd, getattr(a, "action", None)) in NO_DATABASE_ACTIONS else \
        db.connect(dsn, db_password(dsn))
    if conn is not None:
        db.set_as_of(conn, as_of)
        ops.authorize_command(conn, command_action(a), command_area(a), getattr(a, "requester", None))
    result = COMMANDS[a.cmd](conn, a, as_of)          # text, or (text, exit status)
    text, status = result if isinstance(result, tuple) else (result, 0)
    if text:
        print(text)
    if status:
        sys.exit(status)


def utf8_streams():
    """Effect: the standard streams in UTF-8 whatever the locale: output and error, so reports, LDIF and messages
    piped to files are UTF-8 like every file the CLI writes; input, so answers typed or piped in (onboard setup) are
    read as UTF-8, a byte that is not becoming U+FFFD as in read_lines."""
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")


def run():
    import psycopg
    utf8_streams()
    try:
        main()
    except psycopg.Error as e:
        msg = (e.diag.message_primary or str(e)).strip()
        detail = f" ({e.diag.message_detail})" if e.diag.message_detail else ""
        sys.exit(f"REJECTED by the directory: {msg}{detail}")


if __name__ == "__main__":
    run()
