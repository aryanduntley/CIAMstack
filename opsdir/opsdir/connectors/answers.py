"""Guided onboarding's answers (milestone 7.8): one typed document, written by `opsdir onboard setup` (or by hand, or by
any front end) and applied by `opsdir onboard apply`. Pure: the CLI reads and writes the file.

The document is TOML, version 1:

  [record]                     the record's identity: org (its org code), name, parent
  [[team]]                     a team: name, display, mail, operator (true: the party operating the platform)
  [settings]                   estate settings: name = value (approval-separation = false for a one-person install)
  [[environment]]              where the platform runs now: cloud, env, provider, region, partition, account,
                               lifecycle, and [environment.stack]: role = "adapter", or role = { adapter = "...",
                               versions = ">=0.1,<1" } (the adapter package versions the stack accepts)
  [migration]                  "will you be migrating?": from (the cloud/env that moves), the target's cloud, env,
                               provider, region, partition, account, lifecycle; its stack is the source's (none with
                               clear = true) with [migration.stack]'s roles changed (role = "" leaves one out)
  [[source]]                   an original export: importer (adapter/importer), path

parse_answers reads it (refusing keys it doesn't know, so a typo is never silently ignored); answers_problems says what
keeps it from being applied, answers_notices what is worth knowing (an adapter not installed); answers_toml writes it
back (parse_answers(answers_toml(a)) == a). setup_records turns it into the change records making the record say it:
the standard branches, the identity, the settings, the teams, each cloud, environment and declared stack, the
migration target. It
only adds and sets: what the record holds beyond the answers stays, and is named in the notices.
"""
import json
import re
import tomllib
from typing import NamedTuple, Optional

from ..core.changeset import merge_record
from ..core.directory import children, get, make_entry, ou_entry, rdn_value
from ..core.naming import SUFFIX
from ..core.versions import range_problem
from ..domains.governance.identity import code_problem, identity_changes
from ..domains.governance.parties import party_entry
from ..domains.infrastructure.declarations import cloud_entry, environment_dn, environment_entry, stack_entries
from ..core.settings import parse_setting
from .importing import importer_named, record_after
from .settings import changes_for_setting, declared_settings
from .registry import ADAPTERS, DOMAINS, standard_branches, vocabulary

VERSION = 1
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")      # cloud, environment, team and role names
LIFECYCLES = ("active", "building", "retiring", "retired")

Identity = NamedTuple("Identity", [("org", str), ("name", Optional[str]), ("parent", Optional[str])])
Team = NamedTuple("Team", [("name", str), ("display", Optional[str]), ("mail", Optional[str]), ("operator", bool)])
# A role of a declared stack: the adapter that fills it and the adapter package versions it accepts (None: any; a PEP
# 440 range, ciamAdapterVersion: the adapter's own version, not the product's). In a migration's
# changes an adapter of "" leaves the role out of the target.
Component = NamedTuple("Component", [("role", str), ("adapter", str), ("versions", Optional[str])])
Environment = NamedTuple("Environment", [("cloud", str), ("env", str), ("provider", str), ("region", str),
                                         ("partition", Optional[str]), ("account", Optional[str]),
                                         ("lifecycle", Optional[str]), ("stack", tuple)])
# The target of a migration: from (the source's cloud/env), the target environment as an Environment whose provider
# and region may be None (its cloud declared elsewhere in the answers), whether its stack starts empty, the changes.
Migration = NamedTuple("Migration", [("source", str), ("target", Environment), ("clear", bool), ("changes", tuple)])
Source = NamedTuple("Source", [("importer", str), ("path", str)])
# settings: ((estate setting name, its value as text), ...)
Answers = NamedTuple("Answers", [("version", int), ("identity", Optional[Identity]), ("teams", tuple),
                                 ("environments", tuple), ("migration", Optional[Migration]), ("sources", tuple),
                                 ("settings", tuple)])

# The document's shape: per table, its keys and whether each is required (keys a table may hold, the rest refused)
_KEYS = {"": {"version": True, "record": False, "settings": False, "team": False, "environment": False,
              "migration": False, "source": False},
         "record": {"org": True, "name": False, "parent": False},
         "team": {"name": True, "display": False, "mail": False, "operator": False},
         "environment": {"cloud": True, "env": True, "provider": True, "region": True, "partition": False,
                         "account": False, "lifecycle": False, "stack": False},
         "migration": {"from": True, "cloud": True, "env": True, "provider": False, "region": False,
                       "partition": False, "account": False, "lifecycle": False, "clear": False, "stack": False},
         "source": {"importer": True, "path": True}}
_TYPES = {"version": int, "operator": bool, "clear": bool, "stack": dict, "record": dict, "migration": dict,
          "settings": dict, "team": list, "environment": list, "source": list}


def _shape(table, kind, where):
    """Problems with one table's keys: unknown ones, missing required ones, values of the wrong type."""
    keys = _KEYS[kind]
    return (*(f"{where}: unknown key {k!r} (known: {', '.join(keys)})" for k in table if k not in keys),
            *(f"{where}: {k} is required" for k, required in keys.items() if required and k not in table),
            *(f"{where}: {k} must be {_TYPES.get(k, str).__name__}" for k, v in table.items()
              if k in keys and not isinstance(v, _TYPES.get(k, str))))


def _stack_shape(stack, where):
    def one(role, value):
        if isinstance(value, str):
            return ()
        if not isinstance(value, dict):
            return (f"{where}.{role}: give an adapter name, or {{ adapter = ..., versions = ... }}",)
        return (*(f"{where}.{role}: unknown key {k!r} (adapter, versions)" for k in value
                  if k not in ("adapter", "versions")),
                *((f"{where}.{role}: adapter is required",) if "adapter" not in value else ()),
                *(f"{where}.{role}: {k} must be str" for k, v in value.items() if not isinstance(v, str)))
    return tuple(p for role, value in stack.items() for p in one(role, value))


def _tables(raw, key):
    found = raw.get(key, [])
    return found if isinstance(found, list) else []


def shape_problems(raw):
    """Problems with a parsed TOML document's shape (tables, keys, types), before it is read into Answers."""
    tables = ((raw.get("record"), "record", "[record]"), (raw.get("migration"), "migration", "[migration]"),
              *((t, k, f"[[{k}]] #{i + 1}") for k in ("team", "environment", "source")
                for i, t in enumerate(_tables(raw, k))))
    nested = tuple(t for t, _, _ in tables if t is not None)
    settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}
    return (*_shape(raw, "", "the document"),
            *(f"[settings] {k}: give text, a whole number, true or false" for k, v in settings.items()
              if not isinstance(v, (str, int, bool))),
            *(p for t, kind, where in tables if isinstance(t, dict) for p in _shape(t, kind, where)),
            *(f"{where} must be a table" for t, _, where in tables if t is not None and not isinstance(t, dict)),
            *(p for t in nested if isinstance(t, dict) and isinstance(t.get("stack"), dict)
              for p in _stack_shape(t["stack"], "stack")))


def _component(role, value):
    if isinstance(value, str):
        return Component(role, value, None)
    return Component(role, value["adapter"], value.get("versions") or None)


def _stack(table):
    return tuple(_component(role, value) for role, value in table.get("stack", {}).items())


def _environment(t):
    return Environment(t["cloud"], t["env"], t.get("provider"), t.get("region"), t.get("partition"), t.get("account"),
                       t.get("lifecycle"), _stack(t))


def read_answers(raw):
    """The Answers of a parsed document whose shape holds (shape_problems says nothing)."""
    record, migration = raw.get("record"), raw.get("migration")
    return Answers(raw["version"],
                   Identity(record["org"], record.get("name"), record.get("parent")) if record else None,
                   tuple(Team(t["name"], t.get("display"), t.get("mail"), t.get("operator", False))
                         for t in _tables(raw, "team")),
                   tuple(_environment(t) for t in _tables(raw, "environment")),
                   Migration(migration["from"], _environment(migration), migration.get("clear", False),
                             _stack(migration)) if migration else None,
                   tuple(Source(s["importer"], s["path"]) for s in _tables(raw, "source")),
                   tuple((k, _setting_text(v)) for k, v in raw.get("settings", {}).items()))


def _setting_text(v):
    return ("TRUE" if v else "FALSE") if isinstance(v, bool) else str(v)


def parse_answers(text):
    """(Answers or None, problems) of an answers document's text: None with the problems when it isn't TOML or its
    shape doesn't hold."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return None, (f"not TOML: {e}",)
    problems = shape_problems(raw)
    return (None, problems) if problems else (read_answers(raw), ())


# ------------------------------------------------------------------ the migration target
def spec(e):
    return f"{e.cloud}/{e.env}"


def _cloud_of(answers, cloud):
    return next((e for e in answers.environments if e.cloud == cloud), None)


def target_environment(answers):
    """The migration's target as an Environment: its cloud's provider, region, partition and account from the answers
    where the target names none (the same cloud as a declared environment), and its stack the source's (none when
    clear) with the changes applied: a changed role takes the new adapter and versions, an adapter of "" leaves the
    role out. None without a migration (or a source the answers don't declare)."""
    m = answers.migration
    source = next((e for e in answers.environments if spec(e) == m.source), None) if m else None
    if source is None:
        return None
    same = _cloud_of(answers, m.target.cloud)
    held = {} if m.clear else {c.role: c for c in source.stack}
    stack = {**held, **{c.role: c for c in m.changes}}
    t = m.target
    return t._replace(provider=t.provider or (same and same.provider), region=t.region or (same and same.region),
                      partition=t.partition or (same and same.partition), account=t.account or (same and same.account),
                      stack=tuple(c for c in stack.values() if c.adapter))


def declared(answers):
    """Every environment the answers declare: the current ones, then the migration target."""
    target = target_environment(answers)
    return (*answers.environments, *((target,) if target else ()))


# ------------------------------------------------------------------ problems and notices
def _name_problem(name, what):
    return None if NAME.match(name or "") else f"{what} {name!r}: lower-case letters, digits, '.', '_' and '-'"


def _environment_problems(e, where, providers, partitions):
    return tuple(p for p in (
        _name_problem(e.cloud, f"{where}: cloud"), _name_problem(e.env, f"{where}: env"),
        f"{where}: give the cloud's provider" if not e.provider else None if e.provider in providers else
        f"{where}: provider {e.provider!r} is none an installed adapter declares ({', '.join(sorted(providers))})",
        None if e.region else f"{where}: give the cloud's region",
        None if e.partition in (None, *partitions) else
        f"{where}: partition {e.partition!r} isn't one of {', '.join(sorted(partitions))}",
        None if e.lifecycle in (None, *LIFECYCLES) else
        f"{where}: lifecycle {e.lifecycle!r} isn't one of {', '.join(LIFECYCLES)}",
        *(_name_problem(c.role, f"{where}: stack role") for c in e.stack),
        *(f"{where}: stack role {c.role}: {range_problem(c.versions)}" for c in e.stack
          if c.versions and range_problem(c.versions))) if p)


def _cloud_problems(environments):
    """Clouds named more than once with a different provider, region, partition or account."""
    facts = {c: {(e.provider, e.region, e.partition, e.account) for e in environments if e.cloud == c}
             for c in dict.fromkeys(e.cloud for e in environments)}
    return tuple(f"cloud {c} is given different providers, regions, partitions or accounts" for c, seen in facts.items()
                 if len(seen) > 1)


def _vocabulary(installed, attribute):
    return {v for a, v, _ in vocabulary(DOMAINS, installed) if a == attribute}


def answers_problems(answers, installed=ADAPTERS):
    """What keeps the answers from being applied: the version, names, providers and partitions the installed adapters
    don't declare, version ranges, environments declared twice, a cloud given two ways, more than one operator, a
    migration whose source isn't declared or whose target already is, importers not installed."""
    providers, partitions = _vocabulary(installed, "ciamCloudProvider"), _vocabulary(installed, "ciamCloudEnvironment")
    envs = declared(answers)
    specs = [spec(e) for e in answers.environments]
    m = answers.migration
    return tuple(p for p in (
        None if answers.version == VERSION else f"version {answers.version}: this opsdir reads version {VERSION}",
        answers.identity and code_problem(answers.identity.org),
        answers.identity and answers.identity.parent and code_problem(answers.identity.parent, "parent org code"),
        *(_name_problem(t.name, "team") for t in answers.teams),
        None if sum(t.operator for t in answers.teams) <= 1 else "only one team operates the platform",
        *(f"environment {s} is declared twice" for s in sorted(set(specs)) if specs.count(s) > 1),
        *(p for e in answers.environments
          for p in _environment_problems(e, f"environment {spec(e)}", providers, partitions)),
        *((f"migration: from {m.source!r} isn't an environment the answers declare",)
          if m and m.source not in specs else ()),
        *((f"migration: the target {spec(m.target)} is already declared",) if m and spec(m.target) in specs else ()),
        *(p for e in envs[len(answers.environments):]
          for p in _environment_problems(e, f"migration target {spec(e)}", providers, partitions)),
        *(_name_problem(c.role, "migration: stack role") for c in (m.changes if m else ())),
        *_cloud_problems(envs),
        *(_importer_problem(s.importer, installed) for s in answers.sources),
        *(_setting_problem(name, text, installed) for name, text in answers.settings)) if p)


def _setting_problem(name, text, installed):
    found = [x for _, x in declared_settings(DOMAINS, installed) if x.name == name]
    if not found:
        return f"[settings] {name}: no installed domain or adapter declares it (`opsdir report settings` lists them)"
    problem = parse_setting(found[0], text)[1]
    return f"[settings] {name}: {problem}" if problem else None


def _importer_problem(name, installed):
    try:
        importer_named(name, installed)
        return None
    except SystemExit as e:
        return f"source {name}: {e}"


def answers_notices(answers, installed=ADAPTERS):
    """What is worth knowing before applying: each declared adapter that isn't installed here (`opsdir check` says
    where to get it), each role a migration changes that the source doesn't have."""
    names = {a.name for a in installed}
    m = answers.migration
    source = next((e for e in answers.environments if m and spec(e) == m.source), None)
    return (*(f"{spec(e)}: {c.role} = {c.adapter}: not installed here (`opsdir check` says where to get it)"
              for e in declared(answers) for c in e.stack if c.adapter not in names),
            *(f"migration: role {c.role} isn't in {m.source}'s stack: it is added" for c in (m.changes if m else ())
              if source and c.adapter and c.role not in {x.role for x in source.stack}))


# ------------------------------------------------------------------ writing the document
def _value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


def _setting_value(text):
    """A setting's text as the TOML value it was most likely written as: true/false, a whole number, else text."""
    return {"TRUE": True, "FALSE": False}.get(text, int(text) if text.lstrip("-").isdigit() else text)


def _key(k):
    return k if re.match(r"^[A-Za-z0-9_-]+$", k) else json.dumps(k, ensure_ascii=False)


def _pairs(pairs):
    return tuple(f"{_key(k)} = {_value(v)}" for k, v in pairs if v is not None and v != ())


def _stack_lines(header, stack):
    def one(c):
        return _value(c.adapter) if not c.versions else \
            f"{{ adapter = {_value(c.adapter)}, versions = {_value(c.versions)} }}"
    return (header, *(f"{_key(c.role)} = {one(c)}" for c in stack)) if stack else ()


def _environment_pairs(e):
    return (("cloud", e.cloud), ("env", e.env), ("provider", e.provider), ("region", e.region),
            ("partition", e.partition), ("account", e.account), ("lifecycle", e.lifecycle))


def answers_toml(answers):
    """The answers as a TOML document parse_answers reads back as the same Answers."""
    i, m = answers.identity, answers.migration
    blocks = (
        ("# CIAMstack onboarding answers: `opsdir onboard apply <this file>` writes them into the record.",
         *_pairs((("version", answers.version),))),
        *((("[record]", *_pairs((("org", i.org), ("name", i.name), ("parent", i.parent)))),) if i else ()),
        *((("[settings]", *_pairs((n, _setting_value(t)) for n, t in answers.settings)),) if answers.settings else ()),
        *(("[[team]]", *_pairs((("name", t.name), ("display", t.display), ("mail", t.mail),
                                ("operator", t.operator or None))))
          for t in answers.teams),
        *(("[[environment]]", *_pairs(_environment_pairs(e)), *_stack_lines("[environment.stack]", e.stack))
          for e in answers.environments),
        *((("[migration]", *_pairs((("from", m.source), *_environment_pairs(m.target), ("clear", m.clear or None))),
            *_stack_lines("[migration.stack]", m.changes)),) if m else ()),
        *(("[[source]]", *_pairs((("importer", s.importer), ("path", s.path)))) for s in answers.sources))
    return "\n\n".join("\n".join(b) for b in blocks) + "\n"


# ------------------------------------------------------------------ the records
def _suffix_entry():
    return make_entry(SUFFIX, ("top", "domain"), {"dc": (SUFFIX.split("=", 1)[1],)})


def _desired(answers):
    """The entries the answers say the record holds, parents first: teams, clouds, environments and their stacks."""
    envs = declared(answers)
    clouds = {e.cloud: e for e in envs}
    return (*(party_entry(t.name, "operator" if t.operator else "team", t.display, t.mail) for t in answers.teams),
            *(cloud_entry(c, e.provider, e.region, e.partition, e.account) for c, e in clouds.items()),
            *(x for e in envs for x in (environment_entry(e.cloud, e.env, e.lifecycle),
                                        *stack_entries(e.cloud, e.env, tuple(e.stack)))))


def _beyond(d, answers):
    """Notices naming the stack components the record holds for a declared environment that the answers don't."""
    def extra(e):
        held = children(d, f"ou=stack,{environment_dn(e.cloud, e.env)}", "ciamStackComponent")
        named = {c.role for c in e.stack}
        return tuple(f"{spec(e)}: stack role {rdn_value(c)} is in the record but not in the answers: left as it is"
                     for c in held if rdn_value(c) not in named)
    return tuple(n for e in declared(answers) for n in extra(e))


def setup_records(d, answers, record_id, domains=DOMAINS):
    """(change records, notices) making record d say what the answers say: the suffix and every standard branch it
    lacks, the identity (record_id names it when new), the teams, each cloud, environment and declared stack, the
    migration target. Only adds and sets (core.changeset.merge_record): what the record holds beyond the answers stays,
    and the notices name the stack roles among it. ValueError for an identity the record can't take (another org
    code)."""
    base = (*(() if get(d, SUFFIX) else (_suffix_entry(),)),
            *(ou_entry(b) for b in standard_branches(domains) if get(d, b) is None))
    identity = identity_changes(d, answers.identity.org, record_id, answers.identity.parent,
                                answers.identity.name) if answers.identity else ()
    def merged(entries):
        return tuple(r for r in (merge_record(get(d, e.dn), e) for e in entries) if r)
    branches = merged(base)
    with_branches = record_after(d, branches)
    settings = tuple(r for name, text in answers.settings
                     for r in changes_for_setting(with_branches, name, text, domains))
    return (*branches, *identity, *settings, *merged(_desired(answers))), _beyond(d, answers)


# ------------------------------------------------------------------ typed at a prompt
def stack_text(text):
    """The components of a stack typed on one line: 'role=adapter[@versions]' separated by ';' (versions hold commas):
    'directory=pingds@>=7.2,<9; federation=pingfederate'. 'role=' leaves a role out (a migration's change). ValueError
    naming a part without '='."""
    def one(part):
        role, eq, rest = part.partition("=")
        if not eq or not role.strip():
            raise ValueError(f"{part.strip()!r}: give role=adapter[@versions]")
        adapter, _, versions = rest.partition("@")
        return Component(role.strip(), adapter.strip(), versions.strip() or None)
    return tuple(one(p) for p in text.split(";") if p.strip())


def stack_line(stack):
    """A stack as stack_text reads it back."""
    return "; ".join(f"{c.role}={c.adapter}" + (f"@{c.versions}" if c.versions else "") for c in stack)
