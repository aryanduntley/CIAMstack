"""Collecting an importer's export from the live system, read-only (`opsdir collect`): an adapter's collector says
which calls produce the export's files (core.contract Collector, Command, Request); here they are run in rounds, each
asking for what the previous ones' outputs name (a list, then each item's details), through a runner the caller gives
(the effect: live.run_call), so this module stays pure.

A collection is complete or it isn't imported: an import makes the record's subtrees exactly what the export holds, so
a missing file would delete what the record holds. Any call that fails, a collector that keeps asking past ROUNDS
rounds or CALLS calls, or a command carrying a debug switch (provider debug output can print credentials) leaves the
collection incomplete, with its problems. What a complete one ran is its evidence: the identity the provider saw, each
call (the command or URL, never a credential) with the SHA-256 of what it returned and the file it became, and the
credential references it resolved; the applied import records it with the import run (domains.governance.imports).
Resolved credentials are masked (redact) wherever a call's error output or a problem would show them."""
import hashlib
import re
import shlex
from typing import NamedTuple

from ..core.contract import Collector, Command, Request
from ..domains.governance.config_sources import has_sources, source_problems, source_steps
from .importing import import_commands

ROUNDS = 5                  # rounds a collector may ask for more (a list, its items, their details, ...)
WORK = "_work/"             # outputs only the collector reads (the lists it takes items from): not in the export
CALLS = 2000                # calls one collection may make
MASK = "****"
DEBUG_SWITCHES = ("--debug", "--verbose", "-vvv", "--log-http", "--trace")

# One call of a collection: the file it becomes, what was run (provenance), the credential references it resolved, the
# SHA-256 of its output (None when it failed or there was nothing to read) and the problem (None when it didn't fail).
Call = NamedTuple("Call", [("path", str), ("provenance", str), ("credentials", tuple), ("sha256", object),
                           ("problem", object)])
# A collection: the importer ('adapter/importer'), its export ({path: text}, only when complete: else None), the calls
# made, the identity the provider reported (or None) and the problems (none: complete).
Collection = NamedTuple("Collection", [("importer", str), ("files", object), ("calls", tuple), ("identity", object),
                                       ("problems", tuple)])


def provenance(call):
    """What a call runs, in words that never hold a credential: the command line, or GET and the URL."""
    if isinstance(call, Request):
        return f"GET {call.url}"
    return shlex.join(call.argv) + (" (credentials on standard input)" if call.stdin else "")


def credential_refs(call):
    """The credential (and trust anchor) references a call resolves."""
    if isinstance(call, Request):
        return tuple(r for r in ((call.credential[1] if call.credential else None), call.ca) if r)
    return tuple(call.secrets)


def refused(call):
    """Why a call is never run (a debug switch on a command), or None."""
    found = [a for a in (call.argv if isinstance(call, Command) else ()) for s in DEBUG_SWITCHES
             if a == s or a.startswith(s + "=")]
    return f"{provenance(call)}: debug switches are never run ({', '.join(found)})" if found else None


def redact(text, secrets=(), patterns=()):
    """text with each resolved credential value (four characters or more) and each secret pattern's match masked."""
    masked = _masked(text, tuple(s for s in secrets if s and len(s) >= 4))
    return _patterned(masked, tuple(patterns))


def _masked(text, values):
    return _masked(text.replace(values[0], MASK), values[1:]) if values else text


def _patterned(text, patterns):
    return _patterned(re.sub(patterns[0], MASK, text), patterns[1:]) if patterns else text


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _kept(call, out, problem):
    """(output, problem) with the call's keep applied to what it returned: what the importer never reads is gone
    before the export, the evidence's hash or --save see it."""
    return (call.keep(out) if call.keep and out is not None and problem is None else out), problem


def _expanded(path, call, out, problem):
    """((path, call, output, problem), ...): a workdir command's files each under path, else the one output; a file
    kept that isn't a regular UTF-8 file (None: a link or binary) fails, since importers read text."""
    if isinstance(out, dict):
        return tuple((f"{path}/{rel}" if path else rel, call, text,
                      None if text is not None else "not a regular UTF-8 text file")
                     for rel, text in sorted(out.items())) or ((path, call, None, None),)
    return ((path, call, out, problem),)


def _round(collector, d, m, run, options, done, calls, rounds):
    """(calls made, outputs, problems) once the collector asks for nothing new, a call fails or a bound is reached;
    done: the outputs so far ({path: text}), calls the Calls so far."""
    read = {p: t for p, t in done.items() if t is not None}           # what there was to read (not absent)
    wanted = tuple((p, c) for p, c in collector.steps(d, m, read, options) if p not in done)
    if not wanted:
        return calls, done, ()
    if rounds >= ROUNDS or len(calls) + len(wanted) > CALLS:
        return calls, done, (f"{collector.importer}: still asking for more after {rounds} rounds and {len(calls)} "
                             f"calls (at most {ROUNDS} rounds and {CALLS} calls)",)
    bad = tuple(x for x in (refused(c) for _, c in wanted) if x)
    if bad:
        return calls, done, bad
    results = tuple(r for p, c in wanted for r in _expanded(p, c, *_kept(c, *run(c))))
    made = tuple(Call(p, provenance(c), credential_refs(c), sha256(out) if out is not None else None, problem)
                 for p, c, out, problem in results)
    failed = tuple(f"{c.path} ({c.provenance}): {c.problem}" for c in made if c.problem)
    outputs = {**done, **{p: None for p, _ in wanted},              # a workdir command's own path: asked, done
               **{p: out for p, _, out, problem in results if problem is None and out is not None}}
    absent = {p for p, _, out, problem in results if problem is None and out is None}
    outputs = {**outputs, **{p: None for p in absent}}
    if failed:
        return (*calls, *made), outputs, failed
    return _round(collector, d, m, run, options, outputs, (*calls, *made), rounds + 1)


def collect(spec, collector, d, m, run, options=None, identity=None):
    """The Collection of one importer's export (spec 'adapter/importer') by its collector for environment model m (None
    for estate scope), each call run with run(call) -> (output, problem); identity what the adapter's identity check
    saw (or None). Its files only when complete; nothing run when the collector says why it can't collect here."""
    blocked = tuple(collector.problems(d, m, options or {}) or ()) if collector.problems else ()
    if blocked:
        return Collection(spec, None, (), identity, blocked)
    calls, outputs, problems = _round(collector, d, m, run, options or {}, {}, (), 0)
    files = {p: t for p, t in outputs.items() if t is not None and not p.startswith(WORK)}
    return Collection(spec, None if problems else files, calls, identity, problems)


def credentials_used(collection):
    """The credential references a collection resolved, once each."""
    return tuple(dict.fromkeys(r for c in collection.calls for r in c.credentials))


def evidence(collection):
    """What an applied import records of a complete collection on its run: the identity the provider saw, each call
    (the SHA-256 of its output, the file it became and what ran) and the credential references resolved."""
    return {"ciamCollectionIdentity": (collection.identity,) if collection.identity else (),
            "ciamCollectedCall": tuple(f"{c.sha256 or 'absent'} {c.path} <- {c.provenance}" for c in collection.calls),
            "ciamCollectionCredential": credentials_used(collection)}


def first_calls(collector, d, m, options=None):
    """The calls a collector starts with (what `opsdir collect --list` shows: later rounds depend on the outputs)."""
    return tuple(collector.steps(d, m, {}, options or {}))


def command_collector(importer):
    """The estate-scope Collector of an importer whose export its provider commands produce (Importer.commands,
    static or derived from the record: connectors.importing.import_commands), or None: what `opsdir import --run`
    runs, collected the same way."""
    if not importer.commands:
        return None
    return Collector(importer.name, "estate",
                     lambda d, m, done, options: tuple((p, Command(tuple(argv)))
                                                      for p, argv in import_commands(importer, d)))


def _joined(*parts):
    """A function calling each part (None skipped) with the same arguments, their results as one tuple."""
    found = tuple(p for p in parts if p)
    return lambda *args: tuple(x for p in found for x in (p(*args) or ()))


def with_sources(adapter_name, collector):
    """An environment collector that also reads its importer's configuration sources (Git, Kubernetes, SSH:
    domains.governance.config_sources), as one collection: one import of the importer's export."""
    spec = f"{adapter_name}/{collector.importer}"
    return collector._replace(steps=_joined(collector.steps, source_steps(spec)),
                              problems=_joined(collector.problems, source_problems(spec)))


def collectors(adapter, m=None):
    """An adapter's collectors: those it declares (its environment ones also reading their configuration sources),
    then one per importer with provider commands it declares none for, then, for environment model m, one reading
    only its configuration sources for each importer with no environment collector that m declares sources for."""
    declared = tuple(adapter.collectors)
    named = {c.importer for c in declared}
    derived = tuple(c for c in (command_collector(i) for i in adapter.importers if i.name not in named) if c)
    environment = {c.importer for c in declared if c.scope == "environment"}
    sourced = tuple(with_sources(adapter.name, Collector(i.name, "environment", None))
                    for i in adapter.importers if i.name not in environment
                    and m is not None and has_sources(m, f"{adapter.name}/{i.name}"))
    return (*(with_sources(adapter.name, c) if c.scope == "environment" else c for c in declared), *derived, *sourced)


def chosen(adapters, scope, wanted=None, m=None):
    """((adapter, collector), ...) of a scope ('environment' or 'estate') among adapters, only those of the
    adapter[/importer] wanted names when given; m the environment model (source-only collectors only where it
    declares sources)."""
    name, _, importer = (wanted or "").partition("/")
    return tuple((a, c) for a in adapters for c in collectors(a, m) if c.scope == scope
                 and (not name or a.name == name) and (not importer or c.importer == importer))
