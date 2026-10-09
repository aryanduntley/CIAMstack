"""Collection attempts: how each `opsdir collect` of an importer's export last ended, failed ones included. Pure.

An import run (imports) records only what was applied. A collection that fails (a call exits with an error, a call is
refused, a bound is reached) or never starts (the identity check fails, the collector can't collect here) imports
nothing, so without this it would leave no trace once its output scrolled away. Every collection run under a change
(`opsdir collect --change`, not a dry run) records an attempt under ou=imports, beside the import runs: one entry per
importer and environment (or estate-wide), replaced by the next attempt (history keeps the earlier ones), holding the
outcome, when it ran, the change, the identity the provider saw, the calls it made (each with the hash of what it
returned, absent or failed) and its problems (credentials already masked by the collector).
"""
from typing import NamedTuple

from ...core.changeset import new_entry
from ...core.directory import children, get, gtime, one, values
from ...core.interchange.ldif import LdifRecord
from ...core.naming import branch, env_label
from .imports import EVIDENCE, imports_container
from .naming import IMPORTS

ATTEMPT_HEADERS = ("importer", "environment", "outcome", "at", "problems", "change")
ESTATE = "estate"            # where an estate collector (provider-wide data: regions, quotas) reads
OUTCOMES = ("complete", "incomplete", "skipped")

# One collection attempt: the importer ('adapter/importer'), the environment's DN (None: estate-wide), the outcome
# (OUTCOMES), its problems (none when complete) and its evidence ({attribute: values} of imports.EVIDENCE).
Attempt = NamedTuple("Attempt", [("importer", str), ("environment", object), ("outcome", str), ("problems", tuple),
                                 ("evidence", dict)])


def attempt_dn(importer, env=None):
    """The DN of the attempt record of importer ('adapter/importer') for an environment (its DN; None: estate-wide)."""
    where = env_label(env).replace("/", ".") if env else ESTATE
    return f"cn=collection.{importer.replace('/', '.')}.{where},{IMPORTS}"


def _one_line(text):
    return " ".join(text.split())


def _attempt(d, attempt, at, change):
    dn = attempt_dn(attempt.importer, attempt.environment)
    problems = tuple(_one_line(p) for p in attempt.problems)
    held = get(d, dn)
    if held is None:
        return new_entry(dn, ("top", "ciamObject", "ciamCollectionAttempt"), {
            "cn": (dn.split(",", 1)[0][3:],), "ciamImporter": (attempt.importer,),
            "ciamCollectionOutcome": (attempt.outcome,), "ciamCollectedAt": (gtime(at),), "ciamChangeRef": (change,),
            **({"ciamCollectedEnvironment": (attempt.environment,)} if attempt.environment else {}),
            **({"ciamCollectionProblem": problems} if problems else {}),
            **{a: v for a, v in attempt.evidence.items() if v}})
    proof = tuple(("replace", a, tuple(attempt.evidence.get(a, ()))) for a in EVIDENCE
                  if attempt.evidence.get(a) or values(held, a))
    said = ((("replace", "ciamCollectionProblem", problems),)
            if problems or values(held, "ciamCollectionProblem") else ())
    return LdifRecord(dn, "modify", {}, (("replace", "ciamCollectionOutcome", (attempt.outcome,)),
                                         ("replace", "ciamCollectedAt", (gtime(at),)),
                                         ("replace", "ciamChangeRef", (change,)), *said, *proof))


def attempt_records(d, attempts, at, change_id):
    """The records recording collection attempts (Attempts, run at `at`, a UTC datetime) under change change_id: the
    imports container when missing, then per attempt a new entry or the held one's outcome, time, change, problems and
    evidence replaced (none given: removed)."""
    found = tuple(attempts)
    if not found:
        return ()
    change = f"cn={change_id},{branch('changes')}"
    return (*imports_container(d), *(_attempt(d, a, at, change) for a in found))


def attempt_rows(d, dn=None):
    """One row per collection attempt: importer, the environment it read (or estate), outcome, when it ran, its
    problems (joined) and the change it ran under; by importer, then environment."""
    def row(r):
        env = one(r, "ciamCollectedEnvironment")
        return (one(r, "ciamImporter"), env_label(env) if env else ESTATE, one(r, "ciamCollectionOutcome"),
                one(r, "ciamCollectedAt"), "; ".join(values(r, "ciamCollectionProblem")),
                ", ".join(c.split(",", 1)[0].split("=", 1)[1] for c in values(r, "ciamChangeRef")))
    return sorted((row(r) for r in children(d, IMPORTS, "ciamCollectionAttempt")), key=lambda x: (x[0], x[1]))
