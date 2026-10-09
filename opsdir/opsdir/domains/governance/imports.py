"""Import runs: when each part of the record was last read back from the live system, and by which importer. Pure.

An applied import (`opsdir import --change`) records an import run under ou=imports for each environment whose part of
the record it read (and one for what environments share, a product's configuration): the importer, the scopes it made
match the live system, when the export was taken and the change it was applied under. One entry per importer and
environment, replaced by the next run (history keeps the earlier ones). A dry run records nothing. A fix that must not
act on a stale picture of the live system checks the runs (a fresh read of its environment first). When opsdir
collected the export itself (`opsdir collect`), the run also holds how (EVIDENCE: the identity the provider saw, each
call with the hash of what it returned, the credential references resolved); a run from an export read off disk holds
none of it.
"""
from ...core.changeset import new_entry
from ...core.directory import children, get, gtime, one, values, within
from ...core.interchange.ldif import LdifRecord
from ...core.naming import branch, env_label
from .naming import IMPORTS

IMPORT_HEADERS = ("importer", "environment", "scopes", "read at", "change")
EVIDENCE = ("ciamCollectionIdentity", "ciamCollectedCall", "ciamCollectionCredential")
SHARED = "shared"            # what an import reads that no environment holds (a product's configuration)


def _where(env):
    return env_label(env).replace("/", ".") if env else SHARED


def run_dn(importer, env=None):
    """The DN of importer's ('adapter/importer') run of an environment (its DN; None: what environments share)."""
    return f"cn={importer.replace('/', '.')}.{_where(env)},{IMPORTS}"


def _run(d, importer, env, scopes, at, change_id, evidence):
    dn, change = run_dn(importer, env), f"cn={change_id},{branch('changes')}"
    held = get(d, dn)
    if held is None:
        return new_entry(dn, ("top", "ciamObject", "ciamImportRun"), {
            "cn": (dn.split(",", 1)[0][3:],), "ciamImporter": (importer,), "ciamImportScope": scopes,
            "ciamImportedAt": (gtime(at),), "ciamChangeRef": (change,), **{a: v for a, v in evidence.items() if v}})
    proof = tuple(("replace", a, tuple(evidence.get(a, ()))) for a in EVIDENCE if evidence.get(a) or values(held, a))
    return LdifRecord(dn, "modify", {}, (("replace", "ciamImportScope", scopes),
                                         ("replace", "ciamImportedAt", (gtime(at),)),
                                         ("replace", "ciamChangeRef", (change,)), *proof))


def run_records(d, importer, scopes, at, change_id, evidence=None):
    """The records recording an import's runs (its export taken at `at`, a UTC datetime) under change change_id: the
    imports container when missing, then per environment of the scopes it read (and once for shared ones), a new run
    entry or the existing one's scopes, time and change; evidence ({attribute: values} of EVIDENCE: how opsdir
    collected the export, connectors.collecting.evidence) replaces what an earlier run held (none: removed)."""
    read = tuple(dict.fromkeys(scopes))
    by_env = {env: tuple(s for s in read if environment_of_scope(s) == env)
              for env in dict.fromkeys(environment_of_scope(s) for s in read)}
    return (*imports_container(d), *(_run(d, importer, env, found, at, change_id, evidence or {})
                                     for env, found in by_env.items()))


def imports_container(d):
    """(the ou=imports container's record,) when the record has none yet, else (): where import runs and collection
    attempts are kept."""
    return () if get(d, IMPORTS) is not None else (new_entry(IMPORTS, ("top", "organizationalUnit"),
                                                             {"ou": ("imports",)}),)


def environment_of_scope(scope):
    """The DN of the environment a scope lies in (the scope itself, or one under it), None outside environments."""
    parts = scope.split(",")
    at = next((i for i, p in enumerate(parts) if p.strip().lower().startswith("env=")), None)
    return ",".join(parts[at:]) if at is not None and within(scope, branch("environments")) else None


def runs_covering(d, dn):
    """The import runs one of whose scopes holds dn (the entry or one above it), newest first."""
    return tuple(sorted((r for r in children(d, IMPORTS, "ciamImportRun")
                         if any(within(dn, s) for s in values(r, "ciamImportScope"))),
                        key=lambda r: one(r, "ciamImportedAt"), reverse=True))


def import_rows(d, dn=None):
    """One row per import run: importer, the environment it read (or shared), how many scopes, when the export was
    taken and the change it was applied under; by importer, then environment."""
    def row(r):
        scopes = values(r, "ciamImportScope")
        env = environment_of_scope(scopes[0]) if scopes else None
        return (one(r, "ciamImporter"), env_label(env) if env else SHARED, len(scopes), one(r, "ciamImportedAt"),
                ", ".join(c.split(",", 1)[0].split("=", 1)[1] for c in values(r, "ciamChangeRef")))
    return sorted((row(r) for r in children(d, IMPORTS, "ciamImportRun")), key=lambda x: (x[0], x[1]))
