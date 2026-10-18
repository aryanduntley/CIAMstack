"""Import runs: what each import read back from the live system, when, and by which importer. Pure.

An applied import (`opsdir import --change`) records an import run under ou=imports for each environment whose part of
the record it read (and one for what environments share, a product's configuration): the importer, the scopes it made
match the live system (subtree roots, kept even when the export held nothing under one), when the export was taken
and the change it was applied under. A run is one importer's read of one scope set in one environment (or shared),
named by the set (scope_set_key: the same whatever the scopes' order, case or spacing). The next import of the same
set replaces its run (history keeps the earlier one); an import of another set (fewer scopes, more, others) records
its own run beside it, so what an earlier import proved it read stays. A dry run records nothing. A fix that must not
act on a stale picture of the live system checks the runs (the newest one covering everything it changes). When opsdir
collected the export itself (`opsdir collect`), the run also holds how (EVIDENCE: the identity the provider saw, each
call with the hash of what it returned, the credential references resolved); a run from an export opsdir didn't
collect (read off disk, or `opsdir import --run`) holds each file it was read from and the hash of its text instead
(IMPORTED_FILE, file_evidence), and a re-run of the same set either way clears what the other held. imported_files reads
the hashes back either way (what `opsdir onboard verify` checks the originals it is given against).
Runs recorded before runs were named by their scope set (by importer and environment only) are found by
check_import_runs, whose fix renames them under an approved change.
"""
import hashlib
import json

from ...core.changeset import delete_entry, new_entry
from ...core.directory import children, get, gtime, norm_dn, one, rdn_of, rdn_value, values, within
from ...core.findings import Fix, findings
from ...core.interchange.ldif import LdifRecord
from ...core.naming import branch, env_label
from .naming import IMPORTS
from .parties import operator_label

IMPORT_HEADERS = ("importer", "environment", "set", "scopes", "read at", "change")
IMPORT_SCOPE_HEADERS = ("importer", "environment", "set", "read at", "scope")
EVIDENCE = ("ciamCollectionIdentity", "ciamCollectedCall", "ciamCollectionCredential")
IMPORTED_FILE = "ciamImportedFile"
RUN_EVIDENCE = (*EVIDENCE, IMPORTED_FILE)    # what an import run's evidence replaces
SHARED = "shared"            # what an import reads that no environment holds (a product's configuration)
SCOPE_SET = "s1"             # the version of how a scope set is serialized for its name (scope_set_key)
RUN_CLASSES = ("top", "ciamObject", "ciamImportRun")
AREA = "Import runs"
RENAME_FIX = "imports/scope-set-names"


def _where(env):
    return env_label(env).replace("/", ".") if env else SHARED


def _env_key(scope):
    env = environment_of_scope(scope)
    return norm_dn(env) if env else None


def _environment(scopes):
    if len({_env_key(s) for s in scopes}) > 1:
        raise ValueError(f"an import run's scopes lie in one environment (or none): {', '.join(scopes)}")
    return environment_of_scope(scopes[0]) if scopes else None


def _prefix(importer, env):
    return f"{importer.replace('/', '.')}.{_where(norm_dn(env) if env else None)}"


def scope_set(scopes):
    """A scope set in canonical form: its scopes' normalized DNs (core.directory.norm_dn), each once, sorted."""
    return tuple(sorted({norm_dn(s) for s in scopes}))


def scope_set_key(scopes):
    """The name of a scope set: SCOPE_SET, then the first 16 hex digits of the SHA-256 of SCOPE_SET, a newline and the
    canonical set (scope_set) as compact JSON; the same whatever the scopes' order, case, spacing or repeats."""
    text = f"{SCOPE_SET}\n{json.dumps(scope_set(scopes), separators=(',', ':'), ensure_ascii=False)}"
    return f"{SCOPE_SET}-{hashlib.sha256(text.encode()).hexdigest()[:16]}"


def run_dn(importer, scopes):
    """The DN of importer's ('adapter/importer') run of a scope set, all in one environment or all in none:
    cn=<adapter>.<importer>.<environment, or shared>.<scope_set_key>,ou=imports; ValueError when the scopes lie in
    more than one environment."""
    return f"cn={_prefix(importer, _environment(scopes))}.{scope_set_key(scopes)},{IMPORTS}"


def _legacy_dn(importer, env):
    return f"cn={_prefix(importer, env)},{IMPORTS}"


def _replaced(held, scopes, read_at, changes, evidence):
    proof = tuple(("replace", a, tuple(evidence.get(a, ()))) for a in RUN_EVIDENCE
                  if evidence.get(a) or values(held, a))
    return LdifRecord(held.dn, "modify", {}, (("replace", "ciamImportScope", tuple(scopes)),
                                              ("replace", "ciamImportedAt", (read_at,)),
                                              ("replace", "ciamChangeRef", tuple(changes)), *proof))


def _same_set(e, scopes):
    return e is not None and scope_set(values(e, "ciamImportScope")) == scope_set(scopes)


def _run(d, importer, scopes, at, change_id, evidence):
    dn, changes = run_dn(importer, scopes), (f"cn={change_id},{branch('changes')}",)
    held, legacy = get(d, dn), get(d, _legacy_dn(importer, environment_of_scope(scopes[0])))
    if held is not None and not _same_set(held, scopes):
        raise ValueError(f"import run {rdn_value(held)} holds another scope set than the one {importer} read under "
                         f"the same name; nothing is recorded over it")
    retired = (delete_entry(legacy),) if _same_set(legacy, scopes) else ()
    if held is not None:
        return (_replaced(held, scopes, gtime(at), changes, evidence), *retired)
    return (new_entry(dn, RUN_CLASSES, {
        "cn": (rdn_of(dn),), "ciamImporter": (importer,), "ciamImportScope": scopes, "ciamImportedAt": (gtime(at),),
        "ciamChangeRef": changes, **{a: v for a, v in evidence.items() if v}}), *retired)


def _distinct(scopes):
    seen = tuple(norm_dn(s) for s in scopes)
    return tuple(s for i, s in enumerate(scopes) if seen[i] not in seen[:i])


def run_records(d, importer, scopes, at, change_id, evidence=None):
    """The records recording an import's runs (its export taken at `at`, a UTC datetime) under change change_id: the
    imports container when missing, then per environment of the scopes it read (and once for shared ones) the run of
    that scope set: a new entry, or the existing run of the same set given its scopes, time and change. evidence
    ({attribute: values} of RUN_EVIDENCE: how opsdir collected the export, connectors.collecting.evidence, or the files
    it was read from, file_evidence) replaces what that run held (none: removed). A run of the same set still named
    the old way (importer and environment only) is deleted; runs of other sets are left as they are. ValueError when
    another set's run holds the name."""
    read = _distinct(tuple(scopes))
    groups = tuple(tuple(s for s in read if _env_key(s) == k) for k in dict.fromkeys(_env_key(s) for s in read))
    return (*imports_container(d),
            *(r for found in groups for r in _run(d, importer, found, at, change_id, evidence or {})))


def file_evidence(files):
    """The evidence of an export opsdir didn't collect ({relative path: text}, read off disk or a provider command's
    output): {IMPORTED_FILE: each file as '<SHA-256 of its UTF-8 text> <path>', by path}; never its content."""
    return {IMPORTED_FILE: tuple(f"{hashlib.sha256(t.encode()).hexdigest()} {p}" for p, t in sorted(files.items()))}


def _hashed(value):
    digest, _, rest = value.partition(" ")
    return rest.split(" <- ", 1)[0], digest


def imported_files(run):
    """{path: SHA-256} of the files an import run's export was read from: its IMPORTED_FILE values, or the calls of a
    collection (ciamCollectedCall) that returned something (absent and failed calls left out)."""
    called = (_hashed(v) for v in values(run, "ciamCollectedCall"))
    return {**{p: h for p, h in called if h not in ("absent", "failed")},
            **dict(_hashed(v) for v in values(run, IMPORTED_FILE))}


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


def _newest_first(runs):
    return tuple(sorted(sorted(runs, key=lambda r: r.norm), key=lambda r: one(r, "ciamImportedAt"), reverse=True))


def runs_covering(d, dn):
    """The import runs one of whose scopes holds dn (the entry or one above it), newest export first (equal times by
    DN)."""
    return _newest_first(r for r in children(d, IMPORTS, "ciamImportRun")
                         if any(within(dn, s) for s in values(r, "ciamImportScope")))


def _run_env(r):
    scopes = values(r, "ciamImportScope")
    env = environment_of_scope(scopes[0]) if scopes else None
    return env_label(env) if env else SHARED


def _ordered_runs(d):
    by_set = sorted(children(d, IMPORTS, "ciamImportRun"), key=lambda r: scope_set_key(values(r, "ciamImportScope")))
    newest = sorted(by_set, key=lambda r: one(r, "ciamImportedAt"), reverse=True)
    return sorted(newest, key=lambda r: (one(r, "ciamImporter"), _run_env(r)))


def _changes(r):
    return ", ".join(rdn_of(c) for c in values(r, "ciamChangeRef"))


def import_rows(d, dn=None):
    """One row per import run: importer, the environment it read (or shared), its scope set's key, how many scopes,
    when the export was taken and the change it was applied under; by importer, then environment, then newest export
    first, then set."""
    return [(one(r, "ciamImporter"), _run_env(r), scope_set_key(values(r, "ciamImportScope")),
             len(values(r, "ciamImportScope")), one(r, "ciamImportedAt"), _changes(r)) for r in _ordered_runs(d)]


def import_scope_rows(d, dn=None):
    """One row per scope of each import run (the scope sets behind the imports report, in its order): importer,
    environment (or shared), the set's key, when the export was taken, the scope."""
    return [(one(r, "ciamImporter"), _run_env(r), scope_set_key(values(r, "ciamImportScope")),
             one(r, "ciamImportedAt"), s) for r in _ordered_runs(d) for s in values(r, "ciamImportScope")]


# ------------------------------------------------------------------ runs named before scope sets
def _named(r):
    return run_dn(one(r, "ciamImporter"), values(r, "ciamImportScope"))


def misnamed_runs(d):
    """The import runs not named by their scope set (recorded before runs were: by importer and environment only),
    in DN order."""
    return tuple(r for r in children(d, IMPORTS, "ciamImportRun") if r.norm != norm_dn(_named(r)))


def _renamed(d, r):
    dn = _named(r)
    held = get(d, dn)
    if held is None:
        return new_entry(dn, r.classes, {**r.attrs, "cn": (rdn_of(dn),)}), delete_entry(r)
    if one(held, "ciamImportedAt") >= one(r, "ciamImportedAt"):
        return (delete_entry(r),)
    return (_replaced(held, values(r, "ciamImportScope"), one(r, "ciamImportedAt"), values(r, "ciamChangeRef"),
                      {a: values(r, a) for a in RUN_EVIDENCE}), delete_entry(r))


def renamed_run_records(d):
    """The change records giving each misnamed run its scope-set name: the run at its new DN with its scopes, export
    time, change and evidence as they were, and the old entry deleted. Where a run already holds the set under its new
    name, the newer export is kept: the old entry's values replace it only when the old entry's export is newer."""
    return tuple(x for r in misnamed_runs(d) for x in _renamed(d, r))


def _misnamed_text(r):
    scopes = values(r, "ciamImportScope")
    return (f"Import run `{rdn_value(r)}` ({one(r, 'ciamImporter')}, {len(scopes)} scope(s) of {_run_env(r)}, an "
            f"export of {one(r, 'ciamImportedAt')} applied under {_changes(r)}) is still named by importer and "
            f"environment only, as before runs were named by the scope set they read: rename it to "
            f"`{rdn_of(_named(r))}` with fix `{RENAME_FIX}` under an approved change (its scopes, export time, change "
            f"and evidence stay as they are).")


def check_import_runs(ctx):
    """An action per import run still named by importer and environment only, for the party operating the platform,
    with one fix (RENAME_FIX) renaming them all; nothing when every run is named by its scope set."""
    runs = misnamed_runs(ctx.d)
    if not runs:
        return findings()
    owner = operator_label(ctx.d)
    fix = Fix(RENAME_FIX, AREA, f"Name {len(runs)} import run(s) by the scope set each read",
              renamed_run_records(ctx.d), (),
              ("Where a run already holds the same scope set under its new name, only the run of the newer export "
               "stays; history keeps the other.",))
    return findings(actions=[(AREA, _misnamed_text(r), owner, None) for r in runs], fixes=(fix,))
