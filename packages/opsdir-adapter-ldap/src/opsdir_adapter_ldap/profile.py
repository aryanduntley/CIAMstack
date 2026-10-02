"""Importer ldap/data-profile: the profile files `opsdir data-profile` writes (counts only) -> each environment's data
profile under ou=data-profile, one per environment, replaced by every newer import. Pure.

A file is read again as `read_profile` checks it (masked branches, scheme and attribute names, counts), so a file
edited by hand can't bring a value into the record either. A file for an environment the record doesn't have, and an
older file for an environment a newer one also describes, are named and not imported.
"""
from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, gtime, ou_entry
from opsdir.core.environment import env_dn
from opsdir.domains.directory.naming import DATA_PROFILE
from opsdir.domains.directory.profile import profile_entries, read_profile


def read_profiles(files, d, patterns, at=None):
    """Imported: the data profiles in an export's .json files."""
    read = tuple((path, *read_profile(text)) for path, text in sorted(files.items()) if path.endswith(".json"))
    usable = tuple((path, pf) for path, pf, _ in read if pf is not None and get(d, env_dn(pf.label)) is not None)
    latest = {pf.label: (path, pf) for path, pf in sorted(usable, key=lambda u: u[1].captured)}
    return Imported(
        containers=(ou_entry(DATA_PROFILE),),
        groups=tuple(profile_entries(d, pf.label, pf.profile, pf.captured) for _, pf in latest.values()),
        notices=(*(f"{path}: not a data profile ({why}); not imported" for path, pf, why in read if pf is None),
                 *(f"{path}: environment {pf.label} isn't in the record; not imported" for path, pf, _ in read
                   if pf is not None and get(d, env_dn(pf.label)) is None),
                 *(f"{path}: {pf.label} is also described by {latest[pf.label][0]}, taken later "
                   f"({gtime(latest[pf.label][1].captured)}); not imported"
                   for path, pf in usable if latest[pf.label][0] != path),
                 *(f"{path}: not a profile file (.json); skipped" for path in sorted(files)
                   if not path.endswith(".json")),
                 *(("no profile files (.json, written by `opsdir data-profile`)",) if not read else ())))


DATA_PROFILE_IMPORTER = Importer("data-profile", "data profiles written by `opsdir data-profile` (.json, counts only), "
                                                 "one per environment", read_profiles)
