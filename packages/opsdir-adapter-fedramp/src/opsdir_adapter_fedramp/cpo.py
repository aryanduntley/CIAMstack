"""A cloud offering's FedRAMP Certification Package Overview (FRC-CSO-PKG, the JSON schema FedRAMP publishes at
fedramp.gov/schemas) read as the authorization the estate relies on (opsdir.domains.estate.authorizations): its package
id, offering, provider, certification type, deployment model, the services it certifies (certifiedServices: the
services inside its boundary) and when the overview was last updated. The schema states no level: one a provider adds
(securityCategorization, as AWS's do: "High (FedRAMP Certification Level Class D)") is read, else the operator records
it. `opsdir import fedramp/cpo FILE ...` with the overviews saved from the providers (AWS publishes its offerings'
on its FedRAMP page); the import's --at is when they were taken. Pure."""
from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import gtime, gtime_of_iso
from opsdir.core.sources import json_document
from opsdir.domains.estate.authorizations import CpoRow, authorization_import

# the level a provider's securityCategorization states, by its first word
LEVELS = {"low": "fedramp-low", "moderate": "fedramp-moderate", "high": "fedramp-high"}


def _level(props):
    words = str(props.get("securityCategorization") or "").split()
    return LEVELS.get(words[0].lower()) if words else None


def cpo_row(doc):
    """The CpoRow of a package overview document, or None when it isn't one."""
    ident, props = doc.get("serviceIdentification"), doc.get("serviceProperties") or {}
    if not isinstance(ident, dict) or not ident.get("fedRampPackageId"):
        return None
    services = tuple(dict.fromkeys(s["serviceName"] for s in doc.get("certifiedServices") or ()
                                   if isinstance(s, dict) and s.get("serviceName")))
    return CpoRow(ident["fedRampPackageId"], ident.get("serviceName"), ident.get("providerName"),
                  ident.get("certificationType"), props.get("deploymentModel"), _level(props), services,
                  gtime_of_iso((doc.get("cpoMetadata") or {}).get("lastUpdated")))


def read_cpo(files, d, patterns, at=None):
    """Imported: each package overview as its authorization (other files named, not read)."""
    rows = {p: cpo_row(doc) for p, t in sorted(files.items()) for doc in (json_document(t, dict),) if doc is not None}
    retrieved = gtime(at) if hasattr(at, "strftime") else at      # the import's --at: a datetime, or the record's text
    parts = [authorization_import(d, row, retrieved=retrieved) for row in rows.values() if row is not None]
    skipped = [p for p in sorted(files) if rows.get(p) is None]
    if not parts:
        raise SystemExit("fedramp/cpo: no FedRAMP Certification Package Overview (FRC-CSO-PKG) JSON among the files; "
                         "nothing imported")
    return Imported(containers=parts[0].containers, groups=tuple(g for part in parts for g in part.groups),
                    notices=(*(n for part in parts for n in part.notices),
                             *(f"{p}: not a FedRAMP Certification Package Overview; not read" for p in skipped)))


CPO = Importer("cpo", "A cloud offering's FedRAMP Certification Package Overview (FRC-CSO-PKG JSON), as the "
                      "authorization it grants and the services inside its boundary", read_cpo)
