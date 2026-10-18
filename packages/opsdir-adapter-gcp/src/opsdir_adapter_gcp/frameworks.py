"""Google Cloud's compliance frameworks fetched into the framework catalog (core estate: frameworks), for the framework
deployments compliance.py renders.

Fetched (`opsdir import gcp/frameworks --run`, under the operator's own gcloud login) for each organization the
record's Google Cloud environments with posture services belong to (their cloud's ciamOrganizationRef):
`gcloud compliance-manager frameworks list --organization=<o> --location=global --format=json` (the frameworks, built-in
ones included, each at its revision with the cloud controls it holds, at their revisions, and the parameter values it
sets) and `gcloud compliance-manager cloud-controls list` with the same flags (each control's enforcement modes and the
parameters it requires, with their defaults). Each framework is stamped with the neutral framework and baseline ids it
answers (compliance.answers); only the frameworks a posture service names keep their controls. Pure."""
import re
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.sources import json_document
from opsdir.domains.estate.frameworks import (ControlRow, FrameworkRow, framework_import, frameworks_fetched,
                                              wanted_frameworks)
from .account import organization_id
from .compliance import LOCATION, answers, enforcement_modes, short_id
from .inventory import PROVIDER

_ORG = re.compile(r"organizations/([^/]+)/")


def _parameters(detail, spec):
    given = tuple((p["name"], p.get("parameterValue")) for p in detail.get("parameters") or ()
                  if isinstance(p, dict) and p.get("name"))
    named = {n for n, _ in given}
    return (*given, *((p["name"], p.get("defaultValue")) for p in spec.get("parameterSpec") or ()
                      if isinstance(p, dict) and p.get("isRequired") and p.get("name") not in named))


def framework_rows(frameworks, controls):
    """{organization: (FrameworkRow, ...)} of `compliance-manager frameworks list` items, each control's modes and
    required parameters from `cloud-controls list` items (by control id)."""
    specs = {short_id(c["name"]): c for c in controls}
    rows = [(m.group(1), FrameworkRow(
        short_id(f["name"]), f["name"], str(f.get("majorRevisionId") or ""), f.get("displayName"), enforcement_modes(f),
        *answers(short_id(f["name"]), f.get("displayName")),
        tuple(ControlRow(short_id(c["name"]), c["name"], str(c.get("majorRevisionId") or ""),
                         enforcement_modes(spec), _parameters(c, spec))
              for c in f.get("cloudControlDetails") or () if isinstance(c, dict) and c.get("name")
              for spec in (specs.get(short_id(c["name"]), {}),))))
        for f in frameworks for m in (_ORG.match(f["name"]),) if m]
    return {org: tuple(r for o, r in rows if o == org) for org in sorted({o for o, _ in rows})}


def _items(docs, part):
    return [x for doc in docs.values() if doc is not None for x in doc
            if isinstance(x, dict) and f"/{part}/" in (x.get("name") or "")]


def read_frameworks(files, d, patterns, at=None):
    """Imported: the framework catalog of each organization a frameworks list is of, controls described by the
    cloud-controls lists. Refused without a frameworks list."""
    docs = {p: json_document(t, list) for p, t in sorted(files.items())}
    frameworks = _items(docs, "frameworks")
    if not frameworks:
        raise SystemExit("gcp/frameworks: the export has no framework list (add `gcloud compliance-manager frameworks "
                         "list --organization=<o> --location=global --format=json > frameworks/<o>/frameworks.json`); "
                         "nothing imported")
    imported = framework_import(d, PROVIDER, framework_rows(frameworks, _items(docs, "cloudControls")),
                                organization_id)
    return imported._replace(notices=(*imported.notices, *(
        f"{p}: not `gcloud compliance-manager` frameworks or cloud-controls list output; not read"
        for p, doc in docs.items() if not _items({p: doc}, "frameworks") and not _items({p: doc}, "cloudControls"))))


def framework_commands(d):
    """The provider commands fetching the frameworks and cloud controls of each organization whose Google Cloud
    environments' posture services name frameworks or baselines."""
    return tuple((f"frameworks/{org}/{what}.json", ("gcloud", "compliance-manager", what, "list",
                                                   f"--organization={org}", f"--location={LOCATION}",
                                                   "--format=json"))
                 for org in wanted_frameworks(d, PROVIDER, organization_id)
                 for what in ("frameworks", "cloud-controls"))


FRAMEWORKS = Importer("frameworks", "Compliance Manager's frameworks and cloud controls of each organization the "
                                    "record's Google Cloud environments with posture services belong to",
                      read_frameworks, framework_commands, reference=True)
PREREQUISITE = Prerequisite("gcp-frameworks", "Google Cloud's Compliance Manager frameworks for the organizations "
                                              "whose posture services name frameworks, for the framework deployments",
                            FRAMEWORKS.name, partial(frameworks_fetched, provider=PROVIDER,
                                                     organization_of=organization_id))


