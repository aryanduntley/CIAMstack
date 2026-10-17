"""PingFederate's configuration as a bulk import document (render target bulk-config, on request): what a Ping server
profile's instance/bulk-config/data.json holds, which the image imports on the administrative console's start (POST
/pf-admin-api/v1/bulk/import, then replicates it to the engines; research note 2815). Pure.

It holds the same requests the admin-api target renders (admin_api.requests: same order, same secret references), each
as a SAVE operation of a resource type: the collection an object is created in (its POST), a settings resource's
path, a key pair's kind for its import (/keyPairs/signing: fileData and password as the import takes them);
consecutive requests of one type are one operation. The trusted CAs' imports (client_certificates) are left out:
their resource type and item form in a bulk document aren't established. metadata.pfVersion is the version the
environment runs, as four numbers (13.1.3 -> 13.1.3.0): a bulk document is version-specific. The bulk importer
(importer.py) reads it back. What the requests' check finds (opsdir_adapter_pingfederate.diagnostics: the spec of
the version, held settings from other versions) is pingfederate/bulk-config-problems.json, outside the folder a
server profile takes whole, so neither Ping's document nor the profile holds anything of opsdir's.
"""
import json
from itertools import groupby

from opsdir.core.environment import UNBOUND
from .admin_api import request_type, requests
from .client_certificates import CA_IMPORT
from .diagnostics import problems
from .versions import pingfederate_version

OUTPUT = "pingfederate/bulk-config/data.json"
PROBLEMS = "pingfederate/bulk-config-problems.json"      # outside bulk-config/: render.PROFILE takes it whole
_IMPORT = "/import"


def bulk_resource(r):
    """The resource type a Request saves in a bulk import: its request_type, a key pair's import its kind."""
    t = request_type({"path": r.path, "createWith": r.create_with})
    return t[:-len(_IMPORT)] if t.startswith("/keyPairs/") and t.endswith(_IMPORT) else t


def pf_version(version):
    """A PingFederate version as a bulk document's metadata names it, four numbers ('PingFederate 13.1.3' or
    '13.1.3' -> 13.1.3.0), or None."""
    parts = version.split()[-1].split(".") if version else []
    return ".".join((parts + ["0"] * 4)[:4]) if parts else None


def bulk_requests(m, services=None):
    """The requests a bulk document holds: environment m's, but the trusted CAs' imports (their form in a bulk
    document isn't established: the admin-api and terraform targets carry them)."""
    return tuple(r for r in requests(m, services) if r.path != CA_IMPORT)


def bulk_document(m, services=None):
    """Environment m's PingFederate configuration as a bulk import document, or None when the record holds none."""
    reqs = bulk_requests(m, services)
    if not reqs:
        return None
    version, _ = pingfederate_version(m)
    return {"metadata": {"pfVersion": pf_version(version) or f"{UNBOUND}pingfederate-version"},
            "operations": [{"operationType": "SAVE", "resourceType": t, "items": [r.body for r in group]}
                           for t, group in groupby(reqs, key=bulk_resource)]}


def bulk_files(m, services=None):
    """{pingfederate/bulk-config/data.json, pingfederate/bulk-config-problems.json: text} (the problems of its
    requests: diagnostics.problems),
    or {} when the record holds nothing for PingFederate."""
    doc = bulk_document(m, services)
    if not doc:
        return {}
    version, spec, found = problems(m, bulk_requests(m, services))
    return {OUTPUT: json.dumps(doc, indent=2) + "\n",
            PROBLEMS: json.dumps({"pingFederate": version, "adminApi": spec, "problems": list(found)}, indent=2) + "\n"}
