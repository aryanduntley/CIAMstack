"""PingFederate's configuration as a bulk import document (render target bulk-config, on request): what a Ping server
profile's instance/bulk-config/data.json holds, which the image imports on the administrative console's start (POST
/pf-admin-api/v1/bulk/import, then replicates it to the engines; research note 2815). Pure.

It holds the same requests the admin-api target renders (admin_api.requests: same order, same secret references), each
as a SAVE operation of a resource type: the collection an object is created in (its POST), a settings resource's
path, a key pair's kind for its import (/keyPairs/signing: fileData and password as the import takes them);
consecutive requests of one type are one operation. metadata.pfVersion is the version the environment runs, as four
numbers (13.1.3 -> 13.1.3.0): a bulk document is version-specific. The bulk importer (importer.py) reads it back.
"""
import json
from itertools import groupby

from opsdir.core.environment import UNBOUND
from .admin_api import request_type, requests
from .versions import pingfederate_version

OUTPUT = "pingfederate/bulk-config/data.json"
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


def bulk_document(m):
    """Environment m's PingFederate configuration as a bulk import document, or None when the record holds none."""
    reqs = requests(m)
    if not reqs:
        return None
    version, _ = pingfederate_version(m)
    return {"metadata": {"pfVersion": pf_version(version) or f"{UNBOUND}pingfederate-version"},
            "operations": [{"operationType": "SAVE", "resourceType": t, "items": [r.body for r in group]}
                           for t, group in groupby(reqs, key=bulk_resource)]}


def bulk_files(m):
    """{pingfederate/bulk-config/data.json: text}, or {} when the record holds nothing for PingFederate."""
    doc = bulk_document(m)
    return {OUTPUT: json.dumps(doc, indent=2) + "\n"} if doc else {}
