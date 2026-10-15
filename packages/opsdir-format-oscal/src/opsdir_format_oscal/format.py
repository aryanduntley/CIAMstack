"""OSCAL as opsdir knows it, registered under the entry point group opsdir.formats: NIST's Open Security Controls
Assessment Language documents (POA&M, SSP, assessment results, catalogs) in their JSON form, written against
OSCAL_VERSION."""
import json

from opsdir.core.contract import Format
from opsdir.core.jsondata import indented

FORMAT = Format(name="oscal-json", title="OSCAL (JSON)", media_type="application/json", extensions=(".json",),
                comment=(), read=json.loads, write=indented, codec=None)
