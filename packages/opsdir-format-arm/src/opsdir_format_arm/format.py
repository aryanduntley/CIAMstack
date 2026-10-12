"""The ARM template formats as opsdir knows them, registered under the entry point group opsdir.formats: one
ArmTemplate written as ARM template JSON or as Bicep (with // comments, so a generated-file header)."""
from opsdir.core.contract import Format
from .arm_json import as_arm_json
from .bicep import as_bicep

ARM_FORMAT = Format(name="arm-json", title="Azure Resource Manager template (JSON)", media_type="application/json",
                    extensions=(".json",), comment=(), read=None, write=as_arm_json, codec=None)
BICEP_FORMAT = Format(name="bicep", title="Bicep", media_type="text/plain", extensions=(".bicep",), comment=("//",),
                      read=None, write=as_bicep, codec=None)
