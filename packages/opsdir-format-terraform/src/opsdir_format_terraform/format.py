"""The HCL format as opsdir knows it: registered under the entry point group opsdir.formats."""
from opsdir.core.contract import Format
from .hcl import hcl

FORMAT = Format(name="hcl", title="HashiCorp Configuration Language (Terraform)", media_type="text/x-hcl",
                extensions=(".tf", ".hcl"), comment=("#",), read=None, write=hcl)
