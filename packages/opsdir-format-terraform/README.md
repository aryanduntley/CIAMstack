# opsdir-format-terraform

Terraform HCL formatting for opsdir adapters: names, expressions and blocks laid out like `terraform fmt`.

A format library shared by adapters that render Terraform. It knows HCL, not any cloud provider or product. It registers the `hcl` format with opsdir (entry point `opsdir.formats`), so adapters declare their `.tf` files as `hcl` and the MANIFEST records it.

It also reads Terraform state (format version 4) for the cloud adapters' importers: `state.read_state(text)` gives every resource instance (mode, type, name, attributes) with what the state marks sensitive dropped before anything reads it.

```python
from opsdir_format_terraform.hcl import block, hcl, ref, tf_name, Block
from opsdir_format_terraform.state import read_state
```

In this repository: `opsdir/scripts/dev-install.sh`.
