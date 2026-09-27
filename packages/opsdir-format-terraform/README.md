# opsdir-format-terraform

Terraform HCL formatting for opsdir adapters: names, expressions and blocks laid out like `terraform fmt`.

A format library shared by adapters that render Terraform. It knows HCL, not any cloud provider or product.

```python
from opsdir_format_terraform.hcl import block, hcl, ref, tf_name, Block
```

In this repository: `scripts/dev-install.sh`.
