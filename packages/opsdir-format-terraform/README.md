# opsdir-format-terraform

Terraform HCL formatting for opsdir adapters: names, expressions and blocks laid out like `terraform fmt`.

A format library shared by adapters that render Terraform. It knows HCL, not any cloud provider or product. It registers the `hcl` format with opsdir (entry point `opsdir.formats`), so adapters declare their `.tf` files as `hcl` and the MANIFEST records it.

It also reads Terraform state (format version 4) for the cloud adapters' importers: `state.read_state(text)` gives every resource instance (mode, type, name, attributes) with what the state marks sensitive dropped before anything reads it.

It reads back what it writes: `hcl_reader.read_hcl(text)` gives a file's top-level blocks as `TfBlock(kind, labels, body)`, the data `block()` writes them from (a body's values as `hcl()` takes them: nested `Block`s, `("#", comment)`, literals, lists, objects, and any other expression as its raw `'${...}'` text, a quoted `${}` template included), with the comments between them. `block(*b)` writes a block read back byte for byte; the showcase checks that over every cloud render (`examples/showcase/tests/unit/test_terraform_reader.py`). It reads only what `block()`/`hcl()` write; anything else is a `ValueError` naming the line. The cloud round trip (milestone 5.5c) builds its state from these blocks.

`state_builder.tf_state(blocks, assigned, variables)` turns one root's blocks (all its files) into the version 4 state `terraform apply` would record, so a state importer can read a render back without applying it. Each resource and data block is one instance (one per index of a literal `count`), its attributes what it configures, evaluated: literals, lists, objects, nested blocks as lists of objects; references, `data.*`, `var.*`, `count.index`, `[N]`, quoted `${}` templates, `jsonencode` of a JSON document (compact, keys sorted, as Terraform writes it), `tolist`/`tostring`. Meta-arguments (`count`, `depends_on`, `lifecycle`, `provider`) aren't attributes. What the configuration doesn't say comes from the caller: `assigned(mode, type, name, index, configured)` gives what the provider assigns (ids, ARNs, addresses) or a data source returns, which is provider knowledge, so each cloud adapter supplies its own (default `synthetic`: an id naming the instance). An expression it can't evaluate leaves its attribute out and is named in the notices, never guessed. `root_states(files, environment, assigned_for)` builds one state per rendered root (each folder's `.tf` files) of an environment, named after the folder (`terraform.tfstate`, `landing-zone.tfstate`): what a cloud adapter's read-back `prepare` returns.

```python
from opsdir_format_terraform.hcl import block, hcl, ref, tf_name, Block, TfBlock
from opsdir_format_terraform.hcl_reader import read_hcl, value_of
from opsdir_format_terraform.state import read_state
from opsdir_format_terraform.state_builder import tf_state
```

In this repository: `opsdir/scripts/dev-install.sh`.
