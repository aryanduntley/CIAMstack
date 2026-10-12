# opsdir-format-terraform

Terraform HCL formatting for opsdir adapters: names, expressions and blocks laid out like `terraform fmt`.

A format library shared by adapters that render Terraform. It knows HCL, not any cloud provider or product. It registers the `hcl` format with opsdir (entry point `opsdir.formats`), so adapters declare their `.tf` files as `hcl` and the MANIFEST records it.

It also reads Terraform state (format version 4) for the cloud adapters' importers: `state.read_state(text)` gives every resource instance (mode, type, name, attributes) with what the state marks sensitive dropped before anything reads it.

It reads back what it writes: `hcl_reader.read_hcl(text)` gives a file's top-level blocks as `TfBlock(kind, labels, body)`, the data `block()` writes them from (a body's values as `hcl()` takes them: nested `Block`s, `("#", comment)`, literals, lists, objects, and any other expression as its raw `'${...}'` text, a quoted `${}` template included), with the comments between them. `block(*b)` writes a block read back byte for byte; the showcase checks that over every cloud render (`examples/showcase/tests/unit/test_terraform_reader.py`). It reads only what `block()`/`hcl()` write; anything else is a `ValueError` naming the line. The cloud round trip (milestone 5.5c) builds its state from these blocks.

Renderers build Terraform as data and write text only at the edge (milestone 5.5d): `tf_block(kind, labels, body)` gives a `TfBlock`, `comment(text)` a top-level `# text` line (`("#", text)`, as `read_hcl` gives it back), `tf_import(address, id)` an import block, and `TfFile(head, items)` a whole file (head: the generated-file header and the comment lines under it; items: the blocks and comments in order). `hcl_file(f)` is the one writer of a `.tf` file (head, a blank line, the items one blank line apart, a final newline) and `written(files)` writes an adapter's `{path: TfFile | text}`; `read_hcl(hcl_file(f))` gives the items back. `hcl_item` refuses anything that isn't an item (a `TypeError`: text never passes as one). What a renderer asks of items is asked of the data, never of text: `blocks_of(items, kind, type)` the blocks of a kind and type, `mentions(items, text)` whether any value mentions a reference, `distinct(items)` each item once by equality (a block holding a dict or list isn't hashable). `as_text(v)` writes the Terraform data inside any result (tuples, dicts, NamedTuples) for a caller that reads a helper's output as text, such as a test.

`state_builder.tf_state(blocks, assigned, variables)` turns one root's blocks (all its files) into the version 4 state `terraform apply` would record, so a state importer can read a render back without applying it. Each resource and data block is one instance (one per index of a literal `count`), its attributes what it configures, evaluated: literals, lists, objects, nested blocks as lists of objects; references, `data.*`, `var.*`, `count.index`, `[N]`, quoted `${}` templates, `jsonencode` of a JSON document (compact, keys sorted, as Terraform writes it), `tolist`/`tostring`. Meta-arguments (`count`, `depends_on`, `lifecycle`, `provider`) aren't attributes. What the configuration doesn't say comes from the caller: `assigned(mode, type, name, index, configured)` gives what the provider assigns (ids, ARNs, addresses) or a data source returns, which is provider knowledge, so each cloud adapter supplies its own (default `synthetic`: an id naming the instance). An expression it can't evaluate leaves its attribute out and is named in the notices, never guessed. `root_states(files, environment, assigned_for)` (a file given as its text or as the `TfFile` it is written from; both give the same state) builds one state per rendered root (each folder's `.tf` files) of an environment, named after the folder (`terraform.tfstate`, `landing-zone.tfstate`): what a cloud adapter's read-back `prepare` returns.

Other IaC languages are translated from these blocks (milestone 5.6), so a cloud's CloudFormation or Bicep is the same render as its Terraform. `translate` finds the roots among rendered files, parses the references in expressions and string templates (`TfRef`), and splits a root into what the other language writes and a small Terraform root for the rest, with its output variables and a NOTE naming each resource it keeps and why. `native` is the target-neutral engine both cloud targets run on; it knows Terraform only:

- a table of `Native` rows per Terraform type: the native type, an attribute spec (`obj` with `Nest` / `Custom` entries, which refuses an attribute it doesn't name), what a reference to it reads (`refs`), `Merge` for a type that is part of another resource, expansions, `keep` (why a block stays Terraform) and `waits` (what it waits for beside `depends_on`);
- `read_root`, which places each resource by the target's `Layout` (its deployment unit) or keeps it in Terraform with a reason: no native type (in the region), adopted and not importable, part of or waiting on or reading a kept resource, a merged part that would be a cycle, a group the target can't name (`Layout.unplaced`);
- `resolver` and `translate`, which write references through the target's `Forms` and values through its `Target` (concatenation, `join`, `trimprefix`, `jsonencode` documents, indexed lookups), with data sources answered by the target's data table (`Derived`, `Computed`, or the target's own forms);
- `placements`: where every resource went (a template resource, part of one, or the Terraform root, saying why), which the targets' tests check covers each resource exactly once. `placements_document` writes them as the `placements.json` a native render keeps beside each root's templates, and `placements_of` reads that back: the cloud adapters' read-back of a native render (milestone 5.6c) gives each template resource what the Terraform read-back assigns its address.

The AWS adapter's CloudFormation and the Azure adapter's Bicep/ARM are targets of it; neither names the other.

```python
from opsdir_format_terraform.hcl import block, hcl, ref, tf_name, Block, TfBlock
from opsdir_format_terraform.hcl import TfFile, comment, hcl_file, tf_block, tf_import, written
from opsdir_format_terraform.hcl import as_text, blocks_of, distinct, mentions
from opsdir_format_terraform.hcl_reader import read_hcl, value_of
from opsdir_format_terraform.state import read_state
from opsdir_format_terraform.state_builder import tf_state
```

In this repository: `opsdir/scripts/dev-install.sh`.
