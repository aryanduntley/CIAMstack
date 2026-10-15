# opsdir-format-terraform

Terraform for opsdir adapters: HCL written as data and laid out like `terraform fmt`, read back, Terraform state read and built, a root split among the roots its keepers own, and the target-neutral engine that translates a root into another infrastructure-as-code language. A format library: it knows HCL and Terraform, not any cloud provider or product.

**Applies to** no environment by itself: it is not an adapter. It registers the `hcl` format with opsdir (entry point `opsdir.formats`: `hcl`, "HashiCorp Configuration Language (Terraform)", media type `text/x-hcl`, extensions `.tf` and `.hcl`, comments `#`), so adapters declare their `.tf` files as `hcl` and the MANIFEST records it. Used by opsdir-adapter-aws, -azure and -gcp (cloud Terraform, its read-back and placement; the AWS CloudFormation and Azure Bicep/ARM translations) and opsdir-adapter-pingfederate (its Terraform target).

**Depends on** `opsdir` only (the core's `Format` and `Command` contract, directory helpers; for the keepers' roots the governance domain's `keepers` and the network domain's plumbing names, for the state collection steps the governance domain's collection sources). No Terraform binary: what it writes is checked with Terraform by the adapters' `terraform` tests.

## What it writes (`hcl.py`)

Renderers build Terraform as data and write text only at the edge (milestone 5.5d):

| Data | Written as |
|---|---|
| `tf_name(s)` | a Terraform name: lowercase, other characters `_`, `r_` before a leading non-letter |
| `TfBlock(kind, labels, body, origin)`, made with `tf_block(kind, labels, body)` | a top-level block by `block()`: its body `(key, value)` pairs, a value a nested `Block`, `("#", comment)`, a string (a `'${...}'` string is a raw expression), int, float, bool, a list or an object; `=` aligned within each run of single-line values, as `terraform fmt` aligns them; `hcl(v)` writes one value |
| `ref(expr)`, `jsonencoded(v)` | a raw expression; a JSON document as `jsonencode(...)`, spaced as `terraform fmt` writes it |
| `comment(text)` | a top-level `# text` line (`("#", text)`, as `read_hcl` gives it back) |
| `tf_import(address, id)` | an `import` block |
| `TfFile(head, items)` | a whole file by `hcl_file(f)`, the one writer of a rendered `.tf` file: the head (the generated-file header and the comment lines under it), a blank line, the items one blank line apart, a final newline. `hcl_item` refuses anything that isn't an item (`TypeError`: text never passes as one) |
| `{path: TfFile \| text}` | `written(files)`: an adapter's render as text |
| `data_value(v)`, `data_block(kind, labels, pairs, comments)`, `Expr`, `NestedBlock`, `literal(s)` | JSON-like data (dicts, lists, `Expr` raw expressions, `NestedBlock`s such as `required_providers`) laid out like `terraform fmt`, literal strings escaped with template sequences (`${`, `%{`) doubled |
| `unbound_comments(roles)` | `# UNBOUND: required role '<role>' has no binding in this environment` lines |

What a renderer asks of items is asked of the data, never of text: `blocks_of(items, kind, type)` the blocks of a kind and type, `mentions(items, text)` whether any value mentions a reference, `distinct(items)` each item once by equality (a block holding a dict or list isn't hashable). `as_text(v)` writes the Terraform data inside any result (tuples, lists, dicts, NamedTuples; anchors left out) for a caller that reads a helper's output as text, such as a test.

## What it reads back

### HCL (`hcl_reader.py`)

`read_hcl(text)` gives a file's top-level items in order: `TfBlock`s (with no origin) and `("#", comment)` lines, blank lines dropped. It reads only what `block()`/`hcl()` write: quoted labels; `key = value`, nested blocks without labels and comments in a body; quoted strings, numbers, `true`/`false`, lists on one line, objects one `key = value` per line; any other expression (a reference, a function call, a conditional, a quoted `${}` template, a `jsonencode(...)` over several lines, a `for` expression: `[for ...]`, or `{for ...}` on one line) kept as its raw `'${...}'` text. `block(*b)` writes a block read back byte for byte, and `read_hcl(hcl_file(f))` gives `f`'s items back; the showcase checks that over every cloud render (`examples/showcase/tests/unit/test_terraform_reader.py`). Anything else is a `ValueError` naming the line, never a guess: inside an object or a nested block too, and for unbalanced brackets the bracket to blame (one that closes nothing, else the one a wrong kind of closing bracket meets, else the innermost left open). `value_of(text, line=1)` reads one value (`line`: the line `text` starts on, for its errors).

### Terraform state (`state.py`)

`read_state(text)` gives `(state resources, problem)`: every resource instance of a format version 4 state (`terraform state pull`, a backend's file) as `StateResource(mode, type, name, attributes)`, with what the state marks sensitive (`sensitive_attributes`) dropped before anything reads it; no resources and a problem (`not JSON`, `not a Terraform state (format version 4)`) otherwise. `blocks(v)` and `first_block(v)` read a nested block as the state writes it (a list of objects). The cloud adapters' state importers read through it, and share:

- `state_pairs(text, skipped, names)`: `((type, attributes) pairs, notices)` of a state, the attributes under the names the cloud's readers take (`names(type, attributes)`, Azure's `reader_names`), each type in `skipped` (secret-bearing or unmodeled) named with its count: `<type> (<n>): not read (holds secret values, or isn't modeled yet)`.
- `state_resources(text, skipped, read_pairs, names, skipped_first)`: `(resources, notices)`, the pairs read by the cloud's `read_pairs` (its `pairs_resources`), the skipped types' notices after the reader's (before them with `skipped_first`, as Azure writes them).
- `state_steps(m, importer, scheme, fetch, options)`: an environment's terraform-state collection steps, `terraform state pull` in the `terraform_dir` option when given, else for each location of the importer's collection sources starting with `scheme`, `fetch(location)` (a `Command`, or `None` for one it can't read), saved as `<cloud>/<env>/<the location's last segment, else terraform.tfstate>`. Each cloud's collector binds its importer, scheme and fetch command (`s3://`, `azblob://`, `gs://`).

### Which binding a block realizes (`realized.py`)

`realized(m, classes, type, name)`: the binding of environment `m` a resource block renders, by the cloud adapter's table of resource types to object classes and the block's name (`tf_name` of the binding's name, a binding rendered as several blocks numbered `_0`, `_1`, ...); none when the type isn't in the table or the name matches no binding or several.

## Terraform state from a render (`state_builder.py`)

`tf_state(blocks, assigned, variables)` gives `(state text, notices)`: one root's blocks (all its files) as the version 4 state `terraform apply` would record, so a state importer can read a render back without applying it (the round trip, milestone 5.5c). Each resource and data block is one instance (one per index of a literal `count`), its attributes what it configures, evaluated: literals, lists, objects, nested blocks as lists of objects; references (`type.name.attr`, `data.*`, `[N]` indexes), `var.*` (the caller's values, else the variable's default), `count.index`, quoted `${}` templates, `jsonencode` of a JSON document (compact, keys sorted, as Terraform writes it), `tolist`/`toset`/`tostring`/`tonumber`. Meta-arguments (`count`, `for_each`, `depends_on`, `lifecycle`, `provider`, `provisioner`, `connection`) aren't attributes; a nested block named like one is. What the configuration doesn't say comes from the caller: `assigned(mode, type, name, index, configured)` gives what the provider assigns (ids, ARNs, addresses) or a data source returns, merged under what is configured; that is provider knowledge, so each cloud adapter supplies its own (default `synthetic`: an `id` naming the instance). An expression it can't evaluate leaves its attribute out and is named in the notices, never guessed.

`root_states(files, environment, assigned_for, variables)` (a file given as its text or as the `TfFile` it is written from; both give the same state) builds one state per rendered root (each folder's `.tf` files) of an environment, named after the folder below the environment's (`terraform.tfstate`, `landing-zone.tfstate`); an input one root reads from another's output takes that output's value, as applying them in order would. That is what a cloud adapter's read-back `prepare` returns.

## Placing a render in its keepers' roots (`hcl.from_entry`, `translate.partition`, `placing.py`)

A render is placed in several roots by who keeps what it renders (milestone 5.7; the core's `governance.keepers` decides, this package places):

- **Origins.** A `TfBlock` may carry the record entry it renders (`origin`, a DN). `from_entry(dn, items)` stamps a renderer's items for one entry: each resource and import block not stamped already. Items that end in comments get a closing `ANCHOR` block of that origin, which is never written, so the comments travel with the entry. Writing and reading HCL ignore origins.
- **Partition.** `translate.partition(items, place, default, sensitive, label)` splits one root N ways by `place(block)` (a `Partition`: roots, inputs, outputs, apply order). Imports follow their targets, provider and terraform blocks go to every root, and data, ephemeral, variable and module blocks go to every root that reads them (unread ones to the default root). A reference to a resource another root writes becomes an input variable of the reading root and an output of the writing one, sensitive on both when `sensitive` says so, with `label` worded in the input's description. A `depends_on` across roots is dropped and the roots come back in apply order. Refused (`ValueError`): roots that read each other (naming both), one resource address placed in two roots (a renderer wrote it twice), an input named like a variable the root already has. With everything in the default root, the items come back unchanged; a root left with only providers is left out.
- **Placing.** `placing.place_roots(parts, place, default, named, adjust, sensitive, label)` places an environment's Terraform render: its parts `(file name, items)` merged (blocks shared between files written once), partitioned by origin, and each root regrouped into the files its blocks came from (a data source beside its first reader, the added inputs and outputs in `providers.tf`). Roots that `named(root)` says are only asked of their keeper are left out, and their resources are listed with their origins. `adjust(root, items)` lets a cloud adapter fix a root's provider configuration, and providers no block uses afterwards are dropped. The result is a `Placed` (files, named, inputs, outputs, order).
- **Carried files.** `placing.carried_files(roots, files, default)` copies the files a root other than the default reads beside it (`${path.module}/<rel>`: a canary's or function's source folder, a workflow's `file()`) from the default root to that root.

- **The keepers' roots.** `place_roots` itself knows no keepers; the `keeper_*` functions compose it with the core's `governance.keepers` for the cloud adapters. `keeper_placed(m, parts, landing_dns, adjust)` places an environment's render by who keeps what (the stack's root `terraform`, `STACK`; each keeper's; a named keeper's left out). `keeper_roots(m, parts, landing_dns, stack_head, cloud, adjust, providers)` gives the roots' files (`{path: TfFile}`): the stack's under `stack_head(file name)`, a slice's and each keeper's under headers naming the cloud and who keeps them (`keeper_head(m, root, name, keeper, cloud)`), each `providers.tf` as the cloud writes it (`providers(placed)(root, items)`: Azure's registrations and subscription input), and in the stack's `main.tf` a comment per entry asked of a keeper instead. Only the roots the render's scope writes.
- **A keeper's network plumbing.** `keeper_rendered(m, keeper, renderers, data)` gathers what a keeper keeps (`network.plumbing.Keeper`) from its bindings, each rendered by the first of `renderers` (`(object class, fn(m, binding, the keeper's DNs) -> Rendered)`) whose class it has: a `Rendered(blocks, variables, shared)`, each binding's blocks stamped with its entry, inputs once, and `data` (the cloud's network data sources) then the shared blocks once.

The AWS, Azure and Google Cloud adapters render through it, so every kind someone else may keep lands in its keeper's root the same way on each cloud.

## Translating a root into another IaC language (`translate.py`, `native.py`)

Other IaC languages are translated from these blocks (milestone 5.6), so a cloud's CloudFormation or Bicep is the same render as its Terraform. `translate` finds the roots among rendered files (`roots`, `root_items`), parses the references in expressions and string templates (`TfRef`, `parse_ref`, `expression_refs`, `template_parts`), and splits a root (`split_root`: a `Split`) into what the other language writes and a small Terraform root for the rest, with its output variables (`output_variable`) and a heading naming each resource it keeps and why (`no_native_note`). `native` is the target-neutral engine both cloud targets run on; it knows Terraform only:

- a table of `Native` rows per Terraform type: the native type, an attribute spec (`obj` with `Nest` / `Custom` entries, which refuses an attribute it doesn't name), what a reference to it reads (`refs`), `Merge` for a type that is part of another resource, expansions, `keep` (why a block stays Terraform) and `waits` (what it waits for beside `depends_on`); a data table (`Derived`, `Computed`, or the target's own forms) and the types with no native form;
- `read_root`, which places each resource by the target's `Layout` (its deployment unit) or keeps it in Terraform with a reason: no native type (in the region), adopted and not importable, part of or waiting on or reading a kept resource, a merged part that would be a cycle, a group the target can't name (`Layout.unplaced`); a type the table neither maps nor lists is refused by name;
- `resolver` and `translate`, which write references through the target's `Forms` and values through its `Target` (concatenation, `join`, `trimprefix`, `jsonencode` documents, indexed lookups), with data sources answered by the data table (`data_answer`); an expression with no native form is refused (`SystemExit`), never dropped or guessed;
- `placements`: where every resource went (a template resource, part of one, or the Terraform root, saying why), which the targets' tests check covers each resource exactly once. `placements_document` writes them as the `placements.json` a native render keeps beside each root's templates, and `placements_of` reads that back: the cloud adapters' read-back of a native render (milestone 5.6c) gives each template resource what the Terraform read-back assigns its address. `side_inputs` gives the inputs a deployer passes the side root from the templates' outputs.

The AWS adapter's CloudFormation and the Azure adapter's Bicep/ARM are targets of it; neither names the other.

```python
from opsdir_format_terraform.hcl import block, hcl, ref, tf_name, Block, TfBlock
from opsdir_format_terraform.hcl import TfFile, comment, hcl_file, tf_block, tf_import, written
from opsdir_format_terraform.hcl import as_text, blocks_of, distinct, mentions
from opsdir_format_terraform.hcl import ANCHOR, from_entry
from opsdir_format_terraform.hcl_reader import read_hcl, value_of
from opsdir_format_terraform.state import read_state, state_pairs, state_resources, state_steps
from opsdir_format_terraform.state_builder import tf_state, root_states
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.translate import partition, split_root
from opsdir_format_terraform.placing import carried_files, place_roots, STACK
from opsdir_format_terraform.placing import keeper_head, keeper_placed, keeper_roots, Rendered, keeper_rendered
```

## References, vocabulary and schema

None: no reference schemes, vocabulary, schema, secret patterns, importers or planner checks. It is a library the adapters call.

## Known limits

- **The HCL it reads is the subset it writes**: hand-written Terraform beyond it (heredocs, nested blocks with labels such as `dynamic "x" { }`) is a `ValueError`. Live Terraform is read from its state, not its configuration.
- **State format version 4 only.** The built state is what the configuration says plus what the caller assigns: it is no substitute for `terraform plan` against real infrastructure (milestone 7.2).
- The state builder evaluates the expressions above and nothing else: other functions and conditionals leave their attributes out (named).
- The translation engine translates only what a target's table maps; everything else stays Terraform beside the templates, with its reason.

## Tests

- `tests/test_hcl.py`: names, expressions, unsupported values refused, `=` aligned like `terraform fmt`, the `hcl` format registered, data values escaped and nested data blocks laid out like `terraform fmt`.
- `tests/test_hcl_reader.py`: what `block` writes reads back as its data and writes again unchanged; a file as its comments and blocks in order; values; a `for` expression (one or two variables, with a condition) as one raw expression, not a list, written back unchanged; brackets in strings and comments; what it can't read is an error, naming the line it is on (in objects, nested blocks and objects within them; the unbalanced bracket's own line); `value_of` counting lines from its own text; a file written from its items reads back as them; text is never an item.
- `tests/test_state.py`: resource instances read without their sensitive attributes; what isn't a version 4 state refused; a state's pairs with the types not read named and the readers' names, its resources with the skipped types' notices after or first; the collection steps pulling, or fetching each source location (one it can't read, or of another scheme, left out).
- `tests/test_keeper_roots.py`: the stack and the landing zone each in their root with their headers and the cloud's `providers.tf`; a keeper's root taking the adjusted providers; a keeper's headers naming the cloud and the keeper; what a keeper keeps gathered from its bindings.
- `tests/test_state_builder.py`: configured attributes as the state keeps them; a nested block named like a meta-argument; counts, templates, variables and providers; what the provider assigns from the caller; what can't be evaluated left out and named; root states taking the operator's inputs and another root's outputs through a chain; a root given as `TfFile`s.
- `tests/test_partition.py`: unstamped items one root unchanged; each resource in its entry's root with its imports, comments, providers and data; cross-root values as inputs and outputs, sensitive on both sides; a providers-only root left out; roots reading each other, one address in two roots and an input named like a variable refused; stamping; anchors; carried files.
- `tests/test_translate.py`: references parsed from expressions, strings and values; addresses; roots in path order; a root written whole, resources with no native form kept in a Terraform root reading the templates' outputs, a native resource reading one that stays unresolved.
- `tests/test_native.py`: values by the target's forms, expressions with no native form refused, a spec naming every attribute, a root's split with each kept resource's reason, the resolver, `depends_on` across a group, unmapped types refused, keep rules and waits, placements as a document read back.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-format-terraform/tests` (no markers; the rendered Terraform is checked with Terraform by the cloud adapters' `-m terraform` tests).

Installing the package registers the `hcl` format with opsdir (entry point `opsdir.formats`: `hcl`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
