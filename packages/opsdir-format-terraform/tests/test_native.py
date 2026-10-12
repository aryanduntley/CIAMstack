"""The target-neutral translation engine (native.py, 5.6 decision 2592) over a toy target: values (references,
interpolations, jsonencode documents, indexed lookups, join / trimprefix), attribute specs, a root read and split with
each kept resource's reason, merges by target type, the resolver's forms (an Attribute, Computed lookups and what they
read), placements; refusals name the target's language."""
import pytest

from opsdir_format_terraform.hcl import Block, TfFile, ref, tf_block, tf_import
from opsdir_format_terraform.native import (Attribute, Computed, Custom, Cx, Forms, Layout, Merge, Native, Nest, Table,
                                            Target, depends, fields, group_refs, obj, placements, read_root, resolver,
                                            translate)
from opsdir_format_terraform.translate import TfRef


def _concat(*values):
    return values[0] if len(values) == 1 else ("cat", *values)


def _trim(v, prefix):
    if not isinstance(v, str):
        raise SystemExit("Toy can't trim a value known only at deploy time")
    return v.removeprefix(prefix)


TOY = Target("Toy", _concat, lambda sep, values: ("join", sep, values), _trim)


def resolve(r):
    return f"<{r.type or r.kind}.{r.name}.{r.attr}>"


@pytest.mark.parametrize("value, expected", [
    ("plain", "plain"),
    (ref("aws_vpc.main.id"), "<aws_vpc.main.id>"),
    ("${var.a}-x", ("cat", "<var.a.>", "-x")),
    (ref('jsonencode({"R" : "${aws_s3_bucket.b.arn}/*", "N" : 1})'), {"R": ("cat", "<aws_s3_bucket.b.arn>", "/*"),
                                                                     "N": 1}),
    (ref("tolist(data.x_y.z.arns)[0]"), "<x_y.z.arns[0]>"),
    (ref('join(":", ["a", trimprefix("https://h", "https://"), var.b])'), ("cat", "a", ":", "h", ":", "<var.b.>")),
    (ref('join(",", var.list)'), ("join", ",", "<var.list.>")),
    ([{"k": "${var.y}"}], [{"k": "<var.y.>"}])])
def test_values_translate_by_the_targets_forms(value, expected):
    assert translate(value, resolve, TOY) == expected


def test_an_expression_with_no_native_form_is_refused_in_the_targets_language():
    with pytest.raises(SystemExit, match="no Toy form for the Terraform expression 'cidrsubnet"):
        translate(ref("cidrsubnet(var.cidr, 8, 1)"), resolve, TOY)


def test_a_spec_names_every_attribute_or_refuses():
    cx = Cx(lambda v: v.upper() if isinstance(v, str) else v, None, None, None, None, None, "x.y", "Toy")
    f = fields(((("name", "a")), ("skip", True), ("rule", Block((("port", 1),))), ("rule", Block((("port", 2),))),
                ("size", 3)))
    spec = {"name": "Name", "skip": None, "rule": Nest("Rules", {"port": "Port"}, True),
            "size": Custom(lambda v, c: {"Size": v * 2})}
    assert obj(f, cx, spec) == {"Name": "A", "Rules": [{"Port": 1}, {"Port": 2}], "Size": 6}
    with pytest.raises(SystemExit, match="x.y: no Toy form for size"):
        obj(f, cx, {k: v for k, v in spec.items() if k != "size"})


LAYOUT = Layout(lambda b: "main", lambda group: "here", lambda type_, name: f"{type_}:{name}")
TYPES = {
    "t_box": Native("Box", {"name": "Name"}, {"id": "Id", "label": Attribute("name")}, "Name"),
    "t_lid": Native(None, merge=Merge("depends_on", lambda props, f, cx: {**props, "Lid": True}, target="t_box")),
    "t_pipe": Native("Pipe", {"src": "Source"}, {}, "Id", adoptable=lambda f: "a pipe can't be imported"),
    "t_nowhere": Native("Nowhere", {}, {})}
DATA = {"t_lookup": lambda f, a: (Computed(lambda f, value: ("built", value(f["from"]))) if a == "arn" else
                                  "fixed" if a == "id" else None)}
TABLE = Table(TYPES, frozenset({"t_legacy"}), DATA, lambda type_, region: type_ == "t_nowhere")
FILES = {"terraform/main.tf": TfFile("", (
    tf_block("data", ["t_lookup", "l"], [("from", ref("var.region"))]),
    tf_block("resource", ["t_box", "a"], [("name", "a")]),
    tf_block("resource", ["t_lid", "a"], [("depends_on", [ref("t_pipe.p"), ref("t_box.a")])]),
    tf_block("resource", ["t_pipe", "p"], [("src", ref("data.t_lookup.l.arn"))]),
    tf_block("resource", ["t_pipe", "q"], [("src", "q-${t_box.a.label}/${data.t_lookup.l.id}")]),
    tf_import("t_pipe.p", "p-1"),
    tf_block("resource", ["t_legacy", "x"], [("src", ref("t_box.a.id"))]),
    tf_block("resource", ["t_nowhere", "n"], [])))}


@pytest.fixture(scope="module")
def root():
    return read_root("terraform", tuple(FILES.items()), TABLE, "Toy", lambda items: LAYOUT)


def test_a_root_splits_with_each_kept_resources_reason(root):
    assert root.reasons == {"t_pipe.p": "adopted (an import block): a pipe can't be imported",
                            "t_legacy.x": "no Toy type", "t_nowhere.n": "no Toy type in here",
                            "t_lid.a": "waits for t_pipe.p (depends_on), which stays Terraform, applied after the "
                                       "template"}
    assert {a: (p.group, p.id, p.target) for a, p in root.placed.items()} == {
        "t_box.a": ("main", "t_box:a", None), "t_pipe.q": ("main", "t_pipe:q", None)}
    assert placements(root, {"main": "out/template"}, "out/terraform/main.tf")["t_legacy.x"].kind == "terraform"


def test_the_resolver_reads_attributes_computed_lookups_and_variables(root):
    forms = Forms(lambda nid, form: f"{nid}#{form}", lambda r: "cross", lambda name: f"param:{name}",
                  lambda r, found: found)
    resolve_here = resolver(root, "main", TABLE, TOY, forms)
    assert resolve_here(TfRef("resource", "t_box", "a", "id")) == "t_box:a#Id"
    assert resolve_here(TfRef("resource", "t_box", "a", "label")) == "a"
    assert resolve_here(TfRef("data", "t_lookup", "l", "arn")) == ("built", "param:region")
    q = root.by_address["t_pipe.q"]
    assert translate(fields(q.body)["src"], resolve_here, TOY) == ("cat", "q-", "a", "/", "fixed")
    reads = group_refs(root, (root.placed["t_pipe.q"],), DATA)
    assert TfRef("var", "", "region", "") not in reads                  # only a Computed answer's body is read
    computed = group_refs(root, (root.placed["t_box.a"],), DATA) + group_refs(root, (root.placed["t_pipe.q"],), DATA)
    assert TfRef("data", "t_lookup", "l", "id") in computed
    with pytest.raises(SystemExit, match="no Toy form for attribute 'size'"):
        resolve_here(TfRef("resource", "t_box", "a", "size"))


def test_depends_on_names_native_ids_of_the_same_group(root):
    assert depends(root, root.placed["t_box.a"], {"t_box:a"}) == ()
    ordered = TfFile("", (tf_block("resource", ["t_box", "a"], [("name", "a")]),
                          tf_block("resource", ["t_box", "b"], [("name", "b"), ("depends_on", [ref("t_box.a")])])))
    small = read_root("terraform", (("terraform/main.tf", ordered),), TABLE, "Toy", lambda items: LAYOUT)
    assert depends(small, small.placed["t_box.b"], {"t_box:a", "t_box:b"}) == ("t_box:a",)


def test_unmapped_types_are_refused_and_readers_of_kept_resources_stay_too():
    with pytest.raises(SystemExit, match="no Toy mapping for t_nosuch"):
        read_root("terraform", (("terraform/main.tf", TfFile("", (tf_block("resource", ["t_nosuch", "x"], []),))),),
                  TABLE, "Toy", lambda items: LAYOUT)
    reads_kept = TfFile("", (tf_block("resource", ["t_legacy", "x"], []),
                             tf_block("resource", ["t_box", "b"], [("name", ref("t_legacy.x.id"))])))
    kept = read_root("terraform", (("terraform/main.tf", reads_kept),), TABLE, "Toy", lambda items: LAYOUT)
    assert kept.reasons["t_box.b"] == "reads t_legacy.x, which stays Terraform" and not kept.placed


def test_a_keep_rule_and_a_merged_part_waiting_on_a_reader_of_its_target_stay_terraform():
    types = {**TYPES,
             "t_guard": Native("Guard", {"name": "Name"}, {"id": "Id"}, "Name",
                               keep=lambda f, block: "no native guard here" if f.get("name") == "kept" else None),
             "t_grant": Native("Grant", {"on": "On"}, {"id": "Id"}, "Name"),
             "t_seal": Native(None, merge=Merge("box", lambda props, f, cx: props))}
    table = Table(types, frozenset(), DATA)
    root = TfFile("", (
        tf_block("resource", ["t_guard", "g"], [("name", "kept")]),
        tf_block("resource", ["t_box", "a"], [("name", "a")]),
        tf_block("resource", ["t_grant", "x"], [("on", ref("t_box.a.id"))]),
        tf_block("resource", ["t_seal", "s"], [("box", ref("t_box.a.id")), ("depends_on", [ref("t_grant.x")])])))
    read = read_root("terraform", (("terraform/main.tf", root),), table, "Toy", lambda items: LAYOUT)
    assert read.reasons == {"t_guard.g": "no native guard here",
                            "t_seal.s": "part of t_box.a natively, but waits for t_grant.x, which reads it: a cycle "
                                        "there, so it stays Terraform, applied after the template"}
