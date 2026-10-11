import pytest

from opsdir.connectors.registry import format_named
from opsdir_format_terraform.format import FORMAT
from opsdir_format_terraform.hcl import Block, block, hcl, ref, tf_name


@pytest.mark.parametrize("name, expected", [("ds-1", "ds_1"), ("Svc.LDAPS", "svc_ldaps"), ("1st", "r_1st")])
def test_tf_name(name, expected):
    assert tf_name(name) == expected


@pytest.mark.parametrize("value, expected", [
    (True, "true"), (False, "false"), (3, "3"), ("a\"b\\c", '"a\\"b\\\\c"'), (ref("var.region"), "var.region"),
    (["a", 1], '["a", 1]'), ({"k": "v", "long_key": 2}, '{\n  k        = "v"\n  long_key = 2\n}')])
def test_hcl_expressions(value, expected):
    assert hcl(value) == expected


def test_hcl_rejects_unsupported_values():
    with pytest.raises(TypeError):
        hcl(object())


def test_block_aligns_equals_within_runs_like_terraform_fmt():
    text = block("resource", ("aws_instance", "ds_1"), (
        ("ami", "ami-1"), ("instance_type", "m5.large"),
        ("#", "disks"),
        ("root_block_device", Block((("encrypted", True), ("volume_size", 100)))),
        ("tags", {"Name": "ds-1"}),
        ("count", 1)))
    assert text == "\n".join((
        'resource "aws_instance" "ds_1" {',
        '  ami           = "ami-1"',
        '  instance_type = "m5.large"',
        '  # disks',
        '  root_block_device {',
        '    encrypted   = true',
        '    volume_size = 100',
        '  }',
        '  tags = {',
        '    Name = "ds-1"',
        '  }',
        '  count = 1',
        '}'))


def test_registered_as_the_hcl_format():
    assert format_named("hcl") == FORMAT and FORMAT.comment == ("#",) and ".tf" in FORMAT.extensions


def test_data_values_escape_literal_text_and_keep_expressions():
    from opsdir_format_terraform.hcl import Expr, data_value, literal
    assert literal('(mail=${mail}) %{if} "q" \\ x\n') == '"(mail=$${mail}) %%{if} \\"q\\" \\\\ x\\n"'
    assert [data_value(v) for v in (None, True, 5, 1.5, "a", Expr("var.x"), [], {}, ["a", Expr("var.b")])] == \
        ["null", "true", "5", "1.5", '"a"', "var.x", "[]", "{}", '["a", var.b]']


def test_data_block_lays_out_nested_objects_like_terraform_fmt():
    from opsdir_format_terraform.hcl import Expr, data_block
    text = data_block("resource", ["kind", "name"], [
        ("id", "a"), ("long_name", "b"),
        ("config", {"fields": [{"name": "Lifetime", "value": "120"}], "urn:key": {}, "tables": []}),
        ("after", True), ("depends_on", [Expr("kind.other")])], comments=("note",))
    assert text == '''resource "kind" "name" {
  # note
  id        = "a"
  long_name = "b"
  config = {
    fields = [
      {
        name  = "Lifetime"
        value = "120"
      },
    ]
    "urn:key" = {}
    tables    = []
  }
  after      = true
  depends_on = [kind.other]
}'''


def test_objects_align_within_single_line_runs_and_lists_of_objects_go_one_per_line():
    out = hcl({"kind": "Custom", "properties": {"name": "x", "patterns": [{"kind": "Regex", "pattern": "a"}],
                                                "minimum": 60, "status": "on"}})
    assert out == ('{\n  kind = "Custom"\n  properties = {\n    name = "x"\n    patterns = [\n      {\n'
                   '        kind    = "Regex"\n        pattern = "a"\n      },\n    ]\n    minimum = 60\n'
                   '    status  = "on"\n  }\n}')                                # as terraform fmt lays it out
    assert hcl([1, 2]) == "[1, 2]" and hcl({"a": 1, "bb": 2}) == "{\n  a  = 1\n  bb = 2\n}"
