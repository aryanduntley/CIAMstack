import pytest

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
