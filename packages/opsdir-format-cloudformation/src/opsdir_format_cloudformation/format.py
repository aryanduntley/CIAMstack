"""The CloudFormation template formats as opsdir knows them, registered under the entry point group opsdir.formats:
one Template written as YAML (with # comments, so a generated-file header) or as JSON."""
from opsdir.core.contract import Format
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.jsondata import indented
from .template import template_data


def as_yaml(template):
    """A Template as CloudFormation YAML (long-form intrinsic functions, block style, keys in the template's order)."""
    return dump(template_data(template))


def as_json(template):
    """A Template as CloudFormation JSON (indented by two, newline-terminated)."""
    return indented(template_data(template))


YAML_FORMAT = Format(name="cloudformation-yaml", title="AWS CloudFormation template (YAML)",
                     media_type="application/yaml", extensions=(".yaml", ".yml", ".template"), comment=("#",),
                     read=None, write=as_yaml, codec=None)
JSON_FORMAT = Format(name="cloudformation-json", title="AWS CloudFormation template (JSON)",
                     media_type="application/json", extensions=(".json", ".template"), comment=(), read=None,
                     write=as_json, codec=None)
