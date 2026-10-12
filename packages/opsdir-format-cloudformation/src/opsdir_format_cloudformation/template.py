"""CloudFormation templates as data: what a renderer builds, and the template document both writers take. A format
library: it knows CloudFormation's template anatomy and intrinsic functions, not any AWS service. Pure.

A Template holds its parameters, conditions, resources and outputs in the order a renderer gives them (the order a
person reads them; CloudFormation doesn't care). Values are JSON-shaped (dict, list or tuple, str, int, float, bool,
None). An intrinsic function is a one-key dict in CloudFormation's long form ({"Ref": ...}, {"Fn::GetAtt": [...]}),
which YAML and JSON write alike, so one template gives both files, and a reader of either gets the same data back.
"""
import re
from collections import namedtuple

FORMAT_VERSION = "2010-09-09"

# Pseudo parameters (Ref them): the deploying account, partition (aws, aws-us-gov), region, stack, the partition's
# domain suffix, and the value that removes a property (with Fn::If).
ACCOUNT_ID, PARTITION, REGION = "AWS::AccountId", "AWS::Partition", "AWS::Region"
STACK_NAME, URL_SUFFIX, NO_VALUE = "AWS::StackName", "AWS::URLSuffix", "AWS::NoValue"

# A template parameter: its CloudFormation type (String, Number, CommaDelimitedList, an AWS-specific type such as
# AWS::EC2::Subnet::Id, or an SSM parameter type), the default (None: the deployer must give one), what it is, the
# values allowed (() for any) and whether CloudFormation masks it (no_echo).
Parameter = namedtuple("Parameter", ("logical_id", "type", "default", "description", "allowed", "no_echo"),
                       defaults=(None, None, (), False))
# A resource: its logical id, type (AWS::Service::Resource), properties (a dict), the logical ids it must follow
# (depends_on), the condition it is created under, its deletion and update-replace policies (Retain, Snapshot, Delete,
# RetainExceptOnCreate) and metadata (a dict), each None when not set.
Resource = namedtuple("Resource", ("logical_id", "type", "properties", "depends_on", "condition", "deletion_policy",
                                   "update_replace_policy", "metadata"), defaults=((), None, None, None, None))
# A stack output: its value, what it is, and the name it is exported under for Fn::ImportValue (None: not exported).
Output = namedtuple("Output", ("logical_id", "value", "description", "export"), defaults=(None, None))
# A whole template: description, resources, parameters, conditions ((name, condition), ...), outputs, template
# metadata (a dict) and transform (a macro name, or None).
Template = namedtuple("Template", ("description", "resources", "parameters", "conditions", "outputs", "metadata",
                                   "transform"), defaults=((), (), (), None, None))


def logical_id(*parts):
    """A logical id from name parts ('identity_pf' -> 'IdentityPf'): CloudFormation allows letters and digits only.
    The words of each part are capitalized and joined; one starting with a digit gets an R in front."""
    words = [w for p in parts for w in re.split(r"[^A-Za-z0-9]+", str(p)) if w]
    found = "".join(w[:1].upper() + w[1:] for w in words)
    if not found:
        raise ValueError(f"no letters or digits for a logical id in {parts!r}")
    return ("R" + found if found[0].isdigit() else found)[:255]


def ref(name):
    """Ref: a parameter's value, a resource's default return value (usually its id), or a pseudo parameter."""
    return {"Ref": name}


def get_att(name, attribute):
    """Fn::GetAtt: an attribute (Arn, DNSName, ...) of a resource in the template."""
    return {"Fn::GetAtt": [name, attribute]}


def sub(text, variables=None):
    """Fn::Sub: text with ${Name} (a parameter, resource or pseudo parameter) and ${Name.Attribute} filled in; with
    variables ({name: value}), those names too."""
    return {"Fn::Sub": [text, dict(variables)] if variables else text}


def join(separator, values):
    """Fn::Join: the values joined by separator."""
    return {"Fn::Join": [separator, list(values)]}


def select(index, values):
    """Fn::Select: the index-th of a list (a literal list or a function giving one)."""
    return {"Fn::Select": [index, values if isinstance(values, dict) else list(values)]}


def split(separator, text):
    """Fn::Split: a string split at separator, as a list."""
    return {"Fn::Split": [separator, text]}


def import_value(export):
    """Fn::ImportValue: another stack's exported output (same account and region)."""
    return {"Fn::ImportValue": export}


def if_(condition, yes, no):
    """Fn::If: yes where the named condition holds, else no (ref(NO_VALUE) leaves a property out)."""
    return {"Fn::If": [condition, yes, no]}


def equals(a, b):
    """Fn::Equals, for a template condition."""
    return {"Fn::Equals": [a, b]}


def resolve(service, reference):
    """A dynamic reference CloudFormation resolves at deploy time, never stored in the template: service
    secretsmanager (reference '<secret id or ARN>:SecretString:<key>::'), ssm or ssm-secure ('<name>:<version>')."""
    return f"{{{{resolve:{service}:{reference}}}}}"


def lint_metadata(regions):
    """Template metadata naming the regions cfn-lint checks the template for (its in-template configuration): the
    environment's region, so a GovCloud template is checked against GovCloud's resource specification."""
    return {"cfn-lint": {"config": {"regions": list(regions)}}}


def _unique(kind, ids):
    seen = [i for n, i in enumerate(ids) if i in ids[:n]]
    if seen:
        raise ValueError(f"{kind} logical ids used more than once: {', '.join(dict.fromkeys(seen))}")


def _parameter(p):
    return {"Type": p.type, **({"Default": p.default} if p.default is not None else {}),
            **({"Description": p.description} if p.description else {}),
            **({"AllowedValues": list(p.allowed)} if p.allowed else {}), **({"NoEcho": True} if p.no_echo else {})}


def _resource(r):
    return {"Type": r.type, **({"Condition": r.condition} if r.condition else {}),
            **({"DependsOn": list(r.depends_on)} if r.depends_on else {}),
            **({"DeletionPolicy": r.deletion_policy} if r.deletion_policy else {}),
            **({"UpdateReplacePolicy": r.update_replace_policy} if r.update_replace_policy else {}),
            **({"Metadata": r.metadata} if r.metadata else {}),
            **({"Properties": r.properties} if r.properties else {})}


def _output(o):
    return {"Value": o.value, **({"Description": o.description} if o.description else {}),
            **({"Export": {"Name": o.export}} if o.export else {})}


def template_data(t):
    """The template document (sections in CloudFormation's documented order, empty ones left out), as both writers
    take it. Logical ids must be unique within each section (ValueError otherwise)."""
    for kind, ids in (("resource", [r.logical_id for r in t.resources]),
                      ("parameter", [p.logical_id for p in t.parameters]),
                      ("output", [o.logical_id for o in t.outputs])):
        _unique(kind, ids)
    return {"AWSTemplateFormatVersion": FORMAT_VERSION,
            **({"Description": t.description} if t.description else {}),
            **({"Transform": t.transform} if t.transform else {}),
            **({"Metadata": t.metadata} if t.metadata else {}),
            **({"Parameters": {p.logical_id: _parameter(p) for p in t.parameters}} if t.parameters else {}),
            **({"Conditions": dict(t.conditions)} if t.conditions else {}),
            "Resources": {r.logical_id: _resource(r) for r in t.resources},
            **({"Outputs": {o.logical_id: _output(o) for o in t.outputs}} if t.outputs else {})}


def resource_types(t):
    """Each resource type of a template once, in order: what a comparison with another render's types asks."""
    return tuple(dict.fromkeys(r.type for r in t.resources))
