"""What every AWS CLI reader needs of the recognized outputs ((path, top-level key, document), ...): their items, the
documents themselves, a tag list as a dict, and the file name that names what an output doesn't name itself. Pure."""
import re
from urllib.parse import quote, unquote


def tags_of(tags):
    """An AWS CLI tag list ([{Key, Value}]) as a dict."""
    return {t["Key"]: t.get("Value", "") for t in tags or () if isinstance(t, dict) and "Key" in t}


def items(outs, key):
    """The items of every output with this top-level key, in file order."""
    return [item for _, k, doc in outs if k == key for item in doc.get(key) or ()]


def documents(outs, key):
    """(path, document) of every output with this top-level key."""
    return [(p, doc) for p, k, doc in outs if k == key]


def stem(path):
    """A file name without its folder and extension."""
    return path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def file_name(name):
    """A resource name as a file name (without extension) that named maps back: percent-encoded, so a name with
    slashes (a log group's) stays one file."""
    return quote(name or "", safe="")


def named(path):
    """The resource name a file saved under file_name(name) holds."""
    return unquote(stem(path))


_HOME = re.compile(r"^arn:(aws[a-z-]*):[a-z0-9-]+:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):")
# Outputs whose ARNs are the environment's own account and region, in the order they are trusted
_OWN_ARNS = (("Subnets", "SubnetArn"), ("HubArn", None), ("ConfigurationRecorders", "arn"), ("Rules", "Arn"))


def home_of(outs):
    """(partition, region, account) of the environment the outputs describe, from the first ARN among those known to
    be its own (a subnet's, the Security Hub's, a Config recorder's, an EventBridge rule's); None when none says."""
    arns = [doc.get(key) if field is None else item.get(field)
            for key, field in _OWN_ARNS for _, k, doc in outs if k == key
            for item in ((doc,) if field is None else (i for i in doc.get(key) or () if isinstance(i, dict)))]
    found = next((m for a in arns for m in (_HOME.match(a or ""),) if m), None)
    return found.groups() if found else None
