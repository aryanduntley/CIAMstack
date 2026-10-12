"""What every AWS CLI reader needs of the recognized outputs ((path, top-level key, document), ...): their items, the
documents themselves, a tag list as a dict, and the file name that names what an output doesn't name itself. Pure."""
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
