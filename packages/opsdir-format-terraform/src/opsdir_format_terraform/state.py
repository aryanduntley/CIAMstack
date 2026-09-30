"""Terraform state (format version 4, as `terraform state pull` or a backend stores it), read as the resources it
records. Pure. What the state marks sensitive (sensitive_attributes) is dropped before anything reads it, and the
reader asks only for the attributes it needs; state files hold secrets (generated passwords, secret versions) and none
of them is kept.
"""
import json
from typing import Mapping, NamedTuple

# One resource instance of the state: managed or data, its type and name in the configuration, its attributes
StateResource = NamedTuple("StateResource", [("mode", str), ("type", str), ("name", str), ("attributes", Mapping)])


def _sensitive_keys(instance):
    """Top-level attributes the state marks sensitive (the first step of each sensitive path)."""
    return {path[0]["value"] for path in instance.get("sensitive_attributes") or ()
            if isinstance(path, list) and path and isinstance(path[0], dict) and path[0].get("type") == "get_attr"}


def read_state(text):
    """(state resources, problem): the resource instances of a version 4 state, sensitive attributes dropped; a
    problem (and no resources) when the text is not one."""
    try:
        doc = json.loads(text)
    except ValueError:
        return (), "not JSON"
    if not isinstance(doc, dict) or doc.get("version") != 4 or not isinstance(doc.get("resources"), list):
        return (), "not a Terraform state (format version 4)"
    return tuple(StateResource(r.get("mode", "managed"), r.get("type", ""), r.get("name", ""),
                               {k: v for k, v in (i.get("attributes") or {}).items() if k not in _sensitive_keys(i)})
                 for r in doc["resources"] if isinstance(r, dict)
                 for i in r.get("instances") or () if isinstance(i, dict)), None
