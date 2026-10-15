"""Terraform state (format version 4, as `terraform state pull` or a backend stores it), read as the resources it
records. Pure. What the state marks sensitive (sensitive_attributes) is dropped before anything reads it, and the
reader asks only for the attributes it needs; state files hold secrets (generated passwords, secret versions) and none
of them is kept. Also what the cloud importers share: a state as (type, attributes) pairs and resources, and the
collection steps that fetch an environment's states.
"""
import json
from collections import Counter
from typing import Mapping, NamedTuple

from opsdir.core.contract import CollectOption, Command
from opsdir.domains.governance.collection import collection_sources

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


def blocks(v):
    """A nested block of a resource's attributes as a list of objects: the state writes nested blocks as lists (a
    single object, or nothing, is normalized)."""
    return v if isinstance(v, list) else [v] if isinstance(v, dict) else []


def first_block(v):
    """The first object of a nested block ({} when there is none)."""
    return next((b for b in blocks(v) if isinstance(b, dict)), {})


def state_pairs(text, skipped, names=lambda rtype, attributes: attributes):
    """((Terraform resource type, attributes) pairs, notices) of a Terraform state: its resource instances (names(type,
    attributes): the attributes under the names the cloud's readers take), the types in skipped (secret-bearing,
    unmodeled: the readers don't read them) named, with their counts."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = tuple((r.type, names(r.type, r.attributes)) for r in found)
    counted = Counter(t for t, _ in pairs if t in skipped)
    return pairs, tuple(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)"
                        for t, n in sorted(counted.items()))


def state_resources(text, skipped, read_pairs, names=lambda rtype, attributes: attributes, skipped_first=False):
    """(resources, notices) of a Terraform state: its pairs (state_pairs) read by the cloud's read_pairs(pairs) ->
    (resources, notices); the skipped types' notices after the reader's (before them with skipped_first)."""
    pairs, unread = state_pairs(text, skipped, names)
    resources, notices = read_pairs(list(pairs))
    return resources, ((*unread, *notices) if skipped_first else (*notices, *unread))


# The collect option state_steps reads (terraform_dir), declared here once for every cloud's terraform-state collector.
TERRAFORM_DIR = CollectOption("--terraform-dir", "DIR", "read Terraform state with `terraform state pull` in DIR", 10)


def state_steps(m, importer, scheme, fetch, options):
    """The terraform-state collection steps of environment m ((path, Command), ...): `terraform state pull` in the
    terraform_dir option when given, else for each location of the importer's collection sources (governance.collection)
    starting with scheme, fetch(location) (a Command, or None for a location it can't read: left out), saved as
    <environment>/<the location's last segment, else terraform.tfstate>."""
    if options.get("terraform_dir"):
        return ((f"{m.label}/terraform.tfstate",
                 Command(("terraform", f"-chdir={options['terraform_dir']}", "state", "pull"))),)
    return tuple((f"{m.label}/{loc.rsplit('/', 1)[-1] or 'terraform.tfstate'}", step)
                 for s in collection_sources(m, importer) for loc in s.locations if loc.startswith(scheme)
                 for step in (fetch(loc),) if step is not None)
