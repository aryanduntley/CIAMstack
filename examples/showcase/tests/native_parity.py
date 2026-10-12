"""Reader parity of a cloud's native render (5.6c): an environment's render read back as its native templates (the
native ReadBack's prepare: what applying them records, the Terraform root kept beside them as its state) against its
Terraform roots read back as the states applying them record, all read together as one import reads them. What may
differ is named per cloud (Native): what only the Terraform read-back reads beyond lookups (a data source is in a
Terraform state; in a template it is a parameter or an existing reference, not a resource), and the attributes the
cloud assigns at deployment that no template holds (the record keeps them)."""
import json
from typing import Callable, NamedTuple

from opsdir_format_terraform.hcl import TfFile, written

Native = NamedTuple("Native", [("folder", str), ("files", Callable), ("prepare", Callable), ("read", Callable),
                               ("rendered_states", Callable), ("state_pairs", Callable),
                               ("pairs_resources", Callable), ("terraform_only", frozenset),
                               ("assigned", frozenset)])


def text_of(files):
    """{path: text} of rendered files, a TfFile written as Terraform writes it."""
    return {**{p: t for p, t in files.items() if not isinstance(t, TfFile)},
            **written({p: f for p, f in files.items() if isinstance(f, TfFile)})}


def _keyed(resources):
    """{(kind, name): resource}, a resource read twice (managed in one root, looked up in another) merged: each
    attribute as reported (None: not reported, so the record keeps it)."""
    def merged(old, new):
        a, b = dict(old.attrs), dict(new.attrs)
        return old._replace(attrs={x: a.get(x) if a.get(x) is not None else b.get(x) for x in {*a, *b}})
    out = {}
    for r in resources:
        k = (r.kind, r.name or r.ref)
        out = {**out, k: merged(out[k], r) if k in out else r}
    return out


def _states_read(native, states, data_only=False):
    def kept(text):
        state = json.loads(text)
        return json.dumps({**state, "resources": [r for r in state["resources"]
                                                  if not data_only or r.get("mode") == "data"]})
    return _keyed(native.pairs_resources([p for s in states for p in native.state_pairs(kept(s))[0]])[0])


def differences(native, m, files, env):
    """(read by Terraform alone, by the templates alone, {(kind, name): (Terraform's attributes, the templates')}) of
    environment m's render (files) read back both ways, less lookups, native.terraform_only kinds and
    native.assigned attributes."""
    tf = {f"{env}/{p[len('terraform/'):]}": t for p, t in text_of(files).items()
          if p.startswith("terraform/") and p.endswith(".tf")}
    states = tuple(native.rendered_states(tf, m.d, env).values())
    by_terraform, looked_up = _states_read(native, states), set(_states_read(native, states, data_only=True))
    rendered = {f"{env}/{p[len(native.folder):]}": t for p, t in text_of(native.files(m, files)).items()
                if p.startswith(native.folder)}
    by_native = _keyed(native.read({p[len(env) + 1:]: t for p, t in native.prepare(rendered, m.d, env).items()})[0])

    def compared(r):
        return {a: v for a, v in r.attrs.items() if a not in native.assigned}
    return ({k for k in set(by_terraform) - set(by_native) - looked_up if k[0] not in native.terraform_only},
            set(by_native) - set(by_terraform),
            {k: (compared(by_terraform[k]), compared(by_native[k])) for k in set(by_terraform) & set(by_native)
             if compared(by_terraform[k]) != compared(by_native[k])})
