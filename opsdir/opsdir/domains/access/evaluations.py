"""Cloud evaluators' verdicts as recorded evidence (ciamEvaluated), preferred over evaluating the recorded policies.
Pure.

A cloud with an evaluator for any principal (its AccessModel's evaluator: the AWS policy simulator, Google Cloud's
Policy Troubleshooter) gets a script beside its Terraform, access/evaluate.sh, that asks it about each permission of
the principals acting as each identity the environment binds (by its provider ref; an identity it can't answer
for, or a permission on a resource the record names by a pattern, isn't asked), and saves each answer as
<folder>/evaluations/<identity>/<verb>__<role>[.<n>].json (n numbers a permission's parts: a secret and the key that
encrypts it). The cloud's CLI importer reads them back as '<verb> <role>: <state> (<evaluator> <YYYY-MM-DD>)' on the
identity, a permission's state the worst of its parts (denied, then unknown, then allowed), dated the import.
"""
import re
import shlex

from ...core.directory import one, rdn_value
from ...core.environment import of_class, one_role
from .grants import ALLOWED, DENIED, UNKNOWN, rows_for
from .imports import short_name
from .principals import permits, principals

FOLDER = "evaluations"
SCRIPT = "access/evaluate.sh"
_PATH = re.compile(rf"(?:^|/){FOLDER}/([^/]+)/([a-z-]+)__([a-z0-9][a-z0-9-]*)(?:\.\d+)?\.json$")
_WORST = (DENIED, UNKNOWN, ALLOWED)


def evaluation_path(identity, permit, part=None):
    """Where an evaluator's answer about one permission (or one part of it) of an identity is saved."""
    verb, _, role = permit.partition(" ")
    return f"{FOLDER}/{identity}/{verb}__{role}" + (f".{part}" if part else "") + ".json"


def evaluation_of(path):
    """(identity, permit) an evaluator's saved answer is about, from its path; None for any other file."""
    m = _PATH.search(path)
    return (m.group(1), f"{m.group(2)} {m.group(3)}") if m else None


def evaluated(permit, states, evaluator, date):
    """The ciamEvaluated value of a permission's answers: the worst state of its parts."""
    state = min(states, key=lambda s: _WORST.index(s) if s in _WORST else len(_WORST))
    return f"{permit}: {state} ({evaluator} {date or 'undated'})"


def evaluations_by_identity(found, verdict_of, evaluator, date):
    """{identity: (ciamEvaluated values)} of saved answers ((path, document), ...): verdict_of(document) gives a
    part's state (allowed, denied, unknown) or None for a document that isn't an answer."""
    parts = {}
    for path, doc in found:
        about, state = evaluation_of(path), verdict_of(doc)
        if about and state:
            parts.setdefault(about[0], {}).setdefault(about[1], []).append(state)
    return {who: tuple(evaluated(permit, states, evaluator, date) for permit, states in sorted(asked.items()))
            for who, asked in parts.items()}


def _acting(m, b):
    """The principals acting as an identity binding: those whose identity role is its role."""
    return [p for p in principals(m.d) if one(p, "ciamIdentityRole") == one(b, "ciamBindingRole")]


def _questions(m, model, identity, who):
    """(comment, (command, ...)) per permission of the principals acting as an identity."""
    def asked(permit):
        verb, _, role = permit.partition(" ")
        target = one_role(m, role)
        rows = rows_for(m.d, model, target, verb) if target is not None else ()
        if not rows:
            return permit, ()
        return permit, tuple(model.evaluator(m, identity, target, rows[0]))
    return [asked(x) for x in sorted({x for p in who for x in permits(m.d, p)})]


def evaluation_script(m, model, cloud):
    """The script asking the cloud's evaluator about each permission of each identity of environment m, or None when
    the cloud has none or nothing is to be asked."""
    if model is None or model.evaluator is None:
        return None
    identities = [(b, short_name(one(b, "ciamProviderRef")), _acting(m, b)) for b in of_class(m, "ciamIdentityBinding")
                  if one(b, "ciamProviderRef")]
    lines = []
    for b, name, who in identities:
        asked = _questions(m, model, b, who) if who else []
        if not any(commands for _, commands in asked):
            continue
        lines.append(f"\n# identity {rdn_value(b)} ({one(b, 'ciamProviderRef')}): "
                     f"{', '.join(rdn_value(p) for p in who)}")
        lines.append(f'mkdir -p "$OUT/{FOLDER}/{name}"')
        for permit, commands in asked:
            if not commands:
                lines.append(f"# {permit}: not asked (its role isn't bound here, {cloud} has no mapping for it, or "
                             "its evaluator can't answer for it)")
            for i, command in enumerate(commands, 1):
                path = evaluation_path(name, permit, i if len(commands) > 1 else None)
                lines.append(f'{command} > "$OUT/{path}"')
    if not lines:
        return None
    return "\n".join((
        "#!/bin/sh",
        f"# Ask {cloud}'s evaluator about each permission of the identities {m.label} binds; the answers are saved",
        f"# under <folder>/{FOLDER}/ and read back by the cloud's CLI importer (opsdir import <cloud>/cli-inventory).",
        "# Run where the cloud's CLI is signed in, with the environment's export folder (<cloud>/<env>/):",
        f"#   sh {SCRIPT} export/{shlex.quote(m.label)}",
        "set -eu",
        'OUT="${1:?usage: evaluate.sh <export folder for the environment>}"', *lines)) + "\n"


def quoted(*words):
    """A shell command from its words, each quoted where it needs to be."""
    return " ".join(shlex.quote(str(w)) for w in words)



def evaluation_files(m, model, cloud):
    """{access/evaluate.sh: script} for a renderer's output, or {} when there is nothing to ask."""
    script = evaluation_script(m, model, cloud)
    return {SCRIPT: script} if script else {}
