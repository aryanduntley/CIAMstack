"""The findings a planner check of cloud-managed services shares (connectors.managed_identity, managed_directory): a
capability the service's descriptor documents as supported (an action when only on a condition), documented
unsupported (a blocker with no confirmation path: the record has to change) or not established (a blocker until the
operator records the vendor's confirmation as the answer to a question of the unknowns register, ciamUnknown, under
the name the finding gives; its fix proposes the question, and while it is open the register's own check counts it
when it blocks); and the service existing in the environment's partition, alike. Each check speaks in its own Voice.
Pure.
"""
from typing import Callable, NamedTuple

from ..core.changeset import new_entry
from ..core.directory import get, one, rdn_value, values
from ..core.findings import Fix, Input, findings, responsible
from ..core.managed_services import SUPPORTED, UNSUPPORTED, availability, status
from ..domains.governance.naming import UNKNOWNS
from ..domains.governance.unknowns import answered, blocking

# How a check words its findings: its area, a capability in words, what changing the record instead means (when the
# vendor says it can't), and where to run the service instead (when the partition lacks it).
Voice = NamedTuple("Voice", [("area", str), ("words", Callable), ("instead", str), ("elsewhere", str)])


def question_name(m, b, capability):
    """The name of the register's question confirming a capability of a binding in environment m."""
    env, cloud = rdn_value(m.env), m.env.dn.split(",")[1].split("=", 1)[1]
    return f"confirm-{cloud}-{env}-{rdn_value(b)}-{capability}"


def owners(*entries):
    """The owner DNs of the first of these entries that has any."""
    return next((values(e, "ciamOwner") for e in entries if e is not None and values(e, "ciamOwner")), ())


def confirm_fix(voice, name, question, owner_dns, concerns):
    """The Fix adding the blocking question that confirms a capability (its owner given when none is recorded)."""
    record = new_entry(f"cn={name},{UNKNOWNS}", ("top", "ciamUnknown"), {
        "cn": (name,), "ciamQuestion": (question,), "ciamBlocking": ("TRUE",), "ciamConcerns": concerns,
        "ciamOwner": owner_dns or (Input("ciamOwner", "the party who must answer it (an owner's DN)"),)})
    return Fix(f"unknown:{name}", voice.area, f"Ask the question `{name}` in the unknowns register", (record,),
               ("Ask the vendor; record the answer (ciamAnswer, ciamAnsweredAt) under an approved change once it "
                f"confirms the capability. If the vendor says it can't, change the record instead ({voice.instead}): "
                "an answer confirms.",),
               ("Answering the question clears the blocker: answer only with the vendor's confirmation.",))


def confirmed(ctx, voice, m, b, capability, slug, needs, concerns, owner_entries):
    """The finding for a capability no vendor documentation establishes: confirmed (an answered question), waiting on an
    open question (the register counts a blocking one), or a blocker offering the question as its fix. slug: the
    capability as a question name's part."""
    name = question_name(m, b, slug)
    asked = get(ctx.d, f"cn={name},{UNKNOWNS}")
    owner = responsible(ctx.d, *owner_entries)
    said = voice.words(capability)
    if asked is not None and answered(asked):
        return findings(ok=[f"{needs} {said}: confirmed in question `{name}`: {one(asked, 'ciamAnswer')}"])
    if asked is not None and blocking(asked):
        return findings()
    text = (f"{needs} {said}, and no vendor documentation establishes that it can: confirm it with the vendor before "
            "relying on it")
    if asked is not None:
        return findings(blockers=[(voice.area, f"{text}. Question `{name}` asks it and is still open: answer it "
                                   "(ciamAnswer, ciamAnsweredAt) once the vendor confirms.", owner)])
    question = f"{needs} {said}: does the vendor confirm it can?"
    return findings(blockers=[(voice.area, f"{text}, and record the confirmation as the answer to question `{name}` "
                               "(unknowns register; the fix proposes it).", owner)],
                    fixes=[confirm_fix(voice, name, question, owners(*owner_entries), concerns)])


def gap(ctx, voice, m, b, spec, partition, capability, slug, needs, concerns, owner_entries, change):
    """The finding for one capability: nothing when supported (an action when on a condition), a blocker when
    documented unsupported (change: what to do instead), else the confirmation path."""
    found, source = status(spec, partition, capability)
    said = voice.words(capability)
    if found == SUPPORTED:
        condition = spec.conditions.get(capability)
        return findings(actions=[(voice.area, f"{needs} {said}, which {spec.title} does on a condition: {condition}. "
                                  "Confirm it is in place before the move.", responsible(ctx.d, *owner_entries),
                                  None)]) if condition else findings()
    if found == UNSUPPORTED:
        return findings(blockers=[(voice.area, f"{needs} {said}, which {spec.title} can't ({source}). {change}",
                                   responsible(ctx.d, *owner_entries))])
    return confirmed(ctx, voice, m, b, capability, slug, needs, concerns, owner_entries)


def available(ctx, voice, m, b, spec, partition):
    """The finding for a managed service existing in the environment's partition: documented absent a blocker, not
    established a blocker until a question confirms it."""
    found, source = availability(spec, partition)
    where = f"{m.label} ({partition})"
    if found == SUPPORTED:
        return findings()
    if found == UNSUPPORTED:
        return findings(blockers=[(voice.area, f"`{rdn_value(b)}` in {where} is {spec.title}, which doesn't exist "
                                   f"there ({source}). {voice.elsewhere}, or record the environment's cloud "
                                   "correctly.", responsible(ctx.d, b, m.env))])
    name = question_name(m, b, "available")
    asked = get(ctx.d, f"cn={name},{UNKNOWNS}")
    if asked is not None and answered(asked):
        return findings(ok=[f"{spec.title} exists in {where}: confirmed in question `{name}`: "
                            f"{one(asked, 'ciamAnswer')}"])
    if asked is not None and blocking(asked):
        return findings()
    question = f"Does {spec.title} exist in {where} for `{rdn_value(b)}`?"
    return findings(blockers=[(voice.area, f"`{rdn_value(b)}` in {where} is {spec.title}, and no vendor documentation "
                               f"establishes that it exists there: confirm it with the vendor and record the answer "
                               f"to question `{name}` (unknowns register; the fix proposes it).",
                               responsible(ctx.d, b, m.env))],
                    fixes=() if asked is not None else [confirm_fix(voice, name, question, owners(b, m.env),
                                                                    (b.dn,))])


def undeclared(ctx, area, m, b):
    """The blocker for a binding whose ciamManagedService no adapter rendering the environment declares."""
    return findings(blockers=[(area, f"`{rdn_value(b)}` in {m.label} is `{one(b, 'ciamManagedService')}`, which no "
                               f"adapter rendering {m.label} declares: install the adapter that declares it (its "
                               "cloud's), or correct ciamManagedService.", responsible(ctx.d, b, m.env))])
