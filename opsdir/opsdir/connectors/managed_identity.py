"""The planner's managed identity check: the target's cloud-managed identity services (ciamManagedIdentity bindings,
domains/federation/managed.py) against what the adapters rendering it declare of them (Adapter.managed_identity). A
connector: the descriptors come from the adapters. Pure.

A target binding (it realizes one of the platform's identity services) must exist in the environment's partition,
serve every integration the identity service serves (their protocol, grants, client authentication, DPoP, PKCE), sign
with the service's algorithms and keep the hosts it publishes (its base URL and entity ID by a custom domain, its
issuer by a custom issuer). A neighbour binding in the target (the partner side of integrations) must exist there and
play the part its integrations' protocol types give it. What the vendor documents as unsupported is a blocker with no
confirmation path: the record has to change. What no vendor documentation establishes is a blocker until the
operator confirms it: an answered question of the register (governance unknowns, ciamUnknown) under the name the
finding gives (its fix proposes the question); while that question is open the register's own check counts it when it
blocks. A capability supported on a condition (an add-on), per-application MFA the service can't express, claim
transformations it can't express or expresses only on a condition (an extension), what a target in its partition must
know, and how users move are actions.
"""
from urllib.parse import urlsplit

from ..core.changeset import new_entry
from ..core.directory import get, one, rdn_value, values
from ..core.findings import Fix, Input, findings, merge_findings, responsible
from ..domains.federation.managed import (HOST_CAPABILITY, SUPPORTED, UNSUPPORTED, availability,
                                          integration_needs, is_target, managed_identities, mfa_split, partners,
                                          realized_service, roles, served, service_needs, slug, status, transforms,
                                          words)
from ..domains.governance.naming import UNKNOWNS
from ..domains.governance.unknowns import answered, blocking

AREA = "Managed identity"
URL_WORDS = {"ciamBaseUrl": "base URL", "ciamEntityId": "entity ID", "ciamOidcIssuer": "issuer"}


def _listed(names):
    return ", ".join(f"`{n}`" for n in names) or "none"


def question_name(m, b, capability):
    """The name of the register's question confirming a capability of a binding in environment m."""
    env, cloud = rdn_value(m.env), m.env.dn.split(",")[1].split("=", 1)[1]
    return f"confirm-{cloud}-{env}-{rdn_value(b)}-{slug(capability)}"


def _owners(*entries):
    """The owner DNs of the first of these entries that has any."""
    return next((values(e, "ciamOwner") for e in entries if e is not None and values(e, "ciamOwner")), ())


def confirm_fix(name, question, owners, concerns):
    """The Fix adding the blocking question that confirms a capability (its owner given when none is recorded)."""
    record = new_entry(f"cn={name},{UNKNOWNS}", ("top", "ciamUnknown"), {
        "cn": (name,), "ciamQuestion": (question,), "ciamBlocking": ("TRUE",), "ciamConcerns": concerns,
        "ciamOwner": owners or (Input("ciamOwner", "the party who must answer it (an owner's DN)"),)})
    return Fix(f"unknown:{name}", AREA, f"Ask the question `{name}` in the unknowns register", (record,),
               ("Ask the vendor; record the answer (ciamAnswer, ciamAnsweredAt) under an approved change once it "
                "confirms the capability. If the vendor says it can't, change the record instead (the integration, "
                "or where the identity service runs): an answer confirms.",),
               ("Answering the question clears the blocker: answer only with the vendor's confirmation.",))


def _confirmed(ctx, m, b, capability, needs, concerns, owner_entries):
    """The finding for a capability no vendor documentation establishes: confirmed (an answered question), waiting on an
    open question (the register counts a blocking one), or a blocker offering the question as its fix."""
    name = question_name(m, b, capability)
    asked = get(ctx.d, f"cn={name},{UNKNOWNS}")
    owner = responsible(ctx.d, *owner_entries)
    if asked is not None and answered(asked):
        return findings(ok=[f"{needs} {words(capability)}: confirmed in question `{name}`: {one(asked, 'ciamAnswer')}"])
    if asked is not None and blocking(asked):
        return findings()
    text = (f"{needs} {words(capability)}, and no vendor documentation establishes that it can: confirm it with the "
            f"vendor before relying on it")
    if asked is not None:
        return findings(blockers=[(AREA, f"{text}. Question `{name}` asks it and is still open: answer it (ciamAnswer, "
                                   "ciamAnsweredAt) once the vendor confirms.", owner)])
    question = f"{needs} {words(capability)}: does the vendor confirm it can?"
    return findings(blockers=[(AREA, f"{text}, and record the confirmation as the answer to question `{name}` "
                               "(unknowns register; the fix proposes it).", owner)],
                    fixes=[confirm_fix(name, question, _owners(*owner_entries), concerns)])


def _gap(ctx, m, b, spec, partition, capability, needs, concerns, owner_entries, change):
    """The finding for one capability: nothing when supported (an action when on a condition), a blocker when
    documented unsupported (change: what to do instead), else the confirmation path."""
    found, source = status(spec, partition, capability)
    if found == SUPPORTED:
        condition = spec.conditions.get(capability)
        return findings(actions=[(AREA, f"{needs} {words(capability)}, which {spec.title} does on a condition: "
                                  f"{condition}. Confirm it is in place before the move.",
                                  responsible(ctx.d, *owner_entries), None)]) if condition else findings()
    if found == UNSUPPORTED:
        return findings(blockers=[(AREA, f"{needs} {words(capability)}, which {spec.title} can't ({source}). "
                                   f"{change}", responsible(ctx.d, *owner_entries))])
    return _confirmed(ctx, m, b, capability, needs, concerns, owner_entries)


def _available(ctx, m, b, spec, partition):
    """The finding for a managed service existing in the environment's partition."""
    found, source = availability(spec, partition)
    where = f"{m.label} ({partition})"
    if found == SUPPORTED:
        return findings()
    if found == UNSUPPORTED:
        return findings(blockers=[(AREA, f"`{rdn_value(b)}` in {where} is {spec.title}, which doesn't exist there "
                                   f"({source}). Run the identity service elsewhere (keep it on its current product, "
                                   "or choose a service the partition has), or record the environment's cloud "
                                   "correctly.", responsible(ctx.d, b, m.env))])
    name = question_name(m, b, "available")
    asked = get(ctx.d, f"cn={name},{UNKNOWNS}")
    if asked is not None and answered(asked):
        return findings(ok=[f"{spec.title} exists in {where}: confirmed in question `{name}`: "
                            f"{one(asked, 'ciamAnswer')}"])
    if asked is not None and blocking(asked):
        return findings()
    question = f"Does {spec.title} exist in {where} for `{rdn_value(b)}`?"
    return findings(blockers=[(AREA, f"`{rdn_value(b)}` in {where} is {spec.title}, and no vendor documentation "
                               f"establishes that it exists there: confirm it with the vendor and record the answer "
                               f"to question `{name}` (unknowns register; the fix proposes it).",
                               responsible(ctx.d, b, m.env))],
                    fixes=() if asked is not None else [confirm_fix(name, question, _owners(b, m.env), (b.dn,))])


def _hosts(service):
    """((capability, host, attribute), ...): each published http(s) host of an identity service once per capability
    keeping it, in attribute order."""
    found = ((cap, urlsplit(one(service, attr)).hostname, attr) for attr, cap in HOST_CAPABILITY
             if one(service, attr) and urlsplit(one(service, attr)).scheme in ("http", "https"))
    return tuple({(cap, host): (cap, host, attr) for cap, host, attr in found if host}.values())


def _kept(ctx, m, b, spec, partition, service, cap, host, attr):
    """The finding for one published host of the identity service a target binding realizes."""
    name, label = rdn_value(service), rdn_value(b)
    needs = f"`{name}` publishes `{host}` (its {URL_WORDS[attr]}), so `{label}` in {m.label} must"
    found, _ = status(spec, partition, cap)
    if found == SUPPORTED:
        if (one(b, "ciamFqdn") or "").lower() == host.lower():
            return findings(ok=[f"`{label}` keeps `{name}`'s published host `{host}` in {m.label}."])
        return findings(blockers=[(AREA, f"{needs} serve it, and it records no such domain: record the domain it "
                                   f"serves sign-in at (ciamFqdn {host}) and the certificate it presents "
                                   "(ciamTlsCertificate), or change the identity service's URLs as their own approved "
                                   "change.",
                                   responsible(ctx.d, service, b))])
    return _gap(ctx, m, b, spec, partition, cap, needs, (b.dn, service.dn), (service, b, m.env),
                "Partners and applications must move to the service's own address (their metadata, their issuer) as "
                "part of the move, or the identity service stays where it is.")


def _target(ctx, m, b, spec):
    """Findings for a binding running one of the platform's identity services on a managed service."""
    service, label, partition = realized_service(ctx.d, b), rdn_value(b), spec.partition(m)
    if service is None:
        return findings(blockers=[(AREA, f"`{label}` in {m.label} realizes `{one(b, 'ciamRealizes')}`, which isn't "
                                   "one of the platform's identity services: correct ciamRealizes.",
                                   responsible(ctx.d, b, m.env))])
    name, integrations = rdn_value(service), served(ctx.d, service)
    change = ("Serve it from an identity service that can (register it with another), or change the integration as "
              "its own approved change.")
    per_integration = [_gap(ctx, m, b, spec, partition, cap,
                            f"`{rdn_value(i)}` ({one(i, 'ciamProtocolType')}) needs `{label}` ({spec.title}, running "
                            f"`{name}` in {m.label}) to", (b.dn, i.dn), (i, service, b, m.env), change)
                       for i in integrations for cap in integration_needs(i)]
    own = [_gap(ctx, m, b, spec, partition, cap, f"`{name}` needs `{label}` ({spec.title}) in {m.label} to",
                (b.dn, service.dn), (service, b, m.env),
                "Drop the algorithm from the identity service's record (clients verifying with it must change), or "
                "keep the service where it is.") for cap in service_needs(service)]
    kept = [_kept(ctx, m, b, spec, partition, service, cap, host, attr) for cap, host, attr in _hosts(service)]
    split = mfa_split(integrations)
    mfa = [] if not split or status(spec, partition, "mfa-per-client")[0] == SUPPORTED else [findings(actions=[(
        AREA, f"{_listed(rdn_value(i) for i in split)} require MFA and `{name}`'s other integrations don't, and "
        f"{spec.title} can't {words('mfa-per-client')}: decide whether every application on `{label}` in {m.label} "
        "requires MFA, or what enforces it per application.", responsible(ctx.d, service, b), None)])]
    shaped = transforms(ctx.d, integrations)
    expressible = status(spec, partition, "claim-transform")[0] == SUPPORTED
    condition = spec.conditions.get("claim-transform") if expressible else None
    how = (f"need {spec.title}'s {condition}: build them there for `{label}` in {m.label} and record where."
           if condition else f"aren't expressible in {spec.title}'s settings: implement them in `{label}`'s token "
           f"customization in {m.label} and record where.")
    transform = [] if not shaped or expressible and not condition else [findings(actions=[(
        AREA, f"The claim transformations of {_listed(rdn_value(i) for i in shaped)} {how}",
        responsible(ctx.d, service, b), None)])]
    notes = [findings(actions=[(AREA, f"{spec.title} in {m.label} ({partition}): {text} {how}",
                                responsible(ctx.d, service, b), None)])
             for _, text, how in (*spec.notes.get("*", ()), *spec.notes.get(partition, ()))]
    users = findings(actions=[(AREA, f"User accounts and passwords don't move with `{name}`'s configuration onto "
                               f"`{label}` ({spec.title}) in {m.label}: {spec.users}", responsible(ctx.d, service, b),
                               None)])
    issuer_to, relies_on = roles(ctx.d, b)
    ok = findings(ok=[f"`{label}` runs `{name}` on {spec.title} in {m.label}: issuer to {_listed(issuer_to)}; relying "
                      f"party of {_listed(relies_on)}."])
    return merge_findings([_available(ctx, m, b, spec, partition), *per_integration, *own, *kept, *mfa, *transform,
                           *notes, users, ok])


def _neighbour(ctx, m, b, spec):
    """Findings for a neighbour: it exists in its partition and can play the part its integrations give it."""
    label, partition = rdn_value(b), spec.partition(m)
    change = "Correct the record: the integration's protocol type, or which service is its partner side."
    gaps = [_gap(ctx, m, b, spec, partition, cap,
                 f"`{label}` ({spec.title}) in {m.label} is the partner side of `{rdn_value(i)}` "
                 f"({one(i, 'ciamProtocolType')}), so it must", (b.dn, i.dn), (b, i, m.env), change)
            for i in partners(ctx.d, b) for cap in integration_needs(i, as_partner=True)]
    issuer_to, relies_on = roles(ctx.d, b)
    keeper = get(ctx.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    kept_by = f", kept by {rdn_value(keeper)}" if keeper is not None else ""
    ok = findings(ok=[f"`{label}` ({spec.title}{kept_by}) in {m.label} is a neighbour: issuer to the platform for "
                      f"{_listed(issuer_to)}; relying party of the platform for {_listed(relies_on)}."])
    return merge_findings([_available(ctx, m, b, spec, partition), *gaps, ok])


def _undeclared(ctx, m, b):
    return findings(blockers=[(AREA, f"`{rdn_value(b)}` in {m.label} is `{one(b, 'ciamManagedService')}`, which no "
                               f"adapter rendering {m.label} declares: install the adapter that declares it (its "
                               "cloud's), or correct ciamManagedService.", responsible(ctx.d, b, m.env))])


def managed_identity_check(dst_adapters):
    """The planner check of the target's managed identity services, given the adapters rendering it."""
    specs = {s.name: s for a in dst_adapters for s in a.managed_identity}

    def check_managed_identity(ctx):
        m = ctx.dst
        return merge_findings([
            _undeclared(ctx, m, b) if one(b, "ciamManagedService") not in specs else
            (_target if is_target(b) else _neighbour)(ctx, m, b, specs[one(b, "ciamManagedService")])
            for b in managed_identities(m)])
    return check_managed_identity

