"""A system boundary's control implementations as an OSCAL system security plan: the system (its SSP id, name, the
environments inside its authorization boundary), one component for the system itself and one per cloud authorization
its environments rely on, and one implemented requirement per control the authorizations' control responsibilities
name: who meets it (the provider's component when inherited, both when shared, the system when the customer's), how
the operator meets it (its implementation, else the exception or POA&M item covering it, else what the customer must
do). Pure.

What OSCAL requires and the record doesn't hold is written UNBOUND and named in a note: the profile the SSP implements
(import-profile), the information types the system handles, its operational status."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.notes import note

from .common import (AREA, OscalDoc, control_id, entry_uid, is_token, last_modified, metadata, props, unbound,
                     unbound_note)
from .poam import SYSTEM_ID_TYPE
from .record import boundary_responsibilities, environments, labels, system_id

_UNBOUND = ("import-profile href (the profile it implements)", "the system's information types",
            "the system's and its components' operational status")
_DATED = ("ciamScopeAsOf", "ciamCertifiedAt", "ciamRetrievedAt")
_STATES = (("ciamImplementation", "implemented"), ("ciamExceptionRef", "alternative"), ("ciamPoamRef", "planned"))


def _component(uuid, kind, title, description):
    return {"uuid": uuid, "type": kind, "title": title, "description": description,
            "status": {"state": "other", "remarks": unbound("operational-status")}}


def _authorization_component(auth):
    return _component(entry_uid("component", auth), "service", one(auth, "ciamOfferingName") or rdn_value(auth),
                      f"The cloud offering the system relies on, under authorization {one(auth, 'ciamPackageId')}.")


def _how(r):
    """How the operator meets a responsibility the customer holds: (implementation status, description)."""
    state = next((s for attr, s in _STATES if one(r, attr)), None)
    text = one(r, "ciamImplementation") or (f"Covered by {one(r, 'ciamExceptionRef') or one(r, 'ciamPoamRef')}."
                                            if state else one(r, "ciamCustomerAction") or unbound("implementation"))
    return state, text


def _by_components(b, auth, r):
    who = one(r, "ciamResponsibility")
    provider = ({"component-uuid": entry_uid("component", auth), "uuid": entry_uid("by-component", r, "provider"),
                 "description": f"Met by {one(auth, 'ciamOfferingName') or rdn_value(auth)} ({who}).",
                 "props": props((("record-dn", r.dn), ("responsibility", who)))},) if who != "customer" else ()
    state, text = _how(r)
    system = ({"component-uuid": entry_uid("component", b), "uuid": entry_uid("by-component", r, "system"),
               "description": text, "props": props((("record-dn", r.dn), ("responsibility", who))),
               **({"implementation-status": {"state": state}} if state else {})},) if who != "inherited" else ()
    return (*provider, *system)


def _requirements(b, pairs):
    """One implemented requirement per control, its by-components the responsibilities naming it; controls whose id
    isn't an OSCAL token are left out (named by the caller)."""
    by_control = {}
    for auth, r in pairs:
        for ref in values(r, "ciamControlRef"):
            by_control.setdefault(ref, []).extend(_by_components(b, auth, r))
    return [{"uuid": entry_uid("requirement", b, ref), "control-id": control_id(ref)[1],
             "props": props((("control", ref),)), "by-components": parts}
            for ref, parts in sorted(by_control.items()) if is_token(control_id(ref)[1])]


def _skipped(pairs):
    return sorted({ref for _, r in pairs for ref in values(r, "ciamControlRef") if not is_token(control_id(ref)[1])})


def has_ssp(d, b):
    """Whether a system boundary has an SSP to write: a control responsibility (whose id is an OSCAL token) under an
    authorization its environments rely on."""
    return bool(_requirements(b, boundary_responsibilities(d, b)))


def ssp_document(d, b, as_of=None):
    """OscalDoc of a system boundary's SSP (b: its entry); last-modified is when its authorizations' scope was last
    taken or certified, else the day given (as_of). Refused when no control responsibility applies to it (OSCAL
    requires an implemented requirement)."""
    pairs = boundary_responsibilities(d, b)
    requirements = _requirements(b, pairs)
    if not requirements:
        raise SystemExit(f"oscal: system boundary {rdn_value(b)} has no control responsibility under an authorization "
                         "its environments rely on; OSCAL's SSP needs an implemented requirement")
    auths = sorted({a.norm: a for a, _ in pairs}.values(), key=rdn_value)
    envs = labels(environments(b))
    document = {"system-security-plan": {
        "uuid": entry_uid("ssp", b),
        "metadata": metadata(f"System security plan: {rdn_value(b)}", last_modified(auths, _DATED, as_of),
                             one(b, "ciamSspRef")),
        "import-profile": {"href": unbound("profile")},
        "system-characteristics": {
            "system-ids": [{"identifier-type": SYSTEM_ID_TYPE, "id": system_id(b)}],
            "system-name": rdn_value(b),
            "description": f"System boundary {rdn_value(b)} as the opsdir record holds it.",
            "props": props((("record-dn", b.dn),)),
            "system-information": {"information-types": [{"uuid": entry_uid("information-type", b),
                                                          "title": unbound("information-type"),
                                                          "description": unbound("information-type")}]},
            "status": {"state": "other", "remarks": unbound("operational-status")},
            "authorization-boundary": {"description": "Environments inside the boundary: "
                                                      f"{', '.join(envs) or unbound('environments')}."}},
        "system-implementation": {"components": [
            _component(entry_uid("component", b), "this-system", rdn_value(b), "The system as a whole."),
            *(_authorization_component(a) for a in auths)]},
        "control-implementation": {
            "description": "Who meets each control under the cloud authorizations the system's environments rely on, "
                           "from the record's control responsibilities.",
            "implemented-requirements": requirements}}}
    skipped = _skipped(pairs)
    left_out = (note(AREA, "action", f"OSCAL SSP of {rdn_value(b)}", f"controls left out: {', '.join(skipped)} (their "
                     "ids aren't OSCAL tokens)", ("Record the controls as their catalog names them",), entry=b.dn),) \
        if skipped else ()
    return OscalDoc(document, (unbound_note(f"OSCAL SSP of {rdn_value(b)}", b.dn, _UNBOUND, (
        "Complete the UNBOUND fields in the OSCAL SSP before submitting it: the record doesn't hold them",)),
        *left_out))
