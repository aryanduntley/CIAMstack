"""Certificate template risk: templates that let whoever requests a certificate name its subject, for certificates
that authenticate their holder, with nobody approving the request (ESC1-style, after the published research on
certificate template abuse). Pure functions of a snapshot.

A template is at risk when it takes the subject from the request (ciamSubjectFromRequest), what it issues
authenticates (no extended key usage at all, any purpose, client authentication, PKINIT client authentication or
smart card logon: AUTHENTICATING), no CA manager approves its requests (ciamApprovalRequired not TRUE) and they need
no authorized signature (ciamRequiredSignatures 0 or not recorded). Whoever may enroll then obtains a certificate in
any account's name, an administrator's included. Its importer says who may enroll (ciamEnrollee) and whether that is
a broad group (ciamEnrollmentScope: broad, restricted, unknown). A template no recorded CA issues from, where the
record lists the templates its CAs issue from, is latent and only counted; where no CA lists them, whether one
issues from it is unknown and it is judged. Who answers for it: the template's renewal owner, else the owners of the
CAs issuing from it.

Not judged here (README Known limits; follow-up work): any-purpose templates without a requester-named subject,
enrollment agent templates, who may change a template, templates that leave out the requester's security
identifier, and schema version 1 templates on CAs that let the request add application policies.
"""
from ...core.directory import children, one, rdn_of, rdn_value, values
from ...core.findings import findings, responsible
from .issued import AREA, TEMPLATE_CLASS, authorities
from .naming import TEMPLATES

# the extended key usages whose certificates authenticate their holder (no usage at all counts too)
AUTHENTICATING = {"1.3.6.1.5.5.7.3.2": "client authentication", "1.3.6.1.5.2.3.4": "PKINIT client authentication",
                  "1.3.6.1.4.1.311.20.2.2": "smart card logon", "2.5.29.37.0": "any purpose"}
BROAD, RESTRICTED, UNKNOWN, UNPUBLISHED = "broad", "restricted", "unknown", "unpublished"


def authenticates(usages):
    """Whether certificates with these extended key usages authenticate their holder: none at all, or one of
    AUTHENTICATING."""
    return not usages or any(u in AUTHENTICATING for u in usages)


def issuing_authorities(d, name):
    """(the recorded CAs issuing from the template named name, whether any recorded CA lists its templates)."""
    listing = tuple(a for a in authorities(d) if values(a, "ciamTemplateName"))
    return tuple(a for a in listing if name.lower() in {v.lower() for v in values(a, "ciamTemplateName")}), \
        bool(listing)


def template_risk(d, t):
    """The state of a certificate template: None when it doesn't let the requester name the subject of
    authenticating certificates unapproved; unpublished when no recorded CA issues from it (the record listing
    theirs); else who may enroll (broad, restricted or unknown)."""
    if (one(t, "ciamSubjectFromRequest") != "TRUE" or one(t, "ciamApprovalRequired") == "TRUE"
            or (one(t, "ciamRequiredSignatures") or "0") != "0"
            or not authenticates(values(t, "ciamExtendedKeyUsage"))):
        return None
    issuing, known = issuing_authorities(d, rdn_value(t))
    if known and not issuing:
        return UNPUBLISHED
    return one(t, "ciamEnrollmentScope") or UNKNOWN


def _usage(t):
    usages = values(t, "ciamExtendedKeyUsage")
    return ", ".join(AUTHENTICATING[u] for u in usages if u in AUTHENTICATING) if usages else "no usage restriction"


def _owner(d, t, issuing):
    owner = one(t, "ciamRenewalOwner")
    return rdn_of(owner) if owner else responsible(d, *issuing)


def _finding(d, t, state):
    name = rdn_value(t)
    issuing, known = issuing_authorities(d, name)
    where = (f"{', '.join(rdn_value(a) for a in issuing)} issues from it" if issuing else
             "whether a CA issues from it is unknown (no recorded CA lists its templates)")
    what = (f"Certificate template `{name}` lets the requester name the subject of the certificates it issues, which "
            f"authenticate their holder ({_usage(t)}), with no CA manager approval or authorized signature; {where}")
    text = (f"{what}. It lets {', '.join(values(t, 'ciamEnrollee'))} enroll: any of them can obtain a certificate in "
            "any account's name, an administrator's included (ESC1). Require CA manager approval, build the subject "
            "from the directory, or let only the accounts that need it enroll." if state == BROAD else
            f"{what}. Who may enroll from it is unknown (its access rights weren't read): collect them (`opsdir "
            "collect`, the CA product's template collector) and import them, then judge it again.")
    return (AREA, text, _owner(d, t, issuing), None)


def check_template_risk(ctx):
    """Certificate templates letting the requester name the subject of authenticating certificates with no approval
    or authorized signature (ESC1-style): one a broad group may enroll from is an action, as is one whose enrollment
    isn't known (collect its access rights); owned by the template's renewal owner, else the issuing CAs' owners.
    Those only named accounts may enroll from, and those no recorded CA issues from, are counted."""
    judged = tuple((t, template_risk(ctx.d, t)) for t in children(ctx.d, TEMPLATES, TEMPLATE_CLASS))
    counts = {state: sum(1 for _, s in judged if s == state) for state in (RESTRICTED, UNPUBLISHED)}
    lead = "certificate template(s) letting the requester name the subject of authenticating certificates"
    return findings(actions=[_finding(ctx.d, t, s) for t, s in judged if s in (BROAD, UNKNOWN)],
                    ok=[*((f"{counts[RESTRICTED]} {lead} let only named accounts enroll.",) if counts[RESTRICTED]
                          else ()),
                        *((f"{counts[UNPUBLISHED]} {lead} are issued by no recorded CA.",) if counts[UNPUBLISHED]
                          else ())])
