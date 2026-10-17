"""Who may request certificates from a Google Cloud CA pool, per template (the core pki domain's ciamEnrollee and
ciamEnrollmentScope): the IAM policies of the pool, of the certificate template and of the project. Pure.

Requesting a certificate whose subject the requester names takes privateca.certificates.create on the pool
(roles/privateca.certificateRequester, certificateManager, admin; workloadCertificateRequester's createForSelf only
reflects the caller's own identity and isn't counted); naming a template also takes privateca.certificateTemplates.use
on it (roles/privateca.templateUser, admin). A role granted on the project applies to every pool and template in it.
A member may request with a template when it holds both: allUsers, allAuthenticatedUsers and domain: members are
broad (on one side they admit the other side's members). A conditional binding (IAM conditions on the subject, the
names or the template) or a custom role is judged unknown, as is a policy not read. Roles granted on the folders and
the organization above the project aren't read: they can only add members (named).
"""
from opsdir.domains.pki.templates import BROAD, RESTRICTED, UNKNOWN
from .iam import PUBLIC

REQUESTERS = ("roles/privateca.certificateRequester", "roles/privateca.certificateManager", "roles/privateca.admin")
TEMPLATE_USERS = ("roles/privateca.templateUser", "roles/privateca.admin")
CUSTOM = ("projects/", "organizations/")


def is_broad(member):
    """Whether an IAM member is a broad group: everyone, every authenticated account, or a whole domain."""
    return member in PUBLIC or member.startswith("domain:")


def holders(policies, roles):
    """(members holding one of the roles, members whose binding can't be judged: conditional or a custom role) of IAM
    policies; None for one not read."""
    bindings = tuple(b for p in policies if p for b in p.get("bindings") or () if isinstance(b, dict))
    held = tuple(m for b in bindings if b.get("role") in roles and not b.get("condition")
                 for m in b.get("members") or ())
    unknown = tuple(m for b in bindings if (b.get("role") in roles and b.get("condition"))
                    or str(b.get("role") or "").startswith(CUSTOM) for m in b.get("members") or ())
    return tuple(dict.fromkeys(held)), tuple(dict.fromkeys(m for m in unknown if m not in held))


def _both(requesters, users):
    """The members holding both sides: each side's members a broad member on the other side admits, and those on
    both."""
    if any(is_broad(m) for m in users):
        return requesters
    if any(is_broad(m) for m in requesters):
        return users
    return tuple(m for m in requesters if m in users)


def enrollment(pool_policy, template_policy, project_policy, templated):
    """(enrollees, scope, why unknown or None) of requesting from a pool, with a template when templated (then its
    policy counts too); scope broad, restricted or unknown (a policy not read: None)."""
    missing = tuple(n for n, p in (("the pool's", pool_policy), ("the project's", project_policy),
                                   *((("the template's", template_policy),) if templated else ())) if p is None)
    requesters, unsure = holders((pool_policy, project_policy), REQUESTERS)
    if templated:
        users, unsure_users = holders((template_policy, project_policy), TEMPLATE_USERS)
        enrollees, unsure = _both(requesters, users), (*unsure, *unsure_users)
    else:
        enrollees = requesters
    scope = BROAD if any(is_broad(m) for m in enrollees) else UNKNOWN if missing or unsure else RESTRICTED
    why = (f"{' and '.join(missing)} IAM policy wasn't read" if missing else
           f"{len(unsure)} member(s) with a conditional binding or a custom role: {', '.join(unsure[:3])}"
           if unsure else None)
    return enrollees, scope, why if scope == UNKNOWN else None
