"""Who may request certificates from an AWS Private CA, per template (the core pki domain's ciamEnrollee and
ciamEnrollmentScope): the literal grants of the account's IAM policies, the CA's resource policy and ACM's permission.
Pure.

A principal (an IAM user with its groups' policies, or a role) may issue from a CA with a template when one of its
inline or attached policies allows acm-pca:IssueCertificate (Action or NotAction, IAM wildcards) on the CA's ARN
(Resource or NotResource) and no unconditional deny of its policies takes it away; a condition on acm-pca:TemplateArn
(StringEquals/StringLike/ArnEquals/ArnLike, or their negations) narrows it to the templates it names, a deny with
one takes those away. Any other condition, or a policy the export doesn't hold (an AWS managed policy whose document
wasn't saved), makes the principal's access unknown. The CA's resource policy (get-policy) lets other accounts issue:
a statement for every principal ('*') or for another account is broad (that account's IAM decides who). ACM issues
for the account's principals allowed acm:RequestCertificate when the CA grants acm.amazonaws.com IssueCertificate
(list-permissions): they are enrollees through ACM of the templates ACM-issued certificates were issued from.
Permissions boundaries, session policies and organization control policies only take access away and aren't judged:
a principal named may in fact be denied.
"""
from fnmatch import fnmatchcase

from opsdir.domains.pki.templates import BROAD, RESTRICTED, UNKNOWN
from .iam import policy_document, statements

ISSUE, REQUEST = "acm-pca:IssueCertificate", "acm:RequestCertificate"
ACM_PRINCIPAL = "acm.amazonaws.com"
TEMPLATE_KEY = "acm-pca:templatearn"
MATCHING, NEGATED = ("stringequals", "stringlike", "arnequals", "arnlike"), ("stringnotequals", "stringnotlike",
                                                                           "arnnotequals", "arnnotlike")


def _listed(v):
    return [v] if isinstance(v, str) else [x for x in v or () if isinstance(x, str)]


def _matches(patterns, value):
    return any(fnmatchcase(value.lower(), p.lower()) for p in patterns)


def _covers(s, action, resource):
    """Whether a statement's actions and resources take in the action on the resource."""
    acts = (not _matches(_listed(s["NotAction"]), action)) if "NotAction" in s else _matches(_listed(s.get("Action")),
                                                                                             action)
    res = (not _matches(_listed(s["NotResource"]), resource)) if "NotResource" in s else \
        _matches(_listed(s.get("Resource")) or ["*"], resource)
    return acts and res


def statement_grant(s, action, resource):
    """What one statement says of the action on the resource: None (nothing), ('all', None), ('only', template
    patterns), ('except', template patterns) or ('unknown', why)."""
    if not _covers(s, action, resource):
        return None
    cond = {str(op).lower(): keyed for op, keyed in (s.get("Condition") or {}).items() if isinstance(keyed, dict)}
    keys = {(op, str(k).lower()) for op, keyed in cond.items() for k in keyed}
    if not keys:
        return "all", None
    if any(k != TEMPLATE_KEY or op not in (*MATCHING, *NEGATED) for op, k in keys) or len(keys) > 1:
        return "unknown", f"a condition opsdir doesn't judge ({', '.join(sorted(f'{o} {k}' for o, k in keys))})"
    (op, _), = keys
    patterns = tuple(v for keyed in cond.values() for k, vals in keyed.items() for v in _listed(vals))
    return ("only" if op in MATCHING else "except"), patterns


def _applies(grant, template):
    kind, patterns = grant
    return (kind == "all" or (kind == "only" and _matches(patterns, template))
            or (kind == "except" and not _matches(patterns, template)))


def access(docs, action, resource, template):
    """'yes', 'no' or 'unknown': whether policy documents (None: one not held) allow the action on the resource
    with the template (an unconditional or template-matching deny wins)."""
    if any(doc is None for doc in docs):
        return "unknown"
    read = [(s.get("Effect"), statement_grant(s, action, resource)) for doc in docs for s in statements(doc)]
    if any(e == "Deny" and g is not None and g[0] != "unknown" and _applies(g, template) for e, g in read):
        return "no"
    allows = [g for e, g in read if e == "Allow" and g is not None]
    if any(g[0] != "unknown" and _applies(g, template) for g in allows):
        return "yes"
    return "unknown" if any(g[0] == "unknown" for g in allows) else "no"


def _default_version(p):
    return next((v.get("Document") for v in p.get("PolicyVersionList") or () if v.get("IsDefaultVersion")), None)


def principals(iam):
    """((principal ARN, its policy documents: None for one the export doesn't hold), ...) of an
    get-account-authorization-details answer: each user (its groups' policies too) and each role."""
    managed = {p.get("Arn"): _default_version(p) for p in iam.get("Policies") or () if isinstance(p, dict)}
    groups = {g.get("GroupName"): g for g in iam.get("GroupDetailList") or () if isinstance(g, dict)}

    def docs(e, inline_key):
        return (*(p.get("PolicyDocument") for p in e.get(inline_key) or ()),
                *(managed.get(a.get("PolicyArn")) for a in e.get("AttachedManagedPolicies") or ()))
    users = tuple((u.get("Arn"), (*docs(u, "UserPolicyList"),
                                  *(d for g in u.get("GroupList") or () for d in
                                    (docs(groups[g], "GroupPolicyList") if g in groups else (None,)))))
                  for u in iam.get("UserDetailList") or () if isinstance(u, dict))
    roles = tuple((r.get("Arn"), docs(r, "RolePolicyList")) for r in iam.get("RoleDetailList") or ()
                  if isinstance(r, dict))
    return tuple((arn, tuple(policy_document(d) if d is not None else None for d in ds))
                 for arn, ds in (*users, *roles) if arn)


def _resource_principals(s):
    who = s.get("Principal")
    return ("*",) if who == "*" else tuple(_listed((who or {}).get("AWS"))) if isinstance(who, dict) else ()


def _account_of(principal):
    parts = principal.split(":")
    return parts[4] if principal.startswith("arn:") and len(parts) > 4 else principal if principal.isdigit() else None


def resource_policy_enrollees(policy, ca_arn, account, template):
    """((enrollee, broad), ...) and whether any is unknown, of the CA's resource policy for a template: every
    principal ('*') and other accounts are broad, the account's own principals named."""
    read = [(p, statement_grant(s, ISSUE, ca_arn)) for s in statements(policy) if s.get("Effect") == "Allow"
            for p in _resource_principals(s)]
    found = tuple((p, p == "*" or _account_of(p) not in (account, None)) for p, g in read
                  if g is not None and g[0] != "unknown" and _applies(g, template))
    return found, any(g is not None and g[0] == "unknown" for _, g in read)


def acm_grants(permissions):
    """Whether the CA lets ACM issue from it (list-permissions: acm.amazonaws.com with IssueCertificate)."""
    return any(p.get("Principal") == ACM_PRINCIPAL and "IssueCertificate" in (p.get("Actions") or ())
               for p in (permissions or {}).get("Permissions") or () if isinstance(p, dict))


def enrollment(iam, policy, permissions, ca_arn, account, template, through_acm):
    """(enrollees, scope, why unknown or None) of a CA's template: the principals the account's IAM lets issue from
    it, the CA's resource policy's, and when ACM issues from it (through_acm and the CA's ACM permission) the
    principals allowed acm:RequestCertificate; scope broad, restricted or unknown (iam None: not read)."""
    if iam is None:
        return (), UNKNOWN, "the account's IAM policies weren't read (iam get-account-authorization-details)"
    people = principals(iam)
    direct = tuple((arn, access(docs, ISSUE, ca_arn, template)) for arn, docs in people)
    acm = through_acm and acm_grants(permissions)
    via_acm = tuple((arn, access(docs, REQUEST, "*", template)) for arn, docs in people) if acm else ()
    shared, shared_unknown = resource_policy_enrollees(policy, ca_arn, account, template)
    enrollees = (*(a for a, v in direct if v == "yes"), *(f"{a} (through ACM)" for a, v in via_acm if v == "yes"),
                 *(p for p, _ in shared))
    unknown = tuple(a for a, v in (*direct, *via_acm) if v == "unknown")
    scope = BROAD if any(b for _, b in shared) else UNKNOWN if unknown or shared_unknown else RESTRICTED
    why = (f"{len(unknown)} principal(s) whose policies opsdir can't judge or doesn't hold: {', '.join(unknown[:3])}"
           if unknown else "the CA's resource policy has a condition opsdir doesn't judge" if shared_unknown
           else None)
    return tuple(dict.fromkeys(enrollees)), scope, why if scope == UNKNOWN else None
