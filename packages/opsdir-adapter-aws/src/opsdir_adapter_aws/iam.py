"""AWS IAM in an environment's sources as the record's identities, guardrails and access paths (opsdir.core.inventory),
from (Terraform resource type, attributes) pairs like every AWS source. Pure.

  aws_iam_role (+ aws_iam_role_policy,      -> identity (kind role, federated when an OIDC provider may assume it):
    aws_iam_role_policy_attachment,            who may assume it (a service, '<issuer URL> <subject>' for an OIDC
    aws_iam_policy)                            provider, a principal ARN), the grants and denials of its inline and
                                               attached policies, its permissions boundary's allows as its ceiling;
                                               role from its tag Role (or BindingRole); a cloud
                                               evaluator's verdicts (evaluated: opsdir.domains.access.evaluations)
  resource policies: aws_kms_key's policy,  -> grants (' (resource policy)') and denials on the roles they name; a
    aws_kms_key_policy, aws_s3_bucket_policy,  deny naming every principal ('*') applies to every role here
    aws_secretsmanager_secret_policy
  aws_ssoadmin_permission_set (+ its inline -> identity per group it is assigned to (kind permission-set, the group id
    policy, managed policy attachments,        as its provider ref: how the landing zone names an operator's group),
    account assignments)                       the grants of its policies; role from the permission set's tag Role
  aws_organizations_policy (service and     -> guardrail (service-control, resource-control): its denies, its allows
    resource control policies)                 as a ceiling unless they allow everything, what it prevents by the
                                               statement ids the renderer gives; role from its tag Role
  data aws_ssoadmin_instances               -> access path workforce-sso (role access-workforce-sso)
  aws_ec2_instance_connect_endpoint         -> access path session (role access-session)
A statement is read as each of its actions (NotAction: '!a|b', every action but those) on each of its resources
(NotResource: '*', the exclusion its condition), ' (if <condition>)' when it has one. AWS managed policies
(arn:aws:iam::aws:policy/...) and policies outside the state aren't in it: named, not read.
"""
import json
from collections import defaultdict
from urllib.parse import unquote

from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.access.grants import excluding, grant_text
from .guardrails import denials_of

CONTROL_KINDS = {"SERVICE_CONTROL_POLICY": "service-control", "RESOURCE_CONTROL_POLICY": "resource-control"}
ASSUME = ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:TagSession", "sts:*")


def _tags(a):
    return a.get("tags") or a.get("tags_all") or {}


def _listed(v):
    return [v] if isinstance(v, (str, int, float, bool)) else list(v or ())


def policy_document(text):
    """A policy document (JSON text, URL-encoded as IAM's API returns it, or already read), or {} when it isn't
    one."""
    if isinstance(text, dict):
        return text
    if isinstance(text, str) and text.lstrip().startswith("%7B"):
        text = unquote(text)
    try:
        doc = json.loads(text or "{}")
    except (TypeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def statements(text):
    """A policy document's statements."""
    found = policy_document(text).get("Statement") or []
    return [s for s in ([found] if isinstance(found, dict) else found) if isinstance(s, dict)]


def _condition(s):
    """A statement's condition in words ('StringEquals aws:SourceVpc vpc-1'), or None."""
    cond = s.get("Condition") or {}
    return "; ".join(f"{op} {key} {'|'.join(str(v) for v in _listed(vals))}"
                     for op, keyed in sorted(cond.items()) if isinstance(keyed, dict)
                     for key, vals in sorted(keyed.items())) or None


def statement_texts(s, resource_policy=False, own=None):
    """(effect, texts) of a statement: 'Allow' or 'Deny', and each action on each resource as the record writes it.
    own is the resource a resource policy is attached to ('*' there means it)."""
    actions = [excluding("", _listed(s["NotAction"]))] if "NotAction" in s else _listed(s.get("Action"))
    condition = _condition(s)
    if "NotResource" in s:
        resources = ["*"]
        condition = "; ".join(c for c in (condition, f"resource not {'|'.join(_listed(s['NotResource']))}") if c)
    else:
        resources = [own if own and r == "*" else r for r in _listed(s.get("Resource"))] or ([own] if own else [])
    return s.get("Effect"), tuple(grant_text(a, r, condition, resource_policy) for a in actions for r in resources)


def _read(docs, resource_policy=False, own=None):
    """(grants, denials) of policy documents."""
    read = [statement_texts(s, resource_policy, own) for doc in docs for s in statements(doc)]
    return (tuple(t for effect, ts in read if effect == "Allow" for t in ts),
            tuple(t for effect, ts in read if effect == "Deny" for t in ts))


def _principals(s, kind):
    """The principals of a kind ('AWS', 'Service', 'Federated') a statement names; ('*',) for every principal."""
    who = s.get("Principal")
    if who == "*":
        return ("*",)
    return tuple(str(p) for p in _listed((who or {}).get(kind))) if isinstance(who, dict) else ()


def _trust(role):
    """Who may assume a role: services, '<issuer URL> <subject>' per OIDC subject, principal ARNs."""
    def subjects(s, host):
        cond = s.get("Condition") or {}
        found = [v for op in ("StringEquals", "StringLike") for v in _listed((cond.get(op) or {}).get(f"{host}:sub"))]
        return found or ["*"]
    allowed = [s for s in statements(role.get("assume_role_policy")) if s.get("Effect") == "Allow"
               and any(a in ASSUME or a == "*" for a in _listed(s.get("Action")))]
    federated = [(s, p.split(":oidc-provider/", 1)[1]) for s in allowed for p in _principals(s, "Federated")
                 if ":oidc-provider/" in p]
    return tuple(dict.fromkeys((
        *(p for s in allowed for p in _principals(s, "Service")),
        *(f"https://{host} {sub}" for s, host in federated for sub in subjects(s, host)),
        *(p for s in allowed for p in _principals(s, "Federated") if ":oidc-provider/" not in p),
        *(p for s in allowed for p in _principals(s, "AWS")))))


def _resource_policies(found, keys):
    """[(principals, effect, texts)] of the resource policies in the state: KMS keys', buckets', secrets'."""
    def per(doc, own):
        return [(_principals(s, "AWS"), *statement_texts(s, True, own)) for s in statements(doc)]
    return [*(x for k in of_types(found, "aws_kms_key") if k.get("policy") for x in per(k["policy"], k.get("arn"))),
            *(x for p in of_types(found, "aws_kms_key_policy")
              for x in per(p.get("policy"), keys.get(p.get("key_id"), p.get("key_id")))),
            *(x for p in of_types(found, "aws_s3_bucket_policy") for x in per(p.get("policy"), None)),
            *(x for p in of_types(found, "aws_secretsmanager_secret_policy")
              for x in per(p.get("policy"), p.get("secret_arn")))]


def _attached(name, found, field, attachments, key):
    """The policy ARNs attached to a role (or permission set) named name."""
    return (*_listed(field), *(a.get("policy_arn") or a.get("managed_policy_arn")
                               for a in of_types(found, *attachments) if a.get(key) == name))


def _documents(arns, policies, owner):
    """(documents, notices) of attached policies: those in the state; the others named."""
    return (tuple(policies[a] for a in arns if a in policies),
            tuple(f"{owner}: policy {a} isn't in the state (an AWS managed policy, or kept elsewhere); its grants not "
                  "read" for a in dict.fromkeys(arns) if a not in policies))


def _roles(found, policies, by_resource):
    def one_role(r):
        name, arn = r.get("name"), r.get("arn")
        inline = (*(b.get("policy") for b in r.get("inline_policy") or () if b.get("policy")),
                  *(p.get("policy") for p in of_types(found, "aws_iam_role_policy")
                    if p.get("role") in (name, r.get("id"))))
        attached, missing = _documents(_attached(name, found, r.get("managed_policy_arns"),
                                                 ("aws_iam_role_policy_attachment",), "role"), policies, f"role {name}")
        grants, denials = _read((*inline, *attached))
        boundary = r.get("permissions_boundary")
        ceiling, edge = _read((policies[boundary],)) if boundary in policies else ((), ())
        trust = _trust(r)
        extra = by_resource.get(arn, ((), ()))
        return resource("identity", arn, {
            "ciamIdentityKind": None if r.get("assume_role_policy") is None          # only verdicts: kept
            else "federated" if any(t.startswith("https://") for t in trust) else "role",
            "ciamTrustedBy": trust, "ciamGrant": sorted({*grants, *extra[0]}),
            "ciamDenial": sorted({*denials, *edge, *extra[1], *by_resource.get("*", ((), ()))[1]}),
            "ciamBoundary": sorted(ceiling), "ciamEvaluated": r.get("evaluated")}, name=name,
            role=tagged_role(_tags(r))), (
            *missing, *((f"role {name}: permissions boundary {boundary} isn't in the state; its ceiling not read",)
                        if boundary and boundary not in policies else ()))
    read = [one_role(r) for r in of_types(found, "aws_iam_role") if r.get("arn")]
    return tuple(r for r, _ in read), tuple(n for _, ns in read for n in ns)


def _permission_sets(found, policies):
    """An identity per group a permission set is assigned to, with the permission set's grants."""
    sets = {p.get("arn"): p for p in of_types(found, "aws_ssoadmin_permission_set") if p.get("arn")}

    def read(arn):
        p = sets[arn]
        inline = [i.get("inline_policy") for i in of_types(found, "aws_ssoadmin_permission_set_inline_policy")
                  if i.get("permission_set_arn") == arn]
        attached, missing = _documents(_attached(arn, found, (), ("aws_ssoadmin_managed_policy_attachment",),
                                                 "permission_set_arn"), policies, f"permission set {p.get('name')}")
        return _read((*inline, *attached)), missing
    readings = {arn: read(arn) for arn in sets}
    groups = defaultdict(list)
    for a in of_types(found, "aws_ssoadmin_account_assignment"):
        if a.get("permission_set_arn") in sets and a.get("principal_id"):
            groups[(a.get("principal_id"), a.get("principal_type") or "GROUP")].append(a.get("permission_set_arn"))
    return (tuple(resource("identity", pid, {
                "ciamIdentityKind": "permission-set" if kind == "GROUP" else "user",
                "ciamGrant": sorted({g for arn in arns for g in readings[arn][0][0]}),
                "ciamDenial": sorted({d for arn in arns for d in readings[arn][0][1]})},
                name=sets[arns[0]].get("name"), role=next((tagged_role(_tags(sets[a])) for a in arns
                                                           if tagged_role(_tags(sets[a]))), None))
                  for (pid, kind), arns in groups.items()),
            tuple(n for _, missing in readings.values() for n in missing))


def _guardrails(found):
    """Service and resource control policies: their denies, their allows as a ceiling, what they prevent."""
    def one_policy(p):
        grants, denials = _read((p.get("content"),))
        return resource("guardrail", p.get("arn") or p.get("id"), {
            "ciamGuardrailKind": CONTROL_KINDS.get(p.get("type"), "other"),
            "ciamDenies": denials_of(statements(p.get("content"))), "ciamDenial": sorted(denials),
            "ciamBoundary": () if "* on *" in grants else sorted(grants)},
            name=p.get("name"), role=tagged_role(_tags(p)))
    return tuple(one_policy(p) for p in of_types(found, "aws_organizations_policy")
                 if p.get("type") in CONTROL_KINDS and (p.get("arn") or p.get("id")))


def _access_paths(found):
    return (*(resource("access", arn, {"ciamAccessKind": "workforce-sso",
                                       "ciamTrustedBy": list(i.get("identity_store_ids") or ())},
                       name="workforce-sso", role="access-workforce-sso")
              for i in of_types(found, "aws_ssoadmin_instances") for arn in (i.get("arns") or ())[:1]),
            *(resource("access", e.get("arn") or e.get("id"), {"ciamAccessKind": "session"},
                       name=_tags(e).get("Name") or e.get("id"), role=tagged_role(_tags(e)) or "access-session")
              for e in of_types(found, "aws_ec2_instance_connect_endpoint") if e.get("arn") or e.get("id")))


def iam_resources(found):
    """(resources, notices) of AWS IAM in (Terraform resource type, attributes) pairs: identities, guardrails, access
    paths."""
    policies = {p.get("arn"): p.get("policy") for p in of_types(found, "aws_iam_policy") if p.get("arn")}
    keys = {k: a.get("arn") for a in of_types(found, "aws_kms_key") for k in (a.get("key_id"), a.get("arn")) if k}
    by_resource = defaultdict(lambda: ((), ()))
    for who, effect, texts in _resource_policies(found, keys):
        for p in who:
            grants, denials = by_resource[p]
            by_resource[p] = (grants + texts, denials) if effect == "Allow" else (grants, denials + texts)
    roles, role_notices = _roles(found, policies, by_resource)
    sets, set_notices = _permission_sets(found, policies)
    known = {r.ref for r in roles}
    strangers = sorted(p for p, (grants, _) in by_resource.items()
                       if grants and p != "*" and p not in known and not p.endswith(":root"))   # the account itself
    return ((*roles, *sets, *_guardrails(found), *_access_paths(found)),
            (*role_notices, *set_notices,
             *(f"resource policies grant {p}, which isn't a role in this state; not recorded" for p in strangers)))
