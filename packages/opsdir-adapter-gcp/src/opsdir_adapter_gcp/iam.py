"""Google Cloud IAM in an environment's sources as the record's identities, guardrails and access paths
(opsdir.core.inventory), from (Terraform resource type, attributes) pairs like every Google Cloud source. Pure.

  google_service_account                  -> identity (kind service-account, federated when a workload identity pool's
                                             subjects may act as it): its email as provider ref; role from its display
                                             name's '(<role>)' (as the renderer writes it); Policy Troubleshooter's
                                             verdicts (evaluated: opsdir.domains.access.evaluations)
  google_<target>_iam_member / _binding / -> each member's grants: '<role> on <resource name>', ' (if <condition
    _policy on a project, folder,            title or expression>)' when conditional; a role bound on a folder or the
    organization, secret, key, key ring,     organization is inherited (it covers the environment's resources); a
    bucket, topic, subscription, service     custom role (google_project_iam_custom_role, _organization_) as its
    account                                  permissions; a group or user member is an identity of its own (kind group
                                             or user, its email as provider ref: how the landing zone names an
                                             operator's group)
  roles/iam.workloadIdentityUser for a    -> the service account's trust: '<issuer URL> <subject>' (the pool's OIDC
    pool subject                             providers' issuers)
  google_iam_deny_policy                  -> denials on the identities its rules name ('principalSet://goog/public:all':
                                             every identity here): each denied permission (exceptions excluded, 'p!e')
                                             on the resource it is attached to, ' (if <condition>)' when conditional
  google_org_policy_policy,               -> a guardrail per parent (kind org-constraint): what its enforced
    google_project_organization_policy       constraints prevent; role guardrail-org-policy-<parent id>
  google_iap_tunnel_iam_*,                -> access path iap (role access-iap): who may tunnel in, and the grant
    google_iap_tunnel_instance_iam_*
Members that are all users, domains or project roles grant no identity here: named, not recorded.
"""
import json
import re
from collections import defaultdict
from urllib.parse import unquote

from opsdir.core.inventory import of_types, resource
from opsdir.domains.access.grants import excluding, grant_text
from .guardrails import denial_of

WORKLOAD_USER = "roles/iam.workloadIdentityUser"
PUBLIC = ("allUsers", "allAuthenticatedUsers")
_ROLE_IN_NAME = re.compile(r"\(([a-z0-9][a-z0-9-]*)\)\s*$")
_POOL_SUBJECT = re.compile(r"^principal://iam\.googleapis\.com/projects/[^/]+/locations/[^/]+/workloadIdentityPools/"
                           r"([^/]+)/subject/(.+)$")
_SERVICE_NAMES = {"cloudresourcemanager": "resourcemanager"}       # deny policies' service names that differ


def _full(value, prefix, collection, a):
    """A resource name from a full name or a short id in its project ('<collection>/<id>' under projects/<p>)."""
    value = str(value or "")
    if value.startswith(prefix):
        return value
    return f"projects/{a.get('project')}/{collection}/{value}" if value else None


def _kms(value, depth):
    """A key ring's or key's resource name from its full name or '<project>/<location>/<ring>[/<key>]'."""
    value = str(value or "")
    if value.startswith("projects/"):
        return value
    parts = value.split("/")
    names = ("projects", "locations", "keyRings", "cryptoKeys")[:depth]
    return "/".join(f"{n}/{p}" for n, p in zip(names, parts)) if len(parts) == depth else value or None


TARGETS = (           # (type prefix, the resource name an IAM resource of it is on)
    ("google_project_iam", lambda a: f"projects/{a.get('project')}"),
    ("google_folder_iam", lambda a: a.get("folder") if str(a.get("folder")).startswith("folders/")
     else f"folders/{a.get('folder')}"),
    ("google_organization_iam", lambda a: f"organizations/{a.get('org_id')}"),
    ("google_secret_manager_regional_secret_iam", lambda a: _full(a.get("secret_id"), "projects/",
                                                                  f"locations/{a.get('location')}/secrets", a)),
    ("google_secret_manager_secret_iam", lambda a: _full(a.get("secret_id"), "projects/", "secrets", a)),
    ("google_kms_crypto_key_iam", lambda a: _kms(a.get("crypto_key_id"), 4)),
    ("google_kms_key_ring_iam", lambda a: _kms(a.get("key_ring_id"), 3)),
    ("google_storage_bucket_iam", lambda a: f"projects/_/buckets/{str(a.get('bucket')).removeprefix('b/')}"),
    ("google_pubsub_topic_iam", lambda a: _full(a.get("topic"), "projects/", "topics", a)),
    ("google_pubsub_subscription_iam", lambda a: _full(a.get("subscription"), "projects/", "subscriptions", a)),
    ("google_service_account_iam", lambda a: a.get("service_account_id")),
    ("google_iap_tunnel_instance_iam", lambda a: f"projects/{a.get('project')}/iap_tunnel/zones/{a.get('zone')}/"
                                                 f"instances/{a.get('instance')}"),
    ("google_iap_tunnel_iam", lambda a: f"projects/{a.get('project')}/iap_tunnel"),
    ("google_cai_iam", lambda a: a.get("resource")),        # an inventory's IAM policy, on the resource it names
)


def _condition(c):
    """A binding condition's title (else its expression), or None."""
    found = c[0] if isinstance(c, (list, tuple)) and c else c if isinstance(c, dict) else {}
    return found.get("title") or found.get("expression") or None


def _bindings(found):
    """[(resource name, role, member, condition)] of every IAM member, binding and policy in the pairs."""
    def target(t):
        return next((f for prefix, f in TARGETS if t.startswith(prefix + "_")), None)

    def policy(text):
        try:
            doc = json.loads(text or "{}")
        except (TypeError, ValueError):
            return []
        return doc.get("bindings") or [] if isinstance(doc, dict) else []
    out = []
    for t, a in found:
        name_of = target(t)
        if name_of is None:
            continue
        name = name_of(a)
        if t.endswith("_member"):
            out.append((name, a.get("role"), a.get("member"), _condition(a.get("condition"))))
        elif t.endswith("_binding"):
            out.extend((name, a.get("role"), m, _condition(a.get("condition"))) for m in a.get("members") or ())
        elif t.endswith("_policy"):
            out.extend((name, b.get("role"), m, _condition(b.get("condition")))
                       for b in policy(a.get("policy_data")) for m in b.get("members") or ())
    return [b for b in out if b[0] and b[1] and b[2]]


def _custom_roles(found):
    """{role name: permissions} of custom roles."""
    return {k: tuple(r.get("permissions") or ()) for r in of_types(found, "google_project_iam_custom_role",
                                                                     "google_organization_iam_custom_role")
            for k in (r.get("name"), r.get("id")) if k}


def _member(m):
    """(kind, email) of a member that is an identity: serviceAccount, group, user; None otherwise."""
    kind, _, email = str(m).partition(":")
    return ({"serviceAccount": "service-account", "group": "group", "user": "user"}.get(kind), email) \
        if email and kind in ("serviceAccount", "group", "user") else None


def _deny_principal(p):
    """(kind, email) a deny rule's principal names, ('all', None) for every principal, or None."""
    p = str(p)
    if p == "principalSet://goog/public:all":
        return "all", None
    for prefix, kind in (("principal://iam.googleapis.com/projects/-/serviceAccounts/", "service-account"),
                         ("principalSet://goog/group/", "group"), ("principal://goog/subject/", "user")):
        if p.startswith(prefix):
            return kind, p[len(prefix):]
    return None


def permission_v1(p):
    """A deny policy's permission (secretmanager.googleapis.com/versions.access) as IAM names it
    (secretmanager.versions.access)."""
    host, _, rest = str(p).partition("/")
    service = host.split(".", 1)[0]
    return f"{_SERVICE_NAMES.get(service, service)}.{rest}" if rest else str(p)


def _denials(found):
    """{(kind, email) or ('all', None): ((denial text, the principals excepted), ...)} of the deny policies."""
    out = defaultdict(tuple)
    for pol in of_types(found, "google_iam_deny_policy"):
        attached = unquote(str(pol.get("parent") or "")).split("googleapis.com/", 1)[-1]
        for rule in (r for rs in pol.get("rules") or () for r in rs.get("deny_rule") or ()):
            excepted = {_deny_principal(p) for p in rule.get("exception_principals") or ()}
            exceptions = [permission_v1(p) for p in rule.get("exception_permissions") or ()]
            texts = tuple(grant_text(excluding(permission_v1(p), exceptions), attached,
                                     _condition(rule.get("denial_condition")))
                          for p in rule.get("denied_permissions") or ())
            for who in (_deny_principal(p) for p in rule.get("denied_principals") or ()):
                if who is not None and who not in excepted:
                    out[who] += tuple((t, frozenset(excepted)) for t in texts)
    return out


def _trust(found, bindings):
    """{service account email: ('<issuer> <subject>', ...)} of the pool subjects that may act as it."""
    issuers = defaultdict(list)
    for p in of_types(found, "google_iam_workload_identity_pool_provider"):
        for o in p.get("oidc") or ():
            if o.get("issuer_uri"):
                issuers[p.get("workload_identity_pool_id")].append(o["issuer_uri"])
    out = defaultdict(tuple)
    for name, role, member, _ in bindings:
        m = _POOL_SUBJECT.match(str(member))
        if role == WORKLOAD_USER and m:
            pool, subject = m.groups()
            out[str(name).rsplit("/", 1)[-1]] += tuple(f"{i} {subject}" for i in issuers.get(pool, ())) or (
                str(member),)
    return out


def _identities(found):
    """(resources, notices): service accounts and every group or user the IAM resources name, with their grants and
    denials."""
    bindings, custom, denials = _bindings(found), _custom_roles(found), _denials(found)
    trust = _trust(found, bindings)
    grants, kinds = defaultdict(tuple), {}
    for name, role, member, cond in bindings:
        who = _member(member)
        if who is None or (role == WORKLOAD_USER and _POOL_SUBJECT.match(str(member))):
            continue
        kinds.setdefault(who[1], who[0])
        grants[who[1]] += tuple(grant_text(x, name, cond) for x in custom.get(role, (role,)))
    accounts = {a.get("email"): a for a in of_types(found, "google_service_account") if a.get("email")}
    kinds.update({e: "service-account" for e in accounts})

    def identity(email):
        kind, account = kinds[email], accounts.get(email) or {}
        role = _ROLE_IN_NAME.search(str(account.get("display_name") or ""))
        only_verdicts = bool(account.get("evaluated")) and not account.get("name")      # its kind: the record's
        return resource("identity", email, {
            "ciamIdentityKind": None if only_verdicts else "federated" if trust.get(email) else kind,
            "ciamTrustedBy": trust.get(email, ()), "ciamEvaluated": account.get("evaluated"),
            "ciamGrant": sorted(set(grants.get(email, ()))),
            "ciamDenial": sorted({t for who in ((kind, email), ("all", None)) for t, excepted in denials.get(who, ())
                                  if (kind, email) not in excepted})},
            name=email.split("@", 1)[0], role=role.group(1) if role else None)
    public = sorted({f"{role} on {name}" for name, role, member, _ in bindings if member in PUBLIC})
    return (tuple(identity(e) for e in kinds),
            tuple(f"{grant} is granted to every user ({', '.join(PUBLIC)}); not recorded" for grant in public))


def _guardrails(found):
    """A guardrail per parent its organization policies are set on, with what their enforced constraints prevent."""
    def enforced(p):
        rules = [r for s in p.get("spec") or () for r in s.get("rules") or ()]
        return any(str(r.get("enforce")).upper() == "TRUE" or r.get("values") for r in rules)
    found_policies = [
        *((p.get("parent") or p.get("name", "").split("/policies/")[0], p.get("name", "").rsplit("/", 1)[-1])
          for p in of_types(found, "google_org_policy_policy") if enforced(p)),
        *((f"projects/{p.get('project')}", p.get("constraint"))
          for p in of_types(found, "google_project_organization_policy")
          if any(b.get("enforced") for b in p.get("boolean_policy") or ()) or p.get("list_policy"))]
    parents = defaultdict(set)
    for parent, constraint in found_policies:
        if parent and denial_of(constraint):
            parents[parent].add(denial_of(constraint))
    return tuple(resource("guardrail", f"{parent}/policies", {"ciamGuardrailKind": "org-constraint",
                                                              "ciamDenies": sorted(denied)},
                          name=f"org-policy-{parent.rsplit('/', 1)[-1]}",
                          role=f"guardrail-org-policy-{parent.rsplit('/', 1)[-1]}".lower())
                 for parent, denied in parents.items())


def _access_paths(found):
    """IAP tunnels: who may come in through them (per project)."""
    tunnels = defaultdict(list)
    for name, role, member, cond in _bindings(found):
        if "/iap_tunnel" in name:
            tunnels[name.split("/iap_tunnel", 1)[0] + "/iap_tunnel"].append((name, role, member, cond))
    return tuple(resource("access", ref, {"ciamAccessKind": "iap",
                                          "ciamTrustedBy": sorted({m for _, _, m, _ in granted}),
                                          "ciamGrant": sorted({grant_text(r, n, c) for n, r, _, c in granted})},
                          name="iap", role="access-iap")
                 for ref, granted in tunnels.items())


def iam_resources(found):
    """(resources, notices) of Google Cloud IAM in (Terraform resource type, attributes) pairs: identities,
    guardrails, access paths."""
    identities, notices = _identities(found)
    return (*identities, *_guardrails(found), *_access_paths(found)), notices
