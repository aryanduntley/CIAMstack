"""Effective access, three ways, through a fake cloud's permission table: an allow that nothing limits is allowed; an
explicit deny (the identity's own, NotAction, a guardrail's) or a boundary that doesn't allow it is denied; a
conditional allow, an eligible role or a conditional deny is unknown; a cloud evaluator's verdict wins; the key that
encrypts a secret is needed too; and the planner's wording for each."""
import datetime as dt
from types import SimpleNamespace

from opsdir.core.contract import AccessModel, Permission, PlanContext
from opsdir.core.directory import make_entry, one
from opsdir.domains.access.grants import (ALLOWED, DENIED, NOT_GRANTED, UNKNOWN, effective, excluding, grant_of,
                                          grant_text)


def _covers(granted_resource, binding):
    resource = (one(binding, "ciamRefUri") or "").split("://", 1)[-1]
    return granted_resource in ("*", resource) or resource.startswith(granted_resource.rstrip("/") + "/")


MODEL = AccessModel(
    permissions=(Permission("read-secret", "ciamSecretRef", None, (("sm:Get",),), False,
                            (("ciamEncryptedByRole", (("kms:Decrypt",),)),)),),
    escalations=(), covers=_covers, resource=lambda b: None)
SECRET = make_entry("cn=s,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                    {"ciamBindingRole": ["app-password"], "ciamRefUri": ["fake://alpha/app"]})
LOCKED = make_entry("cn=l,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                    {"ciamBindingRole": ["locked-password"], "ciamRefUri": ["fake://alpha/locked"],
                     "ciamEncryptedByRole": ["secrets-key"]})
KEY = make_entry("cn=k,ou=bindings,env=prod", ("top", "ciamKeyRef"),
                 {"ciamBindingRole": ["secrets-key"], "ciamRefUri": ["fake://alpha/keys/secrets"]})
ENV = SimpleNamespace(bindings=(SECRET, LOCKED, KEY))


def _identity(**attrs):
    return make_entry("cn=id,ou=bindings,env=prod", ("top", "ciamIdentityBinding"),
                      {"ciamBindingRole": ["identity-app"], "ciamProviderRef": ["id"],
                       **{k: list(v) if isinstance(v, tuple) else [v] for k, v in attrs.items()}})


def _guardrail(**attrs):
    return make_entry("cn=scp,ou=bindings,env=prod", ("top", "ciamGuardrail"),
                      {"ciamBindingRole": ["guardrails"], "ciamGuardrailKind": ["service-control"],
                       **{k: list(v) if isinstance(v, tuple) else [v] for k, v in attrs.items()}})


def _state(identity, permit="read-secret app-password", guardrails=()):
    v = effective(MODEL, ENV, permit, identity, guardrails)
    return v.state, v.why


def test_grants_read_with_their_conditions_eligibility_and_source():
    g = grant_of("sm:Get on alpha (if aws:SourceVpc=vpc-1) (resource policy)")
    assert (g.action, g.resource, g.condition, g.resource_policy, g.eligible) == (
        "sm:Get", "alpha", "aws:SourceVpc=vpc-1", True, False)
    assert grant_of("Key Vault Secrets User on /v (eligible)").eligible


def test_grants_written_as_they_are_read_and_exclusions():
    text = grant_text("sm:Get", "alpha", 'resource.name.startsWith("x")\n  ', resource_policy=True, eligible=True)
    assert text == 'sm:Get on alpha (resource policy) (if resource.name.startsWith["x"]) (eligible)'
    g = grant_of(text)                                          # parentheses would end the suffix: bracketed
    assert (g.action, g.condition, g.resource_policy, g.eligible) == (
        "sm:Get", 'resource.name.startsWith["x"]', True, True)
    assert excluding("sm:*", ()) == "sm:*" and excluding("sm:*", ("sm:Delete", "sm:Put")) == "sm:*!sm:Delete|sm:Put"
    assert _state(_identity(ciamGrant="sm:*!sm:Put on alpha"))[0] == ALLOWED          # a custom role's NotActions
    assert _state(_identity(ciamGrant="sm:*!sm:G* on alpha"))[0] == NOT_GRANTED
    assert _state(_identity(ciamGrant="sm:Get on alpha", ciamDenial="sm:*!sm:Get on *"))[0] == ALLOWED   # excepted


def test_allowed_not_granted_and_explicitly_denied():
    assert _state(_identity(ciamGrant="sm:Get on alpha")) == (ALLOWED, "")
    assert _state(_identity(ciamGrant="sm:List on alpha"))[0] == NOT_GRANTED
    assert _state(_identity(ciamGrant="sm:* on *", ciamDenial="sm:Get on alpha/app")) == (
        DENIED, "explicitly denied by `sm:Get on alpha/app` (its own policies)")
    assert _state(_identity(ciamGrant="sm:Get on alpha", ciamDenial="!kms:*|iam:* on *"))[0] == DENIED   # NotAction
    assert _state(_identity(ciamGrant="sm:Get on alpha", ciamDenial="!sm:*|iam:* on *"))[0] == ALLOWED


def test_boundaries_and_guardrails_limit_what_is_granted():
    assert _state(_identity(ciamGrant="sm:Get on alpha", ciamBoundary="kms:* on *")) == (
        DENIED, "not allowed by its permissions boundary")
    assert _state(_identity(ciamGrant="sm:Get on alpha", ciamBoundary="sm:* on *"))[0] == ALLOWED
    scp = _guardrail(ciamDenial="sm:Get on *")
    assert _state(_identity(ciamGrant="sm:Get on alpha"), guardrails=(scp,)) == (
        DENIED, "explicitly denied by `sm:Get on *` (guardrail `scp`)")
    ceiling = _guardrail(ciamBoundary="ec2:* on *")
    assert _state(_identity(ciamGrant="sm:Get on alpha"), guardrails=(ceiling,)) == (
        DENIED, "not allowed by guardrail `scp`")


def test_what_cant_be_told_is_unknown():
    state, why = _state(_identity(ciamGrant="sm:Get on alpha (if aws:SourceVpc=vpc-1)"))
    assert state == UNKNOWN and why.startswith("allowed only if aws:SourceVpc=vpc-1")
    assert _state(_identity(ciamGrant="sm:Get on alpha (eligible)"))[1].startswith("eligible, not active")
    state, why = _state(_identity(ciamGrant="sm:Get on alpha", ciamDenial="sm:Get on * (if aws:SourceIp=10.0.0.0/8)"))
    assert state == UNKNOWN and why.startswith("a conditional deny may apply")


def test_a_cloud_evaluators_verdict_wins():
    identity = _identity(ciamGrant="sm:Get on alpha",
                         ciamEvaluated="read-secret app-password: denied (aws simulate-principal-policy 2026-10-02)")
    assert _state(identity) == (DENIED, "by aws simulate-principal-policy 2026-10-02")


def test_the_key_that_encrypts_a_secret_is_needed_too():
    assert _state(_identity(ciamGrant="sm:Get on alpha"), "read-secret locked-password")[0] == NOT_GRANTED
    assert _state(_identity(ciamGrant=("sm:Get on alpha", "kms:Decrypt on alpha/keys")),
                  "read-secret locked-password")[0] == ALLOWED
    unbound = SimpleNamespace(bindings=(LOCKED,))
    v = effective(MODEL, unbound, "read-secret locked-password", _identity(ciamGrant="sm:Get on alpha"))
    assert (v.state, v.why) == (UNKNOWN, "the key `secrets-key` that encrypts it isn't bound in this environment")
